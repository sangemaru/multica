package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/multica-ai/multica/server/internal/admission"
	requestidentity "github.com/multica-ai/multica/server/internal/identity"
)

func humanAuthorizationAdminIdentity() requestidentity.RequestIdentity {
	return requestidentity.RequestIdentity{
		PrincipalType:           requestidentity.PrincipalMember,
		PrincipalID:             testUserID,
		CredentialClass:         requestidentity.CredentialHumanInteractive,
		UserID:                  testUserID,
		SessionID:               "01000000-0000-0000-0000-000000000010",
		AllowedActions:          []string{string(admission.ActionAgentInvoke)},
		AuthenticationAssurance: "fresh_interactive_login",
		AuthenticatedAt:         time.Now(),
	}
}

func policyRequest(method, path string, body any, id requestidentity.RequestIdentity, params map[string]string) *http.Request {
	req := newRequest(method, path, body)
	rctx := chi.NewRouteContext()
	for key, value := range params {
		rctx.URLParams.Add(key, value)
	}
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	return req.WithContext(requestidentity.WithRequest(req.Context(), id))
}

func configureTestAuthorizationApprover(t *testing.T, id requestidentity.RequestIdentity) {
	t.Helper()
	w := httptest.NewRecorder()
	testHandler.SetAuthorizationApprover(w, policyRequest(http.MethodPut, "/api/workspaces/"+testWorkspaceID+"/authorization/approver", SetAuthorizationApproverRequest{UserID: testUserID}, id, map[string]string{"id": testWorkspaceID}))
	if w.Code != http.StatusOK {
		t.Fatalf("configure approver status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestProjectExplicitDenyInterceptsEveryAdmissionPath(t *testing.T) {
	ctx := context.Background()
	admin := humanAuthorizationAdminIdentity()
	configureTestAuthorizationApprover(t, admin)

	var projectID string
	if err := testPool.QueryRow(ctx, `INSERT INTO project (workspace_id, title) VALUES ($1, $2) RETURNING id`, testWorkspaceID, "Authorization deny fixture").Scan(&projectID); err != nil {
		t.Fatalf("create project: %v", err)
	}
	t.Cleanup(func() { testPool.Exec(context.Background(), `DELETE FROM project WHERE id = $1`, projectID) })

	agentID := createHandlerTestAgent(t, "Experimental authorization fixture", nil)
	w := httptest.NewRecorder()
	testHandler.SetAgentAuthorizationClass(w, policyRequest(http.MethodPut, "/api/workspaces/"+testWorkspaceID+"/authorization/agents/"+agentID+"/class", SetAgentAuthorizationClassRequest{AuthorizationClass: "experimental", Reason: "bounded read-only evaluation fixture"}, admin, map[string]string{"id": testWorkspaceID, "agentId": agentID}))
	if w.Code != http.StatusOK {
		t.Fatalf("class assignment status=%d body=%s", w.Code, w.Body.String())
	}

	publication := PublishAuthorizationPolicyRequest{
		ScopeType:       "project",
		ScopeKey:        projectID,
		EnforcementMode: "enforce",
		Reason:          "experimental agents are not authorized for this project",
		Assertions: []AuthorizationPolicyAssertionRequest{{
			Effect: "deny", Action: string(admission.ActionAgentInvoke), SubjectType: "agent_class", SubjectValue: "experimental", ReasonCode: "project.experimental_agent_denied",
		}},
	}
	w = httptest.NewRecorder()
	testHandler.PublishAuthorizationPolicy(w, policyRequest(http.MethodPost, "/api/workspaces/"+testWorkspaceID+"/authorization/policies", publication, admin, map[string]string{"id": testWorkspaceID}))
	if w.Code != http.StatusCreated {
		t.Fatalf("publish status=%d body=%s", w.Code, w.Body.String())
	}
	var published AuthorizationPolicyResponse
	if err := json.NewDecoder(w.Body).Decode(&published); err != nil {
		t.Fatalf("decode publication: %v", err)
	}

	harness := requestidentity.RequestIdentity{
		PrincipalType:   requestidentity.PrincipalHarness,
		PrincipalID:     "02000000-0000-0000-0000-000000000020",
		CredentialClass: requestidentity.CredentialHarnessSession,
		UserID:          testUserID,
		SessionID:       "02000000-0000-0000-0000-000000000020",
		WorkspaceID:     testWorkspaceID,
		AllowedActions:  []string{string(admission.ActionAgentInvoke)},
		PolicyVersion:   1,
	}
	for _, path := range admission.AllPaths() {
		t.Run(string(path), func(t *testing.T) {
			_, err := testHandler.TaskService.AdmitTask(requestidentity.WithRequest(ctx, harness), admission.Request{
				Path: path, WorkspaceID: testWorkspaceID, ProjectID: projectID, AgentID: agentID,
			})
			if !errors.Is(err, admission.ErrDenied) {
				t.Fatalf("path %s error=%v, want ErrDenied", path, err)
			}
		})
	}

	if _, err := testPool.Exec(ctx, `UPDATE authorization_policy_version SET reason = 'rewritten' WHERE id = $1`, published.ID); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("policy mutation error=%v, want append-only rejection", err)
	}
}

func TestAuthorizationPolicyMutationRejectsHarnessPrincipal(t *testing.T) {
	harness := requestidentity.RequestIdentity{
		PrincipalType: requestidentity.PrincipalHarness, CredentialClass: requestidentity.CredentialHarnessSession,
		UserID: testUserID, SessionID: "03000000-0000-0000-0000-000000000030",
	}
	w := httptest.NewRecorder()
	testHandler.PublishAuthorizationPolicy(w, policyRequest(http.MethodPost, "/api/workspaces/"+testWorkspaceID+"/authorization/policies", PublishAuthorizationPolicyRequest{}, harness, map[string]string{"id": testWorkspaceID}))
	if w.Code != http.StatusForbidden {
		t.Fatalf("harness policy mutation status=%d, want 403", w.Code)
	}
}
