package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/multica-ai/multica/server/internal/admission"
	requestidentity "github.com/multica-ai/multica/server/internal/identity"
)

func decodeAuthorizationApprovalCase(t *testing.T, w *httptest.ResponseRecorder) AuthorizationApprovalCaseResponse {
	t.Helper()
	var response AuthorizationApprovalCaseResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("decode approval case: %v; body=%s", err, w.Body.String())
	}
	return response
}

func approvalCaseRequest(method, caseID string, body any, id requestidentity.RequestIdentity) *http.Request {
	path := "/api/workspaces/" + testWorkspaceID + "/authorization/approval-cases"
	params := map[string]string{"id": testWorkspaceID}
	if caseID != "" {
		path += "/" + caseID + "/transitions"
		params["caseId"] = caseID
	}
	return policyRequest(method, path, body, id, params)
}

func TestAuthorizationApprovalCaseLifecycleIsIdempotentAuditableAndHumanDecided(t *testing.T) {
	admin := humanAuthorizationAdminIdentity()
	configureTestAuthorizationApprover(t, admin)
	harnessSessionID := uuid.NewString()
	harness := requestidentity.RequestIdentity{
		PrincipalType:   requestidentity.PrincipalHarness,
		PrincipalID:     uuid.NewString(),
		CredentialClass: requestidentity.CredentialHarnessSession,
		UserID:          testUserID,
		SessionID:       harnessSessionID,
		WorkspaceID:     testWorkspaceID,
		AllowedActions:  []string{string(admission.ActionDeployStaging)},
	}
	create := CreateAuthorizationApprovalCaseRequest{
		IdempotencyKey: "approval:" + uuid.NewString(),
		Action:         string(admission.ActionDeployStaging),
		ResourceType:   "workspace",
		ResourceID:     testWorkspaceID,
		ReasonCode:     "deployment.board_approval_required",
	}

	w := httptest.NewRecorder()
	testHandler.CreateAuthorizationApprovalCase(w, approvalCaseRequest(http.MethodPost, "", create, harness))
	if w.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", w.Code, w.Body.String())
	}
	created := decodeAuthorizationApprovalCase(t, w)
	if created.Status != "requested" || created.RequestingMachineCanApprove ||
		created.RequesterCredentialClass != string(requestidentity.CredentialHarnessSession) ||
		created.RequesterSessionID != harnessSessionID || len(created.Events) != 1 ||
		created.Events[0].EventType != "requested" {
		t.Fatalf("created approval case=%+v", created)
	}

	// The same request returns the same case and does not append a second
	// requested event.
	w = httptest.NewRecorder()
	testHandler.CreateAuthorizationApprovalCase(w, approvalCaseRequest(http.MethodPost, "", create, harness))
	if w.Code != http.StatusOK {
		t.Fatalf("idempotent create status=%d body=%s", w.Code, w.Body.String())
	}
	replayed := decodeAuthorizationApprovalCase(t, w)
	if replayed.ID != created.ID || len(replayed.Events) != 1 {
		t.Fatalf("idempotent create returned case=%s events=%d, want %s/1", replayed.ID, len(replayed.Events), created.ID)
	}

	conflict := create
	conflict.Action = string(admission.ActionDeployProduction)
	w = httptest.NewRecorder()
	testHandler.CreateAuthorizationApprovalCase(w, approvalCaseRequest(http.MethodPost, "", conflict, harness))
	if w.Code != http.StatusConflict {
		t.Fatalf("conflicting create status=%d body=%s", w.Code, w.Body.String())
	}

	delivered := TransitionAuthorizationApprovalCaseRequest{
		IdempotencyKey: "delivered:" + uuid.NewString(),
		Event:          "delivered",
		ReasonCode:     "notification.provider_accepted",
	}
	w = httptest.NewRecorder()
	testHandler.TransitionAuthorizationApprovalCase(w, approvalCaseRequest(http.MethodPost, created.ID, delivered, harness))
	if w.Code != http.StatusOK {
		t.Fatalf("deliver status=%d body=%s", w.Code, w.Body.String())
	}
	afterDelivery := decodeAuthorizationApprovalCase(t, w)
	if afterDelivery.Status != "delivered" || afterDelivery.DeliveredAt == "" || len(afterDelivery.Events) != 2 {
		t.Fatalf("delivered approval case=%+v", afterDelivery)
	}

	// Delivery replay remains successful after the case advances and does not
	// duplicate the event.
	w = httptest.NewRecorder()
	testHandler.TransitionAuthorizationApprovalCase(w, approvalCaseRequest(http.MethodPost, created.ID, delivered, harness))
	if w.Code != http.StatusOK || len(decodeAuthorizationApprovalCase(t, w).Events) != 2 {
		t.Fatalf("idempotent delivery status=%d body=%s", w.Code, w.Body.String())
	}

	// Even though the harness is associated with the designated human account,
	// its machine credential cannot acknowledge or decide the case.
	acknowledge := TransitionAuthorizationApprovalCaseRequest{
		IdempotencyKey: "ack:" + uuid.NewString(),
		Event:          "acknowledged",
		ReasonCode:     "approver.opened_case",
	}
	w = httptest.NewRecorder()
	testHandler.TransitionAuthorizationApprovalCase(w, approvalCaseRequest(http.MethodPost, created.ID, acknowledge, harness))
	if w.Code != http.StatusForbidden {
		t.Fatalf("machine acknowledgement status=%d body=%s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	testHandler.TransitionAuthorizationApprovalCase(w, approvalCaseRequest(http.MethodPost, created.ID, acknowledge, admin))
	if w.Code != http.StatusOK {
		t.Fatalf("acknowledge status=%d body=%s", w.Code, w.Body.String())
	}

	approve := TransitionAuthorizationApprovalCaseRequest{
		IdempotencyKey: "approve:" + uuid.NewString(),
		Event:          "approved",
		ReasonCode:     "approver.authorized_action",
	}
	w = httptest.NewRecorder()
	testHandler.TransitionAuthorizationApprovalCase(w, approvalCaseRequest(http.MethodPost, created.ID, approve, harness))
	if w.Code != http.StatusForbidden {
		t.Fatalf("machine approval status=%d body=%s", w.Code, w.Body.String())
	}

	for _, transition := range []TransitionAuthorizationApprovalCaseRequest{
		approve,
		{IdempotencyKey: "apply:" + uuid.NewString(), Event: "applied", ReasonCode: "action.application_verified"},
		{IdempotencyKey: "resolve:" + uuid.NewString(), Event: "resolved", ReasonCode: "case.final_resolution_verified"},
	} {
		w = httptest.NewRecorder()
		testHandler.TransitionAuthorizationApprovalCase(w, approvalCaseRequest(http.MethodPost, created.ID, transition, admin))
		if w.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", transition.Event, w.Code, w.Body.String())
		}
	}
	final := decodeAuthorizationApprovalCase(t, w)
	if final.Status != "resolved" || final.Decision != "approved" ||
		final.AcknowledgedAt == "" || final.DecidedAt == "" ||
		final.AppliedAt == "" || final.ResolvedAt == "" ||
		len(final.Events) != 6 {
		t.Fatalf("final approval case=%+v", final)
	}
	wantEvents := []string{"requested", "delivered", "acknowledged", "approved", "applied", "resolved"}
	for i, want := range wantEvents {
		if final.Events[i].EventType != want {
			t.Fatalf("event[%d]=%q want=%q", i, final.Events[i].EventType, want)
		}
	}
	if final.Events[1].ActorCredentialClass != string(requestidentity.CredentialHarnessSession) ||
		final.Events[2].ActorCredentialClass != string(requestidentity.CredentialHumanInteractive) {
		t.Fatalf("event actor classes do not preserve machine→human handoff: %+v", final.Events)
	}

	if _, err := testPool.Exec(context.Background(),
		`UPDATE authorization_approval_case_event SET reason_code = 'rewritten' WHERE case_id = $1`,
		created.ID,
	); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("event mutation error=%v, want append-only rejection", err)
	}
	if _, err := testPool.Exec(context.Background(),
		`UPDATE authorization_approval_case SET action = 'deploy:production' WHERE id = $1`,
		created.ID,
	); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("case metadata mutation error=%v, want immutable rejection", err)
	}
}
