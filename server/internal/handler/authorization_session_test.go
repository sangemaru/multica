package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/multica-ai/multica/server/internal/admission"
	requestidentity "github.com/multica-ai/multica/server/internal/identity"
	"github.com/multica-ai/multica/server/internal/middleware"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

func authorizationExchangeRequest(t *testing.T, identity requestidentity.RequestIdentity, body ExchangeAuthorizationSessionRequest) *http.Request {
	t.Helper()
	req := newRequest(http.MethodPost, "/api/authorization/sessions/exchange", body)
	return req.WithContext(requestidentity.WithRequest(req.Context(), identity))
}

func decodeAuthorizationExchange(t *testing.T, w *httptest.ResponseRecorder) ExchangeAuthorizationSessionResponse {
	t.Helper()
	var response ExchangeAuthorizationSessionResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("decode exchange response: %v; body=%s", err, w.Body.String())
	}
	return response
}

func TestAuthorizationSessionHarnessLifecycle(t *testing.T) {
	caller := requestidentity.RequestIdentity{
		PrincipalType:   requestidentity.PrincipalMember,
		PrincipalID:     testUserID,
		CredentialClass: requestidentity.CredentialLegacyPersonalToken,
		UserID:          testUserID,
	}
	w := httptest.NewRecorder()
	testHandler.ExchangeAuthorizationSession(w, authorizationExchangeRequest(t, caller, ExchangeAuthorizationSessionRequest{
		Kind:               "harness_session",
		WorkspaceID:        testWorkspaceID,
		HarnessType:        "codex",
		AllowedActions:     []string{string(admission.ActionAgentInvoke)},
		ExpiresInSeconds:   600,
		MaxDelegationDepth: 0,
	}))
	if w.Code != http.StatusCreated {
		t.Fatalf("exchange status=%d body=%s", w.Code, w.Body.String())
	}
	created := decodeAuthorizationExchange(t, w)
	if !strings.HasPrefix(created.Token, "mha_") || created.CredentialClass != string(requestidentity.CredentialHarnessSession) {
		t.Fatalf("unexpected created session: %+v", created)
	}

	var got requestidentity.RequestIdentity
	authed := middleware.Auth(testHandler.Queries, nil, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = requestidentity.FromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/issues", nil)
	req.Header.Set("Authorization", "Bearer "+created.Token)
	authResult := httptest.NewRecorder()
	authed.ServeHTTP(authResult, req)
	if authResult.Code != http.StatusNoContent {
		t.Fatalf("session auth status=%d body=%s", authResult.Code, authResult.Body.String())
	}
	if got.PrincipalType != requestidentity.PrincipalHarness || got.SessionID != created.ID || got.WorkspaceID != testWorkspaceID || len(got.AllowedActions) != 1 {
		t.Fatalf("authenticated identity=%+v", got)
	}

	revokeReq := newRequest(http.MethodDelete, "/api/authorization/sessions/"+created.ID, nil)
	revokeReq = withURLParam(revokeReq, "id", created.ID)
	revoke := httptest.NewRecorder()
	testHandler.RevokeAuthorizationSession(revoke, revokeReq)
	if revoke.Code != http.StatusOK {
		t.Fatalf("revoke status=%d body=%s", revoke.Code, revoke.Body.String())
	}

	afterRevoke := httptest.NewRecorder()
	authed.ServeHTTP(afterRevoke, req)
	if afterRevoke.Code != http.StatusUnauthorized {
		t.Fatalf("revoked auth status=%d, want 401", afterRevoke.Code)
	}
}

func TestAuthorizationSessionHumanRequiresFreshInteractiveLogin(t *testing.T) {
	fresh := requestidentity.RequestIdentity{
		PrincipalType:   requestidentity.PrincipalMember,
		PrincipalID:     testUserID,
		CredentialClass: requestidentity.CredentialLegacyHumanSession,
		UserID:          testUserID,
		AuthenticatedAt: time.Now().Add(-time.Minute),
	}
	w := httptest.NewRecorder()
	testHandler.ExchangeAuthorizationSession(w, authorizationExchangeRequest(t, fresh, ExchangeAuthorizationSessionRequest{
		Kind:             "human_interactive_session",
		ExpiresInSeconds: 600,
	}))
	if w.Code != http.StatusCreated {
		t.Fatalf("fresh exchange status=%d body=%s", w.Code, w.Body.String())
	}
	created := decodeAuthorizationExchange(t, w)
	if !strings.HasPrefix(created.Token, "mhi_") || len(created.AllowedActions) != len(admission.AllActions()) {
		t.Fatalf("unexpected human session: %+v", created)
	}

	stale := fresh
	stale.AuthenticatedAt = time.Now().Add(-10 * time.Minute)
	w = httptest.NewRecorder()
	testHandler.ExchangeAuthorizationSession(w, authorizationExchangeRequest(t, stale, ExchangeAuthorizationSessionRequest{Kind: "human_interactive_session"}))
	if w.Code != http.StatusForbidden {
		t.Fatalf("stale exchange status=%d, want 403", w.Code)
	}

	harness := fresh
	harness.PrincipalType = requestidentity.PrincipalHarness
	harness.CredentialClass = requestidentity.CredentialHarnessSession
	harness.SessionID = created.ID
	w = httptest.NewRecorder()
	testHandler.ExchangeAuthorizationSession(w, authorizationExchangeRequest(t, harness, ExchangeAuthorizationSessionRequest{
		Kind: "harness_session", WorkspaceID: testWorkspaceID, HarnessType: "nested",
	}))
	if w.Code != http.StatusForbidden {
		t.Fatalf("harness self-mint status=%d, want 403", w.Code)
	}
}

func TestHarnessSessionCannotWidenParentInteractiveGrant(t *testing.T) {
	childAgentID := createHandlerTestAgent(t, "authorization-session-child", nil)
	lineageID := "03000000-0000-0000-0000-000000000003"
	parent := requestidentity.RequestIdentity{
		PrincipalType:            requestidentity.PrincipalMember,
		PrincipalID:              testUserID,
		CredentialClass:          requestidentity.CredentialHumanInteractive,
		UserID:                   testUserID,
		SessionID:                "01000000-0000-0000-0000-000000000001",
		WorkspaceID:              testWorkspaceID,
		LineageID:                lineageID,
		AllowedActions:           []string{string(admission.ActionAgentInvoke)},
		AllowedChildPrincipalIDs: []string{childAgentID},
		CapabilityEnvelope:       true,
		ExpiresAt:                time.Now().Add(30 * time.Minute),
	}

	w := httptest.NewRecorder()
	testHandler.ExchangeAuthorizationSession(w, authorizationExchangeRequest(t, parent, ExchangeAuthorizationSessionRequest{
		Kind:                     "harness_session",
		WorkspaceID:              testWorkspaceID,
		HarnessType:              "test",
		AllowedActions:           []string{string(admission.ActionAgentInvoke), string(admission.ActionAgentDelegate)},
		MaxDelegationDepth:       1,
		AllowedChildPrincipalIDs: []string{childAgentID},
		ExpiresInSeconds:         600,
	}))
	if w.Code != http.StatusForbidden {
		t.Fatalf("widened exchange status=%d body=%s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	testHandler.ExchangeAuthorizationSession(w, authorizationExchangeRequest(t, parent, ExchangeAuthorizationSessionRequest{
		Kind:                     "harness_session",
		WorkspaceID:              testWorkspaceID,
		HarnessType:              "test",
		AllowedActions:           []string{string(admission.ActionAgentInvoke)},
		AllowedChildPrincipalIDs: []string{childAgentID},
		ExpiresInSeconds:         600,
	}))
	if w.Code != http.StatusCreated {
		t.Fatalf("bounded exchange status=%d body=%s", w.Code, w.Body.String())
	}
	created := decodeAuthorizationExchange(t, w)
	if created.LineageID != lineageID || created.MaxDelegationDepth != 0 || len(created.AllowedActions) != 1 {
		t.Fatalf("bounded child session=%+v", created)
	}
	t.Cleanup(func() {
		testPool.Exec(context.Background(), `DELETE FROM authorization_session WHERE id = $1`, created.ID)
	})
}

func TestAuthorizationDecisionLedgerRejectsMutation(t *testing.T) {
	row, err := testHandler.Queries.CreateAuthorizationDecision(context.Background(), authorizationDecisionFixture())
	if err != nil {
		t.Fatalf("create decision: %v", err)
	}
	_, err = testPool.Exec(context.Background(), `UPDATE authorization_decision SET reason_code = 'rewritten' WHERE id = $1`, row.ID)
	if err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("mutation error=%v, want append-only rejection", err)
	}
}

func TestNormalHandlerPersistsObserveOnlyDecision(t *testing.T) {
	ctx := requestidentity.WithRequest(context.Background(), requestidentity.RequestIdentity{
		PrincipalType:   requestidentity.PrincipalMember,
		PrincipalID:     testUserID,
		CredentialClass: requestidentity.CredentialLegacyPersonalToken,
		UserID:          testUserID,
	})
	decision, err := testHandler.TaskService.AdmitTask(ctx, admission.Request{
		Path:        admission.PathQuickCreate,
		WorkspaceID: testWorkspaceID,
		AgentID:     "01000000-0000-0000-0000-000000000001",
	})
	if err != nil {
		t.Fatalf("AdmitTask: %v", err)
	}
	if decision.ID == "" || decision.Allowed || !decision.ObserveOnly {
		t.Fatalf("decision=%+v", decision)
	}
	row, err := testHandler.Queries.GetAuthorizationDecision(context.Background(), parseUUID(decision.ID))
	if err != nil {
		t.Fatalf("load persisted decision: %v", err)
	}
	if row.Path != string(admission.PathQuickCreate) || row.ReasonCode != "legacy_personal_token_requires_exchange" || !row.ObserveOnly {
		t.Fatalf("persisted decision=%+v", row)
	}
}

func authorizationDecisionFixture() db.CreateAuthorizationDecisionParams {
	return db.CreateAuthorizationDecisionParams{
		Path:            string(admission.PathMention),
		Action:          string(admission.ActionAgentInvoke),
		PrincipalType:   string(requestidentity.PrincipalMember),
		CredentialClass: string(requestidentity.CredentialLegacyPersonalToken),
		Allowed:         false,
		ReasonCode:      "test_deny",
		PolicyVersion:   "test-v1",
		ObserveOnly:     true,
		LineageID:       parseUUID("03000000-0000-0000-0000-000000000003"),
		EvaluationPhase: "admission",
	}
}
