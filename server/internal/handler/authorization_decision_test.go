package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

func TestAuthorizationDecisionExplanationDistinguishesAllowDenyAndObserveOnly(t *testing.T) {
	base := db.AuthorizationDecision{
		ID:              pgtype.UUID{Bytes: uuid.New(), Valid: true},
		WorkspaceID:     pgtype.UUID{Bytes: uuid.New(), Valid: true},
		Path:            "mention",
		EvaluationPhase: "admission",
		Action:          "agent:invoke",
		PrincipalType:   "harness",
		CredentialClass: "harness_session",
		PolicyVersion:   "session-v3",
		ReasonCode:      "session_scope_allow",
		Allowed:         true,
	}
	allowed := authorizationDecisionExplanation(base)
	if allowed.Outcome != "allowed" || allowed.PolicyLayer != "delegated_session" ||
		allowed.NextStep != "none" || allowed.ProviderCallStatus != "not_recorded_by_authorization_ledger" {
		t.Fatalf("allowed explanation=%+v", allowed)
	}

	deniedRow := base
	deniedRow.Allowed = false
	deniedRow.ObserveOnly = false
	deniedRow.PolicyVersion = "policy-v7"
	deniedRow.ReasonCode = "project.experimental_class_denied"
	denied := authorizationDecisionExplanation(deniedRow)
	if denied.Outcome != "denied" || denied.Enforcement != "enforced" ||
		denied.PolicyLayer != "workspace_policy" || denied.ProviderCallStatus != "not_reached" ||
		denied.NextStep != "review_policy_or_request_approval" {
		t.Fatalf("denied explanation=%+v", denied)
	}

	observedRow := deniedRow
	observedRow.ObserveOnly = true
	observed := authorizationDecisionExplanation(observedRow)
	if observed.Outcome != "observed_deny" || observed.Enforcement != "observe_only" ||
		observed.NextStep != "review_before_enforcement" ||
		observed.ProviderCallStatus != "not_recorded_by_authorization_ledger" {
		t.Fatalf("observed explanation=%+v", observed)
	}
}

func TestAuthorizationDecisionExplanationAPIIsWorkspaceBounded(t *testing.T) {
	if testHandler == nil {
		t.Skip("database not available")
	}
	var decisionID string
	if err := testPool.QueryRow(t.Context(), `
		INSERT INTO authorization_decision (
			path, action, principal_type, credential_class, workspace_id,
			allowed, reason_code, policy_version, observe_only
		) VALUES (
			'mention', 'agent:invoke', 'harness', 'harness_session', $1,
			false, 'test.workspace_policy_denied', 'policy-v9', false
		)
		RETURNING id
	`, testWorkspaceID).Scan(&decisionID); err != nil {
		t.Fatalf("insert decision: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/authorization/decisions/"+decisionID, nil)
	req = withURLParams(req, "id", testWorkspaceID, "decisionId", decisionID)
	w := httptest.NewRecorder()
	testHandler.GetAuthorizationDecisionExplanation(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("get decision: status=%d body=%s", w.Code, w.Body.String())
	}
	var got AuthorizationDecisionExplanation
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Outcome != "denied" || got.PolicyLayer != "workspace_policy" ||
		got.ProviderCallStatus != "not_reached" || got.TaskCreated {
		t.Fatalf("explanation=%+v", got)
	}

	foreignWorkspaceID := uuid.NewString()
	req = httptest.NewRequest(http.MethodGet, "/authorization/decisions/"+decisionID, nil)
	req = withURLParams(req, "id", foreignWorkspaceID, "decisionId", decisionID)
	w = httptest.NewRecorder()
	testHandler.GetAuthorizationDecisionExplanation(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-workspace decision: status=%d body=%s", w.Code, w.Body.String())
	}
}
