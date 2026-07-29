package handler

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

// AuthorizationDecisionExplanation is the privacy-bounded reader projection
// of an append-only decision. It deliberately exposes opaque identifiers and
// stable reason codes, never prompts, messages, instructions, or credentials.
type AuthorizationDecisionExplanation struct {
	ID                 string   `json:"id"`
	WorkspaceID        string   `json:"workspace_id"`
	TaskID             string   `json:"task_id,omitempty"`
	Path               string   `json:"path"`
	EvaluationPhase    string   `json:"evaluation_phase"`
	Action             string   `json:"action"`
	PrincipalType      string   `json:"principal_type"`
	PrincipalID        string   `json:"principal_id,omitempty"`
	CredentialClass    string   `json:"credential_class"`
	Outcome            string   `json:"outcome"`
	Enforcement        string   `json:"enforcement"`
	ReasonCode         string   `json:"reason_code"`
	PolicyVersion      string   `json:"policy_version"`
	PolicyLayer        string   `json:"policy_layer"`
	Explanation        string   `json:"explanation"`
	NextStep           string   `json:"next_step"`
	TaskCreated        bool     `json:"task_created"`
	ProviderCallStatus string   `json:"provider_call_status"`
	AllowedActions     []string `json:"allowed_actions,omitempty"`
	ExplicitDenies     []string `json:"explicit_denies,omitempty"`
	CreatedAt          string   `json:"created_at"`
}

func (h *Handler) GetAuthorizationDecisionExplanation(w http.ResponseWriter, r *http.Request) {
	workspaceID, ok := parseUUIDOrBadRequest(w, chi.URLParam(r, "id"), "workspace id")
	if !ok {
		return
	}
	decisionID, ok := parseUUIDOrBadRequest(w, chi.URLParam(r, "decisionId"), "decision id")
	if !ok {
		return
	}
	decision, err := h.Queries.GetAuthorizationDecision(r.Context(), decisionID)
	if errors.Is(err, pgx.ErrNoRows) ||
		!decision.WorkspaceID.Valid ||
		uuidToString(decision.WorkspaceID) != uuidToString(workspaceID) {
		writeError(w, http.StatusNotFound, "authorization decision not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read authorization decision")
		return
	}
	writeJSON(w, http.StatusOK, authorizationDecisionExplanation(decision))
}

func (h *Handler) ListAuthorizationDecisionExplanations(w http.ResponseWriter, r *http.Request) {
	workspaceID, ok := parseUUIDOrBadRequest(w, chi.URLParam(r, "id"), "workspace id")
	if !ok {
		return
	}
	limit, offset, ok := authorizationDecisionPage(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "limit must be 1-100 and offset must be non-negative")
		return
	}
	decisions, err := h.Queries.ListAuthorizationDecisionsByWorkspace(
		r.Context(),
		db.ListAuthorizationDecisionsByWorkspaceParams{
			WorkspaceID: workspaceID,
			Limit:       limit,
			Offset:      offset,
		},
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list authorization decisions")
		return
	}
	response := make([]AuthorizationDecisionExplanation, 0, len(decisions))
	for _, decision := range decisions {
		response = append(response, authorizationDecisionExplanation(decision))
	}
	writeJSON(w, http.StatusOK, response)
}

func authorizationDecisionPage(r *http.Request) (int32, int32, bool) {
	parse := func(raw string, fallback int) (int, bool) {
		if raw == "" {
			return fallback, true
		}
		value, err := strconv.Atoi(raw)
		return value, err == nil
	}
	limit, validLimit := parse(r.URL.Query().Get("limit"), 20)
	offset, validOffset := parse(r.URL.Query().Get("offset"), 0)
	if !validLimit || !validOffset || limit < 1 || limit > 100 || offset < 0 {
		return 0, 0, false
	}
	return int32(limit), int32(offset), true
}

func authorizationDecisionExplanation(decision db.AuthorizationDecision) AuthorizationDecisionExplanation {
	outcome := "allowed"
	enforcement := "enforced"
	switch {
	case !decision.Allowed && decision.ObserveOnly:
		outcome = "observed_deny"
		enforcement = "observe_only"
	case !decision.Allowed:
		outcome = "denied"
	case decision.ObserveOnly:
		enforcement = "observe_only"
	}
	providerCallStatus := "not_recorded_by_authorization_ledger"
	if !decision.Allowed && !decision.ObserveOnly {
		providerCallStatus = "not_reached"
	}
	return AuthorizationDecisionExplanation{
		ID:                 uuidToString(decision.ID),
		WorkspaceID:        uuidToString(decision.WorkspaceID),
		TaskID:             uuidToString(decision.TaskID),
		Path:               decision.Path,
		EvaluationPhase:    decision.EvaluationPhase,
		Action:             decision.Action,
		PrincipalType:      decision.PrincipalType,
		PrincipalID:        uuidToString(decision.PrincipalID),
		CredentialClass:    decision.CredentialClass,
		Outcome:            outcome,
		Enforcement:        enforcement,
		ReasonCode:         decision.ReasonCode,
		PolicyVersion:      decision.PolicyVersion,
		PolicyLayer:        authorizationPolicyLayer(decision.PolicyVersion, decision.ReasonCode),
		Explanation:        authorizationReasonExplanation(decision.ReasonCode, outcome),
		NextStep:           authorizationDecisionNextStep(decision.ReasonCode, outcome),
		TaskCreated:        decision.TaskID.Valid,
		ProviderCallStatus: providerCallStatus,
		AllowedActions:     decision.AllowedActions,
		ExplicitDenies:     decision.ExplicitDenies,
		CreatedAt:          timestampToString(decision.CreatedAt),
	}
}

func authorizationPolicyLayer(version, reason string) string {
	switch {
	case strings.HasPrefix(version, "policy-v"):
		return "workspace_policy"
	case strings.HasPrefix(version, "session-v"):
		return "delegated_session"
	case strings.HasPrefix(reason, "session_"),
		strings.Contains(reason, "_scope_"),
		strings.Contains(reason, "_not_granted"),
		strings.Contains(reason, "delegation_"):
		return "session_capability_envelope"
	case strings.HasPrefix(version, "legacy-"):
		return "compatibility"
	default:
		return "credential_baseline"
	}
}

func authorizationReasonExplanation(reason, outcome string) string {
	switch reason {
	case "session_scope_allow":
		return "The delegated session permits this action and target within its recorded scope."
	case "interactive_session_allow":
		return "The interactive human session permits this action within its recorded scope."
	case "session_explicit_deny":
		return "The session capability envelope explicitly denies this action."
	case "session_action_not_granted":
		return "The session capability envelope does not grant this action."
	case "session_workspace_mismatch", "task_token_workspace_mismatch":
		return "The credential scope does not match this workspace."
	case "session_project_mismatch", "task_token_project_mismatch":
		return "The credential scope does not match this project."
	case "session_issue_mismatch", "task_token_issue_mismatch":
		return "The credential scope does not match this issue."
	case "invocation_principal_not_granted", "child_principal_not_granted":
		return "The target principal is not included in the credential's child-principal grant."
	case "delegation_depth_exhausted":
		return "The delegation lineage has no remaining delegation depth."
	case "lineage_budget_exhausted":
		return "The execution lineage has no remaining reserved execution budget."
	case "legacy_personal_token_requires_exchange", "legacy_human_session_requires_exchange":
		return "This legacy credential must be exchanged for a scoped authorization session."
	case "machine_credential_not_dispatch_authorized":
		return "This machine credential authenticates infrastructure but is not authorized to create agent work."
	case "unknown_dispatch_path", "unknown_action", "unknown_credential_class":
		return "The authorization service rejected an unknown admission input."
	default:
		if outcome == "allowed" {
			return "The recorded authorization policy allowed this action."
		}
		if outcome == "observed_deny" {
			return "Policy evaluation would deny this action, but this decision was recorded in observe-only mode."
		}
		return "The recorded authorization policy denied this action."
	}
}

func authorizationDecisionNextStep(reason, outcome string) string {
	if outcome == "allowed" {
		return "none"
	}
	if outcome == "observed_deny" {
		return "review_before_enforcement"
	}
	switch reason {
	case "legacy_personal_token_requires_exchange", "legacy_human_session_requires_exchange":
		return "exchange_for_scoped_session"
	case "session_workspace_mismatch", "session_project_mismatch", "session_issue_mismatch",
		"task_token_workspace_mismatch", "task_token_project_mismatch", "task_token_issue_mismatch",
		"session_action_not_granted", "session_explicit_deny",
		"invocation_principal_not_granted", "child_principal_not_granted",
		"delegation_depth_exhausted":
		return "request_new_scoped_session"
	case "lineage_budget_exhausted":
		return "request_budget_reset"
	default:
		return "review_policy_or_request_approval"
	}
}
