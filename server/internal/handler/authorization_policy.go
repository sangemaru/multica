package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/multica-ai/multica/server/internal/admission"
	requestidentity "github.com/multica-ai/multica/server/internal/identity"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

var authorizationClassPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)

type SetAuthorizationApproverRequest struct {
	UserID string `json:"user_id"`
}

type AuthorizationApproverResponse struct {
	WorkspaceID              string `json:"workspace_id"`
	DesignatedApproverUserID string `json:"designated_approver_user_id"`
	UpdatedAt                string `json:"updated_at"`
}

type AuthorizationPolicyAssertionRequest struct {
	Effect       string `json:"effect"`
	Action       string `json:"action"`
	SubjectType  string `json:"subject_type"`
	SubjectValue string `json:"subject_value,omitempty"`
	ReasonCode   string `json:"reason_code"`
}

type PublishAuthorizationPolicyRequest struct {
	ScopeType       string                                `json:"scope_type"`
	ScopeKey        string                                `json:"scope_key"`
	EnforcementMode string                                `json:"enforcement_mode"`
	Reason          string                                `json:"reason"`
	Assertions      []AuthorizationPolicyAssertionRequest `json:"assertions"`
}

type AuthorizationPolicyResponse struct {
	ID              string                                `json:"id"`
	WorkspaceID     string                                `json:"workspace_id"`
	ScopeType       string                                `json:"scope_type"`
	ScopeKey        string                                `json:"scope_key"`
	Version         int64                                 `json:"version"`
	EnforcementMode string                                `json:"enforcement_mode"`
	CreatedByUserID string                                `json:"created_by_user_id"`
	Reason          string                                `json:"reason"`
	Assertions      []AuthorizationPolicyAssertionRequest `json:"assertions"`
	CreatedAt       string                                `json:"created_at"`
}

type SetAgentAuthorizationClassRequest struct {
	AuthorizationClass string `json:"authorization_class"`
	Reason             string `json:"reason"`
}

func (h *Handler) GetAuthorizationApprover(w http.ResponseWriter, r *http.Request) {
	workspaceID := parseUUID(chi.URLParam(r, "id"))
	config, err := h.Queries.GetWorkspaceAuthorizationConfig(r.Context(), workspaceID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "authorization approver is not configured")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load authorization approver")
		return
	}
	writeJSON(w, http.StatusOK, AuthorizationApproverResponse{
		WorkspaceID: uuidToString(config.WorkspaceID), DesignatedApproverUserID: uuidToString(config.DesignatedApproverUserID), UpdatedAt: timestampToString(config.UpdatedAt),
	})
}

func (h *Handler) SetAuthorizationApprover(w http.ResponseWriter, r *http.Request) {
	id, workspaceID, ok := h.requireHumanAuthorizationAdministrator(w, r, false)
	if !ok {
		return
	}
	var req SetAuthorizationApproverRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	approverID, valid := optionalAuthorizationUUID(req.UserID)
	if !valid || !approverID.Valid {
		writeError(w, http.StatusBadRequest, "valid user_id is required")
		return
	}
	targetMember, err := h.Queries.GetMemberByUserAndWorkspace(r.Context(), db.GetMemberByUserAndWorkspaceParams{UserID: approverID, WorkspaceID: workspaceID})
	if err != nil || targetMember.Role != "owner" {
		writeError(w, http.StatusBadRequest, "designated approver must be a workspace owner")
		return
	}
	current, err := h.Queries.GetWorkspaceAuthorizationConfig(r.Context(), workspaceID)
	if err == nil && uuidToString(current.DesignatedApproverUserID) != id.UserID {
		writeError(w, http.StatusForbidden, "only the current designated approver may transfer authority")
		return
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusInternalServerError, "failed to load authorization approver")
		return
	}
	var updatedAt time.Time
	err = h.DB.QueryRow(r.Context(), `
		INSERT INTO workspace_authorization_config (workspace_id, designated_approver_user_id)
		VALUES ($1, $2)
		ON CONFLICT (workspace_id) DO UPDATE
		SET designated_approver_user_id = EXCLUDED.designated_approver_user_id, updated_at = now()
		RETURNING updated_at
	`, workspaceID, approverID).Scan(&updatedAt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to set authorization approver")
		return
	}
	writeJSON(w, http.StatusOK, AuthorizationApproverResponse{
		WorkspaceID: uuidToString(workspaceID), DesignatedApproverUserID: uuidToString(approverID), UpdatedAt: updatedAt.UTC().Format(time.RFC3339),
	})
}

func (h *Handler) PublishAuthorizationPolicy(w http.ResponseWriter, r *http.Request) {
	id, workspaceID, ok := h.requireHumanAuthorizationAdministrator(w, r, true)
	if !ok {
		return
	}
	var req PublishAuthorizationPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !h.validatePolicyPublication(w, r, workspaceID, req) {
		return
	}
	tx, err := h.TxStarter.Begin(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to begin policy publication")
		return
	}
	defer tx.Rollback(r.Context())
	lockKey := uuidToString(workspaceID) + ":" + req.ScopeType + ":" + req.ScopeKey
	if _, err = tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, lockKey); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to lock policy scope")
		return
	}
	var version int64
	if err = tx.QueryRow(r.Context(), `
		SELECT COALESCE(MAX(version), 0) + 1
		FROM authorization_policy_version
		WHERE workspace_id = $1 AND scope_type = $2 AND scope_key = $3
	`, workspaceID, req.ScopeType, req.ScopeKey).Scan(&version); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to allocate policy version")
		return
	}
	var policyID pgtype.UUID
	var createdAt time.Time
	if err = tx.QueryRow(r.Context(), `
		INSERT INTO authorization_policy_version
			(workspace_id, scope_type, scope_key, version, enforcement_mode, created_by_user_id, reason)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at
	`, workspaceID, req.ScopeType, req.ScopeKey, version, req.EnforcementMode, parseUUID(id.UserID), strings.TrimSpace(req.Reason)).Scan(&policyID, &createdAt); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create policy version")
		return
	}
	for _, assertion := range req.Assertions {
		var subjectValue any
		if assertion.SubjectType != "all" {
			subjectValue = assertion.SubjectValue
		}
		if _, err = tx.Exec(r.Context(), `
			INSERT INTO authorization_policy_assertion
				(policy_version_id, effect, action, subject_type, subject_value, reason_code)
			VALUES ($1, $2, $3, $4, $5, $6)
		`, policyID, assertion.Effect, assertion.Action, assertion.SubjectType, subjectValue, assertion.ReasonCode); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to create policy assertion")
			return
		}
	}
	if _, err = tx.Exec(r.Context(), `
		INSERT INTO authorization_policy_current
			(workspace_id, scope_type, scope_key, policy_version_id, version, enforcement_mode)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (workspace_id, scope_type, scope_key) DO UPDATE
		SET policy_version_id = EXCLUDED.policy_version_id,
			version = EXCLUDED.version,
			enforcement_mode = EXCLUDED.enforcement_mode,
			updated_at = now()
	`, workspaceID, req.ScopeType, req.ScopeKey, policyID, version, req.EnforcementMode); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to activate policy version")
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to commit policy publication")
		return
	}
	writeJSON(w, http.StatusCreated, AuthorizationPolicyResponse{
		ID: uuidToString(policyID), WorkspaceID: uuidToString(workspaceID), ScopeType: req.ScopeType, ScopeKey: req.ScopeKey,
		Version: version, EnforcementMode: req.EnforcementMode, CreatedByUserID: id.UserID, Reason: strings.TrimSpace(req.Reason), Assertions: req.Assertions, CreatedAt: createdAt.UTC().Format(time.RFC3339),
	})
}

func (h *Handler) ListAuthorizationPolicies(w http.ResponseWriter, r *http.Request) {
	workspaceID := parseUUID(chi.URLParam(r, "id"))
	rows, err := h.Queries.ListCurrentAuthorizationPolicies(r.Context(), workspaceID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list authorization policies")
		return
	}
	resp := make([]AuthorizationPolicyResponse, 0, len(rows))
	for _, row := range rows {
		assertions, err := h.Queries.ListAuthorizationPolicyAssertions(r.Context(), row.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to list policy assertions")
			return
		}
		item := AuthorizationPolicyResponse{ID: uuidToString(row.ID), WorkspaceID: uuidToString(row.WorkspaceID), ScopeType: row.ScopeType, ScopeKey: row.ScopeKey, Version: row.Version, EnforcementMode: row.EnforcementMode, CreatedByUserID: uuidToString(row.CreatedByUserID), Reason: row.Reason, CreatedAt: timestampToString(row.CreatedAt)}
		for _, assertion := range assertions {
			item.Assertions = append(item.Assertions, AuthorizationPolicyAssertionRequest{Effect: assertion.Effect, Action: assertion.Action, SubjectType: assertion.SubjectType, SubjectValue: assertion.SubjectValue.String, ReasonCode: assertion.ReasonCode})
		}
		resp = append(resp, item)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) SetAgentAuthorizationClass(w http.ResponseWriter, r *http.Request) {
	id, workspaceID, ok := h.requireHumanAuthorizationAdministrator(w, r, true)
	if !ok {
		return
	}
	var req SetAgentAuthorizationClassRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.AuthorizationClass = strings.TrimSpace(req.AuthorizationClass)
	req.Reason = strings.TrimSpace(req.Reason)
	if !authorizationClassPattern.MatchString(req.AuthorizationClass) || req.Reason == "" {
		writeError(w, http.StatusBadRequest, "valid authorization_class and reason are required")
		return
	}
	agentID := parseUUID(chi.URLParam(r, "agentId"))
	agent, err := h.Queries.GetAgent(r.Context(), agentID)
	if err != nil || agent.WorkspaceID.Bytes != workspaceID.Bytes {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	tx, err := h.TxStarter.Begin(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to begin class assignment")
		return
	}
	defer tx.Rollback(r.Context())
	if _, err = tx.Exec(r.Context(), `
		INSERT INTO authorization_agent_class_assignment
			(workspace_id, agent_id, authorization_class, assigned_by_user_id, reason)
		VALUES ($1, $2, $3, $4, $5)
	`, workspaceID, agentID, req.AuthorizationClass, parseUUID(id.UserID), req.Reason); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to record class assignment")
		return
	}
	if _, err = tx.Exec(r.Context(), `UPDATE agent SET authorization_class = $1, updated_at = now() WHERE id = $2`, req.AuthorizationClass, agentID); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to apply class assignment")
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to commit class assignment")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"agent_id": uuidToString(agentID), "authorization_class": req.AuthorizationClass})
}

func (h *Handler) requireHumanAuthorizationAdministrator(w http.ResponseWriter, r *http.Request, requireDesignated bool) (requestidentity.RequestIdentity, pgtype.UUID, bool) {
	id, ok := requestidentity.FromContext(r.Context())
	if !ok || id.CredentialClass != requestidentity.CredentialHumanInteractive || id.PrincipalType != requestidentity.PrincipalMember {
		writeError(w, http.StatusForbidden, "human_interactive_session required")
		return requestidentity.RequestIdentity{}, pgtype.UUID{}, false
	}
	workspaceID := parseUUID(chi.URLParam(r, "id"))
	member, err := h.Queries.GetMemberByUserAndWorkspace(r.Context(), db.GetMemberByUserAndWorkspaceParams{UserID: parseUUID(id.UserID), WorkspaceID: workspaceID})
	if err != nil || member.Role != "owner" {
		writeError(w, http.StatusForbidden, "workspace owner required")
		return requestidentity.RequestIdentity{}, pgtype.UUID{}, false
	}
	if requireDesignated {
		config, err := h.Queries.GetWorkspaceAuthorizationConfig(r.Context(), workspaceID)
		if err != nil || uuidToString(config.DesignatedApproverUserID) != id.UserID {
			writeError(w, http.StatusForbidden, "designated authorization approver required")
			return requestidentity.RequestIdentity{}, pgtype.UUID{}, false
		}
	}
	return id, workspaceID, true
}

func (h *Handler) validatePolicyPublication(w http.ResponseWriter, r *http.Request, workspaceID pgtype.UUID, req PublishAuthorizationPolicyRequest) bool {
	if req.EnforcementMode != "observe" && req.EnforcementMode != "enforce" {
		writeError(w, http.StatusBadRequest, "enforcement_mode must be observe or enforce")
		return false
	}
	if strings.TrimSpace(req.Reason) == "" || len(req.Assertions) == 0 {
		writeError(w, http.StatusBadRequest, "reason and at least one assertion are required")
		return false
	}
	switch req.ScopeType {
	case "workspace":
		if req.ScopeKey != uuidToString(workspaceID) {
			writeError(w, http.StatusBadRequest, "workspace scope_key must match workspace")
			return false
		}
	case "project":
		projectID, valid := optionalAuthorizationUUID(req.ScopeKey)
		if !valid || !projectID.Valid {
			writeError(w, http.StatusBadRequest, "invalid project scope_key")
			return false
		}
		if _, err := h.Queries.GetProjectInWorkspace(r.Context(), db.GetProjectInWorkspaceParams{ID: projectID, WorkspaceID: workspaceID}); err != nil {
			writeError(w, http.StatusBadRequest, "project is outside workspace")
			return false
		}
	case "agent_class":
		if !authorizationClassPattern.MatchString(req.ScopeKey) {
			writeError(w, http.StatusBadRequest, "invalid agent_class scope_key")
			return false
		}
	default:
		writeError(w, http.StatusBadRequest, "unsupported policy scope_type")
		return false
	}
	for _, assertion := range req.Assertions {
		if assertion.Effect != "allow" && assertion.Effect != "deny" {
			writeError(w, http.StatusBadRequest, "assertion effect must be allow or deny")
			return false
		}
		if !admission.ValidAction(admission.Action(assertion.Action)) {
			writeError(w, http.StatusBadRequest, "assertion uses unknown V1 action")
			return false
		}
		if !regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`).MatchString(assertion.ReasonCode) {
			writeError(w, http.StatusBadRequest, "assertion has invalid reason_code")
			return false
		}
		switch assertion.SubjectType {
		case "all":
			if assertion.SubjectValue != "" {
				writeError(w, http.StatusBadRequest, "all subject cannot have subject_value")
				return false
			}
		case "agent_class":
			if !authorizationClassPattern.MatchString(assertion.SubjectValue) {
				writeError(w, http.StatusBadRequest, "invalid agent_class subject")
				return false
			}
		case "agent":
			agentID, valid := optionalAuthorizationUUID(assertion.SubjectValue)
			agent, err := h.Queries.GetAgent(r.Context(), agentID)
			if !valid || err != nil || agent.WorkspaceID.Bytes != workspaceID.Bytes {
				writeError(w, http.StatusBadRequest, "agent subject is outside workspace")
				return false
			}
		case "credential_class":
			if !validPolicyCredentialClass(assertion.SubjectValue) {
				writeError(w, http.StatusBadRequest, "invalid credential_class subject")
				return false
			}
		case "principal_type":
			if !validPolicyPrincipalType(assertion.SubjectValue) {
				writeError(w, http.StatusBadRequest, "invalid principal_type subject")
				return false
			}
		default:
			writeError(w, http.StatusBadRequest, "unsupported assertion subject_type")
			return false
		}
	}
	return true
}

func validPolicyCredentialClass(value string) bool {
	switch requestidentity.CredentialClass(value) {
	case requestidentity.CredentialLegacyHumanSession, requestidentity.CredentialLegacyPersonalToken,
		requestidentity.CredentialAgentTaskToken, requestidentity.CredentialDaemonToken,
		requestidentity.CredentialCloudNodePAT, requestidentity.CredentialAutopilotTrigger,
		requestidentity.CredentialHarnessSession, requestidentity.CredentialHumanInteractive:
		return true
	default:
		return false
	}
}

func validPolicyPrincipalType(value string) bool {
	switch requestidentity.PrincipalType(value) {
	case requestidentity.PrincipalMember, requestidentity.PrincipalAgent, requestidentity.PrincipalHarness,
		requestidentity.PrincipalRuntime, requestidentity.PrincipalAutopilot, requestidentity.PrincipalService:
		return true
	default:
		return false
	}
}
