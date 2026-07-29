package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/multica-ai/multica/server/internal/admission"
	"github.com/multica-ai/multica/server/internal/auth"
	requestidentity "github.com/multica-ai/multica/server/internal/identity"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

const (
	harnessSessionDefaultTTL = time.Hour
	harnessSessionMaxTTL     = 8 * time.Hour
	humanSessionDefaultTTL   = time.Hour
	humanSessionMaxTTL       = time.Hour
	humanPresenceMaxAge      = 5 * time.Minute
	maxV1DelegationDepth     = 4
)

type ExchangeAuthorizationSessionRequest struct {
	Kind                     string   `json:"kind"`
	WorkspaceID              string   `json:"workspace_id,omitempty"`
	ProjectID                string   `json:"project_id,omitempty"`
	IssueID                  string   `json:"issue_id,omitempty"`
	HarnessType              string   `json:"harness_type,omitempty"`
	AllowedActions           []string `json:"allowed_actions,omitempty"`
	ExplicitDenies           []string `json:"explicit_denies,omitempty"`
	MaxDelegationDepth       int32    `json:"max_delegation_depth,omitempty"`
	AllowedChildPrincipalIDs []string `json:"allowed_child_principal_ids,omitempty"`
	ExpiresInSeconds         int64    `json:"expires_in_seconds,omitempty"`
}

type AuthorizationSessionResponse struct {
	ID                       string   `json:"id"`
	CredentialClass          string   `json:"credential_class"`
	TokenPrefix              string   `json:"token_prefix"`
	WorkspaceID              string   `json:"workspace_id,omitempty"`
	ProjectID                string   `json:"project_id,omitempty"`
	IssueID                  string   `json:"issue_id,omitempty"`
	HarnessType              string   `json:"harness_type,omitempty"`
	AuthenticationAssurance  string   `json:"authentication_assurance"`
	AllowedActions           []string `json:"allowed_actions"`
	ExplicitDenies           []string `json:"explicit_denies"`
	MaxDelegationDepth       int32    `json:"max_delegation_depth"`
	AllowedChildPrincipalIDs []string `json:"allowed_child_principal_ids"`
	LineageID                string   `json:"lineage_id"`
	PolicyVersion            int64    `json:"policy_version"`
	ExpiresAt                string   `json:"expires_at"`
	LastUsedAt               *string  `json:"last_used_at,omitempty"`
	RotatedAt                *string  `json:"rotated_at,omitempty"`
	RevokedAt                *string  `json:"revoked_at,omitempty"`
	CreatedAt                string   `json:"created_at"`
}

type ExchangeAuthorizationSessionResponse struct {
	AuthorizationSessionResponse
	Token string `json:"token"`
}

func authorizationSessionResponse(row db.AuthorizationSession) AuthorizationSessionResponse {
	children := make([]string, 0, len(row.AllowedChildPrincipalIds))
	for _, child := range row.AllowedChildPrincipalIds {
		children = append(children, uuidToString(child))
	}
	return AuthorizationSessionResponse{
		ID:                       uuidToString(row.ID),
		CredentialClass:          row.CredentialClass,
		TokenPrefix:              row.TokenPrefix,
		WorkspaceID:              uuidToString(row.WorkspaceID),
		ProjectID:                uuidToString(row.ProjectID),
		IssueID:                  uuidToString(row.IssueID),
		HarnessType:              row.HarnessType.String,
		AuthenticationAssurance:  row.AuthenticationAssurance,
		AllowedActions:           append([]string(nil), row.AllowedActions...),
		ExplicitDenies:           append([]string(nil), row.ExplicitDenies...),
		MaxDelegationDepth:       row.MaxDelegationDepth,
		AllowedChildPrincipalIDs: children,
		LineageID:                uuidToString(row.LineageID),
		PolicyVersion:            row.PolicyVersion,
		ExpiresAt:                timestampToString(row.ExpiresAt),
		LastUsedAt:               timestampToPtr(row.LastUsedAt),
		RotatedAt:                timestampToPtr(row.RotatedAt),
		RevokedAt:                timestampToPtr(row.RevokedAt),
		CreatedAt:                timestampToString(row.CreatedAt),
	}
}

func (h *Handler) ExchangeAuthorizationSession(w http.ResponseWriter, r *http.Request) {
	id, ok := requestidentity.FromContext(r.Context())
	if !ok || id.UserID == "" {
		writeError(w, http.StatusUnauthorized, "authenticated human identity required")
		return
	}

	var req ExchangeAuthorizationSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Kind = strings.TrimSpace(req.Kind)

	var rawToken, credentialClass, assurance string
	var ttl, maxTTL time.Duration
	var presence pgtype.Timestamptz
	var harnessType pgtype.Text
	var err error

	switch req.Kind {
	case "human_interactive_session":
		if id.CredentialClass != requestidentity.CredentialLegacyHumanSession {
			writeError(w, http.StatusForbidden, "fresh interactive login required")
			return
		}
		now := time.Now()
		if id.AuthenticatedAt.IsZero() || id.AuthenticatedAt.After(now.Add(time.Minute)) || now.Sub(id.AuthenticatedAt) > humanPresenceMaxAge {
			writeError(w, http.StatusForbidden, "interactive presence is stale; authenticate again")
			return
		}
		rawToken, err = auth.GenerateHumanInteractiveSessionToken()
		credentialClass = string(requestidentity.CredentialHumanInteractive)
		assurance = "fresh_interactive_login"
		presence = pgtype.Timestamptz{Time: id.AuthenticatedAt, Valid: true}
		ttl, maxTTL = humanSessionDefaultTTL, humanSessionMaxTTL
		if len(req.AllowedActions) == 0 {
			for _, action := range admission.AllActions() {
				req.AllowedActions = append(req.AllowedActions, string(action))
			}
		}
	case "harness_session":
		switch id.CredentialClass {
		case requestidentity.CredentialLegacyPersonalToken,
			requestidentity.CredentialLegacyHumanSession,
			requestidentity.CredentialHumanInteractive:
		default:
			writeError(w, http.StatusForbidden, "a human bootstrap credential is required")
			return
		}
		if strings.TrimSpace(req.WorkspaceID) == "" || strings.TrimSpace(req.HarnessType) == "" {
			writeError(w, http.StatusBadRequest, "workspace_id and harness_type are required")
			return
		}
		rawToken, err = auth.GenerateHarnessSessionToken()
		credentialClass = string(requestidentity.CredentialHarnessSession)
		assurance = "delegated_by_authenticated_member"
		harnessType = pgtype.Text{String: strings.TrimSpace(req.HarnessType), Valid: true}
		ttl, maxTTL = harnessSessionDefaultTTL, harnessSessionMaxTTL
		if len(req.AllowedActions) == 0 {
			req.AllowedActions = []string{string(admission.ActionAgentInvoke)}
		}
	default:
		writeError(w, http.StatusBadRequest, "kind must be harness_session or human_interactive_session")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate session token")
		return
	}

	allowed, ok := validateAuthorizationActions(w, req.AllowedActions)
	if !ok {
		return
	}
	denies, ok := validateAuthorizationActions(w, req.ExplicitDenies)
	if !ok {
		return
	}
	if req.MaxDelegationDepth < 0 || req.MaxDelegationDepth > maxV1DelegationDepth {
		writeError(w, http.StatusBadRequest, "max_delegation_depth is outside the V1 range")
		return
	}

	workspaceID, projectID, issueID, children, ok := h.validateAuthorizationSessionScope(w, r, id.UserID, req)
	if !ok {
		return
	}
	lineage := uuid.New()
	if req.Kind == "harness_session" {
		if id.CredentialClass == requestidentity.CredentialHumanInteractive {
			if !authorizationScopeWithinParent(id, workspaceID, projectID, issueID) ||
				!stringSetSubset(allowed, id.AllowedActions) ||
				req.MaxDelegationDepth > id.MaxDelegationDepth ||
				!uuidSetSubset(children, id.AllowedChildPrincipalIDs) {
				writeError(w, http.StatusForbidden, "requested harness session exceeds the parent interactive grant")
				return
			}
			denies = unionStrings(id.ExplicitDenies, denies)
			inherited, parseErr := uuid.Parse(id.LineageID)
			if parseErr != nil {
				writeError(w, http.StatusForbidden, "parent interactive session has no valid authorization lineage")
				return
			}
			lineage = inherited
		} else if !stringSetSubset(allowed, []string{string(admission.ActionAgentInvoke)}) || req.MaxDelegationDepth != 0 {
			writeError(w, http.StatusForbidden, "interactive authorization is required for delegated actions or depth")
			return
		}
	}
	if req.ExpiresInSeconds > 0 {
		ttl = time.Duration(req.ExpiresInSeconds) * time.Second
	}
	if ttl <= 0 || ttl > maxTTL {
		writeError(w, http.StatusBadRequest, "expires_in_seconds exceeds the session-class limit")
		return
	}
	if id.CredentialClass == requestidentity.CredentialHumanInteractive && !id.ExpiresAt.IsZero() && time.Now().Add(ttl).After(id.ExpiresAt) {
		writeError(w, http.StatusForbidden, "child session cannot outlive the parent interactive session")
		return
	}

	prefix := rawToken
	if len(prefix) > 12 {
		prefix = prefix[:12]
	}
	row, err := h.Queries.CreateAuthorizationSession(r.Context(), db.CreateAuthorizationSessionParams{
		TokenHash:                auth.HashToken(rawToken),
		TokenPrefix:              prefix,
		CredentialClass:          credentialClass,
		UserID:                   parseUUID(id.UserID),
		WorkspaceID:              workspaceID,
		ProjectID:                projectID,
		IssueID:                  issueID,
		HarnessType:              harnessType,
		AuthenticationAssurance:  assurance,
		PresenceVerifiedAt:       presence,
		AllowedActions:           allowed,
		ExplicitDenies:           denies,
		MaxDelegationDepth:       req.MaxDelegationDepth,
		AllowedChildPrincipalIds: children,
		LineageID:                pgtype.UUID{Bytes: lineage, Valid: true},
		PolicyVersion:            1,
		ExpiresAt:                pgtype.Timestamptz{Time: time.Now().Add(ttl), Valid: true},
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create authorization session")
		return
	}
	writeJSON(w, http.StatusCreated, ExchangeAuthorizationSessionResponse{
		AuthorizationSessionResponse: authorizationSessionResponse(row),
		Token:                        rawToken,
	})
}

func authorizationScopeWithinParent(id requestidentity.RequestIdentity, workspaceID, projectID, issueID pgtype.UUID) bool {
	return optionalScopeContains(id.WorkspaceID, workspaceID) &&
		optionalScopeContains(id.ProjectID, projectID) &&
		optionalScopeContains(id.IssueID, issueID)
}

func optionalScopeContains(parent string, child pgtype.UUID) bool {
	if parent == "" {
		return true
	}
	return child.Valid && uuidToString(child) == parent
}

func stringSetSubset(child, parent []string) bool {
	allowed := make(map[string]struct{}, len(parent))
	for _, value := range parent {
		allowed[value] = struct{}{}
	}
	for _, value := range child {
		if _, ok := allowed[value]; !ok {
			return false
		}
	}
	return true
}

func uuidSetSubset(child []pgtype.UUID, parent []string) bool {
	allowed := make(map[string]struct{}, len(parent))
	for _, value := range parent {
		allowed[value] = struct{}{}
	}
	for _, value := range child {
		if _, ok := allowed[uuidToString(value)]; !ok {
			return false
		}
	}
	return true
}

func unionStrings(first, second []string) []string {
	seen := make(map[string]struct{}, len(first)+len(second))
	out := make([]string, 0, len(first)+len(second))
	for _, values := range [][]string{first, second} {
		for _, value := range values {
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			out = append(out, value)
		}
	}
	return out
}

func validateAuthorizationActions(w http.ResponseWriter, raw []string) ([]string, bool) {
	seen := make(map[string]struct{}, len(raw))
	out := make([]string, 0, len(raw))
	for _, value := range raw {
		value = strings.TrimSpace(value)
		if !admission.ValidAction(admission.Action(value)) {
			writeError(w, http.StatusBadRequest, "unknown V1 authorization action: "+value)
			return nil, false
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out, true
}

func (h *Handler) validateAuthorizationSessionScope(w http.ResponseWriter, r *http.Request, userID string, req ExchangeAuthorizationSessionRequest) (pgtype.UUID, pgtype.UUID, pgtype.UUID, []pgtype.UUID, bool) {
	workspaceID, workspaceOK := optionalAuthorizationUUID(req.WorkspaceID)
	projectID, projectOK := optionalAuthorizationUUID(req.ProjectID)
	issueID, issueOK := optionalAuthorizationUUID(req.IssueID)
	if !workspaceOK {
		writeError(w, http.StatusBadRequest, "invalid workspace_id")
		return pgtype.UUID{}, pgtype.UUID{}, pgtype.UUID{}, nil, false
	}
	if workspaceID.Valid {
		if _, err := h.Queries.GetMemberByUserAndWorkspace(r.Context(), db.GetMemberByUserAndWorkspaceParams{UserID: parseUUID(userID), WorkspaceID: workspaceID}); err != nil {
			writeError(w, http.StatusForbidden, "workspace membership required")
			return pgtype.UUID{}, pgtype.UUID{}, pgtype.UUID{}, nil, false
		}
	}
	if req.ProjectID != "" {
		if !projectOK {
			writeError(w, http.StatusBadRequest, "invalid project_id")
			return pgtype.UUID{}, pgtype.UUID{}, pgtype.UUID{}, nil, false
		}
		if _, err := h.Queries.GetProjectInWorkspace(r.Context(), db.GetProjectInWorkspaceParams{ID: projectID, WorkspaceID: workspaceID}); err != nil {
			writeError(w, http.StatusBadRequest, "project is outside the session workspace")
			return pgtype.UUID{}, pgtype.UUID{}, pgtype.UUID{}, nil, false
		}
	}
	if req.IssueID != "" {
		if !issueOK {
			writeError(w, http.StatusBadRequest, "invalid issue_id")
			return pgtype.UUID{}, pgtype.UUID{}, pgtype.UUID{}, nil, false
		}
		issue, err := h.Queries.GetIssueInWorkspace(r.Context(), db.GetIssueInWorkspaceParams{ID: issueID, WorkspaceID: workspaceID})
		if err != nil || (projectID.Valid && (!issue.ProjectID.Valid || issue.ProjectID.Bytes != projectID.Bytes)) {
			writeError(w, http.StatusBadRequest, "issue is outside the session scope")
			return pgtype.UUID{}, pgtype.UUID{}, pgtype.UUID{}, nil, false
		}
	}
	children := make([]pgtype.UUID, 0, len(req.AllowedChildPrincipalIDs))
	for _, raw := range req.AllowedChildPrincipalIDs {
		childID := parseUUID(raw)
		if !childID.Valid {
			writeError(w, http.StatusBadRequest, "invalid allowed child principal")
			return pgtype.UUID{}, pgtype.UUID{}, pgtype.UUID{}, nil, false
		}
		agent, err := h.Queries.GetAgent(r.Context(), childID)
		if err != nil || !workspaceID.Valid || agent.WorkspaceID.Bytes != workspaceID.Bytes {
			writeError(w, http.StatusBadRequest, "allowed child principal is outside the session workspace")
			return pgtype.UUID{}, pgtype.UUID{}, pgtype.UUID{}, nil, false
		}
		children = append(children, childID)
	}
	return workspaceID, projectID, issueID, children, true
}

func optionalAuthorizationUUID(value string) (pgtype.UUID, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return pgtype.UUID{}, true
	}
	var parsed pgtype.UUID
	if err := parsed.Scan(value); err != nil {
		return pgtype.UUID{}, false
	}
	return parsed, true
}

func (h *Handler) ListAuthorizationSessions(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}
	rows, err := h.Queries.ListAuthorizationSessionsByUser(r.Context(), parseUUID(userID))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list authorization sessions")
		return
	}
	resp := make([]AuthorizationSessionResponse, 0, len(rows))
	for _, row := range rows {
		resp = append(resp, authorizationSessionResponse(row))
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) RevokeAuthorizationSession(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}
	sessionID := parseUUID(chi.URLParam(r, "id"))
	if !sessionID.Valid {
		writeError(w, http.StatusBadRequest, "invalid session id")
		return
	}
	row, err := h.Queries.RevokeAuthorizationSession(r.Context(), db.RevokeAuthorizationSessionParams{ID: sessionID, UserID: parseUUID(userID)})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "authorization session not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to revoke authorization session")
		return
	}
	writeJSON(w, http.StatusOK, authorizationSessionResponse(row))
}

func (h *Handler) RotateAuthorizationSession(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}
	sessionID := parseUUID(chi.URLParam(r, "id"))
	if !sessionID.Valid {
		writeError(w, http.StatusBadRequest, "invalid session id")
		return
	}
	rows, err := h.Queries.ListAuthorizationSessionsByUser(r.Context(), parseUUID(userID))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load authorization session")
		return
	}
	var existing *db.AuthorizationSession
	for i := range rows {
		if rows[i].ID.Bytes == sessionID.Bytes {
			existing = &rows[i]
			break
		}
	}
	if existing == nil {
		writeError(w, http.StatusNotFound, "authorization session not found")
		return
	}
	var rawToken string
	if existing.CredentialClass == string(requestidentity.CredentialHarnessSession) {
		rawToken, err = auth.GenerateHarnessSessionToken()
	} else {
		rawToken, err = auth.GenerateHumanInteractiveSessionToken()
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to rotate authorization session")
		return
	}
	prefix := rawToken
	if len(prefix) > 12 {
		prefix = prefix[:12]
	}
	row, err := h.Queries.RotateAuthorizationSessionSecret(r.Context(), db.RotateAuthorizationSessionSecretParams{
		ID: sessionID, UserID: parseUUID(userID), TokenHash: auth.HashToken(rawToken), TokenPrefix: prefix,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "active authorization session not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to rotate authorization session")
		return
	}
	writeJSON(w, http.StatusOK, ExchangeAuthorizationSessionResponse{
		AuthorizationSessionResponse: authorizationSessionResponse(row),
		Token:                        rawToken,
	})
}
