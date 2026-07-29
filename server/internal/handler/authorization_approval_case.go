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
)

var (
	authorizationApprovalIdempotencyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	authorizationApprovalReasonPattern      = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
)

type CreateAuthorizationApprovalCaseRequest struct {
	IdempotencyKey string `json:"idempotency_key"`
	Action         string `json:"action"`
	ResourceType   string `json:"resource_type"`
	ResourceID     string `json:"resource_id"`
	ReasonCode     string `json:"reason_code"`
}

type TransitionAuthorizationApprovalCaseRequest struct {
	IdempotencyKey string `json:"idempotency_key"`
	Event          string `json:"event"`
	ReasonCode     string `json:"reason_code"`
}

type AuthorizationApprovalCaseEventResponse struct {
	ID                   int64  `json:"id"`
	EventType            string `json:"event_type"`
	ActorPrincipalType   string `json:"actor_principal_type"`
	ActorPrincipalID     string `json:"actor_principal_id"`
	ActorCredentialClass string `json:"actor_credential_class"`
	ActorSessionID       string `json:"actor_session_id,omitempty"`
	ReasonCode           string `json:"reason_code"`
	CreatedAt            string `json:"created_at"`
}

type AuthorizationApprovalCaseResponse struct {
	ID                          string                                   `json:"id"`
	WorkspaceID                 string                                   `json:"workspace_id"`
	RequesterPrincipalType      string                                   `json:"requester_principal_type"`
	RequesterPrincipalID        string                                   `json:"requester_principal_id"`
	RequesterCredentialClass    string                                   `json:"requester_credential_class"`
	RequesterSessionID          string                                   `json:"requester_session_id,omitempty"`
	OriginatorUserID            string                                   `json:"originator_user_id,omitempty"`
	DesignatedApproverUserID    string                                   `json:"designated_approver_user_id"`
	Action                      string                                   `json:"action"`
	ResourceType                string                                   `json:"resource_type"`
	ResourceID                  string                                   `json:"resource_id"`
	ReasonCode                  string                                   `json:"reason_code"`
	Status                      string                                   `json:"status"`
	Decision                    string                                   `json:"decision,omitempty"`
	DeliveredAt                 string                                   `json:"delivered_at,omitempty"`
	AcknowledgedAt              string                                   `json:"acknowledged_at,omitempty"`
	DecidedAt                   string                                   `json:"decided_at,omitempty"`
	AppliedAt                   string                                   `json:"applied_at,omitempty"`
	ResolvedAt                  string                                   `json:"resolved_at,omitempty"`
	CreatedAt                   string                                   `json:"created_at"`
	UpdatedAt                   string                                   `json:"updated_at"`
	RequestingMachineCanApprove bool                                     `json:"requesting_machine_can_approve"`
	Events                      []AuthorizationApprovalCaseEventResponse `json:"events"`
}

type authorizationApprovalCaseRow struct {
	ID                       pgtype.UUID
	WorkspaceID              pgtype.UUID
	IdempotencyKey           string
	RequesterPrincipalType   string
	RequesterPrincipalID     string
	RequesterCredentialClass string
	RequesterSessionID       pgtype.UUID
	OriginatorUserID         pgtype.UUID
	DesignatedApproverUserID pgtype.UUID
	Action                   string
	ResourceType             string
	ResourceID               pgtype.UUID
	ReasonCode               string
	Status                   string
	Decision                 pgtype.Text
	DeliveredAt              pgtype.Timestamptz
	AcknowledgedAt           pgtype.Timestamptz
	DecidedAt                pgtype.Timestamptz
	AppliedAt                pgtype.Timestamptz
	ResolvedAt               pgtype.Timestamptz
	CreatedAt                pgtype.Timestamptz
	UpdatedAt                pgtype.Timestamptz
}

const authorizationApprovalCaseColumns = `
	id, workspace_id, idempotency_key,
	requester_principal_type, requester_principal_id, requester_credential_class,
	requester_session_id, originator_user_id, designated_approver_user_id,
	action, resource_type, resource_id, reason_code, status, decision,
	delivered_at, acknowledged_at, decided_at, applied_at, resolved_at,
	created_at, updated_at`

func scanAuthorizationApprovalCase(row pgx.Row) (authorizationApprovalCaseRow, error) {
	var c authorizationApprovalCaseRow
	err := row.Scan(
		&c.ID, &c.WorkspaceID, &c.IdempotencyKey,
		&c.RequesterPrincipalType, &c.RequesterPrincipalID, &c.RequesterCredentialClass,
		&c.RequesterSessionID, &c.OriginatorUserID, &c.DesignatedApproverUserID,
		&c.Action, &c.ResourceType, &c.ResourceID, &c.ReasonCode, &c.Status, &c.Decision,
		&c.DeliveredAt, &c.AcknowledgedAt, &c.DecidedAt, &c.AppliedAt, &c.ResolvedAt,
		&c.CreatedAt, &c.UpdatedAt,
	)
	return c, err
}

func (h *Handler) CreateAuthorizationApprovalCase(w http.ResponseWriter, r *http.Request) {
	id, ok := requestidentity.FromContext(r.Context())
	if !ok || id.PrincipalType == "" || id.PrincipalID == "" || id.CredentialClass == "" {
		writeError(w, http.StatusForbidden, "authenticated principal required")
		return
	}
	workspaceID, ok := parseUUIDOrBadRequest(w, chi.URLParam(r, "id"), "workspace id")
	if !ok {
		return
	}
	if id.WorkspaceID != "" && id.WorkspaceID != uuidToString(workspaceID) {
		writeError(w, http.StatusForbidden, "authorization session is outside this workspace")
		return
	}

	var req CreateAuthorizationApprovalCaseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.IdempotencyKey = strings.TrimSpace(req.IdempotencyKey)
	req.Action = strings.TrimSpace(req.Action)
	req.ResourceType = strings.TrimSpace(req.ResourceType)
	req.ResourceID = strings.TrimSpace(req.ResourceID)
	req.ReasonCode = strings.TrimSpace(req.ReasonCode)
	resourceID, validResourceID := optionalAuthorizationUUID(req.ResourceID)
	if !authorizationApprovalIdempotencyPattern.MatchString(req.IdempotencyKey) ||
		!admission.ValidAction(admission.Action(req.Action)) ||
		!validAuthorizationApprovalResourceType(req.ResourceType) ||
		!validResourceID || !resourceID.Valid ||
		!authorizationApprovalReasonPattern.MatchString(req.ReasonCode) {
		writeError(w, http.StatusBadRequest, "valid idempotency_key, action, resource_type, resource_id, and reason_code are required")
		return
	}

	config, err := h.Queries.GetWorkspaceAuthorizationConfig(r.Context(), workspaceID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusConflict, "authorization approver is not configured")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load authorization approver")
		return
	}

	requesterSessionID, validSessionID := optionalAuthorizationUUID(id.SessionID)
	originatorUserID, validUserID := optionalAuthorizationUUID(id.UserID)
	if !validSessionID || !validUserID {
		writeError(w, http.StatusForbidden, "authenticated identity is invalid")
		return
	}

	tx, err := h.TxStarter.Begin(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to begin approval case")
		return
	}
	defer tx.Rollback(r.Context())

	insertSQL := `INSERT INTO authorization_approval_case (
		workspace_id, idempotency_key,
		requester_principal_type, requester_principal_id, requester_credential_class,
		requester_session_id, originator_user_id, designated_approver_user_id,
		action, resource_type, resource_id, reason_code
	) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
	ON CONFLICT (workspace_id, idempotency_key) DO NOTHING
	RETURNING ` + authorizationApprovalCaseColumns
	created, err := scanAuthorizationApprovalCase(tx.QueryRow(r.Context(), insertSQL,
		workspaceID, req.IdempotencyKey,
		string(id.PrincipalType), id.PrincipalID, string(id.CredentialClass),
		nullableApprovalUUID(requesterSessionID), nullableApprovalUUID(originatorUserID),
		config.DesignatedApproverUserID, req.Action, req.ResourceType, resourceID, req.ReasonCode,
	))
	status := http.StatusCreated
	if errors.Is(err, pgx.ErrNoRows) {
		status = http.StatusOK
		created, err = scanAuthorizationApprovalCase(tx.QueryRow(r.Context(),
			`SELECT `+authorizationApprovalCaseColumns+`
			 FROM authorization_approval_case
			 WHERE workspace_id = $1 AND idempotency_key = $2
			 FOR UPDATE`,
			workspaceID, req.IdempotencyKey,
		))
		if err == nil && !sameAuthorizationApprovalRequest(created, id, req, resourceID) {
			writeError(w, http.StatusConflict, "idempotency key already identifies a different approval request")
			return
		}
	} else if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO authorization_approval_case_event (
			case_id, idempotency_key, event_type,
			actor_principal_type, actor_principal_id, actor_credential_class,
			actor_session_id, reason_code
		) VALUES ($1,$2,'requested',$3,$4,$5,$6,$7)`,
			created.ID, req.IdempotencyKey,
			string(id.PrincipalType), id.PrincipalID, string(id.CredentialClass),
			nullableApprovalUUID(requesterSessionID), req.ReasonCode,
		)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create approval case")
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to commit approval case")
		return
	}
	response, err := h.loadAuthorizationApprovalCase(r, workspaceID, created.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read approval case")
		return
	}
	writeJSON(w, status, response)
}

func (h *Handler) GetAuthorizationApprovalCase(w http.ResponseWriter, r *http.Request) {
	workspaceID, ok := parseUUIDOrBadRequest(w, chi.URLParam(r, "id"), "workspace id")
	if !ok {
		return
	}
	caseID, ok := parseUUIDOrBadRequest(w, chi.URLParam(r, "caseId"), "approval case id")
	if !ok {
		return
	}
	response, err := h.loadAuthorizationApprovalCase(r, workspaceID, caseID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "approval case not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read approval case")
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (h *Handler) TransitionAuthorizationApprovalCase(w http.ResponseWriter, r *http.Request) {
	workspaceID, ok := parseUUIDOrBadRequest(w, chi.URLParam(r, "id"), "workspace id")
	if !ok {
		return
	}
	caseID, ok := parseUUIDOrBadRequest(w, chi.URLParam(r, "caseId"), "approval case id")
	if !ok {
		return
	}
	id, authenticated := requestidentity.FromContext(r.Context())
	if !authenticated {
		writeError(w, http.StatusForbidden, "authenticated principal required")
		return
	}

	var req TransitionAuthorizationApprovalCaseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.IdempotencyKey = strings.TrimSpace(req.IdempotencyKey)
	req.Event = strings.TrimSpace(req.Event)
	req.ReasonCode = strings.TrimSpace(req.ReasonCode)
	if !authorizationApprovalIdempotencyPattern.MatchString(req.IdempotencyKey) ||
		!validAuthorizationApprovalTransition(req.Event) ||
		!authorizationApprovalReasonPattern.MatchString(req.ReasonCode) {
		writeError(w, http.StatusBadRequest, "valid idempotency_key, event, and reason_code are required")
		return
	}

	tx, err := h.TxStarter.Begin(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to begin approval transition")
		return
	}
	defer tx.Rollback(r.Context())
	current, err := scanAuthorizationApprovalCase(tx.QueryRow(r.Context(),
		`SELECT `+authorizationApprovalCaseColumns+`
		 FROM authorization_approval_case
		 WHERE id = $1 AND workspace_id = $2
		 FOR UPDATE`,
		caseID, workspaceID,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "approval case not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to lock approval case")
		return
	}

	var existingEvent, existingReason string
	err = tx.QueryRow(r.Context(), `
		SELECT event_type, reason_code
		FROM authorization_approval_case_event
		WHERE case_id = $1 AND idempotency_key = $2
	`, caseID, req.IdempotencyKey).Scan(&existingEvent, &existingReason)
	if err == nil {
		if existingEvent != req.Event || existingReason != req.ReasonCode {
			writeError(w, http.StatusConflict, "idempotency key already identifies a different approval transition")
			return
		}
		if err = tx.Commit(r.Context()); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to commit approval transition")
			return
		}
		response, loadErr := h.loadAuthorizationApprovalCase(r, workspaceID, caseID)
		if loadErr != nil {
			writeError(w, http.StatusInternalServerError, "failed to read approval case")
			return
		}
		writeJSON(w, http.StatusOK, response)
		return
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusInternalServerError, "failed to check approval transition")
		return
	}

	if req.Event == "delivered" {
		if !authorizationApprovalDeliveryActor(id, current) {
			writeError(w, http.StatusForbidden, "only the requesting principal or designated approver may record delivery")
			return
		}
	} else {
		adminID, adminWorkspaceID, allowed := h.requireHumanAuthorizationAdministrator(w, r, true)
		if !allowed {
			return
		}
		if adminWorkspaceID.Bytes != workspaceID.Bytes || adminID.UserID != uuidToString(current.DesignatedApproverUserID) {
			writeError(w, http.StatusForbidden, "designated authorization approver required")
			return
		}
		id = adminID
	}
	if !authorizationApprovalCanTransition(current.Status, req.Event) {
		writeError(w, http.StatusConflict, "approval case cannot transition from "+current.Status+" to "+req.Event)
		return
	}

	sessionID, validSessionID := optionalAuthorizationUUID(id.SessionID)
	if !validSessionID {
		writeError(w, http.StatusForbidden, "authenticated identity is invalid")
		return
	}
	if _, err = tx.Exec(r.Context(), `INSERT INTO authorization_approval_case_event (
		case_id, idempotency_key, event_type,
		actor_principal_type, actor_principal_id, actor_credential_class,
		actor_session_id, reason_code
	) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		caseID, req.IdempotencyKey, req.Event,
		string(id.PrincipalType), id.PrincipalID, string(id.CredentialClass),
		nullableApprovalUUID(sessionID), req.ReasonCode,
	); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to record approval transition")
		return
	}
	if _, err = tx.Exec(r.Context(), authorizationApprovalTransitionUpdate(req.Event),
		caseID, req.Event,
	); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to materialize approval transition")
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to commit approval transition")
		return
	}
	response, err := h.loadAuthorizationApprovalCase(r, workspaceID, caseID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read approval case")
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func validAuthorizationApprovalResourceType(value string) bool {
	switch value {
	case "workspace", "project", "issue", "agent", "agent_task", "authorization_policy":
		return true
	default:
		return false
	}
}

func validAuthorizationApprovalTransition(value string) bool {
	switch value {
	case "delivered", "acknowledged", "approved", "denied", "applied", "resolved":
		return true
	default:
		return false
	}
}

func authorizationApprovalCanTransition(status, event string) bool {
	switch status {
	case "requested":
		return event == "delivered"
	case "delivered":
		return event == "acknowledged"
	case "acknowledged":
		return event == "approved" || event == "denied"
	case "approved":
		return event == "applied"
	case "denied", "applied":
		return event == "resolved"
	default:
		return false
	}
}

func authorizationApprovalTransitionUpdate(event string) string {
	switch event {
	case "delivered":
		return `UPDATE authorization_approval_case SET status = $2, delivered_at = now(), updated_at = now() WHERE id = $1`
	case "acknowledged":
		return `UPDATE authorization_approval_case SET status = $2, acknowledged_at = now(), updated_at = now() WHERE id = $1`
	case "approved", "denied":
		return `UPDATE authorization_approval_case SET status = $2, decision = $2, decided_at = now(), updated_at = now() WHERE id = $1`
	case "applied":
		return `UPDATE authorization_approval_case SET status = $2, applied_at = now(), updated_at = now() WHERE id = $1`
	case "resolved":
		return `UPDATE authorization_approval_case SET status = $2, resolved_at = now(), updated_at = now() WHERE id = $1`
	default:
		panic("unreachable approval transition")
	}
}

func authorizationApprovalDeliveryActor(id requestidentity.RequestIdentity, c authorizationApprovalCaseRow) bool {
	if id.PrincipalType == requestidentity.PrincipalMember &&
		id.CredentialClass == requestidentity.CredentialHumanInteractive &&
		id.UserID == uuidToString(c.DesignatedApproverUserID) {
		return true
	}
	return string(id.PrincipalType) == c.RequesterPrincipalType &&
		id.PrincipalID == c.RequesterPrincipalID &&
		string(id.CredentialClass) == c.RequesterCredentialClass &&
		(!c.RequesterSessionID.Valid || id.SessionID == uuidToString(c.RequesterSessionID))
}

func sameAuthorizationApprovalRequest(c authorizationApprovalCaseRow, id requestidentity.RequestIdentity, req CreateAuthorizationApprovalCaseRequest, resourceID pgtype.UUID) bool {
	return c.RequesterPrincipalType == string(id.PrincipalType) &&
		c.RequesterPrincipalID == id.PrincipalID &&
		c.RequesterCredentialClass == string(id.CredentialClass) &&
		(!c.RequesterSessionID.Valid || id.SessionID == uuidToString(c.RequesterSessionID)) &&
		c.Action == req.Action &&
		c.ResourceType == req.ResourceType &&
		c.ResourceID.Bytes == resourceID.Bytes &&
		c.ReasonCode == req.ReasonCode
}

func nullableApprovalUUID(value pgtype.UUID) any {
	if !value.Valid {
		return nil
	}
	return value
}

func approvalTime(value pgtype.Timestamptz) string {
	if !value.Valid {
		return ""
	}
	return value.Time.UTC().Format(time.RFC3339Nano)
}

func (h *Handler) loadAuthorizationApprovalCase(r *http.Request, workspaceID, caseID pgtype.UUID) (AuthorizationApprovalCaseResponse, error) {
	row, err := scanAuthorizationApprovalCase(h.DB.QueryRow(r.Context(),
		`SELECT `+authorizationApprovalCaseColumns+`
		 FROM authorization_approval_case
		 WHERE id = $1 AND workspace_id = $2`,
		caseID, workspaceID,
	))
	if err != nil {
		return AuthorizationApprovalCaseResponse{}, err
	}
	events, err := h.DB.Query(r.Context(), `
		SELECT id, event_type, actor_principal_type, actor_principal_id,
			actor_credential_class, actor_session_id, reason_code, created_at
		FROM authorization_approval_case_event
		WHERE case_id = $1
		ORDER BY id
	`, caseID)
	if err != nil {
		return AuthorizationApprovalCaseResponse{}, err
	}
	defer events.Close()
	response := AuthorizationApprovalCaseResponse{
		ID:                          uuidToString(row.ID),
		WorkspaceID:                 uuidToString(row.WorkspaceID),
		RequesterPrincipalType:      row.RequesterPrincipalType,
		RequesterPrincipalID:        row.RequesterPrincipalID,
		RequesterCredentialClass:    row.RequesterCredentialClass,
		RequesterSessionID:          uuidToString(row.RequesterSessionID),
		OriginatorUserID:            uuidToString(row.OriginatorUserID),
		DesignatedApproverUserID:    uuidToString(row.DesignatedApproverUserID),
		Action:                      row.Action,
		ResourceType:                row.ResourceType,
		ResourceID:                  uuidToString(row.ResourceID),
		ReasonCode:                  row.ReasonCode,
		Status:                      row.Status,
		Decision:                    row.Decision.String,
		DeliveredAt:                 approvalTime(row.DeliveredAt),
		AcknowledgedAt:              approvalTime(row.AcknowledgedAt),
		DecidedAt:                   approvalTime(row.DecidedAt),
		AppliedAt:                   approvalTime(row.AppliedAt),
		ResolvedAt:                  approvalTime(row.ResolvedAt),
		CreatedAt:                   approvalTime(row.CreatedAt),
		UpdatedAt:                   approvalTime(row.UpdatedAt),
		RequestingMachineCanApprove: false,
		Events:                      []AuthorizationApprovalCaseEventResponse{},
	}
	for events.Next() {
		var event AuthorizationApprovalCaseEventResponse
		var sessionID pgtype.UUID
		var createdAt pgtype.Timestamptz
		if err := events.Scan(
			&event.ID, &event.EventType, &event.ActorPrincipalType, &event.ActorPrincipalID,
			&event.ActorCredentialClass, &sessionID, &event.ReasonCode, &createdAt,
		); err != nil {
			return AuthorizationApprovalCaseResponse{}, err
		}
		event.ActorSessionID = uuidToString(sessionID)
		event.CreatedAt = approvalTime(createdAt)
		response.Events = append(response.Events, event)
	}
	return response, events.Err()
}
