package admission

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	requestidentity "github.com/multica-ai/multica/server/internal/identity"
	"github.com/multica-ai/multica/server/internal/util"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

type DecisionStore interface {
	CreateAuthorizationDecision(context.Context, db.CreateAuthorizationDecisionParams) (db.AuthorizationDecision, error)
}

type DryRunRecorder interface {
	RecordAuthorizationDryRunDenied(path, credentialClass, reasonCode string)
}

type ExplicitDenyStore interface {
	FindAuthorizationExplicitDeny(context.Context, db.FindAuthorizationExplicitDenyParams) (db.FindAuthorizationExplicitDenyRow, error)
}

// ObserveOnlyEvaluator records the policy result while preserving legacy task
// behavior. A denied dry-run decision is returned with ObserveOnly=true, so the
// common choke point continues dispatch during the migration window.
type ObserveOnlyEvaluator struct {
	store              DecisionStore
	policyStore        ExplicitDenyStore
	recorder           DryRunRecorder
	enforceCredentials bool
}

func NewObserveOnlyEvaluator(store DecisionStore, recorder DryRunRecorder) *ObserveOnlyEvaluator {
	return NewEvaluator(store, recorder, false)
}

func NewEvaluator(store DecisionStore, recorder DryRunRecorder, enforceCredentials bool) *ObserveOnlyEvaluator {
	e := &ObserveOnlyEvaluator{store: store, recorder: recorder, enforceCredentials: enforceCredentials}
	if policyStore, ok := store.(ExplicitDenyStore); ok {
		e.policyStore = policyStore
	}
	return e
}

// WithStore preserves the evaluator's enforcement configuration while binding
// all policy reads and decision writes to one transaction-scoped query set.
// Claim-time re-authorization uses this so the current-policy read, immutable
// decision append, and queued-to-dispatched transition commit atomically.
func (e *ObserveOnlyEvaluator) WithStore(store DecisionStore) *ObserveOnlyEvaluator {
	if e == nil {
		return nil
	}
	return NewEvaluator(store, e.recorder, e.enforceCredentials)
}

func (e *ObserveOnlyEvaluator) Evaluate(ctx context.Context, req Request) (Decision, error) {
	if req.Phase == "" {
		req.Phase = "admission"
	}
	if req.Phase != "admission" && req.Phase != "claim" && req.Phase != "reclaim" {
		return Decision{}, fmt.Errorf("unknown authorization evaluation phase %q", req.Phase)
	}
	if req.Identity.LineageID == "" {
		req.Identity.LineageID = uuid.NewString()
	} else if _, err := uuid.Parse(req.Identity.LineageID); err != nil {
		return Decision{}, fmt.Errorf("invalid authorization lineage: %w", err)
	}
	allowed, reason := evaluateCredentialScope(req)
	observeOnly := true
	if req.PreconditionFailure != "" {
		allowed = false
		reason = req.PreconditionFailure
		observeOnly = false
	} else if !allowed && isDelegatedSession(req.Identity.CredentialClass) {
		observeOnly = false
	} else if !allowed && e.enforceCredentials {
		observeOnly = false
	}
	policyVersion := "observe-v1"
	if req.Identity.PolicyVersion > 0 {
		policyVersion = fmt.Sprintf("session-v%d", req.Identity.PolicyVersion)
	}
	if e.policyStore != nil && req.PreconditionFailure == "" {
		for _, action := range requiredActions(req.Action) {
			deny, err := e.policyStore.FindAuthorizationExplicitDeny(ctx, db.FindAuthorizationExplicitDenyParams{
				AgentID:         nullableUUID(req.AgentID),
				WorkspaceID:     nullableUUID(req.WorkspaceID),
				Action:          string(action),
				ProjectID:       req.ProjectID,
				CredentialClass: pgtype.Text{String: normalizedIdentityValue(string(req.Identity.CredentialClass)), Valid: true},
				PrincipalType:   pgtype.Text{String: normalizedIdentityValue(string(req.Identity.PrincipalType)), Valid: true},
			})
			switch {
			case err == nil:
				allowed = false
				reason = deny.ReasonCode
				policyVersion = fmt.Sprintf("policy-v%d", deny.Version)
				observeOnly = deny.EnforcementMode != "enforce"
			case errors.Is(err, pgx.ErrNoRows):
				continue
			default:
				return Decision{}, fmt.Errorf("evaluate authorization policy: %w", err)
			}
			break
		}
	}
	capabilityEnvelope := isDelegatedSession(req.Identity.CredentialClass) || req.Identity.CapabilityEnvelope
	decision := Decision{
		LineageID:          req.Identity.LineageID,
		DelegationConsumed: req.Action == ActionAgentDelegate,
		Allowed:            allowed,
		ReasonCode:         reason,
		PolicyVersion:      policyVersion,
		ObserveOnly:        observeOnly,
	}
	if e == nil || e.store == nil {
		return Decision{}, fmt.Errorf("authorization decision store unavailable")
	}
	row, err := e.store.CreateAuthorizationDecision(ctx, db.CreateAuthorizationDecisionParams{
		Path:                     string(req.Path),
		Action:                   string(req.Action),
		PrincipalType:            normalizedIdentityValue(string(req.Identity.PrincipalType)),
		PrincipalID:              nullableUUID(req.Identity.PrincipalID),
		CredentialClass:          normalizedIdentityValue(string(req.Identity.CredentialClass)),
		SessionID:                nullableUUID(req.Identity.SessionID),
		WorkspaceID:              nullableUUID(req.WorkspaceID),
		ProjectID:                nullableUUID(req.ProjectID),
		IssueID:                  nullableUUID(req.IssueID),
		AgentID:                  nullableUUID(req.AgentID),
		ParentTaskID:             nullableUUID(req.ParentTaskID),
		Allowed:                  decision.Allowed,
		ReasonCode:               decision.ReasonCode,
		PolicyVersion:            decision.PolicyVersion,
		ObserveOnly:              decision.ObserveOnly,
		LineageID:                nullableUUID(decision.LineageID),
		EvaluationPhase:          req.Phase,
		TaskID:                   nullableUUID(req.TaskID),
		AllowedActions:           authorizationStrings(req.Identity.AllowedActions),
		ExplicitDenies:           authorizationStrings(req.Identity.ExplicitDenies),
		DelegationDepthRemaining: pgtype.Int4{Int32: req.Identity.MaxDelegationDepth, Valid: capabilityEnvelope},
		AllowedChildPrincipalIds: nullableUUIDs(req.Identity.AllowedChildPrincipalIDs),
		CapabilityEnvelope:       capabilityEnvelope,
		DelegationConsumed:       decision.DelegationConsumed,
	})
	if err != nil {
		return Decision{}, fmt.Errorf("persist authorization decision: %w", err)
	}
	decision.ID = util.UUIDToString(row.ID)
	decision.LineageID = util.UUIDToString(row.LineageID)
	if !allowed && decision.ObserveOnly && e.recorder != nil {
		e.recorder.RecordAuthorizationDryRunDenied(string(req.Path), normalizedIdentityValue(string(req.Identity.CredentialClass)), reason)
	}
	return decision, nil
}

func isDelegatedSession(class requestidentity.CredentialClass) bool {
	return class == requestidentity.CredentialHarnessSession || class == requestidentity.CredentialHumanInteractive
}

func evaluateCredentialScope(req Request) (bool, string) {
	if !ValidPath(req.Path) {
		return false, "unknown_dispatch_path"
	}
	if !ValidAction(req.Action) {
		return false, "unknown_action"
	}
	id := req.Identity
	switch id.CredentialClass {
	case requestidentity.CredentialHarnessSession:
		if id.PrincipalType != requestidentity.PrincipalHarness || id.SessionID == "" {
			return false, "invalid_harness_identity"
		}
		if id.WorkspaceID == "" || id.WorkspaceID != req.WorkspaceID {
			return false, "session_workspace_mismatch"
		}
		if id.ProjectID != "" && id.ProjectID != req.ProjectID {
			return false, "session_project_mismatch"
		}
		if id.IssueID != "" && id.IssueID != req.IssueID {
			return false, "session_issue_mismatch"
		}
		if ok, reason := evaluateGrantedActions(id, req.Action); !ok {
			return false, reason
		}
		if req.Action == ActionAgentInvoke && !containsString(id.AllowedChildPrincipalIDs, req.AgentID) {
			return false, "invocation_principal_not_granted"
		}
		if req.Action == ActionAgentDelegate {
			if id.MaxDelegationDepth <= 0 {
				return false, "delegation_depth_exhausted"
			}
			if !containsString(id.AllowedChildPrincipalIDs, req.AgentID) {
				return false, "child_principal_not_granted"
			}
		}
		return true, "session_scope_allow"
	case requestidentity.CredentialHumanInteractive:
		if id.PrincipalType != requestidentity.PrincipalMember || id.SessionID == "" {
			return false, "invalid_human_interactive_identity"
		}
		if id.WorkspaceID != "" && id.WorkspaceID != req.WorkspaceID {
			return false, "session_workspace_mismatch"
		}
		if containsAction(id.ExplicitDenies, req.Action) {
			return false, "session_explicit_deny"
		}
		if !containsAction(id.AllowedActions, req.Action) {
			return false, "session_action_not_granted"
		}
		return true, "interactive_session_allow"
	case requestidentity.CredentialAgentTaskToken:
		if req.Action == ActionAgentDelegate && !id.CapabilityEnvelope {
			return false, "legacy_task_token_delegation_requires_envelope"
		}
		if id.CapabilityEnvelope {
			if id.WorkspaceID == "" || id.WorkspaceID != req.WorkspaceID {
				return false, "task_token_workspace_mismatch"
			}
			if id.ProjectID != "" && id.ProjectID != req.ProjectID {
				return false, "task_token_project_mismatch"
			}
			if id.IssueID != "" && id.IssueID != req.IssueID {
				return false, "task_token_issue_mismatch"
			}
			if ok, reason := evaluateGrantedActions(id, req.Action); !ok {
				return false, reason
			}
			if req.Action == ActionAgentDelegate {
				if id.MaxDelegationDepth <= 0 {
					return false, "delegation_depth_exhausted"
				}
				if !containsString(id.AllowedChildPrincipalIDs, req.AgentID) {
					return false, "child_principal_not_granted"
				}
			}
		}
		return true, "legacy_agent_task_compatibility_allow"
	case requestidentity.CredentialAutopilotTrigger:
		return true, "legacy_autopilot_compatibility_allow"
	case requestidentity.CredentialLegacyPersonalToken:
		return false, "legacy_personal_token_requires_exchange"
	case requestidentity.CredentialLegacyHumanSession:
		return false, "legacy_human_session_requires_exchange"
	case requestidentity.CredentialDaemonToken,
		requestidentity.CredentialCloudNodePAT:
		return false, "machine_credential_not_dispatch_authorized"
	default:
		return false, "unknown_credential_class"
	}
}

func requiredActions(action Action) []Action {
	if action == ActionAgentDelegate {
		return []Action{ActionAgentInvoke, ActionAgentDelegate}
	}
	return []Action{action}
}

func evaluateGrantedActions(id requestidentity.RequestIdentity, action Action) (bool, string) {
	for _, required := range requiredActions(action) {
		if containsAction(id.ExplicitDenies, required) {
			return false, "session_explicit_deny"
		}
		if !containsAction(id.AllowedActions, required) {
			return false, "session_action_not_granted"
		}
	}
	return true, ""
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func nullableUUIDs(values []string) []pgtype.UUID {
	out := make([]pgtype.UUID, 0, len(values))
	for _, value := range values {
		if parsed := nullableUUID(value); parsed.Valid {
			out = append(out, parsed)
		}
	}
	return out
}

func authorizationStrings(values []string) []string {
	return append(make([]string, 0, len(values)), values...)
}

func containsAction(values []string, action Action) bool {
	for _, value := range values {
		if value == string(action) {
			return true
		}
	}
	return false
}

func nullableUUID(value string) pgtype.UUID {
	if value == "" {
		return pgtype.UUID{}
	}
	parsed, err := util.ParseUUID(value)
	if err != nil {
		return pgtype.UUID{}
	}
	return parsed
}

func normalizedIdentityValue(value string) string {
	if value == "" {
		return "unknown"
	}
	return value
}
