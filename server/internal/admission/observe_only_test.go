package admission

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	requestidentity "github.com/multica-ai/multica/server/internal/identity"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

type fakeDecisionStore struct {
	params db.CreateAuthorizationDecisionParams
	err    error
}

func (s *fakeDecisionStore) CreateAuthorizationDecision(_ context.Context, params db.CreateAuthorizationDecisionParams) (db.AuthorizationDecision, error) {
	s.params = params
	if s.err != nil {
		return db.AuthorizationDecision{}, s.err
	}
	return db.AuthorizationDecision{ID: pgtype.UUID{Bytes: uuid.New(), Valid: true}}, nil
}

type fakeDryRunRecorder struct {
	path, credential, reason string
	calls                    int
}

func (r *fakeDryRunRecorder) RecordAuthorizationDryRunDenied(path, credential, reason string) {
	r.path, r.credential, r.reason = path, credential, reason
	r.calls++
}

func TestObserveOnlyEvaluatorPersistsDryRunDenyWithoutSensitivePayload(t *testing.T) {
	store := &fakeDecisionStore{}
	recorder := &fakeDryRunRecorder{}
	evaluator := NewObserveOnlyEvaluator(store, recorder)
	decision, err := evaluator.Evaluate(context.Background(), Request{
		Path:   PathMention,
		Action: ActionAgentInvoke,
		Identity: requestidentity.RequestIdentity{
			PrincipalType:   requestidentity.PrincipalMember,
			PrincipalID:     "01000000-0000-0000-0000-000000000001",
			CredentialClass: requestidentity.CredentialLegacyPersonalToken,
		},
		WorkspaceID: "02000000-0000-0000-0000-000000000002",
		IssueID:     "03000000-0000-0000-0000-000000000003",
		AgentID:     "04000000-0000-0000-0000-000000000004",
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision.Allowed || !decision.ObserveOnly || decision.ID == "" {
		t.Fatalf("unexpected decision: %+v", decision)
	}
	if decision.ReasonCode != "legacy_personal_token_requires_exchange" {
		t.Fatalf("reason = %q", decision.ReasonCode)
	}
	if store.params.Path != string(PathMention) || store.params.Action != string(ActionAgentInvoke) || store.params.WorkspaceID.Valid == false {
		t.Fatalf("persisted params = %+v", store.params)
	}
	if recorder.calls != 1 || recorder.path != string(PathMention) || recorder.credential != string(requestidentity.CredentialLegacyPersonalToken) {
		t.Fatalf("recorder = %+v", recorder)
	}
}

func TestObserveOnlyEvaluatorEnforcesSessionIntersectionInDryRun(t *testing.T) {
	base := Request{
		Path:        PathDirectChat,
		Action:      ActionAgentInvoke,
		WorkspaceID: "02000000-0000-0000-0000-000000000002",
		AgentID:     "04000000-0000-0000-0000-000000000004",
		Identity: requestidentity.RequestIdentity{
			PrincipalType:            requestidentity.PrincipalHarness,
			PrincipalID:              "01000000-0000-0000-0000-000000000001",
			CredentialClass:          requestidentity.CredentialHarnessSession,
			SessionID:                "01000000-0000-0000-0000-000000000001",
			WorkspaceID:              "02000000-0000-0000-0000-000000000002",
			AllowedActions:           []string{string(ActionAgentInvoke)},
			AllowedChildPrincipalIDs: []string{"04000000-0000-0000-0000-000000000004"},
		},
	}

	decision, err := NewObserveOnlyEvaluator(&fakeDecisionStore{}, nil).Evaluate(context.Background(), base)
	if err != nil || !decision.Allowed || decision.ReasonCode != "session_scope_allow" {
		t.Fatalf("allowed session decision = %+v, err=%v", decision, err)
	}

	base.Identity.ExplicitDenies = []string{string(ActionAgentInvoke)}
	decision, err = NewObserveOnlyEvaluator(&fakeDecisionStore{}, nil).Evaluate(context.Background(), base)
	if err != nil || decision.Allowed || decision.ReasonCode != "session_explicit_deny" {
		t.Fatalf("explicit deny decision = %+v, err=%v", decision, err)
	}
}

func TestObserveOnlyEvaluatorFailsClosedWhenLedgerUnavailable(t *testing.T) {
	store := &fakeDecisionStore{err: errors.New("db unavailable")}
	_, err := NewObserveOnlyEvaluator(store, nil).Evaluate(context.Background(), Request{Path: PathChat, Action: ActionAgentInvoke})
	if err == nil {
		t.Fatal("expected persistence failure")
	}
}

func TestCredentialEnforcementRejectsLegacyPersonalToken(t *testing.T) {
	store := &fakeDecisionStore{}
	decision, err := NewEvaluator(store, nil, true).Evaluate(context.Background(), Request{
		Path: PathIssueAssignee, Action: ActionAgentInvoke,
		Identity: requestidentity.RequestIdentity{PrincipalType: requestidentity.PrincipalMember, CredentialClass: requestidentity.CredentialLegacyPersonalToken},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision.Allowed || decision.ObserveOnly {
		t.Fatalf("enforced legacy decision=%+v", decision)
	}
}

func TestDelegationRequiresBothActionsDepthAndNamedChild(t *testing.T) {
	childID := "04000000-0000-0000-0000-000000000004"
	base := Request{
		Path: PathMention, Action: ActionAgentDelegate,
		WorkspaceID: "02000000-0000-0000-0000-000000000002",
		AgentID:     childID,
		Identity: requestidentity.RequestIdentity{
			PrincipalType:            requestidentity.PrincipalHarness,
			CredentialClass:          requestidentity.CredentialHarnessSession,
			SessionID:                "01000000-0000-0000-0000-000000000001",
			WorkspaceID:              "02000000-0000-0000-0000-000000000002",
			LineageID:                "03000000-0000-0000-0000-000000000003",
			AllowedActions:           []string{string(ActionAgentInvoke), string(ActionAgentDelegate)},
			AllowedChildPrincipalIDs: []string{childID},
			CapabilityEnvelope:       true,
		},
	}

	decision, err := NewObserveOnlyEvaluator(&fakeDecisionStore{}, nil).Evaluate(context.Background(), base)
	if err != nil || decision.Allowed || decision.ObserveOnly || decision.ReasonCode != "delegation_depth_exhausted" {
		t.Fatalf("depth-zero decision=%+v err=%v", decision, err)
	}

	base.Identity.MaxDelegationDepth = 1
	base.Identity.AllowedChildPrincipalIDs = []string{"05000000-0000-0000-0000-000000000005"}
	decision, err = NewObserveOnlyEvaluator(&fakeDecisionStore{}, nil).Evaluate(context.Background(), base)
	if err != nil || decision.Allowed || decision.ReasonCode != "child_principal_not_granted" {
		t.Fatalf("wrong-child decision=%+v err=%v", decision, err)
	}

	store := &fakeDecisionStore{}
	base.Identity.AllowedChildPrincipalIDs = []string{childID}
	decision, err = NewObserveOnlyEvaluator(store, nil).Evaluate(context.Background(), base)
	if err != nil || !decision.Allowed || !decision.DelegationConsumed {
		t.Fatalf("bounded delegation decision=%+v err=%v", decision, err)
	}
	if !store.params.CapabilityEnvelope || !store.params.DelegationConsumed || store.params.DelegationDepthRemaining.Int32 != 1 {
		t.Fatalf("persisted delegation envelope=%+v", store.params)
	}
}
