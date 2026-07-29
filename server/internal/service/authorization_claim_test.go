package service

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/multica-ai/multica/server/internal/admission"
	"github.com/multica-ai/multica/server/internal/events"
	"github.com/multica-ai/multica/server/internal/util"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

type claimAuthorizationFixture struct {
	workspaceID string
	userID      string
	agentID     string
	issueID     string
	taskID      pgtype.UUID
}

// authorizeTaskForClaim upgrades a deliberately low-level test fixture into a
// claimable V1 row. Tests that omit this helper are explicitly exercising the
// fail-closed missing-metadata invariant.
func authorizeTaskForClaim(t *testing.T, pool *pgxpool.Pool, taskID any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		WITH decision AS (
			INSERT INTO authorization_decision (
				path, action, principal_type, principal_id, credential_class,
				workspace_id, project_id, issue_id, agent_id,
				allowed, reason_code, policy_version, observe_only, lineage_id
			)
			SELECT
				CASE
					WHEN t.chat_session_id IS NOT NULL THEN 'chat'
					WHEN t.autopilot_run_id IS NOT NULL THEN 'autopilot'
					WHEN t.issue_id IS NOT NULL THEN 'issue_assignee'
					ELSE 'quick_create'
				END,
				'agent:invoke', 'agent', t.agent_id, 'agent_task_token',
				a.workspace_id, i.project_id, t.issue_id, t.agent_id,
				TRUE, 'test_fixture_allow', 'observe-v1', FALSE, gen_random_uuid()
			FROM agent_task_queue t
			JOIN agent a ON a.id = t.agent_id
			LEFT JOIN issue i ON i.id = t.issue_id
			WHERE t.id = $1
			RETURNING id, policy_version, lineage_id
		), budget AS (
			INSERT INTO authorization_lineage_budget (
				lineage_id, workspace_id, execution_limit, reserved_executions
			)
			SELECT d.lineage_id, a.workspace_id, 64, 1
			FROM decision d
			JOIN agent_task_queue t ON t.id = $1
			JOIN agent a ON a.id = t.agent_id
			RETURNING lineage_id
		), reservation AS (
			INSERT INTO authorization_budget_reservation (
				lineage_id, admission_decision_id, generation, task_id,
				expires_at
			)
			SELECT d.lineage_id, d.id, 1, $1, now() + interval '100 years'
			FROM decision d
			RETURNING id, admission_decision_id
		)
		UPDATE agent_task_queue t
		SET admission_decision_id = d.id,
			authorization_policy_version = d.policy_version,
			lineage_id = d.lineage_id,
			budget_reservation_id = r.id
		FROM decision d
		JOIN reservation r ON r.admission_decision_id = d.id
		WHERE t.id = $1
	`, taskID); err != nil {
		t.Fatalf("authorize task fixture for claim: %v", err)
	}
}

func seedClaimAuthorizationTask(t *testing.T, pool *pgxpool.Pool, withMetadata bool, delegated ...bool) claimAuthorizationFixture {
	t.Helper()
	ctx := context.Background()
	workspaceID, userID, agentID, issueID := seedAttributionFixture(t, pool)

	var runtimeID string
	if err := pool.QueryRow(ctx, `SELECT runtime_id::text FROM agent WHERE id = $1`, agentID).Scan(&runtimeID); err != nil {
		t.Fatalf("read runtime: %v", err)
	}

	var decisionID, lineageID, budgetReservationID any
	if withMetadata {
		action := string(admission.ActionAgentInvoke)
		principalID := agentID
		allowedActions := []string{}
		depth := int32(0)
		children := []string{}
		capabilityEnvelope := false
		delegationConsumed := false
		if len(delegated) > 0 && delegated[0] {
			action = string(admission.ActionAgentDelegate)
			principalID = "05000000-0000-0000-0000-000000000005"
			allowedActions = []string{string(admission.ActionAgentInvoke), string(admission.ActionAgentDelegate)}
			depth = 1
			children = []string{agentID}
			capabilityEnvelope = true
			delegationConsumed = true
		}
		var decision, lineage string
		if err := pool.QueryRow(ctx, `
			INSERT INTO authorization_decision (
				path, action, principal_type, principal_id, credential_class,
				workspace_id, issue_id, agent_id, allowed, reason_code,
				policy_version, observe_only, lineage_id, allowed_actions,
				delegation_depth_remaining, allowed_child_principal_ids,
				capability_envelope, delegation_consumed
			)
			VALUES ('issue_assignee', $4, 'agent', $5, 'agent_task_token',
				$2, $3, $1, TRUE, 'fixture_allow', 'observe-v1', FALSE, gen_random_uuid(),
				$6, $7, $8, $9, $10)
			RETURNING id::text, lineage_id::text
		`, agentID, workspaceID, issueID, action, principalID, allowedActions, depth, children, capabilityEnvelope, delegationConsumed).Scan(&decision, &lineage); err != nil {
			t.Fatalf("insert admission decision: %v", err)
		}
		decisionID, lineageID = decision, lineage
		if err := pool.QueryRow(ctx, `
			WITH budget AS (
				INSERT INTO authorization_lineage_budget (
					lineage_id, workspace_id, execution_limit, reserved_executions
				)
				VALUES ($1, $2, 64, 1)
				RETURNING lineage_id
			)
			INSERT INTO authorization_budget_reservation (
				lineage_id, admission_decision_id, generation,
				expires_at
			)
			VALUES ($1, $3, 1, now() + interval '100 years')
			RETURNING id::text
		`, lineageID, workspaceID, decisionID).Scan(&budgetReservationID); err != nil {
			t.Fatalf("insert budget reservation: %v", err)
		}
	}

	var taskID pgtype.UUID
	if err := pool.QueryRow(ctx, `
		INSERT INTO agent_task_queue (
			agent_id, runtime_id, issue_id, status, priority,
			originator_user_id, accountable_user_id, originator_source,
			trigger_evidence_kind, trigger_evidence_ref_id,
			admission_decision_id, authorization_policy_version, lineage_id,
			budget_reservation_id
		)
		VALUES ($1, $2, $3, 'queued', 1,
			$4, $4, 'direct_human', 'issue_assignment', $3,
			$5, CASE WHEN $5::uuid IS NULL THEN NULL ELSE 'observe-v1' END, $6, $7)
		RETURNING id
	`, agentID, runtimeID, issueID, userID, decisionID, lineageID, budgetReservationID).Scan(&taskID); err != nil {
		t.Fatalf("insert queued task: %v", err)
	}
	return claimAuthorizationFixture{workspaceID: workspaceID, userID: userID, agentID: agentID, issueID: issueID, taskID: taskID}
}

func claimAuthorizationService(pool *pgxpool.Pool) *TaskService {
	q := db.New(pool)
	return &TaskService{
		Queries:   q,
		TxStarter: pool,
		Bus:       events.New(),
		Admission: admission.NewEvaluator(q, nil, false),
	}
}

func TestClaimRejectsTaskMissingAuthorizationMetadata(t *testing.T) {
	pool := newResolveOriginatorPool(t)
	fixture := seedClaimAuthorizationTask(t, pool, false)
	svc := claimAuthorizationService(pool)

	claimed, err := svc.ClaimTask(context.Background(), util.MustParseUUID(fixture.agentID))
	if err != nil {
		t.Fatalf("ClaimTask: %v", err)
	}
	if claimed != nil {
		t.Fatalf("claimed task without authorization metadata: %s", util.UUIDToString(claimed.ID))
	}

	var status, failureReason string
	if err := pool.QueryRow(context.Background(), `SELECT status, failure_reason FROM agent_task_queue WHERE id = $1`, fixture.taskID).Scan(&status, &failureReason); err != nil {
		t.Fatalf("read denied task: %v", err)
	}
	if status != "cancelled" || failureReason != "authorization_denied" {
		t.Fatalf("task status=%q failure_reason=%q", status, failureReason)
	}
	var reason, phase string
	if err := pool.QueryRow(context.Background(), `
		SELECT reason_code, evaluation_phase
		FROM authorization_decision
		WHERE task_id = $1
		ORDER BY created_at DESC LIMIT 1
	`, fixture.taskID).Scan(&reason, &phase); err != nil {
		t.Fatalf("read claim decision: %v", err)
	}
	if reason != "task_authorization_metadata_missing" || phase != "claim" {
		t.Fatalf("claim decision reason=%q phase=%q", reason, phase)
	}
}

func TestClaimReauthorizesAgainstPolicyPublishedAfterAdmission(t *testing.T) {
	pool := newResolveOriginatorPool(t)
	fixture := seedClaimAuthorizationTask(t, pool, true)
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM authorization_policy_current WHERE workspace_id = $1`, fixture.workspaceID)
	})

	var policyID string
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO authorization_policy_version (
			workspace_id, scope_type, scope_key, version, enforcement_mode,
			created_by_user_id, reason
		)
		VALUES ($1::uuid, 'workspace', $1::text, 1, 'enforce', $2, 'claim-time stale-policy test')
		RETURNING id
	`, fixture.workspaceID, fixture.userID).Scan(&policyID); err != nil {
		t.Fatalf("insert policy version: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO authorization_policy_assertion (
			policy_version_id, effect, action, subject_type, subject_value, reason_code
		)
		VALUES ($1, 'deny', 'agent:invoke', 'agent', $2, 'claim.current_policy_denied')
	`, policyID, fixture.agentID); err != nil {
		t.Fatalf("insert policy assertion: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO authorization_policy_current (
			workspace_id, scope_type, scope_key, policy_version_id, version, enforcement_mode
		)
		VALUES ($1::uuid, 'workspace', $1::text, $2, 1, 'enforce')
	`, fixture.workspaceID, policyID); err != nil {
		t.Fatalf("materialize current policy: %v", err)
	}

	claimed, err := claimAuthorizationService(pool).ClaimTask(context.Background(), util.MustParseUUID(fixture.agentID))
	if err != nil {
		t.Fatalf("ClaimTask: %v", err)
	}
	if claimed != nil {
		t.Fatalf("claimed task denied by current policy: %s", util.UUIDToString(claimed.ID))
	}

	var status, reason, phase string
	if err := pool.QueryRow(context.Background(), `
		SELECT t.status, d.reason_code, d.evaluation_phase
		FROM agent_task_queue t
		JOIN authorization_decision d ON d.task_id = t.id
		WHERE t.id = $1 AND d.evaluation_phase = 'claim'
		ORDER BY d.created_at DESC LIMIT 1
	`, fixture.taskID).Scan(&status, &reason, &phase); err != nil {
		t.Fatalf("read claim result: %v", err)
	}
	if status != "cancelled" || reason != "claim.current_policy_denied" || phase != "claim" {
		t.Fatalf("claim result status=%q reason=%q phase=%q", status, reason, phase)
	}
}

func TestClaimDispatchesOnlyAfterCurrentPolicyDecision(t *testing.T) {
	pool := newResolveOriginatorPool(t)
	fixture := seedClaimAuthorizationTask(t, pool, true)

	claimed, err := claimAuthorizationService(pool).ClaimTask(context.Background(), util.MustParseUUID(fixture.agentID))
	if err != nil {
		t.Fatalf("ClaimTask: %v", err)
	}
	if claimed == nil || claimed.Status != "dispatched" {
		t.Fatalf("claimed=%+v, want dispatched", claimed)
	}
	var allowed bool
	var phase string
	if err := pool.QueryRow(context.Background(), `
		SELECT allowed, evaluation_phase
		FROM authorization_decision
		WHERE task_id = $1
		ORDER BY created_at DESC LIMIT 1
	`, fixture.taskID).Scan(&allowed, &phase); err != nil {
		t.Fatalf("read claim decision: %v", err)
	}
	if !allowed || phase != "claim" {
		t.Fatalf("claim decision allowed=%v phase=%q", allowed, phase)
	}
}

func TestDelegatedClaimMintsReducedTaskTokenEnvelope(t *testing.T) {
	pool := newResolveOriginatorPool(t)
	fixture := seedClaimAuthorizationTask(t, pool, true, true)
	svc := claimAuthorizationService(pool)

	claimed, err := svc.ClaimTask(context.Background(), util.MustParseUUID(fixture.agentID))
	if err != nil {
		t.Fatalf("ClaimTask: %v", err)
	}
	if claimed == nil || claimed.Status != "dispatched" {
		t.Fatalf("claimed=%+v, want dispatched", claimed)
	}

	tokenHash := "delegated-envelope-" + uuid.NewString()
	if _, err := svc.FinalizeTaskClaim(context.Background(), *claimed, db.CreateTaskTokenParams{
		TokenHash:   tokenHash,
		TaskID:      claimed.ID,
		AgentID:     claimed.AgentID,
		WorkspaceID: util.MustParseUUID(fixture.workspaceID),
		UserID:      util.MustParseUUID(fixture.userID),
		ExpiresAt:   pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true},
	}, nil, false); err != nil {
		t.Fatalf("FinalizeTaskClaim: %v", err)
	}

	token, err := db.New(pool).GetTaskTokenByHash(context.Background(), tokenHash)
	if err != nil {
		t.Fatalf("GetTaskTokenByHash: %v", err)
	}
	if !token.CapabilityEnvelope || !token.DelegationDepthRemaining.Valid || token.DelegationDepthRemaining.Int32 != 0 {
		t.Fatalf("delegated token envelope=%+v", token)
	}
	if util.UUIDToString(token.LineageID) != util.UUIDToString(claimed.LineageID) {
		t.Fatalf("token lineage=%s task lineage=%s", util.UUIDToString(token.LineageID), util.UUIDToString(claimed.LineageID))
	}
	if len(token.AllowedActions) != 2 || len(token.AllowedChildPrincipalIds) != 1 || util.UUIDToString(token.AllowedChildPrincipalIds[0]) != fixture.agentID {
		t.Fatalf("delegated token grants=%+v", token)
	}
}
