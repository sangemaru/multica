package service

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/multica-ai/multica/server/internal/admission"
	"github.com/multica-ai/multica/server/internal/attribution"
	"github.com/multica-ai/multica/server/internal/events"
	requestidentity "github.com/multica-ai/multica/server/internal/identity"
	"github.com/multica-ai/multica/server/internal/util"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

func budgetAdmissionRequest(lineageID, workspaceID, agentID string) admission.Request {
	return admission.Request{
		Path:        admission.PathAutopilot,
		WorkspaceID: workspaceID,
		AgentID:     agentID,
		Identity: requestidentity.RequestIdentity{
			PrincipalType:   requestidentity.PrincipalAutopilot,
			PrincipalID:     uuid.NewString(),
			CredentialClass: requestidentity.CredentialAutopilotTrigger,
			WorkspaceID:     workspaceID,
			LineageID:       lineageID,
		},
	}
}

func createBudgetedQuickTask(
	t *testing.T,
	ctx context.Context,
	q *db.Queries,
	decision admission.Decision,
	userID, agentID string,
) db.AgentTaskQueue {
	t.Helper()
	agent, err := q.GetAgent(ctx, util.MustParseUUID(agentID))
	if err != nil {
		t.Fatalf("GetAgent: %v", err)
	}
	metadata, err := metadataFromAdmission(decision)
	if err != nil {
		t.Fatalf("metadataFromAdmission: %v", err)
	}
	task, err := q.CreateQuickCreateTask(ctx, db.CreateQuickCreateTaskParams{
		AgentID:                    agent.ID,
		RuntimeID:                  agent.RuntimeID,
		Priority:                   1,
		Context:                    []byte(`{"type":"quick_create","prompt":"opaque-test"}`),
		OriginatorUserID:           util.MustParseUUID(userID),
		AccountableUserID:          util.MustParseUUID(userID),
		OriginatorSource:           pgtype.Text{String: string(attribution.SourceDirectHuman), Valid: true},
		AdmissionDecisionID:        metadata.decisionID,
		AuthorizationPolicyVersion: metadata.policyVersion,
		LineageID:                  metadata.lineageID,
		BudgetReservationID:        metadata.budgetReservationID,
	})
	if err != nil {
		t.Fatalf("CreateQuickCreateTask: %v", err)
	}
	return task
}

func TestLineageBudgetConcurrentCapConsumeReleaseAndReset(t *testing.T) {
	pool := newResolveOriginatorPool(t)
	ctx := context.Background()
	q := db.New(pool)
	workspaceID, userID, agentID, _ := seedAttributionFixture(t, pool)
	lineageID := uuid.NewString()
	if _, err := pool.Exec(ctx, `
		INSERT INTO authorization_lineage_budget (lineage_id, workspace_id, execution_limit)
		VALUES ($1, $2, 2)
	`, lineageID, workspaceID); err != nil {
		t.Fatalf("seed lineage budget: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM agent_task_queue WHERE lineage_id = $1`, lineageID)
		pool.Exec(context.Background(), `DELETE FROM authorization_budget_reservation WHERE lineage_id = $1`, lineageID)
		pool.Exec(context.Background(), `DELETE FROM authorization_lineage_budget WHERE lineage_id = $1`, lineageID)
	})

	svc := &TaskService{
		Queries:   q,
		TxStarter: pool,
		Bus:       events.New(),
		Admission: admission.NewEvaluator(q, nil, false),
	}
	type result struct {
		decision admission.Decision
		err      error
	}
	results := make(chan result, 3)
	var workers sync.WaitGroup
	for range 3 {
		workers.Add(1)
		go func() {
			de, err := svc.AdmitTask(ctx, budgetAdmissionRequest(lineageID, workspaceID, agentID))
			results <- result{decision: de, err: err}
			workers.Done()
		}()
	}
	workers.Wait()
	close(results)

	var admitted []admission.Decision
	denied := 0
	for got := range results {
		switch {
		case got.err == nil:
			admitted = append(admitted, got.decision)
		case errors.Is(got.err, admission.ErrDenied) && got.decision.ReasonCode == "lineage_execution_budget_exhausted":
			denied++
		default:
			t.Fatalf("unexpected concurrent admission: decision=%+v err=%v", got.decision, got.err)
		}
	}
	if len(admitted) != 2 || denied != 1 {
		t.Fatalf("admitted=%d denied=%d, want 2/1", len(admitted), denied)
	}

	first := createBudgetedQuickTask(t, ctx, q, admitted[0], userID, agentID)
	second := createBudgetedQuickTask(t, ctx, q, admitted[1], userID, agentID)
	budget, err := q.GetAuthorizationLineageBudget(ctx, util.MustParseUUID(lineageID))
	if err != nil {
		t.Fatalf("GetAuthorizationLineageBudget: %v", err)
	}
	if budget.ReservedExecutions != 2 || budget.ConsumedExecutions != 0 || budget.BreakerState != "exhausted" {
		t.Fatalf("budget after bind=%+v", budget)
	}

	claimed, err := svc.ClaimTask(ctx, util.MustParseUUID(agentID))
	if err != nil {
		t.Fatalf("ClaimTask: %v", err)
	}
	if claimed == nil || (claimed.ID != first.ID && claimed.ID != second.ID) {
		t.Fatalf("claimed=%+v, want one budgeted task", claimed)
	}
	budget, _ = q.GetAuthorizationLineageBudget(ctx, util.MustParseUUID(lineageID))
	if budget.ReservedExecutions != 2 || budget.ConsumedExecutions != 0 {
		t.Fatalf("claim must preserve reservation until execution starts: %+v", budget)
	}
	if _, err := svc.StartTask(ctx, claimed.ID); err != nil {
		t.Fatalf("StartTask: %v", err)
	}

	otherID := first.ID
	if claimed.ID == first.ID {
		otherID = second.ID
	}
	if _, err := svc.CancelTask(ctx, otherID); err != nil {
		t.Fatalf("CancelTask: %v", err)
	}
	budget, _ = q.GetAuthorizationLineageBudget(ctx, util.MustParseUUID(lineageID))
	if budget.ReservedExecutions != 0 || budget.ConsumedExecutions != 1 || budget.BreakerState != "closed" {
		t.Fatalf("budget after consume/release=%+v", budget)
	}

	reset, err := q.ResetAuthorizationLineageBudget(ctx, db.ResetAuthorizationLineageBudgetParams{
		ExecutionLimit: 2,
		LineageID:      util.MustParseUUID(lineageID),
		ReasonCode:     "test_authorized_reset",
	})
	if err != nil {
		t.Fatalf("ResetAuthorizationLineageBudget: %v", err)
	}
	if reset.Generation != 2 || reset.ReservedExecutions != 0 || reset.ConsumedExecutions != 0 {
		t.Fatalf("reset budget=%+v", reset)
	}

	eventRows, err := q.ListAuthorizationBudgetEvents(ctx, util.MustParseUUID(lineageID))
	if err != nil {
		t.Fatalf("ListAuthorizationBudgetEvents: %v", err)
	}
	eventTypes := make(map[string]int)
	for _, event := range eventRows {
		eventTypes[event.EventType]++
	}
	for eventType, want := range map[string]int{"reserved": 2, "bound": 2, "consumed": 1, "released": 1, "reset": 1} {
		if eventTypes[eventType] != want {
			t.Fatalf("event %q count=%d want=%d; events=%+v", eventType, eventTypes[eventType], want, eventRows)
		}
	}
	if _, err := pool.Exec(ctx, `UPDATE authorization_budget_event SET reason_code = 'rewritten' WHERE lineage_id = $1`, lineageID); err == nil {
		t.Fatal("append-only budget event mutation unexpectedly succeeded")
	}
	if _, err := pool.Exec(ctx, `UPDATE agent_task_queue SET budget_reservation_id = NULL WHERE id = $1`, claimed.ID); err == nil {
		t.Fatal("task authorization metadata mutation unexpectedly succeeded")
	}
}

func TestLineageBudgetExpiresOrphanReservationBeforeNextAdmission(t *testing.T) {
	pool := newResolveOriginatorPool(t)
	ctx := context.Background()
	q := db.New(pool)
	workspaceID, _, agentID, _ := seedAttributionFixture(t, pool)
	lineageID := uuid.NewString()
	if _, err := pool.Exec(ctx, `
		INSERT INTO authorization_lineage_budget (lineage_id, workspace_id, execution_limit)
		VALUES ($1, $2, 1)
	`, lineageID, workspaceID); err != nil {
		t.Fatalf("seed lineage budget: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM agent_task_queue WHERE lineage_id = $1`, lineageID)
		pool.Exec(context.Background(), `DELETE FROM authorization_budget_reservation WHERE lineage_id = $1`, lineageID)
		pool.Exec(context.Background(), `DELETE FROM authorization_lineage_budget WHERE lineage_id = $1`, lineageID)
	})
	svc := &TaskService{
		Queries: q, TxStarter: pool, Bus: events.New(),
		Admission: admission.NewEvaluator(q, nil, false),
	}
	first, err := svc.AdmitTask(ctx, budgetAdmissionRequest(lineageID, workspaceID, agentID))
	if err != nil {
		t.Fatalf("first AdmitTask: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE authorization_budget_reservation
		SET expires_at = now() - interval '1 second'
		WHERE id = $1
	`, first.BudgetReservationID); err != nil {
		t.Fatalf("expire orphan reservation: %v", err)
	}
	second, err := svc.AdmitTask(ctx, budgetAdmissionRequest(lineageID, workspaceID, agentID))
	if err != nil {
		t.Fatalf("second AdmitTask after orphan expiry: %v", err)
	}
	firstReservation, err := q.GetAuthorizationBudgetReservation(ctx, util.MustParseUUID(first.BudgetReservationID))
	if err != nil {
		t.Fatalf("GetAuthorizationBudgetReservation: %v", err)
	}
	if firstReservation.Status != "expired" || second.BudgetReservationID == "" {
		t.Fatalf("first=%+v second=%+v", firstReservation, second)
	}
	metadata, err := metadataFromAdmission(second)
	if err != nil {
		t.Fatalf("metadataFromAdmission: %v", err)
	}
	svc.releaseUnboundAdmissionBudget(ctx, metadata, "test_cleanup")
	budget, err := q.GetAuthorizationLineageBudget(ctx, util.MustParseUUID(lineageID))
	if err != nil {
		t.Fatalf("GetAuthorizationLineageBudget: %v", err)
	}
	if budget.ReservedExecutions != 0 || budget.ConsumedExecutions != 0 || budget.BreakerState != "closed" {
		t.Fatalf("budget after orphan recovery=%+v", budget)
	}
}

func TestMentionRetryFallbackAndRerunShareParentLineageBudget(t *testing.T) {
	pool := newResolveOriginatorPool(t)
	ctx := context.Background()
	q := db.New(pool)
	workspaceID, userID, agentID, _ := seedAttributionFixture(t, pool)
	svc := &TaskService{
		Queries: q, TxStarter: pool, Bus: events.New(),
		Admission: admission.NewEvaluator(q, nil, false),
	}

	root, err := svc.AdmitTask(ctx, budgetAdmissionRequest(uuid.NewString(), workspaceID, agentID))
	if err != nil {
		t.Fatalf("root AdmitTask: %v", err)
	}
	rootTask := createBudgetedQuickTask(t, ctx, q, root, userID, agentID)
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM agent_task_queue WHERE lineage_id = $1`, root.LineageID)
		pool.Exec(context.Background(), `DELETE FROM authorization_budget_reservation WHERE lineage_id = $1`, root.LineageID)
		pool.Exec(context.Background(), `DELETE FROM authorization_lineage_budget WHERE lineage_id = $1`, root.LineageID)
	})

	requests := []admission.Request{
		{
			Path:        admission.PathMention,
			WorkspaceID: workspaceID,
			AgentID:     agentID,
			Identity: requestidentity.RequestIdentity{
				PrincipalType:   requestidentity.PrincipalAgent,
				PrincipalID:     agentID,
				CredentialClass: requestidentity.CredentialAgentTaskToken,
				AgentID:         agentID,
				TaskID:          util.UUIDToString(rootTask.ID),
				WorkspaceID:     workspaceID,
			},
		},
		{Path: admission.PathRetry, WorkspaceID: workspaceID, AgentID: agentID, ParentTaskID: util.UUIDToString(rootTask.ID)},
		{Path: admission.PathDeferredFallback, WorkspaceID: workspaceID, AgentID: agentID, ParentTaskID: util.UUIDToString(rootTask.ID)},
		{Path: admission.PathRerun, WorkspaceID: workspaceID, AgentID: agentID, ParentTaskID: util.UUIDToString(rootTask.ID)},
	}
	for _, req := range requests {
		decision, err := svc.AdmitTask(ctx, req)
		if err != nil {
			t.Fatalf("%s AdmitTask: %v", req.Path, err)
		}
		if decision.LineageID != root.LineageID {
			t.Fatalf("%s lineage=%s want=%s", req.Path, decision.LineageID, root.LineageID)
		}
		metadata, err := metadataFromAdmission(decision)
		if err != nil {
			t.Fatalf("%s metadata: %v", req.Path, err)
		}
		svc.releaseUnboundAdmissionBudget(ctx, metadata, "test_cleanup")
	}

	budget, err := q.GetAuthorizationLineageBudget(ctx, util.MustParseUUID(root.LineageID))
	if err != nil {
		t.Fatalf("GetAuthorizationLineageBudget: %v", err)
	}
	if budget.ReservedExecutions != 1 || budget.ConsumedExecutions != 0 {
		t.Fatalf("shared budget after child cleanup=%+v", budget)
	}
	if _, err := svc.CancelTask(ctx, rootTask.ID); err != nil {
		t.Fatalf("cancel root task: %v", err)
	}
}

func TestClaimRejectsTaskMissingOnlyBudgetReservation(t *testing.T) {
	pool := newResolveOriginatorPool(t)
	ctx := context.Background()
	workspaceID, userID, agentID, issueID := seedAttributionFixture(t, pool)
	var runtimeID string
	if err := pool.QueryRow(ctx, `SELECT runtime_id::text FROM agent WHERE id = $1`, agentID).Scan(&runtimeID); err != nil {
		t.Fatalf("read runtime: %v", err)
	}
	var taskID pgtype.UUID
	if err := pool.QueryRow(ctx, `
		WITH decision AS (
			INSERT INTO authorization_decision (
				path, action, principal_type, principal_id, credential_class,
				workspace_id, issue_id, agent_id, allowed, reason_code,
				policy_version, observe_only, lineage_id
			)
			VALUES ('issue_assignee', 'agent:invoke', 'agent', $1, 'agent_task_token',
				$2, $3, $1, TRUE, 'fixture_allow', 'observe-v1', FALSE, gen_random_uuid())
			RETURNING id, policy_version, lineage_id
		)
		INSERT INTO agent_task_queue (
			agent_id, runtime_id, issue_id, status, priority,
			originator_user_id, accountable_user_id, originator_source,
			trigger_evidence_kind, trigger_evidence_ref_id,
			admission_decision_id, authorization_policy_version, lineage_id
		)
		SELECT $1, $4, $3, 'queued', 1,
			$5, $5, 'direct_human', 'issue_assignment', $3,
			d.id, d.policy_version, d.lineage_id
		FROM decision d
		RETURNING id
	`, agentID, workspaceID, issueID, runtimeID, userID).Scan(&taskID); err != nil {
		t.Fatalf("insert task without budget reservation: %v", err)
	}
	claimed, err := claimAuthorizationService(pool).ClaimTask(ctx, util.MustParseUUID(agentID))
	if err != nil {
		t.Fatalf("ClaimTask: %v", err)
	}
	if claimed != nil {
		t.Fatalf("claimed task missing budget reservation: %+v", claimed)
	}
	var status, reason string
	if err := pool.QueryRow(ctx, `
		SELECT t.status, d.reason_code
		FROM agent_task_queue t
		JOIN authorization_decision d ON d.task_id = t.id
		WHERE t.id = $1 AND d.evaluation_phase = 'claim'
	`, taskID).Scan(&status, &reason); err != nil {
		t.Fatalf("read denied task: %v", err)
	}
	if status != "cancelled" || reason != "task_budget_reservation_missing" {
		t.Fatalf("status=%q reason=%q", status, reason)
	}
}
