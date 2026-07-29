package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	requestidentity "github.com/multica-ai/multica/server/internal/identity"
	"github.com/multica-ai/multica/server/internal/util"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

func TestRunningTaskRevocationSeparatesServerDenialRequestRuntimeAckAndTermination(t *testing.T) {
	pool := newResolveOriginatorPool(t)
	ctx := context.Background()
	fixture := seedClaimAuthorizationTask(t, pool, true)
	svc := claimAuthorizationService(pool)
	q := db.New(pool)

	claimed, err := svc.ClaimTask(ctx, util.MustParseUUID(fixture.agentID))
	if err != nil || claimed == nil {
		t.Fatalf("ClaimTask: task=%+v err=%v", claimed, err)
	}
	running, err := svc.StartTask(ctx, claimed.ID)
	if err != nil {
		t.Fatalf("StartTask: %v", err)
	}
	if running.Status != "running" {
		t.Fatalf("started task status=%q", running.Status)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO task_token (
			token_hash, task_id, agent_id, workspace_id, user_id, expires_at
		)
		VALUES ($1,$2,$3,$4,$5,now()+interval '1 hour')
	`, "revocation-test-"+uuid.NewString(), running.ID, fixture.agentID, fixture.workspaceID, fixture.userID); err != nil {
		t.Fatalf("insert task token: %v", err)
	}

	requester := requestidentity.RequestIdentity{
		PrincipalType:   requestidentity.PrincipalHarness,
		PrincipalID:     uuid.NewString(),
		CredentialClass: requestidentity.CredentialHarnessSession,
		UserID:          fixture.userID,
		SessionID:       uuid.NewString(),
		WorkspaceID:     fixture.workspaceID,
	}
	requestCtx := requestidentity.WithRequest(ctx, requester)
	requested, err := svc.CancelTask(requestCtx, running.ID)
	if err != nil {
		t.Fatalf("CancelTask: %v", err)
	}
	if requested.Status != "running" || !requested.CancellationRequestedAt.Valid ||
		requested.CancellationRuntimeAcknowledgedAt.Valid || requested.TerminationConfirmedAt.Valid ||
		requested.CompletedAt.Valid {
		t.Fatalf("cancellation request overstated termination: %+v", requested)
	}
	var tokenCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM task_token WHERE task_id = $1`, running.ID).Scan(&tokenCount); err != nil {
		t.Fatalf("count task tokens: %v", err)
	}
	if tokenCount != 0 {
		t.Fatalf("server denial left %d task tokens active", tokenCount)
	}
	if _, err := q.CompleteAgentTask(ctx, db.CompleteAgentTaskParams{ID: running.ID}); err != pgx.ErrNoRows {
		t.Fatalf("completion after cancellation request error=%v, want pgx.ErrNoRows", err)
	}

	revocation, err := q.GetAuthorizationTaskRevocationByTask(ctx, running.ID)
	if err != nil {
		t.Fatalf("GetAuthorizationTaskRevocationByTask: %v", err)
	}
	if revocation.Status != "cancellation_requested" || !revocation.ServerDeniedAt.Valid ||
		!revocation.CancellationRequestedAt.Valid || revocation.RuntimeAcknowledgedAt.Valid ||
		revocation.TerminatedAt.Valid {
		t.Fatalf("requested revocation=%+v", revocation)
	}
	events, err := q.ListAuthorizationTaskRevocationEvents(ctx, revocation.ID)
	if err != nil {
		t.Fatalf("list request events: %v", err)
	}
	if len(events) != 2 || events[0].EventType != "server_denied" || events[1].EventType != "cancellation_requested" {
		t.Fatalf("request events=%+v", events)
	}
	if err := svc.CancelTasksForIssue(requestCtx, running.IssueID); !errors.Is(err, ErrTaskTerminationPending) {
		t.Fatalf("bulk issue cancellation error=%v, want ErrTaskTerminationPending", err)
	}
	events, _ = q.ListAuthorizationTaskRevocationEvents(ctx, revocation.ID)
	if len(events) != 2 {
		t.Fatalf("idempotent bulk request appended events: %+v", events)
	}

	runtime := requestidentity.RequestIdentity{
		PrincipalType:   requestidentity.PrincipalRuntime,
		PrincipalID:     uuid.NewString(),
		CredentialClass: requestidentity.CredentialDaemonToken,
		WorkspaceID:     fixture.workspaceID,
	}
	runtimeCtx := requestidentity.WithRequest(ctx, runtime)
	acknowledged, err := svc.AcknowledgeTaskCancellation(runtimeCtx, running.ID)
	if err != nil {
		t.Fatalf("AcknowledgeTaskCancellation: %v", err)
	}
	if acknowledged.Status != "running" || !acknowledged.CancellationRuntimeAcknowledgedAt.Valid ||
		acknowledged.TerminationConfirmedAt.Valid || acknowledged.CompletedAt.Valid {
		t.Fatalf("runtime acknowledgement overstated termination: %+v", acknowledged)
	}
	revocation, _ = q.GetAuthorizationTaskRevocationByTask(ctx, running.ID)
	events, _ = q.ListAuthorizationTaskRevocationEvents(ctx, revocation.ID)
	if revocation.Status != "runtime_acknowledged" || len(events) != 3 ||
		events[2].EventType != "runtime_acknowledged" {
		t.Fatalf("acknowledged revocation=%+v events=%+v", revocation, events)
	}

	beforeTermination := time.Now()
	terminated, err := svc.ConfirmTaskTermination(runtimeCtx, running.ID)
	if err != nil {
		t.Fatalf("ConfirmTaskTermination: %v", err)
	}
	if terminated.Status != "cancelled" || !terminated.TerminationConfirmedAt.Valid ||
		!terminated.CompletedAt.Valid || terminated.TerminationConfirmedAt.Time.Before(beforeTermination) {
		t.Fatalf("terminated task=%+v", terminated)
	}
	revocation, _ = q.GetAuthorizationTaskRevocationByTask(ctx, running.ID)
	events, _ = q.ListAuthorizationTaskRevocationEvents(ctx, revocation.ID)
	if revocation.Status != "terminated" || !revocation.TerminatedAt.Valid ||
		len(events) != 4 || events[3].EventType != "terminated" {
		t.Fatalf("terminated revocation=%+v events=%+v", revocation, events)
	}

	if _, err := svc.ConfirmTaskTermination(runtimeCtx, running.ID); err != nil {
		t.Fatalf("idempotent ConfirmTaskTermination: %v", err)
	}
	events, _ = q.ListAuthorizationTaskRevocationEvents(ctx, revocation.ID)
	if len(events) != 4 {
		t.Fatalf("idempotent termination appended events: %+v", events)
	}

	if _, err := pool.Exec(ctx,
		`UPDATE authorization_task_revocation_event SET reason_code = 'rewritten' WHERE revocation_id = $1`,
		revocation.ID,
	); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("revocation event mutation error=%v, want append-only rejection", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE authorization_task_revocation SET server_denied_at = now() + interval '1 minute' WHERE id = $1`,
		revocation.ID,
	); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("revocation fact mutation error=%v, want immutable rejection", err)
	}
}
