package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	requestidentity "github.com/multica-ai/multica/server/internal/identity"
	"github.com/multica-ai/multica/server/internal/util"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
	"github.com/multica-ai/multica/server/pkg/protocol"
)

const defaultTaskCancellationReason = "task.cancellation_requested"

func taskCancellationRequester(ctx context.Context) requestidentity.RequestIdentity {
	if id, ok := requestidentity.FromContext(ctx); ok &&
		id.PrincipalType != "" && id.PrincipalID != "" && id.CredentialClass != "" {
		return id
	}
	return requestidentity.RequestIdentity{
		PrincipalType:   requestidentity.PrincipalService,
		PrincipalID:     "multica-server",
		CredentialClass: requestidentity.CredentialInternalService,
	}
}

func identityUUID(value string) pgtype.UUID {
	parsed, err := util.ParseUUID(value)
	if err != nil {
		return pgtype.UUID{}
	}
	return parsed
}

func createTaskRevocationEvent(
	ctx context.Context,
	q *db.Queries,
	revocation db.AuthorizationTaskRevocation,
	eventType string,
	actor requestidentity.RequestIdentity,
	reasonCode string,
) error {
	_, err := q.CreateAuthorizationTaskRevocationEvent(ctx, db.CreateAuthorizationTaskRevocationEventParams{
		RevocationID:         revocation.ID,
		TaskID:               revocation.TaskID,
		EventType:            eventType,
		ActorPrincipalType:   string(actor.PrincipalType),
		ActorPrincipalID:     actor.PrincipalID,
		ActorCredentialClass: string(actor.CredentialClass),
		ActorSessionID:       identityUUID(actor.SessionID),
		ReasonCode:           reasonCode,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	return err
}

// requestTaskCancellation denies further server access immediately but keeps a
// started task in its running state until the daemon separately acknowledges
// the request and confirms the local process has actually terminated.
func (s *TaskService) requestTaskCancellation(ctx context.Context, taskID pgtype.UUID) (db.AgentTaskQueue, error) {
	var out db.AgentTaskQueue
	err := s.runInTx(ctx, func(qtx *db.Queries) error {
		task, err := qtx.CancelAgentTask(ctx, taskID)
		if errors.Is(err, pgx.ErrNoRows) {
			task, err = qtx.GetAgentTask(ctx, taskID)
			if err != nil {
				return fmt.Errorf("cancel task: %w", err)
			}
			out = task
			return nil
		}
		if err != nil {
			return fmt.Errorf("cancel task: %w", err)
		}
		out = task

		// Server denial is immediate and independently true even while the host
		// process is still winding down.
		if err := qtx.DeleteTaskTokensByTask(ctx, task.ID); err != nil {
			return fmt.Errorf("deny cancelled task access: %w", err)
		}
		if !task.StartedAt.Valid || task.TerminationConfirmedAt.Valid {
			return nil
		}

		agent, err := qtx.GetAgent(ctx, task.AgentID)
		if err != nil {
			return fmt.Errorf("resolve cancelled task workspace: %w", err)
		}
		requester := taskCancellationRequester(ctx)
		revocation, err := qtx.CreateAuthorizationTaskRevocation(ctx, db.CreateAuthorizationTaskRevocationParams{
			TaskID:                     task.ID,
			WorkspaceID:                agent.WorkspaceID,
			RequestedByPrincipalType:   string(requester.PrincipalType),
			RequestedByPrincipalID:     requester.PrincipalID,
			RequestedByCredentialClass: string(requester.CredentialClass),
			RequestedBySessionID:       identityUUID(requester.SessionID),
			ReasonCode:                 defaultTaskCancellationReason,
			Status:                     "cancellation_requested",
		})
		created := err == nil
		if errors.Is(err, pgx.ErrNoRows) {
			revocation, err = qtx.GetAuthorizationTaskRevocationByTask(ctx, task.ID)
		}
		if err != nil {
			return fmt.Errorf("record task revocation: %w", err)
		}
		if !created {
			return nil
		}
		serviceActor := requestidentity.RequestIdentity{
			PrincipalType:   requestidentity.PrincipalService,
			PrincipalID:     "authorization-service",
			CredentialClass: requestidentity.CredentialInternalService,
		}
		if err := createTaskRevocationEvent(ctx, qtx, revocation, "server_denied", serviceActor, "task_token_revoked"); err != nil {
			return fmt.Errorf("record server denial: %w", err)
		}
		if err := createTaskRevocationEvent(ctx, qtx, revocation, "cancellation_requested", requester, defaultTaskCancellationReason); err != nil {
			return fmt.Errorf("record cancellation request: %w", err)
		}
		return nil
	})
	return out, err
}

// AcknowledgeTaskCancellation records only that the runtime observed the stop
// request. It deliberately does not change the task to a terminal state.
func (s *TaskService) AcknowledgeTaskCancellation(ctx context.Context, taskID pgtype.UUID) (*db.AgentTaskQueue, error) {
	var out db.AgentTaskQueue
	err := s.runInTx(ctx, func(qtx *db.Queries) error {
		task, err := qtx.MarkAgentTaskCancellationRuntimeAcknowledged(ctx, taskID)
		if errors.Is(err, pgx.ErrNoRows) {
			task, err = qtx.GetAgentTask(ctx, taskID)
			if err != nil {
				return err
			}
			out = task
			return nil
		}
		if err != nil {
			return err
		}
		out = task
		revocation, err := qtx.MarkAuthorizationTaskRevocationAcknowledged(ctx, taskID)
		if err != nil {
			return fmt.Errorf("acknowledge task revocation: %w", err)
		}
		actor := taskCancellationRequester(ctx)
		if err := createTaskRevocationEvent(ctx, qtx, revocation, "runtime_acknowledged", actor, "runtime_observed_cancellation"); err != nil {
			return fmt.Errorf("record runtime acknowledgement: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.broadcastTaskEvent(ctx, protocol.EventTaskCancellationAcknowledged, out)
	return &out, nil
}

// ConfirmTaskTermination is called only after runner.run has returned. It
// records a runtime acknowledgement if one was missed, then records actual
// termination and only then moves the legacy task status to cancelled.
func (s *TaskService) ConfirmTaskTermination(ctx context.Context, taskID pgtype.UUID) (*db.AgentTaskQueue, error) {
	var out db.AgentTaskQueue
	newlyTerminated := false
	err := s.runInTx(ctx, func(qtx *db.Queries) error {
		current, err := qtx.GetAuthorizationTaskRevocationByTask(ctx, taskID)
		if errors.Is(err, pgx.ErrNoRows) {
			task, taskErr := qtx.GetAgentTask(ctx, taskID)
			if taskErr != nil {
				return taskErr
			}
			out = task
			return nil
		}
		if err != nil {
			return err
		}
		actor := taskCancellationRequester(ctx)
		if !current.RuntimeAcknowledgedAt.Valid {
			if _, err = qtx.MarkAgentTaskCancellationRuntimeAcknowledged(ctx, taskID); err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			current, err = qtx.MarkAuthorizationTaskRevocationAcknowledged(ctx, taskID)
			if err != nil {
				return fmt.Errorf("imply runtime acknowledgement: %w", err)
			}
			if err := createTaskRevocationEvent(ctx, qtx, current, "runtime_acknowledged", actor, "termination_callback_implied_acknowledgement"); err != nil {
				return fmt.Errorf("record implied runtime acknowledgement: %w", err)
			}
		}
		task, err := qtx.ConfirmAgentTaskTermination(ctx, taskID)
		if errors.Is(err, pgx.ErrNoRows) {
			task, err = qtx.GetAgentTask(ctx, taskID)
		} else if err == nil {
			newlyTerminated = true
		}
		if err != nil {
			return err
		}
		out = task
		revocation, err := qtx.MarkAuthorizationTaskRevocationTerminated(ctx, taskID)
		if errors.Is(err, pgx.ErrNoRows) {
			revocation, err = qtx.GetAuthorizationTaskRevocationByTask(ctx, taskID)
		}
		if err != nil {
			return fmt.Errorf("confirm task revocation termination: %w", err)
		}
		if err := createTaskRevocationEvent(ctx, qtx, revocation, "terminated", actor, "runtime_process_returned"); err != nil {
			return fmt.Errorf("record task termination: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !newlyTerminated {
		return &out, nil
	}

	s.FinalizeDeferredCancelledChat(ctx, out.ID)
	s.ReconcileAgentStatus(ctx, out.AgentID)
	s.broadcastTaskEvent(ctx, protocol.EventTaskCancelled, out)
	s.NotifyTaskFinished(out)
	return &out, nil
}
