-- name: CreateAuthorizationTaskRevocation :one
INSERT INTO authorization_task_revocation (
    task_id, workspace_id,
    requested_by_principal_type, requested_by_principal_id,
    requested_by_credential_class, requested_by_session_id,
    reason_code, status, server_denied_at, cancellation_requested_at,
    runtime_acknowledged_at, terminated_at
)
VALUES (
    @task_id, @workspace_id,
    @requested_by_principal_type, @requested_by_principal_id,
    @requested_by_credential_class, sqlc.narg(requested_by_session_id),
    @reason_code, @status, now(), now(),
    sqlc.narg(runtime_acknowledged_at), sqlc.narg(terminated_at)
)
ON CONFLICT (task_id) DO NOTHING
RETURNING *;

-- name: GetAuthorizationTaskRevocationByTask :one
SELECT * FROM authorization_task_revocation
WHERE task_id = $1;

-- name: CreateAuthorizationTaskRevocationEvent :one
INSERT INTO authorization_task_revocation_event (
    revocation_id, task_id, event_type,
    actor_principal_type, actor_principal_id, actor_credential_class,
    actor_session_id, reason_code
)
VALUES (
    @revocation_id, @task_id, @event_type,
    @actor_principal_type, @actor_principal_id, @actor_credential_class,
    sqlc.narg(actor_session_id), @reason_code
)
ON CONFLICT (revocation_id, event_type) DO NOTHING
RETURNING *;

-- name: MarkAuthorizationTaskRevocationAcknowledged :one
UPDATE authorization_task_revocation
SET status = 'runtime_acknowledged',
    runtime_acknowledged_at = now(),
    updated_at = now()
WHERE task_id = $1
  AND status = 'cancellation_requested'
  AND runtime_acknowledged_at IS NULL
RETURNING *;

-- name: MarkAuthorizationTaskRevocationTerminated :one
UPDATE authorization_task_revocation
SET status = 'terminated',
    runtime_acknowledged_at = COALESCE(runtime_acknowledged_at, now()),
    terminated_at = now(),
    updated_at = now()
WHERE task_id = $1
  AND status IN ('cancellation_requested', 'runtime_acknowledged')
  AND terminated_at IS NULL
RETURNING *;

-- name: MarkAgentTaskCancellationRuntimeAcknowledged :one
UPDATE agent_task_queue
SET cancellation_runtime_acknowledged_at = now()
WHERE id = $1
  AND cancellation_requested_at IS NOT NULL
  AND cancellation_runtime_acknowledged_at IS NULL
  AND termination_confirmed_at IS NULL
RETURNING *;

-- name: ConfirmAgentTaskTermination :one
UPDATE agent_task_queue
SET status = 'cancelled',
    completed_at = COALESCE(completed_at, now()),
    cancellation_runtime_acknowledged_at =
        COALESCE(cancellation_runtime_acknowledged_at, now()),
    termination_confirmed_at = now(),
    prepare_lease_expires_at = NULL
WHERE id = $1
  AND cancellation_requested_at IS NOT NULL
  AND termination_confirmed_at IS NULL
RETURNING *;

-- name: ListAuthorizationTaskRevocationEvents :many
SELECT * FROM authorization_task_revocation_event
WHERE revocation_id = $1
ORDER BY id;
