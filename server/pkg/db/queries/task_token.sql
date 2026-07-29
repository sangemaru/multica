-- name: CreateTaskToken :one
INSERT INTO task_token (
    token_hash, task_id, agent_id, workspace_id, user_id, expires_at,
    project_id, issue_id, lineage_id, authorization_session_id,
    allowed_actions, explicit_denies, delegation_depth_remaining,
    allowed_child_principal_ids, capability_envelope
)
VALUES (
    $1, $2, $3, $4, $5, $6,
    sqlc.narg(project_id), sqlc.narg(issue_id), sqlc.narg(lineage_id), sqlc.narg(authorization_session_id),
    @allowed_actions, @explicit_denies, sqlc.narg(delegation_depth_remaining),
    @allowed_child_principal_ids, @capability_envelope
)
RETURNING *;

-- name: GetTaskTokenByHash :one
SELECT * FROM task_token
WHERE token_hash = $1 AND expires_at > now();

-- name: DeleteTaskTokensByTask :exec
DELETE FROM task_token WHERE task_id = $1;

-- name: DeleteExpiredTaskTokens :exec
DELETE FROM task_token WHERE expires_at <= now();
