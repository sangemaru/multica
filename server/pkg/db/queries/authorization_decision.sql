-- name: CreateAuthorizationDecision :one
INSERT INTO authorization_decision (
    path, action, principal_type, principal_id, credential_class, session_id,
    workspace_id, project_id, issue_id, agent_id, parent_task_id,
    allowed, reason_code, policy_version, observe_only, lineage_id,
    evaluation_phase, task_id,
    allowed_actions, explicit_denies, delegation_depth_remaining,
    allowed_child_principal_ids, capability_envelope, delegation_consumed
)
VALUES (
    $1, $2, $3, $4, $5, $6,
    $7, $8, $9, $10, $11,
    $12, $13, $14, $15, $16,
    $17, $18,
    COALESCE(sqlc.arg(allowed_actions)::TEXT[], '{}'::TEXT[]),
    COALESCE(sqlc.arg(explicit_denies)::TEXT[], '{}'::TEXT[]),
    sqlc.arg(delegation_depth_remaining),
    COALESCE(sqlc.arg(allowed_child_principal_ids)::UUID[], '{}'::UUID[]),
    sqlc.arg(capability_envelope), sqlc.arg(delegation_consumed)
)
RETURNING *;

-- name: GetAuthorizationDecision :one
SELECT * FROM authorization_decision WHERE id = $1;

-- name: GetLatestAuthorizationDecisionByTask :one
SELECT * FROM authorization_decision
WHERE task_id = $1
ORDER BY created_at DESC, id DESC
LIMIT 1;

-- name: ListAuthorizationDecisionsByWorkspace :many
SELECT * FROM authorization_decision
WHERE workspace_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;
