-- name: CreateAuthorizationSession :one
INSERT INTO authorization_session (
    token_hash, token_prefix, credential_class, user_id, workspace_id,
    project_id, issue_id, harness_type, authentication_assurance,
    presence_verified_at, allowed_actions, explicit_denies,
    max_delegation_depth, allowed_child_principal_ids, lineage_id,
    policy_version, bound_runtime_id, expires_at
)
VALUES (
    $1, $2, $3, $4, $5,
    $6, $7, $8, $9,
    $10, $11, $12,
    $13, $14, $15,
    $16, $17, $18
)
RETURNING *;

-- name: GetAuthorizationSessionByHash :one
SELECT * FROM authorization_session
WHERE token_hash = $1
  AND revoked_at IS NULL
  AND expires_at > now();

-- name: GetActiveAuthorizationSessionByID :one
SELECT * FROM authorization_session
WHERE id = $1
  AND revoked_at IS NULL
  AND expires_at > now();

-- name: ListAuthorizationSessionsByUser :many
SELECT * FROM authorization_session
WHERE user_id = $1
ORDER BY created_at DESC;

-- name: TouchAuthorizationSession :exec
UPDATE authorization_session
SET last_used_at = now()
WHERE id = $1 AND revoked_at IS NULL AND expires_at > now();

-- name: RevokeAuthorizationSession :one
UPDATE authorization_session
SET revoked_at = now()
WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL
RETURNING *;

-- name: RotateAuthorizationSessionSecret :one
UPDATE authorization_session
SET token_hash = $3, token_prefix = $4, rotated_at = now()
WHERE id = $1
  AND user_id = $2
  AND revoked_at IS NULL
  AND expires_at > now()
RETURNING *;
