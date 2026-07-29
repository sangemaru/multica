-- name: GetWorkspaceAuthorizationConfig :one
SELECT * FROM workspace_authorization_config WHERE workspace_id = $1;

-- name: GetCurrentAuthorizationPolicy :one
SELECT v.*
FROM authorization_policy_current c
JOIN authorization_policy_version v ON v.id = c.policy_version_id
WHERE c.workspace_id = $1 AND c.scope_type = $2 AND c.scope_key = $3;

-- name: ListCurrentAuthorizationPolicies :many
SELECT v.*
FROM authorization_policy_current c
JOIN authorization_policy_version v ON v.id = c.policy_version_id
WHERE c.workspace_id = $1
ORDER BY c.scope_type, c.scope_key;

-- name: ListAuthorizationPolicyAssertions :many
SELECT * FROM authorization_policy_assertion
WHERE policy_version_id = $1
ORDER BY created_at, id;

-- name: FindAuthorizationExplicitDeny :one
SELECT
    a.reason_code,
    v.version,
    c.enforcement_mode,
    c.scope_type,
    c.scope_key
FROM authorization_policy_current c
JOIN authorization_policy_version v ON v.id = c.policy_version_id
JOIN authorization_policy_assertion a ON a.policy_version_id = v.id
JOIN agent target_agent ON target_agent.id = sqlc.arg(agent_id)::uuid
WHERE c.workspace_id = sqlc.arg(workspace_id)::uuid
  AND a.effect = 'deny'
  AND a.action = sqlc.arg(action)
  AND (
      (c.scope_type = 'workspace' AND c.scope_key = sqlc.arg(workspace_id)::text)
      OR (c.scope_type = 'project' AND c.scope_key = sqlc.arg(project_id)::text)
      OR (c.scope_type = 'agent_class' AND c.scope_key = target_agent.authorization_class)
  )
  AND (
      a.subject_type = 'all'
      OR (a.subject_type = 'agent' AND a.subject_value = sqlc.arg(agent_id)::text)
      OR (a.subject_type = 'agent_class' AND a.subject_value = target_agent.authorization_class)
      OR (a.subject_type = 'credential_class' AND a.subject_value = sqlc.arg(credential_class))
      OR (a.subject_type = 'principal_type' AND a.subject_value = sqlc.arg(principal_type))
  )
ORDER BY
    CASE c.scope_type WHEN 'project' THEN 1 WHEN 'agent_class' THEN 2 ELSE 3 END,
    v.version DESC
LIMIT 1;
