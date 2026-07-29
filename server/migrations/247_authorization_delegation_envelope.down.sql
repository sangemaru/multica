ALTER TABLE task_token
    DROP COLUMN IF EXISTS capability_envelope,
    DROP COLUMN IF EXISTS allowed_child_principal_ids,
    DROP COLUMN IF EXISTS delegation_depth_remaining,
    DROP COLUMN IF EXISTS explicit_denies,
    DROP COLUMN IF EXISTS allowed_actions,
    DROP COLUMN IF EXISTS authorization_session_id,
    DROP COLUMN IF EXISTS lineage_id,
    DROP COLUMN IF EXISTS issue_id,
    DROP COLUMN IF EXISTS project_id;

ALTER TABLE authorization_decision
    DROP COLUMN IF EXISTS delegation_consumed,
    DROP COLUMN IF EXISTS capability_envelope,
    DROP COLUMN IF EXISTS allowed_child_principal_ids,
    DROP COLUMN IF EXISTS delegation_depth_remaining,
    DROP COLUMN IF EXISTS explicit_denies,
    DROP COLUMN IF EXISTS allowed_actions;
