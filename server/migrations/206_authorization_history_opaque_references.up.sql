-- Append-only authorization history must survive deletion of the resources it
-- references. Keep identifiers opaque and intentionally remove cascading or
-- restrictive FKs from historical rows. Materialized current state retains
-- normal workspace/FK lifecycle semantics.
ALTER TABLE authorization_policy_version
    DROP CONSTRAINT IF EXISTS authorization_policy_version_workspace_id_fkey,
    DROP CONSTRAINT IF EXISTS authorization_policy_version_created_by_user_id_fkey;

ALTER TABLE authorization_agent_class_assignment
    DROP CONSTRAINT IF EXISTS authorization_agent_class_assignment_workspace_id_fkey,
    DROP CONSTRAINT IF EXISTS authorization_agent_class_assignment_agent_id_fkey,
    DROP CONSTRAINT IF EXISTS authorization_agent_class_assignment_assigned_by_user_id_fkey;
