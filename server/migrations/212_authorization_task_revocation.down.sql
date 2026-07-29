DROP TRIGGER IF EXISTS agent_task_revocation_projection_guard ON agent_task_queue;
DROP FUNCTION IF EXISTS enforce_agent_task_revocation_projection();
DROP TRIGGER IF EXISTS authorization_task_revocation_projection_guard ON authorization_task_revocation;
DROP FUNCTION IF EXISTS enforce_authorization_task_revocation_projection();
DROP TRIGGER IF EXISTS authorization_task_revocation_event_append_only ON authorization_task_revocation_event;
DROP FUNCTION IF EXISTS prevent_authorization_task_revocation_event_mutation();
DROP TABLE IF EXISTS authorization_task_revocation_event;
DROP TABLE IF EXISTS authorization_task_revocation;
DROP INDEX IF EXISTS agent_task_queue_cancellation_requested_idx;
ALTER TABLE agent_task_queue
    DROP CONSTRAINT IF EXISTS agent_task_termination_time_order,
    DROP CONSTRAINT IF EXISTS agent_task_revocation_time_order,
    DROP COLUMN IF EXISTS termination_confirmed_at,
    DROP COLUMN IF EXISTS cancellation_runtime_acknowledged_at,
    DROP COLUMN IF EXISTS cancellation_requested_at;
