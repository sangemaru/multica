DROP INDEX IF EXISTS agent_task_queue_lineage_idx;
DROP INDEX IF EXISTS agent_task_queue_admission_decision_idx;
ALTER TABLE agent_task_queue
    DROP COLUMN IF EXISTS lineage_id,
    DROP COLUMN IF EXISTS authorization_policy_version,
    DROP COLUMN IF EXISTS admission_decision_id;
ALTER TABLE authorization_decision DROP COLUMN IF EXISTS lineage_id;
