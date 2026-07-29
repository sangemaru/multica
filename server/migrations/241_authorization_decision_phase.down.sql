DROP INDEX IF EXISTS authorization_decision_task_created_idx;
ALTER TABLE authorization_decision
    DROP COLUMN IF EXISTS task_id,
    DROP COLUMN IF EXISTS evaluation_phase;
