CREATE INDEX CONCURRENTLY authorization_decision_task_created_idx
    ON authorization_decision (task_id, created_at DESC)
    WHERE task_id IS NOT NULL;
