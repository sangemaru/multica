CREATE INDEX CONCURRENTLY agent_task_queue_admission_decision_idx
    ON agent_task_queue (admission_decision_id)
    WHERE admission_decision_id IS NOT NULL;
