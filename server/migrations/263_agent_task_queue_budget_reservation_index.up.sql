CREATE UNIQUE INDEX CONCURRENTLY agent_task_queue_budget_reservation_idx
    ON agent_task_queue (budget_reservation_id)
    WHERE budget_reservation_id IS NOT NULL;
