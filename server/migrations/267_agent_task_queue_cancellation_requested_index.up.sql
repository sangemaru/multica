CREATE INDEX CONCURRENTLY agent_task_queue_cancellation_requested_idx
    ON agent_task_queue (runtime_id, cancellation_requested_at)
    WHERE cancellation_requested_at IS NOT NULL
      AND termination_confirmed_at IS NULL;
