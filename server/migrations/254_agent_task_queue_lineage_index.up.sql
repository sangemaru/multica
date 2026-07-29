CREATE INDEX CONCURRENTLY agent_task_queue_lineage_idx
    ON agent_task_queue (lineage_id, created_at)
    WHERE lineage_id IS NOT NULL;
