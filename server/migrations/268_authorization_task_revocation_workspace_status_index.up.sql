CREATE INDEX CONCURRENTLY authorization_task_revocation_workspace_status_idx
    ON authorization_task_revocation (workspace_id, status, created_at DESC);
