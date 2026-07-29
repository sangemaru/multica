CREATE INDEX CONCURRENTLY authorization_approval_case_workspace_status_created_idx
    ON authorization_approval_case (workspace_id, status, created_at DESC);
