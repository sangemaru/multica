CREATE INDEX CONCURRENTLY authorization_decision_workspace_created_idx
    ON authorization_decision (workspace_id, created_at DESC);
