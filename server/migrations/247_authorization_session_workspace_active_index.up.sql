CREATE INDEX CONCURRENTLY authorization_session_workspace_active_idx
    ON authorization_session (workspace_id, credential_class, expires_at DESC)
    WHERE revoked_at IS NULL;
