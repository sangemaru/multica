CREATE INDEX CONCURRENTLY authorization_session_user_active_idx
    ON authorization_session (user_id, expires_at DESC)
    WHERE revoked_at IS NULL;
