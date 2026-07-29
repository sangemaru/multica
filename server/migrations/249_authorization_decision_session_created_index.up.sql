CREATE INDEX CONCURRENTLY authorization_decision_session_created_idx
    ON authorization_decision (session_id, created_at DESC)
    WHERE session_id IS NOT NULL;
