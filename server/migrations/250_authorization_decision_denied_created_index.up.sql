CREATE INDEX CONCURRENTLY authorization_decision_denied_created_idx
    ON authorization_decision (created_at DESC)
    WHERE allowed = FALSE;
