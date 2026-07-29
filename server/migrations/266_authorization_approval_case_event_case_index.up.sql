CREATE INDEX CONCURRENTLY authorization_approval_case_event_case_idx
    ON authorization_approval_case_event (case_id, id);
