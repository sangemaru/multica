CREATE INDEX CONCURRENTLY authorization_task_revocation_event_revocation_idx
    ON authorization_task_revocation_event (revocation_id, id);
