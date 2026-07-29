CREATE INDEX CONCURRENTLY authorization_budget_event_lineage_idx
    ON authorization_budget_event (lineage_id, id);
