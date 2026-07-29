CREATE INDEX CONCURRENTLY authorization_budget_reservation_lineage_status_idx
    ON authorization_budget_reservation (lineage_id, status, created_at);
