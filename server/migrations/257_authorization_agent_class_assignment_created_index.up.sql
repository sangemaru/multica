CREATE INDEX CONCURRENTLY authorization_agent_class_assignment_agent_created_idx
    ON authorization_agent_class_assignment (agent_id, created_at DESC);
