CREATE TABLE authorization_agent_class_assignment (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspace(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES agent(id) ON DELETE CASCADE,
    authorization_class TEXT NOT NULL CHECK (authorization_class ~ '^[a-z][a-z0-9_-]{0,63}$'),
    assigned_by_user_id UUID NOT NULL REFERENCES "user"(id) ON DELETE RESTRICT,
    reason TEXT NOT NULL CHECK (btrim(reason) <> ''),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX authorization_agent_class_assignment_agent_created_idx
    ON authorization_agent_class_assignment (agent_id, created_at DESC);

CREATE TRIGGER authorization_agent_class_assignment_append_only
BEFORE UPDATE OR DELETE ON authorization_agent_class_assignment
FOR EACH ROW EXECUTE FUNCTION prevent_authorization_policy_history_mutation();
