-- Append-only authorization ledger. Resource columns are opaque UUIDs without
-- foreign keys so later deletion cannot rewrite or cascade away decision
-- history. No prompt, message, instruction, token, or private content belongs
-- in this table.
CREATE TABLE authorization_decision (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    path TEXT NOT NULL,
    action TEXT NOT NULL,
    principal_type TEXT NOT NULL,
    principal_id UUID,
    credential_class TEXT NOT NULL,
    session_id UUID,
    workspace_id UUID,
    project_id UUID,
    issue_id UUID,
    agent_id UUID,
    parent_task_id UUID,
    allowed BOOLEAN NOT NULL,
    reason_code TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    observe_only BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (btrim(path) <> ''),
    CHECK (btrim(action) <> ''),
    CHECK (btrim(reason_code) <> ''),
    CHECK (btrim(policy_version) <> '')
);

CREATE INDEX authorization_decision_workspace_created_idx
    ON authorization_decision (workspace_id, created_at DESC);

CREATE INDEX authorization_decision_session_created_idx
    ON authorization_decision (session_id, created_at DESC)
    WHERE session_id IS NOT NULL;

CREATE INDEX authorization_decision_denied_created_idx
    ON authorization_decision (created_at DESC)
    WHERE allowed = FALSE;

-- Authorization decisions are immutable audit facts. Application roles may
-- insert and read them, but PostgreSQL rejects mutation even if a future code
-- path accidentally issues UPDATE or DELETE.
CREATE FUNCTION prevent_authorization_decision_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'authorization_decision is append-only';
END;
$$;

CREATE TRIGGER authorization_decision_append_only
BEFORE UPDATE OR DELETE ON authorization_decision
FOR EACH ROW EXECUTE FUNCTION prevent_authorization_decision_mutation();
