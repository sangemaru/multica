ALTER TABLE agent
    ADD COLUMN authorization_class TEXT NOT NULL DEFAULT 'standard'
    CHECK (authorization_class ~ '^[a-z][a-z0-9_-]{0,63}$');

CREATE TABLE workspace_authorization_config (
    workspace_id UUID PRIMARY KEY REFERENCES workspace(id) ON DELETE CASCADE,
    designated_approver_user_id UUID NOT NULL REFERENCES "user"(id) ON DELETE RESTRICT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Append-only policy publications. The separately materialized current table
-- is the fast evaluation surface; changing current never rewrites history.
CREATE TABLE authorization_policy_version (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspace(id) ON DELETE CASCADE,
    scope_type TEXT NOT NULL CHECK (scope_type IN ('workspace', 'project', 'agent_class')),
    scope_key TEXT NOT NULL,
    version BIGINT NOT NULL CHECK (version > 0),
    enforcement_mode TEXT NOT NULL CHECK (enforcement_mode IN ('observe', 'enforce')),
    created_by_user_id UUID NOT NULL REFERENCES "user"(id) ON DELETE RESTRICT,
    reason TEXT NOT NULL CHECK (btrim(reason) <> ''),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, scope_type, scope_key, version)
);

CREATE TABLE authorization_policy_assertion (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_version_id UUID NOT NULL REFERENCES authorization_policy_version(id) ON DELETE CASCADE,
    effect TEXT NOT NULL CHECK (effect IN ('allow', 'deny')),
    action TEXT NOT NULL,
    subject_type TEXT NOT NULL
        CHECK (subject_type IN ('all', 'agent', 'agent_class', 'credential_class', 'principal_type')),
    subject_value TEXT,
    reason_code TEXT NOT NULL CHECK (reason_code ~ '^[a-z][a-z0-9_.-]{0,127}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK ((subject_type = 'all' AND subject_value IS NULL)
        OR (subject_type <> 'all' AND subject_value IS NOT NULL AND btrim(subject_value) <> ''))
);

CREATE TABLE authorization_policy_current (
    workspace_id UUID NOT NULL REFERENCES workspace(id) ON DELETE CASCADE,
    scope_type TEXT NOT NULL CHECK (scope_type IN ('workspace', 'project', 'agent_class')),
    scope_key TEXT NOT NULL,
    policy_version_id UUID NOT NULL REFERENCES authorization_policy_version(id) ON DELETE RESTRICT,
    version BIGINT NOT NULL CHECK (version > 0),
    enforcement_mode TEXT NOT NULL CHECK (enforcement_mode IN ('observe', 'enforce')),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, scope_type, scope_key)
);

CREATE INDEX authorization_policy_assertion_lookup_idx
    ON authorization_policy_assertion (policy_version_id, action, effect);

CREATE FUNCTION prevent_authorization_policy_history_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'authorization policy history is append-only';
END;
$$;

CREATE TRIGGER authorization_policy_version_append_only
BEFORE UPDATE OR DELETE ON authorization_policy_version
FOR EACH ROW EXECUTE FUNCTION prevent_authorization_policy_history_mutation();

CREATE TRIGGER authorization_policy_assertion_append_only
BEFORE UPDATE OR DELETE ON authorization_policy_assertion
FOR EACH ROW EXECUTE FUNCTION prevent_authorization_policy_history_mutation();
