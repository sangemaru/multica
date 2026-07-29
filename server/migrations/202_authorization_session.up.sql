-- Short-lived credentials used by interactive humans and external harnesses.
-- Only token hashes are stored; the bearer secret is returned once at mint or
-- rotation time. Scope columns contain opaque identifiers and typed actions,
-- never prompts, credentials, instructions, or private resource content.
CREATE TABLE authorization_session (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash TEXT NOT NULL UNIQUE,
    token_prefix TEXT NOT NULL,
    credential_class TEXT NOT NULL
        CHECK (credential_class IN ('harness_session', 'human_interactive_session')),
    user_id UUID NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    workspace_id UUID REFERENCES workspace(id) ON DELETE CASCADE,
    project_id UUID REFERENCES project(id) ON DELETE CASCADE,
    issue_id UUID REFERENCES issue(id) ON DELETE CASCADE,
    harness_type TEXT,
    authentication_assurance TEXT NOT NULL,
    presence_verified_at TIMESTAMPTZ,
    allowed_actions TEXT[] NOT NULL DEFAULT '{}',
    explicit_denies TEXT[] NOT NULL DEFAULT '{}',
    max_delegation_depth INTEGER NOT NULL DEFAULT 0 CHECK (max_delegation_depth >= 0),
    allowed_child_principal_ids UUID[] NOT NULL DEFAULT '{}',
    lineage_id UUID NOT NULL DEFAULT gen_random_uuid(),
    policy_version BIGINT NOT NULL DEFAULT 1 CHECK (policy_version > 0),
    bound_runtime_id UUID,
    expires_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ,
    rotated_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (expires_at > created_at),
    CHECK (expires_at <= created_at + INTERVAL '24 hours'),
    CHECK (
        (credential_class = 'harness_session'
            AND workspace_id IS NOT NULL
            AND harness_type IS NOT NULL
            AND btrim(harness_type) <> ''
            AND presence_verified_at IS NULL)
        OR
        (credential_class = 'human_interactive_session'
            AND harness_type IS NULL
            AND presence_verified_at IS NOT NULL)
    ),
    CHECK (project_id IS NULL OR workspace_id IS NOT NULL),
    CHECK (issue_id IS NULL OR workspace_id IS NOT NULL)
);

CREATE INDEX authorization_session_user_active_idx
    ON authorization_session (user_id, expires_at DESC)
    WHERE revoked_at IS NULL;

CREATE INDEX authorization_session_workspace_active_idx
    ON authorization_session (workspace_id, credential_class, expires_at DESC)
    WHERE revoked_at IS NULL;
