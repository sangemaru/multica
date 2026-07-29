ALTER TABLE authorization_decision
    ADD COLUMN allowed_actions TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN explicit_denies TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN delegation_depth_remaining INTEGER,
    ADD COLUMN allowed_child_principal_ids UUID[] NOT NULL DEFAULT '{}',
    ADD COLUMN capability_envelope BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN delegation_consumed BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE task_token
    ADD COLUMN project_id UUID,
    ADD COLUMN issue_id UUID,
    ADD COLUMN lineage_id UUID,
    ADD COLUMN authorization_session_id UUID,
    ADD COLUMN allowed_actions TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN explicit_denies TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN delegation_depth_remaining INTEGER,
    ADD COLUMN allowed_child_principal_ids UUID[] NOT NULL DEFAULT '{}',
    ADD COLUMN capability_envelope BOOLEAN NOT NULL DEFAULT FALSE;
