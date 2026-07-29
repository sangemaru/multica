-- A running task is not "cancelled" merely because the server accepted a stop
-- request. These task columns are the fast runtime signal and user-facing
-- projection; the separate revocation event ledger below preserves the four
-- independently verifiable facts required by authorization V1.
ALTER TABLE agent_task_queue
    ADD COLUMN cancellation_requested_at TIMESTAMPTZ,
    ADD COLUMN cancellation_runtime_acknowledged_at TIMESTAMPTZ,
    ADD COLUMN termination_confirmed_at TIMESTAMPTZ,
    ADD CONSTRAINT agent_task_revocation_time_order CHECK (
        cancellation_runtime_acknowledged_at IS NULL
        OR cancellation_requested_at IS NOT NULL
    ),
    ADD CONSTRAINT agent_task_termination_time_order CHECK (
        termination_confirmed_at IS NULL
        OR cancellation_requested_at IS NOT NULL
    );

CREATE TABLE authorization_task_revocation (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id UUID NOT NULL UNIQUE,
    workspace_id UUID NOT NULL,
    requested_by_principal_type TEXT NOT NULL,
    requested_by_principal_id TEXT NOT NULL,
    requested_by_credential_class TEXT NOT NULL,
    requested_by_session_id UUID,
    reason_code TEXT NOT NULL CHECK (reason_code ~ '^[a-z][a-z0-9_.-]{0,127}$'),
    status TEXT NOT NULL CHECK (status IN (
        'cancellation_requested', 'runtime_acknowledged', 'terminated'
    )),
    server_denied_at TIMESTAMPTZ NOT NULL,
    cancellation_requested_at TIMESTAMPTZ NOT NULL,
    runtime_acknowledged_at TIMESTAMPTZ,
    terminated_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (btrim(requested_by_principal_type) <> ''),
    CHECK (btrim(requested_by_principal_id) <> ''),
    CHECK (btrim(requested_by_credential_class) <> ''),
    CHECK ((status = 'cancellation_requested') OR runtime_acknowledged_at IS NOT NULL),
    CHECK ((status = 'terminated') = (terminated_at IS NOT NULL))
);

CREATE TABLE authorization_task_revocation_event (
    id BIGSERIAL PRIMARY KEY,
    revocation_id UUID NOT NULL REFERENCES authorization_task_revocation(id) ON DELETE RESTRICT,
    task_id UUID NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type IN (
        'server_denied', 'cancellation_requested',
        'runtime_acknowledged', 'terminated'
    )),
    actor_principal_type TEXT NOT NULL,
    actor_principal_id TEXT NOT NULL,
    actor_credential_class TEXT NOT NULL,
    actor_session_id UUID,
    reason_code TEXT NOT NULL CHECK (reason_code ~ '^[a-z][a-z0-9_.-]{0,127}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (revocation_id, event_type),
    CHECK (btrim(actor_principal_type) <> ''),
    CHECK (btrim(actor_principal_id) <> ''),
    CHECK (btrim(actor_credential_class) <> '')
);

CREATE FUNCTION prevent_authorization_task_revocation_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'authorization_task_revocation_event is append-only';
END;
$$;

CREATE TRIGGER authorization_task_revocation_event_append_only
BEFORE UPDATE OR DELETE ON authorization_task_revocation_event
FOR EACH ROW EXECUTE FUNCTION prevent_authorization_task_revocation_event_mutation();

CREATE FUNCTION enforce_authorization_task_revocation_projection()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'authorization_task_revocation cannot be deleted';
    END IF;
    IF NEW.task_id IS DISTINCT FROM OLD.task_id
       OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id
       OR NEW.requested_by_principal_type IS DISTINCT FROM OLD.requested_by_principal_type
       OR NEW.requested_by_principal_id IS DISTINCT FROM OLD.requested_by_principal_id
       OR NEW.requested_by_credential_class IS DISTINCT FROM OLD.requested_by_credential_class
       OR NEW.requested_by_session_id IS DISTINCT FROM OLD.requested_by_session_id
       OR NEW.reason_code IS DISTINCT FROM OLD.reason_code
       OR NEW.server_denied_at IS DISTINCT FROM OLD.server_denied_at
       OR NEW.cancellation_requested_at IS DISTINCT FROM OLD.cancellation_requested_at
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'authorization_task_revocation request facts are immutable';
    END IF;
    IF (OLD.runtime_acknowledged_at IS NOT NULL
        AND NEW.runtime_acknowledged_at IS DISTINCT FROM OLD.runtime_acknowledged_at)
       OR (OLD.terminated_at IS NOT NULL
           AND NEW.terminated_at IS DISTINCT FROM OLD.terminated_at) THEN
        RAISE EXCEPTION 'authorization_task_revocation lifecycle facts are immutable once set';
    END IF;
    IF NOT (
        (OLD.status = 'cancellation_requested'
            AND NEW.status IN ('cancellation_requested', 'runtime_acknowledged', 'terminated'))
        OR (OLD.status = 'runtime_acknowledged'
            AND NEW.status IN ('runtime_acknowledged', 'terminated'))
        OR (OLD.status = 'terminated' AND NEW.status = 'terminated')
    ) THEN
        RAISE EXCEPTION 'invalid authorization_task_revocation status transition: % -> %',
            OLD.status, NEW.status;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER authorization_task_revocation_projection_guard
BEFORE UPDATE OR DELETE ON authorization_task_revocation
FOR EACH ROW EXECUTE FUNCTION enforce_authorization_task_revocation_projection();

-- Once a lifecycle fact is present on the task projection it cannot be removed
-- or rewritten. Only the server's dedicated transition queries can fill the
-- next NULL timestamp.
CREATE FUNCTION enforce_agent_task_revocation_projection()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF (OLD.cancellation_requested_at IS NOT NULL
        AND NEW.cancellation_requested_at IS DISTINCT FROM OLD.cancellation_requested_at)
       OR (OLD.cancellation_runtime_acknowledged_at IS NOT NULL
           AND NEW.cancellation_runtime_acknowledged_at IS DISTINCT FROM OLD.cancellation_runtime_acknowledged_at)
       OR (OLD.termination_confirmed_at IS NOT NULL
           AND NEW.termination_confirmed_at IS DISTINCT FROM OLD.termination_confirmed_at) THEN
        RAISE EXCEPTION 'agent task revocation lifecycle facts are immutable once set';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER agent_task_revocation_projection_guard
BEFORE UPDATE OF cancellation_requested_at,
    cancellation_runtime_acknowledged_at, termination_confirmed_at
ON agent_task_queue
FOR EACH ROW EXECUTE FUNCTION enforce_agent_task_revocation_projection();
