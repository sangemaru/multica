-- Durable V1 approval cases. The current table is a materialized projection;
-- the event table is the append-only source of independently verifiable
-- lifecycle facts. Resource identifiers are opaque and no prompt, message,
-- credential, instruction, or private content belongs in either table.
CREATE TABLE authorization_approval_case (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL,
    idempotency_key TEXT NOT NULL,
    requester_principal_type TEXT NOT NULL,
    requester_principal_id TEXT NOT NULL,
    requester_credential_class TEXT NOT NULL,
    requester_session_id UUID,
    originator_user_id UUID,
    designated_approver_user_id UUID NOT NULL,
    action TEXT NOT NULL CHECK (action IN (
        'agent:invoke',
        'repo:write',
        'deploy:staging',
        'deploy:production',
        'external:communicate',
        'agent:delegate'
    )),
    resource_type TEXT NOT NULL CHECK (resource_type IN (
        'workspace', 'project', 'issue', 'agent', 'agent_task',
        'authorization_policy'
    )),
    resource_id UUID NOT NULL,
    reason_code TEXT NOT NULL CHECK (reason_code ~ '^[a-z][a-z0-9_.-]{0,127}$'),
    status TEXT NOT NULL DEFAULT 'requested' CHECK (status IN (
        'requested', 'delivered', 'acknowledged', 'approved', 'denied',
        'applied', 'resolved'
    )),
    decision TEXT CHECK (decision IS NULL OR decision IN ('approved', 'denied')),
    delivered_at TIMESTAMPTZ,
    acknowledged_at TIMESTAMPTZ,
    decided_at TIMESTAMPTZ,
    applied_at TIMESTAMPTZ,
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, idempotency_key),
    CHECK (btrim(idempotency_key) <> ''),
    CHECK (btrim(requester_principal_type) <> ''),
    CHECK (btrim(requester_principal_id) <> ''),
    CHECK (btrim(requester_credential_class) <> ''),
    CHECK ((status = 'requested') OR delivered_at IS NOT NULL),
    CHECK ((status NOT IN ('acknowledged', 'approved', 'denied', 'applied', 'resolved'))
        OR acknowledged_at IS NOT NULL),
    CHECK ((status NOT IN ('approved', 'denied', 'applied', 'resolved'))
        OR (decided_at IS NOT NULL AND decision IS NOT NULL)),
    CHECK ((status <> 'applied' AND applied_at IS NULL)
        OR (status IN ('applied', 'resolved') AND decision = 'approved' AND applied_at IS NOT NULL)),
    CHECK ((status = 'resolved') = (resolved_at IS NOT NULL))
);

CREATE INDEX authorization_approval_case_workspace_status_created_idx
    ON authorization_approval_case (workspace_id, status, created_at DESC);

CREATE INDEX authorization_approval_case_approver_status_created_idx
    ON authorization_approval_case (designated_approver_user_id, status, created_at DESC);

CREATE TABLE authorization_approval_case_event (
    id BIGSERIAL PRIMARY KEY,
    case_id UUID NOT NULL REFERENCES authorization_approval_case(id) ON DELETE RESTRICT,
    idempotency_key TEXT NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type IN (
        'requested', 'delivered', 'acknowledged', 'approved', 'denied',
        'applied', 'resolved'
    )),
    actor_principal_type TEXT NOT NULL,
    actor_principal_id TEXT NOT NULL,
    actor_credential_class TEXT NOT NULL,
    actor_session_id UUID,
    reason_code TEXT NOT NULL CHECK (reason_code ~ '^[a-z][a-z0-9_.-]{0,127}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (case_id, idempotency_key),
    CHECK (btrim(idempotency_key) <> ''),
    CHECK (btrim(actor_principal_type) <> ''),
    CHECK (btrim(actor_principal_id) <> ''),
    CHECK (btrim(actor_credential_class) <> '')
);

CREATE INDEX authorization_approval_case_event_case_idx
    ON authorization_approval_case_event (case_id, id);

CREATE FUNCTION prevent_authorization_approval_case_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'authorization_approval_case_event is append-only';
END;
$$;

CREATE TRIGGER authorization_approval_case_event_append_only
BEFORE UPDATE OR DELETE ON authorization_approval_case_event
FOR EACH ROW EXECUTE FUNCTION prevent_authorization_approval_case_event_mutation();

-- The projection may advance, but its request, scope, and assigned human
-- authority never change. Cases are durable control-plane records and cannot
-- be deleted through an accidental low-level query.
CREATE FUNCTION enforce_authorization_approval_case_projection()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'authorization_approval_case cannot be deleted';
    END IF;

    IF NEW.workspace_id IS DISTINCT FROM OLD.workspace_id
       OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
       OR NEW.requester_principal_type IS DISTINCT FROM OLD.requester_principal_type
       OR NEW.requester_principal_id IS DISTINCT FROM OLD.requester_principal_id
       OR NEW.requester_credential_class IS DISTINCT FROM OLD.requester_credential_class
       OR NEW.requester_session_id IS DISTINCT FROM OLD.requester_session_id
       OR NEW.originator_user_id IS DISTINCT FROM OLD.originator_user_id
       OR NEW.designated_approver_user_id IS DISTINCT FROM OLD.designated_approver_user_id
       OR NEW.action IS DISTINCT FROM OLD.action
       OR NEW.resource_type IS DISTINCT FROM OLD.resource_type
       OR NEW.resource_id IS DISTINCT FROM OLD.resource_id
       OR NEW.reason_code IS DISTINCT FROM OLD.reason_code
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'authorization_approval_case request metadata is immutable';
    END IF;

    IF (NEW.delivered_at IS DISTINCT FROM OLD.delivered_at AND OLD.delivered_at IS NOT NULL)
       OR (NEW.acknowledged_at IS DISTINCT FROM OLD.acknowledged_at AND OLD.acknowledged_at IS NOT NULL)
       OR (NEW.decided_at IS DISTINCT FROM OLD.decided_at AND OLD.decided_at IS NOT NULL)
       OR (NEW.applied_at IS DISTINCT FROM OLD.applied_at AND OLD.applied_at IS NOT NULL)
       OR (NEW.resolved_at IS DISTINCT FROM OLD.resolved_at AND OLD.resolved_at IS NOT NULL)
       OR (NEW.decision IS DISTINCT FROM OLD.decision AND OLD.decision IS NOT NULL) THEN
        RAISE EXCEPTION 'authorization_approval_case lifecycle facts are immutable once set';
    END IF;

    IF NOT (
        (OLD.status = 'requested' AND NEW.status IN ('requested', 'delivered'))
        OR (OLD.status = 'delivered' AND NEW.status IN ('delivered', 'acknowledged'))
        OR (OLD.status = 'acknowledged' AND NEW.status IN ('acknowledged', 'approved', 'denied'))
        OR (OLD.status = 'approved' AND NEW.status IN ('approved', 'applied'))
        OR (OLD.status = 'denied' AND NEW.status IN ('denied', 'resolved'))
        OR (OLD.status = 'applied' AND NEW.status IN ('applied', 'resolved'))
        OR (OLD.status = 'resolved' AND NEW.status = 'resolved')
    ) THEN
        RAISE EXCEPTION 'invalid authorization_approval_case status transition: % -> %',
            OLD.status, NEW.status;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER authorization_approval_case_projection_guard
BEFORE UPDATE OR DELETE ON authorization_approval_case
FOR EACH ROW EXECUTE FUNCTION enforce_authorization_approval_case_projection();
