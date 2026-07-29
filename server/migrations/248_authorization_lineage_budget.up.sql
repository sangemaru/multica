-- Hard V1 execution-count budgets. A lineage has one materialized counter and
-- one reservation per admitted task. The event table is the append-only audit
-- history; the budget and reservation tables are the current-state projection.
CREATE TABLE authorization_lineage_budget (
    lineage_id UUID PRIMARY KEY,
    -- Opaque audit/control-plane reference: workspace deletion must not rewrite
    -- or deadlock durable lineage state through reservation history.
    workspace_id UUID NOT NULL,
    execution_limit INTEGER NOT NULL CHECK (execution_limit > 0),
    reserved_executions INTEGER NOT NULL DEFAULT 0 CHECK (reserved_executions >= 0),
    consumed_executions INTEGER NOT NULL DEFAULT 0 CHECK (consumed_executions >= 0),
    generation BIGINT NOT NULL DEFAULT 1 CHECK (generation > 0),
    breaker_state TEXT NOT NULL DEFAULT 'closed' CHECK (breaker_state IN ('closed', 'exhausted')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (reserved_executions + consumed_executions <= execution_limit)
);

CREATE TABLE authorization_budget_reservation (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    lineage_id UUID NOT NULL REFERENCES authorization_lineage_budget(lineage_id) ON DELETE RESTRICT,
    admission_decision_id UUID NOT NULL UNIQUE REFERENCES authorization_decision(id) ON DELETE RESTRICT,
    generation BIGINT NOT NULL CHECK (generation > 0),
    status TEXT NOT NULL DEFAULT 'reserved' CHECK (status IN ('reserved', 'consumed', 'released', 'expired')),
    task_id UUID UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL DEFAULT now() + interval '15 minutes',
    consumed_at TIMESTAMPTZ,
    released_at TIMESTAMPTZ,
    release_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK ((status = 'consumed') = (consumed_at IS NOT NULL)),
    CHECK ((status IN ('released', 'expired')) = (released_at IS NOT NULL))
);

CREATE TABLE authorization_budget_event (
    id BIGSERIAL PRIMARY KEY,
    lineage_id UUID NOT NULL,
    reservation_id UUID,
    admission_decision_id UUID,
    task_id UUID,
    event_type TEXT NOT NULL CHECK (event_type IN (
        'reserved', 'bound', 'consumed', 'released', 'expired', 'reset',
        'migrated_reserved', 'migrated_consumed'
    )),
    generation BIGINT NOT NULL CHECK (generation > 0),
    reason_code TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (btrim(reason_code) <> '')
);

CREATE FUNCTION prevent_authorization_budget_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'authorization_budget_event is append-only';
END;
$$;

CREATE TRIGGER authorization_budget_event_append_only
BEFORE UPDATE OR DELETE ON authorization_budget_event
FOR EACH ROW EXECUTE FUNCTION prevent_authorization_budget_event_mutation();

ALTER TABLE agent_task_queue
    ADD COLUMN budget_reservation_id UUID REFERENCES authorization_budget_reservation(id) ON DELETE RESTRICT;

-- Preserve active rollout work. Historical terminal tasks remain outside the
-- new claim invariant because they can never be claimed again.
WITH active AS (
    SELECT lineage_id, min(a.workspace_id::text)::uuid AS workspace_id, count(*)::integer AS active_count
    FROM agent_task_queue t
    JOIN agent a ON a.id = t.agent_id
    WHERE t.lineage_id IS NOT NULL
      AND t.admission_decision_id IS NOT NULL
      AND t.status IN ('queued', 'deferred', 'dispatched', 'running', 'waiting_local_directory')
    GROUP BY lineage_id
)
INSERT INTO authorization_lineage_budget (
    lineage_id, workspace_id, execution_limit, reserved_executions, consumed_executions, breaker_state
)
SELECT
    lineage_id,
    workspace_id,
    GREATEST(64, active_count),
    0,
    0,
    'closed'
FROM active;

INSERT INTO authorization_budget_reservation (
    lineage_id, admission_decision_id, generation, status, task_id,
    consumed_at, expires_at
)
SELECT
    t.lineage_id,
    t.admission_decision_id,
    1,
    CASE WHEN t.status IN ('queued', 'deferred', 'dispatched', 'waiting_local_directory') AND t.started_at IS NULL
        THEN 'reserved' ELSE 'consumed' END,
    t.id,
    CASE WHEN t.status IN ('queued', 'deferred', 'dispatched', 'waiting_local_directory') AND t.started_at IS NULL
        THEN NULL ELSE COALESCE(t.started_at, t.dispatched_at, t.created_at) END,
    now() + interval '100 years'
FROM agent_task_queue t
WHERE t.lineage_id IS NOT NULL
  AND t.admission_decision_id IS NOT NULL
  AND t.status IN ('queued', 'deferred', 'dispatched', 'running', 'waiting_local_directory');

UPDATE agent_task_queue t
SET budget_reservation_id = r.id
FROM authorization_budget_reservation r
WHERE r.task_id = t.id;

UPDATE authorization_lineage_budget b
SET reserved_executions = counts.reserved_count,
    consumed_executions = counts.consumed_count,
    breaker_state = CASE
        WHEN counts.reserved_count + counts.consumed_count >= b.execution_limit THEN 'exhausted'
        ELSE 'closed'
    END,
    updated_at = now()
FROM (
    SELECT lineage_id,
        count(*) FILTER (WHERE status = 'reserved')::integer AS reserved_count,
        count(*) FILTER (WHERE status = 'consumed')::integer AS consumed_count
    FROM authorization_budget_reservation
    GROUP BY lineage_id
) counts
WHERE counts.lineage_id = b.lineage_id;

INSERT INTO authorization_budget_event (
    lineage_id, reservation_id, admission_decision_id, task_id,
    event_type, generation, reason_code
)
SELECT
    lineage_id,
    id,
    admission_decision_id,
    task_id,
    CASE status WHEN 'reserved' THEN 'migrated_reserved' ELSE 'migrated_consumed' END,
    generation,
    'legacy_active_task_backfill'
FROM authorization_budget_reservation;

-- Bind a reservation to exactly one created task. This trigger is the database
-- invariant behind every high-level enqueue path and rejects mismatched reuse.
CREATE FUNCTION bind_authorization_budget_reservation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    bound authorization_budget_reservation%ROWTYPE;
BEGIN
    IF NEW.budget_reservation_id IS NULL THEN
        RETURN NEW;
    END IF;

    UPDATE authorization_budget_reservation
    SET task_id = NEW.id,
        expires_at = now() + interval '100 years',
        updated_at = now()
    WHERE id = NEW.budget_reservation_id
      AND status = 'reserved'
      AND task_id IS NULL
      AND lineage_id = NEW.lineage_id
      AND admission_decision_id = NEW.admission_decision_id
    RETURNING * INTO bound;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'invalid authorization budget reservation for task %', NEW.id;
    END IF;

    INSERT INTO authorization_budget_event (
        lineage_id, reservation_id, admission_decision_id, task_id,
        event_type, generation, reason_code
    ) VALUES (
        bound.lineage_id, bound.id, bound.admission_decision_id, NEW.id,
        'bound', bound.generation, 'task_created'
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER agent_task_bind_authorization_budget
AFTER INSERT ON agent_task_queue
FOR EACH ROW EXECUTE FUNCTION bind_authorization_budget_reservation();

-- The task lifecycle owns reservation materialization. Starting consumes one
-- execution; terminal pre-start work releases it; task deletion also releases
-- a still-reserved slot. Redispatch/reclaim of the same task never double-counts.
CREATE FUNCTION reconcile_authorization_budget_for_task()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_id UUID;
    target_task_id UUID;
    reservation authorization_budget_reservation%ROWTYPE;
    lifecycle_reason TEXT;
BEGIN
    IF TG_OP = 'DELETE' THEN
        target_id := OLD.budget_reservation_id;
        target_task_id := OLD.id;
        lifecycle_reason := 'task_deleted_before_start';
    ELSE
        target_id := NEW.budget_reservation_id;
        target_task_id := NEW.id;
    END IF;

    IF target_id IS NULL THEN
        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        END IF;
        RETURN NEW;
    END IF;

    IF TG_OP <> 'DELETE'
       AND OLD.started_at IS NULL
       AND NEW.started_at IS NOT NULL THEN
        UPDATE authorization_budget_reservation
        SET status = 'consumed', consumed_at = now(), updated_at = now()
        WHERE id = target_id AND status = 'reserved'
        RETURNING * INTO reservation;
        IF FOUND THEN
            UPDATE authorization_lineage_budget
            SET reserved_executions = reserved_executions - 1,
                consumed_executions = consumed_executions + 1,
                breaker_state = CASE
                    WHEN reserved_executions + consumed_executions >= execution_limit THEN 'exhausted'
                    ELSE 'closed'
                END,
                updated_at = now()
            WHERE lineage_id = reservation.lineage_id;
            INSERT INTO authorization_budget_event (
                lineage_id, reservation_id, admission_decision_id, task_id,
                event_type, generation, reason_code
            ) VALUES (
                reservation.lineage_id, reservation.id, reservation.admission_decision_id,
                target_task_id, 'consumed', reservation.generation, 'task_started'
            );
        END IF;
        RETURN NEW;
    END IF;

    IF TG_OP = 'DELETE'
       OR (OLD.started_at IS NULL AND NEW.started_at IS NULL
           AND NEW.status IN ('cancelled', 'failed')) THEN
        IF lifecycle_reason IS NULL THEN
            lifecycle_reason := 'task_' || NEW.status || '_before_start';
        END IF;
        UPDATE authorization_budget_reservation
        SET status = 'released', released_at = now(), release_reason = lifecycle_reason, updated_at = now()
        WHERE id = target_id AND status = 'reserved'
        RETURNING * INTO reservation;
        IF FOUND THEN
            UPDATE authorization_lineage_budget
            SET reserved_executions = reserved_executions - 1,
                breaker_state = 'closed',
                updated_at = now()
            WHERE lineage_id = reservation.lineage_id;
            INSERT INTO authorization_budget_event (
                lineage_id, reservation_id, admission_decision_id, task_id,
                event_type, generation, reason_code
            ) VALUES (
                reservation.lineage_id, reservation.id, reservation.admission_decision_id,
                target_task_id, 'released', reservation.generation, lifecycle_reason
            );
        END IF;
    END IF;

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER agent_task_reconcile_authorization_budget
AFTER UPDATE OF status, started_at OR DELETE ON agent_task_queue
FOR EACH ROW EXECUTE FUNCTION reconcile_authorization_budget_for_task();

-- Admission facts attached to a task are immutable. Without this guard a
-- later low-level caller could detach or swap the reservation after creation
-- and leave the materialized counters inconsistent with the claim invariant.
CREATE FUNCTION prevent_task_authorization_metadata_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    -- A low-level compatibility caller may insert an inert row first and then
    -- attach one complete, already-valid admission tuple before claim. This is
    -- a one-way repair, not a bypass: the reservation must already be bound to
    -- this task and match its decision and lineage. Once attached, no field can
    -- be changed or removed.
    IF OLD.admission_decision_id IS NULL
       AND OLD.authorization_policy_version IS NULL
       AND OLD.lineage_id IS NULL
       AND OLD.budget_reservation_id IS NULL
       AND NEW.admission_decision_id IS NOT NULL
       AND NEW.authorization_policy_version IS NOT NULL
       AND NEW.lineage_id IS NOT NULL
       AND NEW.budget_reservation_id IS NOT NULL THEN
        PERFORM 1
        FROM authorization_budget_reservation r
        WHERE r.id = NEW.budget_reservation_id
          AND r.task_id = NEW.id
          AND r.admission_decision_id = NEW.admission_decision_id
          AND r.lineage_id = NEW.lineage_id
          AND r.status IN ('reserved', 'consumed');
        IF FOUND THEN
            RETURN NEW;
        END IF;
    END IF;

    IF NEW.admission_decision_id IS DISTINCT FROM OLD.admission_decision_id
       OR NEW.authorization_policy_version IS DISTINCT FROM OLD.authorization_policy_version
       OR NEW.lineage_id IS DISTINCT FROM OLD.lineage_id
       OR NEW.budget_reservation_id IS DISTINCT FROM OLD.budget_reservation_id THEN
        RAISE EXCEPTION 'task authorization metadata is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER agent_task_authorization_metadata_immutable
BEFORE UPDATE OF admission_decision_id, authorization_policy_version, lineage_id, budget_reservation_id
ON agent_task_queue
FOR EACH ROW EXECUTE FUNCTION prevent_task_authorization_metadata_mutation();
