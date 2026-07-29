-- name: ReserveAuthorizationLineageBudget :one
WITH capacity AS (
    INSERT INTO authorization_lineage_budget (
        lineage_id, workspace_id, execution_limit,
        reserved_executions, breaker_state
    ) VALUES (
        @lineage_id, @workspace_id, @execution_limit,
        1, CASE WHEN @execution_limit = 1 THEN 'exhausted' ELSE 'closed' END
    )
    ON CONFLICT (lineage_id) DO UPDATE
    SET reserved_executions = authorization_lineage_budget.reserved_executions + 1,
        breaker_state = CASE
            WHEN authorization_lineage_budget.reserved_executions
                + authorization_lineage_budget.consumed_executions + 1
                >= authorization_lineage_budget.execution_limit THEN 'exhausted'
            ELSE 'closed'
        END,
        updated_at = now()
    WHERE authorization_lineage_budget.workspace_id = EXCLUDED.workspace_id
      AND authorization_lineage_budget.reserved_executions
          + authorization_lineage_budget.consumed_executions
          < authorization_lineage_budget.execution_limit
    RETURNING generation
), reservation AS (
    INSERT INTO authorization_budget_reservation (
        lineage_id, admission_decision_id, generation
    )
    SELECT @lineage_id, @admission_decision_id, generation
    FROM capacity
    RETURNING *
), event AS (
    INSERT INTO authorization_budget_event (
        lineage_id, reservation_id, admission_decision_id,
        event_type, generation, reason_code
    )
    SELECT lineage_id, id, admission_decision_id,
        'reserved', generation, 'task_admission'
    FROM reservation
)
SELECT * FROM reservation;

-- name: GetAuthorizationBudgetReservation :one
SELECT * FROM authorization_budget_reservation
WHERE id = $1;

-- name: GetAuthorizationLineageBudget :one
SELECT * FROM authorization_lineage_budget
WHERE lineage_id = $1;

-- name: ReleaseAuthorizationBudgetReservation :one
WITH released AS (
    UPDATE authorization_budget_reservation
    SET status = 'released',
        released_at = now(),
        release_reason = @reason_code,
        updated_at = now()
    WHERE authorization_budget_reservation.id = @reservation_id
      AND authorization_budget_reservation.status = 'reserved'
      AND authorization_budget_reservation.task_id IS NULL
    RETURNING *
), budget AS (
    UPDATE authorization_lineage_budget b
    SET reserved_executions = b.reserved_executions - 1,
        breaker_state = 'closed',
        updated_at = now()
    FROM released r
    WHERE b.lineage_id = r.lineage_id
), event AS (
    INSERT INTO authorization_budget_event (
        lineage_id, reservation_id, admission_decision_id, task_id,
        event_type, generation, reason_code
    )
    SELECT r.lineage_id, r.id, r.admission_decision_id, r.task_id,
        'released', r.generation, @reason_code
    FROM released r
)
SELECT * FROM released;

-- name: ReleaseExpiredAuthorizationBudgetReservations :many
WITH released AS (
    UPDATE authorization_budget_reservation
    SET status = 'expired',
        released_at = now(),
        release_reason = 'orphan_reservation_expired',
        updated_at = now()
    WHERE status = 'reserved'
      AND task_id IS NULL
      AND expires_at <= now()
    RETURNING *
), counts AS (
    SELECT lineage_id, count(*)::integer AS released_count
    FROM released
    GROUP BY lineage_id
), budget AS (
    UPDATE authorization_lineage_budget b
    SET reserved_executions = b.reserved_executions - counts.released_count,
        breaker_state = 'closed',
        updated_at = now()
    FROM counts
    WHERE b.lineage_id = counts.lineage_id
), event AS (
    INSERT INTO authorization_budget_event (
        lineage_id, reservation_id, admission_decision_id, task_id,
        event_type, generation, reason_code
    )
    SELECT r.lineage_id, r.id, r.admission_decision_id, r.task_id,
        'expired', r.generation, 'orphan_reservation_expired'
    FROM released r
)
SELECT * FROM released;

-- name: ResetAuthorizationLineageBudget :one
WITH reset AS (
    UPDATE authorization_lineage_budget b
    SET execution_limit = @execution_limit,
        consumed_executions = 0,
        generation = generation + 1,
        breaker_state = 'closed',
        updated_at = now()
    WHERE b.lineage_id = @lineage_id
      AND b.reserved_executions = 0
    RETURNING *
), event AS (
    INSERT INTO authorization_budget_event (
        lineage_id, event_type, generation, reason_code
    )
    SELECT r.lineage_id, 'reset', r.generation, @reason_code
    FROM reset r
)
SELECT * FROM reset;

-- name: ListAuthorizationBudgetEvents :many
SELECT * FROM authorization_budget_event
WHERE lineage_id = $1
ORDER BY id ASC;
