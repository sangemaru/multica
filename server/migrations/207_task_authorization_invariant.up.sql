ALTER TABLE authorization_decision
    ADD COLUMN lineage_id UUID NOT NULL DEFAULT gen_random_uuid();

ALTER TABLE agent_task_queue
    ADD COLUMN admission_decision_id UUID REFERENCES authorization_decision(id) ON DELETE RESTRICT,
    ADD COLUMN authorization_policy_version TEXT,
    ADD COLUMN lineage_id UUID;

-- Preserve already-queued/running work during rollout by giving every legacy
-- row an explicit migration decision and lineage. New low-level inserts remain
-- possible for compatibility, but claim SQL rejects rows missing these fields.
INSERT INTO authorization_decision (
    id, path, action, principal_type, credential_class,
    workspace_id, project_id, issue_id, agent_id,
    allowed, reason_code, policy_version, observe_only
)
SELECT
    atq.id,
    'legacy_migration',
    'agent:invoke',
    'unknown',
    'unknown',
    a.workspace_id,
    i.project_id,
    atq.issue_id,
    atq.agent_id,
    TRUE,
    'legacy_task_migration_allow',
    'legacy-v1',
    TRUE
FROM agent_task_queue atq
JOIN agent a ON a.id = atq.agent_id
LEFT JOIN issue i ON i.id = atq.issue_id
ON CONFLICT (id) DO NOTHING;

UPDATE agent_task_queue atq
SET admission_decision_id = d.id,
    authorization_policy_version = d.policy_version,
    lineage_id = d.lineage_id
FROM authorization_decision d
WHERE d.id = atq.id
  AND atq.admission_decision_id IS NULL;

CREATE INDEX agent_task_queue_admission_decision_idx
    ON agent_task_queue (admission_decision_id)
    WHERE admission_decision_id IS NOT NULL;

CREATE INDEX agent_task_queue_lineage_idx
    ON agent_task_queue (lineage_id, created_at)
    WHERE lineage_id IS NOT NULL;
