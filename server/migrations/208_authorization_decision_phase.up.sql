ALTER TABLE authorization_decision
    ADD COLUMN evaluation_phase TEXT NOT NULL DEFAULT 'admission'
        CHECK (evaluation_phase IN ('admission', 'claim', 'reclaim')),
    ADD COLUMN task_id UUID;

CREATE INDEX authorization_decision_task_created_idx
    ON authorization_decision (task_id, created_at DESC)
    WHERE task_id IS NOT NULL;
