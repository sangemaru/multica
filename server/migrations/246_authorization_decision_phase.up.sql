ALTER TABLE authorization_decision
    ADD COLUMN evaluation_phase TEXT NOT NULL DEFAULT 'admission'
        CHECK (evaluation_phase IN ('admission', 'claim', 'reclaim')),
    ADD COLUMN task_id UUID;
