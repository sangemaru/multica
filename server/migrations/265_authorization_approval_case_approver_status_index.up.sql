CREATE INDEX CONCURRENTLY authorization_approval_case_approver_status_created_idx
    ON authorization_approval_case (designated_approver_user_id, status, created_at DESC);
