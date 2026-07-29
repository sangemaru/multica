CREATE INDEX CONCURRENTLY authorization_policy_assertion_lookup_idx
    ON authorization_policy_assertion (policy_version_id, action, effect);
