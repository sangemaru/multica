ALTER TABLE authorization_agent_class_assignment
    ADD CONSTRAINT authorization_agent_class_assignment_workspace_id_fkey
        FOREIGN KEY (workspace_id) REFERENCES workspace(id) ON DELETE CASCADE,
    ADD CONSTRAINT authorization_agent_class_assignment_agent_id_fkey
        FOREIGN KEY (agent_id) REFERENCES agent(id) ON DELETE CASCADE,
    ADD CONSTRAINT authorization_agent_class_assignment_assigned_by_user_id_fkey
        FOREIGN KEY (assigned_by_user_id) REFERENCES "user"(id) ON DELETE RESTRICT;

ALTER TABLE authorization_policy_version
    ADD CONSTRAINT authorization_policy_version_workspace_id_fkey
        FOREIGN KEY (workspace_id) REFERENCES workspace(id) ON DELETE CASCADE,
    ADD CONSTRAINT authorization_policy_version_created_by_user_id_fkey
        FOREIGN KEY (created_by_user_id) REFERENCES "user"(id) ON DELETE RESTRICT;
