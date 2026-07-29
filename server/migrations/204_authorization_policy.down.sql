DROP TRIGGER IF EXISTS authorization_policy_assertion_append_only ON authorization_policy_assertion;
DROP TRIGGER IF EXISTS authorization_policy_version_append_only ON authorization_policy_version;
DROP FUNCTION IF EXISTS prevent_authorization_policy_history_mutation();
DROP TABLE IF EXISTS authorization_policy_current;
DROP TABLE IF EXISTS authorization_policy_assertion;
DROP TABLE IF EXISTS authorization_policy_version;
DROP TABLE IF EXISTS workspace_authorization_config;
ALTER TABLE agent DROP COLUMN IF EXISTS authorization_class;
