DROP TRIGGER IF EXISTS authorization_decision_append_only ON authorization_decision;
DROP FUNCTION IF EXISTS prevent_authorization_decision_mutation();
DROP TABLE IF EXISTS authorization_decision;
