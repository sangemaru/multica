export type AuthorizationDecisionOutcome = "allowed" | "denied" | "observed_deny";

export interface AuthorizationDecisionExplanation {
  id: string;
  workspace_id: string;
  task_id?: string;
  path: string;
  evaluation_phase: string;
  action: string;
  principal_type: string;
  principal_id?: string;
  credential_class: string;
  outcome: AuthorizationDecisionOutcome;
  enforcement: "enforced" | "observe_only";
  reason_code: string;
  policy_version: string;
  policy_layer: string;
  explanation: string;
  next_step: string;
  task_created: boolean;
  provider_call_status: "not_reached" | "not_recorded_by_authorization_ledger";
  allowed_actions?: string[];
  explicit_denies?: string[];
  created_at: string;
}
