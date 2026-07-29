package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestAuthorizationDecisionTextExplainsAllowAndDenyWithoutOverclaimingProvider(t *testing.T) {
	for _, test := range []struct {
		name     string
		decision authorizationDecisionExplanation
		want     []string
	}{
		{
			name: "allow",
			decision: authorizationDecisionExplanation{
				ID: "allow-id", Outcome: "allowed", Enforcement: "enforced",
				Action: "agent:invoke", Path: "mention", EvaluationPhase: "admission",
				PrincipalType: "harness", CredentialClass: "harness_session",
				PolicyVersion: "session-v2", PolicyLayer: "delegated_session",
				ReasonCode: "session_scope_allow", Explanation: "Scoped action permitted.",
				TaskCreated: true, ProviderCallStatus: "not_recorded_by_authorization_ledger",
				NextStep: "none",
			},
			want: []string{
				"Outcome: allowed (enforced)",
				"Policy: session-v2 (delegated_session)",
				"Provider call: not_recorded_by_authorization_ledger",
			},
		},
		{
			name: "deny",
			decision: authorizationDecisionExplanation{
				ID: "deny-id", Outcome: "denied", Enforcement: "enforced",
				Action: "agent:invoke", Path: "autopilot", EvaluationPhase: "claim",
				PrincipalType: "runtime", CredentialClass: "daemon_token",
				PolicyVersion: "policy-v4", PolicyLayer: "workspace_policy",
				ReasonCode: "experimental_class_denied", Explanation: "Policy denied.",
				TaskCreated: false, ProviderCallStatus: "not_reached",
				NextStep: "review_policy_or_request_approval",
			},
			want: []string{
				"Outcome: denied (enforced)",
				"Reason: experimental_class_denied",
				"Task created: false",
				"Provider call: not_reached",
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := writeAuthorizationDecisionExplanation(&out, test.decision); err != nil {
				t.Fatal(err)
			}
			for _, fragment := range test.want {
				if !strings.Contains(out.String(), fragment) {
					t.Fatalf("output missing %q:\n%s", fragment, out.String())
				}
			}
		})
	}
}
