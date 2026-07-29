// Package identity carries the authenticated, server-derived identity of an
// HTTP request. It is deliberately context-only: wire headers may select a
// resource, but they never choose a principal or credential class.
package identity

import (
	"context"
	"time"
)

// PrincipalType is the immediate caller that Multica authenticated.
type PrincipalType string

const (
	PrincipalMember    PrincipalType = "member"
	PrincipalAgent     PrincipalType = "agent"
	PrincipalHarness   PrincipalType = "harness"
	PrincipalRuntime   PrincipalType = "runtime"
	PrincipalAutopilot PrincipalType = "autopilot"
	PrincipalService   PrincipalType = "service"
)

// CredentialClass records how the server authenticated the principal. These
// migration-era classes are inputs to authorization; none is an allow by
// itself. The two short-lived V1 classes are added in migration stage 2.
type CredentialClass string

const (
	CredentialLegacyHumanSession  CredentialClass = "legacy_human_session"
	CredentialLegacyPersonalToken CredentialClass = "legacy_personal_token"
	CredentialAgentTaskToken      CredentialClass = "agent_task_token"
	CredentialDaemonToken         CredentialClass = "daemon_token"
	CredentialCloudNodePAT        CredentialClass = "cloud_node_pat"
	CredentialAutopilotTrigger    CredentialClass = "autopilot_trigger"
	CredentialHarnessSession      CredentialClass = "harness_session"
	CredentialHumanInteractive    CredentialClass = "human_interactive_session"
	CredentialInternalService     CredentialClass = "internal_service"
)

// RequestIdentity is derived only from a credential validated by server auth.
// UserID is the human account associated with the credential for membership
// and accountability; it does not widen the immediate principal's authority.
type RequestIdentity struct {
	PrincipalType            PrincipalType
	PrincipalID              string
	CredentialClass          CredentialClass
	UserID                   string
	AgentID                  string
	TaskID                   string
	WorkspaceID              string
	DaemonID                 string
	SessionID                string
	ProjectID                string
	IssueID                  string
	LineageID                string
	PolicyVersion            int64
	AllowedActions           []string
	ExplicitDenies           []string
	MaxDelegationDepth       int32
	AllowedChildPrincipalIDs []string
	CapabilityEnvelope       bool
	ExpiresAt                time.Time
	AuthenticationAssurance  string
	AuthenticatedAt          time.Time
}

type contextKey struct{}

// WithRequest returns a context carrying one authenticated identity.
func WithRequest(ctx context.Context, id RequestIdentity) context.Context {
	return context.WithValue(ctx, contextKey{}, id)
}

// FromContext returns the identity installed by Auth or DaemonAuth.
func FromContext(ctx context.Context) (RequestIdentity, bool) {
	id, ok := ctx.Value(contextKey{}).(RequestIdentity)
	return id, ok
}
