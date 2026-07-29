package handler

import (
	"net/http/httptest"
	"testing"

	requestidentity "github.com/multica-ai/multica/server/internal/identity"
)

func TestResolveActorNeverUsesClientIdentityHeaders(t *testing.T) {
	h := &Handler{}
	req := httptest.NewRequest("POST", "/api/issues", nil)
	req.Header.Set("X-Agent-ID", "forged-agent")
	req.Header.Set("X-Task-ID", "forged-task")
	req.Header.Set("X-Actor-Source", "task_token")

	actorType, actorID := h.resolveActor(req, "member-id", "workspace-id")
	if actorType != "member" || actorID != "member-id" {
		t.Fatalf("forged headers resolved (%q,%q), want member identity", actorType, actorID)
	}
}

func TestResolveActorUsesOnlyBoundTaskTokenIdentity(t *testing.T) {
	h := &Handler{}
	base := httptest.NewRequest("POST", "/api/issues", nil)
	id := requestidentity.RequestIdentity{
		PrincipalType:   requestidentity.PrincipalAgent,
		PrincipalID:     "agent-id",
		CredentialClass: requestidentity.CredentialAgentTaskToken,
		UserID:          "owner-id",
		AgentID:         "agent-id",
		TaskID:          "task-id",
		WorkspaceID:     "workspace-id",
	}
	req := base.WithContext(requestidentity.WithRequest(base.Context(), id))

	actorType, actorID := h.resolveActor(req, "owner-id", "workspace-id")
	if actorType != "agent" || actorID != "agent-id" {
		t.Fatalf("task identity resolved (%q,%q), want agent", actorType, actorID)
	}

	actorType, actorID = h.resolveActor(req, "owner-id", "different-workspace")
	if actorType != "member" || actorID != "owner-id" {
		t.Fatalf("cross-workspace task identity resolved (%q,%q), want member fallback", actorType, actorID)
	}
}

func TestRequestUserIDPrefersServerIdentity(t *testing.T) {
	base := httptest.NewRequest("GET", "/api/me", nil)
	base.Header.Set("X-User-ID", "forged-user")
	id := requestidentity.RequestIdentity{
		PrincipalType:   requestidentity.PrincipalMember,
		PrincipalID:     "server-user",
		CredentialClass: requestidentity.CredentialLegacyHumanSession,
		UserID:          "server-user",
	}
	req := base.WithContext(requestidentity.WithRequest(base.Context(), id))
	if got := requestUserID(req); got != "server-user" {
		t.Fatalf("requestUserID = %q, want server-user", got)
	}
}
