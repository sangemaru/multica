package identity

import (
	"context"
	"reflect"
	"testing"
)

func TestRequestIdentityContextRoundTrip(t *testing.T) {
	want := RequestIdentity{
		PrincipalType:   PrincipalAgent,
		PrincipalID:     "agent-id",
		CredentialClass: CredentialAgentTaskToken,
		UserID:          "owner-id",
		AgentID:         "agent-id",
		TaskID:          "task-id",
		WorkspaceID:     "workspace-id",
	}
	ctx := WithRequest(context.Background(), want)
	got, ok := FromContext(ctx)
	if !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("FromContext = (%+v,%v), want (%+v,true)", got, ok, want)
	}
}

func TestRequestIdentityAbsentByDefault(t *testing.T) {
	if got, ok := FromContext(context.Background()); ok || !reflect.DeepEqual(got, RequestIdentity{}) {
		t.Fatalf("empty context returned (%+v,%v)", got, ok)
	}
}
