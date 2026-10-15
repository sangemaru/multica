package cli

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/multica-ai/multica/server/pkg/protocol"
)

type inspectRefreshHTTPDeadline struct{ deadline time.Time }

func (transport *inspectRefreshHTTPDeadline) RoundTrip(r *http.Request) (*http.Response, error) {
	transport.deadline, _ = r.Context().Deadline()
	return nil, errors.New("offline transport result")
}

func TestRefreshTaskContextDedicatedFiveSecondHTTPBound(t *testing.T) {
	binding := protocol.ContextBinding{TaskID: "11111111-1111-4111-8111-111111111111", WorkspaceID: "22222222-2222-4222-8222-222222222222", ProjectID: "33333333-3333-4333-8333-333333333333", IssueID: "55555555-5555-4555-8555-555555555555"}
	client := NewAPIClient("http://offline.invalid", binding.WorkspaceID, "mat_offline-test")
	client.TaskID, client.AgentID = binding.TaskID, "44444444-4444-4444-8444-444444444444"
	transport := &inspectRefreshHTTPDeadline{}
	client.HTTPClient.Transport = transport // No DNS or network access.
	before := time.Now()
	_, err := client.RefreshTaskContext(context.Background(), binding)
	after := time.Now()
	if err == nil || transport.deadline.Before(before.Add(5*time.Second)) || transport.deadline.After(after.Add(5*time.Second)) {
		t.Fatal("dedicated refresh HTTP context budget missing")
	}
}

func TestRefreshTaskContextShortParentDeadlineAndCancellation(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		<-r.Context().Done() // No sleep, model, or live endpoint.
	}))
	defer server.Close()
	binding := protocol.ContextBinding{TaskID: "11111111-1111-4111-8111-111111111111", WorkspaceID: "22222222-2222-4222-8222-222222222222", ProjectID: "33333333-3333-4333-8333-333333333333", IssueID: "55555555-5555-4555-8555-555555555555"}
	client := NewAPIClient(server.URL, binding.WorkspaceID, "mat_offline-test")
	client.TaskID, client.AgentID = binding.TaskID, "44444444-4444-4444-8444-444444444444"
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := client.RefreshTaskContext(ctx, binding); err == nil || time.Since(started) > time.Second {
		t.Fatal("refresh did not inherit short deadline")
	}
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	before := requests.Load()
	if _, err := client.RefreshTaskContext(ctx, binding); err == nil || requests.Load() != before {
		t.Fatal("cancelled refresh made outbound request")
	}
}
