package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/multica-ai/multica/server/pkg/protocol"
)

func contextRefreshTestResponse() protocol.ContextRefreshResponse {
	now := time.Now().Add(-time.Second).UTC()
	unauthorized := false
	binding := protocol.ContextBinding{TaskID: "11111111-1111-4111-8111-111111111111", WorkspaceID: "22222222-2222-4222-8222-222222222222",
		ProjectID: "33333333-3333-4333-8333-333333333333", IssueID: "44444444-4444-4444-8444-444444444444"}
	response := protocol.ContextRefreshResponse{Status: "available", ContextBinding: binding,
		ObservedAt: now.Format(time.RFC3339Nano), Coverage: "partial", Freshness: "unknown", ActionAuthorized: &unauthorized}
	response.PreparedProjectContext = &protocol.PreparedProjectContext{TaskID: binding.TaskID, WorkspaceID: binding.WorkspaceID, ProjectID: binding.ProjectID, IssueID: binding.IssueID,
		ObservedAt: response.ObservedAt, ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
		Sources: []protocol.PreparedContextSource{{WorkspaceID: binding.WorkspaceID, ProjectID: binding.ProjectID, IssueID: binding.IssueID,
			SourceID: "55555555-5555-4555-8555-555555555555", Revision: 2, UpdatedAt: now.Add(-time.Minute).Format(time.RFC3339Nano), Excerpt: "Selected source"}}}
	return response
}

func setContextRefreshTaskEnv(t *testing.T, server string, response protocol.ContextRefreshResponse) {
	t.Helper()
	t.Chdir(t.TempDir())
	t.Setenv("MULTICA_SERVER_URL", server)
	t.Setenv("MULTICA_TASK_ID", response.TaskID)
	t.Setenv("MULTICA_AGENT_ID", "66666666-6666-4666-8666-666666666666")
	t.Setenv("MULTICA_WORKSPACE_ID", response.WorkspaceID)
	t.Setenv("MULTICA_TOKEN", "mat_offline-test-token")
}

func TestContextRefreshNativeCLIAuthenticatedBoundedObservation(t *testing.T) {
	response := contextRefreshTestResponse()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/api/context/refresh" || r.URL.Query().Get("expected_project_id") != response.ProjectID || r.URL.Query().Get("expected_issue_id") != response.IssueID ||
			r.Header.Get("Authorization") != "Bearer mat_offline-test-token" || r.Header.Get("X-Task-ID") != response.TaskID || r.Header.Get("X-Workspace-ID") != response.WorkspaceID {
			t.Error("native command used wrong path, identity or authentication")
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()
	setContextRefreshTaskEnv(t, server.URL, response)
	cmd := newContextRefreshCmd()
	cmd.Flags().Set("project-id", response.ProjectID)
	cmd.Flags().Set("issue-id", response.IssueID)
	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := runContextRefresh(cmd, nil); err != nil || !strings.Contains(out.String(), "Selected source") || requests.Load() != 1 {
		t.Fatalf("valid refresh failed: %v", err)
	}
	response.Status = "unavailable"
	response.PreparedProjectContext = nil
	out.Reset()
	if err := runContextRefresh(cmd, nil); err != nil || !strings.Contains(out.String(), `"status": "unavailable"`) || strings.Contains(out.String(), "Selected source") {
		t.Fatal("unavailable refresh printed or reused old observation")
	}
}

func TestContextRefreshNativeCLIRejectsBeforeNetwork(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
	defer server.Close()
	for _, mutate := range []func(*testing.T){
		func(t *testing.T) { t.Setenv("MULTICA_TOKEN", "member-token") },
		func(t *testing.T) { t.Setenv("MULTICA_TOKEN", "") },
		func(t *testing.T) { t.Setenv("MULTICA_TASK_ID", "") },
		func(t *testing.T) { t.Setenv("MULTICA_AGENT_ID", "malformed") },
		func(t *testing.T) { t.Setenv("MULTICA_WORKSPACE_ID", "") },
	} {
		t.Run("missing task auth/binding", func(t *testing.T) {
			response := contextRefreshTestResponse()
			setContextRefreshTaskEnv(t, server.URL, response)
			mutate(t)
			cmd := newContextRefreshCmd()
			cmd.Flags().Set("project-id", response.ProjectID)
			cmd.Flags().Set("issue-id", response.IssueID)
			if runContextRefresh(cmd, nil) == nil || requests.Load() != 0 {
				t.Fatal("invalid local task credentials caused outbound request")
			}
		})
	}
	response := contextRefreshTestResponse()
	setContextRefreshTaskEnv(t, server.URL, response)
	cmd := newContextRefreshCmd()
	cmd.Flags().Set("project-id", response.ProjectID)
	if runContextRefresh(cmd, nil) == nil || requests.Load() != 0 {
		t.Fatal("missing initial issue guard caused outbound request")
	}
}

func TestContextRefreshNativeCLIRejectsPrivateOrInvalidResponse(t *testing.T) {
	mutations := map[string]func(*protocol.ContextRefreshResponse){
		"wrong task":      func(r *protocol.ContextRefreshResponse) { r.TaskID = r.IssueID },
		"wrong workspace": func(r *protocol.ContextRefreshResponse) { r.WorkspaceID = r.IssueID },
		"wrong project":   func(r *protocol.ContextRefreshResponse) { r.ProjectID = r.IssueID },
		"wrong issue":     func(r *protocol.ContextRefreshResponse) { r.IssueID = r.ProjectID },
		"future observed": func(r *protocol.ContextRefreshResponse) {
			r.ObservedAt = time.Now().Add(time.Minute).Format(time.RFC3339Nano)
		},
		"expired":                  func(r *protocol.ContextRefreshResponse) { r.PreparedProjectContext.ExpiresAt = r.ObservedAt },
		"source wrong workspace":   func(r *protocol.ContextRefreshResponse) { r.PreparedProjectContext.Sources[0].WorkspaceID = r.IssueID },
		"source negative revision": func(r *protocol.ContextRefreshResponse) { r.PreparedProjectContext.Sources[0].Revision = -1 },
		"source invalid timestamp": func(r *protocol.ContextRefreshResponse) { r.PreparedProjectContext.Sources[0].UpdatedAt = "invalid" },
		"source oversized": func(r *protocol.ContextRefreshResponse) {
			r.PreparedProjectContext.Sources[0].Excerpt = strings.Repeat("p", 601)
		},
		"unavailable carries stale sources": func(r *protocol.ContextRefreshResponse) { r.Status = "unavailable" },
		"authority claim":                   func(r *protocol.ContextRefreshResponse) { authorized := true; r.ActionAuthorized = &authorized },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			response := contextRefreshTestResponse()
			binding := response
			response.PreparedProjectContext.Sources[0].Excerpt = "PRIVATE must not print"
			mutate(&response)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(response) }))
			defer server.Close()
			setContextRefreshTaskEnv(t, server.URL, binding)
			cmd := newContextRefreshCmd()
			cmd.Flags().Set("project-id", binding.ProjectID)
			cmd.Flags().Set("issue-id", binding.IssueID)
			var out bytes.Buffer
			cmd.SetOut(&out)
			err := runContextRefresh(cmd, nil)
			if err == nil || out.Len() != 0 || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("invalid response returned private content")
			}
		})
	}
	validPayload, _ := json.Marshal(contextRefreshTestResponse())
	for name, body := range map[string]string{
		"unknown fields":   strings.TrimSuffix(string(validPayload), "}") + `,"private_description":"PRIVATE"}`,
		"oversize":         strings.Repeat("PRIVATE", 1000),
		"trailing payload": string(validPayload) + ` {"PRIVATE":true}`,
		"invalid UTF8":     strings.TrimSuffix(string(validPayload), "}") + string([]byte{0xff}) + "}",
	} {
		t.Run(name, func(t *testing.T) {
			response := contextRefreshTestResponse()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
			defer server.Close()
			setContextRefreshTaskEnv(t, server.URL, response)
			cmd := newContextRefreshCmd()
			cmd.Flags().Set("project-id", response.ProjectID)
			cmd.Flags().Set("issue-id", response.IssueID)
			var out bytes.Buffer
			cmd.SetOut(&out)
			if err := runContextRefresh(cmd, nil); err == nil || out.Len() != 0 || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("unknown/oversized/trailing response printed arbitrary content")
			}
		})
	}
}

func TestContextRefreshNativeCLIRejectsHTTPErrorBodyAndRedirect(t *testing.T) {
	var redirected atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
	defer destination.Close()
	for _, status := range []int{http.StatusForbidden, http.StatusFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			response := contextRefreshTestResponse()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", destination.URL)
				w.WriteHeader(status)
				_, _ = w.Write([]byte("PRIVATE arbitrary error/redirect response"))
			}))
			defer server.Close()
			setContextRefreshTaskEnv(t, server.URL, response)
			cmd := newContextRefreshCmd()
			cmd.Flags().Set("project-id", response.ProjectID)
			cmd.Flags().Set("issue-id", response.IssueID)
			var out bytes.Buffer
			cmd.SetOut(&out)
			err := runContextRefresh(cmd, nil)
			if err == nil || out.Len() != 0 || strings.Contains(err.Error(), "PRIVATE") || redirected.Load() != 0 {
				t.Fatal("HTTP failure leaked arbitrary body or followed redirect")
			}
		})
	}
}
