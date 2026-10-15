package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/multica-ai/multica/server/internal/auth"
	"github.com/multica-ai/multica/server/internal/testutil"
	"github.com/multica-ai/multica/server/pkg/protocol"
)

// This suite uses TestMain's real PostgreSQL pool and NewRouter, including Auth
// and RequireWorkspaceMember. Run only against an isolated synthetic test DB;
// TestMain's missing-DB skip is not evidence that these assertions ran.
func TestHybridContextRefreshIntegration(t *testing.T) {
	type fixture struct {
		fx                                                      *testutil.Fixture
		project, issue, sourceIssue, source, agent, task, token string
		excerpt                                                 string
	}
	setup := func(t *testing.T) fixture {
		fx := testutil.New(testPool, testWorkspaceID, testUserID)
		project := fx.Project(t, "Synthetic hybrid refresh project")
		issue := fx.Issue(t, "Synthetic active task", testutil.Cols{"project_id": project})
		sourceIssue := fx.Issue(t, "Synthetic operational source", testutil.Cols{"project_id": project})
		excerpt := "RO: Ședință aprobată doar pentru test. EN: observation, not authorization. <>&\u2028"
		source := fx.Comment(t, sourceIssue, excerpt)
		runtime := fx.Runtime(t, "Synthetic refresh runtime")
		agent := fx.Agent(t, "Synthetic refresh agent", runtime)
		task := fx.Task(t, agent, testutil.Cols{"issue_id": issue, "status": "running", "runtime_id": runtime})
		metadata, err := json.Marshal(map[string]any{"operational_context_mode": "hybrid", "context_comment_1": source, "context_comment_1_revision": int64(1)})
		if err != nil {
			t.Fatal(err)
		}
		fx.Exec(t, "UPDATE issue SET metadata = $1 WHERE id = $2", metadata, issue)
		// A synthetic task token is inserted through the actual persisted hash
		// path. No configured credentials or header-only authentication mocks.
		token := "mat_hybrid_fixture_" + task
		fx.Insert(t, "task_token", testutil.Cols{"token_hash": auth.HashToken(token), "task_id": task, "agent_id": agent, "workspace_id": testWorkspaceID, "user_id": testUserID, "expires_at": time.Now().Add(time.Hour)})
		return fixture{fx: fx, project: project, issue: issue, sourceIssue: sourceIssue, source: source, agent: agent, task: task, token: token, excerpt: excerpt}
	}
	request := func(f fixture, token, project, issue string) *http.Request {
		query := url.Values{"expected_project_id": {project}, "expected_issue_id": {issue}}
		return testutil.WithHeaders(testutil.JSONRequest(http.MethodGet, "/api/context/refresh?"+query.Encode(), nil), "Authorization", "Bearer "+token, "X-Workspace-ID", testWorkspaceID)
	}
	call := func(t *testing.T, req *http.Request, status int) *testutil.Response {
		return testutil.Call(t, testServer.Config.Handler.ServeHTTP, req).Want(status)
	}
	available := func(t *testing.T, f fixture, req *http.Request) protocol.ContextRefreshResponse {
		t.Helper()
		before := time.Now()
		var out protocol.ContextRefreshResponse
		response := call(t, req, http.StatusOK).JSON(&out)
		after := time.Now()
		binding := protocol.ContextBinding{TaskID: f.task, WorkspaceID: testWorkspaceID, ProjectID: f.project, IssueID: f.issue}
		if out.Status != "available" || out.ContextBinding != binding || out.Coverage != "partial" || out.Freshness != "unknown" || out.ActionAuthorized == nil || *out.ActionAuthorized {
			t.Fatalf("unexpected observation envelope: %+v", out.ContextBinding)
		}
		observed, err := time.Parse(time.RFC3339Nano, out.ObservedAt)
		if err != nil || observed.Before(before) || observed.After(after) || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("observation must be current and non-cacheable")
		}
		prepared := out.PreparedProjectContext
		if !protocol.ValidPreparedProjectContext(prepared, binding, after) || prepared.ObservedAt != out.ObservedAt || len(prepared.Sources) != 1 {
			t.Fatal("invalid bounded prepared observation")
		}
		expires, err := time.Parse(time.RFC3339Nano, prepared.ExpiresAt)
		if err != nil || expires.Sub(observed) != 5*time.Minute {
			t.Fatal("incorrect observation expiry")
		}
		source := prepared.Sources[0]
		if source.SourceID != f.source || source.IssueID != f.sourceIssue || source.Revision != 1 || source.Excerpt != f.excerpt {
			t.Fatal("selected same-project source provenance or whole UTF-8 excerpt lost")
		}
		encoded, err := json.Marshal(prepared)
		if err != nil || len(encoded) > protocol.MaxPreparedContextJSONBytes {
			t.Fatal("prepared wire budget exceeded")
		}
		return out
	}
	redacted := func(t *testing.T, f fixture, req *http.Request, status int) {
		t.Helper()
		response := call(t, req, status)
		if strings.Contains(response.Text(), f.excerpt) || strings.Contains(response.Text(), f.token) || strings.Contains(response.Text(), f.source) {
			t.Fatal("rejection leaked selected source or token")
		}
	}

	t.Run("current observation with real task token", func(t *testing.T) {
		f := setup(t)
		available(t, f, request(f, f.token, f.project, f.issue))
	})
	t.Run("client actor and workspace spoof cannot rebind task", func(t *testing.T) {
		f := setup(t)
		req := request(f, f.token, f.project, f.issue)
		testutil.WithHeaders(req, "X-Actor-Source", "human", "X-Agent-ID", f.project, "X-Task-ID", f.sourceIssue, "X-Workspace-ID", f.project)
		q := req.URL.Query()
		q.Set("workspace_id", f.project)
		q.Set("workspace_slug", "not-the-token-workspace")
		req.URL.RawQuery = q.Encode()
		available(t, f, req)
	})
	t.Run("owner JWT cannot impersonate task token", func(t *testing.T) {
		f := setup(t)
		req := request(f, testToken, f.project, f.issue)
		testutil.WithHeaders(req, "X-Actor-Source", "task_token", "X-Agent-ID", f.agent, "X-Task-ID", f.task)
		redacted(t, f, req, http.StatusForbidden)
	})
	t.Run("invalid token is unauthenticated", func(t *testing.T) {
		f := setup(t)
		redacted(t, f, request(f, "mat_invalid_synthetic", f.project, f.issue), http.StatusUnauthorized)
	})
	for _, guard := range []string{"project", "issue"} {
		t.Run("wrong expected "+guard, func(t *testing.T) {
			f := setup(t)
			project, issue := f.project, f.issue
			if guard == "project" {
				project = f.fx.Project(t, "Other project")
			} else {
				issue = f.sourceIssue
			}
			redacted(t, f, request(f, f.token, project, issue), http.StatusConflict)
		})
	}
	t.Run("persisted token agent must match task", func(t *testing.T) {
		f := setup(t)
		other := f.fx.Agent(t, "Other synthetic agent", f.fx.Runtime(t, "Other synthetic runtime"))
		f.fx.Exec(t, "UPDATE task_token SET agent_id = $1 WHERE token_hash = $2", other, auth.HashToken(f.token))
		redacted(t, f, request(f, f.token, f.project, f.issue), http.StatusForbidden)
	})
	t.Run("persisted token workspace cannot access foreign task", func(t *testing.T) {
		f := setup(t)
		foreign := f.fx.Workspace(t, "Foreign synthetic workspace", "hybrid-refresh-"+f.task)
		f.fx.Member(t, foreign, testUserID, "owner")
		f.fx.Exec(t, "UPDATE task_token SET workspace_id = $1 WHERE token_hash = $2", foreign, auth.HashToken(f.token))
		redacted(t, f, request(f, f.token, f.project, f.issue), http.StatusForbidden)
	})
	t.Run("stopped task cannot refresh", func(t *testing.T) {
		f := setup(t)
		f.fx.Exec(t, "UPDATE agent_task_queue SET status = 'completed' WHERE id = $1", f.task)
		redacted(t, f, request(f, f.token, f.project, f.issue), http.StatusConflict)
	})
	t.Run("selected revision drift drops stale observation", func(t *testing.T) {
		f := setup(t)
		available(t, f, request(f, f.token, f.project, f.issue))
		newExcerpt := "RO: revizie nouă. EN: explicitly reselect this revision."
		f.fx.Exec(t, "UPDATE comment SET content = $1, revision = 2, updated_at = now() WHERE id = $2", newExcerpt, f.source)
		var out protocol.ContextRefreshResponse
		response := call(t, request(f, f.token, f.project, f.issue), http.StatusOK).JSON(&out)
		if out.Status != "unavailable" || out.PreparedProjectContext != nil || strings.Contains(response.Text(), f.excerpt) || strings.Contains(response.Text(), newExcerpt) {
			t.Fatal("revision drift must not substitute or return stale text")
		}
		f.fx.Exec(t, "UPDATE issue SET metadata = jsonb_set(metadata, '{context_comment_1_revision}', '2') WHERE id = $1", f.issue)
		call(t, request(f, f.token, f.project, f.issue), http.StatusOK).JSON(&out)
		if out.Status != "available" || out.PreparedProjectContext == nil || out.PreparedProjectContext.Sources[0].Revision != 2 || out.PreparedProjectContext.Sources[0].Excerpt != newExcerpt {
			t.Fatal("explicit current revision selection was not observed")
		}
	})
	for _, variant := range []string{"UTF-8 source bytes", "escaped JSON bytes", "foreign source project"} {
		t.Run("bounded unavailable for "+variant, func(t *testing.T) {
			f := setup(t)
			switch variant {
			case "UTF-8 source bytes":
				f.fx.Exec(t, "UPDATE comment SET content = $1 WHERE id = $2", strings.Repeat("ș", 301), f.source)
			case "escaped JSON bytes":
				f.fx.Exec(t, "UPDATE comment SET content = $1 WHERE id = $2", strings.Repeat("&", 600), f.source)
			case "foreign source project":
				f.fx.Exec(t, "UPDATE issue SET project_id = $1 WHERE id = $2", f.fx.Project(t, "Foreign source project"), f.sourceIssue)
			}
			var out protocol.ContextRefreshResponse
			response := call(t, request(f, f.token, f.project, f.issue), http.StatusOK).JSON(&out)
			if out.Status != "unavailable" || out.PreparedProjectContext != nil || strings.Contains(response.Text(), f.excerpt) || strings.Contains(response.Text(), "&amp;") {
				t.Fatalf("invalid selected source must be omitted whole (%s)", variant)
			}
		})
	}
	t.Run("malformed guard does not bypass task identity", func(t *testing.T) {
		f := setup(t)
		redacted(t, f, request(f, f.token, fmt.Sprintf("%s-invalid", f.project), f.issue), http.StatusBadRequest)
	})
}
