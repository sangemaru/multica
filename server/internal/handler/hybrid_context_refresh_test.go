package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

type fakeTaskContextRefreshQueries struct {
	*fakeClaimContextQueries
	task         db.AgentTaskQueue
	taskCalls    int
	taskDeadline time.Time
	onTask       func()
}

func (q *fakeTaskContextRefreshQueries) GetAgentTaskInWorkspace(ctx context.Context, arg db.GetAgentTaskInWorkspaceParams) (db.AgentTaskQueue, error) {
	q.taskCalls++
	q.taskDeadline, _ = ctx.Deadline()
	if q.onTask != nil {
		q.onTask()
	}
	if arg.WorkspaceID != q.workspace || arg.ID != q.task.ID {
		return db.AgentTaskQueue{}, nil
	}
	return q.task, q.err
}

func refreshContextFixture(t *testing.T) (*fakeTaskContextRefreshQueries, refreshTaskBinding, db.Issue, time.Time) {
	t.Helper()
	issue, _, sources, now := claimContextFixture(t)
	binding := refreshTaskBinding{taskID: claimContextUUID(t, 5), agentID: claimContextUUID(t, 6), workspaceID: issue.WorkspaceID, expectedIssueID: issue.ID}
	q := &fakeTaskContextRefreshQueries{fakeClaimContextQueries: sources,
		task: db.AgentTaskQueue{ID: binding.taskID, AgentID: binding.agentID, IssueID: issue.ID, Status: "running"}}
	return q, binding, issue, now
}

func TestRefreshTaskProjectContextScopedObservationAndRevisionDrift(t *testing.T) {
	q, binding, issue, now := refreshContextFixture(t)
	before := time.Now()
	response, status := refreshTaskProjectContext(context.Background(), q, binding, issue.ProjectID, now)
	after := time.Now()
	if status != http.StatusOK || response.Status != "available" || response.PreparedProjectContext == nil ||
		response.Freshness != "unknown" || response.Coverage != "partial" || response.ActionAuthorized == nil || *response.ActionAuthorized {
		t.Fatal("valid refresh did not return a non-authorizing bounded observation")
	}
	if q.taskDeadline.Before(before.Add(2*time.Second)) || q.taskDeadline.After(after.Add(2*time.Second)) || !q.deadline.Equal(q.taskDeadline) {
		t.Fatal("loads did not share one total two-second deadline")
	}
	if q.taskCalls != 2 || q.calls != 4 {
		t.Fatal("unexpected source reads")
	}
	// A changed selected revision is not automatically substituted or approved.
	for id, comment := range q.comments {
		comment.Revision++
		comment.Content = "PRIVATE changed source must not be returned"
		q.comments[id] = comment
	}
	response, status = refreshTaskProjectContext(context.Background(), q, binding, issue.ProjectID, now)
	encoded, _ := json.Marshal(response)
	if status != http.StatusOK || response.Status != "unavailable" || response.PreparedProjectContext != nil || strings.Contains(string(encoded), "PRIVATE") {
		t.Fatal("revision drift reused or exposed a stale/changed selection")
	}
}

func TestRefreshTaskProjectContextRejectsTaskBindingAndState(t *testing.T) {
	q, binding, issue, now := refreshContextFixture(t)
	binding.expectedIssueID = claimContextUUID(t, 90)
	if _, status := refreshTaskProjectContext(context.Background(), q, binding, issue.ProjectID, now); status != http.StatusConflict || q.calls != 0 {
		t.Fatal("caller issue guard selected arbitrary issue data")
	}
	for _, state := range []string{"queued", "dispatched", "preparing", "paused", "blocked", "completed", "failed", "cancelled", ""} {
		t.Run(state, func(t *testing.T) {
			q, binding, issue, now := refreshContextFixture(t)
			q.task.Status = state
			_, status := refreshTaskProjectContext(context.Background(), q, binding, issue.ProjectID, now)
			if status != http.StatusConflict || q.calls != 0 {
				t.Fatal("non-running task queried issue/source data")
			}
		})
	}
	for _, mutate := range []func(*fakeTaskContextRefreshQueries, *refreshTaskBinding, *db.Issue){
		func(q *fakeTaskContextRefreshQueries, binding *refreshTaskBinding, issue *db.Issue) {
			q.task.AgentID = claimContextUUID(t, 90)
		},
		func(q *fakeTaskContextRefreshQueries, binding *refreshTaskBinding, issue *db.Issue) {
			binding.workspaceID = claimContextUUID(t, 90)
		},
		func(q *fakeTaskContextRefreshQueries, binding *refreshTaskBinding, issue *db.Issue) {
			q.task.IssueID.Valid = false
		},
		func(q *fakeTaskContextRefreshQueries, binding *refreshTaskBinding, issue *db.Issue) {
			q.task.ChatSessionID = claimContextUUID(t, 90)
		},
	} {
		q, binding, issue, now := refreshContextFixture(t)
		mutate(q, &binding, &issue)
		if _, status := refreshTaskProjectContext(context.Background(), q, binding, issue.ProjectID, now); status != http.StatusForbidden || q.calls != 0 {
			t.Fatal("wrong task/agent/workspace/chat binding accepted")
		}
	}
	for _, mutate := range []func(*db.Issue){
		func(issue *db.Issue) { issue.ProjectID = claimContextUUID(t, 90) },
		func(issue *db.Issue) { issue.Metadata = []byte(`{}`) },
	} {
		q, binding, issue, now := refreshContextFixture(t)
		current := issue
		mutate(&current)
		q.issues[issue.ID] = current
		if _, status := refreshTaskProjectContext(context.Background(), q, binding, issue.ProjectID, now); status != http.StatusConflict || q.calls != 1 {
			t.Fatal("project move or revoked hybrid mode accepted")
		}
	}
}

func TestRefreshTaskProjectContextInheritedDeadlineAndCancellation(t *testing.T) {
	q, binding, issue, now := refreshContextFixture(t)
	ctx, cancel := context.WithDeadline(context.Background(), now.Add(time.Second))
	defer cancel()
	if _, status := refreshTaskProjectContext(ctx, q, binding, issue.ProjectID, now); status != http.StatusOK || q.taskDeadline.After(now.Add(time.Second)) {
		t.Fatal("inherited request deadline extended")
	}
	q, binding, issue, now = refreshContextFixture(t)
	ctx, cancel = context.WithCancel(context.Background())
	q.onTask = cancel
	if _, status := refreshTaskProjectContext(ctx, q, binding, issue.ProjectID, now); status != http.StatusServiceUnavailable || q.calls != 0 {
		t.Fatal("cancelled task load continued into private issue sources")
	}
}

func TestRefreshTaskProjectContextFinalGuardsRejectMidReadChanges(t *testing.T) {
	for name, mutate := range map[string]func(*fakeTaskContextRefreshQueries, db.Issue){
		"task completed": func(q *fakeTaskContextRefreshQueries, issue db.Issue) { q.task.Status = "completed" },
		"task rebound":   func(q *fakeTaskContextRefreshQueries, issue db.Issue) { q.task.IssueID = claimContextUUID(t, 90) },
		"project moved": func(q *fakeTaskContextRefreshQueries, issue db.Issue) {
			issue.ProjectID = claimContextUUID(t, 90)
			q.issues[issue.ID] = issue
		},
		"hybrid mode revoked": func(q *fakeTaskContextRefreshQueries, issue db.Issue) {
			issue.Metadata = []byte(`{}`)
			q.issues[issue.ID] = issue
		},
	} {
		t.Run(name, func(t *testing.T) {
			q, binding, issue, now := refreshContextFixture(t)
			q.onIssue = func() {
				if q.calls == 3 { // Selected comment's parent issue read.
					mutate(q, issue)
				}
			}
			response, status := refreshTaskProjectContext(context.Background(), q, binding, issue.ProjectID, now)
			if status != http.StatusConflict || response.PreparedProjectContext != nil {
				t.Fatal("mid-read state/project/identity change exposed source observation")
			}
		})
	}
	q, binding, issue, now := refreshContextFixture(t)
	q.onIssue = func() {
		if q.calls == 3 {
			changed := issue
			changed.Metadata = []byte(strings.ReplaceAll(string(issue.Metadata), `"context_comment_1_revision":2`, `"context_comment_1_revision":3`))
			q.issues[issue.ID] = changed
		}
	}
	response, status := refreshTaskProjectContext(context.Background(), q, binding, issue.ProjectID, now)
	if status != http.StatusOK || response.Status != "unavailable" || response.PreparedProjectContext != nil {
		t.Fatal("selection metadata changed mid-read without a visible unavailable state")
	}
}

func TestRefreshTaskBindingRequiresServerTaskTokenStamp(t *testing.T) {
	q, binding, _, _ := refreshContextFixture(t)
	_ = q
	r := httptest.NewRequest(http.MethodGet, "/api/context/refresh?task_id=foreign&agent_id=foreign", nil)
	r.Header.Set("X-Task-ID", "00000000-0000-4000-8000-000000000005")
	r.Header.Set("X-Agent-ID", "00000000-0000-4000-8000-000000000006")
	r.Header.Set("X-Workspace-ID", "00000000-0000-4000-8000-000000000002")
	for _, source := range []string{"", "cloud_pat", "member", "daemon"} {
		r.Header.Set("X-Actor-Source", source)
		if _, ok := refreshTaskBindingFromRequest(r); ok {
			t.Fatal("non-task-token actor accepted")
		}
	}
	r.Header.Set("X-Actor-Source", "task_token")
	got, ok := refreshTaskBindingFromRequest(r)
	if !ok || got.taskID != binding.taskID || got.agentID != binding.agentID || got.workspaceID != binding.workspaceID {
		t.Fatal("server-stamped binding not used independently of query identities")
	}
	r.Header.Set("X-Task-ID", "malformed")
	if _, ok := refreshTaskBindingFromRequest(r); ok {
		t.Fatal("malformed identity accepted")
	}
}
