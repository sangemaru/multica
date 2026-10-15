package handler

import (
	"bytes"
	"context"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/multica-ai/multica/server/internal/util"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
	"github.com/multica-ai/multica/server/pkg/protocol"
)

type taskContextRefreshQueries interface {
	claimContextQueries
	GetAgentTaskInWorkspace(context.Context, db.GetAgentTaskInWorkspaceParams) (db.AgentTaskQueue, error)
}

type refreshTaskBinding struct {
	taskID          pgtype.UUID
	agentID         pgtype.UUID
	workspaceID     pgtype.UUID
	expectedIssueID pgtype.UUID // caller guard, never the issue data selector
}

// Only Auth-stamped task-token identity is accepted. Caller-supplied task IDs,
// daemon/owner credentials and actor fallback paths are deliberately absent.
func refreshTaskBindingFromRequest(r *http.Request) (refreshTaskBinding, bool) {
	if r.Header.Get("X-Actor-Source") != "task_token" {
		return refreshTaskBinding{}, false
	}
	var binding refreshTaskBinding
	for header, destination := range map[string]*pgtype.UUID{
		"X-Task-ID": &binding.taskID, "X-Agent-ID": &binding.agentID, "X-Workspace-ID": &binding.workspaceID,
	} {
		value := r.Header.Get(header)
		id, err := util.ParseUUID(value)
		if err != nil || !protocol.CanonicalContextID(value) {
			return refreshTaskBinding{}, false
		}
		*destination = id
	}
	return binding, true
}

// One deadline covers task, current issue, and all selected-source reads.
// HTTP auth/workspace membership are enforced before this pure query seam.
func refreshTaskProjectContext(parent context.Context, q taskContextRefreshQueries, binding refreshTaskBinding, expectedProject pgtype.UUID, now time.Time) (protocol.ContextRefreshResponse, int) {
	if !binding.taskID.Valid || !binding.agentID.Valid || !binding.workspaceID.Valid || !binding.expectedIssueID.Valid || !expectedProject.Valid || now.IsZero() {
		return protocol.ContextRefreshResponse{}, http.StatusForbidden
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	if ctx.Err() != nil {
		return protocol.ContextRefreshResponse{}, http.StatusServiceUnavailable
	}
	task, err := q.GetAgentTaskInWorkspace(ctx, db.GetAgentTaskInWorkspaceParams{ID: binding.taskID, WorkspaceID: binding.workspaceID})
	if ctx.Err() != nil {
		return protocol.ContextRefreshResponse{}, http.StatusServiceUnavailable
	}
	if err != nil || task.ID != binding.taskID || task.AgentID != binding.agentID || !task.IssueID.Valid || task.ChatSessionID.Valid {
		return protocol.ContextRefreshResponse{}, http.StatusForbidden
	}
	if task.Status != "running" || task.IssueID != binding.expectedIssueID {
		return protocol.ContextRefreshResponse{}, http.StatusConflict
	}
	issue, err := q.GetIssueInWorkspace(ctx, db.GetIssueInWorkspaceParams{ID: task.IssueID, WorkspaceID: binding.workspaceID})
	if ctx.Err() != nil {
		return protocol.ContextRefreshResponse{}, http.StatusServiceUnavailable
	}
	if err != nil || issue.ID != task.IssueID || issue.WorkspaceID != binding.workspaceID {
		return protocol.ContextRefreshResponse{}, http.StatusForbidden
	}
	hybrid, _ := claimProjectContextMode(issue.Metadata, "")
	if !hybrid || issue.ProjectID != expectedProject {
		return protocol.ContextRefreshResponse{}, http.StatusConflict
	}
	unauthorized := false
	response := protocol.ContextRefreshResponse{
		Status: "unavailable", ContextBinding: protocol.ContextBinding{TaskID: util.UUIDToString(task.ID), WorkspaceID: util.UUIDToString(binding.workspaceID),
			ProjectID: util.UUIDToString(issue.ProjectID), IssueID: util.UUIDToString(issue.ID)},
		ObservedAt: now.UTC().Format(time.RFC3339Nano), Coverage: "partial", Freshness: "unknown", ActionAuthorized: &unauthorized,
	}
	response.PreparedProjectContext = prepareClaimProjectContext(ctx, q, task.ID, task.AgentID, binding.workspaceID, issue, now)
	if ctx.Err() != nil {
		return protocol.ContextRefreshResponse{}, http.StatusServiceUnavailable
	}
	// Detect cancellation/rebinding while source reads were in flight. These
	// guards are observations, not a transaction-atomic source snapshot.
	currentTask, err := q.GetAgentTaskInWorkspace(ctx, db.GetAgentTaskInWorkspaceParams{ID: binding.taskID, WorkspaceID: binding.workspaceID})
	if ctx.Err() != nil {
		return protocol.ContextRefreshResponse{}, http.StatusServiceUnavailable
	}
	if err != nil || currentTask.ID != task.ID || currentTask.AgentID != task.AgentID || currentTask.IssueID != task.IssueID ||
		currentTask.Status != "running" || currentTask.ChatSessionID.Valid {
		return protocol.ContextRefreshResponse{}, http.StatusConflict
	}
	currentIssue, err := q.GetIssueInWorkspace(ctx, db.GetIssueInWorkspaceParams{ID: task.IssueID, WorkspaceID: binding.workspaceID})
	if ctx.Err() != nil {
		return protocol.ContextRefreshResponse{}, http.StatusServiceUnavailable
	}
	currentHybrid, _ := claimProjectContextMode(currentIssue.Metadata, "")
	if err != nil || currentIssue.ID != issue.ID || currentIssue.WorkspaceID != binding.workspaceID || currentIssue.ProjectID != expectedProject || !currentHybrid {
		return protocol.ContextRefreshResponse{}, http.StatusConflict
	}
	if !bytes.Equal(currentIssue.Metadata, issue.Metadata) {
		response.PreparedProjectContext = nil
	}
	if response.PreparedProjectContext != nil {
		response.Status = "available"
	}
	return response, http.StatusOK
}
