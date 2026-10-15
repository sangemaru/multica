package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/multica-ai/multica/server/internal/util"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
	"github.com/multica-ai/multica/server/pkg/protocol"
)

type claimContextQueries interface {
	GetCommentInWorkspace(context.Context, db.GetCommentInWorkspaceParams) (db.Comment, error)
	GetIssueInWorkspace(context.Context, db.GetIssueInWorkspaceParams) (db.Issue, error)
}

type claimCommentSelector struct {
	id       pgtype.UUID
	revision int64
}

// Explicit issue-task opt-in only. Privacy minimization is independent of
// whether the optional selected-source lookup succeeds.
func claimProjectContextMode(raw []byte, description string) (bool, string) {
	var metadata map[string]json.RawMessage
	var mode string
	if json.Unmarshal(raw, &metadata) == nil && json.Unmarshal(metadata["operational_context_mode"], &mode) == nil && mode == "hybrid" {
		return true, ""
	}
	return false, description
}

// Local candidate contract: metadata context_comment_1..3 holds canonical
// comment UUIDs, each paired with context_comment_N_revision (a JSON integer).
// Only whole, short comments are eligible: no implicit body slicing or ranking.
// Selection does not establish business authority or current decision status.
func parseClaimCommentSelectors(raw []byte) ([]claimCommentSelector, bool) {
	var metadata map[string]json.RawMessage
	if len(raw) == 0 {
		return nil, true
	}
	if json.Unmarshal(raw, &metadata) != nil || metadata == nil {
		return nil, false
	}
	allowed := make(map[string]bool)
	for i := 1; i <= 3; i++ {
		key := fmt.Sprintf("context_comment_%d", i)
		allowed[key], allowed[key+"_revision"] = true, true
	}
	for key := range metadata {
		if strings.HasPrefix(key, "context_comment_") && !allowed[key] {
			return nil, false
		}
	}
	var selected []claimCommentSelector
	seen := make(map[pgtype.UUID]bool)
	for i := 1; i <= 3; i++ {
		key := fmt.Sprintf("context_comment_%d", i)
		idRaw, hasID := metadata[key]
		revRaw, hasRev := metadata[key+"_revision"]
		if !hasID && !hasRev {
			continue
		}
		if !hasID || !hasRev {
			return nil, false
		}
		var idString string
		if json.Unmarshal(idRaw, &idString) != nil {
			return nil, false
		}
		id, err := util.ParseUUID(idString)
		if err != nil || !id.Valid || util.UUIDToString(id) != idString || seen[id] {
			return nil, false
		}
		revision, err := strconv.ParseInt(string(revRaw), 10, 64)
		if err != nil || revision < 0 {
			return nil, false
		}
		seen[id] = true
		selected = append(selected, claimCommentSelector{id: id, revision: revision})
	}
	return selected, true
}

// Called only after the authenticated claim's workspace mismatch gate. The
// passed workspace is the actual runtime's workspace, never its owner's scope.
// Existing authorization is workspace-level; this adds a project boundary and
// honors per-comment agent suppression. It does not invent project ACLs.
func prepareClaimProjectContext(parent context.Context, q claimContextQueries, taskID, agentID, workspaceID pgtype.UUID, issue db.Issue, now time.Time) *protocol.PreparedProjectContext {
	if hybrid, _ := claimProjectContextMode(issue.Metadata, ""); !hybrid {
		return nil
	}
	if !taskID.Valid || !agentID.Valid || !workspaceID.Valid || !issue.ID.Valid || !issue.ProjectID.Valid ||
		issue.WorkspaceID != workspaceID || now.IsZero() {
		return nil
	}
	selectors, ok := parseClaimCommentSelectors(issue.Metadata)
	if !ok || len(selectors) == 0 {
		return nil
	}
	// One total budget, inherited from the claim request. No per-source reset.
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	observation := &protocol.PreparedProjectContext{
		TaskID: util.UUIDToString(taskID), WorkspaceID: util.UUIDToString(workspaceID),
		ProjectID: util.UUIDToString(issue.ProjectID), IssueID: util.UUIDToString(issue.ID),
		ObservedAt: now.UTC().Format(time.RFC3339Nano), ExpiresAt: now.Add(5 * time.Minute).UTC().Format(time.RFC3339Nano),
	}
	for _, selector := range selectors {
		if ctx.Err() != nil {
			return nil
		}
		comment, err := q.GetCommentInWorkspace(ctx, db.GetCommentInWorkspaceParams{ID: selector.id, WorkspaceID: workspaceID})
		if err != nil || comment.ID != selector.id || comment.WorkspaceID != workspaceID || !comment.IssueID.Valid ||
			comment.DeletedAt.Valid || comment.Revision != selector.revision || !utf8.ValidString(comment.Content) ||
			strings.TrimSpace(comment.Content) == "" || len(comment.Content) > 600 ||
			!validClaimContextTimestamp(comment.CreatedAt, now) || !validClaimContextTimestamp(comment.UpdatedAt, now) ||
			comment.UpdatedAt.Time.Before(comment.CreatedAt.Time) {
			return nil
		}
		for _, suppressed := range comment.SuppressedAgentIds {
			if suppressed == agentID {
				return nil
			}
		}
		sourceIssue, err := q.GetIssueInWorkspace(ctx, db.GetIssueInWorkspaceParams{ID: comment.IssueID, WorkspaceID: workspaceID})
		if err != nil || sourceIssue.ID != comment.IssueID || sourceIssue.WorkspaceID != workspaceID || sourceIssue.ProjectID != issue.ProjectID {
			return nil
		}
		observation.Sources = append(observation.Sources, protocol.PreparedContextSource{
			WorkspaceID: observation.WorkspaceID, ProjectID: observation.ProjectID, IssueID: util.UUIDToString(sourceIssue.ID),
			SourceID: util.UUIDToString(comment.ID), Revision: comment.Revision,
			UpdatedAt: comment.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), Excerpt: comment.Content,
		})
	}
	encoded, err := json.Marshal(observation)
	if ctx.Err() != nil || err != nil || len(encoded) > protocol.MaxPreparedContextJSONBytes {
		return nil // No partial selection, private content/error logs, or fallback.
	}
	return observation
}

func validClaimContextTimestamp(value pgtype.Timestamptz, observed time.Time) bool {
	return value.Valid && value.InfinityModifier == pgtype.Finite && !value.Time.IsZero() && !value.Time.After(observed) && value.Time.Year() >= 1 && value.Time.Year() <= 9999
}
