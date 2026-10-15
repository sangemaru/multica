package protocol

import (
	"encoding/json"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/multica-ai/multica/server/internal/util"
)

// PreparedProjectContext is a bounded claim-time observation, not a complete
// project snapshot, proof of live freshness, or permission for an action.
type PreparedProjectContext struct {
	TaskID      string                  `json:"task_id"`
	WorkspaceID string                  `json:"workspace_id"`
	ProjectID   string                  `json:"project_id"`
	IssueID     string                  `json:"issue_id"`
	ObservedAt  string                  `json:"observed_at"`
	ExpiresAt   string                  `json:"expires_at"`
	Sources     []PreparedContextSource `json:"sources"`
}

type PreparedContextSource struct {
	WorkspaceID string `json:"workspace_id"`
	ProjectID   string `json:"project_id"`
	IssueID     string `json:"issue_id"`
	SourceID    string `json:"source_id"`
	Revision    int64  `json:"revision"`
	UpdatedAt   string `json:"updated_at"`
	Excerpt     string `json:"excerpt"`
}

// MaxPreparedContextJSONBytes leaves room for the daemon's fixed 4096-byte
// operational-context envelope. JSON escaping counts toward this budget.
const MaxPreparedContextJSONBytes = 2600

type ContextBinding struct {
	TaskID      string `json:"task_id"`
	WorkspaceID string `json:"workspace_id"`
	ProjectID   string `json:"project_id"`
	IssueID     string `json:"issue_id"`
}

// ContextRefreshResponse is a bounded observation, not automatic refresh,
// whole-project freshness, service-health proof, or action authorization.
type ContextRefreshResponse struct {
	Status string `json:"status"`
	ContextBinding
	ObservedAt             string                  `json:"observed_at"`
	Coverage               string                  `json:"coverage"`
	Freshness              string                  `json:"freshness"`
	ActionAuthorized       *bool                   `json:"action_authorized"`
	PreparedProjectContext *PreparedProjectContext `json:"prepared_project_context,omitempty"`
}

func CanonicalContextID(id string) bool {
	u, err := util.ParseUUID(id)
	return err == nil && u.Valid && util.UUIDToString(u) == id
}

// ValidPreparedProjectContext is shared by native claim and refresh consumers.
// Identity, timestamps and byte bounds validate delivery, not business truth.
func ValidPreparedProjectContext(c *PreparedProjectContext, binding ContextBinding, now time.Time) bool {
	for _, id := range []string{binding.TaskID, binding.WorkspaceID, binding.ProjectID, binding.IssueID} {
		if !CanonicalContextID(id) {
			return false
		}
	}
	if c == nil || c.TaskID != binding.TaskID || c.WorkspaceID != binding.WorkspaceID || c.ProjectID != binding.ProjectID ||
		c.IssueID != binding.IssueID || len(c.Sources) == 0 || len(c.Sources) > 3 {
		return false
	}
	observed, err := time.Parse(time.RFC3339Nano, c.ObservedAt)
	if err != nil || observed.After(now) {
		return false
	}
	expires, err := time.Parse(time.RFC3339Nano, c.ExpiresAt)
	if err != nil || !expires.After(now) || !expires.After(observed) || expires.Sub(observed) > 5*time.Minute {
		return false
	}
	seen := make(map[string]bool)
	for _, source := range c.Sources {
		if source.WorkspaceID != binding.WorkspaceID || source.ProjectID != binding.ProjectID ||
			!CanonicalContextID(source.IssueID) || !CanonicalContextID(source.SourceID) || source.Revision < 0 ||
			!utf8.ValidString(source.Excerpt) || strings.TrimSpace(source.Excerpt) == "" || len(source.Excerpt) > 600 || seen[source.SourceID] {
			return false
		}
		updated, err := time.Parse(time.RFC3339Nano, source.UpdatedAt)
		if err != nil || updated.After(observed) {
			return false
		}
		seen[source.SourceID] = true
	}
	encoded, err := json.Marshal(c)
	return err == nil && len(encoded) <= MaxPreparedContextJSONBytes
}
