package handler

import (
	"net/http"
	"time"

	"github.com/multica-ai/multica/server/pkg/protocol"
)

// RefreshTaskProjectContext is registered under Auth and workspace middleware.
// The project parameter is a guard, never a selector for arbitrary task data.
func (h *Handler) RefreshTaskProjectContext(w http.ResponseWriter, r *http.Request) {
	binding, ok := refreshTaskBindingFromRequest(r)
	if !ok {
		writeError(w, http.StatusForbidden, "context refresh requires task-token identity")
		return
	}
	projectString := r.URL.Query().Get("expected_project_id")
	projectID, ok := parseUUIDOrBadRequest(w, projectString, "expected_project_id")
	if !ok {
		return
	}
	if !protocol.CanonicalContextID(projectString) {
		writeError(w, http.StatusBadRequest, "expected_project_id must be a canonical UUID")
		return
	}
	issueString := r.URL.Query().Get("expected_issue_id")
	issueID, ok := parseUUIDOrBadRequest(w, issueString, "expected_issue_id")
	if !ok {
		return
	}
	if !protocol.CanonicalContextID(issueString) {
		writeError(w, http.StatusBadRequest, "expected_issue_id must be a canonical UUID")
		return
	}
	binding.expectedIssueID = issueID
	response, status := refreshTaskProjectContext(r.Context(), h.Queries, binding, projectID, time.Now())
	w.Header().Set("Cache-Control", "no-store")
	if status != http.StatusOK {
		writeError(w, status, "context refresh unavailable for this task binding")
		return
	}
	writeJSON(w, status, response)
}
