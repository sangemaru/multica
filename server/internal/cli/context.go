package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/multica-ai/multica/server/pkg/protocol"
)

// RefreshTaskContext uses the official API client's task credentials, with a
// strict bounded response. No redirect, cached snapshot or member fallback.
func (c *APIClient) RefreshTaskContext(ctx context.Context, expected protocol.ContextBinding) (protocol.ContextRefreshResponse, error) {
	var response protocol.ContextRefreshResponse
	if !strings.HasPrefix(c.Token, TaskTokenPrefix) || c.TaskID != expected.TaskID || c.WorkspaceID != expected.WorkspaceID ||
		!protocol.CanonicalContextID(c.AgentID) || !protocol.CanonicalContextID(expected.TaskID) ||
		!protocol.CanonicalContextID(expected.WorkspaceID) || !protocol.CanonicalContextID(expected.ProjectID) ||
		!protocol.CanonicalContextID(expected.IssueID) {
		return response, fmt.Errorf("context refresh requires valid task-token binding")
	}
	// A dedicated practical refresh bound; a shorter caller deadline wins.
	// Process startup and OS scheduling are outside this HTTP-context budget.
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	path := "/api/context/refresh?expected_project_id=" + url.QueryEscape(expected.ProjectID) + "&expected_issue_id=" + url.QueryEscape(expected.IssueID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return response, fmt.Errorf("context refresh request unavailable")
	}
	c.setHeaders(req)
	transport := *c.HTTPClient
	transport.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := transport.Do(req)
	if err != nil {
		return response, fmt.Errorf("context refresh transport unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return response, &HTTPError{Method: http.MethodGet, Path: path, StatusCode: resp.StatusCode, Body: "context refresh unavailable", TaskScoped: true}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if err != nil || len(data) > 4096 || !utf8.Valid(data) {
		return response, fmt.Errorf("context refresh response unavailable or oversized")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&response) != nil || decoder.Decode(new(any)) != io.EOF || !validContextRefreshResponse(response, expected, time.Now()) {
		return protocol.ContextRefreshResponse{}, fmt.Errorf("context refresh response has invalid binding or schema")
	}
	return response, nil
}

func validContextRefreshResponse(response protocol.ContextRefreshResponse, expected protocol.ContextBinding, now time.Time) bool {
	if response.TaskID != expected.TaskID || response.WorkspaceID != expected.WorkspaceID || response.ProjectID != expected.ProjectID ||
		!protocol.CanonicalContextID(response.IssueID) || response.IssueID != expected.IssueID ||
		response.Coverage != "partial" || response.Freshness != "unknown" || response.ActionAuthorized == nil || *response.ActionAuthorized {
		return false
	}
	observed, err := time.Parse(time.RFC3339Nano, response.ObservedAt)
	if err != nil || observed.After(now) || now.Sub(observed) > 5*time.Minute {
		return false
	}
	switch response.Status {
	case "unavailable":
		return response.PreparedProjectContext == nil
	case "available":
		return response.PreparedProjectContext != nil && response.PreparedProjectContext.ObservedAt == response.ObservedAt &&
			protocol.ValidPreparedProjectContext(response.PreparedProjectContext, response.ContextBinding, now)
	default:
		return false
	}
}
