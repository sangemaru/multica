package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/multica-ai/multica/server/internal/auth"
	"github.com/multica-ai/multica/server/internal/testutil"
	"github.com/multica-ai/multica/server/pkg/protocol"
)

// The compiled daemon-package peer is needed only because the actual env helper
// is private to that package. No product export, mock HTTP server or installed
// native CLI is used. TestMain must use a fresh, isolated synthetic database.
func TestHybridContextNativeCustodyIntegration(t *testing.T) {
	peer, cliBinary := os.Getenv("MULTICA_HYBRID_CUSTODY_PEER_BINARY"), os.Getenv("MULTICA_HYBRID_CLI_TEST_BINARY")
	if peer == "" || cliBinary == "" {
		t.Skip("requires compiled candidate CLI and daemon custody peer")
	}
	for _, path := range []string{peer, cliBinary} {
		info, err := os.Stat(path)
		if !filepath.IsAbs(path) || err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
			t.Fatal("invalid test-created candidate executable")
		}
	}
	u, err := url.Parse(testServer.URL)
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" {
		t.Fatal("fixture server is not isolated loopback")
	}
	fx := testutil.New(testPool, testWorkspaceID, testUserID)
	project := fx.Project(t, "Synthetic native custody project")
	issue := fx.Issue(t, "Synthetic custody trigger", testutil.Cols{"project_id": project})
	sourceIssue := fx.Issue(t, "Synthetic custody source", testutil.Cols{"project_id": project})
	oldText := "RO: Ședință sintetică. EN: selected observation, not authorization. <>&\u2028"
	newText := "RO: schimbare sintetică. EN: not automatically selected."
	source := fx.Comment(t, sourceIssue, oldText)
	runtime := fx.Runtime(t, "Synthetic custody runtime")
	agentID := fx.Agent(t, "Synthetic custody agent", runtime)
	task := fx.Task(t, agentID, testutil.Cols{"issue_id": issue, "runtime_id": runtime, "status": "running"})
	token := "mat_custody_fixture_" + task
	fx.Insert(t, "task_token", testutil.Cols{"token_hash": auth.HashToken(token), "task_id": task, "agent_id": agentID,
		"workspace_id": testWorkspaceID, "user_id": testUserID, "expires_at": time.Now().Add(time.Hour)})
	selection, err := json.Marshal(map[string]any{"operational_context_mode": "hybrid", "context_comment_1": source, "context_comment_1_revision": 1})
	if err != nil {
		t.Fatal("cannot encode fixture selection")
	}
	fx.Exec(t, "UPDATE issue SET metadata = $1 WHERE id = $2", selection, issue)
	req := testutil.WithHeaders(testutil.JSONRequest(http.MethodGet,
		"/api/context/refresh?expected_project_id="+project+"&expected_issue_id="+issue, nil),
		"Authorization", "Bearer "+token, "X-Workspace-ID", testWorkspaceID)
	var initial protocol.ContextRefreshResponse
	testutil.Call(t, testServer.Config.Handler.ServeHTTP, req).Want(http.StatusOK).JSON(&initial)
	binding := protocol.ContextBinding{TaskID: task, WorkspaceID: testWorkspaceID, ProjectID: project, IssueID: issue}
	if initial.Status != "available" || initial.ContextBinding != binding ||
		!protocol.ValidPreparedProjectContext(initial.PreparedProjectContext, binding, time.Now()) ||
		len(initial.PreparedProjectContext.Sources) != 1 || initial.PreparedProjectContext.Sources[0].SourceID != source ||
		initial.PreparedProjectContext.Sources[0].IssueID != sourceIssue || initial.PreparedProjectContext.Sources[0].Excerpt != oldText {
		t.Fatal("real Auth/router did not produce the exact initial observation")
	}
	fixture, err := json.Marshal(map[string]any{"binding": binding, "agent_id": agentID, "token": token, "server": testServer.URL,
		"cli": cliBinary, "initial": initial.PreparedProjectContext, "old_text": oldText, "new_text": newText})
	if err != nil {
		t.Fatal("cannot encode synthetic peer fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, peer, "-test.run=^TestHybridContextNativeCustodyPeer$", "-test.timeout=20s")
	cmd.Dir = t.TempDir()
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "TMPDIR=" + cmd.Dir, "MULTICA_HYBRID_CUSTODY_FIXTURE=" + string(fixture)}
	cmd.WaitDelay = time.Second
	cmd.Stderr = io.Discard // No token, response bodies or process env in logs.
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal("cannot capture peer receipt")
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal("cannot open bounded peer rendezvous")
	}
	if cmd.Start() != nil {
		t.Fatal("cannot start the compiled peer")
	}
	waited := false
	t.Cleanup(func() {
		cancel()
		_ = stdin.Close()
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		if cmd.ProcessState == nil || !cmd.ProcessState.Exited() {
			t.Error("owned daemon peer was not reaped")
		}
	})
	scanner := bufio.NewScanner(io.LimitReader(stdout, 16*1024))
	scanner.Buffer(make([]byte, 1024), 2048)
	phases := []string{}
	for scanner.Scan() {
		line := scanner.Text()
		if line == "PASS" {
			continue
		}
		var receipt struct {
			Phase                  string `json:"phase"`
			SourceExact            bool   `json:"source_exact"`
			BindingExact           bool   `json:"binding_exact"`
			ForgedIdentityRejected bool   `json:"forged_identity_rejected"`
			SourceOmitted          bool   `json:"source_omitted"`
			ToolResults            int    `json:"tool_results"`
		}
		if json.Unmarshal([]byte(line), &receipt) != nil {
			t.Fatal("peer emitted an unexpected/non-machine receipt")
		}
		phases = append(phases, receipt.Phase)
		switch len(phases) {
		case 1:
			if receipt.Phase != "available" || !receipt.SourceExact || !receipt.BindingExact || !receipt.ForgedIdentityRejected {
				t.Fatal("positive custody transcript was not accepted")
			}
			fx.Exec(t, "UPDATE comment SET content = $1, revision = 2, updated_at = now() WHERE id = $2", newText, source)
			if _, err := io.WriteString(stdin, "drift\n"); err != nil {
				t.Fatal("could not release the bounded drift rendezvous")
			}
		case 2:
			if receipt.Phase != "unavailable" || !receipt.SourceOmitted || !receipt.BindingExact {
				t.Fatal("drift reused source text in the native tool transcript")
			}
		case 3:
			if receipt.Phase != "complete" || receipt.ToolResults != 2 {
				t.Fatal("incomplete native custody turn")
			}
		default:
			t.Fatal("unexpected extra native custody receipt")
		}
	}
	_ = stdin.Close()
	if scanner.Err() != nil {
		t.Fatal("peer receipt exceeded bounds")
	}
	err = cmd.Wait()
	waited = true
	if err != nil || ctx.Err() != nil || strings.Join(phases, ",") != "available,unavailable,complete" {
		t.Fatal("bounded native custody peer failed; no skipped acceptance")
	}
	// A refresh is read-only: the caller's explicit selection must still be revision1.
	var finalSelection []byte
	if testPool.QueryRow(context.Background(), "SELECT metadata FROM issue WHERE id = $1", issue).Scan(&finalSelection) != nil {
		t.Fatal("cannot verify persisted selection custody")
	}
	var metadata map[string]any
	if json.Unmarshal(finalSelection, &metadata) != nil || metadata["context_comment_1"] != source || metadata["context_comment_1_revision"] != float64(1) {
		t.Fatal("refresh changed user-selected source/revision")
	}
	t.Log("actual daemon helper -> BuildPrompt -> ResolveBackend/Execute -> fake Codex tool transcript -> real candidate CLI/Auth/DB: available, revision drift unavailable; selection unchanged; owned subprocesses reaped")
}
