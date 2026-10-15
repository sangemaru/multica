package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/multica-ai/multica/server/internal/auth"
	"github.com/multica-ai/multica/server/internal/cli"
	"github.com/multica-ai/multica/server/internal/testutil"
	"github.com/multica-ai/multica/server/pkg/protocol"
)

// Opt in with a separately compiled candidate CLI, not an installed CLI or a
// command-function mock. TestMain must be pointed at a fresh synthetic DB.
func TestHybridContextCLIIntegration(t *testing.T) {
	binary := os.Getenv("MULTICA_HYBRID_CLI_TEST_BINARY")
	if binary == "" {
		t.Skip("set MULTICA_HYBRID_CLI_TEST_BINARY to the compiled candidate CLI")
	}
	if !filepath.IsAbs(binary) {
		t.Fatal("candidate CLI test binary must be an absolute path")
	}
	if info, err := os.Stat(binary); err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		t.Fatal("candidate CLI test binary is missing or not executable")
	}
	server, err := url.Parse(testServer.URL)
	if err != nil || server.Scheme != "http" || server.Hostname() != "127.0.0.1" {
		t.Fatal("CLI fixture must target only TestMain's loopback server")
	}
	fx := testutil.New(testPool, testWorkspaceID, testUserID)
	project := fx.Project(t, "Synthetic CLI context project")
	issue := fx.Issue(t, "Synthetic CLI current issue", testutil.Cols{"project_id": project})
	sourceIssue := fx.Issue(t, "Synthetic CLI same-project source", testutil.Cols{"project_id": project})
	excerpt := "RO: Ședință sintetică. EN: fixture observation, not authorization. <>&\u2028"
	newExcerpt := "RO: revizie nouă sintetică. EN: current selected revision."
	source := fx.Comment(t, sourceIssue, excerpt)
	runtime := fx.Runtime(t, "Synthetic CLI runtime")
	agent := fx.Agent(t, "Synthetic CLI agent", runtime)
	task := fx.Task(t, agent, testutil.Cols{"issue_id": issue, "status": "running", "runtime_id": runtime})
	token := "mat_cli_fixture_" + task
	fx.Insert(t, "task_token", testutil.Cols{"token_hash": auth.HashToken(token), "task_id": task, "agent_id": agent, "workspace_id": testWorkspaceID, "user_id": testUserID, "expires_at": time.Now().Add(time.Hour)})
	selectRevision := func(revision int64) {
		metadata, err := json.Marshal(map[string]any{"operational_context_mode": "hybrid", "context_comment_1": source, "context_comment_1_revision": revision})
		if err != nil {
			t.Fatal("could not encode fixture selection")
		}
		fx.Exec(t, "UPDATE issue SET metadata = $1 WHERE id = $2", metadata, issue)
	}
	selectRevision(1)
	workDir := t.TempDir()
	configRoot := filepath.Join(workDir, "task-config")
	if err := os.Mkdir(configRoot, 0700); err != nil {
		t.Fatal("could not create task-local fixture config root")
	}
	// Explicit environment only: no HOME, credential, provider, daemon or
	// configuration inheritance from the host running this integration test.
	baseEnv := map[string]string{
		"PATH": "/usr/local/bin:/usr/bin:/bin", "TMPDIR": workDir,
		cli.TaskConfigRootEnv: configRoot,
		"MULTICA_SERVER_URL":  testServer.URL, "MULTICA_TOKEN": token,
		"MULTICA_TASK_ID": task, "MULTICA_AGENT_ID": agent, "MULTICA_WORKSPACE_ID": testWorkspaceID,
	}
	type result struct {
		stdout, stderr string
		err            error
	}
	run := func(t *testing.T, projectID, issueID string, overrides map[string]string) result {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, binary, "context", "refresh", "--project-id", projectID, "--issue-id", issueID, "--output", "json")
		cmd.Dir = workDir
		cmd.WaitDelay = time.Second
		for key, value := range baseEnv {
			if override, present := overrides[key]; present {
				value = override
			}
			if value != "" {
				cmd.Env = append(cmd.Env, key+"="+value)
			}
		}
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		if ctx.Err() != nil {
			t.Fatal("candidate CLI subprocess exceeded its fixture deadline")
		}
		return result{stdout.String(), stderr.String(), err}
	}
	decode := func(t *testing.T, got result) protocol.ContextRefreshResponse {
		t.Helper()
		if got.err != nil || got.stderr != "" || len(got.stdout) == 0 || len(got.stdout) > 8192 {
			t.Fatal("candidate CLI did not emit a bounded successful JSON observation")
		}
		var out protocol.ContextRefreshResponse
		decoder := json.NewDecoder(strings.NewReader(got.stdout))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&out) != nil || decoder.Decode(new(any)) != io.EOF {
			t.Fatal("candidate CLI output is not the expected observation schema")
		}
		binding := protocol.ContextBinding{TaskID: task, WorkspaceID: testWorkspaceID, ProjectID: project, IssueID: issue}
		if out.ContextBinding != binding || out.Coverage != "partial" || out.Freshness != "unknown" || out.ActionAuthorized == nil || *out.ActionAuthorized {
			t.Fatal("candidate CLI lost the trusted fixture binding or uncertainty envelope")
		}
		observed, err := time.Parse(time.RFC3339Nano, out.ObservedAt)
		if err != nil || observed.After(time.Now()) || time.Since(observed) > 10*time.Second {
			t.Fatal("candidate CLI emitted a stale/future observation")
		}
		return out
	}
	rejected := func(t *testing.T, got result, expectedExit int) {
		t.Helper()
		var exit *exec.ExitError
		if !errors.As(got.err, &exit) || exit.ExitCode() != expectedExit || got.stdout != "" || got.stderr == "" {
			t.Fatal("candidate CLI rejection must use its documented error exit with no context stdout")
		}
		if strings.Contains(got.stderr, token) || strings.Contains(got.stderr, testToken) || strings.Contains(got.stderr, "mat_invalid_cli_fixture") || strings.Contains(got.stderr, excerpt) || strings.Contains(got.stderr, newExcerpt) || strings.Contains(got.stderr, source) {
			t.Fatal("candidate CLI rejection exposed fixture token or selected source")
		}
	}
	assertSource := func(t *testing.T, out protocol.ContextRefreshResponse, revision int64, text string) {
		t.Helper()
		binding := protocol.ContextBinding{TaskID: task, WorkspaceID: testWorkspaceID, ProjectID: project, IssueID: issue}
		if out.Status != "available" || !protocol.ValidPreparedProjectContext(out.PreparedProjectContext, binding, time.Now()) || len(out.PreparedProjectContext.Sources) != 1 || out.PreparedProjectContext.ObservedAt != out.ObservedAt {
			t.Fatal("candidate CLI did not deliver a valid whole prepared observation")
		}
		got := out.PreparedProjectContext.Sources[0]
		if got.SourceID != source || got.IssueID != sourceIssue || got.Revision != revision || got.Excerpt != text {
			t.Fatal("candidate CLI lost exact current source provenance or RO/EN UTF-8 text")
		}
	}

	t.Run("real CLI current source", func(t *testing.T) {
		assertSource(t, decode(t, run(t, project, issue, nil)), 1, excerpt)
	})
	t.Run("wrong project and issue guards", func(t *testing.T) {
		rejected(t, run(t, sourceIssue, issue, nil), cli.ExitGeneric)
		rejected(t, run(t, project, sourceIssue, nil), cli.ExitGeneric)
	})
	t.Run("forged task environment cannot change persisted token binding", func(t *testing.T) {
		rejected(t, run(t, project, issue, map[string]string{"MULTICA_TASK_ID": sourceIssue}), cli.ExitGeneric)
		rejected(t, run(t, project, issue, map[string]string{"MULTICA_WORKSPACE_ID": project}), cli.ExitGeneric)
	})
	t.Run("owner and absent task credentials do not fall back", func(t *testing.T) {
		rejected(t, run(t, project, issue, map[string]string{"MULTICA_TOKEN": testToken}), cli.ExitGeneric)
		rejected(t, run(t, project, issue, map[string]string{"MULTICA_TOKEN": ""}), cli.ExitGeneric)
	})
	t.Run("invalid task token rejects without context", func(t *testing.T) {
		rejected(t, run(t, project, issue, map[string]string{"MULTICA_TOKEN": "mat_invalid_cli_fixture"}), cli.ExitAuth)
	})
	t.Run("revision drift requires explicit reselection", func(t *testing.T) {
		fx.Exec(t, "UPDATE comment SET content = $1, revision = 2, updated_at = now() WHERE id = $2", newExcerpt, source)
		got := run(t, project, issue, nil)
		out := decode(t, got)
		if out.Status != "unavailable" || out.PreparedProjectContext != nil || strings.Contains(got.stdout, excerpt) || strings.Contains(got.stdout, newExcerpt) {
			t.Fatal("candidate CLI substituted or reused revision-drift text")
		}
		selectRevision(2)
		assertSource(t, decode(t, run(t, project, issue, nil)), 2, newExcerpt)
	})
	t.Run("stopped task emits no stale context", func(t *testing.T) {
		fx.Exec(t, "UPDATE agent_task_queue SET status = 'completed' WHERE id = $1", task)
		rejected(t, run(t, project, issue, nil), cli.ExitGeneric)
	})
}
