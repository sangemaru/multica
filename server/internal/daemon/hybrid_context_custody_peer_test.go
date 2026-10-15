package daemon

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/multica-ai/multica/server/internal/cli"
	"github.com/multica-ai/multica/server/pkg/agent"
	"github.com/multica-ai/multica/server/pkg/protocol"
)

const custodyFixtureEnv = "MULTICA_HYBRID_CUSTODY_FIXTURE"

type custodyFixture struct {
	Binding protocol.ContextBinding          `json:"binding"`
	AgentID string                           `json:"agent_id"`
	Token   string                           `json:"token"`
	Server  string                           `json:"server"`
	CLI     string                           `json:"cli"`
	Initial *protocol.PreparedProjectContext `json:"initial"`
	OldText string                           `json:"old_text"`
	NewText string                           `json:"new_text"`
}

func readCustodyFixture() (custodyFixture, error) {
	var f custodyFixture
	raw := os.Getenv(custodyFixtureEnv)
	if len(raw) == 0 || len(raw) > 8192 || json.Unmarshal([]byte(raw), &f) != nil {
		return f, fmt.Errorf("invalid synthetic custody fixture")
	}
	u, err := url.Parse(f.Server)
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" ||
		!filepath.IsAbs(f.CLI) || !protocol.CanonicalContextID(f.AgentID) ||
		f.Token != "mat_custody_fixture_"+f.Binding.TaskID ||
		!protocol.ValidPreparedProjectContext(f.Initial, f.Binding, time.Now()) ||
		len(f.Initial.Sources) != 1 || f.Initial.Sources[0].Excerpt != f.OldText || f.NewText == f.OldText {
		return f, fmt.Errorf("invalid synthetic custody scope")
	}
	return f, nil
}

// A compiled test peer bridges package-main's real Auth/DB fixture without
// exporting or replacing any product helper. Default tests never launch a CLI.
func TestHybridContextNativeCustodyPeer(t *testing.T) {
	if os.Getenv(custodyFixtureEnv) == "" {
		t.Skip("requires the isolated server custody driver")
	}
	if runtime.GOOS != "linux" {
		t.Fatal("the custody peer requires its isolated Linux fixture namespace")
	}
	f, err := readCustodyFixture()
	if err != nil {
		t.Fatal("invalid custody fixture")
	}
	root := t.TempDir()
	configRoot, codexHome := filepath.Join(root, "task-config"), filepath.Join(root, "codex-home")
	for _, dir := range []string{configRoot, codexHome} {
		if os.Mkdir(dir, 0700) != nil {
			t.Fatal("cannot create isolated custody state")
		}
	}
	task := Task{ID: f.Binding.TaskID, WorkspaceID: f.Binding.WorkspaceID, ProjectID: f.Binding.ProjectID,
		IssueID: f.Binding.IssueID, AgentID: f.AgentID, AuthToken: f.Token, HybridProjectContext: true, PreparedProjectContext: f.Initial}
	if validateHybridTaskBinding(task) != nil {
		t.Fatal("task binding invalid")
	}
	prompt := BuildPrompt(task, "codex")
	encodedInitial, err := json.Marshal(f.Initial)
	refreshCommand := "multica context refresh --project-id " + task.ProjectID + " --issue-id " + task.IssueID + " --output json"
	if err != nil || !strings.Contains(prompt, string(encodedInitial)) || !strings.Contains(prompt, refreshCommand) || strings.Contains(prompt, f.NewText) {
		t.Fatal("initial exact observation or deliberate refresh command missing from BuildPrompt")
	}
	token, err := taskScopedAuthToken(task)
	if err != nil || token != f.Token {
		t.Fatal("actual task token guard rejected the fixture")
	}
	env := taskMulticaEnvironment(task, "Synthetic custody agent", token, configRoot, root, f.Server, 0, 0, root)
	env[custodyFixtureEnv] = os.Getenv(custodyFixtureEnv)
	env["MULTICA_CUSTODY_FAKE"] = "1"
	env["MULTICA_CUSTODY_RELEASE"] = filepath.Join(root, "release")
	env["MULTICA_CUSTODY_PID"] = filepath.Join(root, "fake.pid")
	sum := sha256.Sum256([]byte(prompt))
	env["MULTICA_CUSTODY_PROMPT_SHA"] = hex.EncodeToString(sum[:])
	env["CODEX_HOME"] = codexHome
	env["PATH"] = "/usr/local/bin:/usr/bin:/bin"
	backend, err := agent.ResolveBackend("codex", agent.Config{ExecutablePath: os.Args[0],
		LaunchPrefix: []string{"-test.run=^TestHybridContextCustodyFakeAppServer$", "--"},
		Env:          env, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal("cannot resolve the test-only backend")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	session, err := backend.Execute(ctx, prompt, agent.ExecOptions{Cwd: root, Timeout: 12 * time.Second,
		HandshakeTimeout: 2 * time.Second, ThreadHandshakeTimeout: 2 * time.Second, McpConfig: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal("test-only backend startup failed")
	}
	t.Cleanup(func() {
		cancel()
		select {
		case <-session.Result:
		case <-time.After(3 * time.Second):
			t.Error("backend cleanup exceeded bound")
		}
		pidBytes, err := os.ReadFile(env["MULTICA_CUSTODY_PID"])
		if err != nil {
			t.Error("missing owned helper PID receipt")
			return
		}
		pid, err := strconv.Atoi(string(pidBytes))
		if err != nil || pid <= 1 || pid == os.Getpid() {
			t.Error("invalid owned helper PID")
			return
		}
		owned, findErr := os.FindProcess(pid)
		// os.Process maps the kernel's ESRCH to ErrProcessDone on Linux.
		if findErr != nil || !errors.Is(owned.Signal(syscall.Signal(0)), os.ErrProcessDone) {
			t.Error("owned fake app-server was not reaped")
		}
	})
	release := make(chan string, 1)
	go func() { line, _ := bufio.NewReader(io.LimitReader(os.Stdin, 32)).ReadString('\n'); release <- line }()
	count := 0
	for {
		select {
		case <-ctx.Done():
			t.Fatal("custody backend exceeded its bound")
		case msg, ok := <-session.Messages:
			if !ok {
				select {
				case result := <-session.Result:
					if count != 2 || result.Status != "completed" {
						t.Fatal("incomplete custody transcript")
					}
					fmt.Println(`{"phase":"complete","tool_results":2}`)
					return
				case <-ctx.Done():
					t.Fatal("custody result exceeded its bound")
				}
			}
			if msg.Type != agent.MessageToolResult {
				continue
			}
			count++
			var response protocol.ContextRefreshResponse
			if len(msg.Output) > 4096 || json.Unmarshal([]byte(msg.Output), &response) != nil ||
				response.ContextBinding != f.Binding || response.Coverage != "partial" || response.Freshness != "unknown" ||
				response.ActionAuthorized == nil || *response.ActionAuthorized {
				t.Fatal("tool transcript lost exact binding or uncertainty envelope")
			}
			if count == 1 {
				if response.Status != "available" || !protocol.ValidPreparedProjectContext(response.PreparedProjectContext, f.Binding, time.Now()) ||
					len(response.PreparedProjectContext.Sources) != 1 || response.PreparedProjectContext.Sources[0] != f.Initial.Sources[0] {
					t.Fatal("positive source bytes/provenance missing from the actual tool transcript")
				}
				fmt.Println(`{"phase":"available","source_exact":true,"binding_exact":true,"forged_identity_rejected":true}`)
				select {
				case line := <-release:
					if line != "drift\n" {
						t.Fatal("invalid bounded driver rendezvous")
					}
					if os.WriteFile(env["MULTICA_CUSTODY_RELEASE"], []byte("drift"), 0600) != nil {
						t.Fatal("cannot release fake transport")
					}
				case <-ctx.Done():
					t.Fatal("driver rendezvous exceeded its bound")
				}
			} else if count == 2 {
				if response.Status != "unavailable" || response.PreparedProjectContext != nil ||
					strings.Contains(msg.Output, f.OldText) || strings.Contains(msg.Output, f.NewText) {
					t.Fatal("revision drift delivered old/new source text")
				}
				fmt.Println(`{"phase":"unavailable","source_omitted":true,"binding_exact":true}`)
			} else {
				t.Fatal("unexpected extra tool result")
			}
		}
	}
}

// Explicitly gated re-entry supplies a fake app-server on the real Execute
// boundary. os.Exit prevents testing banners contaminating JSON-RPC stdout.
func TestHybridContextCustodyFakeAppServer(t *testing.T) {
	if os.Getenv("MULTICA_CUSTODY_FAKE") != "1" {
		t.Skip("test-created app-server only")
	}
	if err := custodyFakeAppServer(); err != nil {
		fmt.Fprintln(os.Stderr, "synthetic custody transport failed")
		os.Exit(23)
	}
	os.Exit(0)
}

func custodyFakeAppServer() error {
	f, err := readCustodyFixture()
	if err != nil {
		return err
	}
	if os.Getenv("MULTICA_TOKEN") != f.Token || os.Getenv("MULTICA_TASK_ID") != f.Binding.TaskID ||
		os.Getenv("MULTICA_AGENT_ID") != f.AgentID || os.Getenv("MULTICA_WORKSPACE_ID") != f.Binding.WorkspaceID ||
		os.Getenv("MULTICA_SERVER_URL") != f.Server || os.Getenv(cli.TaskConfigRootEnv) == "" {
		return fmt.Errorf("daemon environment custody failed")
	}
	// The driver starts the peer with explicit synthetic-only env. buildEnv
	// therefore has no host credential/provider state available to inherit.
	for _, key := range []string{"HOME", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "DATABASE_URL", "JWT_SECRET"} {
		if os.Getenv(key) != "" {
			return fmt.Errorf("unexpected ambient state")
		}
	}
	if os.WriteFile(os.Getenv("MULTICA_CUSTODY_PID"), []byte(strconv.Itoa(os.Getpid())), 0600) != nil {
		return fmt.Errorf("missing owned PID receipt")
	}
	encoder := json.NewEncoder(os.Stdout)
	send := func(v any) error { return encoder.Encode(v) }
	scanner := bufio.NewScanner(io.LimitReader(os.Stdin, 128*1024))
	scanner.Buffer(make([]byte, 4096), 64*1024)
	turns := 0
	for scanner.Scan() {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Input []struct {
					Text string `json:"text"`
				} `json:"input"`
			} `json:"params"`
		}
		if json.Unmarshal(scanner.Bytes(), &req) != nil {
			return fmt.Errorf("invalid request")
		}
		if len(req.ID) == 0 {
			continue
		}
		result := any(map[string]any{})
		if req.Method == "thread/start" {
			result = map[string]any{"thread": map[string]any{"id": "custody-thread"}}
		}
		if req.Method == "turn/start" {
			turns++
			if turns != 1 || len(req.Params.Input) != 1 {
				return fmt.Errorf("unexpected turn")
			}
			sum := sha256.Sum256([]byte(req.Params.Input[0].Text))
			if hex.EncodeToString(sum[:]) != os.Getenv("MULTICA_CUSTODY_PROMPT_SHA") {
				return fmt.Errorf("prompt altered at native boundary")
			}
			result = map[string]any{"turn": map[string]any{"id": "custody-turn"}}
		}
		if send(map[string]any{"id": req.ID, "result": result}) != nil {
			return fmt.Errorf("response write failed")
		}
		if req.Method != "turn/start" {
			continue
		}
		params := func(item any) map[string]any {
			return map[string]any{"threadId": "custody-thread", "turnId": "custody-turn", "item": item}
		}
		if send(map[string]any{"method": "turn/started", "params": map[string]any{"threadId": "custody-thread", "turn": map[string]any{"id": "custody-turn"}}}) != nil {
			return fmt.Errorf("start notification failed")
		}
		// Authentic task-token server binding must defeat forged caller env.
		forged, err := custodyRunCLI(f, true)
		var exitError *exec.ExitError
		if !errors.As(err, &exitError) || exitError.ExitCode() != cli.ExitGeneric || len(forged) != 0 {
			return fmt.Errorf("forged caller identity accepted")
		}
		for i := 1; i <= 2; i++ {
			id := fmt.Sprintf("refresh-%d", i)
			if send(map[string]any{"method": "item/started", "params": params(map[string]any{"id": id, "type": "commandExecution", "command": "multica context refresh"})}) != nil {
				return fmt.Errorf("tool start failed")
			}
			output, err := custodyRunCLI(f, false)
			if err != nil {
				return fmt.Errorf("real candidate CLI failed")
			}
			if send(map[string]any{"method": "item/completed", "params": params(map[string]any{"id": id, "type": "commandExecution", "aggregatedOutput": string(output), "exitCode": 0})}) != nil {
				return fmt.Errorf("tool result failed")
			}
			if i == 1 {
				deadline := time.Now().Add(8 * time.Second)
				for {
					body, readErr := os.ReadFile(os.Getenv("MULTICA_CUSTODY_RELEASE"))
					if readErr == nil && string(body) == "drift" {
						break
					}
					if time.Now().After(deadline) {
						return fmt.Errorf("bounded rendezvous expired")
					}
					time.Sleep(10 * time.Millisecond)
				}
			}
		}
		if send(map[string]any{"method": "turn/completed", "params": map[string]any{"threadId": "custody-thread", "turn": map[string]any{"id": "custody-turn", "status": "completed"}}}) != nil {
			return fmt.Errorf("turn finish failed")
		}
	}
	return scanner.Err()
}

func custodyRunCLI(f custodyFixture, forged bool) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, f.CLI, "context", "refresh", "--project-id", f.Binding.ProjectID, "--issue-id", f.Binding.IssueID, "--output", "json")
	cmd.WaitDelay = time.Second
	// Preserve the real daemon/helper-produced env; never rebuild its binding.
	cmd.Env = os.Environ()
	if forged {
		for i, entry := range cmd.Env {
			if strings.HasPrefix(entry, "MULTICA_TASK_ID=") {
				cmd.Env[i] = "MULTICA_TASK_ID=" + f.Binding.ProjectID
			}
		}
	}
	out := custodyBoundedOutput{limit: 4096}
	cmd.Stdout, cmd.Stderr = &out, io.Discard
	err := cmd.Run()
	if out.Len() > 4096 || ctx.Err() != nil {
		return nil, fmt.Errorf("CLI output/deadline bound failed")
	}
	return out.Bytes(), err
}

type custodyBoundedOutput struct {
	bytes.Buffer
	limit int
}

func (w *custodyBoundedOutput) Write(p []byte) (int, error) {
	if len(p) > w.limit-w.Len() {
		return 0, fmt.Errorf("bounded CLI capture exceeded")
	}
	return w.Buffer.Write(p)
}
