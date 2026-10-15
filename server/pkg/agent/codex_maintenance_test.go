package agent

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pelletier/go-toml/v2"
)

func maintenanceTestPolicy(t *testing.T) *CodexMaintenancePolicy {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &CodexMaintenancePolicy{Version: 1, Prompt: "controlled synthetic maintenance prompt", Model: "fake-model", ReadRoots: []string{root}, Provider: CodexMaintenanceProvider{ID: "fake", Name: "Synthetic", BaseURL: "http://127.0.0.1:8787/v1"}}
}

func TestCodexMaintenancePolicyValidation(t *testing.T) {
	valid := maintenanceTestPolicy(t)
	for _, tc := range []struct {
		name   string
		change func(*CodexMaintenancePolicy)
	}{
		{"version", func(p *CodexMaintenancePolicy) { p.Version = 2 }},
		{"empty prompt", func(p *CodexMaintenancePolicy) { p.Prompt = "" }},
		{"implicit model", func(p *CodexMaintenancePolicy) { p.Model = "" }},
		{"model controls", func(p *CodexMaintenancePolicy) { p.Model = "fake\nmodel" }},
		{"root", func(p *CodexMaintenancePolicy) { p.ReadRoots = []string{"/"} }},
		{"traversal", func(p *CodexMaintenancePolicy) { p.ReadRoots = []string{p.ReadRoots[0] + "/../escape"} }},
		{"duplicate roots", func(p *CodexMaintenancePolicy) { p.ReadRoots = append(p.ReadRoots, p.ReadRoots[0]) }},
		{"remote provider", func(p *CodexMaintenancePolicy) { p.Provider.BaseURL = "https://example.invalid/v1" }},
		{"URL auth", func(p *CodexMaintenancePolicy) { p.Provider.BaseURL = "http://secret@127.0.0.1:8787/v1" }},
		{"wire API", func(p *CodexMaintenancePolicy) { p.Provider.WireAPI = "invented" }},
		{"implicit auth", func(p *CodexMaintenancePolicy) { p.Provider.RequiresOpenAIAuth = true }},
		{"zero timeout", func(p *CodexMaintenancePolicy) { n := 0; p.TimeoutSeconds = &n }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := *valid
			p.ReadRoots = append([]string(nil), valid.ReadRoots...)
			tc.change(&p)
			if err := p.Validate(); err == nil {
				t.Fatal("invalid policy accepted")
			}
		})
	}
	for _, key := range []string{"HOME", "PATH", "TMPDIR", "LANG", "LC_ALL", "CODEX_SQLITE_HOME", "XDG_CONFIG_HOME", "MULTICA_TOKEN", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "NODE_OPTIONS", "SHELL", "BASH_ENV", "PYTHONPATH", "RUST_LOG", "ARBITRARY_OPTION"} {
		t.Run(key, func(t *testing.T) {
			p := *valid
			p.Provider.EnvKey = key
			if err := p.Validate(); err == nil {
				t.Fatal("reserved environment key accepted")
			}
		})
	}
	data, _ := json.Marshal(valid)
	for _, value := range []string{"null", strings.TrimSuffix(string(data), "}") + `,"unknown":true}`, strings.TrimSuffix(string(data), "}") + `,"version":1}`, strings.Replace(string(data), `"requires_openai_auth":false,`, "", 1)} {
		// The explicit boolean can occur last, so use a separate omission fixture below.
		if value == string(data) {
			continue
		}
		if _, err := DecodeCodexMaintenance(json.RawMessage(`{"maintenance":` + value + `}`)); err == nil {
			t.Fatalf("invalid JSON policy accepted: %s", value)
		}
	}
	omitted := strings.Replace(string(data), `,"requires_openai_auth":false`, "", 1)
	if _, err := DecodeCodexMaintenance(json.RawMessage(`{"maintenance":` + omitted + `}`)); err == nil {
		t.Fatal("implicit requires_openai_auth accepted")
	}
	for _, auth := range []string{"null", `"false"`, "0"} {
		invalid := strings.Replace(string(data), `"requires_openai_auth":false`, `"requires_openai_auth":`+auth, 1)
		if _, err := DecodeCodexMaintenance(json.RawMessage(`{"maintenance":` + invalid + `}`)); err == nil {
			t.Fatalf("nonboolean requires_openai_auth accepted: %s", auth)
		}
	}
	if _, err := DecodeCodexMaintenance(json.RawMessage(`{"maintenance":` + string(data) + `,"maintenance":` + string(data) + `}`)); err == nil {
		t.Fatal("duplicate maintenance envelope key accepted")
	}
	policy, err := DecodeCodexMaintenance(json.RawMessage(`{"maintenance":` + string(data) + `}`))
	if err != nil || policy == nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
	for _, raw := range []string{`{}`, `{"mode":"normal"}`, `legacy-invalid-json`} {
		if policy, err := DecodeCodexMaintenance(json.RawMessage(raw)); err != nil || policy != nil {
			t.Fatalf("normal config changed: %s", raw)
		}
	}
}

func TestCodexMaintenanceRejectsSymlinkRootAndUnknownRuntime(t *testing.T) {
	p := maintenanceTestPolicy(t)
	link := filepath.Join(p.ReadRoots[0], "escape")
	if err := os.Symlink(p.ReadRoots[0], link); err != nil {
		t.Fatal(err)
	}
	p.ReadRoots = []string{link}
	if err := p.Validate(); err == nil {
		t.Fatal("symlink root accepted")
	}
	p = maintenanceTestPolicy(t)
	executable := filepath.Join(p.ReadRoots[0], "fake-codex")
	if err := os.WriteFile(executable, []byte("synthetic executable"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := p.ValidateRuntime("linux", "0.159.3", executable, true, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	for _, args := range []struct {
		os, version           string
		builtin               bool
		prefix, extra, custom []string
	}{
		{"darwin", "0.159.3", true, nil, nil, nil}, {"windows", "0.159.3", true, nil, nil, nil},
		{"linux", "", true, nil, nil, nil}, {"linux", "0.160.0", true, nil, nil, nil},
		{"linux", "0.159.3", false, nil, nil, nil}, {"linux", "0.159.3", true, []string{"wrapper"}, nil, nil},
		{"linux", "0.159.3", true, nil, []string{"--dangerously-bypass-approvals-and-sandbox"}, nil},
		{"linux", "0.159.3", true, nil, nil, []string{"-c", "mcp_servers.extra.command=unsafe"}},
	} {
		if p.ValidateRuntime(args.os, args.version, executable, args.builtin, args.prefix, args.extra, args.custom) == nil {
			t.Fatalf("unsupported runtime accepted: %+v", args)
		}
	}
}

func TestCodexMaintenanceConfigAndEnvironmentAreExplicit(t *testing.T) {
	p := maintenanceTestPolicy(t)
	data, err := p.Config("/synthetic/codex")
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := toml.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	provider := config["model_providers"].(map[string]any)["fake"].(map[string]any)
	if _, exists := provider["wire_api"]; exists {
		t.Fatal("omitted wire_api invented")
	}
	for _, fragment := range []string{`memories = false`, `multi_agent = false`, `multi_agent_v2 = false`, `plugins = false`, `plugin_hooks = false`, `include_instructions = false`, `generate_memories = false`, `use_memories = false`, `project_doc_max_bytes = 0`, `':root' = 'deny'`} {
		if !strings.Contains(string(data), fragment) {
			t.Errorf("missing restrictive native setting %q: %s", fragment, data)
		}
	}
	t.Setenv("UNAPPROVED_SENTINEL", "private-synthetic-value")
	t.Setenv("MULTICA_CODEX_MEMORY", "1")
	env, err := p.Environment("/synthetic/home", nil)
	if err != nil {
		t.Fatal(err)
	}
	if env["UNAPPROVED_SENTINEL"] != "" || env["MULTICA_CODEX_MEMORY"] != "" {
		t.Fatal("ambient environment inherited")
	}
	if _, err := p.Environment("/synthetic/home", map[string]string{"CODEX_HOME": "escape"}); err == nil {
		t.Fatal("custom config home accepted")
	}
	p.Provider.EnvKey = "EXPLICIT_API_KEY"
	if _, err := p.Environment("/synthetic/home", nil); err == nil {
		t.Fatal("missing explicit provider key accepted")
	}
	env, err = p.Environment("/synthetic/home", map[string]string{"EXPLICIT_API_KEY": "synthetic-key"})
	if err != nil || env["EXPLICIT_API_KEY"] != "synthetic-key" {
		t.Fatal("explicit provider credential lost")
	}
}

func TestCodexMaintenanceThreadPayloadAndNormalRegression(t *testing.T) {
	for _, maintenance := range []bool{false, true} {
		c, _, _ := newTestCodexClient(t)
		if maintenance {
			c.cfg.CodexMaintenance = maintenanceTestPolicy(t)
		}
		stdin := &fakeStdinWithHook{}
		stdin.afterWrite = func() {
			lines := stdin.Lines()
			var request struct {
				ID int `json:"id"`
			}
			_ = json.Unmarshal([]byte(lines[len(lines)-1]), &request)
			response, _ := json.Marshal(map[string]any{"id": request.ID, "result": map[string]any{"thread": map[string]any{"id": "synthetic-thread"}}})
			c.handleLine(string(response))
		}
		c.stdin = stdin
		id, resumed, err := c.startOrResumeThread(context.Background(), ExecOptions{Cwd: "/synthetic/workdir", Model: "fake-model"}, c.cfg.Logger)
		if err != nil || id != "synthetic-thread" || resumed {
			t.Fatalf("thread start: %s %v %v", id, resumed, err)
		}
		var request struct {
			Params map[string]any `json:"params"`
		}
		_ = json.Unmarshal([]byte(stdin.Lines()[0]), &request)
		if maintenance {
			if request.Params["permissions"] != CodexMaintenancePermissions || request.Params["approvalPolicy"] != "never" || request.Params["ephemeral"] != true || request.Params["baseInstructions"] != "" || request.Params["developerInstructions"] != "" {
				t.Fatalf("maintenance native request: %#v", request.Params)
			}
			if _, exists := request.Params["sandbox"]; exists {
				t.Fatal("permissions mixed with legacy sandbox")
			}
			before := len(stdin.Lines())
			if _, _, err := c.startOrResumeThread(context.Background(), ExecOptions{ResumeSessionID: "private-history"}, c.cfg.Logger); err == nil || len(stdin.Lines()) != before {
				t.Fatal("maintenance resumed or wrote transport")
			}
		} else if request.Params["sandbox"] != nil || request.Params["permissions"] != nil || request.Params["persistExtendedHistory"] != true || request.Params["baseInstructions"] != nil {
			t.Fatalf("normal request changed: %#v", request.Params)
		}
	}
	params := map[string]any{"threadId": "synthetic-thread", "input": []any{}, "sandboxPolicy": "legacy"}
	applyCodexMaintenancePermissions(params, maintenanceTestPolicy(t), false)
	if params["permissions"] != CodexMaintenancePermissions || params["sandboxPolicy"] != nil {
		t.Fatal("turn policy not native")
	}
	before := map[string]any{"sandbox": "normal"}
	unchanged := map[string]any{"sandbox": "normal"}
	applyCodexMaintenancePermissions(before, nil, false)
	if !reflect.DeepEqual(before, unchanged) {
		t.Fatal("normal turn mutated")
	}
}

func TestCodexMaintenanceApprovalNeverBroadens(t *testing.T) {
	for _, method := range []string{"item/commandExecution/requestApproval", "item/fileChange/requestApproval", "item/permissions/requestApproval", "mcpServer/elicitation/request"} {
		c, stdin, _ := newTestCodexClient(t)
		c.cfg.CodexMaintenance = maintenanceTestPolicy(t)
		c.handleLine(`{"id":1,"method":` + strconvQuote(method) + `,"params":{"permissions":{"network":{"enabled":true},"fileSystem":{"write":["/"]}}}}`)
		var response map[string]any
		_ = json.Unmarshal([]byte(stdin.Lines()[0]), &response)
		if method == "item/permissions/requestApproval" {
			result := response["result"].(map[string]any)
			if len(result["permissions"].(map[string]any)) != 0 {
				t.Fatal("permissions broadened")
			}
		} else if method == "mcpServer/elicitation/request" {
			if response["error"] == nil {
				t.Fatal("MCP accepted")
			}
		} else if response["result"].(map[string]any)["decision"] != "decline" {
			t.Fatal("tool escalation accepted")
		}
	}
}

func strconvQuote(value string) string { data, _ := json.Marshal(value); return string(data) }

func TestCodexMaintenanceExecutionValidationBeforeLaunch(t *testing.T) {
	p := maintenanceTestPolicy(t)
	executable := filepath.Join(p.ReadRoots[0], "fake-codex")
	_ = os.WriteFile(executable, []byte("synthetic"), 0o700)
	home := filepath.Join(p.ReadRoots[0], "codex-home")
	_ = os.Mkdir(home, 0o700)
	workdir := filepath.Join(p.ReadRoots[0], "workdir")
	_ = os.Mkdir(workdir, 0o700)
	config, _ := p.Config(executable)
	_ = os.WriteFile(filepath.Join(home, "config.toml"), config, 0o600)
	env, _ := p.Environment(home, nil)
	b := &codexBackend{cfg: Config{CodexMaintenance: p, ExecutablePath: executable, CodexVersion: "0.159.3", BuiltinRuntime: true, Env: env}}
	previous := codexMaintenanceGOOS
	codexMaintenanceGOOS = "linux"
	defer func() { codexMaintenanceGOOS = previous }()
	opts := ExecOptions{Cwd: workdir, Model: p.Model, Timeout: time.Second}
	if err := b.validateMaintenanceExecution(p.Prompt, opts); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*ExecOptions){func(o *ExecOptions) { o.ResumeSessionID = "private" }, func(o *ExecOptions) { o.EnableTaskSupplement = true }, func(o *ExecOptions) { o.SystemPrompt = "inherited" }, func(o *ExecOptions) { o.McpConfig = json.RawMessage(`{"unsafe":{"command":"tool"}}`) }, func(o *ExecOptions) { o.Cwd = p.ReadRoots[0] }} {
		bad := opts
		mutate(&bad)
		if b.validateMaintenanceExecution(p.Prompt, bad) == nil {
			t.Fatal("uncontrolled execution accepted")
		}
	}
	env["MULTICA_TOKEN"] = "synthetic-private-token"
	if b.validateMaintenanceExecution(p.Prompt, opts) == nil {
		t.Fatal("daemon credential crossed isolated boundary")
	}
}

// This executes only a test-created shell transport, never an installed Codex
// CLI. It exercises Execute -> actual final argv/env -> thread/start -> turn/start.
func TestCodexMaintenanceExecuteFakeTransportControlsPromptPermissionsAndEnv(t *testing.T) {
	p := maintenanceTestPolicy(t)
	p.Provider.EnvKey = "FAKE_CAPTURE_KEY"
	capture := filepath.Join(p.ReadRoots[0], "transport.jsonl")
	fake, err := filepath.EvalSymlinks(writeFakeCodexAppServer(t, `
printf '%s\n' "ARGV=$*" > "$FAKE_CAPTURE_KEY"
printf '%s\n' "SYNTHETIC_ENV=${MAINTENANCE_AMBIENT_SENTINEL-unset}:${MULTICA_TOKEN-unset}" >> "$FAKE_CAPTURE_KEY"
while IFS= read -r line; do
  printf '%s\n' "$line" >> "$FAKE_CAPTURE_KEY"
  request_id="${line#*\"id\":}"
  request_id="${request_id%%,*}"
  case "$line" in
    *'"method":"initialize"'*)
      printf '{"id":%s,"result":{}}\n' "$request_id" ;;
    *'"method":"thread/start"'*)
      printf '{"id":%s,"result":{"thread":{"id":"synthetic-thread"}}}\n' "$request_id" ;;
    *'"method":"turn/start"'*)
      printf '{"id":%s,"result":{"turn":{"id":"synthetic-turn"}}}\n' "$request_id"
      printf '%s\n' '{"method":"turn/started","params":{"threadId":"synthetic-thread","turn":{"id":"synthetic-turn"}}}'
      printf '%s\n' '{"method":"turn/completed","params":{"threadId":"synthetic-thread","turn":{"id":"synthetic-turn","status":"completed"}}}' ;;
  esac
done
`))
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(p.ReadRoots[0], "codex-home")
	workdir := filepath.Join(p.ReadRoots[0], "workdir")
	for _, path := range []string{home, workdir} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	config, err := p.Config(fake)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "config.toml"), config, 0o600); err != nil {
		t.Fatal(err)
	}
	env, err := p.Environment(home, map[string]string{"FAKE_CAPTURE_KEY": capture})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("MAINTENANCE_AMBIENT_SENTINEL", "synthetic-ambient-private")
	t.Setenv("MULTICA_TOKEN", "mat_synthetic_unapproved")
	previous := codexMaintenanceGOOS
	codexMaintenanceGOOS = "linux"
	defer func() { codexMaintenanceGOOS = previous }()
	backend, err := New("codex", Config{ExecutablePath: fake, CodexVersion: "0.159.3", BuiltinRuntime: true, CodexMaintenance: p, Env: env, Logger: slog.Default()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	session, err := backend.Execute(ctx, p.Prompt, ExecOptions{Cwd: workdir, Model: p.Model, Timeout: 5 * time.Second, HandshakeTimeout: 2 * time.Second, ThreadHandshakeTimeout: 2 * time.Second, McpConfig: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	if session.Supplement != nil || session.SupplementReady != nil {
		t.Fatal("maintenance session exposes a later prompt injection channel")
	}
	go func() {
		for range session.Messages {
		}
	}()
	select {
	case result := <-session.Result:
		if result.Status != "completed" {
			t.Fatalf("fake transport result: %+v", result)
		}
	case <-ctx.Done():
		t.Fatal("fake transport exceeded finite test timeout")
	}
	data, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 5 || lines[0] != "ARGV=app-server --listen stdio://" || lines[1] != "SYNTHETIC_ENV=unset:unset" {
		t.Fatalf("launch boundary: %q", lines)
	}
	seen := map[string]int{}
	for _, line := range lines[2:] {
		var req struct {
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			t.Fatal(err)
		}
		seen[req.Method]++
		if req.Method == "thread/start" || req.Method == "turn/start" {
			if req.Params["permissions"] != CodexMaintenancePermissions || req.Params["approvalPolicy"] != "never" {
				t.Fatalf("actual native policy payload: %#v", req)
			}
			if _, exists := req.Params["sandbox"]; exists {
				t.Fatal("native permissions mixed with sandbox")
			}
			if _, exists := req.Params["sandboxPolicy"]; exists {
				t.Fatal("native permissions mixed with sandboxPolicy")
			}
		}
		if req.Method == "turn/start" {
			inputs := req.Params["input"].([]any)
			if len(inputs) != 1 || inputs[0].(map[string]any)["text"] != p.Prompt {
				t.Fatalf("controlled prompt altered: %#v", inputs)
			}
		}
	}
	if seen["thread/start"] != 1 || seen["turn/start"] != 1 || seen["thread/resume"] != 0 {
		t.Fatalf("unexpected transport methods: %#v", seen)
	}
}
