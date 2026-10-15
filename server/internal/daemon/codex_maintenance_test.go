package daemon

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/multica-ai/multica/server/internal/daemon/execenv"
	"github.com/multica-ai/multica/server/pkg/agent"
)

func maintenanceDaemonFixture(t *testing.T) Task {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := agent.CodexMaintenancePolicy{Version: 1, Prompt: "controlled synthetic prompt", Model: "fake-model", ReadRoots: []string{root}, Provider: agent.CodexMaintenanceProvider{ID: "fake", Name: "Synthetic", BaseURL: "http://127.0.0.1:8787/v1"}}
	policy, _ := json.Marshal(p)
	return Task{ID: "synthetic-task", AgentID: "synthetic-agent", WorkspaceID: "synthetic-workspace", IssueID: "synthetic-issue", AuthToken: "mat_synthetic", Agent: &AgentData{ID: "synthetic-agent", Name: "private-agent-name", RuntimeConfig: json.RawMessage(`{"maintenance":` + string(policy) + `}`)}}
}

func TestCodexMaintenanceTaskInputsRemoveEveryInheritedChannel(t *testing.T) {
	task := maintenanceDaemonFixture(t)
	task.Agent.Instructions = "private instructions"
	task.Agent.Skills = []SkillData{{Name: "private-skill"}}
	task.Agent.McpConfig = json.RawMessage(`{"private":{"command":"tool"}}`)
	task.WorkspaceContext = "private-workspace"
	task.ProjectDescription = "private-project"
	task.TriggerCommentContent = "private-comment"
	task.ChatMessage = "private-chat"
	task.PriorSessionID = "private-session"
	task.PriorWorkDir = "/private/synthetic"
	task.ThreadName = "private-title"
	task.ProjectResources = []ProjectResourceData{{ResourceType: "local_directory", ResourceRef: json.RawMessage(`{"path":"/private/synthetic"}`)}}
	task.PluginHookTools = []PluginHookTool{{}}
	task.ConnectedApps = []ConnectedAppData{{}}
	isolated, policy, err := maintenanceTaskInputs(task, "codex")
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(isolated)
	for _, sentinel := range []string{"private-agent-name", "private instructions", "private-skill", "private-workspace", "private-project", "private-comment", "private-chat", "private-session", "/private/synthetic", "private-title", `"private":`} {
		if strings.Contains(string(encoded), sentinel) {
			t.Fatalf("inherited sentinel %q present: %s", sentinel, encoded)
		}
	}
	if policy.Prompt != "controlled synthetic prompt" || isolated.PriorWorkDir != "" || isolated.PriorSessionID != "" || len(isolated.PluginHookTools) != 0 || len(isolated.ConnectedApps) != 0 || len(isolated.ProjectResources) != 0 || len(isolated.Agent.Skills) != 0 || len(isolated.Agent.McpConfig) != 0 {
		t.Fatal("inherited capability or history field present")
	}
	if isolated.AuthToken != "mat_synthetic" || isolated.IssueID != task.IssueID {
		t.Fatal("daemon reporting identity lost")
	}
	if task.Agent.Instructions != "private instructions" || len(task.ProjectResources) != 1 {
		t.Fatal("original claimed task modified")
	}
	if _, _, err := maintenanceTaskInputs(task, "claude"); err == nil {
		t.Fatal("other provider accepted")
	}
	task.Agent.CustomArgs = []string{"-c", "unsafe=true"}
	if _, _, err := maintenanceTaskInputs(task, "codex"); err == nil {
		t.Fatal("custom args silently dropped")
	}
}

func TestCodexMaintenanceDaemonPreparationTransportAndNormalRegression(t *testing.T) {
	task := maintenanceDaemonFixture(t)
	_, policy, err := maintenanceTaskInputs(task, "codex")
	if err != nil {
		t.Fatal(err)
	}
	base := execenv.PrepareParams{Provider: "codex", TaskID: task.ID, Task: execenv.TaskContextForEnv{AgentInstructions: "synthetic inherited instructions"}}
	params := maintenancePrepareParams(base, policy, "/synthetic/executable", nil)
	data, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	var transported execenv.PrepareParams
	if err := json.Unmarshal(data, &transported); err != nil {
		t.Fatal(err)
	}
	if transported.CodexMaintenance == nil || transported.CodexMaintenance.Prompt != policy.Prompt || transported.CodexExecutable != "/synthetic/executable" {
		t.Fatal("actual prepare helper transport lost policy")
	}
	if !reflect.DeepEqual(maintenancePrepareParams(base, nil, "ignored", nil), base) {
		t.Fatal("normal preparation changed")
	}
	opts := agent.ExecOptions{EnableTaskSupplement: true, Timeout: 17 * time.Second, ResumeSessionID: "private-history", ResumeExpected: true, ThreadName: "private-title", SystemPrompt: "private-instructions", Model: "private-model"}
	isolation := maintenanceExecOptions(opts, policy)
	if isolation.EnableTaskSupplement || isolation.ResumeExpected || isolation.ResumeSessionID != "" || isolation.SystemPrompt != "" || isolation.ThreadName != "" || isolation.Model != policy.Model || isolation.Timeout != opts.Timeout {
		t.Fatal("execution context not isolated or implicit timeout changed")
	}
	n := 3
	policy.TimeoutSeconds = &n
	if maintenanceExecOptions(opts, policy).Timeout != 3*time.Second {
		t.Fatal("explicit execution timeout ignored")
	}
	if !reflect.DeepEqual(maintenanceExecOptions(opts, nil), opts) {
		t.Fatal("normal execution changed")
	}
}

func TestRunTaskCodexMaintenanceInvalidPolicyBeforePreparationAndHooks(t *testing.T) {
	task := maintenanceDaemonFixture(t)
	task.Agent.RuntimeConfig = json.RawMessage(`{"maintenance":{"version":99}}`)
	root := filepath.Join(t.TempDir(), "not-created")
	d := &Daemon{cfg: Config{WorkspacesRoot: root}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	_, err := d.runTask(context.Background(), task, "codex", 0, d.logger)
	if err == nil || !strings.Contains(err.Error(), "maintenance") {
		t.Fatalf("actual daemon gate: %v", err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("invalid policy reached preparation")
	}
}
