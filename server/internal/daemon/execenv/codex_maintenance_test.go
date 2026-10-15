package execenv

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/multica-ai/multica/server/pkg/agent"
	"github.com/pelletier/go-toml/v2"
)

func maintenancePrepareFixture(t *testing.T) PrepareParams {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(root, "fake-codex")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return PrepareParams{WorkspacesRoot: filepath.Join(root, "workspaces"), WorkspaceID: "synthetic-workspace", TaskID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", Provider: "codex", CodexVersion: "0.159.3", CodexExecutable: executable,
		CodexMaintenance: &agent.CodexMaintenancePolicy{Version: 1, Prompt: "controlled synthetic prompt", Model: "fake-model", ReadRoots: []string{root}, Provider: agent.CodexMaintenanceProvider{ID: "fake", Name: "Synthetic", BaseURL: "http://127.0.0.1:8787/v1"}}}
}

func TestCodexMaintenancePrepareNeverSeedsOrHydratesInheritance(t *testing.T) {
	params := maintenancePrepareFixture(t)
	private := filepath.Join(params.CodexMaintenance.ReadRoots[0], "private-synthetic-home")
	for _, path := range []string{".codex/skills/private", ".codex/plugins/private", ".codex/sessions", ".codex/memories"} {
		if err := os.MkdirAll(filepath.Join(private, path), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{".codex/config.toml", ".codex/instructions.md", ".codex/auth.json", ".codex/skills/private/SKILL.md", ".codex/plugins/private/plugin.json", ".codex/sessions/private.jsonl", ".codex/memories/raw_memories.md"} {
		if err := os.WriteFile(filepath.Join(private, path), []byte("PRIVATE-SYNTHETIC-INHERITANCE-SENTINEL"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", private)
	t.Setenv("CODEX_HOME", filepath.Join(private, ".codex"))
	t.Setenv("MULTICA_CODEX_MEMORY", "1")
	t.Setenv("MULTICA_CODEX_MULTI_AGENT", "1")
	params.Task = TaskContextForEnv{AgentInstructions: "PRIVATE-SYNTHETIC-INSTRUCTIONS", WorkspaceContext: "PRIVATE-SYNTHETIC-WORKSPACE", ProjectID: "private-project", ProjectDescription: "private-description", AgentSkills: []SkillContextForEnv{{Name: "private-skill", Content: "private-content"}}, ProjectResources: []ProjectResourceForEnv{{ID: "private-resource", ResourceType: "local_directory", ResourceRef: json.RawMessage(`{"path":"/private/synthetic"}`)}}, Repos: []RepoContextForEnv{{URL: "https://private.invalid/repo"}}}
	previous := runtimeGOOS
	runtimeGOOS = "linux"
	defer func() { runtimeGOOS = previous }()
	env, err := Prepare(params, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer env.Cleanup(true)
	entries, err := os.ReadDir(env.WorkDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("fresh cwd inherited sidecars: %v %v", entries, err)
	}
	for _, path := range []string{"instructions.md", "skills", "plugins", "sessions", "memories", "config.json", "auth.json"} {
		if _, err := os.Lstat(filepath.Join(env.CodexHome, path)); !os.IsNotExist(err) {
			t.Fatalf("inherited %s present: %v", path, err)
		}
	}
	data, err := os.ReadFile(filepath.Join(env.CodexHome, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "PRIVATE-SYNTHETIC") {
		t.Fatal("shared config copied")
	}
	var config map[string]any
	if err := toml.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	if len(config["mcp_servers"].(map[string]any)) != 0 {
		t.Fatal("MCP inherited")
	}
	if env.CodexMaintenanceEnv["HOME"] == private || env.CodexMaintenanceEnv["MULTICA_CODEX_MEMORY"] != "" {
		t.Fatal("ambient runtime environment inherited")
	}
	if source, err := os.ReadFile(filepath.Join(private, ".codex/config.toml")); err != nil || string(source) != "PRIVATE-SYNTHETIC-INHERITANCE-SENTINEL" {
		t.Fatal("shared source modified")
	}
}

func TestCodexMaintenancePrepareExplicitAuthOnlyAndRejectsReuse(t *testing.T) {
	params := maintenancePrepareFixture(t)
	params.CodexMaintenance.AuthFile = filepath.Join(params.CodexMaintenance.ReadRoots[0], "explicit-synthetic-auth.json")
	if err := os.WriteFile(params.CodexMaintenance.AuthFile, []byte(`{"synthetic":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	params.CodexMaintenance.Provider.RequiresOpenAIAuth = true
	previous := runtimeGOOS
	runtimeGOOS = "linux"
	defer func() { runtimeGOOS = previous }()
	env, err := Prepare(params, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer env.Cleanup(true)
	link, err := os.Readlink(filepath.Join(env.CodexHome, "auth.json"))
	if err != nil || link != params.CodexMaintenance.AuthFile {
		t.Fatal("explicit auth link missing")
	}
	if err := prepareCodexMaintenanceHome(env, params); err == nil {
		t.Fatal("existing CODEX_HOME accepted")
	}
	params.LocalWorkDir = params.CodexMaintenance.ReadRoots[0]
	if _, err := Prepare(params, discardLogger()); err == nil {
		t.Fatal("user cwd accepted")
	}
	params.LocalWorkDir = ""
	params.CodexVersion = "0.160.0"
	if _, err := Prepare(params, discardLogger()); err == nil {
		t.Fatal("unknown runtime accepted")
	}
}

func TestCodexMaintenancePrepareUnsupportedHostFailsBeforeEffects(t *testing.T) {
	params := maintenancePrepareFixture(t)
	previous := runtimeGOOS
	runtimeGOOS = "darwin"
	defer func() { runtimeGOOS = previous }()
	if _, err := Prepare(params, discardLogger()); err == nil {
		t.Fatal("unsupported macOS silently loosened")
	}
	if _, err := os.Stat(params.WorkspacesRoot); !os.IsNotExist(err) {
		t.Fatal("unsupported policy prepared files")
	}
}
