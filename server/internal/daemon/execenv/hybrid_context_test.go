package execenv

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const hybridPrivateDescription = "PRIVATE administrative project description"

func hybridEnvContext() TaskContextForEnv {
	return TaskContextForEnv{IssueID: "11111111-1111-4111-8111-111111111111",
		ProjectID: "22222222-2222-4222-8222-222222222222", ProjectTitle: "Selected project",
		ProjectDescription: hybridPrivateDescription, HybridProjectContext: true}
}

func TestHybridContextBriefAndResourcePrivacyLegacyUnchanged(t *testing.T) {
	for _, provider := range []string{"codex", "claude", "hermes"} {
		t.Run(provider, func(t *testing.T) {
			ctx := hybridEnvContext()
			dir := t.TempDir()
			if _, err := InjectRuntimeConfig(dir, provider, ctx); err != nil {
				t.Fatal(err)
			}
			if err := writeProjectResources(dir, ctx, &sidecarManifest{}); err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{runtimeConfigPath(dir, provider), filepath.Join(dir, ".multica", "project", "resources.json")} {
				contents, err := os.ReadFile(path)
				if err != nil || strings.Contains(string(contents), hybridPrivateDescription) {
					t.Fatal("hybrid description escaped into environment file")
				}
			}
			ctx.HybridProjectContext = false
			if !strings.Contains(buildMetaSkillContent(provider, ctx), hybridPrivateDescription) || projectDescriptionForEnv(ctx) != hybridPrivateDescription {
				t.Fatal("legacy description omitted")
			}
		})
	}
}

func TestHybridContextPrepareThenReuseSanitizesManagedFiles(t *testing.T) {
	root := t.TempDir()
	ctx := hybridEnvContext()
	ctx.HybridProjectContext = false
	// Pi's filesystem preparation needs no user home, CLI or model invocation.
	env, err := Prepare(PrepareParams{WorkspacesRoot: root, WorkspaceID: "ws", TaskID: "task", Provider: "pi", Task: ctx}, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	configPath := runtimeConfigPath(env.WorkDir, "pi")
	userBytes := "user instructions, preserve exactly\n"
	if err := os.WriteFile(configPath, []byte(userBytes), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := InjectRuntimeConfig(env.WorkDir, "pi", ctx); err != nil {
		t.Fatal(err)
	}
	ctx.HybridProjectContext = true
	ctx.PriorSessionResumed = true
	reused := Reuse(ReuseParams{WorkDir: env.WorkDir, Provider: "pi", Task: ctx}, discardLogger())
	if reused == nil {
		t.Fatal("managed prior environment could not be safely refreshed")
	}
	if _, err := InjectRuntimeConfig(reused.WorkDir, "pi", ctx); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{configPath, filepath.Join(env.WorkDir, ".multica", "project", "resources.json")} {
		contents, err := os.ReadFile(path)
		if err != nil || strings.Contains(string(contents), hybridPrivateDescription) {
			t.Fatal("legacy private managed output persisted after hybrid reuse")
		}
	}
	contents, err := os.ReadFile(configPath)
	if err != nil || !strings.HasPrefix(string(contents), userBytes) {
		t.Fatal("user runtime instructions changed")
	}
}

func TestHybridContextUnownedResourceCollisionFailsClosed(t *testing.T) {
	dir := t.TempDir()
	resourcePath := filepath.Join(dir, ".multica", "project", "resources.json")
	if err := os.MkdirAll(filepath.Dir(resourcePath), 0o755); err != nil {
		t.Fatal(err)
	}
	privateBytes := `{"project_description":"` + hybridPrivateDescription + `"}`
	if err := os.WriteFile(resourcePath, []byte(privateBytes), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := hybridEnvContext()
	if err := writeProjectResources(dir, ctx, &sidecarManifest{}); err == nil || !strings.Contains(err.Error(), "hybrid context gap") {
		t.Fatal("unowned stale sidecar collision did not fail closed")
	}
	if reused := Reuse(ReuseParams{WorkDir: dir, LocalDirectory: true, Provider: "pi", Task: ctx}, discardLogger()); reused != nil {
		t.Fatal("reuse continued despite unsanitized sidecar")
	}
	contents, err := os.ReadFile(resourcePath)
	if err != nil || string(contents) != privateBytes {
		t.Fatal("unowned resource file overwritten or removed")
	}
}

func TestHybridContextDuplicateManagedBriefFailsClosed(t *testing.T) {
	dir := t.TempDir()
	path := runtimeConfigPath(dir, "claude")
	oldBlock := runtimeMarkerBegin + "\n" + hybridPrivateDescription + "\n" + runtimeMarkerEnd + "\n"
	oldBytes := "user bytes\n" + oldBlock + oldBlock
	if err := os.WriteFile(path, []byte(oldBytes), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := InjectRuntimeConfig(dir, "claude", hybridEnvContext()); err == nil || !strings.Contains(err.Error(), "hybrid context gap") {
		t.Fatal("multiple old managed blocks silently refreshed only partially")
	}
	contents, err := os.ReadFile(path)
	if err != nil || string(contents) != oldBytes {
		t.Fatal("ambiguous runtime file modified")
	}
	legacy := hybridEnvContext()
	legacy.HybridProjectContext = false
	if _, err := InjectRuntimeConfig(dir, "claude", legacy); err != nil {
		t.Fatal("hybrid-only refusal changed legacy runtime behavior")
	}
	contents, err = os.ReadFile(path)
	if err != nil || strings.Count(string(contents), runtimeMarkerBegin) != 2 || !strings.HasPrefix(string(contents), "user bytes\n") {
		t.Fatal("legacy managed-block replacement behavior changed")
	}
}
