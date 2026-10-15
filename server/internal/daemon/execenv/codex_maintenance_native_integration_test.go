//go:build agentintegration

package execenv

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"log/slog"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/multica-ai/multica/server/pkg/agent"
)

// Captures only the application's owned-process cleanup boolean, not private
// messages, headers, body content, stderr or namespace/descendant PIDs.
type maintenanceCleanupReceipt struct{ reaped atomic.Bool }

func (h *maintenanceCleanupReceipt) Enabled(context.Context, slog.Level) bool { return true }
func (h *maintenanceCleanupReceipt) Handle(_ context.Context, record slog.Record) error {
	record.Attrs(func(attr slog.Attr) bool {
		if attr.Key == "reaped" && attr.Value.Kind() == slog.KindBool && attr.Value.Bool() {
			h.reaped.Store(true)
		}
		return true
	})
	return nil
}
func (h *maintenanceCleanupReceipt) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *maintenanceCleanupReceipt) WithGroup(string) slog.Handler      { return h }

// PREPARED ONLY. Run this exact test only after separately approving native
// launch and reviewing its binary/config/provider/outbound discovery boundaries.
// It uses actual Prepare -> ResolveBackend -> Execute, never a replacement CLI.
func TestCodexMaintenanceNativePreparedExecution(t *testing.T) {
	if os.Getenv("MULTICA_RUN_REAL_AGENT_SMOKE") != "1" || testing.Short() {
		t.Skip("native maintenance canary disabled")
	}
	bin, err := maintenanceNativeSelection("1", os.Getenv("MULTICA_REAL_CODEX_BIN"), runtime.GOOS, false)
	if err != nil {
		t.Fatal(err.Error())
	}
	// The gate above occurs before executable lookup/stat/version launch.
	resolved, err := filepath.EvalSymlinks(bin)
	if err != nil || resolved != bin {
		t.Fatal("explicit executable must be a resolved regular file")
	}
	info, err := os.Stat(bin)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		t.Fatal("explicit executable must be executable")
	}
	executableSHA, err := maintenanceNativeExecutableSHA(bin, os.Getenv("MULTICA_REAL_CODEX_SHA256"))
	if err != nil {
		t.Fatal(err.Error())
	}

	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	goodDir, deniedDir := filepath.Join(root, "approved"), filepath.Join(root, "denied-sibling")
	for _, dir := range []string{goodDir, deniedDir} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	good, denied := filepath.Join(goodDir, "fixture"), filepath.Join(deniedDir, "fixture")
	for _, path := range []string{good, denied} {
		if err := os.WriteFile(path, []byte("SYNTHETIC-FIXTURE"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	versionHome := filepath.Join(root, "version-home")
	if err := os.Mkdir(versionHome, 0o700); err != nil {
		t.Fatal(err)
	}
	versionCtx, versionCancel := context.WithTimeout(context.Background(), 3*time.Second)
	versionCmd := exec.CommandContext(versionCtx, bin, "--version")
	versionCmd.Dir = versionHome
	versionCmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8", "HOME=" + versionHome, "CODEX_HOME=" + versionHome}
	version, versionErr := versionCmd.Output()
	versionCancel()
	if versionErr != nil || strings.TrimSpace(string(version)) != "codex-cli 0.159.3" {
		t.Fatal("native version must be exactly codex-cli 0.159.3")
	}

	fixture := &maintenanceResponsesFixture{prompt: maintenanceCanaryPrompt}
	server := httptest.NewUnstartedServer(fixture)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal("cannot listen on synthetic loopback provider")
	}
	_ = server.Listener.Close()
	server.Listener = listener
	server.Start()
	defer func() { server.CloseClientConnections(); server.Close() }()
	policy := &agent.CodexMaintenancePolicy{Version: 1, Prompt: maintenanceCanaryPrompt, Model: "maintenance-fixture-model", ReadRoots: []string{goodDir}, Provider: agent.CodexMaintenanceProvider{ID: "fixture", Name: "Synthetic loopback fixture", BaseURL: server.URL + "/v1", WireAPI: "responses", RequiresOpenAIAuth: false}}
	receipt := &maintenanceCleanupReceipt{}
	logger := slog.New(receipt)
	environment, err := Prepare(PrepareParams{WorkspacesRoot: filepath.Join(root, "workspaces"), WorkspaceID: "synthetic-native", TaskID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeef", Provider: "codex", CodexVersion: "0.159.3", CodexExecutable: bin, CodexMaintenance: policy}, logger)
	if err != nil {
		t.Fatal("actual maintenance preparation failed")
	}
	defer func() {
		if err := environment.Cleanup(true); err != nil {
			t.Error("owned synthetic environment cleanup failed")
		}
	}()
	fixture.command = maintenanceCanaryShell(good, denied, environment.WorkDir)
	config, err := os.ReadFile(filepath.Join(environment.CodexHome, "config.toml"))
	if err != nil {
		t.Fatal("prepared native config missing")
	}
	expected, err := policy.Config(bin)
	if err != nil || string(config) != string(expected) {
		t.Fatal("prepared native config differs from explicit policy")
	}
	backend, err := agent.ResolveBackend("codex", agent.Config{ExecutablePath: bin, CLIVersion: "0.159.3", CodexVersion: "0.159.3", BuiltinRuntime: true, Env: environment.CodexMaintenanceEnv, CodexMaintenance: policy, Logger: logger})
	if err != nil {
		t.Fatal("actual backend resolution failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	session, err := backend.Execute(ctx, policy.Prompt, agent.ExecOptions{Cwd: environment.WorkDir, Model: policy.Model, Timeout: 20 * time.Second, HandshakeTimeout: 3 * time.Second, ThreadHandshakeTimeout: 3 * time.Second, TurnInterruptTimeout: 2 * time.Second, McpConfig: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal("actual native Execute failed")
	}
	if session.Supplement != nil || session.SupplementReady != nil {
		t.Fatal("maintenance supplement channel exposed")
	}
	messagesDone := make(chan struct{})
	go func() {
		defer close(messagesDone)
		for range session.Messages {
		}
	}()
	var result agent.Result
	select {
	case result = <-session.Result:
	case <-ctx.Done():
		cancel()
		select {
		case result = <-session.Result:
		case <-time.After(3 * time.Second):
			t.Fatal("native owned-child cleanup unconfirmed after deadline")
		}
	}
	select {
	case <-messagesDone:
	case <-time.After(time.Second):
		t.Fatal("native message drain unconfirmed")
	}
	if result.Status != "completed" || strings.TrimSpace(result.Output) != maintenanceCanaryMarker {
		t.Fatal("native fixture completion not proven")
	}
	if count, status := fixture.snapshot(); count != 2 || status != "completed" {
		t.Fatal("synthetic provider controls not proven")
	}
	if !receipt.reaped.Load() {
		t.Fatal("application owned-child reap not proven")
	}
	for _, path := range []string{good, denied} {
		data, err := os.ReadFile(path)
		if err != nil || string(data) != "SYNTHETIC-FIXTURE" {
			t.Fatal("synthetic fixture unexpectedly changed")
		}
	}
	if _, err := os.Stat(filepath.Join(environment.WorkDir, "forbidden-write")); !os.IsNotExist(err) {
		t.Fatal("synthetic cwd write was not denied")
	}
	t.Logf("native_fixture status=completed controls=true owned_child_reaped=true responses_requests=2 executable_sha256=%s config_sha256=%x", executableSHA, sha256.Sum256(config))
}
