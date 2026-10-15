package execenv

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCodexMaintenanceNativeGateHasNoImplicitSelection(t *testing.T) {
	for _, input := range []struct {
		enabled, bin, goos string
		short              bool
	}{
		{"", "/missing/never-look-up", "linux", false},
		{"1", "/missing/never-look-up", "linux", true},
		{"1", "/missing/never-look-up", "darwin", false},
		{"1", "", "linux", false},
		{"1", "codex", "linux", false},
	} {
		if _, err := maintenanceNativeSelection(input.enabled, input.bin, input.goos, input.short); err == nil {
			t.Fatal("unsafe native selection accepted")
		}
	}
	if got, err := maintenanceNativeSelection("1", "/explicit/synthetic/codex", "linux", false); err != nil || got != "/explicit/synthetic/codex" {
		t.Fatal("explicit gated selection rejected")
	}
}

func TestCodexMaintenanceNativeExecutableHashPin(t *testing.T) {
	file := filepath.Join(t.TempDir(), "synthetic-never-executed")
	fixture := []byte("synthetic executable fixture")
	if err := os.WriteFile(file, fixture, 0o600); err != nil {
		t.Fatal(err)
	}
	expected := fmt.Sprintf("%x", sha256.Sum256(fixture))
	for _, invalid := range []string{"", "123", strings.Repeat("z", 64), strings.Repeat("0", 64)} {
		if _, err := maintenanceNativeExecutableSHA(file, invalid); err == nil {
			t.Fatal("missing/invalid/mismatching binary pin accepted")
		}
	}
	if got, err := maintenanceNativeExecutableSHA(file, expected); err != nil || got != expected {
		t.Fatal("synthetic expected hash rejected")
	}
}

func maintenanceFixtureRequest(t *testing.T, fixture *maintenanceResponsesFixture, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	fixture.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(string(data))))
	return recorder
}

func TestCodexMaintenanceResponsesFixtureProtocol(t *testing.T) {
	f := &maintenanceResponsesFixture{prompt: maintenanceCanaryPrompt, command: "synthetic command never executed"}
	request := map[string]any{"model": "maintenance-fixture-model", "stream": true, "input": []any{map[string]any{"role": "user", "content": []any{map[string]any{"type": "input_text", "text": maintenanceCanaryPrompt}}}}, "tools": []any{map[string]any{"type": "function", "name": "exec_command", "parameters": map[string]any{"properties": map[string]any{"cmd": map[string]any{"type": "string"}}, "required": []string{"cmd"}}}}}
	first := maintenanceFixtureRequest(t, f, request)
	if first.Code != 200 || first.Header().Get("Content-Type") != "text/event-stream" {
		t.Fatal("fixture rejected synthetic supported request")
	}
	var events []map[string]any
	for _, line := range strings.Split(first.Body.String(), "\n") {
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &event); err != nil {
			t.Fatal("invalid fixture SSE JSON")
		}
		events = append(events, event)
	}
	if len(events) != 6 || events[0]["type"] != "response.created" || events[5]["type"] != "response.completed" {
		t.Fatal("fixture event lifecycle incomplete")
	}
	item := events[4]["item"].(map[string]any)
	if item["name"] != "exec_command" || item["call_id"] != "call_maintenance" || !strings.Contains(item["arguments"].(string), f.command) {
		t.Fatal("fixture tool call differs from controlled probe")
	}
	request["input"] = []any{map[string]any{"type": "function_call_output", "call_id": "call_maintenance", "output": maintenanceCanaryProbeOK}}
	second := maintenanceFixtureRequest(t, f, request)
	if second.Code != 200 || !strings.Contains(second.Body.String(), maintenanceCanaryMarker) {
		t.Fatal("fixture did not complete after successful probe")
	}
	if requests, status := f.snapshot(); requests != 2 || status != "completed" {
		t.Fatal("fixture status mismatch")
	}
	if third := maintenanceFixtureRequest(t, f, request); third.Code == 200 {
		t.Fatal("fixture permits unexpected request retry")
	}
}

func TestCodexMaintenanceResponsesFixtureFailsClosed(t *testing.T) {
	for _, body := range []map[string]any{
		{"model": "other", "stream": true},
		{"model": "maintenance-fixture-model", "stream": false},
		{"model": "maintenance-fixture-model", "stream": true, "input": []any{map[string]any{"role": "user", "content": []any{map[string]any{"text": maintenanceCanaryPrompt}}}}},
	} {
		f := &maintenanceResponsesFixture{prompt: maintenanceCanaryPrompt}
		if result := maintenanceFixtureRequest(t, f, body); result.Code == 200 {
			t.Fatal("unsupported fixture request accepted")
		}
	}
	f := &maintenanceResponsesFixture{requests: 1}
	if result := maintenanceFixtureRequest(t, f, map[string]any{"model": "maintenance-fixture-model", "stream": true, "input": []any{map[string]any{"type": "function_call_output", "call_id": "call_maintenance", "output": "read_sibling=true"}}}); result.Code == 200 {
		t.Fatal("failed filesystem controls accepted")
	}
	encoded := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader("not-decoded-or-dumped"))
	encoded.Header.Set("Content-Encoding", "zstd")
	recorder := httptest.NewRecorder()
	(&maintenanceResponsesFixture{}).ServeHTTP(recorder, encoded)
	if recorder.Code == 200 || !strings.Contains(recorder.Body.String(), "unsupported Responses content encoding") {
		t.Fatal("unverified compressed wire shape accepted")
	}
	namespaced := map[string]any{"model": "maintenance-fixture-model", "stream": true, "input": []any{map[string]any{"role": "user", "content": []any{map[string]any{"text": maintenanceCanaryPrompt}}}}, "tools": []any{map[string]any{"type": "namespace", "name": "functions", "tools": []any{map[string]any{"type": "function", "name": "exec_command"}}}}}
	if result := maintenanceFixtureRequest(t, &maintenanceResponsesFixture{prompt: maintenanceCanaryPrompt}, namespaced); result.Code == 200 {
		t.Fatal("namespaced function missing shell parameter schema accepted")
	}
}

func TestCodexMaintenanceResponsesPinnedNamespaceAndOutputs(t *testing.T) {
	request := map[string]any{"model": "maintenance-fixture-model", "stream": true, "input": []any{map[string]any{"role": "user", "content": []any{map[string]any{"text": maintenanceCanaryPrompt}}}}, "tools": []any{map[string]any{"type": "namespace", "name": "functions", "tools": []any{map[string]any{"type": "function", "name": "exec_command", "parameters": map[string]any{"properties": map[string]any{"cmd": map[string]any{"type": "string"}}, "required": []string{"cmd"}}}}}}}
	f := &maintenanceResponsesFixture{prompt: maintenanceCanaryPrompt, command: "synthetic never executed"}
	response := maintenanceFixtureRequest(t, f, request)
	if response.Code != 200 || !strings.Contains(response.Body.String(), `"namespace":"functions"`) {
		t.Fatal("pinned namespace function call missing")
	}
	for _, output := range []any{maintenanceCanaryProbeOK, []any{map[string]any{"type": "input_text", "text": maintenanceCanaryProbeOK}}, map[string]any{"content": maintenanceCanaryProbeOK, "success": true}} {
		fixture := &maintenanceResponsesFixture{requests: 1}
		request["input"] = []any{map[string]any{"type": "function_call_output", "call_id": "call_maintenance", "output": output}}
		if got := maintenanceFixtureRequest(t, fixture, request); got.Code != 200 {
			t.Fatal("pinned successful output representation rejected")
		}
	}
	for _, output := range []any{nil, []any{}, []any{map[string]any{"type": "output_text", "text": maintenanceCanaryProbeOK}}, map[string]any{"content": maintenanceCanaryProbeOK, "success": false}, map[string]any{"content": maintenanceCanaryProbeOK, "success": nil}, map[string]any{"other": maintenanceCanaryProbeOK}} {
		fixture := &maintenanceResponsesFixture{requests: 1}
		request["input"] = []any{map[string]any{"type": "function_call_output", "call_id": "call_maintenance", "output": output}}
		if got := maintenanceFixtureRequest(t, fixture, request); got.Code == 200 {
			t.Fatal("unsupported/unsuccessful output representation accepted")
		}
	}
}
