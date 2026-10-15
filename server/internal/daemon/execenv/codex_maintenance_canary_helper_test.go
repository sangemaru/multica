package execenv

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const maintenanceCanaryPrompt = "Synthetic maintenance canary: run the supplied fixture-only shell probe, then reply MULTICA_MAINTENANCE_NATIVE_OK. Do not inspect anything else."
const maintenanceCanaryMarker = "MULTICA_MAINTENANCE_NATIVE_OK"
const maintenanceCanaryProbeOK = "MAINTENANCE_FS read_good=true read_sibling=false write_good=false write_sibling=false write_cwd=false"

// No lookup, stat, config or account access belongs before this gate.
func maintenanceNativeSelection(enabled, bin, goos string, short bool) (string, error) {
	if enabled != "1" || short {
		return "", fmt.Errorf("native maintenance canary disabled")
	}
	if goos != "linux" {
		return "", fmt.Errorf("native maintenance canary requires Linux")
	}
	if !filepath.IsAbs(bin) || filepath.Clean(bin) != bin {
		return "", fmt.Errorf("explicit canonical absolute MULTICA_REAL_CODEX_BIN required")
	}
	return bin, nil
}

func maintenanceNativeExecutableSHA(bin, expected string) (string, error) {
	decoded, err := hex.DecodeString(expected)
	if err != nil || len(decoded) != sha256.Size {
		return "", fmt.Errorf("explicit 64-hex MULTICA_REAL_CODEX_SHA256 required")
	}
	file, err := os.Open(bin)
	if err != nil {
		return "", fmt.Errorf("cannot hash explicit executable")
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("cannot hash explicit executable")
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if actual != strings.ToLower(expected) {
		return "", fmt.Errorf("explicit executable SHA256 mismatch")
	}
	return actual, nil
}

func maintenanceCanaryShell(good, denied, cwd string) string {
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
	return "read_good=false; read_sibling=false; write_good=false; write_sibling=false; write_cwd=false; " +
		"if /bin/cat " + quote(good) + " >/dev/null 2>/dev/null; then read_good=true; fi; " +
		"if /bin/cat " + quote(denied) + " >/dev/null 2>/dev/null; then read_sibling=true; fi; " +
		"if (printf forbidden > " + quote(good) + ") 2>/dev/null; then write_good=true; fi; " +
		"if (printf forbidden > " + quote(denied) + ") 2>/dev/null; then write_sibling=true; fi; " +
		"if (printf forbidden > " + quote(filepath.Join(cwd, "forbidden-write")) + ") 2>/dev/null; then write_cwd=true; fi; " +
		`printf 'MAINTENANCE_FS read_good=%s read_sibling=%s write_good=%s write_sibling=%s write_cwd=%s\n' "$read_good" "$read_sibling" "$write_good" "$write_sibling" "$write_cwd"`
}

// This provider is a two-request fixture, not a model or replacement executor.
// It retains only fixed statuses/counts, never headers or request/response bodies.
type maintenanceResponsesFixture struct {
	mu              sync.Mutex
	prompt, command string
	requests        int
	status          string
}

type maintenanceResponsesTool struct {
	Type, Name string
	Tools      []maintenanceResponsesTool `json:"tools"`
	Parameters struct {
		Properties map[string]struct {
			Type string `json:"type"`
		} `json:"properties"`
		Required []string `json:"required"`
	} `json:"parameters"`
}

// Pinned upstream output_value_to_text and call_output_content_and_success
// accept string, single input_text part, or content-string/success-bool object.
func maintenanceFixtureOutput(raw json.RawMessage) (string, bool) {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text, true
	}
	var parts []struct{ Type, Text string }
	if json.Unmarshal(raw, &parts) == nil && len(parts) == 1 && parts[0].Type == "input_text" {
		return parts[0].Text, true
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || len(object) != 2 || string(object["success"]) != "true" || json.Unmarshal(object["content"], &text) != nil {
		return "", false
	}
	return text, true
}

func (f *maintenanceResponsesFixture) snapshot() (int, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests, f.status
}

func (f *maintenanceResponsesFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fail := func(status string) { f.status = status; http.Error(w, status, http.StatusBadRequest) }
	if r.Method != http.MethodPost || r.URL.Path != "/v1/responses" || r.Header.Get("Authorization") != "" {
		fail("unexpected endpoint or authorization")
		return
	}
	if encoding := r.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		fail("unsupported Responses content encoding")
		return
	}
	var request struct {
		Model  string                     `json:"model"`
		Stream bool                       `json:"stream"`
		Input  []json.RawMessage          `json:"input"`
		Tools  []maintenanceResponsesTool `json:"tools"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(&request); err != nil || request.Model != "maintenance-fixture-model" || !request.Stream {
		fail("unsupported Responses request")
		return
	}
	f.requests++
	var output map[string]any
	if f.requests == 1 {
		promptSeen := false
		for _, raw := range request.Input {
			var item struct {
				Role    string
				Content []struct{ Type, Text string }
			}
			if json.Unmarshal(raw, &item) == nil && item.Role == "user" {
				for _, part := range item.Content {
					promptSeen = promptSeen || part.Text == f.prompt
				}
			}
		}
		if !promptSeen {
			fail("controlled prompt missing")
			return
		}
		name, key, namespace := "", "", ""
		consider := func(tool maintenanceResponsesTool, parent string) {
			if name != "" {
				return
			}
			candidate := ""
			switch tool.Name {
			case "exec_command":
				candidate = "cmd"
			case "shell_command":
				candidate = "command"
			}
			if tool.Type != "function" || candidate == "" || tool.Parameters.Properties[candidate].Type != "string" {
				return
			}
			compatible := true
			for _, required := range tool.Parameters.Required {
				compatible = compatible && required == candidate
			}
			if compatible {
				name, key, namespace = tool.Name, candidate, parent
			}
		}
		for _, tool := range request.Tools {
			if tool.Type == "namespace" && tool.Name != "" {
				for _, child := range tool.Tools {
					consider(child, tool.Name)
				}
			} else {
				consider(tool, "")
			}
		}
		if name == "" {
			fail("unsupported advertised shell tool schema")
			return
		}
		args, _ := json.Marshal(map[string]any{key: f.command})
		output = map[string]any{"type": "function_call", "id": "fc_maintenance", "call_id": "call_maintenance", "name": name, "arguments": string(args), "status": "completed"}
		if namespace != "" {
			output["namespace"] = namespace
		}
		f.status = "probe_sent"
	} else if f.requests == 2 {
		probeSeen := false
		for _, raw := range request.Input {
			var item struct {
				Type, CallID string
				Output       json.RawMessage
			}
			// Responses uses call_id, not Go's default field-name matching.
			var fields map[string]json.RawMessage
			_ = json.Unmarshal(raw, &fields)
			_ = json.Unmarshal(fields["type"], &item.Type)
			_ = json.Unmarshal(fields["call_id"], &item.CallID)
			item.Output = fields["output"]
			text, supported := maintenanceFixtureOutput(item.Output)
			probeSeen = probeSeen || supported && item.Type == "function_call_output" && item.CallID == "call_maintenance" && strings.Contains(text, maintenanceCanaryProbeOK)
		}
		if !probeSeen {
			fail("filesystem probe did not satisfy controls")
			return
		}
		output = map[string]any{"type": "message", "id": "msg_maintenance", "role": "assistant", "status": "completed", "content": []any{map[string]any{"type": "output_text", "text": maintenanceCanaryMarker, "annotations": []any{}}}}
		f.status = "completed"
	} else {
		fail("unexpected extra Responses request")
		return
	}
	writeMaintenanceSSE(w, output, f.requests)
}

// Wire format follows official Responses function-calling and streaming docs:
// https://developers.openai.com/api/docs/guides/function-calling
// https://developers.openai.com/api/reference/resources/responses/streaming-events
// Pinned Codex fixture source (ev_completed, ev_assistant_message,
// ev_function_call):
// https://raw.githubusercontent.com/openai/codex/rust-v0.159.3/codex-rs/core/tests/common/responses.rs
// ev_function_call_with_namespace and tool namespace children are supported;
// zstd request encoding intentionally fails closed without a decoder dependency.
func writeMaintenanceSSE(w http.ResponseWriter, item map[string]any, index int) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	sequence := 0
	emit := func(kind string, fields map[string]any) {
		fields["type"], fields["sequence_number"] = kind, sequence
		sequence++
		data, _ := json.Marshal(fields)
		_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", kind, data)
		if flush, ok := w.(http.Flusher); ok {
			flush.Flush()
		}
	}
	response := map[string]any{"id": fmt.Sprintf("resp_maintenance_%d", index), "object": "response", "created_at": 1, "model": "maintenance-fixture-model", "status": "in_progress", "output": []any{}}
	emit("response.created", map[string]any{"response": response})
	added := map[string]any{}
	for key, value := range item {
		added[key] = value
	}
	added["status"] = "in_progress"
	if item["type"] == "function_call" {
		added["arguments"] = ""
	} else {
		added["content"] = []any{}
	}
	emit("response.output_item.added", map[string]any{"output_index": 0, "item": added})
	if item["type"] == "function_call" {
		emit("response.function_call_arguments.delta", map[string]any{"output_index": 0, "item_id": item["id"], "delta": item["arguments"]})
		emit("response.function_call_arguments.done", map[string]any{"output_index": 0, "item_id": item["id"], "arguments": item["arguments"]})
	}
	emit("response.output_item.done", map[string]any{"output_index": 0, "item": item})
	response["status"], response["output"] = "completed", []any{item}
	response["usage"] = map[string]any{"input_tokens": 0, "output_tokens": 0, "total_tokens": 0, "input_tokens_details": map[string]any{"cached_tokens": 0}, "output_tokens_details": map[string]any{"reasoning_tokens": 0}}
	emit("response.completed", map[string]any{"response": response})
}
