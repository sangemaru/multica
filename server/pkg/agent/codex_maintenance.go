package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
)

const CodexMaintenancePermissions = "multica-maintenance"

// CodexMaintenancePolicy is an opt-in, controlled-input contract. Prompt and
// model are explicit inputs, not a projection of issue/comment/agent context.
// TimeoutSeconds bounds execution only; it is not a model-request/token budget.
type CodexMaintenancePolicy struct {
	Version        int                      `json:"version"`
	Prompt         string                   `json:"prompt"`
	Model          string                   `json:"model"`
	ReadRoots      []string                 `json:"read_roots"`
	Provider       CodexMaintenanceProvider `json:"provider"`
	AuthFile       string                   `json:"auth_file,omitempty"`
	TimeoutSeconds *int                     `json:"timeout_seconds,omitempty"`
}

type CodexMaintenanceProvider struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	BaseURL            string `json:"base_url"`
	WireAPI            string `json:"wire_api,omitempty"`
	EnvKey             string `json:"env_key,omitempty"`
	RequiresOpenAIAuth bool   `json:"requires_openai_auth"`
}

var codexMaintenanceGOOS = runtime.GOOS
var maintenanceIdentifier = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,63}$`)
var maintenanceEnvKey = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)
var maintenanceModel = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`)

// DecodeCodexMaintenance leaves unrelated/legacy runtime config alone. Once a
// maintenance key is present, malformed, null and unknown fields fail closed.
func DecodeCodexMaintenance(raw json.RawMessage) (*CodexMaintenancePolicy, error) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		if bytes.Contains(raw, []byte(`"maintenance"`)) {
			return nil, fmt.Errorf("maintenance: invalid runtime_config JSON")
		}
		return nil, nil
	}
	value, exists := envelope["maintenance"]
	if !exists {
		return nil, nil
	}
	if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
		return nil, fmt.Errorf("maintenance: policy must be an object")
	}
	if err := maintenanceUniqueJSON(raw); err != nil {
		return nil, err
	}
	var policy CodexMaintenancePolicy
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil {
		return nil, fmt.Errorf("maintenance: invalid policy: %w", err)
	}
	var required struct {
		Provider map[string]json.RawMessage `json:"provider"`
	}
	_ = json.Unmarshal(value, &required)
	auth, present := required.Provider["requires_openai_auth"]
	if !present || !bytes.Equal(bytes.TrimSpace(auth), []byte("true")) && !bytes.Equal(bytes.TrimSpace(auth), []byte("false")) {
		return nil, fmt.Errorf("maintenance: requires_openai_auth must be an explicit boolean")
	}
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	return &policy, nil
}

func maintenanceUniqueJSON(raw json.RawMessage) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var value func() error
	value = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		if delimiter == '{' {
			seen := map[string]bool{}
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return fmt.Errorf("maintenance: duplicate JSON policy key")
				}
				seen[name] = true
				if err := value(); err != nil {
					return err
				}
			}
		} else if delimiter == '[' {
			for decoder.More() {
				if err := value(); err != nil {
					return err
				}
			}
		}
		_, err = decoder.Token()
		return err
	}
	if err := value(); err != nil {
		return fmt.Errorf("maintenance: invalid policy JSON: %w", err)
	}
	return nil
}

func maintenanceConcretePath(path string, directory bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return fmt.Errorf("maintenance: paths must be concrete, canonical absolute paths below filesystem root")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return fmt.Errorf("maintenance: path missing or traverses a symlink")
	}
	info, err := os.Stat(path)
	if err != nil || directory && !info.IsDir() || !directory && !info.Mode().IsRegular() {
		return fmt.Errorf("maintenance: path has an unsupported file type")
	}
	return nil
}

func (p *CodexMaintenancePolicy) Validate() error {
	if p == nil || p.Version != 1 {
		return fmt.Errorf("maintenance: only policy version 1 is supported")
	}
	if strings.TrimSpace(p.Prompt) == "" || len(p.Prompt) > 64*1024 || strings.ContainsRune(p.Prompt, 0) {
		return fmt.Errorf("maintenance: explicit bounded prompt required")
	}
	if !maintenanceModel.MatchString(p.Model) {
		return fmt.Errorf("maintenance: explicit model selector required")
	}
	if len(p.ReadRoots) == 0 || len(p.ReadRoots) > 16 {
		return fmt.Errorf("maintenance: one to sixteen explicit read roots required")
	}
	seen := make(map[string]bool)
	for _, root := range p.ReadRoots {
		if seen[root] {
			return fmt.Errorf("maintenance: duplicate read root")
		}
		seen[root] = true
		if err := maintenanceConcretePath(root, true); err != nil {
			return err
		}
	}
	provider := p.Provider
	if !maintenanceIdentifier.MatchString(provider.ID) || strings.TrimSpace(provider.Name) == "" || len(provider.Name) > 128 {
		return fmt.Errorf("maintenance: explicit provider id/name required")
	}
	endpoint, err := url.Parse(provider.BaseURL)
	if err != nil || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || (endpoint.Scheme != "http" && endpoint.Scheme != "https") {
		return fmt.Errorf("maintenance: provider URL must be an explicit loopback HTTP(S) URL")
	}
	ip := net.ParseIP(endpoint.Hostname())
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("maintenance: provider URL must use a loopback IP literal")
	}
	if provider.WireAPI != "" && provider.WireAPI != "responses" {
		return fmt.Errorf("maintenance: unsupported explicit wire_api")
	}
	reservedEnv := provider.EnvKey == "HOME" || provider.EnvKey == "PATH" || provider.EnvKey == "TMPDIR" || provider.EnvKey == "LANG" || provider.EnvKey == "SHELL" || provider.EnvKey == "ENV" || provider.EnvKey == "BASH_ENV" || provider.EnvKey == "NODE_OPTIONS" || provider.EnvKey == "PYTHONPATH"
	for _, prefix := range []string{"CODEX_", "XDG_", "MULTICA_", "LD_", "DYLD_", "LC_", "RUST_"} {
		reservedEnv = reservedEnv || strings.HasPrefix(provider.EnvKey, prefix)
	}
	if provider.EnvKey != "" && (!maintenanceEnvKey.MatchString(provider.EnvKey) || reservedEnv) {
		return fmt.Errorf("maintenance: invalid provider env_key")
	}
	if provider.EnvKey != "" && !strings.HasSuffix(provider.EnvKey, "_KEY") && !strings.HasSuffix(provider.EnvKey, "_TOKEN") && !strings.HasSuffix(provider.EnvKey, "_SECRET") {
		return fmt.Errorf("maintenance: env_key must identify an explicit credential key")
	}
	if p.AuthFile != "" {
		if err := maintenanceConcretePath(p.AuthFile, false); err != nil {
			return err
		}
	}
	if provider.RequiresOpenAIAuth && p.AuthFile == "" {
		return fmt.Errorf("maintenance: explicit auth_file required for OpenAI auth provider")
	}
	if p.TimeoutSeconds != nil && (*p.TimeoutSeconds < 1 || *p.TimeoutSeconds > 3600) {
		return fmt.Errorf("maintenance: timeout_seconds must be between 1 and 3600")
	}
	return nil
}

func (p *CodexMaintenancePolicy) ValidateRuntime(goos, version, executable string, builtin bool, prefix, extra, custom []string) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if goos != "linux" || strings.TrimPrefix(strings.TrimSpace(version), "codex-cli ") != "0.159.3" || !builtin {
		return fmt.Errorf("maintenance: requires built-in Linux Codex 0.159.3")
	}
	if len(prefix)+len(extra)+len(custom) != 0 {
		return fmt.Errorf("maintenance: custom launch prefixes and CLI args are unsupported")
	}
	return maintenanceConcretePath(executable, false)
}

// Config synthesizes only the explicit provider and restrictive local policy.
// A missing wire_api remains missing; provider defaults are not guessed here.
func (p *CodexMaintenancePolicy) Config(executable string) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	filesystem := map[string]any{":root": "deny", ":minimal": "read", executable: "read", ":workspace_roots": map[string]any{".": "read"}}
	for _, root := range p.ReadRoots {
		filesystem[root] = "read"
	}
	provider := map[string]any{"name": p.Provider.Name, "base_url": p.Provider.BaseURL, "requires_openai_auth": p.Provider.RequiresOpenAIAuth}
	if p.Provider.WireAPI != "" {
		provider["wire_api"] = p.Provider.WireAPI
	}
	if p.Provider.EnvKey != "" {
		provider["env_key"] = p.Provider.EnvKey
	}
	return toml.Marshal(map[string]any{
		"model": p.Model, "model_provider": p.Provider.ID,
		"model_providers":     map[string]any{p.Provider.ID: provider},
		"default_permissions": CodexMaintenancePermissions, "approval_policy": "never",
		"project_doc_max_bytes": 0, "project_doc_fallback_filenames": []string{},
		"mcp_servers": map[string]any{},
		// Supported by the pinned rust-v0.159.3 config.schema.json. Actual
		// native uptake is a separate live proof, not an offline test claim.
		"features":                 map[string]any{"memories": false, "multi_agent": false, "multi_agent_v2": false, "plugins": false, "plugin_hooks": false},
		"agents":                   map[string]any{"enabled": false},
		"cloud":                    map[string]any{"skills": map[string]any{"enabled": false}},
		"skills":                   map[string]any{"include_instructions": false, "bundled": map[string]any{"enabled": false}},
		"memories":                 map[string]any{"generate_memories": false, "use_memories": false},
		"permissions":              map[string]any{CodexMaintenancePermissions: map[string]any{"filesystem": filesystem, "network": map[string]any{"enabled": false}}},
		"shell_environment_policy": map[string]any{"inherit": "none"},
	})
}

// Environment does not consult os.Environ. Only an explicitly configured
// provider key can cross from the agent's custom_env into the fresh runtime.
func (p *CodexMaintenancePolicy) Environment(codexHome string, custom map[string]string) (map[string]string, error) {
	env := map[string]string{"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "CODEX_HOME": codexHome, "HOME": filepath.Join(codexHome, "user-home"), "TMPDIR": filepath.Join(codexHome, "tmp")}
	for _, name := range []string{"config", "data", "cache", "state"} {
		env["XDG_"+strings.ToUpper(name)+"_HOME"] = filepath.Join(codexHome, "user-home", name)
	}
	for key, value := range custom {
		if key != p.Provider.EnvKey || key == "" || strings.ContainsRune(value, 0) {
			return nil, fmt.Errorf("maintenance: custom_env permits only the explicit provider env_key")
		}
		env[key] = value
	}
	if p.Provider.EnvKey != "" && env[p.Provider.EnvKey] == "" {
		return nil, fmt.Errorf("maintenance: explicit provider environment value missing")
	}
	return env, nil
}

func maintenanceEnvironmentList(env map[string]string) []string {
	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, key+"="+env[key])
	}
	return out
}

func applyCodexMaintenancePermissions(params map[string]any, p *CodexMaintenancePolicy, thread bool) {
	if p == nil {
		return
	}
	delete(params, "sandbox")
	delete(params, "sandboxPolicy")
	params["permissions"] = CodexMaintenancePermissions
	params["approvalPolicy"] = "never"
	if thread {
		params["modelProvider"] = p.Provider.ID
		params["baseInstructions"] = ""
		params["developerInstructions"] = ""
		params["persistExtendedHistory"] = false
		params["ephemeral"] = true
	}
}

func (b *codexBackend) validateMaintenanceExecution(prompt string, opts ExecOptions) error {
	p := b.cfg.CodexMaintenance
	if p == nil {
		return nil
	}
	if err := p.ValidateRuntime(codexMaintenanceGOOS, b.cfg.CodexVersion, b.cfg.ExecutablePath, b.cfg.BuiltinRuntime, b.cfg.LaunchPrefix, opts.ExtraArgs, opts.CustomArgs); err != nil {
		return err
	}
	if prompt != p.Prompt || opts.Model != p.Model || opts.ResumeSessionID != "" || opts.ResumeExpected || opts.EnableTaskSupplement || opts.SystemPrompt != "" || opts.ThreadName != "" || opts.ThinkingLevel != "" || opts.ServiceTier != "" {
		return fmt.Errorf("maintenance: uncontrolled prompt, model, resume, supplement or instructions")
	}
	var mcp map[string]any
	if len(opts.McpConfig) > 0 && (json.Unmarshal(opts.McpConfig, &mcp) != nil || len(mcp) != 0) {
		return fmt.Errorf("maintenance: MCP must be empty")
	}
	home := b.cfg.Env["CODEX_HOME"]
	if home == "" || maintenanceConcretePath(home, true) != nil || maintenanceConcretePath(opts.Cwd, true) != nil {
		return fmt.Errorf("maintenance: prepared home and fresh cwd required")
	}
	if opts.Cwd != filepath.Join(filepath.Dir(home), "workdir") {
		return fmt.Errorf("maintenance: cwd is not the task-local fresh workdir")
	}
	custom := map[string]string{}
	if p.Provider.EnvKey != "" {
		custom[p.Provider.EnvKey] = b.cfg.Env[p.Provider.EnvKey]
	}
	expectedEnv, err := p.Environment(home, custom)
	if err != nil || len(expectedEnv) != len(b.cfg.Env) {
		return fmt.Errorf("maintenance: execution environment is not isolated")
	}
	for key, value := range expectedEnv {
		if b.cfg.Env[key] != value {
			return fmt.Errorf("maintenance: execution environment is not isolated")
		}
	}
	if maintenanceConcretePath(filepath.Join(home, "config.toml"), false) != nil {
		return fmt.Errorf("maintenance: native config must be a task-local regular file")
	}
	expected, err := p.Config(b.cfg.ExecutablePath)
	if err != nil {
		return err
	}
	actual, err := os.ReadFile(filepath.Join(home, "config.toml"))
	if err != nil || !bytes.Equal(actual, expected) {
		return fmt.Errorf("maintenance: prepared native configuration missing or modified")
	}
	if p.TimeoutSeconds != nil && opts.Timeout != time.Duration(*p.TimeoutSeconds)*time.Second {
		return fmt.Errorf("maintenance: configured execution timeout not applied")
	}
	return nil
}
