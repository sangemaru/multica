package daemon

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/multica-ai/multica/server/internal/daemon/execenv"
	"github.com/multica-ai/multica/server/pkg/agent"
)

// maintenanceTaskInputs runs before skill resolution, repo registration, MCP
// discovery, hook startup or resource hydration. The original claimed task can
// carry private context; none of that becomes this profile's model input.
func maintenanceTaskInputs(task Task, provider string) (Task, *agent.CodexMaintenancePolicy, error) {
	if task.Agent == nil {
		return task, nil, nil
	}
	policy, err := agent.DecodeCodexMaintenance(task.Agent.RuntimeConfig)
	if err != nil || policy == nil {
		return task, policy, err
	}
	if provider != "codex" || len(task.Agent.CustomArgs) != 0 {
		return Task{}, nil, fmt.Errorf("maintenance: only built-in Codex without custom args is supported")
	}
	if _, err := policy.Environment("unused", task.Agent.CustomEnv); err != nil {
		return Task{}, nil, err
	}
	// Retain only execution/reporting identity and the task-scoped daemon
	// credential. That credential is not added to the isolated child env.
	isolated := Task{
		ID: task.ID, AgentID: task.AgentID, RuntimeID: task.RuntimeID,
		WorkspaceID: task.WorkspaceID, IssueID: task.IssueID,
		ChatSessionID: task.ChatSessionID, AuthToken: task.AuthToken,
		StartClaimSupported: task.StartClaimSupported, DispatchedAt: task.DispatchedAt,
		Agent: &AgentData{ID: task.Agent.ID, Name: "maintenance", Model: policy.Model,
			RuntimeConfig: task.Agent.RuntimeConfig, CustomEnv: task.Agent.CustomEnv},
	}
	return isolated, policy, nil
}

// maintenancePrepareParams is used by the actual fresh-Prepare path, including
// its serialized helper-process transport. Reuse has no maintenance variant.
func maintenancePrepareParams(params execenv.PrepareParams, policy *agent.CodexMaintenancePolicy, executable string, providerEnv map[string]string) execenv.PrepareParams {
	if policy != nil {
		params.CodexMaintenance = policy
		params.CodexExecutable = executable
		params.CodexMaintenanceProviderEnv = providerEnv
	}
	return params
}

func maintenanceExecOptions(opts agent.ExecOptions, policy *agent.CodexMaintenancePolicy) agent.ExecOptions {
	if policy == nil {
		return opts
	}
	opts.EnableTaskSupplement = false
	opts.Model = policy.Model
	opts.SystemPrompt = ""
	opts.ThreadName = ""
	opts.ResumeSessionID = ""
	opts.ResumeExpected = false
	opts.ResumeContinuityNotice = ""
	opts.ExtraArgs = nil
	opts.CustomArgs = nil
	opts.McpConfig = json.RawMessage(`{}`)
	opts.ThinkingLevel = ""
	opts.ServiceTier = ""
	if policy.TimeoutSeconds != nil {
		opts.Timeout = time.Duration(*policy.TimeoutSeconds) * time.Second
	}
	return opts
}
