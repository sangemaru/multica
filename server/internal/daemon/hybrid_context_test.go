package daemon

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/multica-ai/multica/server/internal/handler"
	"github.com/multica-ai/multica/server/pkg/protocol"
)

func TestHybridContextClaimResponseWireToNativePrompt(t *testing.T) {
	fixture := hybridTask(time.Now())
	response := handler.AgentTaskResponse{ID: fixture.ID, WorkspaceID: fixture.WorkspaceID,
		ProjectID: fixture.ProjectID, IssueID: fixture.IssueID, PreparedProjectContext: fixture.PreparedProjectContext, HybridProjectContext: true}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Task
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.HybridProjectContext {
		t.Fatal("hybrid privacy flag lost on wire")
	}
	for _, provider := range []string{"codex", "claude", "hermes"} {
		if !strings.Contains(BuildPrompt(decoded, provider), fixture.PreparedProjectContext.Sources[0].Excerpt) {
			t.Fatalf("claim source lost at native prompt boundary for %s", provider)
		}
	}
}

func hybridTask(now time.Time) Task {
	task := Task{
		ID:                   "11111111-1111-4111-8111-111111111111",
		WorkspaceID:          "22222222-2222-4222-8222-222222222222",
		ProjectID:            "33333333-3333-4333-8333-333333333333",
		IssueID:              "44444444-4444-4444-8444-444444444444",
		ProjectDescription:   "PRIVATE administrative information",
		HybridProjectContext: true,
	}
	task.PreparedProjectContext = &protocol.PreparedProjectContext{
		TaskID: task.ID, WorkspaceID: task.WorkspaceID, ProjectID: task.ProjectID, IssueID: task.IssueID,
		ObservedAt: now.Add(-time.Second).Format(time.RFC3339Nano),
		ExpiresAt:  now.Add(time.Minute).Format(time.RFC3339Nano),
		Sources: []protocol.PreparedContextSource{{WorkspaceID: task.WorkspaceID, ProjectID: task.ProjectID,
			IssueID: task.IssueID, SourceID: "55555555-5555-4555-8555-555555555555", Revision: 2,
			UpdatedAt: now.Add(-time.Minute).Format(time.RFC3339Nano), Excerpt: "Decizie: verifică sursa / Verify source"}},
	}
	return task
}

func TestHybridContextPerRunNativePrompt(t *testing.T) {
	for _, provider := range []string{"codex", "claude", "hermes"} {
		t.Run(provider, func(t *testing.T) {
			task := hybridTask(time.Now())
			task.PriorSessionID = "prior-session-not-current-binding"
			prompt := BuildPrompt(task, provider)
			for _, expected := range []string{"Task-bound operational context", task.WorkspaceID,
				"Decizie: verifică sursa", "source freshness is unknown", "integration is unverified",
				"multica context refresh --project-id " + task.ProjectID + " --issue-id " + task.IssueID + " --output json", "Compare source IDs and revisions", "not tool interception"} {
				if !strings.Contains(prompt, expected) {
					t.Fatalf("missing %q", expected)
				}
			}
			if strings.Contains(prompt, task.ProjectDescription) {
				t.Fatal("private project description copied")
			}
			// A later run on the same resumed session must deliver the new selection.
			task.PreparedProjectContext.Sources[0].Revision = 3
			task.PreparedProjectContext.Sources[0].Excerpt = "New decision"
			if !strings.Contains(BuildPrompt(task, provider), "New decision") {
				t.Fatal("stale resume selection")
			}
		})
	}
}

func TestHybridContextRejectsInvalidSelection(t *testing.T) {
	now := time.Now()
	cases := map[string]func(*Task){
		"wrong task":             func(t *Task) { t.PreparedProjectContext.TaskID = t.IssueID },
		"wrong source project":   func(t *Task) { t.PreparedProjectContext.Sources[0].ProjectID = t.IssueID },
		"wrong source workspace": func(t *Task) { t.PreparedProjectContext.Sources[0].WorkspaceID = t.IssueID },
		"expiry":                 func(t *Task) { t.PreparedProjectContext.ExpiresAt = now.Format(time.RFC3339Nano) },
		"future observation":     func(t *Task) { t.PreparedProjectContext.ObservedAt = now.Add(time.Minute).Format(time.RFC3339Nano) },
		"long lifetime":          func(t *Task) { t.PreparedProjectContext.ExpiresAt = now.Add(time.Hour).Format(time.RFC3339Nano) },
		"oversized excerpt":      func(t *Task) { t.PreparedProjectContext.Sources[0].Excerpt = strings.Repeat("x", 601) },
		"duplicate": func(t *Task) {
			t.PreparedProjectContext.Sources = append(t.PreparedProjectContext.Sources, t.PreparedProjectContext.Sources[0])
		},
		"bad revision": func(t *Task) { t.PreparedProjectContext.Sources[0].Revision = -1 },
		"future update": func(t *Task) {
			t.PreparedProjectContext.Sources[0].UpdatedAt = now.Add(time.Minute).Format(time.RFC3339Nano)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			task := hybridTask(now)
			mutate(&task)
			block := buildHybridContextBlock(task, now)
			if strings.Contains(block, "Decizie:") || !strings.Contains(block, "Prepared selection unavailable") {
				t.Fatal("invalid selection delivered")
			}
		})
	}
}

func TestHybridContextInvalidBindingAndNoProject(t *testing.T) {
	task := hybridTask(time.Now())
	task.WorkspaceID = "invalid; execute-other-command"
	block := buildHybridContextBlock(task, time.Now())
	if strings.Contains(block, task.WorkspaceID) || !strings.Contains(block, "binding is invalid") {
		t.Fatal("unsafe identity rendered")
	}
	task.ProjectID = ""
	if buildHybridContextBlock(task, time.Now()) != "" {
		t.Fatal("project inferred")
	}
}

func TestHybridContextNoPreparedDataIsExplicitlyDegraded(t *testing.T) {
	task := hybridTask(time.Now())
	task.PreparedProjectContext = nil
	block := buildHybridContextBlock(task, time.Now())
	if !strings.Contains(block, "Prepared selection unavailable") || strings.Contains(block, "PRIVATE") {
		t.Fatal("missing context misrepresented")
	}
	if len(block) > maxPreparedContextBytes {
		t.Fatal("unbounded output")
	}
}

func TestHybridContextTriggeredAndWakeupPrompts(t *testing.T) {
	for _, trigger := range []string{"comment", "wakeup"} {
		t.Run(trigger, func(t *testing.T) {
			task := hybridTask(time.Now())
			if trigger == "comment" {
				task.TriggerCommentID = "66666666-6666-4666-8666-666666666666"
				task.TriggerCommentContent = "Review latest decision"
			} else {
				task.WakeupID = "77777777-7777-4777-8777-777777777777"
			}
			if !strings.Contains(BuildPrompt(task, "codex"), "Decizie: verifică sursa") {
				t.Fatal("per-run context lost on trigger path")
			}
		})
	}
}

func TestHybridContextJSONEscapingPreservesOutputBound(t *testing.T) {
	task := hybridTask(time.Now())
	task.PreparedProjectContext.Sources[0].Excerpt = strings.Repeat("<", 600)
	block := buildHybridContextBlock(task, time.Now())
	if len(block) > maxPreparedContextBytes || strings.Contains(block, `\u003c`) {
		t.Fatal("oversized serialized selection delivered")
	}
	if !strings.Contains(block, "No excerpt was delivered") {
		t.Fatal("output omission not explicit")
	}
}

func TestHybridContextBindingAndLegacyOptIn(t *testing.T) {
	task := hybridTask(time.Now())
	if validateHybridTaskBinding(task) != nil {
		t.Fatal("valid issue binding rejected")
	}
	for _, invalid := range []func(*Task){
		func(task *Task) { task.ProjectID = "not-a-project" },
		func(task *Task) { task.ChatSessionID = "chat" },
		func(task *Task) { task.IssueID = "" },
	} {
		candidate := task
		invalid(&candidate)
		if validateHybridTaskBinding(candidate) == nil {
			t.Fatal("invalid hybrid binding accepted")
		}
	}
	task.HybridProjectContext = false
	if buildHybridContextBlock(task, time.Now()) != "" || validateHybridTaskBinding(task) != nil {
		t.Fatal("legacy non-opted task changed")
	}
}
