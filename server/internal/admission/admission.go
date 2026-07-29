// Package admission defines the single pre-dispatch authorization contract for
// all Multica task creation. It intentionally contains no handler or database
// dependencies so every dispatch surface can use the same evaluator.
package admission

import (
	"context"
	"errors"

	requestidentity "github.com/multica-ai/multica/server/internal/identity"
)

// Path identifies the product path creating work. It is audit context, not an
// authorization result. Every path in AllPaths must reach the same evaluator.
type Path string

const (
	PathIssueAssignee    Path = "issue_assignee"
	PathMention          Path = "mention"
	PathSquadLeader      Path = "squad_leader"
	PathDeferredFallback Path = "deferred_fallback"
	PathQuickCreate      Path = "quick_create"
	PathChat             Path = "chat"
	PathDirectChat       Path = "direct_chat"
	PathAutopilot        Path = "autopilot"
	PathRetry            Path = "retry"
	PathRerun            Path = "rerun"
)

var allPaths = []Path{
	PathIssueAssignee,
	PathMention,
	PathSquadLeader,
	PathDeferredFallback,
	PathQuickCreate,
	PathChat,
	PathDirectChat,
	PathAutopilot,
	PathRetry,
	PathRerun,
}

// AllPaths returns a copy so callers cannot mutate the inventory.
func AllPaths() []Path {
	return append([]Path(nil), allPaths...)
}

// ValidPath keeps unknown create-work paths fail closed.
func ValidPath(path Path) bool {
	for _, candidate := range allPaths {
		if candidate == path {
			return true
		}
	}
	return false
}

// Action is the small, versioned V1 action vocabulary. Create-work admission
// initially evaluates invocation; side-effect actions are added at the policy
// classification boundary rather than inferred from prompts.
type Action string

const (
	ActionAgentInvoke         Action = "agent:invoke"
	ActionRepoWrite           Action = "repo:write"
	ActionDeployStaging       Action = "deploy:staging"
	ActionDeployProduction    Action = "deploy:production"
	ActionExternalCommunicate Action = "external:communicate"
	ActionAgentDelegate       Action = "agent:delegate"
)

var allActions = []Action{
	ActionAgentInvoke,
	ActionRepoWrite,
	ActionDeployStaging,
	ActionDeployProduction,
	ActionExternalCommunicate,
	ActionAgentDelegate,
}

func AllActions() []Action {
	return append([]Action(nil), allActions...)
}

func ValidAction(action Action) bool {
	for _, candidate := range allActions {
		if candidate == action {
			return true
		}
	}
	return false
}

// Request is the non-sensitive input to authorization. IDs are opaque; prompt,
// credential, instruction, and private content are deliberately absent.
type Request struct {
	Path         Path
	Phase        string
	Action       Action
	Identity     requestidentity.RequestIdentity
	WorkspaceID  string
	ProjectID    string
	IssueID      string
	AgentID      string
	ParentTaskID string
	TaskID       string
	// PreconditionFailure is set only by trusted server-side claim code after
	// detecting missing/stale authorization metadata or an inactive session.
	// It is always an enforced denial and is persisted through the same ledger.
	PreconditionFailure string
}

// Decision is returned by every evaluator in both observe and enforce modes.
type Decision struct {
	ID                  string
	LineageID           string
	BudgetReservationID string
	DelegationConsumed  bool
	Allowed             bool
	ReasonCode          string
	PolicyVersion       string
	ObserveOnly         bool
}

// Evaluator is the single admission choke point.
type Evaluator interface {
	Evaluate(context.Context, Request) (Decision, error)
}

var ErrDenied = errors.New("task admission denied")
var ErrUnknownPath = errors.New("unknown task admission path")
var ErrUnknownAction = errors.New("unknown task admission action")

// CompatibilityEvaluator preserves current behavior during migration stage 1.
// It still returns a typed decision so stage 3 can replace it with durable
// observe-only evaluation without changing any enqueue caller.
type CompatibilityEvaluator struct{}

func (CompatibilityEvaluator) Evaluate(_ context.Context, _ Request) (Decision, error) {
	return Decision{
		LineageID:     "",
		Allowed:       true,
		ReasonCode:    "legacy_compatibility_allow",
		PolicyVersion: "legacy-v1",
		ObserveOnly:   true,
	}, nil
}
