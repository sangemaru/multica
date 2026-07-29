package service

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/multica-ai/multica/server/internal/admission"
	requestidentity "github.com/multica-ai/multica/server/internal/identity"
)

type recordingAdmissionEvaluator struct {
	request  admission.Request
	decision admission.Decision
	err      error
}

func (e *recordingAdmissionEvaluator) Evaluate(_ context.Context, req admission.Request) (admission.Decision, error) {
	e.request = req
	return e.decision, e.err
}

func TestAdmitTaskUsesServerDerivedIdentityAndFailsUnknownPath(t *testing.T) {
	serverIdentity := requestidentity.RequestIdentity{
		PrincipalType:   requestidentity.PrincipalAgent,
		PrincipalID:     "agent-id",
		CredentialClass: requestidentity.CredentialAgentTaskToken,
		AgentID:         "agent-id",
		TaskID:          "task-id",
		WorkspaceID:     "workspace-id",
		LineageID:       "05000000-0000-0000-0000-000000000005",
	}
	ctx := requestidentity.WithRequest(context.Background(), serverIdentity)
	evaluator := &recordingAdmissionEvaluator{decision: admission.Decision{Allowed: true, ReasonCode: "allow", PolicyVersion: "test-v1"}}
	svc := &TaskService{Admission: evaluator}

	if _, err := svc.AdmitTask(ctx, admission.Request{Path: admission.PathMention, AgentID: "target"}); err != nil {
		t.Fatalf("AdmitTask: %v", err)
	}
	if !reflect.DeepEqual(evaluator.request.Identity, serverIdentity) {
		t.Fatalf("identity = %+v, want server identity %+v", evaluator.request.Identity, serverIdentity)
	}
	if evaluator.request.Action != admission.ActionAgentDelegate {
		t.Fatalf("machine cross-agent action = %q, want %q", evaluator.request.Action, admission.ActionAgentDelegate)
	}

	harnessIdentity := serverIdentity
	harnessIdentity.PrincipalType = requestidentity.PrincipalHarness
	harnessIdentity.CredentialClass = requestidentity.CredentialHarnessSession
	harnessIdentity.AgentID = ""
	ctx = requestidentity.WithRequest(context.Background(), harnessIdentity)
	if _, err := svc.AdmitTask(ctx, admission.Request{Path: admission.PathMention, AgentID: "target"}); err != nil {
		t.Fatalf("harness AdmitTask: %v", err)
	}
	if evaluator.request.Action != admission.ActionAgentInvoke {
		t.Fatalf("harness top-level action = %q, want %q", evaluator.request.Action, admission.ActionAgentInvoke)
	}

	if _, err := svc.AdmitTask(ctx, admission.Request{Path: admission.Path("unreviewed")}); !errors.Is(err, admission.ErrUnknownPath) {
		t.Fatalf("unknown path error = %v, want ErrUnknownPath", err)
	}
}

func TestAdmitTaskEnforcesDenyButDoesNotEnforceObserveOnlyDeny(t *testing.T) {
	evaluator := &recordingAdmissionEvaluator{decision: admission.Decision{Allowed: false, ReasonCode: "deny"}}
	svc := &TaskService{Admission: evaluator}
	if _, err := svc.AdmitTask(context.Background(), admission.Request{Path: admission.PathMention}); !errors.Is(err, admission.ErrDenied) {
		t.Fatalf("enforced deny error = %v, want ErrDenied", err)
	}

	evaluator.decision.ObserveOnly = true
	if _, err := svc.AdmitTask(context.Background(), admission.Request{Path: admission.PathMention}); err != nil {
		t.Fatalf("observe-only deny must not block: %v", err)
	}
}

// This inventory is intentionally explicit. Adding a task insert path requires
// a security review and a corresponding entry here; otherwise the test fails.
var expectedTaskInsertSites = []string{
	"service/autopilot.go::dispatchRunOnly::CreateAutopilotTask",
	"service/task.go::EnqueueChatTask::CreateChatTask",
	"service/task.go::EnqueueDeferredAssigneeFallback::CreateDeferredAgentTask",
	"service/task.go::EnqueueQuickCreateTask::CreateQuickCreateTask",
	"service/task.go::FailTask::CreateRetryTask",
	"service/task.go::MaybeRetryFailedTask::CreateRetryTask",
	"service/task.go::SendDirectChatMessage::CreateChatTask",
	"service/task.go::enqueueIssueTaskWithCommentPlan::CreateAgentTask",
	"service/task.go::enqueueMentionTaskWithCommentPlan::CreateAgentTask",
}

func TestEveryTaskInsertSiteUsesSingleAdmissionChokePoint(t *testing.T) {
	createQueries := taskCreationQueryNames(t)
	internalRoot := filepath.Clean("..")
	fset := token.NewFileSet()
	var found []string

	err := filepath.WalkDir(internalRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			hasAdmission := false
			var inserts []string
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if sel.Sel.Name == "AdmitTask" {
					hasAdmission = true
				}
				if createQueries[sel.Sel.Name] {
					inserts = append(inserts, sel.Sel.Name)
				}
				return true
			})
			if len(inserts) > 0 && !hasAdmission {
				t.Errorf("%s reaches task creation without AdmitTask", fn.Name.Name)
			}
			rel, err := filepath.Rel(internalRoot, path)
			if err != nil {
				return err
			}
			for _, insert := range inserts {
				found = append(found, filepath.ToSlash(rel)+"::"+fn.Name.Name+"::"+insert)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan task insert sites: %v", err)
	}

	sort.Strings(found)
	want := append([]string(nil), expectedTaskInsertSites...)
	sort.Strings(want)
	if strings.Join(found, "\n") != strings.Join(want, "\n") {
		t.Fatalf("task insert inventory changed without review\nfound:\n%s\n\nwant:\n%s", strings.Join(found, "\n"), strings.Join(want, "\n"))
	}
}

func taskCreationQueryNames(t *testing.T) map[string]bool {
	t.Helper()
	re := regexp.MustCompile(`(?m)^-- name: (Create[A-Za-z0-9]*Task) :one$`)
	queryRoot := filepath.Join("..", "..", "pkg", "db", "queries")
	names := make(map[string]bool)
	entries, err := os.ReadDir(queryRoot)
	if err != nil {
		t.Fatalf("read sqlc query directory: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(queryRoot, entry.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", entry.Name(), err)
		}
		for _, match := range re.FindAllSubmatch(data, -1) {
			names[string(match[1])] = true
		}
	}
	if len(names) == 0 {
		t.Fatal("no task-creation sqlc queries found")
	}
	return names
}

func TestDispatchPathVocabularyIsExplicit(t *testing.T) {
	want := []admission.Path{
		admission.PathIssueAssignee,
		admission.PathMention,
		admission.PathSquadLeader,
		admission.PathDeferredFallback,
		admission.PathQuickCreate,
		admission.PathChat,
		admission.PathDirectChat,
		admission.PathAutopilot,
		admission.PathRetry,
		admission.PathRerun,
	}
	got := admission.AllPaths()
	if len(got) != len(want) {
		t.Fatalf("dispatch path count = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("dispatch path[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
