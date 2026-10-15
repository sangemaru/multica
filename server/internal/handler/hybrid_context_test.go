package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/multica-ai/multica/server/internal/util"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

type fakeClaimContextQueries struct {
	comments  map[pgtype.UUID]db.Comment
	issues    map[pgtype.UUID]db.Issue
	err       error
	calls     int
	deadline  time.Time
	workspace pgtype.UUID
	onIssue   func()
}

func (q *fakeClaimContextQueries) GetCommentInWorkspace(ctx context.Context, arg db.GetCommentInWorkspaceParams) (db.Comment, error) {
	q.calls++
	q.deadline, _ = ctx.Deadline()
	if arg.WorkspaceID != q.workspace {
		return db.Comment{}, errors.New("unscoped lookup")
	}
	return q.comments[arg.ID], q.err
}

func (q *fakeClaimContextQueries) GetIssueInWorkspace(ctx context.Context, arg db.GetIssueInWorkspaceParams) (db.Issue, error) {
	q.calls++
	if q.onIssue != nil {
		q.onIssue()
	}
	if arg.WorkspaceID != q.workspace {
		return db.Issue{}, errors.New("unscoped lookup")
	}
	return q.issues[arg.ID], q.err
}

func TestPrepareClaimProjectContextTotalBudgetAndMidQueryCancellation(t *testing.T) {
	issue, _, q, now := claimContextFixture(t)
	before := time.Now()
	got := prepareClaimProjectContext(context.Background(), q, claimContextUUID(t, 5), claimContextUUID(t, 6), q.workspace, issue, now)
	after := time.Now()
	if got == nil || q.deadline.Before(before.Add(2*time.Second)) || q.deadline.After(after.Add(2*time.Second)) {
		t.Fatal("default total deadline not bounded to two seconds")
	}
	issue, _, q, now = claimContextFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// A backend may return a row even when cancellation races its result.
	q.onIssue = cancel
	if prepareClaimProjectContext(ctx, q, claimContextUUID(t, 5), claimContextUUID(t, 6), q.workspace, issue, now) != nil || q.calls != 2 {
		t.Fatal("selection delivered despite cancellation during final query")
	}
}

func claimContextUUID(t *testing.T, n int) pgtype.UUID {
	t.Helper()
	id, err := util.ParseUUID(fmt.Sprintf("00000000-0000-4000-8000-%012d", n))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func claimContextFixture(t *testing.T) (db.Issue, db.Comment, *fakeClaimContextQueries, time.Time) {
	t.Helper()
	now := time.Now().UTC()
	issue := db.Issue{ID: claimContextUUID(t, 1), WorkspaceID: claimContextUUID(t, 2), ProjectID: claimContextUUID(t, 3)}
	comment := db.Comment{ID: claimContextUUID(t, 4), IssueID: issue.ID, WorkspaceID: issue.WorkspaceID,
		Revision: 2, Content: "Decizie verificată / Verify current source",
		CreatedAt: pgtype.Timestamptz{Valid: true, Time: now.Add(-time.Hour)},
		UpdatedAt: pgtype.Timestamptz{Valid: true, Time: now.Add(-time.Minute)}}
	issue.Metadata = []byte(fmt.Sprintf(`{"operational_context_mode":"hybrid","context_comment_1":%q,"context_comment_1_revision":2}`, util.UUIDToString(comment.ID)))
	q := &fakeClaimContextQueries{comments: map[pgtype.UUID]db.Comment{comment.ID: comment}, issues: map[pgtype.UUID]db.Issue{issue.ID: issue}, workspace: issue.WorkspaceID}
	return issue, comment, q, now
}

func TestPrepareClaimProjectContextSelectedScopedSource(t *testing.T) {
	issue, comment, q, now := claimContextFixture(t)
	// Unselected private content is present but never queried or delivered.
	privateID := claimContextUUID(t, 99)
	q.comments[privateID] = db.Comment{ID: privateID, Content: "PRIVATE unrelated source"}
	parent, cancel := context.WithDeadline(context.Background(), now.Add(time.Second))
	defer cancel()
	got := prepareClaimProjectContext(parent, q, claimContextUUID(t, 5), claimContextUUID(t, 6), issue.WorkspaceID, issue, now)
	if got == nil || len(got.Sources) != 1 || got.Sources[0].Excerpt != comment.Content || got.Sources[0].Revision != comment.Revision || q.calls != 2 {
		t.Fatalf("selected context or query count incorrect: %#v, calls=%d", got, q.calls)
	}
	if q.deadline.After(now.Add(time.Second)) {
		t.Fatal("claim deadline extended")
	}
	expires, err := time.Parse(time.RFC3339Nano, got.ExpiresAt)
	if err != nil || expires.Sub(now) != 5*time.Minute {
		t.Fatal("invalid observation lifetime")
	}
	encoded, _ := json.Marshal(got)
	if strings.Contains(string(encoded), "PRIVATE") {
		t.Fatal("unselected source leaked")
	}
}

func TestPrepareClaimProjectContextFailsClosed(t *testing.T) {
	cases := map[string]func(*db.Issue, *db.Comment, *fakeClaimContextQueries, time.Time){
		"wrong target workspace": func(i *db.Issue, c *db.Comment, q *fakeClaimContextQueries, now time.Time) {
			i.WorkspaceID = claimContextUUID(t, 98)
		},
		"wrong comment workspace": func(i *db.Issue, c *db.Comment, q *fakeClaimContextQueries, now time.Time) {
			c.WorkspaceID = claimContextUUID(t, 98)
		},
		"wrong comment ID": func(i *db.Issue, c *db.Comment, q *fakeClaimContextQueries, now time.Time) {
			c.ID = claimContextUUID(t, 98)
		},
		"wrong parent ID": func(i *db.Issue, c *db.Comment, q *fakeClaimContextQueries, now time.Time) {
			parent := q.issues[i.ID]
			parent.ID = claimContextUUID(t, 98)
			q.issues[i.ID] = parent
		},
		"wrong parent workspace": func(i *db.Issue, c *db.Comment, q *fakeClaimContextQueries, now time.Time) {
			parent := q.issues[i.ID]
			parent.WorkspaceID = claimContextUUID(t, 98)
			q.issues[i.ID] = parent
		},
		"wrong parent project": func(i *db.Issue, c *db.Comment, q *fakeClaimContextQueries, now time.Time) {
			parent := q.issues[i.ID]
			parent.ProjectID = claimContextUUID(t, 98)
			q.issues[i.ID] = parent
		},
		"deleted": func(i *db.Issue, c *db.Comment, q *fakeClaimContextQueries, now time.Time) { c.DeletedAt.Valid = true },
		"suppressed agent": func(i *db.Issue, c *db.Comment, q *fakeClaimContextQueries, now time.Time) {
			c.SuppressedAgentIds = []pgtype.UUID{claimContextUUID(t, 6)}
		},
		"revision changed": func(i *db.Issue, c *db.Comment, q *fakeClaimContextQueries, now time.Time) { c.Revision++ },
		"future update": func(i *db.Issue, c *db.Comment, q *fakeClaimContextQueries, now time.Time) {
			c.UpdatedAt.Time = now.Add(time.Second)
		},
		"invalid update": func(i *db.Issue, c *db.Comment, q *fakeClaimContextQueries, now time.Time) { c.UpdatedAt.Valid = false },
		"infinite update": func(i *db.Issue, c *db.Comment, q *fakeClaimContextQueries, now time.Time) {
			c.UpdatedAt.InfinityModifier = pgtype.Infinity
		},
		"future created": func(i *db.Issue, c *db.Comment, q *fakeClaimContextQueries, now time.Time) {
			c.CreatedAt.Time = now.Add(time.Second)
		},
		"update before creation": func(i *db.Issue, c *db.Comment, q *fakeClaimContextQueries, now time.Time) {
			c.UpdatedAt.Time = c.CreatedAt.Time.Add(-time.Second)
		},
		"oversized": func(i *db.Issue, c *db.Comment, q *fakeClaimContextQueries, now time.Time) {
			c.Content = strings.Repeat("x", 601)
		},
		"escaping exceeds budget": func(i *db.Issue, c *db.Comment, q *fakeClaimContextQueries, now time.Time) {
			c.Content = strings.Repeat("<", 600)
		},
		"invalid UTF8": func(i *db.Issue, c *db.Comment, q *fakeClaimContextQueries, now time.Time) {
			c.Content = string([]byte{0xff})
		},
		"empty source": func(i *db.Issue, c *db.Comment, q *fakeClaimContextQueries, now time.Time) { c.Content = " \n" },
		"lookup failure": func(i *db.Issue, c *db.Comment, q *fakeClaimContextQueries, now time.Time) {
			q.err = errors.New("private DB details must not escape")
		},
		"missing second source no partial result": func(i *db.Issue, c *db.Comment, q *fakeClaimContextQueries, now time.Time) {
			i.Metadata = []byte(fmt.Sprintf(`{"operational_context_mode":"hybrid","context_comment_1":%q,"context_comment_1_revision":2,"context_comment_2":%q,"context_comment_2_revision":2}`, util.UUIDToString(c.ID), util.UUIDToString(claimContextUUID(t, 98))))
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			issue, comment, q, now := claimContextFixture(t)
			requestedID := comment.ID
			mutate(&issue, &comment, q, now)
			q.comments[requestedID] = comment
			if got := prepareClaimProjectContext(context.Background(), q, claimContextUUID(t, 5), claimContextUUID(t, 6), q.workspace, issue, now); got != nil {
				t.Fatal("invalid source delivered")
			}
		})
	}
}

func TestPrepareClaimProjectContextUnselectedMalformedAndCancelled(t *testing.T) {
	issue, _, q, now := claimContextFixture(t)
	for _, raw := range []string{`{}`, `{"unrelated":"value"}`, `null`, `[]`, `{"context_comment_1":"not-uuid","context_comment_1_revision":2}`} {
		issue.Metadata = []byte(raw)
		if prepareClaimProjectContext(context.Background(), q, claimContextUUID(t, 5), claimContextUUID(t, 6), q.workspace, issue, now) != nil || q.calls != 0 {
			t.Fatal("unselected/malformed metadata queried sources")
		}
	}
	issue, _, q, now = claimContextFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if prepareClaimProjectContext(ctx, q, claimContextUUID(t, 5), claimContextUUID(t, 6), q.workspace, issue, now) != nil || q.calls != 0 {
		t.Fatal("cancelled claim queried sources")
	}
}

func TestParseClaimCommentSelectorsStrict(t *testing.T) {
	id := util.UUIDToString(claimContextUUID(t, 4))
	for _, raw := range []string{
		fmt.Sprintf(`{"context_comment_1":%q}`, id),
		`{"context_comment_1_revision":2}`,
		fmt.Sprintf(`{"context_comment_1":%q,"context_comment_1_revision":2.5}`, id),
		fmt.Sprintf(`{"context_comment_1":%q,"context_comment_1_revision":"2"}`, id),
		fmt.Sprintf(`{"context_comment_1":%q,"context_comment_1_revision":-1}`, id),
		fmt.Sprintf(`{"context_comment_1":%q,"context_comment_1_revision":9223372036854775808}`, id),
		fmt.Sprintf(`{"context_comment_1":%q,"context_comment_1_revision":2,"context_comment_2":%q,"context_comment_2_revision":2}`, id, id),
		fmt.Sprintf(`{"context_comment_4":%q,"context_comment_4_revision":2}`, id),
	} {
		if _, ok := parseClaimCommentSelectors([]byte(raw)); ok {
			t.Fatalf("invalid selector accepted: %s", raw)
		}
	}
	got, ok := parseClaimCommentSelectors([]byte(fmt.Sprintf(`{"context_comment_1":%q,"context_comment_1_revision":9223372036854775807}`, id)))
	if !ok || got[0].revision != int64(9223372036854775807) {
		t.Fatal("integer precision lost")
	}
}

func TestClaimProjectContextModePrivacyIndependentOfSources(t *testing.T) {
	for _, raw := range []string{
		`{"operational_context_mode":"hybrid"}`,
		`{"operational_context_mode":"hybrid","context_comment_1":"malformed"}`,
		`{"operational_context_mode":"hybrid","context_comment_1_revision":9}`,
	} {
		hybrid, description := claimProjectContextMode([]byte(raw), "PRIVATE project description")
		if !hybrid || description != "" {
			t.Fatal("privacy mode depended on valid selected sources")
		}
	}
	for _, raw := range []string{`{}`, `null`, `{"operational_context_mode":"legacy"}`, `{"operational_context_mode":true}`} {
		hybrid, description := claimProjectContextMode([]byte(raw), "legacy description")
		if hybrid || description != "legacy description" {
			t.Fatal("legacy behavior changed without explicit opt-in")
		}
	}
	issue, _, q, now := claimContextFixture(t)
	issue.Metadata = []byte(strings.ReplaceAll(string(issue.Metadata), `"operational_context_mode":"hybrid",`, ""))
	if prepareClaimProjectContext(context.Background(), q, claimContextUUID(t, 5), claimContextUUID(t, 6), q.workspace, issue, now) != nil || q.calls != 0 {
		t.Fatal("non-opted issue queried selected sources")
	}
}
