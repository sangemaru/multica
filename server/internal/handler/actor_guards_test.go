package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	requestidentity "github.com/multica-ai/multica/server/internal/identity"
)

// TestRequireHumanActor_AllowsHumanRequest pins the happy path: a
// presence-checked human session reaches the protected endpoint.
//
// We construct a bare http.Handler chain (no full router) so the test
// exercises only the middleware logic and is independent of any
// downstream wiring.
func TestRequireHumanActor_AllowsHumanRequest(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	mw := RequireHumanActor(next)

	req := httptest.NewRequest(http.MethodGet, "/api/cloud-billing/balance", nil)
	req = req.WithContext(requestidentity.WithRequest(req.Context(), requestidentity.RequestIdentity{
		PrincipalType:   requestidentity.PrincipalMember,
		CredentialClass: requestidentity.CredentialHumanInteractive,
	}))
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if !called {
		t.Fatal("inner handler must run for non-task-token requests")
	}
}

// TestRequireHumanActor_BlocksMachineCredentials walks every machine-
// credential X-Actor-Source value the auth middlewares stamp today
// and confirms each is rejected with 403. The two values must stay
// in lockstep with auth.go and daemon_auth.go: a new machine
// credential added there without a corresponding case here would
// silently grant agents/nodes account-level access.
func TestRequireHumanActor_BlocksMachineCredentials(t *testing.T) {
	cases := []struct {
		name            string
		credentialClass requestidentity.CredentialClass
	}{
		// mat_ task token — set in middleware/auth.go's mat_ branch.
		// An agent process holding its task-scoped token must not be
		// able to read its owner's billing data.
		{name: "task_token", credentialClass: requestidentity.CredentialAgentTaskToken},
		// mcn_ cloud-node PAT — set in BOTH middleware/auth.go and
		// middleware/daemon_auth.go's mcn_ branches. A cloud-runtime
		// EC2 node operating on the owner's behalf is the same kind
		// of machine credential as mat_ for billing-authorization
		// purposes.
		{name: "cloud_pat", credentialClass: requestidentity.CredentialCloudNodePAT},
		{name: "daemon_token", credentialClass: requestidentity.CredentialDaemonToken},
		{name: "harness_session", credentialClass: requestidentity.CredentialHarnessSession},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
				t.Fatalf("inner handler must NOT run for credential class %q", tc.credentialClass)
			})
			mw := RequireHumanActor(next)

			req := httptest.NewRequest(http.MethodGet, "/api/cloud-billing/balance", nil)
			// This is what the Auth (or DaemonAuth) middleware sets
			// for the matching token kind. Setting it directly here
			// proves the gate triggers on the header regardless of
			// upstream context — the auth middlewares strip any
			// client-supplied value before stamping their own, so a
			// non-empty value at this point IS authoritative.
			req = req.WithContext(requestidentity.WithRequest(req.Context(), requestidentity.RequestIdentity{
				PrincipalType:   requestidentity.PrincipalRuntime,
				CredentialClass: tc.credentialClass,
			}))
			w := httptest.NewRecorder()
			mw.ServeHTTP(w, req)

			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", w.Code)
			}
		})
	}
}

func TestRequireHumanActor_RejectsMissingTypedIdentity(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	mw := RequireHumanActor(next)

	// A client header is never an authenticated identity.
	req := httptest.NewRequest(http.MethodGet, "/api/cloud-billing/balance", nil)
	req.Header.Set("X-Actor-Source", "future_kind")
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 — forged actor header must not satisfy the allowlist", w.Code)
	}
	if called {
		t.Fatal("inner handler must not run without typed human identity")
	}
}

func TestRequireHumanActor_ObserveMigrationAllowsLegacyHuman(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	mw := RequireHumanActorWithEnforcement(false)(next)
	req := httptest.NewRequest(http.MethodGet, "/api/cloud-billing/balance", nil)
	req = req.WithContext(requestidentity.WithRequest(req.Context(), requestidentity.RequestIdentity{
		PrincipalType: requestidentity.PrincipalMember, CredentialClass: requestidentity.CredentialLegacyPersonalToken,
	}))
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !called {
		t.Fatalf("migration compatibility status=%d called=%v", w.Code, called)
	}
}

// TestRequireHumanActor_AppliedViaChiRouterUse pins the wiring side of
// the contract: when the guard is attached to a chi route group via
// r.Use, every endpoint in that group is protected, and a task-token
// request never reaches the handler — even one we add later. This is
// what router.go's r.Route("/api/cloud-billing", ...) + r.Use(...)
// guarantees in production; the test is small but a developer adding
// a new billing endpoint and forgetting to re-attach the middleware
// would not be caught by the per-handler tests above.
func TestRequireHumanActor_AppliedViaChiRouterUse(t *testing.T) {
	// Use a real chi router so we exercise r.Use(), not just the
	// middleware function in isolation.
	r := chi.NewRouter()
	r.Use(RequireHumanActor)
	r.Get("/billing/probe", func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("inner handler must NOT run when guard rejects")
	})

	req := httptest.NewRequest(http.MethodGet, "/billing/probe", nil)
	req = req.WithContext(requestidentity.WithRequest(req.Context(), requestidentity.RequestIdentity{
		PrincipalType:   requestidentity.PrincipalAgent,
		CredentialClass: requestidentity.CredentialAgentTaskToken,
	}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}
