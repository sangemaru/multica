# Authorization V1 implementation and verification matrix

Status: forward-ported to current `origin/main` and locally verified on 2026-07-29, with three isolated current-main Issue Table E2E exceptions recorded below
Source: fine-grained authorization proposal §§18.2, 19, 20, and 22
Base: `origin/main` at `beb3e9be65023f63bd5dfdbb0231ed41aa9f1cb8`

## Migration-stage order

| Stage | Required outcome | Authoritative evidence |
|---|---|---|
| 1 | Server-derived identity; no client-header actor reclassification; one admission evaluator; complete create-work path inventory | Auth/identity unit tests; handler actor tests; AST inventory test; service integration tests |
| 2 | Opaque revocable `harness_session` and presence-checked `human_interactive_session` credentials | Migrations, token exchange/revoke API tests, middleware credential-class tests |
| 3 | Observe-only evaluation with durable decisions, `dry_run.denied`, warning/exchange guidance | Decision-row tests, metrics tests, response compatibility tests |
| 4 | Explicit workspace/project deny; protected-route credential enforcement; allowlist human gate | Table-driven dispatch-path deny tests; protected-route tests; legacy-client compatibility matrix |
| 5 | Principal boundaries, non-escalating delegation, claim-time re-authorization in the claim transaction | Boundary/depth tests; stale-policy and admission-versus-claim race tests |
| 6 | Immutable lineage and shared budget enforcement with reservation lifecycle | Mention/retry/fallback/rerun lineage tests; concurrent reservation, crash/refund/reset tests |
| V1 closeout | Durable approval cases, revocation state honesty, UI/CLI explanations, compatibility and full verification | API/schema/UI/CLI tests; approval state-machine tests; revocation tests; `make check` |

## §20 acceptance audit

Completion requires direct evidence for every row; a narrower passing subset does not complete V1.

| AC | Requirement | Planned proof |
|---|---|---|
| 1–3 | Experimental read-only boundary plus project deny; assignment, activation, mention, direct run, retry, fallback, and autopilot return the same deny | Generic policy fixtures and table-driven dispatch test |
| 4 | Denied work never invokes a provider | Task remains absent/unclaimable; fake-runtime invocation counter stays zero |
| 5 | Delegated harness identity; raw PAT denied on protected dispatch/owner routes; interactive exchange required; unknown credential denied | Auth exchange and route matrix tests |
| 6–7 | Coordinator cannot widen grants; delegation depth zero denies | Evaluator lattice/delegation tests |
| 8–9 | Capable agent admitted; UI/CLI explain allow and deny | Integration plus API schema/client rendering tests |
| 10 | Decision records contain opaque references and no prompt, credential, or private content | Persistence schema and leakage assertions |
| 11 | Stale policy and admission/claim race fail closed | Transactional race test |
| 12 | Legacy private/public behavior preserved through compatibility mapping | Existing access suite plus mapping tests |
| 13 | Inventory test fails when a create-work path bypasses admission | AST/static inventory test and negative fixture |
| 14 | Mention/retry/fallback/rerun preserve lineage and one budget; concurrent siblings cannot exceed it | Lineage and reservation lifecycle tests |
| 15 | Missing decision, policy version, lineage, or reservation makes a task unclaimable | DB/claim invariant tests using direct inserts |
| 16 | One idempotent approval case; independently verifiable delivery/acknowledgement/decision/application/resolution; requester cannot approve | Approval state-machine integration tests |
| 17 | Running-task revocation distinguishes denial, cancellation request, runtime acknowledgement, and actual termination | State transition and audit wording tests |

## Resolutions to make when reached

- Keep the initial action vocabulary to `repo:write`, `deploy:staging`, `deploy:production`, `external:communicate`, and `agent:delegate`; add only actions required by a demonstrated V1 path.
- Denied dispatches persist a decision row; create a skipped task row only where an existing client contract requires a task-shaped result.
- Mention deduplication remains separate from authorization. Mentions retain current trigger semantics but share immutable lineage and budget.
- Use native typed Go evaluation. No OPA/Cedar, signed bundles, sender-constrained credentials, or tool-capability envelope in V1.

## Completion evidence

- The authorization commit was rebased from its original 2026-07-19 base onto current `origin/main` at `beb3e9be65023f63bd5dfdbb0231ed41aa9f1cb8`. A pre-forward-port snapshot is retained at `codex/authorization-v1-pre-forward-port-20260729`.
- The authorization schema was renumbered to migrations 235–245. All 19 indexes were separated into migrations 246–264 so every index migration contains one `CREATE INDEX CONCURRENTLY` statement and one matching concurrent rollback.
- Fresh database `multica_auth_v1_forward_20260729_1939` migrated successfully from 001 through 264.
- `GOCACHE=/private/tmp/go-build-authorization-v1-forward go test -p 1 ./... -count=1` passed against that database.
- `scripts/check.sh` passed all six TypeScript typecheck packages, 4,869 TypeScript unit tests, migrations, and all Go packages. Playwright passed 26 of 29 scenarios after correcting the isolated runner ports.
- The three remaining Playwright failures reproduce in the focused `e2e/issue-table.spec.ts` run: progress copy is absent in two tests, and one response waiter captures a transient zero-count grouped-row response before the populated response. The authorization forward-port does not modify the Issue Table handlers, view controller, or these tests; this is retained as a separate current-main verification exception rather than folded into the authorization change.
- Focused authorization-path race run passed for `internal/admission`, `internal/identity`, `internal/middleware`, `internal/handler`, `internal/service`, `cmd/multica`, and `cmd/server`.
- Forced uncached lint completed with zero errors and pre-existing warnings only.
- `make sqlc`, `git diff --check`, conflict-marker inspection, concurrent-index inspection, and shell syntax checks for the verification scripts passed.
- The work is committed locally on `codex/authorization-v1`. No push, pull request, deployment, production mutation, or permission change was performed.
