# Implementation plan

Status: **Draft**

Ordered tasks for Phases 0 and 1 (see [Roadmap](roadmap.md)). Each task is
small enough to review in one sitting and lists the tests that prove it.
A task is done when its tests pass in CI, not when the code exists.

Conventions:
- Pure packages (no I/O) come first; everything above them is tested against them.
- Every invariant from the [threat model](threat-model.md) gets a dedicated test.
- Standard library first. Every new dependency needs a one-line justification in the PR.

## Phase 0: foundations

| ID | Task | Depends on | Tests / done when |
|---|---|---|---|
| P0.1 ✅ | Module skeleton: `go.mod`, `cmd/utopian` (`version` only), Makefile, `.gitignore` | — | `go build ./...`, `go vet ./...` |
| P0.2 ⏳ written, not yet run | CI: `go test -race`, vet, golangci-lint, govulncheck, gosec | P0.1 | Green on the skeleton |
| P0.3 ✅ | `internal/registry`: v1 method table, classes, scopes, redaction | P0.1 | Exposed ∩ forbidden = ∅; internal methods never exposed; unknown → not found; every mutating method has a scope |
| P0.4 ✅ | `internal/secret`: `secret.Value` | P0.1 | Every formatting path (`%v %+v %#v %s %q`, JSON, `slog`, `errors`) prints `[REDACTED]` |
| P0.5 ✅ | `pkg/sign`: string-to-sign, sign, verify, header parse/format, `SignRequest` | P0.1 | Published test vectors (cross-checked with `openssl`); fuzzed header parser; field validation blocks newline injection |
| P0.6 ✅ | `test/fakeutopia`: scriptable fake upstream, records every request | P0.1 | Self-tests for each fault mode: delay, drop before read, drop after read, garbage, upstream error |
| P0.7 | Real-client verification script; answer method registry open questions | — | Raw responses recorded under `test/fixtures/upstream/` |

## Phase 1: secure gateway (MVP)

| ID | Task | Depends on | Tests / done when |
|---|---|---|---|
| P1.1 | `internal/config`: typed config, defaults, validation, secret files | P0.4 | Invalid configs rejected (table tests); token only via file or env |
| P1.2 | `internal/secret`: KEK loading, AES-256-GCM seal/open | P0.4 | Round-trip; tamper detection; wrong KEK fails |
| P1.3 | `internal/store` interfaces + `sqlite` implementation + migrations | P1.2 | Repository tests on a temp DB; migrations idempotent |
| P1.4 | `internal/audit`: hash-chained append, `Verify` | P1.3 | Modify/delete/reorder any row → verify fails at that row |
| P1.5 | `internal/auth`: verify signed requests, nonce cache, process-start rule | P0.5, P1.3 | Skew, replay, restart, wrong key, mutated body; uniform 401 |
| P1.6 | `internal/policy`: documents + evaluation, exact decimal amounts | P0.3 | Table tests per condition; fuzz evaluator; any error → deny (I6) |
| P1.7 | `internal/upstream`: client, sent/not-sent detection, circuit breaker | P0.3, P0.4, P0.6 | Mutating calls reach upstream at most once under every fault (I3) |

Notes for P1.7:
- Only a refused dial is a reliable "not sent". A connection that is accepted and then dropped can still look written to the client, so it must map to `outcome_unknown` (see `fakeutopia.DropConnections`).
- Go's `http.Transport` retries some requests transparently. Mutating calls must never carry `Idempotency-Key` / `X-Idempotency-Key` headers (which make a POST replayable), and the at-most-once test must cover reused keep-alive connections, not only fresh ones.
| P1.8 | `internal/rpc` + `internal/gateway`: pipeline steps 1–13 | P1.4–P1.7 | End-to-end against fakeutopia; one audit record per request |
| P1.9 | `internal/ratelimit`: global and per-key token buckets | P1.8 | Deterministic tests with a fake clock |
| P1.10 | `internal/service` + CLI: `init`, `key create/list/revoke`, `policy set`, `audit verify`, `backup` | P1.3, P1.4 | CLI golden tests; `init` refuses to run twice |
| P1.11 | `internal/metrics`, `/healthz`, `/readyz` | P1.7, P1.8 | Readiness reflects DB, upstream, circuit state |
| P1.12 | Canary test (I1) | P1.8, P1.10 | Canary token absent from logs, audit, responses, metrics, DB file, backups |
| P1.13 | `pkg/client`: Go SDK + snippets (curl, Python, Node) | P0.5 | Snippets verified against test vectors in CI |

## Invariant test map

| Invariant | Test location |
|---|---|
| I1 token never leaves | `test/invariants/token_confinement_test.go` (P1.12) |
| I2 every request signed | `test/invariants/signed_only_test.go` (P1.8) |
| I3 at most once | `test/invariants/at_most_once_test.go` (P1.7, P1.8) |
| I4 unknown methods denied | `internal/registry` + `test/invariants/deny_unknown_test.go` |
| I5 audit tamper-evident | `internal/audit` (P1.4) |
| I6 policy fails closed | `internal/policy` (P1.6) |
