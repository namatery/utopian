# Roadmap

Each phase has exit criteria. A phase is done when all of them are met, not
when its features exist.

## Phase 0: Foundations

- Threat model, ADRs 0001–0005, method registry, payment safety doc
- `architecture.md` (package layout, interfaces)
- Fake Utopia server design (scriptable, fault injection)
- CI skeleton: `go test -race`, `golangci-lint`, `govulncheck`, `gosec`

**Exit:** all ADRs accepted; method registry open questions answered against a real Utopia client; CI green on an empty module.

## Phase 1: Secure gateway (MVP)

- `POST /v1/rpc` with `UTOPIAN-HMAC-SHA256` signing (ADR-0002)
- `utopian init`: one-time root admin credential
- Scoped keys, JSON policy documents, method registry enforcement (deny by default)
- Stateless policy conditions: max amount per transaction, currency and recipient allowlists, source IP allowlist
- At-most-once forwarding, `outcome_unknown` errors (ADR-0003)
- Upstream token confinement + canary test (ADR-0005)
- Hash-chained audit log + `utopian audit verify`
- Prometheus metrics, `/healthz`, `/readyz`
- Local `utopian` CLI (keys, policies, audit, backup) over the shared service layer (ADR-0006)
- Go SDK (`pkg/client`), signing test vectors

**Exit:** safety invariant tests pass; canary test passes; fuzzing of auth parser and policy evaluator runs in CI.

## Phase 2: Events and rolling caps

- Utopian owns the single upstream WebSocket, or receives the client's `--notificationCallback` POSTs on a private listener (decide in an ADR)
- Authenticated event stream (SSE) for keys with `events:read`, best-effort
- Rolling-window spend caps, counted pessimistically (unknown outcome = spent), admin reset
- Optional mTLS client certificate binding per key

**Exit:** cap counters proven fail-closed under injected timeouts; event stream survives upstream reconnects.

## Phase 3: Dashboard

Server-rendered panel, see ADR-0006.

- Login with password + TOTP
- Keys and policies management, audit viewer, balance and finance history (read-only)
- Cap counters with reset, upstream health

**Exit:** CSP/CSRF/cookie review done; end-to-end UI tests; dashboard and CLI go through the same service layer.

## Phase 4: Release hardening

- Distroless, non-root, read-only image; `docker-compose.yml` example with the Utopia client
- `utopian backup` / restore
- Signed releases (cosign), SBOM, reproducible builds
- `operations.md`, `configuration.md`, `SECURITY.md`
- Nightly end-to-end tests against a real Utopia client

**Exit:** v1.0.0 tagged; self pen-test checklist completed.

## Phase 5 (v1.1): Webhooks

- Signed with the same scheme as requests
- Persistent queue, retries with backoff, dead-letter view
- At-least-once delivery by design; every event carries an ID for deduplication

## Not planned

- Multiple Utopia accounts per instance
- High availability / Postgres
- Remote admin API, sudo mode, login rate limiting (deferred by ADR-0006, not rejected)
- Messaging, channels, uNS, mining APIs (may be revisited as opt-in packs)
