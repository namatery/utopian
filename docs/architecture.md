# Architecture

Status: **Draft**

This document describes how Utopian is built. The *why* lives in the ADRs; this
is the *how*. It must stay consistent with ADRs 0001–0005.

## 1. Overview

One Go process, two listeners, one upstream.

```
                     ┌──────────────────────────── utopian ─────────────────────────────┐
                     │                                                                  │
 client ──TLS──► :8080 api ─► request pipeline ─► registry ─► upstream.Client ──────────┼──► Utopia :20000
                     │              │                                                   │
 operator ─TLS─► :8443 admin ─► dashboard (html/template) ─► service ◄── local CLI      │
                     │              │                                                   │
                     │        store (SQLite)   audit   metrics   events ◄───────────────┼──── Utopia ws :25000
                     └──────────────────────────────────────────────────────────────────┘
```

## 2. Request pipeline (`POST /v1/rpc`)

Each step either passes the request on or ends it. The order is deliberate:
cheap and unauthenticated checks first, anything that touches upstream last.

| # | Step | Package | Fails with |
|---|---|---|---|
| 1 | Assign request ID, start deadline | `gateway` | — |
| 2 | Global rate limit (protects upstream) | `ratelimit` | `429` |
| 3 | Limit and read raw body | `gateway` | `413` |
| 4 | Verify signature, timestamp, nonce (ADR-0002) | `auth` | `401` |
| 5 | Per-key rate limit | `ratelimit` | `429` |
| 6 | Parse envelope; reject `token` field | `rpc` | `400` |
| 7 | Look up method in registry; deny unknown | `registry` | `403` |
| 8 | Check key scopes | `policy` | `403` |
| 9 | Evaluate policy conditions (fail closed) | `policy` | `403` |
| 10 | Reserve rolling-cap amount (Phase 2) | `caps` | `403` |
| 11 | Forward to upstream (ADR-0003) | `upstream` | `503` / `504` |
| 12 | Settle cap reservation, write audit record | `caps`, `audit` | — |
| 13 | Normalize and return response | `rpc` | — |

Every request produces exactly one audit record, including rejected ones. The
audit write for a mutating call happens **before** the response is returned;
if the audit write fails, the response is still returned (the payment already
happened) and an alert metric is raised.

## 3. Packages

```
cmd/utopian/            main: flag parsing, wiring, subcommands (serve, init, audit verify, backup, key ...)
internal/config/        typed config, defaults, validation, secret file loading
internal/secret/        secret.Value (redacting type), KEK, AES-GCM envelope encryption
internal/auth/          signature parsing and verification, nonce cache, admin sessions, TOTP
internal/registry/      method table: name → class, scope, policy params, redaction rules
internal/policy/        policy documents, evaluation (pure functions)
internal/caps/          rolling-window counters, reserve/settle (Phase 2)
internal/ratelimit/     token buckets: global and per key
internal/rpc/           envelope types, error codes, response normalization
internal/upstream/      Utopia JSON-RPC client, circuit breaker, WebSocket owner
internal/events/        fan-out of upstream events to SSE subscribers (Phase 2)
internal/audit/         hash-chained append-only log, verifier
internal/store/         repository interfaces
internal/store/sqlite/  SQLite implementation, migrations
internal/gateway/       API listener: HTTP handler that runs the pipeline
internal/service/       admin operations: keys, policies, admins, audit queries (used by dashboard and CLI)
internal/dashboard/     admin listener: sessions, CSRF, handlers, templates (ADR-0006)
internal/metrics/       Prometheus collectors
web/                    templates, CSS, vendored htmx; embedded via embed.FS
pkg/client/             public Go SDK (signing + typed calls)
test/fakeutopia/        scriptable fake Utopia server with fault injection
test/e2e/               end-to-end tests
```

Rules:
- `internal/upstream` is the **only** package that can read the raw upstream
  token (ADR-0005). Enforced by a lint check on calls to `secret.Value.Reveal`.
- `policy`, `registry`, and `auth` signature verification are pure and have no
  I/O, so they can be tested exhaustively and fuzzed.
- `pkg/client` imports nothing from `internal/`, except a shared signing
  package that is moved to `pkg/sign` so the server and SDK use the same code.

## 4. Key interfaces

Sketches, not final signatures.

```go
// registry
type Class int // Read, Mutating, Internal

type Method struct {
    Name       string
    Class      Class
    Scope      string   // "finance:send"
    Redact     []string // params to redact in audit
}

func Lookup(name string) (Method, bool)

// policy
type Decision struct {
    Allow  bool
    Reason string // for audit only, never returned to the client
}

func Evaluate(p Policy, m registry.Method, params map[string]any, req RequestContext) Decision

// upstream
type Client interface {
    // Call sends exactly one request. It never retries Mutating methods.
    Call(ctx context.Context, m registry.Method, params, filters map[string]any) (Result, error)
}

var (
    ErrUnavailable    = errors.New("upstream unavailable")   // not sent → 503
    ErrOutcomeUnknown = errors.New("upstream outcome unknown") // sent, no answer → 504
)

// audit
type Log interface {
    Append(ctx context.Context, r Record) error
    Verify(ctx context.Context) (VerifyReport, error)
}

// store
type Keys interface {
    Get(ctx context.Context, id string) (Key, error)
    Create(ctx context.Context, k Key) error
    Revoke(ctx context.Context, id string) error
    List(ctx context.Context) ([]Key, error)
}
```

## 5. Data model (SQLite)

| Table | Purpose | Notes |
|---|---|---|
| `keys` | Client keys | id, name, policy_id, status, created_at, expires_at |
| `key_secrets` | Up to two active secrets per key | AES-GCM ciphertext, nonce, KEK version |
| `policies` | Policy documents | JSON, version |
| `admins` | Dashboard users | argon2id hash, TOTP secret (encrypted) |
| `sessions` | Dashboard sessions | random ID (hashed), admin_id, csrf token, idle/absolute expiry |
| `audit` | Append-only log | seq, time, request_id, actor, method, redacted params, outcome, prev_hash, hash |
| `cap_windows` | Rolling-cap counters (Phase 2) | key_id, currency, bucket start, reserved, settled |
| `schema_migrations` | Migration state | — |

Never stored: the upstream token, the KEK, plaintext client secrets.

### Audit hash chain

`hash = SHA-256(prev_hash || canonical_json(record_without_hash))`. The first
record uses a fixed genesis value. `utopian audit verify` recomputes the whole
chain and reports the first broken link. The chain detects modification and
deletion in the middle; deletion of the tail is detected by exporting the
latest hash periodically (metrics and logs carry it).

## 6. Upstream client

- One shared `http.Client` with explicit timeouts; no transport-level retries.
- `Mutating` calls: one attempt. If the connection fails **before** the request
  is written, return `ErrUnavailable`; otherwise any failure is
  `ErrOutcomeUnknown`. (Implemented with `httptrace.WroteRequest`.)
- `Read` calls: up to 2 retries with jittered backoff on transport errors.
- Circuit breaker: opens after N consecutive transport failures; while open,
  every call returns `ErrUnavailable` without touching the network.
- Upstream error messages are mapped to Utopian error codes; raw upstream text
  is never returned to clients.
- Owns the single upstream WebSocket (Phase 2): reconnects with backoff,
  publishes events to `internal/events`.

## 7. Configuration

File (`/etc/utopian/config.yaml`) plus env overrides (`UTOPIAN_*`). Validated
at startup; invalid config means the process exits.

```yaml
api:
  listen: ":8080"
  tls: { cert_file: /run/secrets/tls.crt, key_file: /run/secrets/tls.key }
admin:
  listen: ":8443"
upstream:
  url: "http://utopia:20000/api/1.0/"
  ws_url: "ws://utopia:25000/UtopiaWSS"
  token_file: /run/secrets/utopia_token
  timeout: 15s
security:
  kek_file: /run/secrets/utopian_kek
  signature_window: 60s
  max_body_bytes: 65536
storage:
  path: /data/utopian.db
limits:
  global_rps: 5
```

## 8. Observability

- Logs: `log/slog`, JSON, request ID on every line, secrets redacted by type.
- Metrics: requests by method/outcome, policy denials by reason, upstream
  latency, circuit state, `outcome_unknown` count, audit append failures,
  latest audit hash.
- Health: `/healthz` (process alive), `/readyz` (DB writable, upstream reachable,
  circuit closed). Served on the admin listener.

## 9. Testing layout

| Level | What | Where |
|---|---|---|
| Unit | Registry, policy, signing, hash chain, config validation | next to code |
| Fuzz | Authorization header parser, envelope parser, policy evaluator | next to code |
| Integration | Full pipeline against `fakeutopia` with fault injection | `test/` |
| Invariants | I1–I6 from the threat model, one test file each | `test/invariants/` |
| End-to-end | Real Utopia client in Docker (nightly) | `test/e2e/` |

`fakeutopia` can be scripted per call: respond normally, delay, drop the
connection before or after reading the request, return garbage, or return an
upstream error. It records every request it receives, so tests can assert
"exactly one `sendPayment` reached upstream".

## 10. Admin side

See ADR-0006: server-rendered dashboard with session auth on `:8443`; local-only
CLI; both call `internal/service`. No remote admin API in v1.

## 11. Open items

- Amount representation: decimal string end-to-end, never `float64` (blocked on the method registry verification).
