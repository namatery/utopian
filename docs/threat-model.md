# Threat model

Status: **Draft**

## Security invariants

These are the properties Utopian exists to guarantee. Every design decision and
every test traces back to one of them.

| # | Invariant | Enforced by |
|---|---|---|
| I1 | The upstream Utopia token never leaves the Utopian process. | ADR-0005, canary test |
| I2 | Every API request is signed. Utopian never accepts a bearer credential on the API. | ADR-0002 |
| I3 | A mutating call reaches upstream at most once per inbound request. Utopian never retries it. | ADR-0003 |
| I4 | Unknown or unclassified methods are denied. | Method registry |
| I5 | The audit log is append-only and tamper-evident. | Hash chain, `audit verify` |
| I6 | Policy evaluation fails closed: any error means deny. | Policy engine tests |

## System and trust boundaries

```
 [ Client service ] ──TLS──► [ :8080 API ]  ┐
                                            ├─ Utopian process ──private net──► [ Utopia client :20000 / ws :25000 ]
 [ Operator browser ] ──TLS──► [ :8443 admin ] ┘        │
                                                      [ /data: SQLite, KEK-encrypted secrets ]
```

| Boundary | Trusted side | Untrusted side |
|---|---|---|
| B1: API listener | Utopian | Client services, the network |
| B2: Admin listener | Utopian | Operators until authenticated, the network |
| B3: Upstream link | Utopian, the Utopia client | Anything else on the host network |
| B4: Storage | Utopian process | Anyone with filesystem or backup access |

The Utopia client itself is **trusted**. If it is compromised, the wallet is
compromised and Utopian cannot help.

## Assets

| Asset | Why it matters |
|---|---|
| Upstream Utopia token | Full control of the wallet |
| Wallet funds | The thing being protected |
| Client key secrets | Can spend within their policy |
| Admin credentials | Can create keys and change policies |
| Key-encryption key (KEK) | Decrypts all stored client secrets |
| Audit log | Evidence for investigations and disputes |

## Threats and controls

### T1: Stolen client key secret
Leaked through a log, a repository, or a compromised client host.
- Scopes and policies limit the damage (per-transaction max, allowlists, rolling caps).
- Instant revocation; key expiry.
- Optional source IP allowlist and mTLS certificate binding (an attacker also needs the client's private key).
- Audit log shows exactly what the key did.

### T2: Request interception or tampering
- TLS on all listeners.
- The signature covers method, path, timestamp, nonce and body hash, so a modified request fails verification.
- The secret itself never travels over the wire.

### T3: Replay of a captured request
- Timestamp window (default ±60 s).
- Nonce cache for the window; nonces are recorded only after the signature verifies.
- After a restart, requests with timestamps earlier than process start are rejected.
- **Not covered:** a client retrying its own request. That is a new, valid request. See [Payment safety](payment-safety.md).

### T4: Upstream token leakage
See ADR-0005. Covers logs, panics, errors, config, dashboard, audit log, WebSocket URLs, and methods that could return it.

### T5: Compromised admin account
- Admin listener separate from the API listener; must not be exposed publicly (localhost, VPN, or private network).
- Password + mandatory TOTP; server-side sessions (ADR-0006).
- The CLI is local-only (`docker exec`); there is no remote admin API in v1.
- All admin actions go to the audit log.
- Deferred: sudo mode, login rate limiting, two-person approval.

### T6: Stolen database or backup
- Client secrets encrypted with AES-256-GCM under a KEK held outside the database (file or Docker secret).
- Admin passwords hashed with argon2id.
- The upstream token is never stored in the database.
- The audit log hash chain detects modification; it does not prevent reading.

### T7: Web attacks on the dashboard
- Strict CSP, no third-party scripts, all assets embedded.
- CSRF tokens, `SameSite=Strict`, `HttpOnly`, `Secure` cookies.
- Server-rendered `html/template` (context-aware escaping), vendored htmx, no inline scripts.
- Dashboard and CLI share one service layer, so neither can bypass validation or audit.

### T8: Denial of service
- Body size limits before hashing or parsing.
- Timeouts on every read, write, and upstream call.
- Per-key and global rate limits (the global limit protects the Utopia client).
- Circuit breaker on upstream: fail fast, never queue.

### T9: Supply chain
- Small dependency set, pinned, reviewed.
- `govulncheck` and `gosec` in CI.
- Signed releases, SBOM, reproducible builds.

### T10: Double payment caused by Utopian
- No retries of mutating calls (ADR-0003).
- Timeouts after the request was sent return `outcome_unknown`, never a generic error that invites a blind retry.

### T11: Payment to a hijacked nick
`sendPayment.to` accepts uNS nicks, and nick ownership can change.
- Policies reject nick recipients unless `allowNickRecipients: true`.
- Recipient allowlists match exact public keys or card IDs.

### T12: Voucher code leakage
Voucher codes are bearer money: whoever has the code can redeem it.
- `getVouchers` requires a separate `vouchers:read` scope.
- Voucher IDs are redacted in audit records; voucher responses are never logged.

## Out of scope

- Compromise of the Utopia client or the host running it.
- Compromise of a client service's host beyond what policies and mTLS limit.
- Business-level double payments caused by client services. Utopian documents the problem; it does not solve it.
- Availability guarantees beyond a single node.
