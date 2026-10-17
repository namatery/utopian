# ADR-0006: Admin authentication and dashboard stack

Status: **Accepted** (2026-10-17)

Amends: ADR-0001 and ADR-0005, where "admin API" now means the admin panel and
the shared service layer. There is no remote admin API in v1.

## Context

Operators manage Utopian through a simple web panel (in the spirit of pgAdmin)
and a CLI. ADR-0002 signs API requests with HMAC, but a browser cannot hold an
HMAC secret safely: any XSS would expose it. Browser-based admin panels in
comparable projects (pgAdmin, Gitea, Grafana) use server-side sessions for
humans and API keys for machines.

## Decision

### Dashboard

- Server-rendered with Go `html/template`, plus a vendored copy of htmx for
  partial page updates. No SPA, no npm, no JS build step.
- Templates and static assets embedded in the binary via `embed.FS`.
- Strict CSP: `default-src 'self'; script-src 'self'; object-src 'none';
  frame-ancestors 'none'`. No inline scripts, no CDNs.
- Served only on the admin listener (`:8443`).

### Admin authentication

- Login: username + password (argon2id) + TOTP. TOTP is mandatory.
- Server-side sessions stored in SQLite. The cookie holds only a random
  256-bit session ID: `HttpOnly`, `Secure`, `SameSite=Strict`, `__Host-` prefix.
- Idle timeout 30 minutes, absolute timeout 8 hours. Logout deletes the session server-side.
- CSRF token on every state-changing request.
- Every admin action is written to the audit log with the admin's identity.

### CLI

- The CLI runs **locally**, inside the container (`docker exec utopian utopian ...`).
  It operates on the local database directly. There is no remote admin API in v1.
- The first admin is created only by `utopian init`. There is no web signup.
- Recovery commands (`admin reset-password`, `admin reset-totp`) exist only in the CLI.

### Shared service layer

Both the dashboard handlers and the CLI call the same internal service layer
(`internal/service`). Validation, authorization and audit logging live there,
so neither front end can bypass them.

### Deferred

- **Sudo mode** (re-enter TOTP before dangerous actions).
- **Login rate limiting and lockout.** Until then, the operator should keep the
  admin listener off the public internet (localhost, VPN, or private network).
  Note: argon2id makes each login attempt CPU-expensive, so unlimited attempts
  are also a DoS vector on the admin listener.
- **Remote admin API with HMAC admin keys**, for automation such as Terraform.
- WebAuthn / passkeys, OIDC login.

## Alternatives considered

- **SPA (React/Preact) + JSON admin API.** Richer UI, but adds an npm toolchain
  and a large dependency tree, and needs a separate API surface. Rejected for v1.
- **HMAC in the browser.** The secret would be readable by JavaScript. Rejected.
- **Remote CLI over an admin API.** More convenient, but more attack surface.
  Deferred.

## Consequences

- The UI stays simple: tables and forms. Charts are minimal or absent in v1.
- Contributors need only Go to work on the dashboard.
- Without login rate limiting, the admin listener must not be exposed publicly.
  The operations guide must say so.
