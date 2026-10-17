# ADR-0005: Upstream token confinement

Status: **Accepted** (2026-10-15)

## Context

The Utopia API token grants full control of the wallet. Utopian exists so that
no other service ever needs it. Leaking it through Utopian would defeat the
whole project.

## Decision

The upstream token never leaves the Utopian process. Controls:

| Leak path | Control |
|---|---|
| Logs, panics, `fmt` | `secret.Value` type: `String`, `GoString`, `MarshalJSON`, `LogValue` all return `[REDACTED]`. The raw value is reachable only through one explicit method, used only in the upstream client package. |
| Configuration | Loaded from a file (`UTOPIA_TOKEN_FILE`, Docker secret). A plain env var is accepted with a warning. Never from a CLI flag. |
| Storage | Never written to the database or backups. |
| Admin API and dashboard | Write-only. Shown only as "configured, last verified at …". |
| Upstream errors | Normalized, never passed through raw. Responses are scrubbed of the token string as a backstop. |
| WebSocket URL | Contains the token in the query string. Built only inside the upstream package, never logged; library errors are wrapped and sanitized. |
| Exposed methods | The method registry excludes methods that return connection settings, WebSocket configuration, or keys. |
| Audit log | Stores method, redacted params, and outcome. Never the upstream request envelope. |
| Network | The Utopia client port is reachable only on the private container network. |

### Canary test

The integration suite starts Utopian with a recognizable token
(`CANARY-<random>`), runs every scenario (success, upstream errors, timeouts,
panics, invalid config, admin and dashboard calls), then searches **all**
outputs for the canary: logs, audit rows, HTTP responses, metrics, the SQLite
file, and backups. Any match fails CI.

## Consequences

- Clients cannot accidentally receive or store the upstream token.
- Rotating the upstream token is an admin operation; clients are unaffected.
- The canary test must be kept up to date as new outputs are added.
