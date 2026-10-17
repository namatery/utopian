# ADR-0004: Single container, SQLite

Status: **Accepted** (2026-10-15)

## Context

The target deployment is a single Docker container. One Utopian instance serves
one Utopia account. High availability is not a goal for v1.

## Decision

- One static Go binary, with the dashboard embedded via `embed.FS`.
- Storage is SQLite (pure Go driver, no CGO) in WAL mode on a `/data` volume.
  It holds keys, policies, admin users, cap counters, and the audit log. It
  never holds the upstream token or the KEK.
- Storage is behind interfaces, so another backend could be added later
  without touching the rest of the code.
- Image: distroless, non-root, read-only root filesystem.
- Two listeners: `:8080` for the API, `:8443` for admin and dashboard. Both TLS.
  Bring your own certificate, or a self-signed one is generated on first start.
- The Utopia client runs as a **separate** container. A `docker-compose.yml`
  example connects them on a private network, and the Utopia API port is never
  published.
- `utopian backup` makes a consistent online backup.

## Alternatives considered

- **Postgres.** Needed only for multiple replicas, which we are not building. Rejected for v1.
- **Bundling the Utopia client in the same image.** One fewer container, but
  Utopian would own Utopia's update cycle and run two processes in one
  container. Rejected.

## Consequences

- Simple to run, back up, and reason about.
- No horizontal scaling; nonce cache and rate limits can live in memory.
- Restarting Utopian means a short API outage.
