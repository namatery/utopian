# ADR-0001: Scope and non-goals

Status: **Accepted** (2026-10-15)

## Context

The Utopia client exposes a JSON-RPC API protected by a single token that has
full control of the wallet. Services that want to use it must either hold that
token, or build their own protection around it. We want a reusable, open-source
component that does this, deployable like MinIO or Vault.

## Decision

Utopian is a **security gateway plus dashboard**, and nothing more.

It does:
- Authenticate every request (ADR-0002).
- Authorize requests against scoped keys and policy documents.
- Forward allowed calls 1:1 to the Utopia client, using the same method names and parameters.
- Record an audit log, expose metrics, and provide an admin API, CLI, and dashboard.

It does not:
- Add business logic, ledgers, reconciliation, or balance tracking.
- Provide idempotency or deduplicate payments (see [Payment safety](../payment-safety.md)).
- Serve multiple Utopia accounts from one instance. One instance means one account.
- Offer drop-in compatibility with existing Utopia SDKs. Utopian has its own signed API.
- Expose messaging, channels, uNS, or mining in v1.

Policy conditions (limits, allowlists, caps) are allowed because they only ever
**refuse** requests. They never change, retry, or create one.

## Consequences

- The codebase stays small and auditable.
- Users must handle payment idempotency themselves; the docs must say so plainly.
- Users of existing Utopia SDKs must switch to the Utopian SDK or sign requests themselves.
- New method groups can be added later as opt-in registry entries.
