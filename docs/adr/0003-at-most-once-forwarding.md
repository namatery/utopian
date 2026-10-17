# ADR-0003: At-most-once forwarding of mutating calls

Status: **Accepted** (2026-10-15)

## Context

The Utopia API has no idempotency keys. A gateway that retries a payment on a
timeout, or returns an ambiguous error that leads the client to retry, can cause
a double payment that neither side intended.

## Decision

- A call classified `mutating` in the method registry is sent upstream **at most
  once** per inbound request. No retries at any layer: no retrying HTTP
  transport, no retry middleware.
- `read` calls may be retried a bounded number of times on transport errors.
- Utopian distinguishes three failure cases and reports them explicitly:

| Situation | Response |
|---|---|
| Rejected before sending (auth, policy, validation) | `4xx` |
| Not sent: upstream down or circuit breaker open | `503 upstream_unavailable` |
| Sent, but no response before the deadline | `504 outcome_unknown` |

- The circuit breaker fails fast. Requests are never queued for later delivery.
- Each request gets an `X-Request-Id`, returned to the client and recorded in
  the audit log together with the outcome.

## Consequences

- Utopian can never be the cause of a double payment.
- Clients receive `outcome_unknown` and must check finance history before
  retrying. This is documented in [Payment safety](../payment-safety.md).
- A test suite with a fault-injecting fake upstream proves the invariant under
  every failure mode (timeout before send, after send, connection reset,
  partial response).
