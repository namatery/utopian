# Utopian

**A security gateway and dashboard for the [Utopia](https://u.is) API.**

> Status: **design phase**. No code yet. See [`docs/`](docs/README.md).

Utopian sits in front of a Utopia client and turns its single, all-powerful API
token into scoped, signed, auditable, revocable access. It runs as a single
container, the way you would run MinIO or Vault.

```
your services ──(signed requests, TLS)──► Utopian ──(private network)──► Utopia client
                                            │
                                   audit · policy · metrics · dashboard
```

## What it is

- **An authentication gateway.** Every request is HMAC-signed. The upstream
  Utopia token never leaves Utopian.
- **An authorization layer.** Scoped keys, policy documents, per-transaction
  limits, recipient allowlists, rolling spend caps.
- **An audit trail.** Append-only, hash-chained, verifiable.
- **An operations surface.** Metrics, health checks, a local CLI, and a
  web admin panel.

## What it is not

- **Not a payment processor.** Utopian adds no business logic. It forwards
  allowed calls 1:1 and refuses everything else.
- **Not an idempotency layer.** Utopian never retries a payment, and it also
  does not prevent *your* service from sending the same payment twice. Read
  [Payment safety](docs/payment-safety.md) before integrating.
- **Not a ledger.** The wallet in the Utopia client is the source of truth.
- **Not a replacement for the Utopia client.**

## License

TBD.
