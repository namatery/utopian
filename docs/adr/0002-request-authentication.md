# ADR-0002: Request authentication

Status: **Accepted** (2026-10-15)

## Context

Bearer credentials can be reused by anyone who sees them once: a proxy, a log,
an APM tool. For an API that moves money, every request should prove possession
of a secret without sending it, and should be impossible to modify or replay.

## Decision

All API requests use the `UTOPIAN-HMAC-SHA256` signing scheme over TLS. There
is no bearer mode.

### Request format

```
POST /v1/rpc
Authorization: UTOPIAN-HMAC-SHA256 KeyId=<id>, Timestamp=<unix>, Nonce=<nonce>, Signature=<hex>
Content-Type: application/json

{"method": "...", "params": {...}, "filters": {...}}
```

A body containing a `token` field is rejected.

### String to sign

```
UTOPIAN-HMAC-SHA256\n
<KeyId>\n
<Timestamp>\n
<Nonce>\n
<HTTP method>\n
<path>\n
<lowercase hex SHA-256 of the raw body>
```

`Signature = hex(HMAC-SHA256(secret, string_to_sign))`

### Verification order

1. Enforce body size limit; hash the raw bytes as received (never re-serialize).
2. Look up `KeyId`.
3. Check `Timestamp` is within the window (default ±60 s).
4. Reject if `Timestamp` is earlier than process start.
5. Compare signatures with `hmac.Equal`.
6. Record `Nonce`; reject if already seen within the window.

All failures return the same generic `401`. The specific reason goes to the audit log.

### Secrets

- Nonce ≥ 128 bits of randomness, base64url.
- Client secrets are 256-bit random values, shown once at creation.
- Stored encrypted with AES-256-GCM under a key-encryption key (KEK) loaded from
  a file or Docker secret, never stored in the database.
- Each key can hold two active secrets during rotation.

### Optional mTLS binding

A policy condition `clientCertSHA256` binds a key to specific client
certificates. This requires Utopian to terminate TLS itself.

## Alternatives considered

- **Bearer keys (hashed with argon2id).** Simpler and the server cannot leak
  them, but they can be reused by anyone who sees one. Rejected.
- **Ed25519 signatures.** The server stores only public keys, so a database
  leak can never forge requests. Harder for clients in some languages. Deferred:
  the scheme name in the header allows adding `UTOPIAN-ED25519` later.
- **mTLS only.** Strong, but painful to operate and lost behind TLS-terminating
  proxies. Kept as an optional extra factor.

## Consequences

- Clients need a few lines of signing code. We ship a Go SDK, snippets for
  curl, Python and Node, and published test vectors.
- Clocks must be synchronized (NTP). Documented.
- Signing prevents attacker replay, not client retries (see Payment safety).
- The KEK becomes a critical secret and must be backed up separately from the database.
