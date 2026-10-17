# Payment safety

Status: **Draft**

Read this before you integrate a service that sends money through Utopian.

## The short version

1. **Utopian never retries a payment.** If it sends your request upstream once,
   that is the only time.
2. **Utopian does not stop *you* from paying twice.** If your service sends the
   same payment twice, both are valid, signed requests and both are forwarded.
3. **A timeout does not mean the payment failed.** When Utopian returns
   `outcome_unknown`, the payment may or may not have happened. Check before you
   retry.

## Why Utopian does not deduplicate payments

The Utopia API has no idempotency keys. Utopian could only fake them with its
own state, and that state could disagree with the wallet. A gateway that
*sometimes* prevents double payments is more dangerous than one that clearly
never does, because people stop checking. So Utopian stays a pass-through and
gives you the tools to check.

## Error outcomes

| Response | Meaning | Safe to retry? |
|---|---|---|
| `2xx` | Upstream accepted the call. | No: it happened. |
| `4xx` (auth, policy, validation) | Rejected by Utopian. Nothing was sent upstream. | Yes, after fixing the cause. |
| `503 upstream_unavailable` | Utopian did not send the request (circuit open, upstream down). | Yes. |
| `504 outcome_unknown` | The request was sent; no answer arrived in time. | **Not until you check.** |

Every response carries `X-Request-Id`, which also appears in the Utopian audit log.

## Recommended pattern

1. Generate your own payment ID (for example, an order ID) before paying.
2. Put it in the payment `comment` (max 148 characters).
3. Store "payment started" in your own database before calling Utopian.
4. On `outcome_unknown`, query `getFinanceHistory` (filters: destination,
   amount, date range) and look for your ID in the comment.
5. Retry only if it is not there, and only after enough time has passed for the
   transfer to appear.

## Pay to public keys or card IDs, not nicks

`sendPayment` accepts a nick as the recipient, but nicks are uNS names and can
change owner. By default, Utopian rejects nick recipients. Resolve the nick to a
public key once, verify it, and pay the key.

## Signing does not prevent duplicates

Request signing stops an *attacker* from replaying a captured request. A retry
by your own service gets a fresh timestamp, nonce, and signature, and is a new,
valid request.

## Spend caps

Rolling spend caps count what passed through Utopian, not what the wallet
actually did. A request with an unknown outcome counts as spent. Caps are a
blast-radius limit for a stolen key, not an accounting tool.
