# Method registry

Status: **Draft**. Classified from the official Utopia API Client Reference
(saved copy, 168 methods). Items marked ⚠ in [Open questions](#open-questions)
must be confirmed against a real Utopia client.

The registry is the single source of truth for which Utopia methods Utopian
exposes. It drives scope checks, retry behavior, audit redaction, and policy
conditions. In code it is one table; this document will later be generated
from that table.

Any method not listed in the v1 table is **denied**.

## Classes

| Class | Exposed | Retry on transport error | Audit |
|---|---|---|---|
| `read` | Yes | Yes (bounded) | Method, outcome |
| `mutating` | Yes | **Never** (ADR-0003) | Method, params (redacted), outcome |
| `internal` | No: used only by Utopian itself | n/a | n/a |
| `deferred` | No, may become an opt-in pack later | — | — |
| `forbidden` | Never, not even as an opt-in | — | — |

## Upstream facts that shape the registry

- **Envelope:** `{"method", "params", "token"}`; responses are
  `{"result", "resultExtraInfo": {"elapsed"}}`. Methods returning arrays accept
  an optional generic filter (`sortBy`, `offset`, `limit`).
- **Amounts** are decimal strings in the examples (`"10"`), must be > 0, and have
  at most 9 digits after the decimal point. Utopian requires amounts as JSON
  **strings**, parses them with exact decimal arithmetic (never `float64`), and
  rejects JSON numbers.
- **Currencies:** `CRP` and `USD`. `CRP` is the default when omitted.
- **`sendPayment.to` accepts a nick, a public key, or a card ID.** Nicks are
  uNS names and can change owner, so a payment to a nick can reach a different
  person than intended. See the policy conditions below.
- **Vouchers are bearer money.** Anyone who has a voucher code can redeem it.
  Voucher codes are therefore secrets: in parameters and in responses.
- **`acceptInvoice` pays an invoice by ID**, with no amount in the request.
  Amount-based policy cannot be applied to it without looking the invoice up
  first, which would add logic and a time-of-check/time-of-use gap.
- **Finance notifications:** besides the WebSocket, the Utopia client can POST
  finance notifications to a URL (`--notificationCallback=<url>`, with
  `--notificationCallbackFilter` = `transfer`, `voucher`, `invoice`, `uns`,
  `other`, `all`). This is relevant for Phase 2 events.

## v1 methods

### Finance: read (`finance:read`)

| Method | Class | Notes |
|---|---|---|
| `getBalance` | read | Main balance only, not cards |
| `getFinanceSystemInformation` | read | Fees and limits |
| `getFinanceHistory` | read | Main reconciliation tool (payment safety) |
| `getCards` | read | |
| `getTransactionIdByReferenceNumber` | read | Returns `batchid` |
| `requestHistoryByDate` | read | Asks the client to fetch history; no money moves |
| `requestHistoryByBatch` | read | Same |
| `verifyTransaction` | read | Async: returns `request_id` |
| `verifyTransactionByHash` | read | Async: returns `request_id` |
| `getVerifyTransactionResponse` | read | Result of the two above |

### Finance: send (`finance:send`)

| Method | Class | Policy-relevant params |
|---|---|---|
| `sendPayment` | mutating | `to`, `amount`, `currency`, `cardid`, `alias` |
| `createVoucher` | mutating | `amount`, `currency`. Response treated as sensitive until open question 3 is answered |
| `createVoucherBatch` | mutating | `amount × count`, `currency`. Response treated as sensitive (same) |

### Vouchers

| Method | Class | Scope | Notes |
|---|---|---|---|
| `getVouchers` | read | `vouchers:read` | ⚠ Assumed to return redeemable codes. Separate, sensitive scope. Response never logged. |
| `verifyVoucherByHash` | read | `vouchers:read` | `voucherid` redacted |
| `useVoucher` | mutating | `vouchers:redeem` | Money in. `voucherid` redacted |
| `deleteVoucher` | mutating | `vouchers:manage` | Refunds to the main balance. `voucherid` redacted |

### Invoices (money in)

| Method | Class | Scope |
|---|---|---|
| `getInvoices` | read | `invoices:read` |
| `getInvoiceByReferenceNumber` | read | `invoices:read` |
| `sendInvoice` | mutating | `invoices:write` |
| `cancelInvoice` | mutating | `invoices:write` |
| `declineInvoice` | mutating | `invoices:write` |

### System (`system:read`)

| Method | Class |
|---|---|
| `getSystemInfo` | read |
| `getProfileStatus` | read |
| `getOwnContact` | read |
| `getUnsSyncInfo` | read |

### Internal (used by Utopian, never exposed)

| Method | Used for |
|---|---|
| `setWebSocketState`, `getWebSocketState` | Owning the event stream (Phase 2) |
| `getSystemInfo`, `getUnsSyncInfo` | `/readyz`, dashboard health |
| `getNetworkConnections` | Dashboard health only (returns peer addresses) |

## Policy conditions per method

| Method | Parameter | Condition |
|---|---|---|
| `sendPayment` | `amount` | `maxAmountPerTx`; rolling cap (Phase 2) |
| `sendPayment` | `currency` | `currencies` allowlist |
| `sendPayment` | `to` | `recipients` allowlist (exact match). **Nick recipients are rejected unless `allowNickRecipients: true`.** |
| `sendPayment` | `cardid` | `sourceCards` allowlist |
| `sendPayment` | `alias` | `aliases` allowlist |
| `createVoucher` | `amount`, `currency` | `maxAmountPerTx`, `currencies`, rolling cap |
| `createVoucherBatch` | `amount`, `count`, `currency` | Total `amount × count` against `maxAmountPerTx` and rolling cap |
| `sendInvoice` | `amount`, `currency` | `maxAmountPerTx` (optional) |

Recipient form is decided by shape: 64 hex characters is a public key, 16 hex
characters is a card ID, anything else is treated as a nick.

## Deferred (possible opt-in packs)

| Group | Methods | Why deferred |
|---|---|---|
| Outgoing invoice payment | `acceptInvoice` | Pays money with no amount in the request; caps cannot apply |
| Cards | `addCard`, `deleteCard` | Card creation costs fees and has daily limits; operator task |
| Payment aliases | `requestNewPublicKeyPaymentAlias`, `getMyPublicKeyPaymentAliases` | Not needed for v1 |
| Promo codes | `createPromoCode`, `deletePromoCode` | Not needed for v1 |
| uCode | `ucodeEncode`, `ucodeDecode` | Useful for payment QR codes later |
| uNS read | `unsSearchByPk`, `unsSearchByNick`, `unsRegisteredNames`, `summaryUnsRegisteredNames`, `unsHistoryName`, `unsRegisteredNamesByDatetimes`, `unsUnregisteredNamesByDatetimes`, `incomingUnsTransfer`, `outgoingUnsTransfer`, `getWhoIsInfo` | Out of scope (ADR-0001) |
| uNS write | `unsCreateRecordRequest`, `unsModifyRecordRequest`, `unsDeleteRecordRequest` | Cost fees; out of scope |
| Treasury and mining data | `requestTreasuryPoSRates`, `getTreasuryPoSRates`, `requestTreasuryTransactionVolumes`, `getTreasuryTransactionVolumes`, `requestTreasuryUUSDSupply`, `getTreasuryUUSDSupply`, `requestTreasuryCrpSupply`, `getTreasuryCrpSupply`, `getMiningInfo`, `getMiningBlocks`, `getMiningBlocksWithTreasury`, `statusHistoryMining`, `getDPoSInfo` | Read-only, but not needed for payments |
| Profile | `setProfileStatus`, `setProfileData`, `getReleaseNotes`, `lowTrafficMode`, `setLowTrafficMode` | Out of scope |
| Contacts | `getContacts`, `getContactGroups`, `getContactsByGroup`, `setContactGroup`, `renameContactGroup`, `deleteContactGroup`, `setContactNick`, `deleteContact`, `getContactAvatar`, `getAvatarByKey`, `getChannelAvatar`, `sendAuthorizationRequest`, `acceptAuthorizationRequest`, `rejectAuthorizationRequest` | Out of scope (ADR-0001) |
| Instant messages | `sendInstantMessage`, `sendInstantQuote`, `sendInstantSticker`, `sendDeleteInstantMessage`, `sendEditInstantMessage`, `pinInstantMessage`, `getPinnedMessages`, `bookmarkInstantMessage`, `getStickerCollections`, `getStickerNamesByCollection`, `getImageSticker`, `sendInstantBuzz`, `sendInstantInvitation`, `removeInstantMessages`, `getContactMessages`, `clearTrayNotifications` | Out of scope (ADR-0001) |
| Email | `sendEmailMessage`, `getEmailFolder`, `getEmails`, `getEmailById`, `deleteEmail`, `sendReplyEmailMessage`, `sendForwardEmailMessage`, `sendEmailInvitation`, `emptyEmailsTrash` | Out of scope (ADR-0001) |
| Channels | `getChannels`, `sendChannelMessage`, `sendChannelDeleteMessage`, `sendChannelEditMessage`, `sendChannelComment`, `getChannelComments`, `sendChannelPicture`, `sendChannelQuote`, `removeChannelMessage`, `enableChannelNotification`, `joinChannel`, `fetchChannelHistory`, `leaveChannel`, `setChannelAsBookmarked`, `getChannelMessages`, `getChannelInfo`, `getChannelModerators`, `getChannelContacts`, `getChannelModeratorRight`, `createChannel`, `modifyChannel`, `modifyChannelTitle`, `modifyChannelPassword`, `deleteChannel`, `getChannelSystemInfo`, `getChannelBannedContacts`, `applyChannelBannedContacts`, `sendChannelPrivateMessageToContact`, `getChannelPrivateMessagesOfContact` | Out of scope (ADR-0001) |

## Forbidden (never exposable)

These would let an API client damage the wallet, the node, or the gateway
itself, or move value outside any policy.

| Method | Reason |
|---|---|
| `storageWipe` | Destroys the client's storage |
| `getSettingInfo`, `setSettingInfo` | Node configuration |
| `enableLogs`, `getLogs` | Client logs may contain sensitive data |
| `clearNetHostDatabase` | Disrupts networking |
| `getProxyMappings`, `createProxyMapping`, `enableProxyMapping`, `disableProxyMapping`, `removeProxyMapping` | Opens network paths through the node |
| `uploadFile`, `getFile`, `deleteFile`, `sendFileByMessage`, `getFilesFromManager`, `getTransfersFromManager`, `abortTransfers`, `hideTransfers`, `acceptFileMessage`, `abortFileMessage`, `acceptAttachment`, `abortAttachment` | File system and file transfer access |
| `addDelegate`, `revokeDelegated` | Moves stake outside spend policy |
| `enableMining`, `enablePoS`, `enableHistoryMining` | Node operation; operator decision |
| `requestUnsTransfer`, `acceptUnsTransfer`, `declineUnsTransfer` | Transfers name ownership (identity takeover) |

`setWebSocketState` and `getWebSocketState` are `internal`: Utopian uses them,
clients never can.

## Open questions

To confirm against a real Utopia client (Phase 0 exit criterion):

1. ⚠ **What does `sendPayment` return?** The docs only say "status of
   completion". If there is no reference number, the payment-safety recipe
   relies on the `comment` field alone.
2. ⚠ **What does `getVouchers` return?** If it includes redeemable codes, the
   `vouchers:read` scope is as sensitive as `finance:send`.
3. ⚠ **What does `createVoucher` return?** The example is a 64-hex value, not a
   voucher code (`UTP-...`). How does a caller get the code?
4. ⚠ **Currency tag:** the docs say `USD`; the Go client library uses `UUSD`.
5. ⚠ **Error envelope:** not documented. Needed to map upstream errors.
6. ⚠ **Generic filter field name:** `filter` (docs) or `filters` (Go library)?
7. ⚠ **Does the `--notificationCallback` POST carry any authentication?** If
   not, Utopian must accept it only on the private network.
8. Is `amount` accepted as a JSON number as well as a string? (Utopian will
   send strings either way.)
