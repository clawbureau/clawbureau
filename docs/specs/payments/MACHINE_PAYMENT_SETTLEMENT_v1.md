> **Type:** Spec
> **Status:** ACTIVE
> **Owner:** @clawbureau/economy
> **Last reviewed:** 2026-02-11
> **Source of truth:**
> - `packages/schema/payments/machine_payment_settlement.v1.json`
> - `services/ledger/src/payment-settlements.ts`

# Machine Payment Settlement v1

Provider-agnostic settlement ingestion contract for machine payments.

This layer is intentionally **rail-neutral** (card, ACH, crypto rails, etc.) so later provider adapters (including Stripe machine payments) plug into a stable core without reworking ledger semantics.

---

## 1) Canonical settlement object

Each settlement ingest payload must resolve into this canonical record shape:

- `provider` (string)
- `external_payment_id` (string)
- `direction` (`payin | refund | payout`)
- `status` (`pending | confirmed | failed | reversed`)
- `account_id` (ledger account id)
- `amount_minor` (integer-safe string)
- `currency` (ISO-4217 uppercase)
- `network` (optional rail/network family)
- `rail` (optional provider-specific rail channel)
- `metadata` (optional object)
- optional provider timestamps:
  - `provider_created_at`
  - `provider_updated_at`
  - `settled_at`

Natural key:
- `(provider, external_payment_id, direction)`

---

## 2) Idempotency + dedupe rules

Ingest endpoint requires `Idempotency-Key` header.

Rules:
1. Same idempotency key + identical payload hash → replay cached response.
2. Same idempotency key + different payload hash → reject (`IDEMPOTENCY_KEY_REUSED`, fail-closed).
3. Same natural key + same canonical business payload/status with different idempotency key → dedupe (no second side effect).
4. Same natural key + conflicting immutable fields (`account_id`, `amount_minor`, `currency`) → reject (`DUPLICATE_CONFLICT`).

---

## 3) Status transition policy (fail-closed)

Allowed transitions:
- `pending -> confirmed | failed | reversed`
- `confirmed -> reversed`
- `failed -> (none)`
- `reversed -> (none)`
- same-status replays are accepted as no-op dedupe

Any other transition is rejected with `INVALID_STATUS_TRANSITION`.

---

## 4) Ledger event mapping

When status transitions trigger economic effects:

- **confirmed payin**
  - balance: `available += amount_minor`
  - event type: `payin_settle`

- **reversed payin** or **confirmed refund**
  - balance: `available -= amount_minor` (must remain non-negative)
  - event type: `payin_reverse`
  - insufficient funds → `INSUFFICIENT_FUNDS` (fail-closed)

- **confirmed payout**
  - event type: `payout_settle`
  - settlement record persists; ingestion path must not apply duplicate debits (idempotent no-double-debit rule)

For all emitted settlement events:
- event hash chain semantics remain unchanged (`previous_hash -> event_hash`).

---

## 5) API surface (ledger)

- `POST /v1/payments/settlements/ingest`
- `GET /v1/payments/settlements/:provider/:external_payment_id`
- `GET /v1/payments/settlements?account_id=&status=&provider=&direction=&limit=&cursor=`

Auth:
- admin-auth only (fail-closed if `LEDGER_ADMIN_KEY` is unset).

Pagination:
- deterministic cursor ordering by `(created_at DESC, id DESC)`.
