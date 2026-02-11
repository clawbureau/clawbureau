# clawsettle

Settlement rail adapter service.

Current scope:
- Verify Stripe webhooks (signature fail-closed)
- Enforce strict Stripe livemode environment guard
  - staging rejects `livemode=true`
  - production rejects `livemode=false` unless explicitly allowed
- Persist verified settlement events in a durable forwarding outbox before ledger forwarding
- Retry failed ledger forwarding (cron + manual admin endpoint)
- Initiate payouts with deterministic ledger lock-before-provider semantics
- Track payout lifecycle state machine with exact-once finalize/rollback behavior for `payout.paid` / `payout.failed`
- Provide payout reconciliation + ops endpoints (stuck/failed visibility, targeted retry, JSON/CSV report artifacts)
- Map verified provider events into clawledger settlement ingest API
- Deduplicate replayed webhook events by Stripe `event.id`

## Endpoints

- `POST /v1/stripe/webhook`
- `POST /v1/stripe/forwarding/retry` (admin; supports `{ limit, force, event_id }`)
- `POST /v1/payouts/connect/onboard`
- `POST /v1/payouts` (requires idempotency key header)
- `GET /v1/payouts/:id`
- `POST /v1/payouts/:id/retry` (admin)
- `GET /v1/payouts/ops/stuck` (admin)
- `GET /v1/payouts/ops/failed` (admin)
- `GET /v1/reconciliation/payouts/daily?date=YYYY-MM-DD&format=json|csv` (admin)
- `GET /health`

## Required secrets

- `STRIPE_WEBHOOK_SIGNING_SECRET`
- `LEDGER_ADMIN_KEY`
- `SETTLE_ADMIN_KEY` (admin retry + ops endpoints)

## Notable vars

- `PAYOUTS_CLEARING_DOMAIN` (default: `clawsettle.payouts`)
- `PAYOUT_STUCK_MINUTES_DEFAULT` (default: `60`)
- `STRIPE_CONNECT_ONBOARD_BASE_URL`

## Smoke

```bash
STRIPE_WEBHOOK_SIGNING_SECRET=*** \
LEDGER_ADMIN_KEY=*** \
node scripts/poh/smoke-clawsettle-stripe-webhook.mjs --env staging
```

If local DNS has not propagated yet, force an edge IP for the staging hostname:

```bash
STRIPE_WEBHOOK_SIGNING_SECRET=*** \
LEDGER_ADMIN_KEY=*** \
node scripts/poh/smoke-clawsettle-stripe-webhook.mjs --env staging --clawsettle-resolve-ip 104.21.55.125
```

Retry/outbox smoke (failure -> retry success -> no double-credit):

```bash
STRIPE_WEBHOOK_SIGNING_SECRET=*** \
LEDGER_ADMIN_KEY=*** \
SETTLE_ADMIN_KEY=*** \
node scripts/poh/smoke-clawsettle-forwarding-retry.mjs --env staging
```

Payout initiation + lifecycle exact-once smoke:

```bash
STRIPE_WEBHOOK_SIGNING_SECRET=*** \
LEDGER_ADMIN_KEY=*** \
node scripts/poh/smoke-clawsettle-payout-lifecycle.mjs --env staging
```

Payout reconciliation + ops controls smoke:

```bash
STRIPE_WEBHOOK_SIGNING_SECRET=*** \
LEDGER_ADMIN_KEY=*** \
SETTLE_ADMIN_KEY=*** \
node scripts/poh/smoke-clawsettle-payout-reconciliation.mjs --env staging
```
