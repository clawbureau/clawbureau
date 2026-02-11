# clawsettle

Settlement rail adapter service.

Current scope:
- Verify Stripe webhooks (signature fail-closed)
- Enforce strict Stripe livemode environment guard
  - staging rejects `livemode=true`
  - production rejects `livemode=false` unless explicitly allowed
- Persist verified settlement events in a durable forwarding outbox before ledger forwarding
- Retry failed ledger forwarding (cron + manual admin endpoint)
- Map verified provider events into clawledger settlement ingest API
- Deduplicate replayed webhook events by Stripe `event.id`

## Endpoints

- `POST /v1/stripe/webhook`
- `POST /v1/stripe/forwarding/retry` (requires `Authorization: Bearer <SETTLE_ADMIN_KEY>`, supports `{ limit, force, event_id }`)
- `GET /health`

## Required secrets

- `STRIPE_WEBHOOK_SIGNING_SECRET`
- `LEDGER_ADMIN_KEY`
- `SETTLE_ADMIN_KEY` (manual retry endpoint)

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
