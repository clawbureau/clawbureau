# clawsettle

Settlement rail adapter service.

Current scope (MPY-US-003):
- Verify Stripe webhooks (signature fail-closed)
- Map verified provider events into clawledger settlement ingest API
- Deduplicate replayed webhook events by Stripe `event.id`

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
