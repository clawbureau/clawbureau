# clawtrials (arbitration MVP + harness lane)

Deterministic arbitration service for marketplace disputes, plus legacy harness endpoints used by test-lane bounty closure.

## Public endpoints

- `GET /health`
- `GET /v1/harness/catalog`
- `POST /v1/harness/run`

## Admin endpoints (`Authorization: Bearer <TRIALS_ADMIN_KEY>`)

- `POST /v1/trials/cases`
- `GET /v1/trials/cases`
- `GET /v1/trials/cases/:id`
- `POST /v1/trials/cases/:id/decision`
- `POST /v1/trials/cases/:id/appeal`
- `GET /v1/trials/reports/disputes`

## Required bindings / secrets

- D1: `TRIALS_DB`
- `TRIALS_ADMIN_KEY`
- `TRIALS_JUDGE_POOL` (comma-separated DID list)
- `ESCROW_BASE_URL`
- `TRIALS_ESCROW_KEY` (must match `ESCROW_TRIALS_KEY` on clawescrow)

## Migrations

```bash
cd services/clawtrials
npx wrangler d1 migrations apply clawtrials-staging --env staging --remote
npx wrangler d1 migrations apply clawtrials --remote
```

## Deploy

```bash
cd services/clawtrials
npx wrangler deploy --env staging
npx wrangler deploy
```
