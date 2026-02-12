# clawinsure (CINR-OPS-001 MVP)

Deterministic insurance quoting, policy issuance, claims adjudication, and payouts.

## Endpoints

### Claimant-authenticated
- `POST /v1/quotes`
- `POST /v1/policies`
- `GET /v1/policies/:id`
- `POST /v1/claims`
- `GET /v1/claims/:id`

### Admin-authenticated (`Authorization: Bearer <INSURE_ADMIN_KEY>`)
- `POST /v1/claims/:id/adjudicate`
- `POST /v1/claims/:id/payout`
- `GET /v1/reports/claims`

### Public
- `GET /v1/risk/:did`
- `GET /health`

## Required bindings/secrets

- D1: `INSURE_DB`
- `INSURE_ADMIN_KEY`
- `CLAWSCOPE_BASE_URL`
- `INSURE_REQUIRED_AUDIENCE`
- `CLAWREP_BASE_URL`
- `LEDGER_BASE_URL`
- `LEDGER_ADMIN_KEY`
- `TRIALS_BASE_URL` + `TRIALS_ADMIN_KEY` (for trial evidence refs)
- `ESCROW_BASE_URL` + `ESCROW_ADMIN_KEY` (for escrow evidence refs)
- `INCOME_BASE_URL` (for statement linkage URLs)

## Migrations

```bash
cd services/clawinsure
npx wrangler d1 migrations apply clawinsure-staging --env staging --remote
npx wrangler d1 migrations apply clawinsure --remote
```

## Deploy

```bash
cd services/clawinsure
npx wrangler deploy --env staging
npx wrangler deploy
```
