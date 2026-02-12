# clawrep

Canonical reputation service for deterministic scoring, tiers, reviewer selection, penalties, and decay.

## Endpoints

- `POST /v1/events/ingest`
- `POST /v1/events/ingest-loop`
- `GET /v1/rep/:did`
- `GET /v1/tiers/:did`
- `POST /v1/reviewers/select`
- `GET /v1/reviewers/:did`
- `POST /v1/penalties/apply`
- `POST /v1/decay/run`
- `GET /v1/audit/events`
- `GET /v1/ops/queue/status`
- `POST /v1/ops/queue/replay`
- `GET /v1/ops/slo/ingest`
- `POST /v1/ops/drift/recompute`
- `GET /v1/ops/drift/latest`

## Auth

- Ingest auth: `REP_INGEST_KEY`
- Admin auth: `REP_ADMIN_KEY`

## Commands

- `npm run typecheck`
- `npm test`
- `npx wrangler deploy --env staging`
- `npx wrangler deploy`
