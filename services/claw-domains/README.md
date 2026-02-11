# claw-domains

Multi-domain landing and ecosystem navigation service for parked Claw Bureau domains.

This Worker serves domain-specific pages with:
- clearer purpose copy per domain
- logical cross-domain links (related services + live surfaces)
- richer event analytics (pageviews + click taxonomy + form intent)
- ecosystem map UI (`/ecosystem`) and machine-readable catalog (`/api/domains`)

## Page modes

Configured in `src/config.ts`:
- **for_sale**: premium domain page with BIN benchmark + inquiry form
- **coming_soon**: purpose-forward page with related links and live alternatives
- **redirect**: hard redirect to canonical destination

## Public endpoints

- `GET /health`
- `GET /ecosystem` — full domain map grouped by pillar/status
- `GET /api/domains[?host=<domain>]` — ecosystem/domain metadata JSON
- `POST /api/inquiries` — submit offer/inquiry
- `POST /api/track` — lightweight click/CTA tracking beacon

## Admin endpoints

Require: `Authorization: Bearer <ADMIN_TOKEN>`

- `GET /api/inquiries?domain=clawinsure.com&limit=100`
- `GET /api/analytics` (D1 inquiry summary)

## Analytics dataset

Analytics Engine dataset: `claw_domain_visits`

Current event schema (`services/claw-domains/src/analytics.ts`):
- `blob1` hostname
- `blob2` path+query
- `blob3` referrer domain
- `blob4` country
- `blob5` action (`pageview`, `inquiry`, `offer`, `*_click`)
- `blob6` context (`label`, `target`, UA snippet)
- `double2` numeric value (offer amount, if present)
- `index1` pseudo visitor hash

Query script:

```bash
CF_API_TOKEN=... CF_ACCOUNT_ID=... node scripts/query-analytics.mjs
CF_API_TOKEN=... CF_ACCOUNT_ID=... node scripts/query-analytics.mjs --days 7 --domain clawinsure.com
```

DNS demand script:

```bash
CF_API_TOKEN=... node scripts/query-dns.mjs --days 7
```

## Deploy

```bash
cd services/claw-domains
npm install
npm run typecheck
npm run deploy
# or staging
npm run deploy:staging
```

## D1 migrations

```bash
wrangler d1 migrations apply claw-domains --remote
wrangler d1 migrations apply claw-domains-staging --env staging --remote
```
