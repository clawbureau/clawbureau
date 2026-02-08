# claw-domains

Multi-domain landing page & inquiry capture for parked Claw Bureau domains.

One Worker serves **20 domains** with two page types:
- **For-sale** (5 domains) — branded "available" page + BIN price + offer form
- **Coming-soon** (15 domains) — ecosystem holding page linking to clawbureau.com

## Live domains

### For sale
| Domain | BIN Price | URL |
|--------|----------|-----|
| clawinsure.com | $79,000 | https://clawinsure.com |
| clawsettle.com | $59,000 | https://clawsettle.com |
| clawportfolio.com | $39,000 | https://clawportfolio.com |
| clawadvisory.com | $29,000 | https://clawadvisory.com |
| clawcareers.com | $24,000 | https://clawcareers.com |

### Coming soon
clawrep · clawsig · clawea · clawsilo · clawdelegate · clawintel · clawtrials · clawcontrols · clawmanage · clawlogs · clawforhire · clawsupply · clawincome · clawgrant · clawgang

### Known issue
`clawmerch.com` — Cloudflare Registrar parking override (172.16.16.16). Needs manual fix in CF dashboard.

## Infrastructure

- **Worker:** `claw-domains` (Cloudflare Workers)
- **D1:** `claw-domains` (inquiry storage)
- **Analytics Engine:** `claw_domain_visits` (cross-domain visit tracking)
- **SSL:** Full mode + Universal SSL + Always-Use-HTTPS on all 21 zones

## API

### Public
- `GET /health` — health check
- `POST /api/inquiries` — submit an offer/inquiry (from landing page form)

### Admin (requires `Authorization: Bearer <ADMIN_TOKEN>`)
- `GET /api/inquiries?domain=clawinsure.com&limit=100` — list inquiries
- `GET /api/analytics` — cross-domain inquiry summary

Admin token: `~/.clawbureau-secrets/claw_domains_admin_token.txt`

## Analytics scripts

```bash
# Cross-domain visit analytics (requires CF API token with Analytics Engine read)
CF_API_TOKEN=... node scripts/query-analytics.mjs
CF_API_TOKEN=... node scripts/query-analytics.mjs --days 7 --domain clawinsure.com

# DNS query volume across all claw* zones
CF_API_TOKEN=... node scripts/query-dns.mjs
CF_API_TOKEN=... node scripts/query-dns.mjs --days 7
```

## Config

Domain config lives in `src/config.ts`. To change pricing, add/remove domains, or switch modes, edit the config and redeploy:

```bash
cd monorepo/services/claw-domains
npx wrangler deploy
```

## D1 migrations

```bash
wrangler d1 migrations apply claw-domains --remote
```
