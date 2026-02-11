# clawea.com Weekly Growth Report — 2026-02-11

## Scope covered
- M1 marketing growth execution in `services/clawea-www`
- Manifest-safe BOFU content expansion
- Indexing reliability hardening (retry/backoff + failure queue + replay)
- Conversion instrumentation and weekly telemetry summary

## 1) Indexed / indexing pipeline status
- Core sitemap pages currently publishable: **117**
- New BOFU tool pages shipped this week: **21**
- Latest indexing run artifact:
  - `articles/_indexing_runs/2026-02-11-bofu-index-only-03.json`
  - requested URLs: **118**
  - submitted URLs: **0**
  - failed URLs: **118**
  - retried batches: **6**
  - retry attempts: **18**
- Failure queue artifact:
  - `articles/_indexing_failures.json`
  - pending URLs: **118**

### Engine-level reality (from latest run)
- IndexNow: persistent `429 TooManyRequests`
- Google Indexing API: `429 RESOURCE_EXHAUSTED` (daily publish quota exceeded)

## 2) Query / CTR status
- Query and CTR signals are not yet representative for this batch (fresh publication window).
- Current decision: treat this week as baseline collection.
- Next pull source: GSC performance export after quota reset + crawl/index delay.

## 3) Conversion status
- Conversion telemetry is now live (`/api/events` + `/api/events/summary`).
- Weekly summary artifact:
  - `reports/conversion/weekly-2026-02-11.json`
  - `reports/conversion/weekly-2026-02-11.md`
- Current baseline snapshot:
  - total events: **1** (smoke)
  - contact intent views: **0**
  - contact intent actions: **0**
  - intent-to-action rate: **0**

## 4) Content refresh + publishing actions
Completed:
- Added 21 BOFU tool pages under `/tools/*` with strict fail-closed promotion gates.
- Injected strong trust/conversion endcaps during promotion:
  - CTA to `/contact`
  - Trust proof CTA to `/trust`

Immediate next actions:
1. Replay pending queue after Google daily quota reset (`npm run index:replay`).
2. Split replay into smaller slices to avoid repeated IndexNow lockouts.
3. Add quota-aware engine mode (auto-fallback to Google-only or IndexNow-only based on current failure class).
4. Pull first non-smoke conversion week after real traffic accrues.
5. Pull first GSC query/CTR sample for new BOFU pages and rank pages by impressions for refresh wave.
