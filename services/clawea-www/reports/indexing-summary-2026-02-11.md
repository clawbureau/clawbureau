# clawea.com Indexing Reliability Summary — 2026-02-11

Run artifact: `articles/_indexing_runs/2026-02-11-bofu-index-only-03.json`

## Outcome
- requested URLs: 118
- submitted URLs: 0
- failed URLs: 118
- retried batches: 6
- total retry attempts: 18

## Failure mode
- IndexNow: `429 TooManyRequests` (persistent across retries)
- Google Indexing API: per-URL `429 RESOURCE_EXHAUSTED` (daily quota exhausted)

## Queue + replay
- Failure queue written to: `articles/_indexing_failures.json`
- Replay command:
  - `npm run index:replay`
  - or `npx tsx scripts/upload-to-r2.ts --auto-index --replay-failures articles/_indexing_failures.json`

## Reliability features now active
- Exponential backoff + retry for indexing batch submissions
- Deterministic per-run artifact with requested/submitted/failed/retried fields
- Structured failure queue artifact for replay
- Replay mode to process only failed URLs
