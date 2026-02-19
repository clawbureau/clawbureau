> **Type:** Runbook
> **Status:** ACTIVE
> **Owner:** @clawbureau/marketplace + @clawbureau/clawsig
> **Last reviewed:** 2026-02-19
> **Scope:** Bounty Arena MVP (AGP-US-031..046)

# Bounty Arena MVP Runbook

This runbook covers the end-to-end operator workflow for Bounty Arena:

1) Generate deterministic contender artifacts
2) Persist arena start + result in clawbounties
3) Inspect compare UI in clawsig-explorer
4) Route future delegation using manager routing API

## 1. Delivered stories (merge commits)

- AGP-US-031 — proof-pack v3 + review artifacts
  - merge: `ad77a35964e844550b048fe6600e8b1c894b2da5`
- AGP-US-032 — arena runner + deterministic scoring
  - merge: `1f4b9f19b3b412731044b246b7fa3f6f142b28d6`
- AGP-US-033 — explorer compare UI
  - merge: `b0500342d8b5cc49b1ad0a992a49e214750bacce`
- AGP-US-034 — clawbounties arena integration
  - merge: `f16c80e8b48c445db291ffd4721cfaf8cb51496e`
- AGP-US-035 — delegation insights
  - merge: `fa38dc5b99b0d5a7760d066fe56697fa807317ab`
- AGP-US-036 — manager routing API
  - merge: `100b0ba19b32ce8d2eef10424e23293b1eb78bbe`
- AGP-US-043 — live bounty-triggered arena lifecycle persistence
  - merge: pending
- AGP-US-044 — decision paste autopost (PR comment + bounty review thread)
  - merge: pending
- AGP-US-045 — override-driven policy learning + routing feedback loop
  - merge: pending
- AGP-US-046 — historical backtesting + calibration drift analytics
  - merge: pending

## 2. Key files

### Arena generators
- `scripts/arena/run-bounty-arena.mjs`
- `scripts/arena/lib/arena-runner.mjs`
- `scripts/arena/lib/proof-pack-v3.mjs`
- `scripts/arena/generate-policy-learning-report.mjs`
- `scripts/arena/run-historical-backtest.mjs`

### Arena schemas
- `packages/schema/arena/proof_pack.v3.json`
- `packages/schema/arena/manager_review.v1.json`
- `packages/schema/arena/arena_report.v1.json`

### Arena persistence / APIs
- `services/_archived/clawbounties/migrations/0019_bounty_arena_runs.sql`
- `services/_archived/clawbounties/migrations/0022_bounty_arena_live_lifecycle.sql`
- `services/_archived/clawbounties/migrations/0023_arena_outcome_override_reasons.sql`
- `services/_archived/clawbounties/src/index.ts`

### Explorer routes
- `services/clawsig-explorer/src/pages/arena.ts`
- `services/clawsig-explorer/src/index.ts`
- `services/clawsig-explorer/src/api.ts`

## 3. API contract (MVP)

### Arena lifecycle
- `POST /v1/bounties/{bounty_id}/arena/start` (admin)
- `POST /v1/bounties/{bounty_id}/arena/result` (admin)
- `GET /v1/bounties/{bounty_id}/arena`
- `GET /v1/arena`
- `GET /v1/arena/{arena_id}`
- `GET /v1/arena/{arena_id}/delegation-insights`

### Manager route API
- `POST /v1/arena/manager/route` (admin)
- `POST /v1/arena/manager/coach` (admin)

### Policy learning API
- `GET /v1/arena/policy-learning` (admin)
  - supports `task_fingerprint` and `limit`
  - returns override reason breakdown + contract/prompt rewrite recommendations

### Backtesting API
- `GET /v1/arena/backtesting` (admin)
  - supports `task_fingerprint` and `limit`
  - returns predicted-winner hit/miss metrics, calibration drift, and weight-update suggestions

### Existing reads now enriched
- `GET /v1/bounties/{bounty_id}` includes `arena` + `arena_lifecycle`
- `GET /v1/bounties/{bounty_id}/arena` includes `arena_lifecycle`
- `GET /v1/submissions/{submission_id}` includes `submission.arena`

### Live trigger behavior
- Valid work submission (`POST /v1/bounties/{bounty_id}/submit`) auto-creates a started arena run.
- Bounty row now persists deterministic lifecycle fields (`arena_status`, `arena_id`, winner + evidence links).

## 4. Data model

### `bounty_arena_runs`
Stores run-level contract binding + objective profile + winner/result metadata + idempotency keys.

### `bounty_arena_contenders`
Stores contender-level score/metrics/check matrix + proof pack JSON + manager review JSON + review paste.

## 5. Deployment steps (arena DB)

Run from `services/_archived/clawbounties`:

```bash
wrangler d1 migrations apply clawbounties-staging --env staging --remote
wrangler d1 migrations apply clawbounties --remote
```

Required migrations for Arena MVP:
- `0019_bounty_arena_runs.sql`
- `0022_bounty_arena_live_lifecycle.sql`
- `0023_arena_outcome_override_reasons.sql`

## 6. End-to-end operator flow

### Step A — Generate arena artifacts

```bash
node scripts/arena/run-bounty-arena.mjs \
  --contract contracts/arena/bounty-contract.sample.v1.json \
  --contenders contracts/arena/contenders.sample.v1.json \
  --out artifacts/arena
```

Expected output directory (example):
- `artifacts/arena/arena_bty_arena_001/arena-report.json`
- `artifacts/arena/arena_bty_arena_001/contenders/<id>/proof-pack.v3.json`
- `artifacts/arena/arena_bty_arena_001/contenders/<id>/manager-review.json`
- `artifacts/arena/arena_bty_arena_001/contenders/<id>/review-paste.md`

### Step B — Start run in clawbounties

```bash
curl -sS -X POST "$BOUNTIES_BASE/v1/bounties/$BOUNTY_ID/arena/start" \
  -H "x-admin-key: $BOUNTIES_ADMIN_KEY" \
  -H "content-type: application/json" \
  -d @arena-start.json | jq .
```

### Step C — Submit result payload

```bash
curl -sS -X POST "$BOUNTIES_BASE/v1/bounties/$BOUNTY_ID/arena/result" \
  -H "x-admin-key: $BOUNTIES_ADMIN_KEY" \
  -H "content-type: application/json" \
  -d @arena-result.json | jq .
```

### Step D — Validate read paths

```bash
curl -sS "$BOUNTIES_BASE/v1/arena" | jq .
curl -sS "$BOUNTIES_BASE/v1/arena/$ARENA_ID" | jq .
curl -sS "$BOUNTIES_BASE/v1/arena/$ARENA_ID/delegation-insights" | jq .
curl -sS "$BOUNTIES_BASE/v1/bounties/$BOUNTY_ID/arena" | jq .
```

### Step E — Manager routing recommendation

```bash
curl -sS -X POST "$BOUNTIES_BASE/v1/arena/manager/route" \
  -H "x-admin-key: $BOUNTIES_ADMIN_KEY" \
  -H "content-type: application/json" \
  -d '{
    "task_fingerprint": "typescript:worker:api-hardening",
    "objective_profile_name": "balanced",
    "require_hard_gate_pass": true,
    "allow_fallback": true,
    "max_runs": 50
  }' | jq .

# Coaching-enhanced route output:
curl -sS -X POST "$BOUNTIES_BASE/v1/arena/manager/coach" \
  -H "x-admin-key: $BOUNTIES_ADMIN_KEY" \
  -H "content-type: application/json" \
  -d '{
    "task_fingerprint": "typescript:worker:api-hardening",
    "objective_profile_name": "balanced"
  }' | jq .

# CLI helper:
node scripts/arena/get-manager-coach.mjs \
  --task-fingerprint "typescript:worker:api-hardening" \
  --objective-profile-name balanced \
  --mode coach
```

### Step F — Explorer UI check

- `GET /arena`
- `GET /arena/{arena_id}`

Explorer env wiring:
- `VAAS_API_BASE` (existing)
- `ARENA_API_BASE` (new; defaults to clawbounties domain)

### Step G — Real bounty launcher (one command)

Use the launcher to run arena + persist start/result against a real bounty id:

```bash
node scripts/arena/run-real-bounty-arena.mjs \
  --bounty-id bty_... \
  --contract contracts/arena/bounty-contract.sample.v1.json \
  --contenders contracts/arena/contenders.sample.v1.json \
  --bounties-base https://staging.clawbounties.com
```

Dry-run (generate artifacts only, no API writes):

```bash
node scripts/arena/run-real-bounty-arena.mjs \
  --bounty-id bty_... \
  --contract contracts/arena/bounty-contract.sample.v1.json \
  --contenders contracts/arena/contenders.sample.v1.json \
  --dry-run
```

### Step H — Decision paste autopost workflow (PR + bounty thread)

Create a decision paste for the winning contender and autopost it:

```bash
node scripts/arena/post-decision-paste.mjs \
  --arena-report artifacts/arena/<arena_id>/arena-report.json \
  --arena-base-url https://staging.clawsig-explorer.com \
  --pr-number 123 \
  --post-bounty-thread \
  --bounty-id bty_... \
  --bounties-base https://staging.clawbounties.com
```

`run-real-bounty-arena.mjs` now also autoposts by default:
- PR comment (when `--pr-number` is provided or discovered from contract metadata)
- bounty review thread (auto-posted from result ingestion, with fallback post if absent)

Decision paste markdown now includes:
- APPROVE / REQUEST_CHANGES / REJECT recommendation
- confidence
- manager summary (decision + metrics + failed checks)
- reason codes + evidence links
- one-click links (proof card, arena comparison, manager-review.json)

### Step I — Outcome feedback + calibration loop

Post real-world decision outcomes back into Arena calibration:

```bash
node scripts/arena/post-outcome-feedback.mjs \
  --bounty-id bty_... \
  --arena-id arena_... \
  --outcome-status ACCEPTED \
  --review-time-minutes 18 \
  --time-to-accept-minutes 55 \
  --bounties-base https://staging.clawbounties.com

# OVERRIDDEN outcomes now require explicit reason codes:
node scripts/arena/post-outcome-feedback.mjs \
  --bounty-id bty_... \
  --arena-id arena_... \
  --outcome-status OVERRIDDEN \
  --override-reason-code ARENA_OVERRIDE_POLICY_RISK \
  --review-time-minutes 27
```

Read calibration + policy-learning metrics:
- `GET /v1/arena/calibration`
- `GET /v1/arena/{arena_id}/outcomes`
- `GET /v1/arena/policy-learning?task_fingerprint=<...>`

Emit policy-learning artifacts:
```bash
node scripts/arena/generate-policy-learning-report.mjs \
  --task-fingerprint "typescript:worker:api-hardening" \
  --bounties-base https://staging.clawbounties.com

# Backtest historical winner accuracy + calibration drift:
node scripts/arena/run-historical-backtest.mjs \
  --task-fingerprint "typescript:worker:api-hardening" \
  --bounties-base https://staging.clawbounties.com
```

### Registry pins + experiment arm controls (AGP-US-047)

Migration:
- `services/_archived/clawbounties/migrations/0024_arena_contender_registry_pins.sql`

Dry-run with registry + explicit arm:
```bash
node scripts/arena/run-real-bounty-arena.mjs \
  --bounty-id bty_... \
  --contract contracts/arena/bounty-contract.sample.v1.json \
  --contenders contracts/arena/contenders.sample.v1.json \
  --registry contracts/arena/contender-registry.sample.v1.json \
  --experiment-id exp_api_hardening_ab_v1 \
  --experiment-arm B \
  --dry-run
```

`/v1/bounties/{bounty_id}/arena/start` now accepts optional context:
- `registry.registry_version`
- `registry.selected_contenders[]` (`contender_id`, `version_pin`)
- `experiment.experiment_id`
- `experiment.arm`

Routing can be filtered by experiment context:
- `POST /v1/arena/manager/route` with optional `experiment_id` and `experiment_arm`

### Live enablement + seeded adoption loop (AGP-US-048)

Apply migration + deploy staging:
```bash
cd services/_archived/clawbounties
wrangler d1 migrations apply clawbounties-staging --env staging --remote
wrangler deploy --env staging

cd ../../services/clawsig-explorer
wrangler deploy --env staging
```

Seed a real arena run with registry + experiment metadata:
```bash
node scripts/arena/run-real-bounty-arena.mjs \
  --bounty-id bty_... \
  --contract artifacts/ops/arena-productization/staging-contract-agp-us-048.json \
  --contenders contracts/arena/contenders.sample.v1.json \
  --registry contracts/arena/contender-registry.sample.v1.json \
  --experiment-id exp_api_hardening_ab_v1 \
  --experiment-arm B \
  --bounties-base https://staging.clawbounties.com
```

Validate manager route filtering by experiment arm:
```bash
curl -sS https://staging.clawbounties.com/v1/arena/manager/route \
  -H "Authorization: Bearer $BOUNTIES_ADMIN_KEY" \
  -H 'content-type: application/json' \
  -d '{"task_fingerprint":"typescript:worker:api-hardening","objective_profile_name":"balanced","experiment_id":"exp_api_hardening_ab_v1","experiment_arm":"B","max_runs":20}'

# Fail-closed arm with no matching run should return 404 ARENA_ROUTE_NOT_FOUND:
curl -sS https://staging.clawbounties.com/v1/arena/manager/route \
  -H "Authorization: Bearer $BOUNTIES_ADMIN_KEY" \
  -H 'content-type: application/json' \
  -d '{"task_fingerprint":"typescript:worker:api-hardening","objective_profile_name":"balanced","experiment_id":"exp_api_hardening_ab_v1","experiment_arm":"A","max_runs":20}'
```

If staging checks are green, repeat migration/deploy/seed/route checks on production.

### One-click arena start in bounty review flow (AGP-US-049)

Bounty submission read APIs now include `arena_review_flow`:
- `GET /v1/bounties/{bounty_id}/submissions`
- `GET /v1/submissions/{submission_id}`

`arena_review_flow.start_arena.payload_template` contains a ready-to-send `POST /v1/bounties/{bounty_id}/arena/start` payload.

`arena_review_flow.latest_arena` exposes inline winner + tradeoffs + winner confidence for review UX.

Arena auto-thread now includes direct links to contender artifacts:
- review paste anchor (`#review-paste-<contender_id>`)
- manager review anchor (`#manager-review-<contender_id>`)

Rollout evidence (AGP-US-049):
- staging deploys: `clawbounties-staging` `b080128b-b7dd-489c-9a8f-34f4fc9c7b46`, `clawsig-explorer-staging` `3bb8e443-27f3-4c33-ae8a-f8ecc4473900`
- production deploys: `clawbounties` `94e28319-4ede-4e54-8c81-f7abaffcbd05`, `clawsig-explorer` `19a3b700-620c-4a64-8e27-2aa2b05c5cd9`
- seeded runs: `arena_bty_aaaaaaaa_stage_seed_003`, `arena_bty_bbbbbbbb_prod_seed_003`
- evidence summary: `artifacts/ops/arena-productization/2026-02-19T21-00-00Z-agp-us-049-bounty-ui-one-click/summary.json`

## 7. Fail-closed behavior checklist

- Start/result idempotency conflicts return `409 IDEMPOTENCY_CONFLICT`
- Result without prior start returns `404 ARENA_RUN_NOT_STARTED`
- Result contract mismatch returns `409 ARENA_CONTRACT_MISMATCH`
- Manager route with no candidates returns `404 ARENA_ROUTE_NOT_FOUND`
- Manager route hard-gate block (fallback disabled) returns `409 ARENA_ROUTE_HARD_GATE_BLOCKED`

## 8. Required validation commands before merge

```bash
cd services/_archived/clawbounties && npm run typecheck
cd services/clawsig-explorer && npm run typecheck && npm test
cd services/clawsig-ledger && npm run typecheck && npm test
node scripts/docs/lint-prds.mjs
node scripts/protocol/run-clawsig-verified-pr.mjs
```

## 9. Artifact snippets (minimum)

### `arena-report.json`
Must include:
- `arena_id`
- `contract.bounty_id`
- `contract.contract_hash_b64u`
- `winner.contender_id`
- `reason_codes[]`

### `proof-pack.v3.json`
Must include:
- `claim_binding.contract_hash_b64u`
- `compliance.checks[]`
- `metrics.*`
- `insights.next_delegation_hints[]`

### `manager-review.json`
Must include:
- `decision`
- `confidence`
- `reason_codes[]`

## 10. Rollback guidance

If Arena routes must be disabled quickly:

1. Keep existing bounty/submission endpoints intact.
2. Block write paths first (`/arena/start`, `/arena/result`) via service hotfix.
3. Leave read endpoints up if payload integrity is intact.
4. If integrity issue is detected, return deterministic `DATA_INTEGRITY_ERROR` from read endpoints.
5. Do not delete D1 rows without explicit incident approval.
