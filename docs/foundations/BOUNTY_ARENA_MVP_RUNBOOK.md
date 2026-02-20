> **Type:** Runbook
> **Status:** ACTIVE
> **Owner:** @clawbureau/marketplace + @clawbureau/clawsig
> **Last reviewed:** 2026-02-20
> **Scope:** Bounty Arena MVP (AGP-US-031..070)

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
- AGP-US-053 — real contender dispatch orchestrator
  - merge: pending
- AGP-US-054 — reviewer truth-capture normalization
  - merge: pending
- AGP-US-055 — route policy optimizer shadow/promote
  - merge: pending
- AGP-US-056 — contract copilot from real failures
  - merge: pending
- AGP-US-057 — arena ROI dashboard from real metrics
  - merge: pending
- AGP-US-058 — harness fleet identity + capability control
  - merge: pending

## 2. Key files

### Arena generators
- `scripts/arena/run-bounty-arena.mjs`
- `scripts/arena/run-real-contender-dispatch.mjs`
- `scripts/arena/lib/arena-runner.mjs`
- `scripts/arena/lib/proof-pack-v3.mjs`
- `scripts/arena/generate-policy-learning-report.mjs`
- `scripts/arena/run-policy-optimizer-shadow.mjs`
- `scripts/arena/run-contract-copilot-from-outcomes.mjs`
- `scripts/arena/run-roi-dashboard-report.mjs`
- `scripts/arena/register-harness-fleet-workers.mjs`
- `scripts/arena/generate-contract-language-optimizer.mjs`
- `scripts/arena/run-historical-backtest.mjs`
- `scripts/arena/run-autonomous-discovery-loop.mjs`
- `scripts/arena/run-autonomous-decision-loop.mjs`
- `scripts/arena/run-autonomous-desk-cycle.mjs`
- `scripts/arena/run-ui-duel-evaluator.mjs`

### Real contender dispatch config
- `contracts/arena/real-contender-dispatch.sample.v1.json`
- `contracts/arena/policy-optimizer.sample.v1.json`
- `contracts/arena/contract-copilot.sample.v1.json`
- `contracts/arena/harness-fleet-worker.sample.v1.json`
- `contracts/arena/autonomous-discovery-loop.sample.v1.json`
- `contracts/arena/autonomous-decision-loop.sample.v1.json`
- `contracts/arena/autonomous-desk-cycle.sample.v1.json`
- `contracts/arena/bounty-ui-duel.clawbounties.v1.json`

### Arena schemas
- `packages/schema/arena/proof_pack.v3.json`
- `packages/schema/arena/manager_review.v1.json`
- `packages/schema/arena/arena_report.v1.json`

### Arena persistence / APIs
- `services/_archived/clawbounties/migrations/0019_bounty_arena_runs.sql`
- `services/_archived/clawbounties/migrations/0022_bounty_arena_live_lifecycle.sql`
- `services/_archived/clawbounties/migrations/0023_arena_outcome_override_reasons.sql`
- `services/_archived/clawbounties/migrations/0024_arena_contender_registry_pins.sql`
- `services/_archived/clawbounties/migrations/0025_arena_contract_language_optimizer.sql`
- `services/_archived/clawbounties/migrations/0026_arena_reviewer_decision_capture.sql`
- `services/_archived/clawbounties/migrations/0027_arena_route_policy_optimizer_state.sql`
- `services/_archived/clawbounties/migrations/0028_arena_contract_copilot_suggestions.sql`
- `services/_archived/clawbounties/migrations/0029_arena_harness_fleet_registry.sql`
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
- `POST /v1/arena/manager/autopilot` (admin)

### Harness fleet control API
- `POST /v1/arena/fleet/workers/register` (admin)
  - upserts fleet worker identity/capability profile + optional heartbeat touch
- `POST /v1/arena/fleet/workers/heartbeat` (admin)
  - updates live availability state and heartbeat sequence
- `GET /v1/arena/fleet/workers` (admin)
  - lists discoverable fleet workers with capability/risk/cost filters
- `POST /v1/arena/fleet/match` (admin)
  - computes capability match candidates used by manager route/coach/autopilot payloads

### Autonomous desk control API
- `POST /v1/arena/desk/discover-loop` (admin)
  - computes live open-bounty desk posture and seeds additional requester-closure bounties when below target.
- `POST /v1/arena/desk/claim-loop` (admin)
  - claims open bounties with deterministic lock ledger + budget/cost/risk guardrails.
- `POST /v1/arena/desk/submit-loop` (admin)
  - executes/submits accepted bounties through conformance signer lane.
- `POST /v1/arena/desk/decision-loop` (admin)
  - applies deterministic approve/reject transitions for pending-review submissions using internal requester auth override.
- `GET /v1/arena/mission` (admin)
  - mission KPI posture snapshot.
- `POST /v1/arena/desk/kpi-gate` (admin)
  - enforceable KPI gate with fail-closed `409` on `enforce=true` + failure.
- `POST /v1/arena/desk/self-tune-rollout` (admin)
  - KPI-gated policy optimizer promotion path.

### Policy learning API
- `GET /v1/arena/policy-learning` (admin)
  - supports `task_fingerprint` and `limit`
  - returns override reason breakdown + contract/prompt rewrite recommendations
- `GET /v1/arena/roi-dashboard` (admin)
  - supports task/objective/contender/experiment filters + `min_samples`/`limit`
  - returns real persisted ROI metrics + 7d/30d trend windows + reason-code drilldowns
  - returns deterministic `INSUFFICIENT_SAMPLE` when sample gates are not met
- `POST /v1/arena/policy-optimizer` (admin)
  - body: `task_fingerprint`, optional `{objective_profile_name,experiment_id,experiment_arm,environment,max_runs,min_samples,min_confidence}`
  - computes real-data shadow policy from current route evidence and promotes to active only when gates pass
- `GET /v1/arena/policy-optimizer` (admin)
  - supports `task_fingerprint`, optional objective/experiment/environment filters
  - returns persisted shadow/active policy state + promotion event + deterministic reason codes
- `POST /v1/arena/contract-copilot/generate` (admin)
  - body: `task_fingerprint`, optional `{min_outcomes,min_arenas,max_suggestions,limit}`
  - computes copilot-grade before/after rewrites from real failed outcomes with source evidence traceability
  - returns deterministic `INSUFFICIENT_SAMPLE` when real sample gates are not met
- `GET /v1/arena/contract-copilot` (admin)
  - supports `task_fingerprint`, `contender_id`, `limit`
  - returns persisted copilot suggestions + evidence links
- `POST /v1/arena/contract-language-optimizer` (admin)
  - body: `task_fingerprint`, optional `limit`
  - computes + persists contract/prompt rewrite suggestions for failed/overridden outcomes
- `GET /v1/arena/contract-language-optimizer` (admin)
  - supports `task_fingerprint`, `contender_id`, `limit`
  - returns persisted optimizer suggestions

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
- `0024_arena_contender_registry_pins.sql`
- `0025_arena_contract_language_optimizer.sql`
- `0026_arena_reviewer_decision_capture.sql`
- `0027_arena_route_policy_optimizer_state.sql`
- `0028_arena_contract_copilot_suggestions.sql`
- `0029_arena_harness_fleet_registry.sql`

## 6. End-to-end operator flow

### Step A — Generate arena artifacts

```bash
# deterministic local arena generation (non-dispatch)
node scripts/arena/run-bounty-arena.mjs \
  --contract contracts/arena/bounty-contract.sample.v1.json \
  --contenders contracts/arena/contenders.sample.v1.json \
  --out artifacts/arena

# AGP-US-053 real contender dispatch (live command execution + API persistence)
node scripts/arena/run-real-contender-dispatch.mjs \
  --bounty-id bty_... \
  --contract contracts/arena/bounty-contract.sample.v1.json \
  --contenders contracts/arena/contenders.sample.v1.json \
  --dispatch-config contracts/arena/real-contender-dispatch.sample.v1.json \
  --registry contracts/arena/contender-registry.sample.v1.json \
  --experiment-id exp_api_hardening_live_v1 \
  --experiment-arm LIVE \
  --bounties-base https://staging.clawbounties.com
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

# AGP-US-058: register/heartbeat harness fleet workers
node scripts/arena/register-harness-fleet-workers.mjs \
  --workers contracts/arena/harness-fleet-workers.seed.v1.json \
  --bounties-base https://staging.clawbounties.com

# AGP-US-059: run auto bounty claim loop (idempotent lock + budget/risk/cost guards)
node scripts/arena/run-auto-bounty-grabber.mjs \
  --bounties-base https://staging.clawbounties.com \
  --target-claims 10 \
  --budget-minor 250000 \
  --max-fleet-cost-tier medium \
  --max-fleet-risk-tier medium

# AGP-US-060: run execution + submission autopilot from accepted claims
node scripts/arena/run-execution-submission-autopilot.mjs \
  --bounties-base https://staging.clawbounties.com \
  --worker-did did:key:z6MkneMkZqwqRiU5mJzSG3kDwzt9P8C59N4NGTfBLfSGE7c7 \
  --target-submissions 10 \
  --bounty-ids-file /tmp/agp060-stage-claimed-ids.txt

# AGP-US-061: mission control summary (API + Explorer)
node scripts/arena/run-mission-dashboard-report.mjs \
  --bounties-base https://staging.clawbounties.com \
  --worker-did did:key:z6MkneMkZqwqRiU5mJzSG3kDwzt9P8C59N4NGTfBLfSGE7c7 \
  --window-hours 24

# AGP-US-062: enforce KPI gates before autonomous rollout
node scripts/arena/run-mission-kpi-gates.mjs \
  --bounties-base https://staging.clawbounties.com \
  --window-hours 24 \
  --enforce

# AGP-US-063: self-tuning rollout (KPI-gated policy optimizer promotion)
node scripts/arena/run-self-tuning-rollout.mjs \
  --bounties-base https://staging.clawbounties.com \
  --task-fingerprint "typescript:worker:api-hardening" \
  --environment staging \
  --window-hours 24 \
  --min-samples 6 \
  --min-confidence 0.4 \
  --require-promotion

# AGP-US-064: autonomous discovery loop (seed open desk supply fail-closed)
node scripts/arena/run-autonomous-discovery-loop.mjs \
  --bounties-base https://staging.clawbounties.com \
  --target-open-bounties 25 \
  --seed-limit 25 \
  --seed-reward-minor 25

# AGP-US-067/068: autonomous review+accept decision loop (admin fail-closed path)
node scripts/arena/run-autonomous-decision-loop.mjs \
  --bounties-base https://staging.clawbounties.com \
  --decision-mode approve_valid \
  --target-decisions 15 \
  --require-claimed

# AGP-US-069: one-shot autonomous desk cycle (discover -> claim -> submit -> review/accept -> tune)
node scripts/arena/run-autonomous-desk-cycle.mjs \
  --bounties-base https://staging.clawbounties.com \
  --target-open-bounties 25 \
  --target-claims 15 \
  --target-submissions 15 \
  --target-decisions 15

# AGP-US-075: pending arena resolver loop (deterministic winner/unresolved closure)
node scripts/arena/run-autonomous-resolve-loop.mjs \
  --bounties-base https://staging.clawbounties.com \
  --limit 150 \
  --target-resolved 80 \
  --min-pending-age-minutes 30

# AGP-US-076: KPI gate recovery loop (claim/submission gap + gate enforce)
node scripts/arena/run-autonomous-kpi-recovery-loop.mjs \
  --bounties-base https://staging.clawbounties.com \
  --window-hours 24 \
  --limit 80

# AGP-US-070: UI duel evaluator (Playwright + Lighthouse + a11y hard gates)
node scripts/arena/run-ui-duel-evaluator.mjs \
  --base-url https://staging.clawbounties.com \
  --contender-id contender_gemini_3_1_pro_preview_pi \
  --admin-key "$BOUNTIES_ADMIN_KEY"

# AGP-US-055: compute shadow policy and promote active policy (fail-closed)
node scripts/arena/run-policy-optimizer-shadow.mjs \
  --task-fingerprint "typescript:worker:api-hardening" \
  --objective-profile-name balanced \
  --experiment-id exp_api_hardening_live_v1 \
  --experiment-arm LIVE \
  --environment staging \
  --bounties-base https://staging.clawbounties.com

# AGP-US-056: generate contract copilot suggestions from real outcomes
node scripts/arena/run-contract-copilot-from-outcomes.mjs \
  --task-fingerprint "typescript:worker:api-hardening" \
  --min-outcomes 10 \
  --min-arenas 3 \
  --bounties-base https://staging.clawbounties.com

# AGP-US-057: query ROI dashboard from persisted real outcomes
node scripts/arena/run-roi-dashboard-report.mjs \
  --task-fingerprint "typescript:worker:api-hardening" \
  --objective-profile-name balanced \
  --experiment-id exp_api_hardening_live_v1 \
  --experiment-arm LIVE \
  --bounties-base https://staging.clawbounties.com
```

### Step F — Explorer UI check

- `GET /arena`
- `GET /arena/mission`
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

# Compute + persist contract/prompt rewrite suggestions:
node scripts/arena/generate-contract-language-optimizer.mjs \
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

### Reviewer decision capture + override taxonomy (AGP-US-050)

`arena_review_flow` now includes `decision_capture` in submission review APIs:
- `GET /v1/bounties/{bounty_id}/submissions`
- `GET /v1/submissions/{submission_id}`

`decision_capture` payload contracts:
- `outcome_endpoint.payload_template` (ready-to-send body for `POST /v1/bounties/{bounty_id}/arena/outcome`)
- `outcome_status_options` (including `requires_override_reason` flags)
- `override_reason_options` (weight + rewrite hints from override taxonomy)
- `calibration_bindings` (deterministic payload paths for rationale and override reason)

Calibration outputs now surface rationale/taxonomy signals:
- `override_taxonomy.reason_breakdown`
- `rationale_signals.top_tags`
- `rationale_signals.recent_decisions`

Rollout evidence (AGP-US-050):
- staging deploy: `clawbounties-staging` `7d0a2571-25a9-4e74-9cbb-ac212d4e47eb`
- production deploy: `clawbounties` `77e7a2fd-cb0c-4402-b5f4-cddfe00be535`
- seeded runs: `arena_bty_5c048032_stage_050_001`, `arena_bty_836a4e15_prod_050_001`
- evidence summary: `artifacts/ops/arena-productization/2026-02-19T21-24-53Z-agp-us-050-decision-capture/summary.json`

### Routing policy autopilot + explorer panel (AGP-US-051)

Added manager autopilot endpoint:
- `POST /v1/arena/manager/autopilot` (admin)

Behavior:
- wraps manager-route ranking output
- applies deterministic guardrails (run count, winner stability, win-rate, override/rework rates, calibration gap, hard-gate stability)
- emits `arena_manager_autopilot.v1` payload with violations + policy template scaffold

Arena detail payload now includes `autopilot` preview (`arena_autopilot_preview.v1`) for UI surfacing.

Explorer now renders a **Routing autopilot** panel on arena pages.

Rollout evidence (AGP-US-051):
- staging deploys: `clawbounties-staging` `678d049e-9586-4963-8aca-94301c0db094`, `clawsig-explorer-staging` `c6260209-dfd1-492f-94b1-338ed6f731ca`
- production deploys: `clawbounties` `950b78b8-2ce8-42af-8375-a917a3f0c23f`, `clawsig-explorer` `d520225a-8c90-4757-959b-a95ec482b90e`
- evidence summary: `artifacts/ops/arena-productization/2026-02-19T21-39-33Z-agp-us-051-routing-autopilot/summary.json`

### Contract language optimizer + persisted rewrite store (AGP-US-052)

Added migration:
- `services/_archived/clawbounties/migrations/0025_arena_contract_language_optimizer.sql`

Added API endpoints:
- `POST /v1/arena/contract-language-optimizer` (admin) — compute + persist suggestions for a task fingerprint
- `GET /v1/arena/contract-language-optimizer` (admin) — list persisted suggestions

Optimizer behavior:
- learns from failed/overridden outcomes
- derives reason-code-specific contract + prompt rewrites
- persists deterministic suggestions keyed by task fingerprint/scope/reason code
- surfaces preview in `GET /v1/arena/{arena_id}` as `contract_language_optimizer`

Explorer now renders a **Contract language optimizer** card on arena pages.

Rollout evidence (AGP-US-052):
- staging deploys: `clawbounties-staging` `9a6ff198-c9d2-456e-8bb6-e773083e3da8`, `clawsig-explorer-staging` `a0d7858e-eec0-464b-b35d-fb328a28dc5b`
- production deploys: `clawbounties` `8621dc5a-8b64-47ba-9e5f-cd0749d6d80b`, `clawsig-explorer` `47012fb3-affe-4fd0-abcb-e99e88e24613`
- optimizer API checks: stage/prod `POST /v1/arena/contract-language-optimizer` => `200` with persisted rows
- fail-closed route check preserved: arm `B` => `200`, arm `A` => `404 ARENA_ROUTE_NOT_FOUND`
- evidence summary: `artifacts/ops/arena-productization/2026-02-19T22-00-09Z-agp-us-052-contract-language-optimizer/summary.json`

### Real contender dispatch orchestrator + real-data bootstrap (AGP-US-053)

Added dispatch runner:
- `scripts/arena/run-real-contender-dispatch.mjs`

Dispatch guarantees:
- executes real contender command plans per contender stack
- derives runtime signals from actual execution (`latency_ms`, `retries`, `tool_calls`)
- emits fail-closed error if required evidence categories (typecheck/test + artifacts) are missing
- forwards generated contender evidence into live arena start/result/review thread APIs

Phase-0 real-data bootstrap completed using live bounties:
- staging bounties: `bty_5c048032-1c54-4db5-947e-b82f68ddaa96`, `bty_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaab`
- production bounty: `bty_bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb`
- completed arenas with >=3 contenders each:
  - `arena_bty_5c048032_stage_053_002`
  - `arena_bty_aaaaaaaa_stage_053_002`
  - `arena_bty_bbbbbbbb_prod_053_002`

Gate checks passed:
- `GET /v1/arena` non-empty
- `GET /v1/arena/calibration` non-empty
- `GET /v1/arena/{arena_id}/outcomes` non-empty (staging)
- manager route/autopilot endpoints return deterministic `200` responses for LIVE-arm real records

Rollout evidence (AGP-US-053):
- evidence summary: `artifacts/ops/arena-productization/2026-02-19T22-43-56Z-agp-us-053-real-dispatch/summary.json`

### Reviewer truth-capture normalization (AGP-US-054)

Added migration:
- `services/_archived/clawbounties/migrations/0026_arena_reviewer_decision_capture.sql`

Normalized outcome decision capture now persists and returns:
- `reviewer_decision` (`approve|request_changes|reject`)
- `rework_required`
- `reviewer_rationale`
- `decision_taxonomy_tags`

Calibration payload adds first-class reviewer decision/taxonomy analytics:
- `totals.reviewer_decisions`
- `reviewer_decision_capture.decision_breakdown`
- `reviewer_decision_capture.decision_taxonomy_tags`

Bounty review decision-capture templates now include:
- `reviewer_decision_options`
- calibration bindings for `reviewer_decision`, `reviewer_rationale`, and `decision_taxonomy_tags`

Explorer arena page now renders:
- reviewer decision fields in outcome feed
- reviewer decision totals + top decision taxonomy tags in calibration card

Rollout evidence (AGP-US-054):
- staging deploys: `clawbounties-staging` `b0c97528-c4a7-424d-9ccc-22d2d414a8dd`, `clawsig-explorer-staging` `5b12ad50-94b8-4cf6-a4c4-f0e3eb4dacf5`
- production deploys: `clawbounties` `286ee311-268b-464d-9d1f-877f2c41cdb1`, `clawsig-explorer` `1794a3a6-5ba1-4240-aee9-f48304f1f9c8`
- real reviewer-event gate: 10/10 structured events persisted with taxonomy tags populated
- evidence summary: `artifacts/ops/arena-productization/2026-02-19T23-19-37Z-agp-us-054-reviewer-truth-capture/summary.json`

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
