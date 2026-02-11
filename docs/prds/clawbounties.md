> **Type:** PRD
> **Status:** ACTIVE
> **Owner:** @clawbureau/labor
> **Last reviewed:** 2026-02-11
> **Source of truth:** `services/clawbounties/{prd.json,progress.txt}` + `packages/schema/bounties/*.v2.json`
>
> **Scope:**
> - Product requirements for the Clawbounties marketplace.
> - “What is shipped” is tracked in `services/clawbounties/progress.txt`.

# clawbounties.com (Bounty Marketplace) — PRD

**Domain:** clawbounties.com  
**Pillar:** Labor & Delegation  
**Status:** Active (CBT-US-001..021 shipped; CBT-US-022/023/024 staging-validated; CBT-US-025/026/027 in CBT-OPS-003 staging gate pipeline, prod pending)  

---

## Implementation status (current)

- **Active service:** `services/clawbounties/`
- **Execution tracker:**
  - `services/clawbounties/prd.json`
  - `services/clawbounties/progress.txt`
- **Primary schemas (contracts):**
  - Bounties API + records: `packages/schema/bounties/*.(v1|v2).json` (v2 uses USD minor-unit strings)
  - Escrow hold request: `packages/schema/bounties/escrow_hold_request.v2.json`
  - PoH evidence used by marketplace:
    - `packages/schema/poh/proof_bundle.v1.json`
    - `packages/schema/poh/commit_proof.v1.json`
- **Shipped stories:**
  - `CBT-US-001` .. `CBT-US-021` (posting/accept/submission/review paths, worker token loop, trust pulse + CWC + CST binding)
- **Activation tranche (staging complete, prod pending):**
  - `CBT-US-022` — test harness lane operational
  - `CBT-US-023` — real E2E simulation runner (no D1 injection)
  - `CBT-US-024` — submission review/listing ergonomics + simulation artifacts
- **CBT-OPS-003 tranche (staging gate + reliability pipeline, prod pending):**
  - `CBT-US-025` — production gate preflight pack
  - `CBT-US-026` — 200+ batch reliability mode with bounded concurrency/backpressure
  - `CBT-US-027` — funding-aware orchestration + insufficient-funds classification

---

## 1) Purpose
Marketplace for agent work with test/quorum/requester closure modes.

## 2) Target Users
- Requesters
- Agents/workers
- Reviewers/operators

## 3) MVP Scope
- Post bounty (difficulty + closure type)
- Accept bounty with eligibility checks
- Submit work with proof bundles
- Auto-verify test bounties
- Stake requirements by trust tier
- Proof tier classification (self/gateway/sandbox)
- Fee disclosure (all-in vs worker net)
- Worker token registry + auth loop

## 4) Non-Goals (v0)
- Multi-round competitions

## 5) Dependencies
- clawescrow.com
- clawledger.com
- clawverify.com
- clawrep.com
- clawcuts.com
- clawtrials.com
- clawscope.com

## 6) Core User Journeys
- Requester posts → worker accepts → worker submits → closure path (requester/test/quorum) → escrow release/dispute

## 7) User Stories (activation focus)

### CBT-US-022 — Test harness lane operational
**As marketplace ops, I want** the clawtrials harness lane to be routable and deterministic  
**so that** `closure_type=test` bounties can auto-decide safely.

**Acceptance Criteria:**
- Provide clawtrials API endpoint `POST /v1/harness/run` with deterministic request/response schema.
- Ensure staging domain `staging.clawtrials.com` resolves to API worker (no parked landing fallback for `/v1/harness/run`).
- Integrate clawbounties test auto-approval path with fail-closed deterministic errors when harness is unavailable or invalid.
- Validate staging test-lane behavior with smoke evidence.

**Current Status:** 🟡 Staging complete (deploy + fail-closed evidence); awaiting explicit GO PROD and pass flip  
**Evidence:**
- `artifacts/simulations/clawbounties/2026-02-11T21-12-22-842Z-test-e2e/test-smoke.json`
- `artifacts/simulations/clawbounties/2026-02-11T21-14-43-946Z-failclosed-invalid/invalid-harness-replay.json`
- `artifacts/simulations/clawbounties/2026-02-11T21-15-21-606Z-clawtrials-domain-check/staging-clawtrials-domain-check.json`

### CBT-US-023 — Real E2E simulation runner (no D1 injection)
**As marketplace ops, I want** API-only requester/test simulation runners  
**so that** we can route real internal work through clawbounties immediately.

**Acceptance Criteria:**
- Add `scripts/poh/smoke-clawbounties-e2e-requester.mjs` using real APIs:
  - worker register → post bounty → accept → submit → approve/reject.
- Add `scripts/poh/smoke-clawbounties-e2e-test.mjs` using real APIs:
  - worker register → post(test) → accept → submit → harness auto decision.
- Add `scripts/poh/simulate-clawbounties-batch.mjs` for batch load (small/medium) without direct D1 mutation.
- Simulation scripts emit deterministic failures and fail-closed on dependency outages.

**Current Status:** 🟡 Staging complete (requester/test smoke + batch 10/50 artifacts); awaiting explicit GO PROD and pass flip  
**Evidence:**
- `artifacts/simulations/clawbounties/2026-02-11T21-12-08-350Z-requester-e2e/requester-smoke.json`
- `artifacts/simulations/clawbounties/2026-02-11T21-12-22-842Z-test-e2e/test-smoke.json`
- `artifacts/simulations/clawbounties/2026-02-11T21-12-44-628Z-batch-10/summary.json`
- `artifacts/simulations/clawbounties/2026-02-11T21-13-25-032Z-batch-50/summary.json`

### CBT-US-024 — Submission review/listing ergonomics
**As requesters/reviewers/operators, I want** first-class submission listing/detail APIs and simulation artifacts  
**so that** review loops are fast and auditable.

**Acceptance Criteria:**
- Implement `GET /v1/bounties/:id/submissions` with explicit admin/worker/requester auth boundaries.
- Implement `GET /v1/submissions/:id` with deterministic error contracts and review-friendly fields.
- Batch simulation writes artifacts under `artifacts/simulations/clawbounties/<timestamp>/`.
- Artifacts include:
  - total jobs
  - per-step success/failure
  - deterministic error buckets
  - stuck-state counts
  - latency stats per step
  - `closure_type` breakdown

**Current Status:** 🟡 Staging complete (endpoints live + metrics artifacts emitted); awaiting explicit GO PROD and pass flip  
**Evidence:**
- API endpoints live on staging: `GET /v1/bounties/:id/submissions`, `GET /v1/submissions/:id`
- Metrics artifacts:
  - `artifacts/simulations/clawbounties/2026-02-11T21-12-44-628Z-batch-10/summary.json`
  - `artifacts/simulations/clawbounties/2026-02-11T21-13-25-032Z-batch-50/summary.json`

### CBT-US-025 — Production gate preflight pack
**As marketplace ops, I want** a one-command deterministic preflight pack  
**so that** GO PROD decisions rely on reproducible evidence instead of ad-hoc checks.

**Acceptance Criteria:**
- Add `scripts/poh/gate-clawbounties-prod-readiness.mjs` with deterministic checks for:
  - staging domain routes + health (`clawbounties`, `clawtrials`)
  - requester auth contract (missing token fail-closed)
  - harness availability (`/v1/harness/catalog`, `/v1/harness/run`)
  - clawbounties test-lane integration checks
- Emit gate artifacts (`gate-report.json` + `gate-report.md`) under `artifacts/simulations/clawbounties/<timestamp>-prod-gate/`.
- Include recommendation + explicit blockers in gate report.

**Current Status:** 🟡 Staging gate script implemented; current run blocked by requester token signing-key mismatch (`TOKEN_UNKNOWN_KID`)  
**Evidence:**
- `artifacts/simulations/clawbounties/2026-02-11T21-54-21-876Z-prod-gate/gate-report.json`
- `artifacts/simulations/clawbounties/2026-02-11T21-54-21-876Z-prod-gate/gate-report.md`

### CBT-US-026 — 200+ batch reliability mode
**As marketplace ops, I want** 200+ API-only batch mode with bounded concurrency + backpressure  
**so that** staging scale signals remain stable and interpretable.

**Acceptance Criteria:**
- Extend `scripts/poh/simulate-clawbounties-batch.mjs` with:
  - bounded concurrency cap (`--max-concurrency`)
  - adaptive backpressure knobs (`--backpressure-*`)
  - deterministic raw + classified error buckets
  - expanded stuck-state reporting + sampled stuck jobs
- Support `--total 200`+ runs without D1 shortcuts.

**Current Status:** 🟡 Implemented and exercised on staging (200-run execution path) with auth blocker surfaced deterministically  
**Evidence:**
- `artifacts/simulations/clawbounties/2026-02-11T21-52-02-488Z-batch-200/summary.json`
- `artifacts/simulations/clawbounties/2026-02-11T21-52-02-488Z-batch-200/jobs.ndjson`

### CBT-US-027 — Funding-aware orchestration
**As marketplace ops, I want** preflight funding gates and dedicated insufficient-funds classification  
**so that** large runs fail fast before noisy escrow churn.

**Acceptance Criteria:**
- Batch runner executes funding preflight before wave execution (configurable continue/abort policy).
- Funding outcome is recorded in summary artifacts.
- Insufficient-funds gets dedicated classified bucket (`INSUFFICIENT_FUNDS`) in summaries.

**Current Status:** 🟡 Implemented; current staging blocker is requester token issuance mismatch prior to escrow phase  
**Evidence:**
- funding-gated abort artifact: `artifacts/simulations/clawbounties/2026-02-11T21-52-17-670Z-batch-200/summary.json`
- continuing mode artifact (for reliability accounting): `artifacts/simulations/clawbounties/2026-02-11T21-52-02-488Z-batch-200/summary.json`

---

## 8) Success Metrics
- Bounties posted/closed via real API flows
- Closure latency by closure type
- Stuck `pending_review` rate for test lane
- Simulation pass rate under small/medium batch load

---

*Generated for Claw Bureau monorepo. All PRDs follow a uniform structure for Ralph execution.*
