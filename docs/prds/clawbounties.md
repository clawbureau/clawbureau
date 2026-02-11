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
**Status:** Active (CBT-US-001..030 shipped with staging+prod evidence; CBT-OPS-004 productionized)  

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
- **Activation tranche (production complete):**
  - `CBT-US-022` — test harness lane operational (staging + prod)
  - `CBT-US-023` — real E2E simulation runner (no D1 injection)
  - `CBT-US-024` — submission review/listing ergonomics + simulation artifacts
- **CBT-OPS-003 tranche (production complete):**
  - `CBT-US-025` — production gate preflight pack
  - `CBT-US-026` — 200+ batch reliability mode with bounded concurrency/backpressure
  - `CBT-US-027` — funding-aware orchestration + insufficient-funds classification
- **CBT-OPS-004 tranche (production complete):**
  - `CBT-US-028` — identity control-plane contract assimilation
  - `CBT-US-029` — sensitive transition enforcement hardening
  - `CBT-US-030` — API-only simulation discipline for control-plane lane

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

**Current Status:** ✅ Production complete (staging + prod routed and validated).  
**Evidence:**
- Staging gate + harness integration:
  - `artifacts/simulations/clawbounties/2026-02-11T22-14-08-561Z-prod-gate/gate-report.json`
- Production gate + deterministic replay:
  - `artifacts/simulations/clawbounties/2026-02-11T22-23-53-242Z-prod-gate/gate-report.json`
- Production test-lane E2E:
  - `artifacts/simulations/clawbounties/2026-02-11T22-21-49-713Z-test-e2e/test-smoke.json`

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

**Current Status:** ✅ Production complete (API-only flows validated on staging and prod).  
**Evidence:**
- Staging requester/test smoke:
  - `artifacts/simulations/clawbounties/2026-02-11T22-14-52-117Z-requester-e2e/requester-smoke.json`
  - `artifacts/simulations/clawbounties/2026-02-11T22-14-58-203Z-test-e2e/test-smoke.json`
- Production requester/test smoke:
  - `artifacts/simulations/clawbounties/2026-02-11T22-20-53-579Z-requester-e2e/requester-smoke.json`
  - `artifacts/simulations/clawbounties/2026-02-11T22-21-49-713Z-test-e2e/test-smoke.json`
- Production batch smoke:
  - `artifacts/simulations/clawbounties/2026-02-11T22-22-07-779Z-batch-10/summary.json`
  - `artifacts/simulations/clawbounties/2026-02-11T22-22-33-468Z-batch-50/summary.json`

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

**Current Status:** ✅ Production complete (review/list endpoints exercised in requester/worker loops).  
**Evidence:**
- Endpoints exercised in production smoke loops:
  - `GET /v1/bounties/:id/submissions`
  - `GET /v1/submissions/:id`
- Production metrics artifacts:
  - `artifacts/simulations/clawbounties/2026-02-11T22-22-07-779Z-batch-10/summary.json`
  - `artifacts/simulations/clawbounties/2026-02-11T22-22-33-468Z-batch-50/summary.json`
  - `artifacts/simulations/clawbounties/2026-02-11T22-23-42-689Z-batch-200/summary.json`

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

**Current Status:** ✅ Production complete (gate pack green in staging + prod).  
**Evidence:**
- Staging gate artifacts:
  - `artifacts/simulations/clawbounties/2026-02-11T22-14-08-561Z-prod-gate/gate-report.json`
  - `artifacts/simulations/clawbounties/2026-02-11T22-14-08-561Z-prod-gate/gate-report.md`
- Production gate artifacts:
  - `artifacts/simulations/clawbounties/2026-02-11T22-23-53-242Z-prod-gate/gate-report.json`
  - `artifacts/simulations/clawbounties/2026-02-11T22-23-53-242Z-prod-gate/gate-report.md`

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

**Current Status:** ✅ Production complete (200+ mode passed in staging + prod).  
**Evidence:**
- Staging 200-run artifacts:
  - `artifacts/simulations/clawbounties/2026-02-11T22-17-00-795Z-batch-200/summary.json`
  - `artifacts/simulations/clawbounties/2026-02-11T22-17-00-795Z-batch-200/jobs.ndjson`
- Production 200-run artifacts:
  - `artifacts/simulations/clawbounties/2026-02-11T22-23-42-689Z-batch-200/summary.json`
  - `artifacts/simulations/clawbounties/2026-02-11T22-23-42-689Z-batch-200/jobs.ndjson`

### CBT-US-027 — Funding-aware orchestration
**As marketplace ops, I want** preflight funding gates and dedicated insufficient-funds classification  
**so that** large runs fail fast before noisy escrow churn.

**Acceptance Criteria:**
- Batch runner executes funding preflight before wave execution (configurable continue/abort policy).
- Funding outcome is recorded in summary artifacts.
- Insufficient-funds gets dedicated classified bucket (`INSUFFICIENT_FUNDS`) in summaries.

**Current Status:** ✅ Production complete (funding preflight + classification running in staging/prod).  
**Evidence:**
- Staging funding-aware batch artifacts:
  - `artifacts/simulations/clawbounties/2026-02-11T22-15-12-040Z-batch-10/summary.json`
  - `artifacts/simulations/clawbounties/2026-02-11T22-15-40-868Z-batch-50/summary.json`
  - `artifacts/simulations/clawbounties/2026-02-11T22-17-00-795Z-batch-200/summary.json`
- Production funding-aware batch artifacts:
  - `artifacts/simulations/clawbounties/2026-02-11T22-22-07-779Z-batch-10/summary.json`
  - `artifacts/simulations/clawbounties/2026-02-11T22-22-33-468Z-batch-50/summary.json`
  - `artifacts/simulations/clawbounties/2026-02-11T22-23-42-689Z-batch-200/summary.json`

### CBT-US-028 — Identity control-plane contract assimilation
**As marketplace ops, I want** requester/worker auth contracts aligned with identity control-plane outputs  
**so that** production auth decisions remain deterministic across services.

**Acceptance Criteria:**
- Align marketplace auth checks with clawscope/clawclaim claim contracts.
- Document required audience/scope/subject invariants.
- Add deterministic compatibility smoke assertions.

**Current Status:** ✅ Production complete (`passes=true`).  
**Evidence:**
- Staging gate contract checks (legacy worker token rejected, scoped token accepted):
  - `artifacts/simulations/clawbounties/2026-02-11T23-13-16-036Z-prod-gate/gate-report.json`
- Production gate contract checks:
  - `artifacts/simulations/clawbounties/2026-02-11T23-13-25-303Z-prod-gate/gate-report.json`
- Staging requester/test E2E:
  - `artifacts/simulations/clawbounties/2026-02-11T23-06-24-298Z-requester-e2e/requester-smoke.json`
  - `artifacts/simulations/clawbounties/2026-02-11T23-06-32-801Z-test-e2e/test-smoke.json`
- Production requester/test E2E:
  - `artifacts/simulations/clawbounties/2026-02-11T23-10-20-634Z-requester-e2e/requester-smoke.json`
  - `artifacts/simulations/clawbounties/2026-02-11T23-10-29-162Z-test-e2e/test-smoke.json`

### CBT-US-029 — Sensitive transition enforcement hardening
**As marketplace ops, I want** sensitive production transitions guarded by canonical control-plane semantics  
**so that** auth shortcuts cannot bypass governance.

**Acceptance Criteria:**
- Map sensitive marketplace operations to explicit control-plane transitions.
- Fail-closed on missing/invalid sensitive transition evidence.
- Add deterministic sensitive-transition denial errors.

**Current Status:** ✅ Production complete (`passes=true`).  
**Evidence:**
- Sensitive-transition revalidation + audit persistence verified in staging/prod gates:
  - `artifacts/simulations/clawbounties/2026-02-11T23-13-16-036Z-prod-gate/gate-report.json`
  - `artifacts/simulations/clawbounties/2026-02-11T23-13-25-303Z-prod-gate/gate-report.json`
- Deterministic invalid-harness replay remains fail-closed (422 / `TEST_HARNESS_INVALID`) in both envs:
  - included under `harness.integration.invalid-replay` in the gate reports above.
- Migration + persistence:
  - `services/clawbounties/migrations/0015_requester_auth_events_control_plane.sql`

### CBT-US-030 — API-only simulation discipline for control-plane lane
**As marketplace ops, I want** control-plane assimilation validated via API-only simulation flows  
**so that** production confidence never depends on datastore shortcuts.

**Acceptance Criteria:**
- Extend simulation/gate packs with control-plane contract checks.
- Emit deterministic artifacts for control-plane auth outcomes.
- Define rollout/rollback runbook for CBT-OPS-004 productionization.

**Current Status:** ✅ Production complete (`passes=true`).  
**Evidence:**
- Staging API-only strict-auth runs:
  - requester E2E: `artifacts/simulations/clawbounties/2026-02-11T23-06-24-298Z-requester-e2e/requester-smoke.json`
  - test E2E: `artifacts/simulations/clawbounties/2026-02-11T23-06-32-801Z-test-e2e/test-smoke.json`
  - batch 10/50/200: `artifacts/simulations/clawbounties/2026-02-11T23-06-49-664Z-batch-10/summary.json`, `artifacts/simulations/clawbounties/2026-02-11T23-07-27-180Z-batch-50/summary.json`, `artifacts/simulations/clawbounties/2026-02-11T23-09-15-458Z-batch-200/summary.json`
  - gate (legacy header rejection + invalid-harness replay): `artifacts/simulations/clawbounties/2026-02-11T23-13-16-036Z-prod-gate/gate-report.json`
- Production API-only strict-auth runs:
  - requester E2E: `artifacts/simulations/clawbounties/2026-02-11T23-10-20-634Z-requester-e2e/requester-smoke.json`
  - test E2E: `artifacts/simulations/clawbounties/2026-02-11T23-10-29-162Z-test-e2e/test-smoke.json`
  - batch 10/50/200: `artifacts/simulations/clawbounties/2026-02-11T23-10-42-942Z-batch-10/summary.json`, `artifacts/simulations/clawbounties/2026-02-11T23-11-14-085Z-batch-50/summary.json`, `artifacts/simulations/clawbounties/2026-02-11T23-12-36-717Z-batch-200/summary.json`
  - gate (legacy header rejection + invalid-harness replay): `artifacts/simulations/clawbounties/2026-02-11T23-13-25-303Z-prod-gate/gate-report.json`

---

## 8) Success Metrics
- Bounties posted/closed via real API flows
- Closure latency by closure type
- Stuck `pending_review` rate for test lane
- Simulation pass rate under small/medium batch load

---

*Generated for Claw Bureau monorepo. All PRDs follow a uniform structure for Ralph execution.*
