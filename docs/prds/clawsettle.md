> **Type:** PRD
> **Status:** ACTIVE
> **Owner:** @clawbureau/economy
> **Last reviewed:** 2026-02-12
> **Source of truth:** `services/clawsettle/{prd.json,progress.txt}`
>
> **Scope:**
> - Product requirements for `clawsettle.com`.
> - Shipped behavior is tracked in `services/clawsettle/progress.txt`.

# clawsettle.com (Settlement) — PRD

**Domain:** clawsettle.com  
**Pillar:** Economy & Settlement  
**Status:** Active (MPY-US-003/006/007/008/009/010 shipped; MPY-US-011 staging-validated, prod pending GO PROD)  

---

## Implementation status (current)

- **Active service:** `services/clawsettle/`
- **Execution tracker:**
  - `services/clawsettle/prd.json`
  - `services/clawsettle/progress.txt`
- **Current shipped stories:**
  - `MPY-US-003` — Stripe webhook verification + deterministic ledger forwarding
  - `MPY-US-006` — production activation + strict livemode environment guard
  - `MPY-US-007` — durable forwarding outbox + retry (cron/manual) with exact-once side effects
  - `MPY-US-008` (`CST-US-001`) — payout initiation + deterministic lock semantics
  - `MPY-US-009` (`CST-US-003`) — payout lifecycle state machine + status endpoint
  - `MPY-US-010` (`CST-US-004`) — reconciliation reports + ops controls
  - **Environment:** staging + production (`clawsettle-staging`, `clawsettle`), smoke passed
- **In progress (staging complete, prod pending explicit GO PROD):**
  - `MPY-US-011` (`CST-US-002`) — deterministic netting engine

---

## 1) Purpose
Payouts, netting, and external rails (Stripe/USDC).

## 2) Target Users
- Agents
- Enterprises
- Finance ops

## 3) MVP Scope
- Payout initiation
- Netting ledger
- Reconciliation reports

## 4) Non-Goals (v0)
- Full global remittance v0

## 5) Dependencies
- clawledger.com
- clawescrow.com

## 6) Core User Journeys
- Escrow release → payout → receipt

## 7) User Stories
### MPY-US-003 — Stripe webhook verification + ledger settlement forwarding
**As a** settlement adapter, **I want** fail-closed Stripe webhook verification and deterministic forwarding into clawledger settlements **so that** external payment provenance is machine-verifiable and idempotent.

**Acceptance Criteria:**
  - POST /v1/stripe/webhook verifies Stripe signatures fail-closed
  - Verified events map to canonical ledger settlement ingest payloads
  - Forwarding uses deterministic idempotency key `stripe:event:<event_id>`
  - Replay events dedupe without double-forwarding side effects

**Current Status:** ✅ Shipped to staging (staging deploy + smoke evidence in `services/clawsettle/progress.txt`)

### MPY-US-006 — clawsettle production activation + livemode hardening
**As an** operator, **I want** strict environment-mode gating for Stripe webhooks and production activation controls **so that** staging/prod cannot ingest cross-mode events.

**Acceptance Criteria:**
  - Production rollout (migration + deploy + smoke)
  - Staging rejects Stripe live events fail-closed
  - Production rejects Stripe test-mode events unless explicit allow flag is enabled
  - Deterministic fail-closed livemode mismatch error
  - Signature verification + replay dedupe semantics remain intact

**Current Status:** ✅ Shipped to staging + production (deploy + smoke evidence in `services/clawsettle/progress.txt`)

### MPY-US-007 — clawsettle reliable forwarding (outbox/retry)
**As a** settlement operator, **I want** durable verified-event persistence and retryable forwarding **so that** transient ledger failures cannot silently drop settlement side effects.

**Acceptance Criteria:**
  - Persist verified webhook event before forwarding attempt
  - Durable outbox status + retry mechanism (cron/manual)
  - Exact-once economic side effects under replay/retry races
  - Deterministic status/error lifecycle
  - Smoke: initial failure → retry success → no double-credit

**Current Status:** ✅ Shipped to staging + production (failure→retry→no-double-credit smoke evidence in `services/clawsettle/progress.txt`)

### MPY-US-008 (CST-US-001) — Initiate payout + deterministic lock semantics
**As an** agent/operator, **I want** payout initiation to lock funds deterministically before provider submission **so that** retries cannot over-release funds.

**Acceptance Criteria:**
  - `POST /v1/payouts/connect/onboard`
  - `POST /v1/payouts`
  - Enforce ledger balance check before lock
  - Deterministic lock semantics before external payout submission
  - Idempotent payout request keys + fail-closed deterministic errors

**Current Status:** ✅ Shipped to staging + production (onboarding + payout initiation with deterministic idempotency and lock semantics)

### MPY-US-011 (CST-US-002) — Deterministic netting engine
**As** finance ops, **I want** payout netting runs to be deterministic, replay-safe, and auditable **so that** settlement batching cannot double-apply under retries or races.

**Acceptance Criteria:**
  - Add netting persistence schema (`netting_runs`, `netting_entries`) with replay-safe indexes/uniques
  - `POST /v1/netting/runs` (admin) creates/executes deterministic netting runs
  - `GET /v1/netting/runs/:id` exposes run status + entry summary
  - `GET /v1/netting/runs/:id/report?format=json|csv` exports deterministic artifacts with stable hash
  - Candidate payout selection + entry ordering is deterministic and minor-unit only
  - Overlapping run collisions and retries/replays do not double-apply ledger side effects

**Current Status:** 🚧 Implemented + staging-validated (migration/deploy/smoke complete), awaiting explicit GO PROD

### MPY-US-009 (CST-US-003) — Payout lifecycle state machine + status endpoint
**As an** operator, **I want** payout lifecycle transitions to be explicit and exact-once **so that** webhook replays/retries cannot cause double-release or double-credit behavior.

**Acceptance Criteria:**
  - Add payout state machine + `GET /v1/payouts/:id`
  - Wire `payout.paid` into exact-once finalize behavior
  - Wire `payout.failed` into exact-once rollback behavior
  - Deterministic lifecycle errors (including `INVALID_STATUS_TRANSITION`)
  - Demonstrate no double-credit / double-release under replay+retry races

**Current Status:** ✅ Shipped to staging + production (state machine + payout webhook finalize/rollback exact-once path live)

### MPY-US-010 (CST-US-004) — Reconciliation + ops reporting
**As** finance ops, **I want** deterministic payout reconciliation outputs and operational controls **so that** incident response and reporting are auditable.

**Acceptance Criteria:**
  - Daily reconciliation report + CSV/export
  - Stuck/failed payout visibility
  - Targeted retry controls
  - Deterministic audit artifacts for finance ops

**Current Status:** ✅ Shipped to staging + production (daily JSON/CSV reconciliation + ops visibility + targeted retry controls live)

### CST-US-005 — Compliance checks
**As a** operator, **I want** basic compliance gates **so that** risk is reduced.

**Acceptance Criteria:**
  - KYC flag support
  - Sanctions blocklist
  - Audit log


### CST-US-006 — Multi-rail support
**As a** enterprise, **I want** multiple rails **so that** I can choose payout.

**Acceptance Criteria:**
  - Stripe + USDC connectors
  - Config per account
  - Test mode


## 8) Success Metrics
- Payout success rate
- Settlement time
- Reconciliation accuracy

---

*Generated for Claw Bureau monorepo. All PRDs follow a uniform structure for Ralph execution.*
