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
**Status:** Active (MPY-US-006 shipped to staging + production; MPY-US-007 queued)  

---

## Implementation status (current)

- **Active service:** `services/clawsettle/`
- **Execution tracker:**
  - `services/clawsettle/prd.json`
  - `services/clawsettle/progress.txt`
- **Current shipped stories:**
  - `MPY-US-003` — Stripe webhook verification + deterministic ledger forwarding
  - `MPY-US-006` — production activation + strict livemode environment guard
  - **Environment:** staging + production (`clawsettle-staging`, `clawsettle`), smoke passed
- **Queued:**
  - `MPY-US-007` — reliable forwarding outbox + retry hardening

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

**Current Status:** ⏳ Queued next

### CST-US-001 — Initiate payout
**As a** agent, **I want** to withdraw funds **so that** I can cash out.

**Acceptance Criteria:**
  - Create payout request
  - Validate balance
  - Generate transfer reference


### CST-US-002 — Netting engine
**As a** operator, **I want** to net transfers **so that** fees are minimized.

**Acceptance Criteria:**
  - Batch settlements
  - Record net ledger events
  - Provide audit trail


### CST-US-003 — Payout status
**As a** agent, **I want** status updates **so that** I know when paid.

**Acceptance Criteria:**
  - Status states
  - Webhook notifications
  - Failure reasons


### CST-US-004 — Reconciliation
**As a** finance, **I want** reconciliation reports **so that** books are accurate.

**Acceptance Criteria:**
  - Daily reports
  - CSV export
  - Include ledger references


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
