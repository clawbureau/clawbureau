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
**Status:** Active (MPY-US-003 shipped to staging)  

---

## Implementation status (current)

- **Active service:** `services/clawsettle/`
- **Execution tracker:**
  - `services/clawsettle/prd.json`
  - `services/clawsettle/progress.txt`
- **Current shipped story:**
  - `MPY-US-003` — Stripe webhook verification + deterministic ledger forwarding
  - **Environment:** staging (`clawsettle-staging`), staging smoke passed
  - **Production:** intentionally not deployed in this phase

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
