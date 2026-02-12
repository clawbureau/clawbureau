> **Type:** PRD
> **Status:** ACTIVE
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-11
> **Source of truth:** `services/clawcuts/{prd.json,progress.txt}`
>
> **Scope:**
> - Product requirements for clawcuts (fee policy + fee simulation).
> - Shipped behavior is tracked in `services/clawcuts/progress.txt`.

# clawcuts.com (Pricing Engine) — PRD

**Domain:** clawcuts.com  
**Pillar:** Capital & Incentives  
**Status:** ACTIVE (CCU-OPS-001 shipped)  

---

## Implementation status (current)

- **Active service:** `services/clawcuts/`
- **Execution tracker:**
  - `services/clawcuts/prd.json`
  - `services/clawcuts/progress.txt`
- **Shipped in CCU-OPS-001:**
  - D1-backed policy control plane with immutable version rows + activate/deactivate lifecycle
  - policy audit log (`policy_audit_events`) with actor/timestamp and history APIs (`/history`, `/history.csv`)
  - deterministic settlement apply endpoints:
    - `POST /v1/fees/apply` (idempotent snapshot apply)
    - `POST /v1/fees/apply/finalize` (bind ledger event refs)
  - referral split planning in simulation + apply transfer plans
  - monthly revenue reporting with JSON + CSV exports:
    - `GET /v1/reports/revenue/monthly?month=YYYY-MM[&product=...][&format=csv]`
  - escrow integration updated to consume clawcuts apply plans fail-closed and emit separate fee/referral ledger refs
  - production evidence:
    - `artifacts/simulations/clawcuts/2026-02-12T00-10-13-377Z-staging/smoke.json`
    - `artifacts/simulations/clawcuts/2026-02-12T00-11-08-054Z-prod/smoke.json`

---

## 1) Purpose
Fee engine and take-rate policies for markets and escrow.

## 2) Target Users
- Operators
- Marketplaces

## 3) MVP Scope
- Fee policy definitions
- Apply fees to ledger events
- Revenue reporting

## 4) Non-Goals (v0)
- Dynamic market maker v0

## 5) Dependencies
- clawledger.com
- clawcontrols.com

## 6) Core User Journeys
- Update fee policy → applied to all new escrows

## 7) User Stories
### CCU-US-001 — Define fee policies
**As a** operator, **I want** to set fees **so that** revenue is consistent.

**Acceptance Criteria:**
  - Create policy per product
  - Version policies
  - Activate/deactivate


### CCU-US-002 — Apply fees
**As a** ledger, **I want** to apply fees **so that** settlements are correct.

**Acceptance Criteria:**
  - Apply stored fee snapshot on release (do not recompute)
  - Record fee event
  - Support discounts


### CCU-US-003 — Referral splits
**As a** growth, **I want** referral splits **so that** partners are rewarded.

**Acceptance Criteria:**
  - Define split rules
  - Apply on transactions
  - Ledger event emitted


### CCU-US-004 — Policy audit
**As a** auditor, **I want** fee change logs **so that** pricing is transparent.

**Acceptance Criteria:**
  - Log policy changes
  - Include actor + timestamp
  - Expose history API


### CCU-US-005 — Fee simulation
**As a** operator, **I want** simulate fees **so that** pricing changes are safe.

**Acceptance Criteria:**
  - Input sample transaction
  - Return computed fees
  - No ledger mutation


### CCU-US-006 — Revenue reporting
**As a** finance, **I want** fee revenue reports **so that** I can track income.

**Acceptance Criteria:**
  - Monthly fee summary
  - Export CSV
  - Segment by product


## 8) Success Metrics
- Fee revenue
- Policy change frequency
- Simulation usage

---

*Generated for Claw Bureau monorepo. All PRDs follow a uniform structure for Ralph execution.*
