> **Type:** PRD
> **Status:** ACTIVE
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-12
> **Source of truth:** `services/clawincome/{prd.json,progress.txt}`
>
> **Scope:**
> - Product requirements for `clawincome.com`.
> - Shipped behavior is tracked in `services/clawincome/progress.txt`.

# clawincome.com (Income & Tax) — PRD

**Domain:** clawincome.com  
**Pillar:** Economy & Settlement  
**Status:** ACTIVE (CIN-OPS-001 shipped)

---

## Implementation status (current)

- **Active service:** `services/clawincome/`
- **Execution tracker:**
  - `services/clawincome/prd.json`
  - `services/clawincome/progress.txt`
- **Shipped in CIN-OPS-001:**
  - New Worker + D1-backed report snapshot control plane (`report_snapshots`, `access_audit_events`)
  - Endpoints:
    - `GET /v1/statements/monthly`
    - `GET /v1/statements/monthly.csv`
    - `GET /v1/invoices`
    - `GET /v1/tax-lots`
    - `GET /v1/income`
  - Own-data auth by default (`sub === did`) with admin override (`INCOME_ADMIN_KEY`)
  - Access audit logging for allowed/denied reads
  - Fail-closed dependency and finance reference checks across ledger/escrow/clawcuts/clawsettle
  - Deterministic BigInt minor-unit math for all totals/splits/rollups
  - Idempotent report snapshots keyed by `(report_type, did, period_key)` with hash evidence
  - Production evidence:
    - `artifacts/simulations/clawincome/2026-02-12T01-09-04-3NZ-staging/smoke.json`
    - `artifacts/simulations/clawincome/2026-02-12T01-09-18-3NZ-prod/smoke.json`

---

## 1) Purpose
Statements, invoices, tax exports, and timeline APIs for agents and enterprises.

## 2) Target Users
- Agents
- Enterprises
- Accountants
- Platform integrators

## 3) MVP Scope
- Monthly statements (JSON + CSV)
- Invoice export (JSON)
- Tax-lot export (JSON, yearly)
- Income timeline API (cursor pagination)

## 4) Non-Goals (v0)
- Full tax filing service
- Jurisdiction-specific filing automation

## 5) Dependencies
- clawledger.com
- clawescrow.com
- clawcuts.com
- clawsettle.com
- clawscope.com

## 6) Core User Journeys
- Agent downloads monthly statement and reconciles payout activity.
- Enterprise exports invoices for monthly buyer spend reconciliation.
- Accountant pulls yearly tax lots for reporting workflows.
- Integrator reads timeline deltas via paginated `/v1/income`.

## 7) User Stories
### CIN-US-001 — Monthly statements
**As an** agent, **I want** monthly earnings statements **so that** I can report income.

**Acceptance Criteria:**
  - Generate monthly report
  - Include payouts + fees
  - Download JSON/CSV


### CIN-US-002 — Invoice export
**As an** enterprise, **I want** invoices **so that** I can reconcile spend.

**Acceptance Criteria:**
  - Generate invoices per escrow
  - Include tax-ready fields
  - Export JSON


### CIN-US-003 — Tax lots
**As an** accountant, **I want** tax-lot exports **so that** I can file taxes.

**Acceptance Criteria:**
  - Filter by year
  - Include lot metadata
  - Deterministic minor-unit math


### CIN-US-004 — Income API
**As a** platform, **I want** income data endpoints **so that** I can integrate.

**Acceptance Criteria:**
  - `GET /v1/income`
  - Date filters
  - Cursor pagination


### CIN-US-005 — Expense reports
**As an** enterprise, **I want** expense exports **so that** budgeting is easier.

**Acceptance Criteria:**
  - Aggregate spend
  - Tag by policy/escrow
  - Export via statement/invoice APIs


### CIN-US-006 — Privacy controls
**As a** user, **I want** privacy controls **so that** my data is protected.

**Acceptance Criteria:**
  - Own-data-only access unless admin
  - Audit access logs
  - Fail-closed auth


## 8) Success Metrics
- Statements generated per month
- Invoice/tax export usage
- Snapshot replay consistency (idempotent hash)
- Zero privacy policy regressions

---

*Generated for Claw Bureau monorepo. All PRDs follow a uniform structure for Ralph execution.*
