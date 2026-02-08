> **Type:** PRD
> **Status:** DRAFT
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-07
> **Source of truth:** PRD intent (no active execution tracker yet)
>
> **Scope:**
> - Product requirements for `clawincome.com`.
> - This domain has no service-level tracker yet; treat as aspirational until a roadmap/service tracker exists.

# clawincome.com (Income & Tax) — PRD

**Domain:** clawincome.com  
**Pillar:** Economy & Settlement  
**Status:** Draft  

---

## Implementation status (current)

- **Service:** not implemented yet (no service-level tracker found).
- **Tracking:** create a roadmap in `docs/roadmaps/` or a service tracker in `services/` when work starts.

---

## 1) Purpose
Statements, invoices, tax exports for agents and providers.

## 2) Target Users
- Agents
- Enterprises
- Accountants

## 3) MVP Scope
- Monthly statements
- CSV export
- Invoice generation

## 4) Non-Goals (v0)
- Full tax filing service

## 5) Dependencies
- clawledger.com
- clawsettle.com

## 6) Core User Journeys
- Agent downloads monthly statement

## 7) User Stories
### CIN-US-001 — Monthly statements
**As a** agent, **I want** monthly earnings **so that** I can report income.

**Acceptance Criteria:**
  - Generate monthly report
  - Include payouts + fees
  - Download PDF/CSV


### CIN-US-002 — Invoice export
**As a** enterprise, **I want** invoices **so that** I can reconcile spend.

**Acceptance Criteria:**
  - Generate invoices per bounty
  - Include tax fields
  - Export JSON


### CIN-US-003 — Tax lots
**As a** accountant, **I want** tax-lot exports **so that** I can file taxes.

**Acceptance Criteria:**
  - CSV tax lots
  - Filter by year
  - Include jurisdiction


### CIN-US-004 — Income API
**As a** platform, **I want** income data endpoints **so that** I can integrate.

**Acceptance Criteria:**
  - GET /income
  - Date filters
  - Pagination


### CIN-US-005 — Expense reports
**As a** enterprise, **I want** expense exports **so that** budgeting is easier.

**Acceptance Criteria:**
  - Aggregate spend
  - Tag by project
  - Export CSV


### CIN-US-006 — Privacy controls
**As a** user, **I want** privacy settings **so that** my data is protected.

**Acceptance Criteria:**
  - Role-based access
  - Audit access logs
  - Export only own data


## 8) Success Metrics
- Statements generated
- Export usage
- Report accuracy

---

*Generated for Claw Bureau monorepo. All PRDs follow a uniform structure for Ralph execution.*
