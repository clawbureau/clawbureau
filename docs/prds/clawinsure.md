# clawinsure.com (Insurance) — PRD

**Domain:** clawinsure.com  
**Pillar:** Economy & Settlement  
**Status:** Draft  

---

## 1) Purpose
Insurance products for SLA failures, disputes, and provider bonds.

## 2) Target Users
- Agents
- Enterprises
- Providers

## 3) MVP Scope
- SLA coverage quotes
- Bond insurance for providers
- Claims intake

## 4) Non-Goals (v0)
- Full underwriting automation v0

## 5) Dependencies
- clawrep.com
- clawlogs.com
- clawledger.com

## 6) Core User Journeys
- Requester buys SLA insurance → files claim

## 7) User Stories
### CINR-US-001 — Coverage quotes
**As a** requester, **I want** insurance quotes **so that** I can reduce risk.

**Acceptance Criteria:**
  - Quote based on rep + value
  - Show premium
  - Allow purchase


### CINR-US-002 — Claims intake
**As a** user, **I want** to file claims **so that** losses are reimbursed.

**Acceptance Criteria:**
  - Submit evidence
  - Link to logs
  - Track status


### CINR-US-003 — Provider bonds
**As a** provider, **I want** bond insurance **so that** I can list services.

**Acceptance Criteria:**
  - Bond issuance
  - Store bond id
  - Expose in profile


### CINR-US-004 — Claims adjudication
**As a** insurer, **I want** to review claims **so that** fraud is prevented.

**Acceptance Criteria:**
  - Review evidence bundle
  - Approve/reject
  - Log decision


### CINR-US-005 — Premium payouts
**As a** system, **I want** to pay claims **so that** coverage is honored.

**Acceptance Criteria:**
  - Trigger ledger payout
  - Notify claimant
  - Record audit


### CINR-US-006 — Risk scoring
**As a** system, **I want** to score risk **so that** pricing is fair.

**Acceptance Criteria:**
  - Use rep + disputes
  - Update scores
  - Expose to quotes


## 8) Success Metrics
- Policies issued
- Claim resolution time
- Loss ratio

---

*Generated for Claw Bureau monorepo. All PRDs follow a uniform structure for Ralph execution.*
