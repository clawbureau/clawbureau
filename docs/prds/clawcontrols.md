# clawcontrols.com (Policy Controls) — PRD

**Domain:** clawcontrols.com  
**Pillar:** Governance & Risk Controls  
**Status:** Draft  

---

## 1) Purpose
Policy engine for spend caps, allowlists, and kill switches.

## 2) Target Users
- Operators
- Enterprises

## 3) MVP Scope
- Spend caps
- Allowlist rules
- Global kill switch

## 4) Non-Goals (v0)
- Full IAM v0

## 5) Dependencies
- clawledger.com
- clawrep.com

## 6) Core User Journeys
- Admin sets caps → enforced on transactions

## 7) User Stories
### CCO-US-001 — Spend caps
**As a** admin, **I want** to set caps **so that** risk is limited.

**Acceptance Criteria:**
  - Daily cap
  - Per-tx cap
  - Enforced server-side


### CCO-US-002 — Allowlist rules
**As a** admin, **I want** allowlists **so that** only trusted agents act.

**Acceptance Criteria:**
  - Allowlist by DID
  - Apply to services
  - Audit changes


### CCO-US-003 — Kill switch
**As a** operator, **I want** global halt **so that** incidents are contained.

**Acceptance Criteria:**
  - Disable transfers
  - Status banner
  - Require quorum


### CCO-US-004 — Policy simulation
**As a** admin, **I want** simulate policies **so that** changes are safe.

**Acceptance Criteria:**
  - Simulate actions
  - Show allow/deny
  - No mutations


### CCO-US-005 — Policy API
**As a** platform, **I want** policy endpoints **so that** I can enforce rules.

**Acceptance Criteria:**
  - GET /policies
  - POST /policies
  - Webhook on changes


### CCO-US-006 — Audit logs
**As a** auditor, **I want** policy change logs **so that** controls are traceable.

**Acceptance Criteria:**
  - Log changes
  - Include actor
  - Export logs


## 8) Success Metrics
- Policy changes
- Violations blocked
- Kill switch usage

---

*Generated for Claw Bureau monorepo. All PRDs follow a uniform structure for Ralph execution.*
