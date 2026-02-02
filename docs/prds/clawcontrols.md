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
- Dispute parameter registry
- Reserve impairment circuit breaker
- Trials kill switches
- Token policy registry (CST)
- Owner-verified gating rules

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


### CCO-US-007 — Dispute parameter registry
**As a** operator, **I want** dispute configs **so that** trials are consistent.

**Acceptance Criteria:**
  - Define bonds, deadlines, quorum rules
  - Version parameter sets
  - Expose registry API


### CCO-US-008 — Trials kill switch
**As a** safety officer, **I want** to halt trials **so that** incidents are contained.

**Acceptance Criteria:**
  - Disable new trial creation
  - Allow ongoing cases to finish or pause
  - Require quorum override to re-enable


### CCO-US-009 — Reserve impairment circuit breaker
**As a** finance operator, **I want** reserve gates **so that** cash-out is safe.

**Acceptance Criteria:**
  - Disable cash-out when reserve coverage drops below threshold
  - Publish impairment notice
  - Log override actions with quorum


### CCO-US-010 — Token policy registry
**As a** platform, **I want** token policies **so that** CST scopes are controlled.

**Acceptance Criteria:**
  - Define max TTL + allowed scopes per tier
  - Enforce audience restrictions per service
  - Provide policy simulation endpoint


### CCO-US-011 — Owner-verified gating
**As a** platform, **I want** owner verification gates **so that** sybil attacks are reduced.

**Acceptance Criteria:**
  - Configure actions requiring owner-verified status
  - Provide rate-limit multipliers by owner status
  - Log enforcement decisions


## 8) Success Metrics
- Policy changes
- Violations blocked
- Kill switch usage

---

*Generated for Claw Bureau monorepo. All PRDs follow a uniform structure for Ralph execution.*
