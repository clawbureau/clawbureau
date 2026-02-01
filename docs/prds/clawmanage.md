# clawmanage.com (Admin Ops) — PRD

**Domain:** clawmanage.com  
**Pillar:** Governance & Risk Controls  
**Status:** Draft  

---

## 1) Purpose
Admin console for disputes, escalations, fraud, and ops.

## 2) Target Users
- Operators
- Support

## 3) MVP Scope
- Dispute queue
- Fraud cases
- System config

## 4) Non-Goals (v0)
- Public dashboards

## 5) Dependencies
- clawlogs.com
- clawintel.com

## 6) Core User Journeys
- Operator reviews dispute → decision logged

## 7) User Stories
### CMG-US-001 — Dispute queue
**As a** operator, **I want** a dispute queue **so that** cases are handled.

**Acceptance Criteria:**
  - List disputes
  - Assign owners
  - Track status


### CMG-US-002 — Fraud case management
**As a** operator, **I want** fraud case tools **so that** fraud is mitigated.

**Acceptance Criteria:**
  - Open case
  - Attach evidence
  - Resolve case


### CMG-US-003 — User suspension
**As a** operator, **I want** to suspend users **so that** risk is reduced.

**Acceptance Criteria:**
  - Suspend DID
  - Notify user
  - Log reason


### CMG-US-004 — Config management
**As a** operator, **I want** system configs **so that** ops can adjust rules.

**Acceptance Criteria:**
  - Edit settings
  - Version configs
  - Audit changes


### CMG-US-005 — Incident dashboard
**As a** operator, **I want** incident view **so that** I can respond fast.

**Acceptance Criteria:**
  - Incident timeline
  - Runbooks
  - Status updates


### CMG-US-006 — Ops reporting
**As a** operator, **I want** ops metrics **so that** I track workload.

**Acceptance Criteria:**
  - Case counts
  - Resolution time
  - Export CSV


## 8) Success Metrics
- Disputes resolved
- Fraud cases closed
- Ops response time

---

*Generated for Claw Bureau monorepo. All PRDs follow a uniform structure for Ralph execution.*
