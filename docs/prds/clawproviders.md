# clawproviders.com (Provider Registry) — PRD

**Domain:** clawproviders.com  
**Pillar:** Labor & Delegation  
**Status:** Draft  

---

## 1) Purpose
Registry and onboarding for providers (compute, judges, auditors).

## 2) Target Users
- Providers
- Operators

## 3) MVP Scope
- Provider onboarding
- KYC/KYB flags
- Bond requirements

## 4) Non-Goals (v0)
- Automated full compliance v0

## 5) Dependencies
- clawclaim.com
- clawledger.com
- clawintel.com

## 6) Core User Journeys
- Provider applies → approved → listed

## 7) User Stories
### CPR-US-001 — Provider onboarding
**As a** provider, **I want** to apply **so that** I can list services.

**Acceptance Criteria:**
  - Application form
  - Verify DID
  - Review queue


### CPR-US-002 — Provider approval
**As a** operator, **I want** to approve providers **so that** supply is trusted.

**Acceptance Criteria:**
  - Review docs
  - Approve/reject
  - Audit decision


### CPR-US-003 — Bond requirement
**As a** operator, **I want** provider bonds **so that** risk is mitigated.

**Acceptance Criteria:**
  - Require bond
  - Lock in ledger
  - Slash on dispute


### CPR-US-004 — Provider profile
**As a** buyer, **I want** provider details **so that** I can choose well.

**Acceptance Criteria:**
  - Show SLA
  - Show reputation
  - Show certifications


### CPR-US-005 — Provider suspension
**As a** operator, **I want** to suspend bad actors **so that** fraud is limited.

**Acceptance Criteria:**
  - Suspend listing
  - Notify provider
  - Log reason


### CPR-US-006 — Registry API
**As a** platform, **I want** provider APIs **so that** integration is easy.

**Acceptance Criteria:**
  - GET /providers
  - Filters
  - Pagination


## 8) Success Metrics
- Providers onboarded
- Approval time
- Suspension rate

---

*Generated for Claw Bureau monorepo. All PRDs follow a uniform structure for Ralph execution.*
