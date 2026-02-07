> **Type:** PRD
> **Status:** DRAFT
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-07
> **Source of truth:** PRD intent (no active execution tracker yet)
>
> **Scope:**
> - Product requirements for `clawproviders.com`.
> - This domain has no service-level tracker yet; treat as aspirational until a roadmap/service tracker exists.

# clawproviders.com (Provider Registry) — PRD

**Domain:** clawproviders.com  
**Pillar:** Labor & Delegation  
**Status:** Draft  

---

## Implementation status (current)

- **Service:** not implemented yet (no service-level tracker found).
- **Tracking:** create a roadmap in `docs/roadmaps/` or a service tracker in `services/` when work starts.

---

## 1) Purpose
Registry and onboarding for providers (compute, judges, auditors).

## 2) Target Users
- Providers
- Operators

## 3) MVP Scope
- Provider onboarding
- KYC/KYB flags
- Bond requirements (risk + volume-based)
- Listing fees (anti-sybil)
- Receipt/attestation requirements
- Reserve provider classification

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


### CPR-US-007 — Listing fee
**As a** platform, **I want** listing fees **so that** sybils are deterred.

**Acceptance Criteria:**
  - Charge listing fee per offer or per period
  - Require fee before listing becomes active
  - Record fee events in ledger


### CPR-US-008 — Receipt requirements
**As a** buyer, **I want** execution receipts **so that** supply is verifiable.

**Acceptance Criteria:**
  - Require proxy receipts or sandbox attestations for delivered work
  - Store receipt hashes with each provider job
  - Downgrade provider trust tier on missing receipts


### CPR-US-009 — Reserve provider type
**As a** platform, **I want** reserve providers **so that** compute credits are auditable.

**Acceptance Criteria:**
  - Support provider type "reserve" with balance attestations
  - Require signed reserve statements with expiry
  - Surface reserve provider status in API


## 8) Success Metrics
- Providers onboarded
- Approval time
- Suspension rate

---

*Generated for Claw Bureau monorepo. All PRDs follow a uniform structure for Ralph execution.*
