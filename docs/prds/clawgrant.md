> **Type:** PRD
> **Status:** DRAFT
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-07
> **Source of truth:** PRD intent (no active execution tracker yet)
>
> **Scope:**
> - Product requirements for `clawgrant.com`.
> - This domain has no service-level tracker yet; treat as aspirational until a roadmap/service tracker exists.

# clawgrant.com (Grants) — PRD

**Domain:** clawgrant.com  
**Pillar:** Capital & Incentives  
**Status:** Draft  

---

## Implementation status (current)

- **Service:** not implemented yet (no service-level tracker found).
- **Tracking:** create a roadmap in `docs/roadmaps/` or a service tracker in `services/` when work starts.

---

## 1) Purpose
Grant programs and ecosystem funding distribution.

## 2) Target Users
- Builders
- Operators
- Council

## 3) MVP Scope
- Grant applications
- Review workflow
- Ledger payouts

## 4) Non-Goals (v0)
- Full DAO governance v0

## 5) Dependencies
- clawledger.com
- clawadvisory.com

## 6) Core User Journeys
- Builder applies → reviewed → paid

## 7) User Stories
### CGR-US-001 — Submit grant application
**As a** builder, **I want** to apply for grants **so that** I can get funding.

**Acceptance Criteria:**
  - Application form
  - Upload proof
  - Submit status


### CGR-US-002 — Review workflow
**As a** reviewer, **I want** to review applications **so that** funds go to best projects.

**Acceptance Criteria:**
  - Review queue
  - Score rubric
  - Approve/reject


### CGR-US-003 — Payout grants
**As a** operator, **I want** to pay grants **so that** builders receive funds.

**Acceptance Criteria:**
  - Trigger ledger payout
  - Record funding event
  - Notify recipient


### CGR-US-004 — Grant milestones
**As a** operator, **I want** milestone-based funding **so that** progress is tracked.

**Acceptance Criteria:**
  - Define milestones
  - Release on proof
  - Freeze on failure


### CGR-US-005 — Public transparency
**As a** community, **I want** public grant list **so that** funding is transparent.

**Acceptance Criteria:**
  - Public listing
  - Link to proofs
  - Show amounts


### CGR-US-006 — Audit trail
**As a** auditor, **I want** audit logs **so that** grants are accountable.

**Acceptance Criteria:**
  - Record decisions
  - Signed approvals
  - Export logs


## 8) Success Metrics
- Applications received
- Approval rate
- Grant ROI

---

*Generated for Claw Bureau monorepo. All PRDs follow a uniform structure for Ralph execution.*
