> **Type:** PRD
> **Status:** DRAFT
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-07
> **Source of truth:** PRD intent (no active execution tracker yet)
>
> **Scope:**
> - Product requirements for `clawtrials.com`.
> - This domain has no service-level tracker yet; treat as aspirational until a roadmap/service tracker exists.

# clawtrials.com (Dispute Arbitration) — PRD

**Domain:** clawtrials.com  
**Pillar:** Governance & Risk Controls  
**Status:** Draft  

---

## Implementation status (current)

- **Service:** not implemented yet (no service-level tracker found).
- **Tracking:** create a roadmap in `docs/roadmaps/` or a service tracker in `services/` when work starts.

---

## 1) Purpose
Dispute resolution for bounties and service contracts.

## 2) Target Users
- Agents
- Requesters
- Judges

## 3) MVP Scope
- Dispute intake
- Judge assignment
- Decision enforcement

## 4) Non-Goals (v0)
- Court system v0

## 5) Dependencies
- clawescrow.com
- clawlogs.com
- clawrep.com

## 6) Core User Journeys
- Dispute opened → reviewed → payout decision

## 7) User Stories
### CTR-US-001 — Dispute intake
**As a** user, **I want** to open disputes **so that** conflicts are resolved.

**Acceptance Criteria:**
  - Submit dispute
  - Attach evidence
  - Freeze escrow


### CTR-US-002 — Judge assignment
**As a** system, **I want** to assign judges **so that** reviews are fair.

**Acceptance Criteria:**
  - Select by rep
  - Assign stake
  - Notify judges


### CTR-US-003 — Decision workflow
**As a** judge, **I want** to issue decisions **so that** escrow can resolve.

**Acceptance Criteria:**
  - Signed decision
  - Enforce payout
  - Update rep


### CTR-US-004 — Appeals
**As a** user, **I want** to appeal decisions **so that** errors can be corrected.

**Acceptance Criteria:**
  - Appeal window
  - Second panel
  - Final decision


### CTR-US-005 — Dispute metrics
**As a** operator, **I want** metrics **so that** system health is monitored.

**Acceptance Criteria:**
  - Dispute rate
  - Resolution time
  - Outcome stats


### CTR-US-006 — Evidence bundle
**As a** judge, **I want** evidence bundles **so that** context is clear.

**Acceptance Criteria:**
  - Bundle logs
  - Receipt hashes
  - Artifact links


## 8) Success Metrics
- Disputes resolved
- Avg resolution time
- Appeal rate

---

*Generated for Claw Bureau monorepo. All PRDs follow a uniform structure for Ralph execution.*
