> **Type:** PRD
> **Status:** DRAFT
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-07
> **Source of truth:** PRD intent (no active execution tracker yet)
>
> **Scope:**
> - Product requirements for `clawadvisory.com`.
> - This domain has no service-level tracker yet; treat as aspirational until a roadmap/service tracker exists.

# clawadvisory.com (Governance) — PRD

**Domain:** clawadvisory.com  
**Pillar:** Governance & Risk Controls  
**Status:** Draft  

---

## Implementation status (current)

- **Service:** not implemented yet (no service-level tracker found).
- **Tracking:** create a roadmap in `docs/roadmaps/` or a service tracker in `services/` when work starts.

---

## 1) Purpose
Council governance: proposals, votes, decisions, and attestations.

## 2) Target Users
- Council members
- Community

## 3) MVP Scope
- Proposal creation
- Voting
- Decision logs

## 4) Non-Goals (v0)
- Full DAO tooling

## 5) Dependencies
- clawlogs.com
- clawverify.com

## 6) Core User Journeys
- Proposal submitted → voted → ratified

## 7) User Stories
### CAD-US-001 — Create proposal
**As a** council member, **I want** to create proposals **so that** policy can evolve.

**Acceptance Criteria:**
  - Proposal form
  - Attach evidence
  - Publish draft


### CAD-US-002 — Voting
**As a** member, **I want** to vote **so that** decisions are legit.

**Acceptance Criteria:**
  - Signed votes
  - Quorum required
  - Vote tally


### CAD-US-003 — Decision logs
**As a** community, **I want** decision history **so that** governance is transparent.

**Acceptance Criteria:**
  - Public decision log
  - Signed results
  - Exportable


### CAD-US-004 — Proposal lifecycle
**As a** operator, **I want** status changes **so that** process is consistent.

**Acceptance Criteria:**
  - Draft/Review/Vote/Closed
  - Notifications
  - Audit trail


### CAD-US-005 — Policy attestation
**As a** auditor, **I want** attested policies **so that** compliance is clear.

**Acceptance Criteria:**
  - Signed policy records
  - Versioning
  - Public endpoint


### CAD-US-006 — Council roster
**As a** community, **I want** council visibility **so that** trust is increased.

**Acceptance Criteria:**
  - Roster page
  - DID verification
  - Term info


### CAD-US-007 — Attester allowlists (audits + execution)
**As a** community, **I want** governance-published allowlists of trusted attesters **so that** clawverify can fail closed on audit/execution attestations.

**Acceptance Criteria:**
  - Publish allowlists for:
    - audit result attesters
    - sandbox execution attesters (clawea)
    - future TEE attestation roots / vendors
  - Each allowlist entry includes: attester DID, scope, added_at, expires_at (optional)
  - Provide a signed public endpoint returning the current allowlist bundle
  - Support revocation (mark attester as revoked with reason + timestamp)


### CAD-US-008 — Emergency revocation (attestation vulnerabilities)
**As a** safety officer, **I want** an emergency revocation mechanism **so that** compromised attesters/TCB versions can be invalidated quickly.

**Acceptance Criteria:**
  - Record emergency revocation decisions (signed)
  - Expose a machine-readable revocation feed
  - clawverify can consume revocations to fail closed on revoked attestations


## 8) Success Metrics
- Proposals/month
- Vote participation
- Decision publication time

---

*Generated for Claw Bureau monorepo. All PRDs follow a uniform structure for Ralph execution.*
