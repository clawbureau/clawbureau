# clawescrow.com (Escrow) — PRD

**Domain:** clawescrow.com  
**Pillar:** Economy & Settlement  
**Status:** Draft  

---

## 1) Purpose
Escrow holds/releases/milestones for agent work.

## 2) Target Users
- Requesters
- Agents
- Markets

## 3) MVP Scope
- Create escrow hold
- Release escrow
- Dispute window
- Milestones

## 4) Non-Goals (v0)
- On-chain escrow v0

## 5) Dependencies
- clawledger.com
- clawverify.com
- clawtrials.com

## 6) Core User Journeys
- Requester posts escrow → agent completes → release

## 7) User Stories
### CES-US-001 — Create escrow hold
**As a** requester, **I want** to lock funds **so that** work is safe.

**Acceptance Criteria:**
  - Hold reduces balance
  - Return escrow id
  - Support metadata/terms


### CES-US-002 — Release escrow
**As a** requester, **I want** to pay after approval **so that** work is settled.

**Acceptance Criteria:**
  - Transfer to agent
  - Record ledger event
  - Emit webhook


### CES-US-003 — Dispute window
**As a** agent, **I want** a dispute period **so that** fraud is handled.

**Acceptance Criteria:**
  - Configurable dispute window
  - Freeze escrow on dispute
  - Escalate to trials


### CES-US-004 — Milestone payouts
**As a** requester, **I want** milestones **so that** long jobs can be staged.

**Acceptance Criteria:**
  - Define milestones
  - Partial releases
  - Track remaining


### CES-US-005 — Escrow cancellation
**As a** requester, **I want** to cancel **so that** funds return if no work.

**Acceptance Criteria:**
  - Cancel if no submission
  - Release hold
  - Audit log entry


### CES-US-006 — Escrow status API
**As a** platform, **I want** status endpoints **so that** UI can show progress.

**Acceptance Criteria:**
  - GET /escrow/{id}
  - Status states
  - Include timestamps

### CES-US-007 — Public landing + skill docs
**As a** developer, **I want** public landing/docs/skill endpoints **so that** I can discover and integrate clawescrow quickly.

**Acceptance Criteria:**
  - GET / returns a small HTML landing page with links to /docs and /skill.md
  - GET /skill.md returns integration docs + example curl commands
  - GET /robots.txt and /sitemap.xml exist (minimal)
  - GET /.well-known/security.txt exists


## 8) Success Metrics
- Escrows created
- Avg time to release
- Dispute rate

---

*Generated for Claw Bureau monorepo. All PRDs follow a uniform structure for Ralph execution.*
