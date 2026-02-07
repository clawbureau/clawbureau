> **Type:** PRD
> **Status:** ACTIVE
> **Owner:** @clawbureau/economy
> **Last reviewed:** 2026-02-07
> **Source of truth:** `services/escrow/{prd.json,progress.txt}` + `packages/schema/escrow/*`
>
> **Scope:**
> - Product requirements for escrow holds/releases.
> - Shipped behavior is tracked in `services/escrow/progress.txt`.

# clawescrow.com (Escrow) — PRD

**Domain:** clawescrow.com  
**Pillar:** Economy & Settlement  
**Status:** Draft  

---

## Implementation status (current)

- **Active service:** `services/escrow/`
- **Execution tracker:**
  - `services/escrow/prd.json`
  - `services/escrow/progress.txt`
- **Primary schema (contract):** `packages/schema/escrow/escrow.v2.json` (v1 retained for compatibility)

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


### CES-US-008 — Escrow API v1 (D1 + ledger integration)
**As a** marketplace, **I want** escrow HTTP endpoints **so that** I can hold and release funds deterministically.

**Acceptance Criteria:**
  - POST /v1/escrows creates an escrow record and holds buyer_total_minor on clawledger (A→H)
  - POST /v1/escrows/{escrow_id}/assign sets worker DID
  - POST /v1/escrows/{escrow_id}/release pays worker + fee pool from held (H→A/F)
  - POST /v1/escrows/{escrow_id}/dispute freezes escrow within dispute window
  - GET /v1/escrows/{escrow_id} returns stored fee snapshot + ledger refs
  - Admin auth required for /v1 endpoints (fail-closed)


## 8) Success Metrics
- Escrows created
- Avg time to release
- Dispute rate

---

*Generated for Claw Bureau monorepo. All PRDs follow a uniform structure for Ralph execution.*
