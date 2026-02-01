# clawledger.com (Ledger) — PRD

**Domain:** clawledger.com  
**Pillar:** Economy & Settlement  
**Status:** Draft  

---

## 1) Purpose
Event-sourced ledger for balances, holds, and transfers. Idempotent and auditable.

## 2) Target Users
- Agents
- Markets
- Finance ops

## 3) MVP Scope
- Accounts + balances
- Ledger events
- Idempotency keys
- Merkle anchoring

## 4) Non-Goals (v0)
- Full blockchain settlement

## 5) Dependencies
- clawlogs.com

## 6) Core User Journeys
- Deposit credits → balance updated
- Escrow release → ledger transfer

## 7) User Stories
### CLD-US-001 — Create accounts
**As a** user, **I want** a balance account **so that** I can receive credits.

**Acceptance Criteria:**
  - Create account on first use
  - Enforce unique DID
  - Return current balance


### CLD-US-002 — Ledger event writes
**As a** system, **I want** append-only events **so that** audits are possible.

**Acceptance Criteria:**
  - Event types: mint/burn/transfer/hold/release
  - Idempotency key required
  - Write hash to clawlogs


### CLD-US-003 — Hold/Release support
**As a** escrow, **I want** to lock funds **so that** payments are safe.

**Acceptance Criteria:**
  - Create hold event
  - Release or cancel hold
  - Prevent negative balances


### CLD-US-004 — Balance reconciliation
**As a** operator, **I want** ledger replay checks **so that** bugs are caught.

**Acceptance Criteria:**
  - Nightly replay job
  - Alert on mismatch
  - Export report


### CLD-US-005 — Reserve attestation
**As a** auditor, **I want** reserve coverage reports **so that** credits are trusted.

**Acceptance Criteria:**
  - Compute reserves/outstanding
  - Signed attestation
  - Public endpoint


### CLD-US-006 — API access
**As a** platform, **I want** ledger APIs **so that** I can integrate.

**Acceptance Criteria:**
  - GET /balances
  - POST /transfers
  - Webhook for events


## 8) Success Metrics
- Ledger events/day
- Idempotent replay success
- Reserve coverage ratio

---

*Generated for Claw Bureau monorepo. All PRDs follow a uniform structure for Ralph execution.*
