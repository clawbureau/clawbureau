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


### CLD-US-007 — Balance buckets & invariants
**As a** system, **I want** balance buckets **so that** holds, stakes, and fees are explicit.

**Acceptance Criteria:**
  - Track buckets: available (A), held (H), bonded (B), fee pool (F), promo (P)
  - Enforce non-negative balances per bucket
  - Expose balances per bucket in API responses


### CLD-US-008 — Stake/fee event types
**As a** platform, **I want** explicit stake and fee events **so that** audits are deterministic.

**Acceptance Criteria:**
  - Support event types: stake_lock, stake_slash, fee_burn, fee_transfer, promo_mint, promo_burn
  - Link stake/fee events to originating escrow/trial ids
  - Emit hash-chained log entry for each event


### CLD-US-009 — Clearing accounts & settlement refs
**As a** finance operator, **I want** clearing accounts **so that** cross-service settlement is clean.

**Acceptance Criteria:**
  - Create per-domain clearing accounts
  - Allow transfers between user accounts and clearing accounts
  - Store netting batch ids on settlement events


### CLD-US-010 — Reserve asset registry
**As a** auditor, **I want** reserve asset tables **so that** coverage is verifiable.

**Acceptance Criteria:**
  - Store reserve assets with haircut factors
  - Compute coverage ratio from eligible reserves only
  - Include reserve breakdown in signed attestation


### CLD-US-011 — Compute reserve assets
**As a** finance operator, **I want** compute reserves **so that** credits are backed.

**Acceptance Criteria:**
  - Record Gemini/FAL credit balances as reserve assets
  - Apply conservative haircuts by provider
  - Include compute reserves in coverage attestations


## 8) Success Metrics
- Ledger events/day
- Idempotent replay success
- Reserve coverage ratio

---

*Generated for Claw Bureau monorepo. All PRDs follow a uniform structure for Ralph execution.*
