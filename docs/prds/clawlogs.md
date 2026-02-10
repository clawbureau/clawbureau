> **Type:** PRD
> **Status:** DRAFT
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-07
> **Source of truth:** PRD intent (no active execution tracker yet)
>
> **Scope:**
> - Product requirements for `clawlogs.com`.
> - This domain has no service-level tracker yet; treat as aspirational until a roadmap/service tracker exists.

# clawlogs.com (Audit Logs) — PRD

**Domain:** clawlogs.com  
**Pillar:** Identity & Trust  
**Status:** Draft  

---

## Implementation status (current)

- **Service:** not implemented yet (no service-level tracker found).
- **Tracking:** create a roadmap in `docs/roadmaps/` or a service tracker in `services/` when work starts.

---

## 0) OpenClaw Fit (primary design target)
OpenClaw already has local session logs and run metadata; `clawlogs` is the **external, append-only audit sink** when runs need to be independently verifiable.

Primary OpenClaw integration points:
- forward `clawproxy` receipts (hash-only) + correlation fields (`agentId`, `sessionKey`, `model`)
- export bundles for third-party audits without giving full OpenClaw workspace access

See: `docs/integration/OPENCLAW_INTEGRATION.md`.

See also (PoH vNext):
- `docs/roadmaps/proof-of-harness/DESIGN_model-identity-and-verifiable-audits.md`
- `docs/roadmaps/proof-of-harness/ROADMAP_vNext.md`

---

## 1) Purpose
Tamper-evident audit logging and Merkle anchoring for all economic and verification events.

## 2) Target Users
- OpenClaw gateway operators (optional external audit)
- Auditors
- Enterprises
- Operators

## 3) MVP Scope
- Append-only log API
- Hash chain integrity
- Merkle root anchoring

## 4) Non-Goals (v0)
- Full blockchain settlement

## 5) Dependencies
- clawledger.com
- clawproxy.com

## 6) Core User Journeys
- Ledger event → audit entry
- Auditor requests inclusion proof

## 7) User Stories
### CLG-US-001 — Append-only log
**As a** system, **I want** all events logged **so that** audit trails are immutable.

**Acceptance Criteria:**
  - Insert log entry
  - Link to previous hash
  - Reject out-of-order inserts


### CLG-US-002 — Merkle anchoring
**As a** auditor, **I want** periodic Merkle roots **so that** I can verify integrity.

**Acceptance Criteria:**
  - Compute root daily
  - Publish root endpoint
  - Return inclusion proofs


### CLG-US-003 — Log export
**As a** enterprise, **I want** exportable logs **so that** compliance can audit.

**Acceptance Criteria:**
  - CSV/JSON export
  - Filter by date/service
  - Signed export bundle


### CLG-US-004 — Evidence bundles
**As a** judge, **I want** evidence snapshots **so that** disputes are resolvable.

**Acceptance Criteria:**
  - Bundle log entries
  - Include receipt hashes
  - Immutable reference link


### CLG-US-005 — Audit alerts
**As a** operator, **I want** alerts on log gaps **so that** tampering is detected.

**Acceptance Criteria:**
  - Detect hash chain breaks
  - Alert on missing sequence
  - Provide repair instructions


### CLG-US-006 — Access control
**As a** auditor, **I want** role-based access **so that** sensitive logs are protected.

**Acceptance Criteria:**
  - RBAC roles
  - Signed access grants
  - Audit access events


### CLG-US-007 — Token/attestation hash logging
**As a** auditor, **I want** token and owner hashes **so that** authorization is provable.

**Acceptance Criteria:**
  - Store token_scope_hash + policy_hash on relevant events
  - Store owner attestation hash when present
  - Store commit proof hash when supplied


### CLG-US-008 — Portable inclusion proof schema + API
**As a** third party, **I want** a portable inclusion proof object **so that** transparency verification works without bespoke integration.

**Acceptance Criteria:**
  - Define `log_inclusion_proof.v1` schema (`packages/schema/poh/log_inclusion_proof.v1.json`)
  - Publish a root endpoint (signed root) and an inclusion proof endpoint
  - Inclusion proof validates leaf membership in a published root


### CLG-US-009 — Transparency log entry types for audits/derivations
**As a** compliance officer, **I want** standard log entry types for audit/derivation attestations **so that** published compliance claims are discoverable and time-anchored.

**Acceptance Criteria:**
  - Log entry types include: `model_derivation_attested`, `model_audit_attested`
  - Entries store hash pointers only (attestation hash, signer DID, issued_at, related model identity hash)
  - Support export + inclusion proof for these entries


## 8) Success Metrics
- Log events/day
- Inclusion proof latency
- Integrity alerts

---

*Generated for Claw Bureau monorepo. All PRDs follow a uniform structure for Ralph execution.*
