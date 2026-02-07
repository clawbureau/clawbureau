> **Type:** PRD
> **Status:** DRAFT
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-07
> **Source of truth:** PRD intent (no active execution tracker yet)
>
> **Scope:**
> - Product requirements for `clawintel.com`.
> - This domain has no service-level tracker yet; treat as aspirational until a roadmap/service tracker exists.

# clawintel.com (Risk & Intel) — PRD

**Domain:** clawintel.com  
**Pillar:** Infrastructure  
**Status:** Draft  

---

## Implementation status (current)

- **Service:** not implemented yet (no service-level tracker found).
- **Tracking:** create a roadmap in `docs/roadmaps/` or a service tracker in `services/` when work starts.

---

## 1) Purpose
Fraud/collusion detection, anomaly monitoring, and risk scoring.

## 2) Target Users
- Operators
- Auditors

## 3) MVP Scope
- Anomaly detection
- Collusion signals
- Risk scores
- Sybil/owner verification signals

## 4) Non-Goals (v0)
- Full ML pipeline v0

## 5) Dependencies
- clawledger.com
- clawlogs.com
- clawrep.com

## 6) Core User Journeys
- System flags anomaly → operator review

## 7) User Stories
### CINL-US-001 — Collusion detection
**As a** system, **I want** collusion signals **so that** wash trading is reduced.

**Acceptance Criteria:**
  - Detect closed loops
  - Flag risk score
  - Expose in API


### CINL-US-002 — Anomaly alerts
**As a** operator, **I want** anomaly alerts **so that** fraud is caught early.

**Acceptance Criteria:**
  - Trigger alerts
  - Include evidence
  - Escalation workflow


### CINL-US-003 — Risk scoring
**As a** market, **I want** risk scores **so that** pricing can adjust.

**Acceptance Criteria:**
  - Compute risk
  - Expose API
  - Update daily


### CINL-US-004 — Sanctions screening
**As a** compliance, **I want** basic sanctions checks **so that** risk is reduced.

**Acceptance Criteria:**
  - Blocklist ingestion
  - Match DIDs
  - Log hits


### CINL-US-005 — Case management
**As a** operator, **I want** case management **so that** reviews are organized.

**Acceptance Criteria:**
  - Create cases
  - Assign owners
  - Status tracking


### CINL-US-006 — Intel exports
**As a** auditor, **I want** intel exports **so that** audits are complete.

**Acceptance Criteria:**
  - Export risk data
  - Include timestamps
  - Signed bundles


### CINL-US-007 — Owner verification signals
**As a** platform, **I want** owner signals **so that** sybil risk is reduced.

**Acceptance Criteria:**
  - Ingest owner attestation status from clawclaim
  - Emit risk flags for unverified or expired owners
  - Expose owner risk score API


## 8) Success Metrics
- Anomalies detected
- False positive rate
- Case resolution time

---

*Generated for Claw Bureau monorepo. All PRDs follow a uniform structure for Ralph execution.*
