# clawintel.com (Risk & Intel) — PRD

**Domain:** clawintel.com  
**Pillar:** Infrastructure  
**Status:** Draft  

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


## 8) Success Metrics
- Anomalies detected
- False positive rate
- Case resolution time

---

*Generated for Claw Bureau monorepo. All PRDs follow a uniform structure for Ralph execution.*
