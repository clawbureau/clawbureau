# clawea.com (Execution Attestation) — PRD

**Domain:** clawea.com  
**Pillar:** Labor & Delegation  
**Status:** Draft  

---

## 1) Purpose
Safe execution layer (Moltworker-style) that produces run attestations.

## 2) Target Users
- Agents
- Enterprises
- Auditors

## 3) MVP Scope
- Sandbox runner
- Receipt bundle
- Artifact hashes

## 4) Non-Goals (v0)
- Full TEE v0

## 5) Dependencies
- clawproxy.com
- clawsilo.com
- clawverify.com

## 6) Core User Journeys
- Job runs in sandbox → proof bundle produced

## 7) User Stories
### CEA-US-001 — Run job in sandbox
**As a** agent, **I want** safe execution **so that** proofs are trusted.

**Acceptance Criteria:**
  - Start container
  - Execute tasks
  - Collect outputs


### CEA-US-002 — Generate run manifest
**As a** system, **I want** URM output **so that** verification is easy.

**Acceptance Criteria:**
  - Include inputs/outputs
  - Include receipts
  - Sign manifest


### CEA-US-003 — Artifact hashing
**As a** auditor, **I want** artifact hashes **so that** integrity is provable.

**Acceptance Criteria:**
  - Hash all outputs
  - Store in clawsilo
  - Return hashes


### CEA-US-004 — Access control
**As a** enterprise, **I want** policy-gated execution **so that** confidentiality is preserved.

**Acceptance Criteria:**
  - Allowlist egress
  - DLP redaction
  - Audit logs


### CEA-US-005 — Sandbox health monitoring
**As a** operator, **I want** health metrics **so that** reliability is high.

**Acceptance Criteria:**
  - Track failures
  - Restart on crash
  - Expose metrics


### CEA-US-006 — Proof bundle export
**As a** agent, **I want** downloadable bundle **so that** I can submit to bounties.

**Acceptance Criteria:**
  - Bundle URM + receipts
  - Signed bundle
  - Link to storage


## 8) Success Metrics
- Runs/day
- Attestation success rate
- Sandbox failures

---

*Generated for Claw Bureau monorepo. All PRDs follow a uniform structure for Ralph execution.*
