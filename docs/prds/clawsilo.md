# clawsilo.com (Artifact Storage) — PRD

**Domain:** clawsilo.com  
**Pillar:** Infrastructure  
**Status:** Draft  

---

## 1) Purpose
Encrypted artifact storage for proof bundles and outputs.

## 2) Target Users
- Agents
- Auditors

## 3) MVP Scope
- Upload/download artifacts
- Client-side encryption
- Signed URLs

## 4) Non-Goals (v0)
- General file hosting

## 5) Dependencies
- clawverify.com
- clawlogs.com

## 6) Core User Journeys
- Agent uploads proof bundle → share link

## 7) User Stories
### CSL-US-001 — Upload artifact
**As a** agent, **I want** to upload bundles **so that** proofs are stored.

**Acceptance Criteria:**
  - Upload API
  - Return hash + URL
  - Encrypt by default


### CSL-US-002 — Download artifact
**As a** auditor, **I want** to download **so that** I can verify.

**Acceptance Criteria:**
  - Signed URL
  - Expiry support
  - Access control


### CSL-US-003 — Hash registry
**As a** system, **I want** to store hashes **so that** integrity is tracked.

**Acceptance Criteria:**
  - Store hash metadata
  - Lookup by hash
  - Prevent overwrites


### CSL-US-004 — Artifact retention
**As a** operator, **I want** retention policies **so that** storage is managed.

**Acceptance Criteria:**
  - TTL policies
  - Archive old artifacts
  - Retention audit


### CSL-US-005 — Access control
**As a** enterprise, **I want** access controls **so that** private data is protected.

**Acceptance Criteria:**
  - DID-based ACL
  - Revocation
  - Audit logs


### CSL-US-006 — Bundle viewer
**As a** user, **I want** preview bundles **so that** I can inspect quickly.

**Acceptance Criteria:**
  - Metadata view
  - Hash list
  - Download button


## 8) Success Metrics
- Artifacts stored
- Download success rate
- Storage cost

---

*Generated for Claw Bureau monorepo. All PRDs follow a uniform structure for Ralph execution.*
