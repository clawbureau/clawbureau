# clawclaim.com (DID Binding) — PRD

**Domain:** clawclaim.com  
**Pillar:** Identity & Trust  
**Status:** Draft  

---

## 1) Purpose
Bind DIDs to accounts and external platforms (GitHub, X, Moltbook) via challenge-response.

## 2) Target Users
- Agents
- Platforms
- Auditors

## 3) MVP Scope
- Challenge generation
- Signature verification
- Bind/unbind DID
- Platform claim registry

## 4) Non-Goals (v0)
- Full OAuth provider suite v0

## 5) Dependencies
- clawverify.com
- clawlogs.com

## 6) Core User Journeys
- User requests challenge → signs → bind DID
- User binds GitHub by signed gist

## 7) User Stories
### CCL-US-001 — Challenge issuance
**As a** user, **I want** a binding challenge **so that** I can prove key control.

**Acceptance Criteria:**
  - Issue short-lived nonce
  - Store challenge
  - Expire after 10 minutes


### CCL-US-002 — Bind DID
**As a** user, **I want** to bind my DID **so that** my identity is portable.

**Acceptance Criteria:**
  - Verify signature
  - Store DID binding
  - Mark DID as active


### CCL-US-003 — Revoke binding
**As a** user, **I want** to revoke a DID **so that** compromised keys are disabled.

**Acceptance Criteria:**
  - Mark binding revoked
  - Prevent new sessions
  - Log audit event


### CCL-US-004 — Platform claims
**As a** user, **I want** to bind external accounts **so that** trust aggregates cross-platform.

**Acceptance Criteria:**
  - Support GitHub/X/Moltbook
  - Store proof URL
  - Verify via clawverify


### CCL-US-005 — Primary DID selection
**As a** user, **I want** to pick a primary DID **so that** my profile is consistent.

**Acceptance Criteria:**
  - Set is_primary flag
  - Only one primary per account
  - Expose in profile API


### CCL-US-006 — Binding audit trail
**As a** auditor, **I want** to inspect binding history **so that** identity claims are traceable.

**Acceptance Criteria:**
  - Append-only binding log
  - Include timestamps
  - Export for compliance


## 8) Success Metrics
- Bindings created
- Binding success rate
- Revocations processed

---

*Generated for Claw Bureau monorepo. All PRDs follow a uniform structure for Ralph execution.*
