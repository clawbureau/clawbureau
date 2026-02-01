# clawsig.com (Signing UX) — PRD

**Domain:** clawsig.com  
**Pillar:** Identity & Trust  
**Status:** Draft  

---

## 1) Purpose
Key management + signing UX, including key rotation and optional custodial/HSM support.

## 2) Target Users
- Agents
- Enterprises needing custody
- Auditors

## 3) MVP Scope
- Key generation and rotation
- Artifact/message signing UI
- DID export
- Signature validation against clawverify

## 4) Non-Goals (v0)
- Full HSM integration v0
- On-chain signing

## 5) Dependencies
- clawverify.com
- clawclaim.com

## 6) Core User Journeys
- User creates DID → signs artifact → verifies
- User rotates key and preserves continuity

## 7) User Stories
### CSG-US-001 — Create DID identity
**As a** user, **I want** to generate a DID **so that** I can sign my work.

**Acceptance Criteria:**
  - Generate ed25519 keypair
  - Display did:key
  - Store encrypted key


### CSG-US-002 — Sign artifacts
**As a** user, **I want** to sign a file **so that** others can verify it.

**Acceptance Criteria:**
  - Create signature envelope
  - Use RFC 8785 canonicalization
  - Save .sig.json


### CSG-US-003 — Sign messages
**As a** user, **I want** to sign challenges **so that** I can bind accounts.

**Acceptance Criteria:**
  - Create message_signature envelope
  - Include metadata
  - Verify with clawverify


### CSG-US-004 — Key rotation
**As a** user, **I want** to rotate keys **so that** compromise doesn’t break identity.

**Acceptance Criteria:**
  - Generate new keypair
  - Produce rotation certificate
  - Verify continuity


### CSG-US-005 — Export identity manifest
**As a** user, **I want** to export my DID **so that** I can use it elsewhere.

**Acceptance Criteria:**
  - Export JSON manifest
  - Include public key
  - Include bindings list


### CSG-US-006 — Custodial signing (enterprise)
**As a** enterprise, **I want** optional custody **so that** keys are managed centrally.

**Acceptance Criteria:**
  - Admin-controlled key policies
  - Audit log of signings
  - Role-based access


## 8) Success Metrics
- DIDs created
- Signatures generated
- Rotation success rate

---

*Generated for Claw Bureau monorepo. All PRDs follow a uniform structure for Ralph execution.*
