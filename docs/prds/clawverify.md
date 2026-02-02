# clawverify.com (Verification API) — PRD

**Domain:** clawverify.com  
**Pillar:** Identity & Trust  
**Status:** Draft  

---

## 1) Purpose
Universal signature verifier for artifacts, messages, receipts, and attestations. Fail-closed on unknown schema/versions.

## 2) Target Users
- Agents verifying work
- Platforms integrating verification
- Auditors

## 3) MVP Scope
- POST /v1/verify for artifact signatures
- POST /v1/verify-message for message envelopes
- Receipt verification (gateway receipts)
- Proof bundle verification (URM + chain + receipts)
- Owner attestation verification
- Commit proof verification
- One-call agent verification
- Scoped token introspection
- Fail-closed validation (version/type/algo)

## 4) Non-Goals (v0)
- Full chain-of-custody storage
- On-chain verification

## 5) Dependencies
- clawlogs.com (audit logging, optional)
- clawsig.com (schema alignment)
- clawclaim.com (attestation registry)

## 6) Core User Journeys
- Agent submits a signed artifact → verifier returns VALID
- Platform validates receipt → trust tier increased
- Auditor batch-verifies archive of artifacts

## 7) User Stories
### CVF-US-001 — Verify artifact signatures
**As a** verifier, **I want** to validate artifact envelopes **so that** I can prove authorship.

**Acceptance Criteria:**
  - Reject unknown version/type/algo
  - Recompute hash and match envelope
  - Return VALID/INVALID with reason


### CVF-US-002 — Verify message signatures
**As a** platform, **I want** to validate signed messages **so that** I can bind DIDs to accounts.

**Acceptance Criteria:**
  - Support message_signature envelopes
  - Fail if signature invalid
  - Return signer DID


### CVF-US-003 — Verify gateway receipts
**As a** marketplace, **I want** to validate proxy receipts **so that** I can enforce proof-of-harness.

**Acceptance Criteria:**
  - Validate receipt signature
  - Check receipt schema
  - Return verified provider/model


### CVF-US-004 — Batch verification
**As a** auditor, **I want** to submit multiple envelopes **so that** I can verify at scale.

**Acceptance Criteria:**
  - POST /v1/verify/batch
  - Return per-item results
  - Limit batch size to prevent abuse


### CVF-US-005 — Verification provenance
**As a** compliance officer, **I want** verification results logged **so that** audits are traceable.

**Acceptance Criteria:**
  - Write hash-chained audit log entry
  - Include request hash + timestamp
  - Allow retrieval by receipt id


### CVF-US-006 — Public docs and schema registry
**As a** developer, **I want** clear verification docs **so that** I can integrate quickly.

**Acceptance Criteria:**
  - Publish schema versions
  - Provide example payloads
  - Include fail-closed rules


### CVF-US-007 — Verify proof bundles
**As a** marketplace, **I want** proof bundle verification **so that** trust tiers are automated.

**Acceptance Criteria:**
  - Validate URM + event chain + receipts + attestations
  - Fail closed on unknown schema/version
  - Return computed trust tier


### CVF-US-008 — Verify event chains
**As a** auditor, **I want** event chain verification **so that** logs are tamper-evident.

**Acceptance Criteria:**
  - Validate hash chain and root
  - Enforce run_id consistency
  - Return chain_root_hash and error codes


### CVF-US-009 — Schema registry allowlist
**As a** developer, **I want** a schema registry **so that** validation is deterministic.

**Acceptance Criteria:**
  - Publish allowlisted schema ids + versions
  - Reject unknown ids by default
  - Provide example payloads per schema


### CVF-US-010 — Verify owner attestations
**As a** platform, **I want** owner verification **so that** sybil resistance is possible.

**Acceptance Criteria:**
  - Validate owner attestation envelope
  - Check expiry and provider reference
  - Return verified/expired/unknown status


### CVF-US-011 — Verify commit proofs
**As a** reviewer, **I want** commit proof verification **so that** agent work is trusted.

**Acceptance Criteria:**
  - Validate commit proof envelope
  - Ensure repo claim exists in clawclaim
  - Return repo + commit + signer DID


### CVF-US-012 — One-call agent verification
**As a** platform, **I want** a single verify call **so that** integrations are easy.

**Acceptance Criteria:**
  - Return DID validity + owner status + PoH tier
  - Include policy compliance (if WPC present)
  - Include risk flags (optional)


### CVF-US-013 — Scoped token introspection
**As a** service, **I want** token introspection **so that** authorization is safe.

**Acceptance Criteria:**
  - Validate token signature + expiry
  - Return scope + audience + owner_ref
  - Log token hash to clawlogs


## 8) Success Metrics
- Verification success rate
- Median verification latency < 50ms
- % invalid envelopes detected

---

*Generated for Claw Bureau monorepo. All PRDs follow a uniform structure for Ralph execution.*
