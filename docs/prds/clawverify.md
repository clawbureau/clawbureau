> **Type:** PRD
> **Status:** ACTIVE
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-07
> **Source of truth:** `services/clawverify/{prd.json,progress.txt}` + `packages/schema/**`
>
> **Scope:**
> - Product requirements for clawverify (fail-closed verification service).
> - Shipped behavior is tracked in `services/clawverify/progress.txt`.

# clawverify.com (Verification API) — PRD

**Domain:** clawverify.com  
**Pillar:** Identity & Trust  
**Status:** Draft  

---

## Implementation status (current)

- **Active service:** `services/clawverify/`
- **Execution tracker:**
  - `services/clawverify/prd.json`
  - `services/clawverify/progress.txt`
- **Primary schemas (contracts):**
  - PoH bundles/receipts: `packages/schema/poh/*`
  - Owner attestations: `packages/schema/identity/owner_attestation.v1.json`
  - Commit proofs: `packages/schema/poh/commit_proof.v1.json`

---

## Tier semantics (current outputs)

`clawverify` exposes **two related tier concepts**:

1) `proof_tier` (canonical, marketplace-facing)
- Enum: `unknown | self | gateway | sandbox | tee | witnessed_web`
- Derived strictly from *verified* proof-bundle components (receipts + attestations).
- This is the tier that should align with marketplace `min_proof_tier` semantics.

2) `trust_tier` (verifier-internal)
- Enum: `unknown | basic | verified | attested | full`
- Derived from envelope validity + which components validated (URM/event_chain/receipts/attestations).
- Important nuance: an `event_chain`-only bundle may be `trust_tier=verified` but `proof_tier=self`.

**Endpoints:**
- `POST /v1/verify/bundle`
  - returns `result.trust_tier` and `result.proof_tier`
  - mirrors them at top-level as `trust_tier` and `proof_tier`
- `POST /v1/verify/agent` returns:
  - `trust_tier` (verifier-internal)
  - `proof_tier` (canonical)
  - `poh_tier` (numeric mapping of `proof_tier`):
    - `unknown=0, self=1, gateway=2, sandbox=3, tee=4, witnessed_web=5`

## 0) OpenClaw Fit (primary design target)
OpenClaw is the reference harness for Claw Bureau verification workflows.

`clawverify` should be consumable from OpenClaw as a **tool plugin** (and/or as an internal library), so OpenClaw can validate receipts/proof bundles during runs (or during post-run audits) without bespoke glue.

See: `docs/integration/OPENCLAW_INTEGRATION.md`.

See also (PoH vNext):
- `docs/roadmaps/proof-of-harness/DESIGN_model-identity-and-verifiable-audits.md`
- `docs/roadmaps/proof-of-harness/ROADMAP_vNext.md`
- `docs/foundations/decisions/0001-audit-pack-convention.md`

---

## 1) Purpose
Universal signature verifier for artifacts, messages, receipts, and attestations.

**Hard rule:** fail-closed on unknown `schema_id` / `version` / `envelope_type` / `algorithm`.

## 2) Target Users
- OpenClaw gateway operators
- OpenClaw plugin authors (provider/tool integration)
- Agents verifying work
- Platforms integrating verification
- Auditors

## 3) MVP Scope
- Artifact + message signature verification
- Receipt verification (gateway receipts)
- Proof bundle verification (URM + chain + receipts)
- Owner attestation verification
- Commit proof verification
- One-call agent verification
- Scoped token introspection

## 4) Non-Goals (v0)
- Full chain-of-custody storage
- On-chain verification

## 5) Dependencies
- clawlogs.com (audit logging, optional)
- clawsig.com (schema alignment)
- clawclaim.com (repo/identity claim registry)

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

---

### CVF-US-010 — Verify owner attestations
**As a** platform, **I want** owner verification **so that** sybil resistance is possible.

**Acceptance Criteria:**
- Validate owner attestation envelope
- Check expiry and provider reference
- Return verified/expired/unknown status

**Implementation notes (v1 guidance):**
- **Source of truth schema:** `packages/schema/identity/owner_attestation.v1.json`.
- Suggested endpoint: `POST /v1/verify/owner-attestation`.
- Semantics (deterministic):
  - `owner_status = VERIFIED` when the envelope is cryptographically valid **and** not expired.
  - `owner_status = EXPIRED` when cryptographically valid but `expires_at < now`.
  - `owner_status = UNKNOWN` when cryptographically valid and not expired, but the provider reference is missing/unsupported.
- Always fail-closed on unknown `owner_provider` / schema version.

### CVF-US-011 — Verify commit proofs
**As a** reviewer, **I want** commit proof verification **so that** agent work is trusted.

**Acceptance Criteria:**
- Validate commit proof envelope
- Ensure repo claim exists in clawclaim
- Return repo + commit + signer DID

**Implementation notes (v1 guidance):**
- **Source of truth schema:** `packages/schema/poh/commit_proof.v1.json`.
- Suggested endpoint: `POST /v1/verify/commit-proof`.
- Hard rules:
  - Fail-closed if `commit_sha` is not a 40-hex SHA.
  - Fail-closed if `repo_url` is not a valid URI.
  - Enforce `payload.agent_did === envelope.signer_did` (unless an explicit delegation model is introduced).
- Repo claim check:
  - **Fast-path:** accept an optional `repo_claim` object in the request so this can work before `clawclaim` is live.
  - **Best-path:** call `clawclaim` to resolve `repo_url -> active claim -> agent_did` and require a match.

### CVF-US-012 — One-call agent verification
**As a** platform, **I want** a single verify call **so that** integrations are easy.

**Acceptance Criteria:**
- Return DID validity + owner status + PoH tier
- Include policy compliance (if WPC present)
- Include risk flags (optional)

**Implementation notes (v1 guidance):**
- Suggested endpoint: `POST /v1/verify/agent`.
- Should compose existing verifiers (message, owner attestation, receipt / bundle) and return a single normalized response.
- **Fast-path:** only support `{ did, proof_bundle? }` and return `{ did_valid, proof_tier }` + optional `owner_status` when an attestation is provided.

### CVF-US-013 — Scoped token introspection
**As a** service, **I want** token introspection **so that** authorization is safe.

**Acceptance Criteria:**
- Validate token signature + expiry
- Return scope + audience + owner_ref
- Log token hash to clawlogs

**Implementation notes (v1 guidance):**
- **Source of truth schema:** `packages/schema/auth/scoped_token_claims.v1.json`.
- Suggested endpoint: `POST /v1/token/introspect` (RFC-7662-ish semantics).
- Response should be stable and safe for services to consume:
  - return `active: false` on failed signature/exp/aud/scope
  - return parsed claims when active

### CVF-US-014 — Public landing + skill docs
**As a** developer, **I want** public landing/docs/skill endpoints **so that** I can discover and integrate clawverify quickly.

**Acceptance Criteria:**
- GET / returns a small HTML landing page with links to /docs and /skill.md
- GET /skill.md returns integration docs + example curl commands
- GET /robots.txt and /sitemap.xml exist (minimal)
- GET /.well-known/security.txt exists

### CVF-US-015 — OpenClaw verification tool plugin
**As an** OpenClaw operator, **I want** a verification tool inside OpenClaw **so that** I can validate receipts/proof bundles during runs or post-run audits.

**Acceptance Criteria:**
- Provide an OpenClaw **tool slot** plugin that wraps core verification endpoints
- Provide an OpenClaw skill (`skills/clawverify/SKILL.md`) with examples (receipt, commit proof, proof bundle)
- Fail closed on unknown schema/version, matching Claw Bureau verifier semantics

### CVF-US-016 — Verify and surface model identity (tiered)
**As a** platform, **I want** clawverify to extract and validate tiered model identity from receipts/bundles **so that** integrations can gate on honest model identity strength.

**Acceptance Criteria:**
- Validate `payload.metadata.model_identity` against `packages/schema/poh/model_identity.v1.json` when present
- Compute and/or validate `model_identity_hash_b64u = sha256_b64u(JCS(model_identity))`
- Return `model_identity_tier` and deterministic risk flags (e.g. `MODEL_IDENTITY_OPAQUE`)
- Do not conflate model identity tier with PoH tier

### CVF-US-017 — Verify derivation attestations
**As a** verifier, **I want** to validate derivation attestations **so that** model transformations (quantize/fine-tune/merge) are traceable.

**Acceptance Criteria:**
- POST /v1/verify/derivation-attestation
- Fail closed on unknown schema/version/algo
- Validate optional clawlogs inclusion proof if supplied

### CVF-US-018 — Verify audit result attestations
**As a** regulator-facing auditor, **I want** to validate audit result attestations **so that** benchmark/audit claims are cryptographically checkable.

**Acceptance Criteria:**
- POST /v1/verify/audit-result-attestation
- Fail closed on unknown schema/version/algo
- Validate optional clawlogs inclusion proof if supplied
- Return a stable summary: audit status + audit_pack_hash_b64u (when present) + model identity tier + refs

### CVF-US-019 — Verify clawlogs inclusion proofs
**As a** third party, **I want** clawverify to validate clawlogs inclusion proofs **so that** transparency log anchoring can be checked offline.

**Acceptance Criteria:**
- Support validating `log_inclusion_proof.v1` objects (`packages/schema/poh/log_inclusion_proof.v1.json`)
- Verify Merkle path + signed root
- Expose deterministic error codes for invalid proofs

### CVF-US-020 — Verify-under-policy (WPC compliance)
**As a** security admin, **I want** verification to optionally enforce WPC requirements **so that** systems can fail closed on missing audits or insufficient model identity tiers.

**Acceptance Criteria:**
- /v1/verify/bundle and /v1/verify/agent accept an optional WPC ref (e.g., `policy_hash_b64u`)
- Verification output includes `policy_compliance` + per-requirement failures
- Verification fails closed when policy is supplied and requirements are not met

## 8) Success Metrics
- Verification success rate
- Median verification latency < 50ms
- % invalid envelopes detected

---

*Generated for Claw Bureau monorepo. All PRDs follow a uniform structure for Ralph execution.*
