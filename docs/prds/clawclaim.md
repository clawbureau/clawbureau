> **Type:** PRD
> **Status:** ACTIVE
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-11
> **Source of truth:** `services/clawclaim/{prd.json,progress.txt}` + `packages/schema/identity/*`
>
> **Scope:**
> - Product requirements for clawclaim (DID binding + claims).
> - Shipped behavior is tracked in `services/clawclaim/progress.txt`.

# clawclaim.com (DID Binding) — PRD

**Domain:** clawclaim.com  
**Pillar:** Identity & Trust  
**Status:** Draft  

---

## Implementation status (current)

- **Active service:** `services/clawclaim/`
- **Execution tracker:**
  - `services/clawclaim/prd.json`
  - `services/clawclaim/progress.txt`
- **Related schemas (where applicable):**
  - Owner attestation: `packages/schema/identity/owner_attestation.v1.json`
  - Commit proof (for repo claims via clawverify): `packages/schema/poh/commit_proof.v1.json`

---

## 0) OpenClaw Fit (primary design target)
OpenClaw is the reference harness for Claw Bureau identity and trust flows.

`clawclaim` provides DID binding + external account claims in a form that an OpenClaw gateway (and its plugins/skills) can drive via challenge/response.

See: `docs/integration/OPENCLAW_INTEGRATION.md`.

---

## 1) Purpose
Bind DIDs to accounts and external platforms (GitHub, X, Moltbook) via challenge-response, with revocation and auditability suitable for OpenClaw multi-agent setups.

---

## 2) Target Users
- OpenClaw users (self-hosted gateways)
- OpenClaw plugin authors (identity + trust)
- Platforms consuming OpenClaw/Claw Bureau proofs
- Auditors

---

## 3) MVP Scope
- Challenge generation (purpose-aware: bind, revoke)
- Signature verification (initially `did:key` Ed25519)
- Bind/unbind DID
- Platform claim registry (GitHub/X/Moltbook)
- Owner attestation registry (provider-agnostic)
- Scoped token bootstrap (exchange DID proof → CST via clawscope)
- Org/team DID roster claims (future)

---

## 4) Non-Goals (v0)
- Full OAuth provider suite
- Acting as OpenClaw’s local agent identity system (OpenClaw already manages agent identity; clawclaim binds cryptographic identity to trust rails)

---

## 5) Dependencies
- clawverify.com (signature / proof verification)
- clawscope.com (CST issuance)
- clawlogs.com (audit logging; optional)
- clawcontrols.com (policy gates; optional)

---

## 6) Core User Journeys
- **OpenClaw agent DID setup** → user requests challenge → agent signs via DID Work tooling → bind DID
- DID is used to obtain scoped tokens for calling Claw Bureau services (clawscope)
- If keys are compromised: revoke binding → tokens stop working (revocation + policy gates)

---

## 7) User Stories

### CCL-US-001 — Challenge issuance
**As an** OpenClaw user, **I want** a binding challenge **so that** I can prove key control.

**Acceptance Criteria:**
  - Issue short-lived nonce
  - Store challenge
  - Expire after 10 minutes
  - Support purpose (`bind` default; `revoke` for revocations)


### CCL-US-002 — Bind DID
**As an** OpenClaw user, **I want** to bind my agent DID **so that** my identity is portable across Claw Bureau services.

**Acceptance Criteria:**
  - Verify signature
  - Store DID binding
  - Mark DID as active
  - (OpenClaw fit) allow storing `openclaw_agent_id` metadata for multi-agent gateways


### CCL-US-003 — Revoke binding
**As an** OpenClaw user, **I want** to revoke a DID **so that** compromised keys are disabled.

**Acceptance Criteria:**
  - Mark binding revoked
  - Prevent new sessions (block new bind challenges / token bootstrap for revoked DIDs)
  - Log audit event


### CCL-US-004 — Platform claims
**As an** OpenClaw user, **I want** to bind external accounts **so that** trust aggregates cross-platform.

**Acceptance Criteria:**
  - Support GitHub/X/Moltbook
  - Store proof URL
  - Verify via clawverify


### CCL-US-005 — Primary DID selection
**As an** OpenClaw user, **I want** to pick a primary DID **so that** my OpenClaw identity and receipts are consistent.

**Acceptance Criteria:**
  - Set is_primary flag
  - Only one primary per account
  - Expose in profile API


### CCL-US-006 — Binding audit trail
**As an** auditor, **I want** to inspect binding history **so that** identity claims are traceable.

**Acceptance Criteria:**
  - Append-only binding log
  - Include timestamps
  - Export for compliance


### CCL-US-007 — Owner attestation registry
**As a** platform, **I want** owner attestations **so that** sybil resistance is possible.

**Acceptance Criteria:**
  - Store owner attestation envelope (provider-agnostic)
  - Record expiry and verification level
  - Support OneMolt/WorldID lookup references


### CCL-US-008 — Scoped token issuance (CST)
**As an** OpenClaw plugin, **I want** scoped tokens **so that** agents can authenticate to Claw Bureau services safely.

**Acceptance Criteria:**
  - Exchange DID challenge for token issuance via clawscope
  - Issue short-lived tokens bound to DID + scope + audience
  - Include optional owner attestation reference
  - Log token hash + policy version to clawlogs


### CCL-US-009 — Org/team roster claims
**As a** team, **I want** roster claims **so that** roles can be verified.

**Acceptance Criteria:**
  - Register org/team DID + roster members
  - Issue signed roster manifest
  - Expose roster verification endpoint


### CCL-US-010 — OpenClaw tool plugin + skill workflow
**As an** OpenClaw user, **I want** a first-class workflow inside OpenClaw **so that** binding/revocation is easy and repeatable.

**Acceptance Criteria:**
  - Provide an OpenClaw **tool plugin** for clawclaim workflows (bind/revoke/claim)
  - Provide an OpenClaw **skill** (`skills/clawclaim/SKILL.md`) describing the flow
  - Support OpenClaw config schema (TypeBox) for base URLs + storage settings

---

## 8) Success Metrics
- Bindings created
- Binding success rate
- Revocations processed
- % of OpenClaw gateways with at least one bound DID

---

## 9) 2026-02-11 addendum — ICP-US-001 controller-first provisioning hard cutover

Shipped in `services/clawclaim/src/index.ts`:
- `POST /v1/control-plane/challenges`
- `POST /v1/control-plane/controllers/register`
- `POST /v1/control-plane/controllers/{controller_did}/agents/register`
- `POST /v1/control-plane/controllers/{controller_did}/sensitive-policy`
- deterministic chain read/list endpoints under `/v1/control-plane/controllers/*`

Delivery evidence:
- Deploys:
  - staging: `clawclaim-staging` version `7c1cf0b7-af77-4d21-b29d-b902055519a5`
  - prod: `clawclaim` version `4af46ea4-05b7-43de-ae1f-6f100b4fde56`
- Smoke artifacts:
  - staging: `artifacts/smoke/identity-control-plane/2026-02-11T21-47-01-985Z-staging/result.json`
  - prod: `artifacts/smoke/identity-control-plane/2026-02-11T21-47-11-161Z-prod/result.json`

---

## 10) 2026-02-11 addendum — CCL-US-013/014/015 claim lifecycle + portability

Shipped in `services/clawclaim/src/index.ts`:
- rotation continuity:
  - `POST /v1/control-plane/rotations/confirm`
- transfer state machine:
  - `POST /v1/control-plane/controllers/{controller_did}/transfer/request`
  - `POST /v1/control-plane/controllers/{controller_did}/transfer/confirm`
- identity bundle portability:
  - `POST /v1/control-plane/identity/export`
  - `POST /v1/control-plane/identity/import`

Contract highlights:
- challenge purposes extended for lifecycle operations (`confirm_rotation`, transfer request/confirm, export/import)
- controller state machine: `active -> transfer_pending -> transferred`
- transfer freeze semantics enforced with deterministic `CONTROLLER_TRANSFER_FROZEN`
- signed export/import contract uses `CLAIM_EXPORT_SIGNING_KEY` (HMAC-SHA256)

Validation evidence:
- unit tests: `services/clawclaim/test/claim-lifecycle-portability.test.ts`
- quality checks: `cd services/clawclaim && npm run typecheck && npm test`
- deploys:
  - staging: `clawclaim-staging` version `ace3a741-85e3-4fcb-b582-aac6993d974f`
  - prod: `clawclaim` version `2b45efe3-7bfd-48b2-a9c2-df5250f51488`
- smoke artifacts:
  - staging: `artifacts/smoke/identity-control-plane/2026-02-11T22-10-50-682Z-staging/result.json`
  - prod: `artifacts/smoke/identity-control-plane/2026-02-11T22-11-02-225Z-prod/result.json`

---

*Generated for Claw Bureau monorepo. All PRDs follow a uniform structure for Ralph execution.*
