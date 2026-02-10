> **Type:** PRD
> **Status:** DRAFT
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-07
> **Source of truth:** PRD intent (no active execution tracker yet)
>
> **Scope:**
> - Product requirements for `clawea.com`.
> - This domain has no service-level tracker yet; treat as aspirational until a roadmap/service tracker exists.

# clawea.com (Execution Attestation) — PRD

**Domain:** clawea.com  
**Pillar:** Labor & Delegation  
**Status:** Draft  

> **Note:** `clawea.com` is expanding into an enterprise agent platform (fleet orchestration + execution attestation). This file remains the **execution attestation** PRD slice.
>
> For the full enterprise PRD, see: `docs/prds/clawea-enterprise.md`.

---

## Implementation status (current)

- **Service:** not implemented yet (no service-level tracker found).
- **Tracking:** create a roadmap in `docs/roadmaps/` or a service tracker in `services/` when work starts.

---

## 1) Purpose
Safe execution layer (Moltworker-style) that produces run attestations.

## 2) Target Users
- Agents
- Enterprises
- Auditors

## 3) MVP Scope
- Sandbox runner
- Receipt bundle + event chain
- Artifact hashes
- Work Policy Contract enforcement
- Redaction pipeline + log root
- Egress mediation via clawproxy
- Scoped token auth (CST)
- Mission metadata binding

## 4) Non-Goals (v0)
- Proving closed-provider weight identity (OpenAI/Anthropic/Gemini). Use tiered `model_identity` instead.
- Full TEE v0

## 5) Dependencies
- clawproxy.com
- clawsilo.com
- clawverify.com
- clawscope.com

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


### CEA-US-007 — Attestation log root
**As a** verifier, **I want** log roots embedded **so that** audits are consistent.

**Acceptance Criteria:**
  - Include clawlogs log_root_hash in attestation
  - Include receipt hashes + artifact hashes
  - Provide bundle export for verification


### CEA-US-008 — Scoped token enforcement
**As a** platform, **I want** scoped tokens **so that** runs are authorized.

**Acceptance Criteria:**
  - Require CST token on run start
  - Validate audience + expiry + scope
  - Embed token_scope_hash in attestation


### CEA-US-009 — Mission metadata binding
**As a** operator, **I want** mission ids **so that** multi-agent runs are grouped.

**Acceptance Criteria:**
  - Accept mission_id on run start
  - Persist mission_id in URM and attestation
  - Emit mission_id in run events


## 8) Success Metrics
- Runs/day
- Attestation success rate
- Sandbox failures

---

*Generated for Claw Bureau monorepo. All PRDs follow a uniform structure for Ralph execution.*
