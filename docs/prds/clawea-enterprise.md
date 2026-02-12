> **Type:** PRD
> **Status:** DRAFT
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-12
> **Source of truth:** This PRD (product intent). Implementation tracking lives in service repos/worktrees when built.
>
> **Scope:**
> - Enterprise agent platform on `clawea.com` (managed OpenClaw-in-Sandbox fleets) plus execution attestation features.
> - This is the *enterprise wrapper* around the existing execution-attestation slice (`docs/prds/clawea.md`).

# clawea.com (Enterprise Agents) — PRD

**Domain:** clawea.com  
**Pillar:** Infrastructure / Enterprise  
**Status:** Draft  

> **Canonical for enterprise:** This file.
>
> **Execution-attestation slice:** `docs/prds/clawea.md` (kept for backwards compatibility and for PRD readers who only care about attestations).

Related trust design + roadmap:
- `docs/roadmaps/proof-of-harness/DESIGN_model-identity-and-verifiable-audits.md`
- `docs/roadmaps/proof-of-harness/ROADMAP_vNext.md`

---

## Implementation status (current)

- **Implementation:** Not yet implemented in this monorepo (enterprise control plane/data plane work happens in dedicated service repos/worktrees).
- **Staging origin (canonical):** https://staging.clawea.com
- **Fallback staging mount (temporary):** https://clawea.com/staging/*
- **Primary PoH contracts (schemas):**
  - Model identity: `packages/schema/poh/model_identity.v1.json`
  - Gateway receipts: `packages/schema/poh/gateway_receipt.v1.json`
  - Proof bundle: `packages/schema/poh/proof_bundle.v1.json`
  - Execution attestation: `packages/schema/poh/execution_attestation.v1.json`
- **Roadmap (PoH evidence slice):** `docs/roadmaps/proof-of-harness/ROADMAP_vNext.md`
- **Protocol (narrow waist):**
  - Spec: `docs/specs/clawsig-protocol/CLAWSIG_PROTOCOL_v0.1.md`
  - Roadmap: `docs/roadmaps/clawsig-protocol/`

---

## 0) Thesis

Enterprises want OpenClaw-like agents, but they require:
- **policy enforcement** (WPC)
- **verifiable execution evidence** (PoH + execution attestations)
- **audit-ready exports** (offline verification)
- **billing + governance**

clawea is the managed control plane + data plane for this.

---

## 1) Purpose

Provision, manage, and orchestrate fleets of OpenClaw-in-Sandbox instances for enterprise tenants.

Every agent deployed through clawea should be pre-wired for:
- `clawproxy` egress (gateway receipts)
- `clawcontrols` enforcement (WPC)
- `clawscope` tokens (CST)
- PoH exports + execution attestations

---

## 2) Target users
- Enterprise IT admins
- Security / compliance
- Team leads (operators)
- Developers (skills + integrations)
- Finance

---

## 3) MVP scope

### Control plane
- Tenant provisioning
- Agent templates (opinionated defaults)
- Agent lifecycle: deploy/health/sleep/wake/destroy
- Secret injection (provider keys, gateway tokens)
- Usage metering (compute, tokens, verification)

### Data plane
- Cloudflare Sandbox/Containers execution
- R2-backed persistence per tenant (where allowed)
- Default-deny egress (WPC)

### Trust slice (must-have)
- PoH proof bundles per run
- Hardened execution attestations for sandbox tier
- Audit-ready export bundles

---

## 4) Non-goals (v0)
- On-prem deployment
- Proving closed-provider model weights (use model identity tiers)
- Full TEE-based confidential audits in v0

---

## 5) Dependencies
- `clawproxy` — receipts + WPC enforcement
- `clawverify` — proof bundle + attestation verification
- `clawcontrols` — WPC registry + policy constraints
- `clawscope` — CST issuance + revocation
- `clawlogs` — transparency log (optional MVP; strongly recommended for enterprise)
- `clawsilo` / tenant R2 — artifact storage

---

## 6) Core user journeys

### A) Onboarding
1) Admin creates tenant
2) Admin sets WPC defaults
3) Admin deploys first agent from a template

### B) Compliance audit
1) Auditor lists runs
2) Auditor opens a run detail
3) Auditor exports an offline audit bundle

---

## 7) User stories (selected)

### Agent lifecycle

#### CEA-US-010 — Deploy agent from template
**As an** enterprise admin, **I want** to deploy an agent from a template **so that** I get a pre-configured assistant.

**Acceptance Criteria:**
- POST /v1/agents with template_id + config overrides
- Container starts in CF Sandbox within ~2 minutes
- Agent automatically routes all LLM calls through clawproxy

#### CEA-US-012 — Agent health monitoring
**As an** enterprise admin, **I want** to see agent health **so that** I know everything is running.

**Acceptance Criteria:**
- GET /v1/agents/:id/health returns status + last_active + basic resource usage
- Fleet summary endpoint exists

### Policy + governance

#### CEA-US-030 — Assign WPC to agent
**As a** security admin, **I want** to assign a Work Policy Contract **so that** agent behavior is governed.

**Acceptance Criteria:**
- PATCH /v1/agents/:id/policy sets WPC hash
- WPC is enforced in the runtime (not advisory)

### Governance UX (two-phase by default)

#### CEA-US-050 — Two-phase execution default (plan/diff → apply)
**As a** human operator, **I want** two-phase execution to be the default **so that** governance is simple and safe.

**Acceptance Criteria:**
- Phase A (plan) is always allowed: read-only + plan + produce artifacts/diffs
- Phase B (apply) requires an explicit capability (CST scopes) to perform side-effects
- The plan output enumerates intended side-effects (repo writes, network egress, emails, etc.) in a deterministic format
- Fail-closed: if apply capability is missing/invalid, phase B is denied with deterministic reason codes

#### CEA-US-051 — One approval card + scoped delegation (Slack/Teams/GitHub)
**As a** human operator, **I want** a single approval card **so that** I can approve once without reading logs.

**Acceptance Criteria:**
- Approval card lists: intended actions, risk flags, cost/time estimate
- Buttons: Approve once, Approve for scope (time-bound), Deny
- On approval, mint a new CST pinned to scope + optional WPC hash and emit a verifiable approval receipt
- Denials are deterministic and machine-readable (agent can adapt)

#### CEA-US-052 — Shareable verified run summary
**As a** stakeholder, **I want** a shareable run artifact **so that** trust is legible without reconstruction.

**Acceptance Criteria:**
- Each run produces a summary: VERIFIED PASS/FAIL under WPC hash + scope hash
- Summary links to the proof bundle (and export bundle when available)
- Summary includes a “what changed” diff link (GitHub) and redacted side-effect summary (when applicable)

#### CEA-US-053 — Verify-lite preflight for compliance
**As an** agent, **I want** verify-lite preflight **so that** I can self-check compliance before executing.

**Acceptance Criteria:**
- Standard preflight endpoint or tool exists that answers: “would scope X be allowed under policy Y?”
- Preflight returns deterministic denial codes (no freeform text-only failures)
- Preflight can be used in CI to prevent non-compliant runs

### Compliance / evidence

#### CEA-US-032 — Audit dashboard
**As a** compliance officer, **I want** an audit dashboard **so that** I can prove agent behavior to regulators.

**Acceptance Criteria:**
- View all agent runs with timestamps
- Each run links to proof bundle, receipts, artifacts, WPC-at-time-of-run
- Export report

#### CEA-US-033 — Execution attestation emission (hardened sandbox)
**As a** compliance officer, **I want** each clawea run to produce an execution attestation bound to the runtime environment **so that** the `sandbox` PoH tier has concrete meaning.

**Acceptance Criteria:**
- Each run has a stable `run_id` and links to its proof artifacts
- clawea produces a `SignedEnvelope<execution_attestation.v1>` for the run
- `execution_attestation.runtime_metadata` includes (minimum):
  - container image digest
  - sandbox runtime version
  - enforced WPC hash (and/or network posture summary)
  - resource limits (cpu/mem)
  - optional clawlogs anchoring (root hash + inclusion proof)

#### CEA-US-034 — Audit-ready export bundles (offline verification)
**As an** auditor, **I want** a single export bundle per run **so that** verification works offline and evidence is court/regulator friendly.

**Acceptance Criteria:**
- Export bundle contains:
  - proof bundle (and materialized URM when needed)
  - execution attestation envelope
  - any attached audit_result_attestation / derivation_attestation artifacts (when present)
  - clawlogs inclusion proofs (when clawlogs enabled)
- Bundle includes a manifest listing `{path,sha256_b64u,content_type,size_bytes}` for each file
- Bundle is itself signed and content-addressed
- Bundle verifies via `clawverify` endpoint: `POST /v1/verify/export-bundle` (offline path; no external fetches required)

#### CEA-US-035 — Stateless execution mode (policy-gated)
**As a** security admin, **I want** stateless execution mode for sensitive runs **so that** prompt residue and covert channels are reduced.

**Acceptance Criteria:**
- WPC can require stateless mode
- When enabled, clawea runs the job in a fresh sandbox/container with no persistence
- Execution attestation includes a deterministic statelessness claim in `runtime_metadata`

---

## 8) API sketch (v1)

```
# Audit
GET /v1/audit/runs
GET /v1/audit/runs/:id
GET /v1/audit/runs/:id/export
```
