> **Type:** PRD
> **Status:** DRAFT
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-12
> **Source of truth:** `services/clawcontrols/prd.json` + `services/clawcontrols/progress.txt` + `docs/roadmaps/trust-vnext/{prd.json,progress.txt}`
>
> **Scope:**
> - Product requirements for `clawcontrols.com`.
> - Service tracker lives in `services/clawcontrols/{prd.json,progress.txt}`.

# clawcontrols.com (Policy Controls) — PRD

**Domain:** clawcontrols.com  
**Pillar:** Governance & Risk Controls  
**Status:** Draft  

---

## Implementation status (current)

- **Service:** implemented (initial MVP) at `services/clawcontrols/`.
- **Tracking:**
  - Trust vNext roadmap: `docs/roadmaps/trust-vnext/{prd.json,progress.txt}`
  - Service tracker:
    - `services/clawcontrols/prd.json`
    - `services/clawcontrols/progress.txt`
- **Shipped (CCO-US-021):** signed Work Policy Contract (WPC) registry API:
  - `POST /v1/wpc` (admin-gated)
  - `GET /v1/wpc/:policy_hash_b64u`

---

## 0) OpenClaw Fit (primary design target)
OpenClaw already has a strong local policy system (tool allow/deny profiles + sandboxing). `clawcontrols` should complement this by:
- hosting **portable policy contracts** (e.g., Work Policy Contracts / WPC)
- providing a translation layer so OpenClaw can map WPC → tool policy restrictions deterministically
- hosting token policy tiers used by `clawscope`

See: `docs/integration/OPENCLAW_INTEGRATION.md`.

See also (PoH vNext):
- `docs/roadmaps/proof-of-harness/DESIGN_model-identity-and-verifiable-audits.md`
- `docs/roadmaps/proof-of-harness/ROADMAP_vNext.md`
- `docs/foundations/decisions/0001-audit-pack-convention.md`

---

## 1) Purpose
Policy engine for spend caps, allowlists, and kill switches.

## Protocol alignment (Claw Protocol v0.1)

- Canonical narrow-waist spec: `docs/specs/claw-protocol/CLAW_PROTOCOL_v0.1.md`
- `clawcontrols` is the reference **Policy Artifact (WPC)** registry and governance surface.
- Protocol requirement: policy artifacts are signed, immutable, and content-addressed; updates require publishing a new artifact (new hash), not mutation.

## 2) Target Users
- OpenClaw gateway operators
- Operators
- Enterprises

## 3) MVP Scope
- Spend caps
- Allowlist rules
- Global kill switch
- Dispute parameter registry
- Reserve impairment circuit breaker
- Trials kill switches
- Token policy registry (CST)
- Owner-verified gating rules

## 4) Non-Goals (v0)
- Full IAM v0

## 5) Dependencies
- clawledger.com
- clawrep.com

## 6) Core User Journeys
- Admin sets caps → enforced on transactions

## 7) User Stories
### CCO-US-001 — Spend caps
**As a** admin, **I want** to set caps **so that** risk is limited.

**Acceptance Criteria:**
  - Daily cap
  - Per-tx cap
  - Enforced server-side


### CCO-US-002 — Allowlist rules
**As a** admin, **I want** allowlists **so that** only trusted agents act.

**Acceptance Criteria:**
  - Allowlist by DID
  - Apply to services
  - Audit changes


### CCO-US-003 — Kill switch
**As a** operator, **I want** global halt **so that** incidents are contained.

**Acceptance Criteria:**
  - Disable transfers
  - Status banner
  - Require quorum


### CCO-US-004 — Policy simulation
**As a** admin, **I want** simulate policies **so that** changes are safe.

**Acceptance Criteria:**
  - Simulate actions
  - Show allow/deny
  - No mutations


### CCO-US-005 — Policy API
**As a** platform, **I want** policy endpoints **so that** I can enforce rules.

**Acceptance Criteria:**
  - GET /policies
  - POST /policies
  - Webhook on changes


### CCO-US-006 — Audit logs
**As a** auditor, **I want** policy change logs **so that** controls are traceable.

**Acceptance Criteria:**
  - Log changes
  - Include actor
  - Export logs


### CCO-US-007 — Dispute parameter registry
**As a** operator, **I want** dispute configs **so that** trials are consistent.

**Acceptance Criteria:**
  - Define bonds, deadlines, quorum rules
  - Version parameter sets
  - Expose registry API


### CCO-US-008 — Trials kill switch
**As a** safety officer, **I want** to halt trials **so that** incidents are contained.

**Acceptance Criteria:**
  - Disable new trial creation
  - Allow ongoing cases to finish or pause
  - Require quorum override to re-enable


### CCO-US-009 — Reserve impairment circuit breaker
**As a** finance operator, **I want** reserve gates **so that** cash-out is safe.

**Acceptance Criteria:**
  - Disable cash-out when reserve coverage drops below threshold
  - Publish impairment notice
  - Log override actions with quorum


### CCO-US-010 — Token policy registry
**As a** platform, **I want** token policies **so that** CST scopes are controlled.

**Acceptance Criteria:**
  - Define max TTL + allowed scopes per tier
  - Enforce audience restrictions per service
  - Provide policy simulation endpoint


### CCO-US-011 — Owner-verified gating
**As a** platform, **I want** owner verification gates **so that** sybil attacks are reduced.

**Acceptance Criteria:**
  - Configure actions requiring owner-verified status
  - Provide rate-limit multipliers by owner status
  - Log enforcement decisions


### CCO-US-012 — WPC requirements: model identity tier + audit packs
**As a** security admin, **I want** WPC to express minimum model identity tiers and required audit packs **so that** sensitive workflows fail closed when only opaque model identity is available.

**Acceptance Criteria:**
  - WPC supports `minimum_model_identity_tier` (e.g. closed_opaque|closed_provider_manifest|openweights_hashable|tee_measured)
  - WPC supports `required_audit_packs` by deterministic `audit_pack_hash_b64u` (see ADR 0001)
  - Provide policy simulation for these constraints (builds on CCO-US-004)
  - Enforcement points are explicit (clawproxy, clawea runner, clawverify)

### CCO-US-013 — WPC protocol pins + capability/receipt binding semantics
**As a** protocol implementer, **I want** standardized policy hash pinning semantics **so that** capabilities and receipts can prove which policy governed a run.

**Acceptance Criteria:**
  - Define canonical `policy_hash_b64u` computation and stability guarantees
  - Define how CSTs can pin to a `policy_hash_b64u` (policy pin)
  - Define how receipts/bundles reference the enforced policy hash at time of action
  - Document fail-closed guidance for required policy pins when missing/mismatched

## 8) Success Metrics
- Policy changes
- Violations blocked
- Kill switch usage

---

*Generated for Claw Bureau monorepo. All PRDs follow a uniform structure for Ralph execution.*
