> **Type:** PRD
> **Status:** ACTIVE
> **Owner:** @clawbureau/infra
> **Last reviewed:** 2026-02-12
> **Source of truth:** `services/clawscope/{prd.json,progress.txt}` + `packages/schema/auth/scoped_token_claims.v1.json`
>
> **Scope:**
> - Product requirements for clawscope (CST issuance/introspection/revocation).
> - Shipped behavior is tracked in `services/clawscope/progress.txt`.

# clawscope.com (Scope + Observability) — PRD

**Domain:** clawscope.com  
**Pillar:** Infrastructure  
**Status:** Draft  

---

## Implementation status (current)

- **Active service:** `services/clawscope/`
- **Execution tracker:**
  - `services/clawscope/prd.json`
  - `services/clawscope/progress.txt`
- **Primary schema (contract):** `packages/schema/auth/scoped_token_claims.v1.json`

---

## 0) OpenClaw Fit (primary design target)
OpenClaw is the **reference harness** for Claw Bureau services.

`clawscope` is the **central scoped-token issuer** (CST) used by OpenClaw extensions (tool/provider plugins) to authenticate to Claw Bureau services such as `clawproxy`.

See: `docs/integration/OPENCLAW_INTEGRATION.md`.

---

## 1) Purpose
Define and enforce scoped token access (CST), issue/introspect/revoke tokens, and provide auditability suitable for OpenClaw multi-agent + multi-session operation.

## Protocol alignment (Claw Protocol v0.1)

- Canonical narrow-waist spec: `docs/specs/claw-protocol/CLAW_PROTOCOL_v0.1.md`
- `clawscope` is the reference **Capability Token (CST)** primitive.
- Protocol requirements: short TTL, deterministic scope hashing, optional policy hash pinning, and deterministic denial semantics.
- Protocol identity is bring-your-own; DID is supported but must not be the only viable subject model.

---

## 2) Target Users
- OpenClaw gateway operators (self-hosted)
- OpenClaw plugin authors (tool + provider plugins)
- Claw Bureau service operators
- Auditors (post-incident analysis)

---

## 3) MVP Scope
**Security primitives (v0):**
- Scoped token issuance (CST, Ed25519 / EdDSA JWT)
- JWKS/public key discovery + rotation
- Token introspection (RFC-7662-ish semantics) + revocation
- Policy enforcement (tiered allowlists, max TTL)
- Minimal audit export (issuance + revocations)

**Observability primitives (v0):**
- Mission/run correlation fields (support OpenClaw `sessionKey`/run ids)

**Later (post-v0):**
- Metrics dashboards, usage reports, alerting, cost analytics

---

## 4) Non-Goals (v0)
- Replacing OpenClaw’s local tool-policy/sandboxing system
- Full IAM / OAuth provider suite
- Full APM suite

---

## 5) Dependencies
- clawclaim.com (DID binding; token bootstrap without long-lived secrets)
- clawcontrols.com (policy registry; future)
- clawlogs.com (optional audit sink; future)
- clawproxy.com (primary consumer)

---

## 6) Core User Journeys
- **OpenClaw plugin requests CST** → uses it to call a Claw Bureau service → verifier validates via JWKS (fast path) or introspection (revocation-aware path)
- Operator revokes compromised tokens → OpenClaw integrations fail closed

---

## 7) User Stories

### CSC-US-001 — Issue scoped tokens
**As an** OpenClaw gateway/plugin, **I want** time-bound tokens **so that** external service calls are safe and don’t require long-lived secrets.

**Acceptance Criteria:**
  - Issue tokens bound to **agent DID** (`sub`) + **audience** (`aud`) + **scope[]**
  - Support optional `payment_account_did` claim for machine-payment account binding
  - Enforce TTL and max scope length
  - Return token hash + policy version
  - Support OpenClaw correlation via `mission_id` (recommended default = OpenClaw `sessionKey`)


### CSC-US-002 — Token introspection
**As a** Claw Bureau service, **I want** introspection **so that** I can enforce authorization consistently.

**Acceptance Criteria:**
  - Validate signature + expiry
  - Return scope + audience + owner_ref + payment_account_did (when present)
  - Fail closed on unknown version
  - Support revocation-aware `active:false` response


### CSC-US-003 — Token revocation
**As an** OpenClaw operator, **I want** revocation **so that** compromises stop quickly.

**Acceptance Criteria:**
  - Revoke tokens immediately
  - Broadcast revocation events (event feed)
  - Provide audit log


### CSC-US-004 — Policy enforcement
**As an** OpenClaw operator, **I want** policy checks **so that** tokens stay narrow and predictable.

**Acceptance Criteria:**
  - Enforce allowed scopes per tier
  - Enforce max TTL per policy
  - Reject tokens that exceed limits


### CSC-US-005 — JWKS / public keys
**As a** verifier (OpenClaw plugin or external service), **I want** key discovery **so that** verification is offline, fast, and cacheable.

**Acceptance Criteria:**
  - Publish JWKS endpoint
  - Rotate keys with versioning (multi-key JWKS)
  - Cache-control headers


### CSC-US-006 — Token audit trail
**As an** auditor, **I want** logs **so that** issuance and revocation are traceable back to OpenClaw runs.

**Acceptance Criteria:**
  - Log token hash + issuance metadata (incl. `mission_id` when present)
  - Store revocation timestamps
  - Export audit bundles


### CSC-US-007 — Metrics dashboard
**As an** operator, **I want** real-time metrics **so that** I can monitor health.

**Acceptance Criteria:**
  - Service metrics
  - Latency charts
  - Error rates


### CSC-US-008 — Usage reports
**As an** OpenClaw operator, **I want** usage reports **so that** I can understand token/service usage.

**Acceptance Criteria:**
  - Daily usage
  - Export CSV
  - Segment by service


### CSC-US-009 — Alerting
**As an** operator, **I want** alerts **so that** I can respond quickly.

**Acceptance Criteria:**
  - Threshold alerts
  - Email/Slack
  - Ack workflow


### CSC-US-010 — Cost analytics
**As a** finance operator, **I want** cost analytics **so that** budgets are managed.

**Acceptance Criteria:**
  - Cost by service
  - Trend charts
  - Forecasting


### CSC-US-011 — Trace viewer
**As an** engineer, **I want** tracing **so that** I can debug issues.

**Acceptance Criteria:**
  - Trace search
  - Span view
  - Correlation IDs


### CSC-US-012 — SLA reports
**As an** enterprise, **I want** SLA reports **so that** compliance is proven.

**Acceptance Criteria:**
  - SLA metrics
  - Downtime logs
  - Export reports


### CSC-US-013 — Mission aggregation
**As an** OpenClaw operator, **I want** mission rollups **so that** multi-agent work is visible.

**Acceptance Criteria:**
  - Group spend and receipts by mission_id
  - Show per-role and per-agent breakdowns
  - Export mission summary reports

### CSC-US-019 — Job-bound CSTs + WPC policy-hash pinning
**As a** security owner, **I want** CSTs to be job-bound and optionally policy-pinned **so that** capabilities cannot be replayed across unrelated runs.

**Acceptance Criteria:**
  - Token claims support an explicit job/run binding field (e.g. `run_id` or `job_id`) when required by policy
  - Token claims support optional `policy_hash_b64u` pinning
  - Downstream services can deterministically enforce binding and return stable mismatch codes
  - Acceptance tests: replay across jobs denied; policy pin mismatch denied; correct binding passes

### CSC-US-020 — Capability negotiation / preflight API
**As an** agent, **I want** to request capabilities and get deterministic denials **so that** I can adapt automatically.

**Acceptance Criteria:**
  - Provide a standard request shape: `{ scope, reason, evidence_required }`
  - Denials include machine-readable reason codes (e.g., `DENIED_POLICY`, `DENIED_SCOPE`)
  - Provide a verify-lite / preflight mode that answers “would this scope be allowed?” without minting a token
  - Acceptance tests: same request yields same denial code under same policy

### CSC-US-021 — Approval-minted capabilities (human approval receipts)
**As a** human operator, **I want** one approval moment to mint a new CST **so that** governance is low-friction and auditable.

**Acceptance Criteria:**
  - Support exchanging a verifiable approval receipt into a short-lived CST
  - Approval receipt binds to the minted token via deterministic scope + optional policy pin
  - Emit deterministic audit records for approvals and minted tokens
  - Acceptance tests: invalid approval receipt denied; valid approval receipt mints token; replay is idempotent or denied deterministically

---

## 8) Success Metrics
- Tokens issued/day
- Introspection latency
- Revocation time
- % offline JWKS verifications vs introspection
- Audit export success rate

---

## 9) 2026-02-11 addendum — ICP-US-002 canonical CST lane hard cutover

Shipped in `services/clawscope/src/index.ts`:
- canonical issuance: `POST /v1/tokens/issue/canonical`
- migration-gated legacy issuance: `POST /v1/tokens/issue` (`SCOPE_LEGACY_EXCHANGE_MODE`)
- sensitive transition matrix: `POST /v1/tokens/introspect/matrix`
- revocation stream contract: `GET /v1/revocations/stream`
- key overlap contract: `GET /v1/keys/rotation-contract`

Schema contract updates:
- `packages/schema/auth/scoped_token_claims.v1.json` now includes canonical chain claims (`owner_did`, `controller_did`, `agent_did`), `control_plane_policy_hash_b64u`, and `token_lane`.

Delivery evidence:
- Deploys:
  - staging: `clawscope-staging` version `37e14c8f-1016-4b5e-b117-70dd372e0131`
  - prod: `clawscope` version `2edbae03-adf5-4b8a-8cce-74ff3613cd79`
- Smoke artifacts:
  - staging: `artifacts/smoke/identity-control-plane/2026-02-11T21-47-01-985Z-staging/result.json`
  - prod: `artifacts/smoke/identity-control-plane/2026-02-11T21-47-11-161Z-prod/result.json`

---

## 10) 2026-02-11 addendum — CSC-US-016/017/018 key interoperability hardening

Shipped in `services/clawscope/src/index.ts`:
- verify-only overlap key support via `SCOPE_VERIFY_PUBLIC_KEYS_JSON`
- deterministic overlap expiry error: `TOKEN_KID_EXPIRED`
- introspection diagnostics: `kid`, `kid_source`
- key overlap contract v2 (`GET /v1/keys/rotation-contract`):
  - `signing_kids`
  - `verify_only_kids`
  - `expiring_kids`
- JWKS now serves only currently accepted keys in overlap window.

Operational unblock:
- Staging/prod active signing key aligned to one kid.
- Legacy staging kid retained as verify-only overlap key with explicit expiry for deterministic cutover.

Validation evidence:
- unit tests: `services/clawscope/test/key-kid-interop.test.ts`
- interop smoke: `scripts/identity/smoke-scope-kid-interop.mjs`
- operational runbook: `scripts/identity/RUNBOOK-identity-control-plane-operations.md`
- artifacts:
  - `artifacts/smoke/identity-control-plane/2026-02-11T22-43-00-300Z-kid-interop/result.json`
- updated deploys:
  - staging: `clawscope-staging` version `30cb1291-9cf1-467d-ac2c-f697a9a7b422`
  - prod: `clawscope` version `b45c4100-8ba5-44ba-b2e6-e715329bc744`

Compatibility note for Agent C:
- published note: `scripts/identity/COMPATIBILITY-NOTE-AGENT-C-token-kid.md`
- downstream token-control/introspection consumers should treat:
  - `TOKEN_UNKNOWN_KID` => reissue token / refresh overlap contract
  - `TOKEN_KID_EXPIRED` => token cannot be recovered; must reissue with active key

---

## 11) 2026-02-11 addendum — ICP-M5 observability/control reporting (CSC-US-007..013)

Shipped in `services/clawscope/src/observability.ts` + integration in `services/clawscope/src/index.ts`:
- Dashboard + reporting:
  - `GET /v1/metrics/dashboard`
  - `POST /v1/reports/rollups/run`
  - `GET /v1/reports/usage` (`format=json|csv`)
  - `GET /v1/reports/sla`
  - `GET /v1/analytics/cost`
  - `GET /v1/missions/aggregate`
- Alerting + traces:
  - `POST /v1/alerts/rules`
  - `GET /v1/alerts/events`
  - `GET /v1/traces/{trace_id}`
  - `GET /v1/traces?correlation_id=...`
- Runtime event ingestion:
  - token issue/revoke/introspect/matrix routes emit observability events (best-effort)
  - queue consumer persists events to D1 + updates trace index
  - scheduled/manual rollups materialize daily usage/cost/mission/SLA tables

Cloudflare-native stack used:
- D1: `SCOPE_OBSERVABILITY_DB` (`clawscope-observability`, `clawscope-observability-staging`)
- Queues: `SCOPE_OBS_EVENTS` (`clawscope-obs-events`, `clawscope-obs-events-staging`)
- Analytics Engine dataset: `SCOPE_METRICS`
- R2: `SCOPE_REPORTS_BUCKET` (`clawscope-obs-reports*`)
- Durable Object: `ScopeObservabilityCoordinator` (alert dedupe)
- Cron trigger: hourly rollup schedule (`5 * * * *`)

Validation + rollout evidence:
- Quality checks:
  - `cd services/clawscope && npm run typecheck && npm test`
  - `cd services/clawclaim && npm run typecheck && npm test`
  - `cd services/clawverify && npm run typecheck && npm test`
- Deploys:
  - staging: `clawscope-staging` version `aa78cace-a561-4efe-908a-8696cbbc40f8`
  - prod: `clawscope` version `56b88b3f-7914-42dc-a680-a6a9b43f3d8d`
- Smoke artifacts:
  - staging: `artifacts/smoke/identity-control-plane/2026-02-11T23-49-28-476Z-staging-m5/result.json`
  - prod: `artifacts/smoke/identity-control-plane/2026-02-11T23-49-48-765Z-prod-m5/result.json`

---

## 12) 2026-02-12 addendum — ICP-M6 universal enforcement + governance closure (CSC-US-019)

Shipped governance/auth closure in `services/clawscope/src/index.ts` with canonical protected access defaults:
- `SCOPE_PROTECTED_AUTH_MODE=canonical_cst` (default)
- protected routes enforce canonical CST and reject legacy admin-token headers in canonical mode

Governance APIs now first-class:
- key transparency:
  - `GET /v1/keys/transparency/latest`
  - `GET /v1/keys/transparency/history`
  - `POST /v1/keys/transparency/snapshot`
- revocation propagation SLO:
  - `GET /v1/reports/revocation-slo`

M6 hardening fixes applied during closure:
- `/v1/reports/revocation-slo` routed through canonical protected auth (not observability admin-token router)
- transparency snapshot transition contract normalized to `key.rotate`

Cloudflare evidence:
- governance migration active: `services/clawscope/migrations/0002_governance_transparency_revocation_slo.sql`
- deploys:
  - staging: `clawscope-staging` version `028de033-b1ac-45b5-82f5-904cd517e5b7`
  - prod: `clawscope` version `89b90fad-84da-4920-aceb-27d46c45256a`

M6 pass artifacts:
- staging ops summary: `artifacts/ops/identity-control-plane/2026-02-12T00-52-18-553Z-staging/deploy-summary.json`
- prod ops summary: `artifacts/ops/identity-control-plane/2026-02-12T00-52-32-525Z-prod/deploy-summary.json`
- baseline hard-cutover refresh:
  - staging: `artifacts/smoke/identity-control-plane/2026-02-12T00-57-11-396Z-staging/result.json`
  - prod: `artifacts/smoke/identity-control-plane/2026-02-12T00-57-20-846Z-prod/result.json`

---

*Generated for Claw Bureau monorepo. All PRDs follow a uniform structure for Ralph execution.*
