# clawscope.com (Scope + Observability) — PRD

**Domain:** clawscope.com  
**Pillar:** Infrastructure  
**Status:** Draft  

---

## 0) OpenClaw Fit (primary design target)
OpenClaw is the **reference harness** for Claw Bureau services.

`clawscope` is the **central scoped-token issuer** (CST) used by OpenClaw extensions (tool/provider plugins) to authenticate to Claw Bureau services such as `clawproxy`.

See: `docs/OPENCLAW_INTEGRATION.md`.

---

## 1) Purpose
Define and enforce scoped token access (CST), issue/introspect/revoke tokens, and provide auditability suitable for OpenClaw multi-agent + multi-session operation.

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
  - Issue tokens bound to **agent DID** (`sub`) + **audience** (`aud`) + **scope[]`
  - Enforce TTL and max scope length
  - Return token hash + policy version
  - Support OpenClaw correlation via `mission_id` (recommended default = OpenClaw `sessionKey`)


### CSC-US-002 — Token introspection
**As a** Claw Bureau service, **I want** introspection **so that** I can enforce authorization consistently.

**Acceptance Criteria:**
  - Validate signature + expiry
  - Return scope + audience + owner_ref
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

---

## 8) Success Metrics
- Tokens issued/day
- Introspection latency
- Revocation time
- % offline JWKS verifications vs introspection
- Audit export success rate

---

*Generated for Claw Bureau monorepo. All PRDs follow a uniform structure for Ralph execution.*
