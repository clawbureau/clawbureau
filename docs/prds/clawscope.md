# clawscope.com (Scope + Observability) — PRD

**Domain:** clawscope.com  
**Pillar:** Infrastructure  
**Status:** Draft  

---

## 1) Purpose
Define and enforce scoped token access, issue/introspect CSTs, and provide mission + usage analytics across services.

## 2) Target Users
- Platforms
- Developers
- Operators
- Enterprises

## 3) MVP Scope
- Scoped token issuance (CST)
- Token introspection + revocation
- Policy enforcement hooks (clawcontrols)
- JWKS/public key endpoint
- Metrics dashboards
- Usage reports
- Alerts
- Mission-level aggregation

## 4) Non-Goals (v0)
- Full IAM / OAuth provider suite
- Full APM suite

## 5) Dependencies
- clawclaim.com
- clawcontrols.com
- clawlogs.com
- clawproxy.com
- clawledger.com

## 6) Core User Journeys
- Service requests token → uses it → introspection verifies scope
- Operator monitors service health and mission spend

## 7) User Stories
### CSC-US-001 — Issue scoped tokens
**As a** platform, **I want** time‑bound tokens **so that** access is safe.

**Acceptance Criteria:**
  - Issue tokens bound to DID + audience + scope
  - Enforce TTL and max scope length
  - Return token hash + policy version


### CSC-US-002 — Token introspection
**As a** service, **I want** introspection **so that** I can verify tokens.

**Acceptance Criteria:**
  - Validate signature + expiry
  - Return scope + audience + owner_ref
  - Fail closed on unknown version


### CSC-US-003 — Token revocation
**As a** security operator, **I want** revocation **so that** compromises stop.

**Acceptance Criteria:**
  - Revoke tokens immediately
  - Broadcast revocation events
  - Provide audit log


### CSC-US-004 — Policy enforcement
**As a** platform, **I want** policy checks **so that** tokens stay narrow.

**Acceptance Criteria:**
  - Enforce allowed scopes per tier
  - Enforce max TTL per policy
  - Reject tokens that exceed limits


### CSC-US-005 — JWKS / public keys
**As a** verifier, **I want** key discovery **so that** verification is easy.

**Acceptance Criteria:**
  - Publish JWKS endpoint
  - Rotate keys with versioning
  - Cache-control headers


### CSC-US-006 — Token audit trail
**As a** auditor, **I want** logs **so that** issuance is traceable.

**Acceptance Criteria:**
  - Log token hash + issuance metadata
  - Store revocation timestamps
  - Export audit bundles


### CSC-US-007 — Metrics dashboard
**As a** operator, **I want** real-time metrics **so that** I can monitor health.

**Acceptance Criteria:**
  - Service metrics
  - Latency charts
  - Error rates


### CSC-US-008 — Usage reports
**As a** enterprise, **I want** usage reports **so that** I can track spend.

**Acceptance Criteria:**
  - Daily usage
  - Export CSV
  - Segment by service


### CSC-US-009 — Alerting
**As a** operator, **I want** alerts **so that** I can respond quickly.

**Acceptance Criteria:**
  - Threshold alerts
  - Email/Slack
  - Ack workflow


### CSC-US-010 — Cost analytics
**As a** finance, **I want** cost analytics **so that** budgets are managed.

**Acceptance Criteria:**
  - Cost by service
  - Trend charts
  - Forecasting


### CSC-US-011 — Trace viewer
**As a** engineer, **I want** tracing **so that** I can debug issues.

**Acceptance Criteria:**
  - Trace search
  - Span view
  - Correlation IDs


### CSC-US-012 — SLA reports
**As a** enterprise, **I want** SLA reports **so that** compliance is proven.

**Acceptance Criteria:**
  - SLA metrics
  - Downtime logs
  - Export reports


### CSC-US-013 — Mission aggregation
**As a** operator, **I want** mission rollups **so that** multi-agent work is visible.

**Acceptance Criteria:**
  - Group spend and receipts by mission_id
  - Show per-role and per-agent breakdowns
  - Export mission summary reports


## 8) Success Metrics
- Tokens issued/day
- Introspection latency
- Revocation time
- Alert response time
- Report downloads
- SLA compliance

---

*Generated for Claw Bureau monorepo. All PRDs follow a uniform structure for Ralph execution.*
