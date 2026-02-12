> **Type:** PRD
> **Status:** DELIVERED (CDL-MAX-001)
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-12
> **Source of truth:** `services/clawdelegate/` runtime + `docs/roadmaps/trust-vnext/`
>
> **Scope:**
> - Delegation control plane for `clawdelegate.com`.
> - Delegated CST lifecycle, spend governance, revocation, and audit/export evidence.

# clawdelegate.com (Delegation) — PRD

**Domain:** clawdelegate.com  
**Pillar:** Labor & Delegation  
**Status:** Delivered (CDL-MAX-001)  

---

## Implementation status (current)

- **Service:** implemented at `services/clawdelegate`.
- **Service trackers:**
  - `services/clawdelegate/prd.json`
  - `services/clawdelegate/progress.txt`
- **Endpoints shipped:** create/get/list/approve/issue/revoke + spend reserve/consume/release/authorize + audit/export.
- **Cross-service wiring shipped:**
  - `clawclaim` delegation bootstrap (`POST /v1/delegations/bootstrap`)
  - `clawscope` canonical delegated CST issuance
  - `clawproxy` delegated spend idempotency enforcement
  - `ledger` delegation spend hook + replay contracts
- **Rollout evidence:**
  - Deploy summary: `artifacts/ops/clawdelegate/2026-02-12T04-56-45-407Z-deploy/deploy-summary.json`
  - Staging smoke: `artifacts/smoke/clawdelegate/2026-02-12T11-57-51-889Z-staging/result.json`
  - Prod smoke: `artifacts/smoke/clawdelegate/2026-02-12T11-57-55-034Z-prod/result.json`
  - Routing check: `artifacts/ops/clawdelegate/2026-02-12T04-53-42-573Z-routing/routing-check.json`
- **Tracker lane:** `CDL-MAX-001` in `docs/roadmaps/trust-vnext/prd.json`.

---

## 1) Purpose
Delegation policies and approvals for agents hiring agents.

## 2) Target Users
- Agents
- Teams
- Enterprises

## 3) MVP Scope
- Delegation contracts
- Approval flows
- Spend caps
- Delegated scoped tokens (CST)

## 4) Non-Goals (v0)
- Full org management v0

## 5) Dependencies
- clawcontrols.com
- clawledger.com
- clawclaim.com
- clawscope.com

## 6) Core User Journeys
- Agent delegates budget → subagent completes task

## 7) User Stories
### CDL-US-001 — Create delegation contract
**As a** agent, **I want** to delegate scope **so that** subagents can work.

**Acceptance Criteria:**
  - Define scope + budget
  - Sign contract
  - Store record


### CDL-US-002 — Approval workflows
**As a** manager, **I want** approval gates **so that** spend is controlled.

**Acceptance Criteria:**
  - Configurable approvals
  - Notify approvers
  - Audit decisions


### CDL-US-003 — Spend caps
**As a** enterprise, **I want** spend limits **so that** risk is bounded.

**Acceptance Criteria:**
  - Set daily limits
  - Block overages
  - Log violations


### CDL-US-004 — Delegation audit trail
**As a** auditor, **I want** audit logs **so that** delegation is traceable.

**Acceptance Criteria:**
  - Log all grants
  - Include signatures
  - Export records


### CDL-US-005 — Delegation revoke
**As a** user, **I want** to revoke access **so that** permissions are safe.

**Acceptance Criteria:**
  - Immediate revoke
  - Invalidate delegated tokens
  - Propagate revocation event to services
  - Notify delegate


### CDL-US-006 — Delegation API
**As a** platform, **I want** APIs **so that** integration is easy.

**Acceptance Criteria:**
  - POST /delegations
  - GET /delegations
  - Webhook updates


### CDL-US-007 — Delegated scoped tokens
**As a** manager, **I want** delegated tokens **so that** subagents have narrow authority.

**Acceptance Criteria:**
  - Issue CST tokens bound to delegation contract
  - Enforce TTL + spend caps + audience
  - Log token hash + scope in clawlogs


## 8) Success Metrics
- Delegations created
- Approval turnaround time
- Spend violations

---

*Generated for Claw Bureau monorepo. All PRDs follow a uniform structure for Ralph execution.*
