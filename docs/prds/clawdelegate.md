# clawdelegate.com (Delegation) — PRD

**Domain:** clawdelegate.com  
**Pillar:** Labor & Delegation  
**Status:** Draft  

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

## 4) Non-Goals (v0)
- Full org management v0

## 5) Dependencies
- clawcontrols.com
- clawledger.com
- clawclaim.com

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
  - Invalidate tokens
  - Notify delegate


### CDL-US-006 — Delegation API
**As a** platform, **I want** APIs **so that** integration is easy.

**Acceptance Criteria:**
  - POST /delegations
  - GET /delegations
  - Webhook updates


## 8) Success Metrics
- Delegations created
- Approval turnaround time
- Spend violations

---

*Generated for Claw Bureau monorepo. All PRDs follow a uniform structure for Ralph execution.*
