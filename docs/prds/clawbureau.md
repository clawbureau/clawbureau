> **Type:** PRD
> **Status:** DRAFT
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-07
> **Source of truth:** PRD intent (no active execution tracker yet)
>
> **Scope:**
> - Product requirements for `clawbureau.com`.
> - This domain has no service-level tracker yet; treat as aspirational until a roadmap/service tracker exists.

# clawbureau.com (Main Portal) — PRD

**Domain:** clawbureau.com  
**Pillar:** Governance & Risk Controls  
**Status:** Draft  

---

## Implementation status (current)

- **Service:** `services/clawbureau/` exists, but there is no service-level tracker yet (`prd.json` + `progress.txt`).
- **Tracking:** add a service tracker under `services/clawbureau/` (preferred once implementation starts), or a roadmap under `docs/roadmaps/`.

---

## 0) OpenClaw Fit (primary design target)
Claw Bureau should feel “native” to OpenClaw users.

`clawbureau.com` is the **distribution + documentation hub** for:
- OpenClaw extensions (provider/tool/memory plugins)
- OpenClaw skills (`SKILL.md` workflows)
- configuration snippets (`openclaw.json`) for safe defaults

See: `docs/integration/OPENCLAW_INTEGRATION.md`.

---

## 1) Purpose
Main portal for docs, dashboards, and service navigation.

## 2) Target Users
- OpenClaw users (self-hosted)
- Agents
- Enterprises
- Operators

## 3) MVP Scope
- Unified navigation
- Docs
- Scoped token + policy management
- Skill install hub (Pi/OpenClaw)
- Reserve-backed compute status

## 4) Non-Goals (v0)
- Full admin suite v0

## 5) Dependencies
- clawmanage.com
- clawscope.com

## 6) Core User Journeys
- User logs in → navigates services

## 7) User Stories
### CBU-US-001 — Unified dashboard
**As a** user, **I want** a central dashboard **so that** I can access services.

**Acceptance Criteria:**
  - Single nav
  - Service cards
  - Status indicators


### CBU-US-002 — Docs portal
**As a** developer, **I want** docs **so that** I can integrate.

**Acceptance Criteria:**
  - API docs
  - Guides
  - SDK links


### CBU-US-003 — Token & policy management
**As a** user, **I want** scoped tokens **so that** I can authenticate safely.

**Acceptance Criteria:**
  - Create scoped token policy
  - Issue time-bound tokens
  - Revoke tokens and audit changes


### CBU-US-004 — Service status
**As a** user, **I want** status page **so that** I can trust uptime.

**Acceptance Criteria:**
  - Status indicators
  - Incident history
  - Subscribe


### CBU-US-005 — Billing overview
**As a** enterprise, **I want** billing dashboard **so that** I can track spend.

**Acceptance Criteria:**
  - Usage charts
  - Invoices
  - Download CSV


### CBU-US-006 — User profile
**As a** user, **I want** profile management **so that** my data is correct.

**Acceptance Criteria:**
  - Edit profile
  - Bind DID
  - Manage org


### CBU-US-007 — Skill install hub
**As a** developer, **I want** installable skills **so that** agents integrate easily.

**Acceptance Criteria:**
  - Publish Pi/OpenClaw skill install commands
  - Provide environment setup and base URLs
  - Link to proof bundle examples


### CBU-US-008 — Reserve-backed compute status
**As a** developer, **I want** compute status **so that** I can trust reserves.

**Acceptance Criteria:**
  - Show Gemini/FAL reserve balances
  - Show coverage ratio from clawledger
  - Publish reserve attestation links


## 8) Success Metrics
- Monthly active users
- Doc engagement
- Token policy creations

---

*Generated for Claw Bureau monorepo. All PRDs follow a uniform structure for Ralph execution.*
