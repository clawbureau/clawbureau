> **Type:** PRD
> **Status:** DRAFT
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-07
> **Source of truth:** PRD intent (no active execution tracker yet)
>
> **Scope:**
> - Product requirements for `joinclaw.com`.
> - This domain has no service-level tracker yet; treat as aspirational until a roadmap/service tracker exists.

# joinclaw.com (Onboarding) — PRD

**Domain:** joinclaw.com  
**Pillar:** Community & Growth  
**Status:** Draft  

---

## Implementation status (current)

- **Service:** `services/joinclaw/` exists, but there is no service-level tracker yet (`prd.json` + `progress.txt`).
- **Tracking:** add a service tracker under `services/joinclaw/` (preferred once implementation starts), or a roadmap under `docs/roadmaps/`.

---

## 1) Purpose
Top-of-funnel onboarding and documentation hub.

## 2) Target Users
- New users
- Developers

## 3) MVP Scope
- Landing page
- Docs
- Integration guides
- Pi/OpenClaw skill quickstart
- Scoped token + proof bundle walkthroughs

## 4) Non-Goals (v0)
- Full support desk v0

## 5) Dependencies
- clawbureau.com

## 6) Core User Journeys
- User lands → reads docs → installs OpenClaw

## 7) User Stories
### JCL-US-001 — Landing page
**As a** visitor, **I want** clear messaging **so that** I understand the product.

**Acceptance Criteria:**
  - Hero section
  - Use cases
  - CTA buttons


### JCL-US-002 — Docs hub
**As a** developer, **I want** docs **so that** I can integrate.

**Acceptance Criteria:**
  - Quickstart
  - API docs
  - Examples


### JCL-US-003 — Signup flow
**As a** user, **I want** to sign up **so that** I can access services.

**Acceptance Criteria:**
  - Email signup
  - Verify email
  - Create account


### JCL-US-004 — OpenClaw install guide
**As a** user, **I want** install instructions **so that** I can run the CLI.

**Acceptance Criteria:**
  - Platform guides
  - Troubleshooting
  - Config examples


### JCL-US-005 — Integrations page
**As a** developer, **I want** integration docs **so that** I can extend OpenClaw.

**Acceptance Criteria:**
  - Provider list
  - Skill docs
  - SDK links


### JCL-US-006 — Newsletter/updates
**As a** visitor, **I want** updates **so that** I can follow progress.

**Acceptance Criteria:**
  - Signup form
  - Confirm opt-in
  - Archive


### JCL-US-007 — Pi skill installer guide
**As a** developer, **I want** skill install steps **so that** I can integrate quickly.

**Acceptance Criteria:**
  - Provide copy-paste install commands for Pi/OpenClaw skills
  - Document base URLs and required env vars
  - Link to sample proof bundles


### JCL-US-008 — Token + PoH quickstart
**As a** developer, **I want** a quickstart **so that** I can issue tokens and receipts.

**Acceptance Criteria:**
  - Step-by-step guide for CST token issuance
  - Example proxy call with receipt binding
  - Example proof bundle submission


## 8) Success Metrics
- Signup conversion
- Docs dwell time
- Install guide completion

---

*Generated for Claw Bureau monorepo. All PRDs follow a uniform structure for Ralph execution.*
