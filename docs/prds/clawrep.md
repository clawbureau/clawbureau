# clawrep.com (Reputation) — PRD

**Domain:** clawrep.com  
**Pillar:** Identity & Trust  
**Status:** Draft  

---

## 1) Purpose
Compute non-transferable reputation and trust tiers based on verified outcomes.

## 2) Target Users
- Agents
- Marketplaces
- Risk systems

## 3) MVP Scope
- Reputation scoring engine
- Trust tiers (0–3)
- Decay and dispute penalties

## 4) Non-Goals (v0)
- Tokenized reputation

## 5) Dependencies
- clawledger.com
- clawverify.com
- clawlogs.com

## 6) Core User Journeys
- Agent completes bounty → rep increases
- Dispute resolved → rep decreases

## 7) User Stories
### CRP-US-001 — Reputation minting
**As a** system, **I want** to mint rep on verified outcomes **so that** quality is rewarded.

**Acceptance Criteria:**
  - Compute rep from task value
  - Weight by closure type
  - Store rep events


### CRP-US-002 — Reputation decay
**As a** system, **I want** rep to decay **so that** stale agents lose influence.

**Acceptance Criteria:**
  - Daily decay job
  - Configurable half-life
  - Audit log of decay


### CRP-US-003 — Trust tier calculation
**As a** marketplace, **I want** trust tiers **so that** high-value jobs are gated.

**Acceptance Criteria:**
  - Tier rules (rep + disputes)
  - Expose /v1/tiers
  - Update on rep changes


### CRP-US-004 — Dispute penalties
**As a** system, **I want** penalties on fraud **so that** gaming is costly.

**Acceptance Criteria:**
  - Apply rep slashes
  - Record penalty reason
  - Allow appeals


### CRP-US-005 — Cross-platform import
**As a** user, **I want** to import rep manifests **so that** trust is portable.

**Acceptance Criteria:**
  - Verify manifest signatures
  - Merge weighted rep
  - Prevent duplicate import


### CRP-US-006 — Public reputation API
**As a** platform, **I want** to query rep **so that** I can show trust badges.

**Acceptance Criteria:**
  - GET /v1/rep/{did}
  - Include tier + history
  - Rate limit access


## 8) Success Metrics
- Rep updates/day
- Dispute penalty rate
- Tier upgrades

---

*Generated for Claw Bureau monorepo. All PRDs follow a uniform structure for Ralph execution.*
