# clawsupply.com (Supply Marketplace) — PRD

**Domain:** clawsupply.com  
**Pillar:** Economy & Settlement  
**Status:** Draft  

---

## 1) Purpose
Marketplace for compute/work supply offers priced in credits.

## 2) Target Users
- Compute providers
- Agents
- Enterprises

## 3) MVP Scope
- Provider offers
- Order execution
- Receipt-based settlement

## 4) Non-Goals (v0)
- Full derivatives market

## 5) Dependencies
- clawledger.com
- clawproviders.com
- clawlogs.com

## 6) Core User Journeys
- Provider lists offer → agent buys compute

## 7) User Stories
### CSU-US-001 — Create supply offer
**As a** provider, **I want** to list an offer **so that** agents can buy capacity.

**Acceptance Criteria:**
  - Define price + SLA
  - Set capacity
  - Publish offer


### CSU-US-002 — Buy supply units
**As a** agent, **I want** to purchase capacity **so that** I can do work.

**Acceptance Criteria:**
  - Escrow funds
  - Confirm order
  - Issue receipt


### CSU-US-003 — Execution receipts
**As a** buyer, **I want** execution proof **so that** I can dispute fraud.

**Acceptance Criteria:**
  - Require receipt hash
  - Store in logs
  - Verify on completion


### CSU-US-004 — Provider ratings
**As a** buyer, **I want** provider ratings **so that** I can choose reliable supply.

**Acceptance Criteria:**
  - Rate after completion
  - Display average
  - Link to rep


### CSU-US-005 — Offer discovery
**As a** agent, **I want** to search offers **so that** I can optimize cost.

**Acceptance Criteria:**
  - Filter by GPU type
  - Sort by price
  - Show SLA


### CSU-US-006 — Provider bonds
**As a** system, **I want** bonded listings **so that** fraud is reduced.

**Acceptance Criteria:**
  - Require bond for high volume
  - Lock bond in ledger
  - Slash on disputes


## 8) Success Metrics
- Offers listed
- Order completion rate
- Dispute rate

---

*Generated for Claw Bureau monorepo. All PRDs follow a uniform structure for Ralph execution.*
