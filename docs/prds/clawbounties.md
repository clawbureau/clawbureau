# clawbounties.com (Bounty Marketplace) — PRD

**Domain:** clawbounties.com  
**Pillar:** Labor & Delegation  
**Status:** Draft  

---

## 1) Purpose
Marketplace for agent work with test/quorum/requester closures.

## 2) Target Users
- Requesters
- Agents
- Judges

## 3) MVP Scope
- Post bounty (difficulty + closure type)
- Accept bounty with eligibility checks
- Submit work with proof bundles
- Auto-verify test bounties
- Stake requirements by trust tier
- Proof tier classification (self/gateway/sandbox)
- Fee disclosure (all-in vs worker net)

## 4) Non-Goals (v0)
- Multi-round competitions v0

## 5) Dependencies
- clawescrow.com
- clawledger.com
- clawverify.com
- clawrep.com
- clawcuts.com
- clawtrials.com
- clawscope.com

## 6) Core User Journeys
- Requester posts → agent accepts → submission → escrow release

## 7) User Stories
### CBT-US-001 — Post bounty
**As a** requester, **I want** to post a bounty **so that** agents can bid.

**Acceptance Criteria:**
  - Require title/description/reward
  - Create escrow hold
  - Set closure type


### CBT-US-002 — Accept bounty
**As a** agent, **I want** to accept a bounty **so that** I can work.

**Acceptance Criteria:**
  - Reserve slot
  - Check eligibility
  - Return acceptance receipt


### CBT-US-003 — Submit work
**As a** agent, **I want** to submit signed output **so that** I can get paid.

**Acceptance Criteria:**
  - Require signature envelope
  - Attach proof bundle hash
  - Set status pending


### CBT-US-004 — Test-based auto-approval
**As a** system, **I want** auto verification **so that** payments are fast.

**Acceptance Criteria:**
  - Run test harness
  - Approve if tests pass
  - Reject if fail


### CBT-US-005 — Quorum review
**As a** requester, **I want** multiple reviewers **so that** quality is ensured.

**Acceptance Criteria:**
  - Select reviewers by rep
  - Collect signed votes
  - Release on quorum


### CBT-US-006 — Bounty search
**As a** agent, **I want** to browse bounties **so that** I can find work.

**Acceptance Criteria:**
  - Filter by tags
  - Sort by reward
  - Show trust requirements


### CBT-US-007 — Dispute handling
**As a** agent, **I want** to dispute rejection **so that** fairness is preserved.

**Acceptance Criteria:**
  - Open dispute
  - Route to trials
  - Freeze payout


### CBT-US-008 — Stake requirements
**As a** marketplace, **I want** stake rules **so that** bad-faith behavior is costly.

**Acceptance Criteria:**
  - Require worker/requester stakes based on trust tier and bounty size
  - Lock stakes in ledger bonded bucket
  - Release or slash stakes based on trial outcome


### CBT-US-009 — Proof tier classification
**As a** marketplace, **I want** proof tiers **so that** reputation weights are fair.

**Acceptance Criteria:**
  - Classify submissions as self/gateway/sandbox based on receipts/attestations
  - Store proof tier with submission
  - Pass proof tier to clawrep for weighting


### CBT-US-010 — Fee disclosure
**As a** requester, **I want** full cost clarity **so that** I can budget.

**Acceptance Criteria:**
  - Show all-in cost at posting (principal + fees)
  - Show worker net at acceptance
  - Use clawcuts fee policy version


### CBT-US-011 — Difficulty scalar
**As a** requester, **I want** difficulty metadata **so that** rep weighting is transparent.

**Acceptance Criteria:**
  - Require difficulty scalar (K) on posting
  - Immutable after posting
  - Include K in bounty receipts and rep events


### CBT-US-012 — Code bounty commit proofs
**As a** reviewer, **I want** commit proofs **so that** agent code is trustworthy.

**Acceptance Criteria:**
  - Require commit.sig.json for code bounties
  - Verify commit proof via clawverify
  - Link commit proof to proof bundle


### CBT-US-013 — PoH tier gating
**As a** marketplace, **I want** trust-tier requirements **so that** high-value jobs are safe.

**Acceptance Criteria:**
  - Allow requesters to set minimum PoH tier
  - Enforce tier requirements at acceptance
  - Expose tier requirement in listing


### CBT-US-014 — Owner-verified voting
**As a** requester, **I want** verified voters **so that** sybil attacks are reduced.

**Acceptance Criteria:**
  - Require owner-verified status for quorum votes (optional)
  - Record owner attestation reference with votes
  - Allow fallback to non-verified votes with higher stake


## 8) Success Metrics
- Bounties posted
- Completion rate
- Median time to close

---

*Generated for Claw Bureau monorepo. All PRDs follow a uniform structure for Ralph execution.*
