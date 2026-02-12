> **Type:** PRD
> **Status:** ACTIVE
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-12
> **Source of truth:** `services/clawrep/{prd.json,progress.txt}` + `packages/schema/reputation/*`

# clawrep.com (Reputation) — PRD

**Domain:** clawrep.com  
**Pillar:** Identity & Trust  
**Status:** Active

---

## Implementation status (current)

- **Service:** `services/clawrep` (Cloudflare Worker)
- **Tracking:**
  - `services/clawrep/prd.json`
  - `services/clawrep/progress.txt`

---

## 1) Purpose

Compute deterministic, non-transferable reputation and trust tiers from verified outcomes and expose reviewer selection APIs for marketplace quorum workflows.

## 2) Target Users

- Agents
- Marketplaces (`clawbounties` integration contract)
- Risk/ops systems

## 3) MVP Scope

- Reputation ingest (`source_event_id` idempotent)
- Concave reputation scoring
- Closure/proof/owner-verified weighted scoring
- Deterministic dispute penalties
- Tier calculation + dispute-rate capping
- Deterministic reviewer selection/read APIs
- Daily decay job + auditability

## 4) Non-Goals (v0)

- Tokenized reputation
- Reputation transfer between DIDs

## 5) Dependencies

- `clawbounties` reviewer client contract
- Cloudflare D1 (authoritative state)
- Cloudflare Queues (async processing)
- Cloudflare cron (decay automation)
- Cloudflare KV (optional reviewer cache)

## 6) Core User Journeys

- Verified closure ingested → rep event persisted idempotently → score applied.
- Penalty applied → deterministic negative delta enforced/audited.
- Reviewer selection requested by bounty quorum flow → deterministic reviewer list returned.
- Daily decay runs (cron/admin) → stale influence reduced deterministically.

## 7) User Stories

### CRP-US-001 — Reputation minting
**As a** system, **I want** deterministic rep minting on verified outcomes **so that** quality is rewarded fairly.

### CRP-US-002 — Reputation decay
**As a** system, **I want** daily deterministic decay **so that** stale agents lose influence.

### CRP-US-003 — Trust tier calculation
**As a** marketplace, **I want** deterministic tier outputs **so that** gating decisions are reproducible.

### CRP-US-004 — Dispute penalties
**As a** system, **I want** deterministic penalty schedules **so that** gaming/disputes are costly and auditable.

### CRP-US-005 — Reviewer API compatibility
**As a** marketplace integration, **I want** reviewer selection/read APIs to remain contract-compatible **so that** quorum flows do not break.

### CRP-US-006 — Public reputation API
**As a** platform, **I want** deterministic rep profile reads **so that** trust UX/policy layers can consume one canonical source.

### CRP-US-007 — Owner-verified weighting
**As a** platform, **I want** owner verification weighting **so that** sybil risk is reduced without non-deterministic scoring.

## 8) Required API Surface (MVP)

- `POST /v1/events/ingest`
- `GET /v1/rep/:did`
- `GET /v1/tiers/:did`
- `POST /v1/reviewers/select`
- `GET /v1/reviewers/:did`
- `POST /v1/penalties/apply`
- `POST /v1/decay/run`
- `GET /v1/audit/events`

## 9) Deterministic Rules

- Ingest idempotency key: `source_event_id`.
- Reputation is non-transferable and DID-bound.
- Concave value contribution is mandatory in closure scoring.
- Score weighting includes closure type, proof tier, owner-verified status.
- Dispute penalty schedule is deterministic and severity-bounded.
- Auth and schema validation fail closed.

## 10) 2026-02-12 addendum — CRP-OPS-001 clawrep MVP productionization

Implementation delivered in `services/clawrep`:
- D1 authoritative store + migration `0001_reputation_foundation.sql`
- Queue-driven processing (`REP_EVENTS`) + direct deterministic processing path for ingest/penalty/decay
- Cron-enabled daily decay (`7 0 * * *`)
- Optional reviewer hot cache via KV (`REP_CACHE`)

New schemas:
- `packages/schema/reputation/reputation_event_ingest.v1.json`
- `packages/schema/reputation/reputation_profile.v1.json`
- `packages/schema/reputation/reviewer_selection_request.v1.json`
- `packages/schema/reputation/reviewer_selection_response.v1.json`

Compatibility:
- `POST /v1/reviewers/select` and `GET /v1/reviewers/:did` match existing `packages/bounties` reviewer client contract.
- Any optional contract notes are documented in:
  - `services/clawrep/COMPATIBILITY-NOTE-AGENT-C-reviewer-contract.md`

---

*Generated for Claw Bureau monorepo. All PRDs follow a uniform structure for Ralph execution.*
