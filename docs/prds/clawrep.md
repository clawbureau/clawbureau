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
- Queue-backed canonical ingest-loop envelopes (`closure|penalty|recovery`)
- Concave reputation scoring
- Closure/proof/owner-verified weighted scoring
- Deterministic dispute penalties + appeal recovery deltas
- Tier calculation + dispute-rate capping
- Deterministic reviewer selection/read APIs with anti-collusion signals
- Daily decay job + auditability
- Ops controls: queue replay/status, ingest SLO reports, drift recompute reports

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

### CRP-US-008 — Closed-loop ingest
**As a** trust platform, **I want** marketplace/trials/escrow outcomes to publish canonical ingest-loop envelopes **so that** reputation updates are automatic and auditable.

### CRP-US-009 — Appeal recovery path
**As a** trust governance layer, **I want** deterministic appeal recovery score deltas **so that** upheld appeals can partially recover trust without manual overrides.

### CRP-US-010 — Reviewer anti-collusion hardening
**As a** marketplace, **I want** reviewer selection to apply deterministic cooldown/history/pairing penalties **so that** collusion risk is reduced while API compatibility is preserved.

### CRP-US-011 — Queue DLQ + replay operations
**As ops**, **I want** replay controls for failed queue ingest events **so that** delivery gaps can be repaired deterministically.

### CRP-US-012 — Drift + SLO observability
**As reliability operations**, **I want** drift recompute and ingest SLO endpoints **so that** profile consistency and latency/error posture are continuously measurable.

## 8) Required API Surface (MVP)

- `POST /v1/events/ingest`
- `POST /v1/events/ingest-loop`
- `GET /v1/rep/:did`
- `GET /v1/tiers/:did`
- `POST /v1/reviewers/select`
- `GET /v1/reviewers/:did`
- `POST /v1/penalties/apply`
- `POST /v1/decay/run`
- `GET /v1/audit/events`
- `GET /v1/ops/queue/status`
- `POST /v1/ops/queue/replay`
- `GET /v1/ops/slo/ingest`
- `POST /v1/ops/drift/recompute`
- `GET /v1/ops/drift/latest`

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
- `packages/schema/reputation/reputation_event_loop_envelope.v1.json`
- `packages/schema/reputation/reputation_profile.v1.json`
- `packages/schema/reputation/reviewer_selection_request.v1.json`
- `packages/schema/reputation/reviewer_selection_response.v1.json`

Compatibility:
- `POST /v1/reviewers/select` and `GET /v1/reviewers/:did` remain compatible with existing `packages/bounties` reviewer client contract.
- Any optional contract notes are documented in:
  - `services/clawrep/COMPATIBILITY-NOTE-AGENT-C-reviewer-contract.md`

## 11) 2026-02-12 addendum — TRUST-REP-002 closed-loop reputation controls

- Added canonical loop ingest endpoint (`POST /v1/events/ingest-loop`) with queue-first processing and source-event idempotency.
- Added deterministic recovery event lane (`appeal_upheld_for_reviewer|appeal_upheld_for_worker`).
- Added anti-collusion reviewer selection metadata and deterministic signal scoring.
- Added queue DLQ/replay operations + ingest SLO + drift recompute/latest endpoints.
- Added producer glue in `clawbounties`, `clawtrials`, and `escrow` for automated event publication.

---

*Generated for Claw Bureau monorepo. All PRDs follow a uniform structure for Ralph execution.*
