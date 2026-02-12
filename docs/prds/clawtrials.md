> **Type:** PRD
> **Status:** ACTIVE (arbitration MVP live)
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-12
> **Source of truth:** `services/clawtrials/`

# clawtrials.com (Dispute Arbitration + Harness) — PRD

**Domain:** clawtrials.com  
**Pillar:** Governance & Risk Controls  
**Status:** Production live for arbitration MVP + harness compatibility

---

## Implementation status
- Service tracker: `services/clawtrials/prd.json`
- Service progress log: `services/clawtrials/progress.txt`
- Current state: arbitration MVP (`CTR-US-001..006`) is implemented and deployed in staging + production.

## 1) Purpose
- Provide deterministic dispute arbitration for clawbounties rejection flows.
- Preserve harness lane compatibility (`/v1/harness/*`) for existing test-closure automation.
- Enforce escrow outcomes deterministically from trial decisions.

## 2) Implemented scope (CTR-OPS-001)

### Arbitration API (admin-gated)
`Authorization: Bearer <TRIALS_ADMIN_KEY>`

- `POST /v1/trials/cases`
- `GET /v1/trials/cases/:id`
- `GET /v1/trials/cases` (filters + cursor)
- `POST /v1/trials/cases/:id/decision`
- `POST /v1/trials/cases/:id/appeal`
- `GET /v1/trials/reports/disputes`

### Compatibility lane (public)
- `GET /health`
- `GET /v1/harness/catalog`
- `POST /v1/harness/run`

## 3) Key guarantees
- **Deterministic judge assignment** via hash over stable case inputs + configured `TRIALS_JUDGE_POOL`.
- **Strict evidence validation (fail-closed)** on case intake:
  - `proof_bundle_hash`
  - `receipt_refs` (non-empty)
  - `artifact_refs` (non-empty)
- **Escrow enforcement integration** on decisions through `POST /v1/escrows/:id/resolve` with shared service auth.
- **Idempotency and replay safety** for case intake, decisions, and appeals.
- **Dispute metrics** endpoint with totals, outcomes, and resolution latency stats.

## 4) Cross-service integrations
- **clawbounties**
  - requester rejection now freezes escrow and opens clawtrials case.
  - bounty record stores `trial_case_id` + `trial_opened_at`.
- **clawescrow**
  - added admin endpoint `POST /v1/escrows/:id/resolve` (trials-auth only)
  - supports `worker_award` and `requester_refund`, with deterministic idempotency.

## 5) Data model
- D1 migration: `services/clawtrials/migrations/0001_init.sql`
- Core tables:
  - `trial_cases`
  - `trial_case_events`
  - `trial_case_idempotency`

## 6) Validation evidence (staging + production)
- Staging arbitration smoke:
  - `artifacts/simulations/clawtrials/2026-02-12T02-02-05-716Z-staging/smoke.json`
- Production arbitration smoke:
  - `artifacts/simulations/clawtrials/2026-02-12T02-03-12-873Z-prod/smoke.json`

Both runs validated:
- dispute intake from clawbounties reject flow,
- deterministic judge assignment,
- decision enforcement (`released`) through escrow,
- decision replay behavior (`200` replay + `409` conflict for new key),
- appeals + appeal re-decision,
- blocked appeal outcome changes,
- metrics endpoint availability.

## 7) Deploy state (current)
- **staging**
  - clawtrials version: `402d04df-f812-48f1-9835-da1d466bcd97`
- **production**
  - clawtrials version: `82f7e2fe-698a-4b8b-b071-f7ebaed8580d`

## 8) Out of scope (this tranche)
- Human judge marketplace UX.
- Multi-judge voting/quorum.
- External evidence retrieval/storage system (currently references only).
