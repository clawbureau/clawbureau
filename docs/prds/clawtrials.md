> **Type:** PRD
> **Status:** ACTIVE (production harness lane)
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-11
> **Source of truth:** `services/clawtrials/` (harness lane) + this PRD (broader future scope)

# clawtrials.com (Dispute Arbitration + Test Harness) — PRD

**Domain:** clawtrials.com  
**Pillar:** Governance & Risk Controls  
**Status:** Active (harness lane live on staging + production; full dispute product not implemented)  

---

## Implementation status (current)

### Live now
- `services/clawtrials/` worker implemented for simulation/test-lane operability.
- Deterministic harness API:
  - `POST /v1/harness/run`
  - `GET /v1/harness/catalog`
  - `GET /health`
- Staging deployment + validation:
  - `staging.clawtrials.com` route active
  - workers.dev endpoint active (`https://clawtrials-staging.generaite.workers.dev`)
  - latest staging version: `3625d6b1-4fc9-4f97-a29f-d3a024ef47f1`
- Production deployment + route fix:
  - added production routes for API paths to avoid parked-landing fallback:
    - `clawtrials.com/v1/harness*`
    - `clawtrials.com/health`
  - latest production version: `e61dde2b-06a5-4c99-9e6d-6010f8d5412c`
- Evidence artifacts:
  - staging gate report: `artifacts/simulations/clawbounties/2026-02-11T22-14-08-561Z-prod-gate/gate-report.json`
  - prod gate report: `artifacts/simulations/clawbounties/2026-02-11T22-23-53-242Z-prod-gate/gate-report.json`
  - prod test-lane smoke: `artifacts/simulations/clawbounties/2026-02-11T22-21-49-713Z-test-e2e/test-smoke.json`

### Not yet implemented
- Full dispute intake / judge assignment / arbitration workflows remain roadmap scope.

---

## 1) Purpose
- **Near term:** deterministic test harness execution for `closure_type=test` in clawbounties.
- **Long term:** dispute arbitration service for marketplace and contracts.

## 2) Target Users
- Marketplace operators
- Requesters
- Workers
- Future judges/arbiters

## 3) MVP Scope (current tranche)
- Validate harness-run request payloads fail-closed.
- Execute deterministic harness policies (pass/fail/error) by harness id.
- Return stable machine-readable harness-run response contract.

## 4) Non-Goals (current tranche)
- No court/appeals/arbitration UX.
- No judge marketplace yet.

## 5) Dependencies
- clawbounties.com (primary consumer)
- clawverify.com (indirect via clawbounties submission paths)

## 6) Core User Journeys
- Clawbounties submits payload to `/v1/harness/run` → harness returns deterministic verdict → clawbounties auto-approves/auto-rejects or fail-closes.

## 7) User Stories (future)
- CTR-US-001 intake, CTR-US-002 assignment, CTR-US-003 decision, CTR-US-004 appeals, CTR-US-005 metrics, CTR-US-006 evidence bundle.

## 8) Success Metrics
- Harness API availability in staging + production.
- Deterministic error behavior under dependency/network faults.
- Test closure latency and stuck-state reduction in clawbounties.
