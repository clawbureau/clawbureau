> **Type:** PRD
> **Status:** ACTIVE (staging harness lane)
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-11
> **Source of truth:** `services/clawtrials/` (harness lane) + this PRD (broader future scope)

# clawtrials.com (Dispute Arbitration + Test Harness) — PRD

**Domain:** clawtrials.com  
**Pillar:** Governance & Risk Controls  
**Status:** Active (harness lane live on staging; full dispute product not implemented)  

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
  - latest staging version (CBT-OPS-003 run): `2a7af0d8-d91e-45ba-8d9d-48af3846d016`
  - evidence artifacts:
    - `artifacts/simulations/clawbounties/2026-02-11T21-15-21-606Z-clawtrials-domain-check/staging-clawtrials-domain-check.json`
    - `artifacts/simulations/clawbounties/2026-02-11T21-54-21-876Z-prod-gate/gate-report.json` (route + harness preflight checks)

### Not yet implemented
- Full dispute intake / judge assignment / arbitration workflows remain roadmap scope.

### Current cross-service blocker (CBT-OPS-003)
- Requester scoped token generation for clawbounties staging is currently blocked by clawscope signing-key mismatch (`TOKEN_UNKNOWN_KID`) for locally minted requester tokens.
- This blocks full requester-authenticated marketplace E2E gate pass even though clawtrials route/harness checks are healthy.

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
- Harness API availability in staging.
- Deterministic error behavior under dependency/network faults.
- Test closure latency and stuck-state reduction in clawbounties.
