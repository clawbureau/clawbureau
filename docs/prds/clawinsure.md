> **Type:** PRD
> **Status:** ACTIVE (MVP live in staging + production)
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-12
> **Source of truth:** `services/clawinsure/`

# clawinsure.com (Insurance) — PRD

**Domain:** clawinsure.com  
**Pillar:** Economy & Settlement  
**Status:** CINR-OPS-001 shipped (staging + production)

---

## Implementation status
- Service tracker: `services/clawinsure/prd.json`
- Service progress log: `services/clawinsure/progress.txt`
- Current execution tranche: `CINR-OPS-001` for MVP endpoints, deterministic adjudication, and payout rails.
- Story completion: `CINR-US-001..006` are implemented and marked `passes=true`.
- Deploys:
  - `clawinsure-staging` `65754896-45ef-4f53-b5b0-7b93680ea5cb`
  - `clawinsure` `876d4e59-379c-42a2-951f-07ca6c2299f7`
- Smokes:
  - staging: `artifacts/simulations/clawinsure/2026-02-12T03-25-42-778Z-staging/smoke.json`
  - prod: `artifacts/simulations/clawinsure/2026-02-12T03-25-51-801Z-prod/smoke.json`
- Ops deploy artifact:
  - `artifacts/ops/clawinsure/2026-02-12T03-21-09Z/deploy-summary.json`

## 1) Purpose
Insurance products for SLA failures, disputes, and provider bonds.

## 2) Target Users
- Agents
- Enterprises
- Providers

## 3) MVP Scope
- Coverage quotes
- Claims intake
- Provider bonds
- Claims adjudication
- Claim payouts
- Risk scoring + claims reporting

## 4) Non-Goals (v0)
- Full underwriting automation
- Multi-provider collateral optimization

## 5) Dependencies
- clawrep.com (risk signals)
- clawledger.com (premium + payout transfers)
- clawtrials.com (claim evidence refs)
- clawescrow.com (escrow-linked claims)
- clawincome.com (statement linkage)

## 6) Core User Journeys
- Claimant requests quote → purchases policy.
- Claimant files claim with evidence references.
- Operator adjudicates claim and executes payout.
- Operator monitors claims report + risk posture.

## 7) User Stories
- CINR-US-001 Coverage quotes
- CINR-US-002 Claims intake
- CINR-US-003 Provider bonds
- CINR-US-004 Claims adjudication
- CINR-US-005 Premium payouts
- CINR-US-006 Risk scoring

## 8) Success Metrics
- Policies issued
- Claim resolution time
- Payout replay/idempotency correctness
- Zero non-deterministic money transitions
