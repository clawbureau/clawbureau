# Clawsig v0.2 — Real-Usecase Evidence Pack

Status: **BUYER-FACING EVIDENCE SNAPSHOT (NO DEPLOY IN THIS LANE)**

Date: 2026-02-18

## Scope

This pack links the concrete evidence produced for:

1. npm package release mission (v0.2.0)
2. real-usecase E2E matrix (staging + prod)
3. artifact-tracer outputs proving bundle/URM/verify linkage

## Evidence index

### A) npm publish evidence (Mission B1)

- publish log:
  - `docs/releases/clawsig-v0.2-publish-log.md`
- machine summary:
  - `artifacts/release/clawsig-v0.2-npm-publish/2026-02-18T14-26-39Z/summary.json`
- prep smoke summary:
  - `artifacts/release/clawsig-v0.2-package-prep/2026-02-18T14-18-45-458Z/summary.json`
- npm refs:
  - <https://www.npmjs.com/package/@clawbureau/schema/v/0.2.0>
  - <https://www.npmjs.com/package/@clawbureau/clawverify-core/v/0.2.0>
  - <https://www.npmjs.com/package/@clawbureau/clawverify-cli/v/0.2.0>

### B) Real-usecase E2E evidence (Mission B2)

- consolidated matrix summary:
  - `artifacts/e2e/real-usecases/2026-02-18T14-38-26Z/summary.json`
- run artifact roots:
  - `artifacts/simulations/marketplace-e2e-settlement/2026-02-18T14-37-07-978Z-staging/`
  - `artifacts/simulations/marketplace-e2e-dispute/2026-02-18T14-37-39-346Z-staging/`
  - `artifacts/simulations/marketplace-e2e-settlement/2026-02-18T14-37-49-846Z-prod/`
  - `artifacts/simulations/marketplace-e2e-dispute/2026-02-18T14-38-06-712Z-prod/`

### C) Artifact tracer outputs

- settlement (staging):
  - `artifacts/e2e/real-usecases/2026-02-18T14-38-26Z/traces/settlement-staging.trace.json`
- dispute (staging):
  - `artifacts/e2e/real-usecases/2026-02-18T14-38-26Z/traces/dispute-staging.trace.json`
- settlement (prod):
  - `artifacts/e2e/real-usecases/2026-02-18T14-38-26Z/traces/settlement-prod.trace.json`
- dispute (prod):
  - `artifacts/e2e/real-usecases/2026-02-18T14-38-26Z/traces/dispute-prod.trace.json`

## Buyer-facing KPIs

Source: `artifacts/e2e/real-usecases/2026-02-18T14-38-26Z/summary.json`

- **Pass rate:** `3 / 4 = 75%`
- **Deterministic reason-code behavior:** `4 / 4 = 100%` runs emitted a single deterministic verifier code (`OK` or `SMOKE_STEP_FAILED`)
- **Artifact completeness rate:** `4 / 4 = 100%` runs emitted canonical set:
  - `proof-bundle.json`
  - `urm.json`
  - `verify.json`
  - `smoke.json`

## Deterministic reason-code matrix

- `staging / marketplace-settlement` → `FAIL` / `SMOKE_STEP_FAILED`
- `staging / marketplace-dispute` → `PASS` / `OK`
- `prod / marketplace-settlement` → `PASS` / `OK`
- `prod / marketplace-dispute` → `PASS` / `OK`

## Interpretation

- Fail-closed behavior is preserved: the failing staging settlement run produced deterministic `SMOKE_STEP_FAILED` evidence (not silent success).
- Artifact contract compliance is complete across the whole matrix (100%).
- Tracer outputs show URM hash linkage and verification outcome binding per run.

## Operational note

- No deploys were performed in this mission lane.
- If staging settlement auth is fixed upstream, re-run the same matrix commands to refresh this pack.
