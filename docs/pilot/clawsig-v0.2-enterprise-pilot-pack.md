# Clawsig v0.2 — Enterprise Pilot Pack (30 days)

Status: **INTERNAL PILOT TEMPLATE (NO PUBLISH / NO DEPLOY EXECUTED)**

Date: 2026-02-18

## Objective

Run a 30-day buyer-ready pilot that demonstrates deterministic, fail-closed agent evidence verification using Clawsig v0.2 artifacts and conformance tooling.

## Scope

- Security teams validating fail-closed verification behavior
- Engineering teams integrating artifact generation/verification in CI
- Audit/compliance teams validating evidence completeness and control mappings

## 30-day plan

### Week 1 — Baseline

- Run `scripts/protocol/run-clawsig-v0.2-quickstart.mjs`
- Run at least one integration starter pack from `docs/examples/integrations/`
- Collect first evidence set (`proof-bundle`, `URM`, `verify`, `smoke`)

### Week 2 — CI integration

- Wire starter pack flow into target CI platform
- Require deterministic verification output (`PASS`/`FAIL` + reason codes)
- Produce artifact-tracer summaries for representative runs

### Week 3 — Control mapping

- Map key reason-code classes to enterprise controls
- Define response/escalation playbook for failing reason codes
- Review relevant conformance vectors with security/audit stakeholders

### Week 4 — Closeout

- Assemble evidence package and score outcomes
- Draft go/no-go recommendation memo
- Define rollout backlog (if pilot is accepted)

## Success metrics

### Security

- Deterministic fail-closed behavior demonstrated across pilot corpus
- No accepted bypass for unknown schema/algorithm inputs

### Engineering

- Starter packs reproducible from clean clone in target CI
- Artifact contract outputs produced consistently per run

### Audit

- Evidence completeness across sampled runs
- Control mapping references documented and reviewable

## Required pilot evidence

- quickstart summary:
  - `artifacts/examples/clawsig-v0.2-quickstart/<timestamp>/summary.json`
- integration pack artifacts:
  - `artifacts/examples/integrations/<pack>/{proof-bundle.json,urm.json,verify.json,smoke.json}`
- artifact-tracer summaries:
  - `artifacts/ops/artifact-trace/<timestamp>/{summary.json,summary.md}`
- protocol conformance summary:
  - `artifacts/conformance/clawsig-protocol/<timestamp>/summary.json`

## Control mapping anchors

- reason code registry:
  - `docs/specs/clawsig-protocol/REASON_CODE_REGISTRY.md`
- normative protocol:
  - `docs/specs/clawsig-protocol/CLAWSIG_PROTOCOL_v1.0.md`
- conformance corpus:
  - `packages/schema/fixtures/protocol-conformance/manifest.v1.json`
- conformance runner:
  - `scripts/protocol/run-clawsig-protocol-conformance.mjs`

## Machine-readable checklist + detached signature

- checklist JSON:
  - `docs/pilot/clawsig-v0.2-enterprise-pilot-pack-checklist.v1.json`
- signature envelope:
  - `proofs/docs/pilot/ADP-US-003-enterprise-pilot-pack/pilot-pack-checklist.sig.json`

Checklist JSON digest (detached):

- `sha256: 688531b21dbe2e163ba44578b5fb01d47beef5f6575237686d0e91176caf045f`
- source of truth: signature message in `proofs/docs/pilot/ADP-US-003-enterprise-pilot-pack/pilot-pack-checklist.sig.json`

## Safety note

This pack is planning + validation material only.

- no npm publish
- no production deploy
- no external posting
