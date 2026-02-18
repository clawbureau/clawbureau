> **Type:** Roadmap
> **Status:** SHIPPED
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-18
> **Source of truth:** `docs/roadmaps/clawsig-protocol-v0.2/prd.json` + `docs/roadmaps/clawsig-protocol-v0.2/progress.txt`

# Clawsig Protocol v0.2

**Status summary:** v0.2 core is fully shipped on `main`, and the causal attribution hardening tranche is shipped through `CAV-US-023` (merge PR #326).

## Shipped stories

| ID | Title | Status | Evidence |
|----|-------|--------|----------|
| CPL-V2-001 | Protocol-level rate limiting semantics | ✅ complete | PR #285 (`1b21d0cdb562e02347304451cc6edd137a5b99d2`) |
| CPL-V2-002 | Multi-party receipt co-signing | ✅ complete | PR #281 (`a936c099814802df68e810d974d03017f39fd497`), PR #283 (`7c81b6c45cf1a59fbcf157e99940ce4c09ffa4c5`) |
| CPL-V2-003 | Receipt expiry / TTL semantics | ✅ complete | PR #282 (`4199b2b80ea5e1993e9063b8408dd81b90757e74`), PR #283 (`7c81b6c45cf1a59fbcf157e99940ce4c09ffa4c5`) |
| CPL-V2-004 | Selective disclosure for tool receipt arguments | ✅ complete | PR #281 (`a936c099814802df68e810d974d03017f39fd497`), PR #283 (`7c81b6c45cf1a59fbcf157e99940ce4c09ffa4c5`) |
| CPL-V2-005 | Aggregate proof bundles (bundle-of-bundles) | ✅ complete | PR #282 (`4199b2b80ea5e1993e9063b8408dd81b90757e74`), PR #283 (`7c81b6c45cf1a59fbcf157e99940ce4c09ffa4c5`) |

## Merge sequence

- PR #281 (`a936c099814802df68e810d974d03017f39fd497`) — R48 verifier uptake
- PR #282 (`4199b2b80ea5e1993e9063b8408dd81b90757e74`) — R49 aggregate/temporal uptake
- PR #283 (`7c81b6c45cf1a59fbcf157e99940ce4c09ffa4c5`) — executable R48/R49 vectors
- PR #285 (`1b21d0cdb562e02347304451cc6edd137a5b99d2`) — CPL-V2-001 rate-limit semantics

## Integrator adoption assets

- v0.2 adoption guide: [`ADOPTION_GUIDE.md`](../../specs/clawsig-protocol/ADOPTION_GUIDE.md)
- v0.2 quickstart fixture manifest: [`docs/examples/clawsig-v0.2-quickstart/manifest.v1.json`](../../examples/clawsig-v0.2-quickstart/manifest.v1.json)
- v0.2 quickstart runner: [`scripts/protocol/run-clawsig-v0.2-quickstart.mjs`](../../../scripts/protocol/run-clawsig-v0.2-quickstart.mjs)
- integration starter packs: [`docs/examples/integrations/README.md`](../../examples/integrations/README.md)
- enterprise pilot pack: [`docs/pilot/clawsig-v0.2-enterprise-pilot-pack.md`](../../pilot/clawsig-v0.2-enterprise-pilot-pack.md)
- real-usecase evidence pack: [`docs/pilot/clawsig-v0.2-real-usecase-evidence-pack.md`](../../pilot/clawsig-v0.2-real-usecase-evidence-pack.md)

## Release-prep assets (internal)

- package release checklist: [`docs/releases/clawsig-v0.2-package-release-checklist.md`](../../releases/clawsig-v0.2-package-release-checklist.md)
- machine-readable checklist: [`docs/releases/clawsig-v0.2-package-release-checklist.v1.json`](../../releases/clawsig-v0.2-package-release-checklist.v1.json)
- release-prep pack/install runner: [`scripts/release/run-clawsig-v0.2-package-prep.mjs`](../../../scripts/release/run-clawsig-v0.2-package-prep.mjs)

## Causal attribution tranche (shipped through CAV-US-023)

Decision freeze for causal attribution work is tracked in:

- [`CAUSAL_ATTRIBUTION_IMPLEMENTATION_CONTRACT_v0.3.md`](../../specs/clawsig-protocol/CAUSAL_ATTRIBUTION_IMPLEMENTATION_CONTRACT_v0.3.md)

Shipped causal lanes on `main`:

- ✅ `CAV-US-001` additive causal binding schema contract — PR #305 (`9d9eb79a`)
- ✅ `CAV-US-002` fail-closed causal DAG verifier checks — PR #305 (`9d9eb79a`)
- ✅ `CAV-US-003` runtime tool-span emission wiring — PR #306 (`934bace6`)
- ✅ `CAV-US-004` CLDD discrepancy enforcement + reason-code closure — PR #307 (`392162e8`)
- ✅ `CAV-US-005` tracer confidence/CLDD delivery surface — PR #308 (`ec382f18`)
- ✅ `CAV-US-006` causal/CLDD fixture + CI guardrails — PR #309 (`3c6db794`)
- ✅ `CAV-US-007` causal binding normalization hardening — PR #310 (`7344fca0`)
- ✅ `CAV-US-008` causal confidence overclaim enforcement — PR #311 (`8071fa99`)
- ✅ `CAV-US-009` causal replay/span-reuse guardrails — PR #312 (`b4fafa2a`)
- ✅ `CAV-US-010` reason-code parity + explain coverage closure — PR #313 (`2ac4ccd3`)
- ✅ `CAV-US-011` causal connectivity/orphan enforcement — PR #314 (`6b543532`)
- ✅ `CAV-US-012` causal mutation-evasion guardrails — PR #315 (`dae42d87`)
- ✅ `CAV-US-013` causal clock monotonicity + phase transition automaton — PR #316 (`d708c4bd`)
- ✅ `CAV-US-014` aggregate causal consistency — PR #317 (`b1b0e989`)
- ✅ `CAV-US-015` causal integrity burn-in meta gate — PR #318 (`adfec1f3`)
- ✅ `CAV-US-016` policy-profile lock (anti-downgrade) — PR #319 (`7a3bfc82`)
- ✅ `CAV-US-017` cross-runtime causal determinism gate — PR #320 (`d2dc1bcd`)
- ✅ `CAV-US-018` truth-sync + release causal evidence contract — PR #321 (`145d0af7`)
- ✅ `CAV-US-019` roadmap truth-sync closure + continuity checker gate — PR #322 (`ede03d37`)
- ✅ `CAV-US-020` deterministic causal reason-code stability gate — PR #323 (`75feadba`)
- ✅ `CAV-US-021` signed causal evidence contract for release gate — PR #324 (`03c1a893`)
- ✅ `CAV-US-022` roadmap continuity hardening for CAV drift prevention — PR #325 (`b9ab26fc`)
- ✅ `CAV-US-023` core/service causal semantics parity uplift — PR #326 (`578b0828`)

## Prior art

- v0.1 changelog: [`CHANGELOG.md`](../../specs/clawsig-protocol/CHANGELOG.md)
- v0.1 tracker: [`docs/roadmaps/clawsig-protocol/prd.json`](../clawsig-protocol/prd.json)
