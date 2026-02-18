> **Type:** Roadmap
> **Status:** SHIPPED
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-18
> **Source of truth:** `docs/roadmaps/clawsig-protocol-v0.2/prd.json` + `docs/roadmaps/clawsig-protocol-v0.2/progress.txt`

# Clawsig Protocol v0.2

**Status summary:** v0.2 is fully shipped on `main`. Final remaining lane (CPL-V2-001) merged via PR #285.

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
- v0.2 quickstart fixture manifest: [`packages/schema/fixtures/quickstart/v0.2/manifest.v1.json`](../../../packages/schema/fixtures/quickstart/v0.2/manifest.v1.json)
- v0.2 quickstart runner: [`scripts/protocol/run-clawsig-v0.2-quickstart.mjs`](../../../scripts/protocol/run-clawsig-v0.2-quickstart.mjs)

## Prior art

- v0.1 changelog: [`CHANGELOG.md`](../../specs/clawsig-protocol/CHANGELOG.md)
- v0.1 tracker: [`docs/roadmaps/clawsig-protocol/prd.json`](../clawsig-protocol/prd.json)
