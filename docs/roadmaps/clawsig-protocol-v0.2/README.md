> **Type:** Roadmap
> **Status:** PARTIALLY SHIPPED
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-17
> **Source of truth:** `docs/roadmaps/clawsig-protocol-v0.2/prd.json` + `docs/roadmaps/clawsig-protocol-v0.2/progress.txt`

# Clawsig Protocol v0.2

**Status summary:** R48/R49 tranche is shipped on `main`. CPL-V2-002..005 are complete. Only CPL-V2-001 remains open.

## Shipped stories

| ID | Title | Status | Evidence |
|----|-------|--------|----------|
| CPL-V2-002 | Multi-party receipt co-signing | ✅ complete | PR #281 (`a936c099814802df68e810d974d03017f39fd497`), PR #283 (`7c81b6c45cf1a59fbcf157e99940ce4c09ffa4c5`) |
| CPL-V2-003 | Receipt expiry / TTL semantics | ✅ complete | PR #282 (`4199b2b80ea5e1993e9063b8408dd81b90757e74`), PR #283 (`7c81b6c45cf1a59fbcf157e99940ce4c09ffa4c5`) |
| CPL-V2-004 | Selective disclosure for tool receipt arguments | ✅ complete | PR #281 (`a936c099814802df68e810d974d03017f39fd497`), PR #283 (`7c81b6c45cf1a59fbcf157e99940ce4c09ffa4c5`) |
| CPL-V2-005 | Aggregate proof bundles (bundle-of-bundles) | ✅ complete | PR #282 (`4199b2b80ea5e1993e9063b8408dd81b90757e74`), PR #283 (`7c81b6c45cf1a59fbcf157e99940ce4c09ffa4c5`) |

## Open story

| ID | Title | Priority | Status |
|----|-------|----------|--------|
| CPL-V2-001 | Protocol-level rate limiting semantics | 1 | ⏳ pending |

## Next execution lane

- Branch target: `feat/protocol/CPL-V2-001-rate-limit-semantics`
- Scope: deterministic rate-limit claims, fail-closed verifier behavior, conformance vectors, reason-code wiring.

## Prior art

- v0.1 changelog: [`CHANGELOG.md`](../../specs/clawsig-protocol/CHANGELOG.md)
- v0.1 tracker: [`docs/roadmaps/clawsig-protocol/prd.json`](../clawsig-protocol/prd.json)
