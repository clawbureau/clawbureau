> **Type:** Roadmap
> **Status:** DRAFT
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-12
> **Source of truth:** `docs/roadmaps/clawsig-protocol-v0.2/prd.json`

# Clawsig Protocol v0.2 — Candidate Stories

**Status: Seed.** These stories are identified but not scheduled. v0.1 must see real third-party adoption before committing to v0.2 scope.

## Candidates

| ID | Title | Priority | Why |
|----|-------|----------|-----|
| CPL-V2-001 | Rate limiting semantics | 1 | Detect burst abuse without online state |
| CPL-V2-002 | Multi-party co-signing | 2 | Multi-party attestation for high-stakes agents |
| CPL-V2-003 | Receipt TTL / expiry | 3 | Compliance regimes needing fresh attestations |
| CPL-V2-004 | Selective disclosure | 4 | Audit visibility without full content exposure |
| CPL-V2-005 | Aggregate bundles | 5 | Fleet-level verification + compliance reporting |

## Decision criteria for scheduling

- Real adoption signal (>10 external integrations or enterprise RFPs)
- Concrete use case from a paying customer or major framework
- Backward compatibility with v0.1 (all v0.2 features must be additive)

## Prior art

- v0.1 changelog: [`CHANGELOG.md`](../../specs/clawsig-protocol/CHANGELOG.md)
- v0.1 tracker: [`docs/roadmaps/clawsig-protocol/prd.json`](../clawsig-protocol/prd.json) (12/12 ✅)
