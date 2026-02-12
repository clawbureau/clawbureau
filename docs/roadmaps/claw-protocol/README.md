> **Type:** Roadmap
> **Status:** ACTIVE
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-12
> **Source of truth:** `docs/roadmaps/claw-protocol/prd.json` + `docs/roadmaps/claw-protocol/progress.txt`
>
> **Scope:**
> - Execution roadmap for turning Claw from a suite of services into a **protocol** with a tiny, open narrow waist.
> - This roadmap is cross-service by design (clawcontrols + clawscope + clawproxy + clawverify + OpenClaw integrations).

# Claw Protocol — Roadmap (v0.1)

## Why this roadmap exists

Security alone earns procurement.

To become **the protocol** (lowest friction + highest trust), Claw needs:
- a tiny, implementable narrow waist (5 primitives)
- explicit coverage semantics (no ambiguous “every action attested”)
- a human UX that feels like autocomplete (diff-first approvals, scoped delegation)
- agent UX with deterministic denial semantics (capability negotiation)

## Canonical spec

- `docs/specs/claw-protocol/CLAW_PROTOCOL_v0.1.md`

## Related PRDs (requirements intent)

- `docs/prds/clawcontrols.md` (Policy Artifact / WPC)
- `docs/prds/clawscope.md` (Capability Token / CST)
- `docs/prds/clawproxy.md` (Model gateway receipts)
- `docs/prds/clawverify.md` (Verifier)
- `docs/prds/clawea-enterprise.md` (approval UX + enterprise posture)
- `docs/prds/clawproviders.md` (ecosystem supply-chain + “Claw Verified” mark)

## Execution tracker

- Stories: `docs/roadmaps/claw-protocol/prd.json`
- Progress log: `docs/roadmaps/claw-protocol/progress.txt`

## Guiding constraints

- **Fail-closed** by default in verification/auth.
- **Deterministic semantics** (stable reason codes; idempotency everywhere).
- **Progressive adoption** is a feature:
  - observe (emit receipts)
  - receipt (portable proof)
  - enforce (block missing receipts / policy violations)
- **Modules remain optional** (payments/escrow/marketplace are not the protocol).
