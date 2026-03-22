> **Type:** Roadmap
> **Status:** ACTIVE
> **Owner:** @clawbureau/labor
> **Last reviewed:** 2026-03-22
> **Source of truth:** `docs/roadmaps/clawbounties-assurance-decision-policy-v1/prd.json` + `progress.txt`
>
> **Scope:**
> - Turn compiled evidence from reviewer context into deterministic marketplace decision policy.
> - Make requester approval, arena desk loops, and manager autopilot consume the same authoritative compiled-evidence contract.

# Clawbounties Assurance Decision Policy v1

## Context

Clawbounties Assurance Review v1 made compiled evidence visible inside submission detail/list APIs, requester/reviewer next-actions, and arena/operator surfaces. That solved trust legibility, but not decision consistency: the marketplace still treats compiled evidence mostly as a reviewer hint instead of a canonical approval policy input.

Today, authoritative compiled non-pass findings can be visible while requester approval, arena desk actions, and manager autopilot continue to rely primarily on proof/payout readiness. That leaves too much room for silent inconsistency: strong evidence may be shown but not actually drive approval posture, and override behavior is not yet explicit enough for later audit.

## Product goal

Turn compiled evidence into a deterministic decision layer that can honestly say:

> This submission is approve-recommended, manual-review-required, or fix-required — and if a human overrides that posture, the marketplace records exactly what evidence was seen and why the override happened.

## Principles

- Only authoritative compiled evidence can improve approval posture; narrative or reference-only inputs never count as authoritative pass evidence.
- Distinguish **approve recommended**, **manual review required**, and **fix required** as first-class decision states.
- Requester closure can remain manual, but approving against non-green evidence must be explicit and auditable.
- Arena desk and manager autopilot must fail closed to manual review when compiled evidence is unavailable, unverified, or non-pass.
- Decision snapshots must preserve authoritative-vs-non-authoritative boundaries for later reviewer/operator audit.

## Proposed tracks

### Track A — Canonical compiled-evidence decision policy
- `CBA-DP-001` canonical compiled-evidence decision evaluator
- `CBA-DP-002` requester approval override + fail-closed requester contract

### Track B — Automation adoption
- `CBA-DP-003` arena desk decision policy adoption
- `CBA-DP-004` manager autopilot compiled-evidence guardrails

### Track C — Decision auditability
- `CBA-DP-005` persisted decision snapshots and override audit surfaces

## Execution waves

### Wave 1 — Decision policy foundations
- `CBA-DP-001` canonical compiled-evidence decision evaluator
- `CBA-DP-002` requester approval override + fail-closed requester contract
- `CBA-DP-003` arena desk decision policy adoption

### Wave 2 — Autopilot + audit closeout
- `CBA-DP-004` manager autopilot compiled-evidence guardrails
- `CBA-DP-005` persisted decision snapshots and override audit surfaces

## Current status

- Wave 1 shipped via PR #533.
- `CBA-DP-001` through `CBA-DP-003` are complete.
- Wave 2 remains:
  - `CBA-DP-004` manager autopilot compiled-evidence guardrails
  - `CBA-DP-005` decision snapshots and override audit surfaces
- Roadmap status is now **3/5 stories shipped**.
- Implementation is still centered in `services/_archived/clawbounties/src/index.ts`, so Wave 2 should remain a mostly single-lane execution tranche.

## Success criteria

- Submission/requester review flows expose a canonical compiled-evidence decision state instead of only loose reviewer hints.
- Requester approval against non-green compiled evidence requires explicit override acknowledgement; fix-required posture fails closed.
- Arena desk auto-approval only happens when compiled evidence is decision-green.
- Manager autopilot drops to manual review when compiled evidence posture is non-pass, unverified, or unavailable.
- Submission/bounty/arena/operator surfaces preserve a compact decision snapshot showing what evidence posture drove the last decision.
