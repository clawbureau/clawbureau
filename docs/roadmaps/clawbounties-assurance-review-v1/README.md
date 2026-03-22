> **Type:** Roadmap
> **Status:** ACTIVE
> **Owner:** @clawbureau/labor
> **Last reviewed:** 2026-03-22
> **Source of truth:** `docs/roadmaps/clawbounties-assurance-review-v1/prd.json` + `progress.txt`
>
> **Scope:**
> - Bring compiled evidence / assurance outputs into the live Clawbounties reviewer workflow.
> - Make requester/reviewer decisions faster without letting narrative or optional membranes override authoritative results.

# Clawbounties Assurance Review v1

## Context

Clawbounties already accepts proof bundles, proof tiers, marketplace assurance requirements, and reviewer/arena workflows. Clawcompiler Runtime v1 now adds deterministic compiled evidence reports, execution assurance packs, export/viewer integration, and a non-authoritative narrative membrane. The next product step is to make those compiled outputs visible and useful inside the actual marketplace review loop.

## Product goal

Turn Clawbounties submission review into a trust legibility surface that can honestly say:

> This submission is not just `proof_verify_status=valid`; here is the authoritative compiled matrix, the important non-pass controls, and the exact boundary between machine-verifiable evidence and optional narrative explanation.

## Principles

- Never let narrative override authoritative compiled results.
- Keep marketplace review additive first: surface better evidence before adding aggressive new gating.
- Preserve fail-closed behavior when compiled evidence is malformed, missing where required, or inconsistent with the proof bundle.
- Keep reviewer surfaces concise and decision-oriented.
- Reuse existing compiled evidence formats instead of inventing marketplace-only one-offs.

## Proposed tracks

### Track A — Submission assurance ingestion
- `CBA-RV-001` compiled evidence attachment contract on submissions
- `CBA-RV-002` compiled evidence verification + normalization at ingest

### Track B — Reviewer-facing assurance surfaces
- `CBA-RV-003` submission detail/list assurance summary
- `CBA-RV-004` requester/reviewer next-actions + approval surfaces

### Track C — Arena/operator propagation
- `CBA-RV-005` arena and manager-review compiled evidence carry-through

## Execution waves

### Wave 1 — Submission assurance contract
- `CBA-RV-001` compiled evidence attachment contract
- `CBA-RV-002` compiled evidence verification + normalization
- `CBA-RV-003` submission detail/list assurance summary

### Wave 2 — Review workflow adoption
- `CBA-RV-004` requester/reviewer next-actions + approval surfaces
- `CBA-RV-005` arena + manager-review compiled evidence propagation

## Current status

- Wave 1 shipped via PR #527.
- `CBA-RV-001`, `CBA-RV-002`, and `CBA-RV-003` are complete.
- Roadmap status is now **3/5 stories shipped**.
- Next wave: `CBA-RV-004` requester/reviewer next-actions + approval surfaces and `CBA-RV-005` arena/manager-review propagation.

## Success criteria

- Submission detail/list endpoints expose authoritative compiled evidence summaries when available.
- Reviewer surfaces distinguish authoritative matrix vs optional narrative.
- Invalid/malformed compiled evidence is surfaced deterministically and cannot silently improve approval posture.
- Reviewers can make better approval/reject/request-changes decisions without opening raw proof artifacts first.
