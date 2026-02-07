> **Type:** Guide
> **Status:** ACTIVE
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-07
> **Source of truth:** `scripts/ralph/*` + actual team practice
>
> **Scope:**
> - How to run Ralph + Pi in parallel across domains.

# Parallel Execution Plan (Pi + Ralph)

## Goal
Ship 32 domain services safely and in parallel without losing architectural coherence.

## Pattern

### Ralph Loops (Per-Domain)
- Each domain has its own `prd.json`
- Ralph loops run **one story per iteration**
- Branch naming: `ralph/<domain>/<story-id>`
- Context resets every iteration

### Pi Agents (Cross-Cutting)
Pi agents work across domains on:
- Shared schemas (DID envelopes, receipts, policies)
- Shared SDKs + UI components
- Infrastructure (Workers, auth, CI templates)
- Docs and governance

## Execution Rules
- Ralph handles **domain-specific implementation**
- Pi handles **shared packages + integration**
- All PRs link back to PRDs via story ID
- Shared package changes must be backward-compatible

## Cadence
- Weekly planning sync: update PRD_INDEX priorities
- Daily execution: 2–5 Ralph loops in parallel + 1 Pi integration loop

## Quality Gates
- Typecheck
- Unit tests
- API contract tests
- PRD acceptance criteria verification

