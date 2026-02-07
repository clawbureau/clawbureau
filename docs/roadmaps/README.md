> **Type:** Index
> **Status:** CANONICAL
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-07
> **Source of truth:** `docs/roadmaps/*/prd.json` + `docs/roadmaps/*/progress.txt`
>
> **Scope:**
> - Roadmaps are the execution layer: concrete stories + progress logs.
> - Roadmaps are the canonical “what we’re doing next”.

# Roadmaps

Roadmaps are the **execution layer** of planning: concrete stories + progress logs that can be run via `scripts/ralph/ralph.sh`.

## Active roadmaps

- **Proof-of-Harness (adapters + registry + specs)**
  - Folder: `docs/roadmaps/proof-of-harness/`
  - Status: **POH-US-001 … POH-US-012 complete** (see `progress.txt`)

- **Trust vNext (PoH hardening + prompt integrity + confidential consulting + subscription-web strategy)**
  - Folder: `docs/roadmaps/trust-vnext/`
  - Status: planned; seeded from oracle synthesis `docs/roadmaps/proof-of-harness/oracle/2026-02-07/next-building-blocks-plan.gpt-5.2-pro.md`

- **Docs IA (docs information architecture + freshness cleanup)**
  - Folder: `docs/roadmaps/docs-ia/`
  - Status: active

## Roadmap folder contract (Ralph-compatible)

Each roadmap folder should contain:
- `prd.json`
- `progress.txt`
- `README.md`

Optional but recommended:
- `oracle/<YYYY-MM-DD>/` (prompts, outputs, INDEX)
- `specs/` (long-lived specs / protocols)
