> **Type:** Index
> **Status:** CANONICAL
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-12
> **Source of truth:** `docs/roadmaps/*/prd.json` + `docs/roadmaps/*/progress.txt`
>
> **Scope:**
> - Roadmaps are the execution layer: concrete stories + progress logs.
> - Roadmaps are the canonical “what we’re doing next”.

# Roadmaps

Roadmaps are the **execution layer** of planning: concrete stories + progress logs that can be run via `scripts/ralph/ralph.sh`.

## Active roadmaps

- **Clawsig Protocol (narrow waist + explicit coverage + frictionless governance)**
  - Folder: `docs/roadmaps/clawsig-protocol/`
  - Status: active (see `prd.json` + `progress.txt`)

- **Docs IA (docs information architecture + freshness cleanup)**
  - Folder: `docs/roadmaps/docs-ia/`
  - Status: active

## Completed roadmaps

- **Proof-of-Harness (adapters + registry + specs)**
  - Folder: `docs/roadmaps/proof-of-harness/`
  - Status: complete (see `prd.json` + `progress.txt`)

- **Trust vNext (PoH hardening + prompt integrity + confidential consulting + subscription-web strategy)**
  - Folder: `docs/roadmaps/trust-vnext/`
  - Status: complete (see `prd.json` + `progress.txt`)

## Roadmap folder contract (Ralph-compatible)

Each roadmap folder should contain:
- `prd.json`
- `progress.txt`
- `README.md`

Optional but recommended:
- `oracle/<YYYY-MM-DD>/` (prompts, outputs, INDEX)
- `specs/` (long-lived specs / protocols)
