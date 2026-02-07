> **Type:** Index
> **Status:** CANONICAL
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-07
> **Source of truth:** this repository (`main`) + `docs/roadmaps/*/progress.txt`
>
> **Scope:**
> - Navigation for the monorepo documentation.
> - Explains what is canonical vs planning vs reference.

# Claw Bureau — Documentation Hub

This `docs/` folder is the canonical, reviewable documentation for the Claw Bureau monorepo.

## What to read first

- `docs/WHAT_TO_READ.md` (fast reading paths by audience)

## Core indexes

- Ecosystem / strategy (context, not binding implementation truth):
  - `docs/ecosystem/README.md`
- PRDs (requirements/intent):
  - `docs/PRD_INDEX.md`
  - `docs/prds/`
- Roadmaps (execution trackers; Ralph compatible):
  - `docs/roadmaps/README.md`
- OpenClaw integration constraints (upstream mirror):
  - `docs/openclaw/README.md`
- Oracle outputs (research inputs, not canonical):
  - `docs/oracle/README.md`

## Core “current truth” docs

These are the docs most likely to matter when making code changes:

- `docs/INTERCONNECTION.md` — cross-service contracts + schema policy
- `docs/GIT_STRATEGY.md` — branch naming + proof requirements
- `docs/AGENT_ECONOMY_MVP_SPEC.md` — marketplace trust/economy spec (implementation-grade, but still evolves)
- `docs/OPENCLAW_INTEGRATION.md` — OpenClaw-first integration constraints

## Roadmaps (active)

- `docs/roadmaps/proof-of-harness/` — PoH v1 (spec + registry + tracking)
- `docs/roadmaps/trust-vnext/` — next building blocks (hardening + consulting + subscription-web strategy)
- `docs/roadmaps/docs-ia/` — docs information architecture / freshness cleanup

## Conventions

- **PRDs** live in `docs/prds/<domain>.md` and are indexed by `docs/PRD_INDEX.md`.
- **Roadmaps** live in `docs/roadmaps/<topic>/` and should include:
  - `prd.json` (machine-readable stories)
  - `progress.txt` (append-only progress log)
  - `README.md` (human entrypoint)
- **Oracle runs** should:
  - live next to the roadmap/spec they inform (preferred), or under `docs/oracle/`
  - include an `INDEX.md` describing prompts + outputs

Docs organization rules + templates:
- `docs/_templates/DOC_RULES.md`
- `docs/_templates/STATUS_BLOCK.md`
