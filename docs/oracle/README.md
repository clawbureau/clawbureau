> **Type:** Index
> **Status:** REFERENCE
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-07
> **Source of truth:** oracle run outputs (non-canonical)
>
> **Scope:**
> - Oracle-generated research artifacts.
> - Inputs to planning; **not** canonical system truth.

# Oracle Outputs

This folder contains **Oracle-generated research** and planning artifacts.

## Roadmaps (oracle-generated; archive)

- `docs/oracle/roadmaps/` — older oracle-generated roadmaps (“remaining stories”, launch sprints, merge plans, etc.)

## PoH / Trust research

Newer PoH-focused oracle batches are colocated with the PoH roadmap:
- `docs/roadmaps/proof-of-harness/oracle/2026-02-07/`

That folder contains:
- prompts (`PROMPT_*.md`)
- outputs (`*.gpt-5.2-pro.md`, `*.google-gemini-3-pro-preview.md`)
- an index (`INDEX.md`)

## Convention

- Prefer colocating oracle runs next to the roadmap/spec they inform.
- Always include an `INDEX.md` describing what ran, with stable file links.
