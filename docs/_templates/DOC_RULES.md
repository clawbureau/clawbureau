# Docs rules (where things go)

Use this as the canonical guideline for adding/organizing documentation.

## Folder map

- `docs/README.md` — docs hub / navigation
- `docs/ecosystem/` — ecosystem strategy + workspace context
- `docs/prds/` — domain PRDs (requirements/intent)
- `docs/roadmaps/` — execution trackers (`prd.json` + `progress.txt`)
- `docs/openclaw/` — upstream OpenClaw docs mirror (reference constraints)
- `docs/oracle/` — oracle outputs that are not colocated with a specific roadmap

As the repo grows, we also use:
- `docs/foundations/` — repo-level “rules that can break systems if wrong” (contracts, invariants)
- `docs/specs/` — cross-domain implementation specs (stitch multiple PRDs/roadmaps)
- `docs/integration/` — integration docs that cut across repos/systems (OpenClaw bridge, etc.)
- `docs/plans/` — non-binding go-to-market / SEO / launch plans
- `docs/archive/` — explicitly not current; preserved history

## Status blocks are required

Anything that can be mistaken for current truth must start with a status block.

Template:
- `docs/_templates/STATUS_BLOCK.md`

Minimum expectation:
- Hubs/indexes, foundations, specs, and roadmap READMEs must have a status block.
- PRDs should clearly state whether they are *requirements intent* vs *shipped behavior*.

## Principle

- **Roadmaps** are the canonical “what we’re doing next.”
- **PRDs** are canonical “what we want.”
- **Code + schemas** are canonical “what is true today.”
- **Oracle outputs** are inputs, not truth.
