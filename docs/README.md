# Claw Bureau — Documentation Hub

This `docs/` folder is the canonical, reviewable documentation for the Claw Bureau monorepo.

## Start here

- Ecosystem / strategy:
  - `docs/ecosystem/README.md`
  - `docs/ecosystem/STRATEGIC_PLAN.md`
  - `docs/ecosystem/ECOSYSTEM-MAP.md`
- Product / architecture:
  - `docs/ARCHITECTURE.md`
  - `docs/INTERCONNECTION.md`
  - `docs/AGENT_ECONOMY_MVP_SPEC.md`
- Roadmaps (tracked with `prd.json` + `progress.txt`):
  - `docs/roadmaps/README.md`
  - `docs/roadmaps/proof-of-harness/README.md`
  - `docs/roadmaps/trust-vnext/README.md`
- PRDs (per domain):
  - `docs/PRD_INDEX.md`
  - `docs/prds/`
- OpenClaw integration constraints (local mirror):
  - `docs/openclaw/README.md`
- Oracle research outputs:
  - `docs/oracle/README.md`

## Conventions

- **PRDs** live in `docs/prds/<domain>.md` and are indexed by `docs/PRD_INDEX.md`.
- **Roadmaps** live in `docs/roadmaps/<topic>/` and should include:
  - `prd.json` (machine-readable stories)
  - `progress.txt` (append-only progress log; Ralph-compatible)
  - `README.md` (human entrypoint)
- **Oracle runs** should:
  - live next to the roadmap/spec they inform (preferred), or under `docs/oracle/`
  - include an `INDEX.md` describing prompts + outputs

If you’re unsure where a new doc belongs, default to:
- PRD change → `docs/prds/...`
- Implementation roadmap / story tracking → `docs/roadmaps/...`
- Long research dump → `docs/oracle/...` (and link it from the nearest roadmap/PRD)
