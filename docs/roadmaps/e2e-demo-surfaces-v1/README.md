> **Type:** Roadmap
> **Status:** COMPLETE
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-03-22
> **Source of truth:** `docs/roadmaps/e2e-demo-surfaces-v1/prd.json` + `progress.txt`
>
> **Scope:**
> - Turn real E2E artifacts into human-usable product surfaces.
> - Use existing sites (`clawea-www`, `clawsig-explorer`) instead of inventing a separate demo microsite.
> - Follow `~/.agents/skills/frontend-skill/SKILL.md` for all public/operator UI work in this roadmap.

# E2E Demo Surfaces v1

This roadmap turns **actual proof artifacts** into **reviewable UI** on the sites people already use.

## Product intent

We already have the evidence:
- DID-signed commit proofs
- proof bundles + run summaries
- arena decision artifacts
- autopilot/productization summaries

What was missing was the presentation layer. The goal here is to make those flows readable by:
- buyers on `clawea.com`
- operators and reviewers on `explorer.clawsig.com`

## UI bar

All UI work in this roadmap follows `~/.agents/skills/frontend-skill/SKILL.md`:
- composition first, not component count
- one dominant idea per section
- cardless by default for branded pages
- utility-first copy for operator surfaces
- strong hierarchy, restrained color, no dashboard-card soup

## Waves

### Wave 1 — shipped in this lane
- `E2E-UI-001` — seed the roadmap + Beads epic/stories
- `E2E-UI-002` — publish public-facing workflow demo on `clawea-www`
- `E2E-UI-003` — publish operator-facing workflow showcase on `clawsig-explorer`

### Wave 2 — shipped in this lane
- ✅ pull deeper live artifact traces into a generated registry instead of curated constants
- ✅ add richer reviewer drill-downs from explorer showcase into inspect/run/arena surfaces

### Wave 3 — shipped in this lane
- ✅ add real staging-safe demo paths with fresh auto-generated artifacts and scheduled refresh

## Closeout
- Feature packaged in PR #539: `feat(e2edemo): ship E2E-UI-002-007 demo surfaces v1`
- Deployed to staging + production on 2026-03-22
- Staging caveat: `staging-www.clawea.com` was DNS-unresolved during smoke while the staging workers.dev instance remained healthy
- Deploy evidence: `artifacts/ops/e2e-demo/deploys/2026-03-22T17-21-22Z/deploy-summary.json`
