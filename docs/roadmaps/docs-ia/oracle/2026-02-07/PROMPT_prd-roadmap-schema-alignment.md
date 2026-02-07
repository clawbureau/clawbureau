# Oracle prompt: PRD ↔ Roadmap ↔ Schema alignment audit

We need to answer:
- Are the domain PRDs under `docs/prds/` aligned with:
  - execution trackers/roadmaps (`docs/roadmaps/*` and per-service `services/*/{prd.json,progress.txt}`), and
  - shared schemas (`packages/schema/*`)?
- Are they being kept up to date?

You are given the current docs/PRDs/roadmaps/schemas (and a generated PRD↔tracker matrix). Audit drift and propose fixes.

## Tasks

1) Produce an **alignment scorecard** with a table per PRD (one row per domain):
   - PRD file
   - Has execution tracker? (where)
   - References schemas? (which)
   - Drift severity: LOW / MED / HIGH
   - What is stale / mismatched (short bullets)
   - Recommended action: Keep / Update / Add status banner / Add “Implementation status” link / Move to archive

2) Identify **systemic drift patterns** (examples: tier naming changes, schema versions, WPC/CWC terminology, endpoints renamed, etc.).

3) Decide what “kept up to date” should mean here:
   - Which docs are canonical truth vs intent vs reference
   - What must be updated when schemas change
   - What must be updated when a roadmap story completes

4) Propose an **enforcement / maintenance mechanism**:
   - minimal friction
   - ideally some CI checks (e.g., PRDs must link to tracker, status banner required, schema IDs referenced must exist)
   - do NOT require perfect automation; pragmatic checks are fine.

5) Output a **concrete next PR plan** (small PRs) to reduce drift:
   - exact files to touch
   - suggested order

## Constraints
- Prefer archiving to deleting.
- Do not break the existing roadmap pattern.
- Be explicit about what’s currently aspirational vs implemented.

## Output format
- Alignment scorecard table
- Drift patterns
- Definition of “up to date” + canonical truth model
- Maintenance/CI proposal
- Next PR plan
