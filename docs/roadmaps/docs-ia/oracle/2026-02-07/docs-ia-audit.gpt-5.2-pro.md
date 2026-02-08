## IA proposal (for `docs/`)

### Goals (opinionated)
1. **One default path** for “current truth”: contracts, invariants, and “how the repo works today”.
2. **Planned/intended** docs are still easy to find, but impossible to confuse with current behavior.
3. Roadmaps remain the **execution truth** for work-in-progress (`docs/roadmaps/*/prd.json` + `progress.txt`).

### Proposed folder structure (minimal disruption, strong clarity)

```
docs/
  README.md                         # top hub (canonical entrypoint)  [exists]
  _templates/
    STATUS_BLOCK.md                 # copy/paste status banner
    DOC_RULES.md                    # what goes where + required fields

  foundations/                      # "how this repo works" + hard rules
    README.md                       # index
    ARCHITECTURE.md                 # current state architecture (not marketing pillars)
    INTERCONNECTION.md              # dependency + schema policy
    GIT_STRATEGY.md                 # branch/PR/proof rules
    PARALLEL_EXECUTION.md           # Ralph/Pi parallelism rules

  specs/                            # cross-domain implementation specs (not per-service PRDs)
    README.md                       # index
    agent-economy/
      MVP.md                        # moved from root

  integration/                      # integration guides that cut across domains
    README.md                       # index
    OPENCLAW_INTEGRATION.md         # moved from root (Claw Bureau ↔ OpenClaw plan)

  prds/                             # domain PRDs (keep as-is)         [exists]
  roadmaps/                         # execution trackers (keep as-is)  [exists]
  ecosystem/                        # strategy + workspace context      [exists]
  openclaw/                         # upstream mirror/reference         [exists]
  oracle/                           # oracle outputs (archive + overflow) [exists]

  plans/                            # non-binding go-to-market / SEO / launch plans (not specs)
    README.md                       # index + disclaimers
    joinclaw/PLAN.md
    clawproviders/SEO_PLAN.md

  archive/                          # explicitly “not current”; preserved history
    README.md
    ecosystem/                      # moved research notes if desired
    oracle-roadmaps/                # legacy oracle roadmaps (optional move)
```

### What belongs where (rules)
- **`foundations/`**: rules that can break systems if wrong (schemas, idempotency norms, inter-service policy, PR proof rules). Current candidates:  
  - `docs/INTERCONNECTION.md`  
  - `docs/GIT_STRATEGY.md`  
  - `docs/PARALLEL_EXECUTION.md`  
  - `docs/ARCHITECTURE.md` (but rewritten to “current state”; today it’s pillar-y and thin)  
- **`specs/`**: cross-domain, implementation-grade specs that stitch multiple PRDs together (ex: “Agent Economy MVP”). Current candidate: `docs/AGENT_ECONOMY_MVP_SPEC.md`.
- **`integration/`**: integration plans that describe how Claw Bureau maps into external systems. Current candidate: `docs/OPENCLAW_INTEGRATION.md`.
- **`prds/`**: per-domain “product requirements” (intended behavior). Keep `docs/PRD_INDEX.md` as the canonical index (`docs/PRD_INDEX.md`).
- **`roadmaps/`**: story trackers + progress logs (canonical “what we’re doing next”), must keep structure (`docs/roadmaps/README.md`, `docs/roadmaps/proof-of-harness/*`, `docs/roadmaps/trust-vnext/*`, `docs/roadmaps/docs-ia/*`).
- **`plans/`**: marketing/site plans that may conflict with implementation; never treated as canonical system truth. Current examples:  
  - `docs/CLAWPROVIDERS_SEO_PLAN.md` (explicitly planning)  
  - `docs/JOINCLAW_PLAN.md`
- **`oracle/`**: oracle-generated artifacts that are *inputs*, not truth. Keep PoH oracle batches colocated with PoH roadmap (already done in `docs/roadmaps/proof-of-harness/oracle/2026-02-07/INDEX.md`).

### What should be indexed by default (the “main menus”)
Update `docs/README.md` (currently good, but too flat) to link only to:
1. **Start / reading maps** (new small index doc; see reading map section below)
2. **Foundations** index (`docs/foundations/README.md`)
3. **PRDs** (`docs/PRD_INDEX.md`)
4. **Roadmaps** (`docs/roadmaps/README.md`)
5. **Specs** index (`docs/specs/README.md`)
6. **Integration** index (`docs/integration/README.md`)
7. **OpenClaw mirror** (`docs/openclaw/README.md`)
8. **Oracle** (`docs/oracle/README.md`) but labeled “non-canonical research”

(Keep `docs/ecosystem/README.md` linked, but mark it “strategy/workspace context”, not implementation truth.)

---

## Docs status convention (freshness + truth signaling)

### Principle
Every “decision-bearing” doc starts with a **status block** that answers:
- Is this **current truth** or **intent**?
- Who owns it?
- When was it last reviewed?
- What supersedes it?

### Required header block (copy/paste)

Put this at the top of any key doc:

```md
---
doc_status: CANONICAL | ACTIVE | DRAFT | REFERENCE | ARCHIVE
last_reviewed: 2026-02-07
owner: "@team-or-github-handle"
audience: contributors | marketplace | trust | openclaw | ops
scope: >
  One paragraph: what this document covers (and what it explicitly does not).
source_of_truth: >
  Link(s) to code, schemas, PRDs, or roadmap stories that define truth.
supersedes: []
superseded_by: []
staleness:
  review_by: 2026-03-07
  risk_if_stale: LOW | MED | HIGH
---
```

Then an explicit banner line:

```md
> **Status:** DRAFT (intent). Do not treat as current behavior unless linked from a passing roadmap story/prod code.
```

### Status meanings (single axis, strong semantics)
- **CANONICAL**: current repo truth; safe to implement against.
- **ACTIVE**: current but evolving; generally safe; verify against roadmaps/code.
- **DRAFT**: intended design/spec; not yet true; must link to roadmap/PRDs.
- **REFERENCE**: constraints/externals (e.g., OpenClaw mirror), useful but not “our behavior”.
- **ARCHIVE**: preserved history; never current.

### Which documents MUST include status
Must include the block:
- Top hubs/indexes: `docs/README.md`, `docs/roadmaps/README.md`, `docs/ecosystem/README.md`, `docs/oracle/README.md`, `docs/openclaw/README.md`
- All **Foundations** docs: `docs/ARCHITECTURE.md`, `docs/INTERCONNECTION.md`, `docs/GIT_STRATEGY.md`, `docs/PARALLEL_EXECUTION.md`
- All cross-domain **specs**: `docs/AGENT_ECONOMY_MVP_SPEC.md`, `docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md`
- All PRDs under `docs/prds/*.md` (they already have “Status: Draft”; formalize into the block)
- Every roadmap `README.md` under `docs/roadmaps/*/README.md` (and optionally `prd.json` gets a `metadata.status` field later—unknown if you want machine enforcement)

---

## Canonical reading map (4 audiences)

### 1) New contributor (5–10 minutes)
Order:
1. `docs/README.md` (hub)  
2. `docs/ecosystem/AGENTS.md` (workspace quickstart + live status; note it contains current operational notes)  
3. `docs/foundations/INTERCONNECTION.md` (contracts/schema rules; currently `docs/INTERCONNECTION.md`)  
4. `docs/foundations/GIT_STRATEGY.md` (branch/PR/proof rules; currently `docs/GIT_STRATEGY.md`)  
5. `docs/roadmaps/README.md` (how work is tracked/executed)

Files cited: `docs/README.md`, `docs/ecosystem/AGENTS.md`, `docs/INTERCONNECTION.md`, `docs/GIT_STRATEGY.md`, `docs/roadmaps/README.md`.

### 2) Marketplace engineer (clawbounties / escrow / ledger)
Order:
1. `docs/specs/agent-economy/MVP.md` (currently `docs/AGENT_ECONOMY_MVP_SPEC.md`) — end-to-end flow + invariants  
2. PRDs:
   - `docs/prds/clawbounties.md`
   - `docs/prds/clawescrow.md`
   - `docs/prds/clawledger.md`
   - `docs/prds/clawcuts.md`
   - `docs/prds/clawsettle.md`
   - `docs/prds/clawincome.md`
3. `docs/foundations/INTERCONNECTION.md` (schemas/events/idempotency expectations)

Files cited: `docs/AGENT_ECONOMY_MVP_SPEC.md`, `docs/prds/clawbounties.md`, `docs/prds/clawescrow.md`, `docs/prds/clawledger.md`, `docs/prds/clawcuts.md`, `docs/prds/clawsettle.md`, `docs/prds/clawincome.md`, `docs/INTERCONNECTION.md`.

### 3) Trust / PoH engineer (clawproxy / clawverify / PoH)
Order:
1. PoH roadmap entrypoint: `docs/roadmaps/proof-of-harness/README.md`  
2. PoH spec: `docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md`  
3. Harness registry: `docs/roadmaps/proof-of-harness/HARNESS_REGISTRY.md`  
4. Trust vNext tracker: `docs/roadmaps/trust-vnext/README.md` + `docs/roadmaps/trust-vnext/prd.json`  
5. PRDs:
   - `docs/prds/clawproxy.md`
   - `docs/prds/clawverify.md`
   - (optional) `docs/prds/clawea.md` (attestation runner)

Files cited: `docs/roadmaps/proof-of-harness/README.md`, `docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md`, `docs/roadmaps/proof-of-harness/HARNESS_REGISTRY.md`, `docs/roadmaps/trust-vnext/README.md`, `docs/roadmaps/trust-vnext/prd.json`, `docs/prds/clawproxy.md`, `docs/prds/clawverify.md`, `docs/prds/clawea.md`.

### 4) OpenClaw integration engineer
Order:
1. `docs/integration/OPENCLAW_INTEGRATION.md` (currently `docs/OPENCLAW_INTEGRATION.md`)  
2. OpenClaw mirror hub: `docs/openclaw/README.md`  
3. OpenClaw constraints (typical):
   - `docs/openclaw/10-extensions-and-plugins.md`
   - `docs/openclaw/6.2-tool-security-and-sandboxing.md`
   - `docs/openclaw/4.3-multi-agent-configuration.md`
   - `docs/openclaw/3.2-gateway-protocol.md`
4. PoH integration points:
   - `docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md`
   - `docs/prds/clawproxy.md`

Files cited: `docs/OPENCLAW_INTEGRATION.md`, `docs/openclaw/README.md`, `docs/openclaw/10-extensions-and-plugins.md`, `docs/openclaw/6.2-tool-security-and-sandboxing.md`, `docs/openclaw/4.3-multi-agent-configuration.md`, `docs/openclaw/3.2-gateway-protocol.md`, `docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md`, `docs/prds/clawproxy.md`.

---

## Classification & actions (audit of current docs)

**Inventory source:** `docs/roadmaps/docs-ia/oracle/2026-02-07/DOCS_INVENTORY.md`.

### A) Top-level hubs / foundations / specs / integration

| Path | Class | Action | Notes |
|---|---|---|---|
| `docs/README.md` | CANONICAL | **Keep**, add status block, update links to new IA indexes | Already a good hub; becomes “default truth map”. |
| `docs/ARCHITECTURE.md` | DRAFT (too thin) | **Move** → `docs/foundations/ARCHITECTURE.md`, add banner; **consider split** | Current text is pillars, not “current architecture” (`docs/ARCHITECTURE.md`). |
| `docs/INTERCONNECTION.md` | CANONICAL | **Move** → `docs/foundations/INTERCONNECTION.md`, add status block | Strong “contracts not trust” guidance (`docs/INTERCONNECTION.md`). |
| `docs/GIT_STRATEGY.md` | CANONICAL | **Move** → `docs/foundations/GIT_STRATEGY.md`, add status block | Operationally binding (`docs/GIT_STRATEGY.md`). |
| `docs/PARALLEL_EXECUTION.md` | ACTIVE | **Move** → `docs/foundations/PARALLEL_EXECUTION.md`, add status block | Execution policy (`docs/PARALLEL_EXECUTION.md`). |
| `docs/AGENT_ECONOMY_MVP_SPEC.md` | ACTIVE (spec) | **Move** → `docs/specs/agent-economy/MVP.md`, add status block | Already has “Status: Draft spec (implementation-ready)”—formalize (`docs/AGENT_ECONOMY_MVP_SPEC.md`). |
| `docs/OPENCLAW_INTEGRATION.md` | ACTIVE | **Move** → `docs/integration/OPENCLAW_INTEGRATION.md`, add status block | Clear mapping doc; keep separate from mirror (`docs/OPENCLAW_INTEGRATION.md`). |
| `docs/PRD_INDEX.md` | CANONICAL | **Keep**, add status block; optionally add “PRD status” column later | It is the canonical index (`docs/PRD_INDEX.md`). |

### B) Ecosystem folder (`docs/ecosystem/`)
These are valuable, but must be clearly **strategy/research** vs repo truth.

| Path | Class | Action | Notes |
|---|---|---|---|
| `docs/ecosystem/README.md` | CANONICAL (hub) | **Keep**, add status block + add “what is binding vs not” | Currently mixes both (`docs/ecosystem/README.md`). |
| `docs/ecosystem/AGENTS.md` | ACTIVE | **Keep**, add status block (HIGH staleness risk) | Contains live operational claims (“implemented PR #53”) (`docs/ecosystem/AGENTS.md`). |
| `docs/ecosystem/STRATEGIC_PLAN.md` | DRAFT/PLANNING | **Keep**, add strong planning banner | It self-identifies planning (`docs/ecosystem/STRATEGIC_PLAN.md`). |
| `docs/ecosystem/ECOSYSTEM-MAP.md` | REFERENCE (oracle snapshot) | **Keep**, add “oracle snapshot” banner | Generated by oracle; not implementation truth (`docs/ecosystem/ECOSYSTEM-MAP.md`). |
| `docs/ecosystem/ORACLE-ECOSYSTEM-MAP.md` | ARCHIVE or REFERENCE | **Archive or merge** | Duplicative with ECOSYSTEM-MAP; pick one canonical snapshot; I’d archive this one with a pointer (`docs/ecosystem/ORACLE-ECOSYSTEM-MAP.md`). |
| `docs/ecosystem/cf-domains.md` | REFERENCE | **Keep**, add banner | It’s a registrar dump; not system behavior (`docs/ecosystem/cf-domains.md`). |
| `docs/ecosystem/chat-ideas.md` | ARCHIVE (research notes) | **Move** → `docs/archive/ecosystem/chat-ideas.md` *or* keep with ARCHIVE banner | It’s raw brainstorming; high confusion risk (`docs/ecosystem/chat-ideas.md`). |
| `docs/ecosystem/cloudflare-moltworker.md` | REFERENCE | **Move** → `docs/archive/ecosystem/cloudflare-moltworker.md` *or* keep with REFERENCE banner | It’s essentially an excerpt/reference (`docs/ecosystem/cloudflare-moltworker.md`). |

### C) Roadmaps (`docs/roadmaps/*`)
Roadmaps are execution truth; keep structure unchanged.

| Path | Class | Action | Notes |
|---|---|---|---|
| `docs/roadmaps/README.md` | CANONICAL | **Keep**, add status block | Already defines contract (`docs/roadmaps/README.md`). |
| `docs/roadmaps/proof-of-harness/*` | CANONICAL/ACTIVE | **Keep**, ensure status blocks on README/spec | This is current active engineering truth (`docs/roadmaps/proof-of-harness/README.md`, `docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md`). |
| `docs/roadmaps/trust-vnext/*` | ACTIVE (planned execution) | **Keep**, add status block | Seeded from oracle; but it’s now an execution tracker (`docs/roadmaps/trust-vnext/README.md`, `docs/roadmaps/trust-vnext/prd.json`). |
| `docs/roadmaps/docs-ia/*` | ACTIVE | **Keep** | This effort itself (`docs/roadmaps/docs-ia/README.md`, `docs/roadmaps/docs-ia/prd.json`). |

### D) PRDs (`docs/prds/*.md`)
Treat PRDs as **canonical intent per-domain**, but not “current behavior” unless linked to shipped code/roadmap completion. Action: add standardized status blocks; optionally add `owner` fields later.

- **Class:** DRAFT (intent) for most PRDs as written (they all say “Status: Draft”), but **keep them canonical as the requirement source**.
- **Action:** **Keep**, add status block to each, and add a one-line “Implementation status lives in roadmaps and code” banner.

Examples cited: `docs/prds/clawbounties.md`, `docs/prds/clawproxy.md`, `docs/prds/clawverify.md`, etc.

**Special conflict to resolve:**
- `docs/CLAWPROVIDERS_SEO_PLAN.md` claims: “This PRD supersedes the registry-focused `clawproviders.md` PRD for MVP”. That’s currently a footgun.
  - Action: mark `docs/prds/clawproviders.md` as **DRAFT (superseded for MVP)** and link to the plan (after moving it under `docs/plans/`), or update the plan to be an appendix to the PRD.

Files cited: `docs/CLAWPROVIDERS_SEO_PLAN.md`, `docs/prds/clawproviders.md`.

### E) OpenClaw mirror (`docs/openclaw/*`)
- **Class:** REFERENCE
- **Action:** **Keep in place**, do not intermingle. Optionally add a short status block to `docs/openclaw/README.md` clarifying “mirror/reference”.

File cited: `docs/openclaw/README.md`.

### F) Oracle (`docs/oracle/*` and PoH colocated oracle runs)
- `docs/oracle/README.md` is a useful hub but must be explicit “non-canonical research” (it already is).
- `docs/oracle/roadmaps/*` are explicitly archived by `docs/oracle/roadmaps/README.md`.

Actions:
- Add status blocks to `docs/oracle/README.md` and `docs/oracle/roadmaps/README.md`.
- Consider moving `docs/oracle/roadmaps/` → `docs/archive/oracle-roadmaps/` later (optional; only if link churn is acceptable).

Files cited: `docs/oracle/README.md`, `docs/oracle/roadmaps/README.md`, `docs/roadmaps/proof-of-harness/oracle/2026-02-07/INDEX.md`.

### G) Plans at root (currently risky)
| Path | Class | Action | Notes |
|---|---|---|---|
| `docs/CLAWPROVIDERS_SEO_PLAN.md` | DRAFT/PLANNING | **Move** → `docs/plans/clawproviders/SEO_PLAN.md`, add banner, link from PRD | Planning doc; conflicts with PRD unless reconciled. |
| `docs/JOINCLAW_PLAN.md` | DRAFT/PLANNING | **Move** → `docs/plans/joinclaw/PLAN.md`, add banner | Same: plan, not system spec. |

Files cited: `docs/CLAWPROVIDERS_SEO_PLAN.md`, `docs/JOINCLAW_PLAN.md`.

### Deletes
None recommended. Prefer archive/move + banners.

---

## PR implementation plan (as if preparing PRs)

### Link-fix strategy (avoid chaos)
1. **Do moves with stubs**: leave the old file path in place containing only:
   - an **ARCHIVE** banner
   - “Moved to …” link
2. Run a repo-wide search and update internal links:
   - `rg "docs/AGENT_ECONOMY_MVP_SPEC.md"` etc.
3. Only in a later cleanup PR, remove stubs once links stabilize.

### PR sequence (small, safe PRs)

#### PR 1 — Add status convention + templates (no moves yet)
- Add:
  - `docs/_templates/STATUS_BLOCK.md`
  - `docs/_templates/DOC_RULES.md`
- Update status blocks + banners in-place for:
  - `docs/README.md`
  - `docs/roadmaps/README.md`
  - `docs/PRD_INDEX.md`
  - `docs/oracle/README.md`
  - `docs/openclaw/README.md`
  - `docs/ecosystem/README.md`
- (Optional) Add a new short `docs/WHAT_TO_READ.md` that contains the four audience maps, linked from `docs/README.md`.

Files to touch (existing): `docs/README.md`, `docs/roadmaps/README.md`, `docs/PRD_INDEX.md`, `docs/oracle/README.md`, `docs/openclaw/README.md`, `docs/ecosystem/README.md`.

#### PR 2 — Introduce new IA folders + move “foundations”
**Moves/renames mapping:**
- `docs/ARCHITECTURE.md` → `docs/foundations/ARCHITECTURE.md`
- `docs/INTERCONNECTION.md` → `docs/foundations/INTERCONNECTION.md`
- `docs/GIT_STRATEGY.md` → `docs/foundations/GIT_STRATEGY.md`
- `docs/PARALLEL_EXECUTION.md` → `docs/foundations/PARALLEL_EXECUTION.md`

Add stubs at old paths (same filenames) pointing to new locations.

Add index:
- `docs/foundations/README.md`

Update links in:
- `docs/README.md`
- `docs/ecosystem/AGENTS.md` (it links to many of these; see `docs/ecosystem/AGENTS.md`)

#### PR 3 — Move cross-domain spec(s) into `specs/`
**Moves:**
- `docs/AGENT_ECONOMY_MVP_SPEC.md` → `docs/specs/agent-economy/MVP.md`

Add:
- `docs/specs/README.md`

Stub old file path.

Update links in:
- `docs/README.md` (currently links to `docs/AGENT_ECONOMY_MVP_SPEC.md`)
- `docs/ecosystem/AGENTS.md` (references the spec)

Files cited: `docs/AGENT_ECONOMY_MVP_SPEC.md`, `docs/README.md`, `docs/ecosystem/AGENTS.md`.

#### PR 4 — Move integration plan into `integration/`
**Moves:**
- `docs/OPENCLAW_INTEGRATION.md` → `docs/integration/OPENCLAW_INTEGRATION.md`

Add:
- `docs/integration/README.md`

Stub old file path.

Update links in:
- `docs/README.md`
- PRDs that reference it (e.g., `docs/prds/clawproxy.md`, `docs/prds/clawverify.md`, `docs/prds/clawclaim.md`, etc. all say “See: `docs/OPENCLAW_INTEGRATION.md`”).

Files cited: `docs/OPENCLAW_INTEGRATION.md`, `docs/prds/clawproxy.md`, `docs/prds/clawverify.md`, `docs/prds/clawclaim.md`.

#### PR 5 — Create `plans/` and move root planning docs out of the canonical surface
**Moves:**
- `docs/JOINCLAW_PLAN.md` → `docs/plans/joinclaw/PLAN.md`
- `docs/CLAWPROVIDERS_SEO_PLAN.md` → `docs/plans/clawproviders/SEO_PLAN.md`

Add:
- `docs/plans/README.md` (explicitly non-canonical)

Reconcile conflicts:
- Update `docs/prds/clawproviders.md` to add a **superseded_by** link to `docs/plans/clawproviders/SEO_PLAN.md` (or incorporate the SEO plan as an appendix and mark the plan as superseded—your choice, but pick one).

Files cited: `docs/JOINCLAW_PLAN.md`, `docs/CLAWPROVIDERS_SEO_PLAN.md`, `docs/prds/clawproviders.md`.

#### PR 6 — Archive high-confusion ecosystem research notes (optional, but recommended)
**Moves (optional):**
- `docs/ecosystem/chat-ideas.md` → `docs/archive/ecosystem/chat-ideas.md`
- `docs/ecosystem/cloudflare-moltworker.md` → `docs/archive/ecosystem/cloudflare-moltworker.md`
- `docs/ecosystem/ORACLE-ECOSYSTEM-MAP.md` → `docs/archive/ecosystem/ORACLE-ECOSYSTEM-MAP.md`

Update `docs/ecosystem/README.md` to link to the archived locations.

Files cited: `docs/ecosystem/chat-ideas.md`, `docs/ecosystem/cloudflare-moltworker.md`, `docs/ecosystem/ORACLE-ECOSYSTEM-MAP.md`, `docs/ecosystem/README.md`.

---

## Explicit unknowns / assumptions
- I only audited what appears in `docs/roadmaps/docs-ia/oracle/2026-02-07/DOCS_INVENTORY.md`. If there are additional docs not in that inventory (or generated docs outside `docs/`), they may need separate handling.
- I did **not** assess “current truth vs stale” by code comparison (no code files provided). The status convention is designed to make that safe anyway: anything not explicitly CANONICAL becomes “intent” unless tied to roadmaps/code.
- Some docs (notably `docs/ecosystem/AGENTS.md`) contain operational claims (deployments/PR numbers). Those should carry **HIGH staleness risk** and ideally be reviewed on a schedule.

If you want, I can output a **single move-map file** (JSON/YAML) suitable for scripting the renames + generating stub redirect pages.
