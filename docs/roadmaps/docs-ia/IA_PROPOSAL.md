> **Type:** Spec
> **Status:** CANONICAL
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-12
> **Source of truth:** This document

# Documentation Information Architecture — Proposal

## Overview

222 markdown files in `docs/`. This proposal classifies them, defines canonical reading paths, and codifies archiving rules.

## Folder structure (implemented)

```
docs/
├── README.md                  # Hub: what's here, what to read
├── WHAT_TO_READ.md            # Audience-specific reading paths
├── PRD_INDEX.md               # Index of all PRDs
├── _templates/                # Doc templates (STATUS_BLOCK, DOC_RULES)
├── foundations/               # Canonical operational docs
│   ├── ARCHITECTURE.md
│   ├── INTERCONNECTION.md
│   ├── GIT_STRATEGY.md
│   ├── DEPLOYMENT_RUNBOOK.md
│   ├── CLAW_VERIFIED_PR_PIPELINE.md
│   ├── PARALLEL_EXECUTION.md
│   └── decisions/             # ADRs
├── specs/                     # Protocol & domain specs
│   ├── clawsig-protocol/      # Clawsig Protocol v0.1
│   ├── agent-economy/         # Economy specs
│   ├── payments/              # Settlement specs
│   ├── clawlogs/              # Transparency log spec
│   ├── clawea/                # Enterprise integration
│   └── tee/                   # TEE attestation
├── prds/                      # All domain PRDs (36 files)
├── roadmaps/                  # Active roadmaps
│   ├── clawsig-protocol/      # 12/12 ✅
│   ├── proof-of-harness/      # 20/20 ✅
│   ├── trust-vnext/           # 59/59 ✅
│   └── docs-ia/               # This roadmap
├── integration/               # OpenClaw integration docs
├── ecosystem/                 # Strategic planning, ecosystem maps
├── openclaw/                  # OpenClaw platform docs (50+ files)
├── plans/                     # Pre-implementation plans
├── archive/                   # Retired/superseded content
└── [redirect stubs]           # 6 root-level redirects to foundations/
```

## Classification

### Canonical (source of truth, always current)

| Doc | Category | Why canonical |
|-----|----------|---------------|
| `docs/README.md` | Index | Entry point |
| `docs/WHAT_TO_READ.md` | Index | Reading paths by audience |
| `docs/PRD_INDEX.md` | Index | PRD master list |
| `docs/foundations/ARCHITECTURE.md` | Foundation | Service graph |
| `docs/foundations/INTERCONNECTION.md` | Foundation | Service deps |
| `docs/foundations/GIT_STRATEGY.md` | Foundation | Branch/PR conventions |
| `docs/foundations/DEPLOYMENT_RUNBOOK.md` | Foundation | Deploy procedures |
| `docs/foundations/CLAW_VERIFIED_PR_PIPELINE.md` | Foundation | CI verification |
| `docs/specs/clawsig-protocol/CLAWSIG_PROTOCOL_v0.1.md` | Spec | Protocol spec |
| `docs/specs/clawsig-protocol/REASON_CODE_REGISTRY.md` | Spec | Error codes |
| `docs/specs/clawsig-protocol/ADOPTION_GUIDE.md` | Spec | Third-party adoption |
| `docs/specs/agent-economy/MVP.md` | Spec | Economy spec |
| All `docs/prds/*.md` | PRD | Domain definitions |
| All `docs/roadmaps/**/prd.json` | Tracker | Story pass/fail |

### Active (maintained, may lag implementation)

- `docs/ecosystem/*.md` — Strategic planning docs
- `docs/openclaw/*.md` — OpenClaw platform docs
- `docs/integration/*.md` — Integration guides
- `docs/roadmaps/**/README.md` — Roadmap overviews

### Draft (work in progress)

- `docs/plans/*.md` — Pre-implementation plans
- `docs/roadmaps/**/oracle/*.md` — Oracle audit outputs

### Archive (historical, not maintained)

- `docs/archive/*` — Superseded content
- Root-level redirect stubs (`docs/ARCHITECTURE.md`, etc.)

## Archiving rules

1. **Never delete** — move to `docs/archive/`
2. **Add redirect stub** at old path pointing to canonical location
3. **Update indexes** — remove from WHAT_TO_READ, PRD_INDEX, README
4. **Preserve git history** — use `git mv` for moves

## Status block convention

All canonical and active docs must include the status block from `docs/_templates/STATUS_BLOCK.md`:

```markdown
> **Type:** (Spec | Guide | Index | Roadmap | PRD | Plan | Reference)
> **Status:** (CANONICAL | ACTIVE | DRAFT | REFERENCE | ARCHIVE)
> **Owner:** (team or handle)
> **Last reviewed:** YYYY-MM-DD
> **Source of truth:** (code paths / schemas / roadmap stories)
```

Applied to the top 20 most-referenced docs (see DOCS-US-003 below).
