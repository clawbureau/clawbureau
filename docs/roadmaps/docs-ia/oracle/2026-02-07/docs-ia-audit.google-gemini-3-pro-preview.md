Here is the comprehensive Documentation cleanup plan.

## 1. Information Architecture (IA) Proposal

We will move from a flat root layout to a functional hierarchy.

### Folder Structure
```
docs/
├── README.md                  # Main entrypoint (Hub)
├── specs/                     # THE LAW: Canonical technical constraints & architecture
│   ├── ARCHITECTURE.md
│   ├── INTERCONNECTION.md
│   ├── AGENT_ECONOMY.md       # Was MVP_SPEC
│   ├── OPENCLAW_BRIDGE.md     # Was OPENCLAW_INTEGRATION
│   └── GIT_WORKFLOW.md        # Was GIT_STRATEGY / PARALLEL_EXECUTION
├── guides/                    # HOW-TO: Contributor & Workspace guides
│   ├── WORKSPACE.md           # Was ecosystem/AGENTS.md
│   └── ...
├── plans/                     # STRATEGY: One-off implementation plans (SEO, Marketing)
│   ├── CLAWPROVIDERS_SEO.md
│   └── JOINCLAW_STRATEGY.md
├── ecosystem/                 # CONTEXT: High-level maps & strategy
│   ├── README.md
│   ├── STRATEGIC_PLAN.md
│   └── ECOSYSTEM-MAP.md
├── prds/                      # DEFINITIONS: Domain-specific requirements
│   ├── README.md              # Was PRD_INDEX.md
│   └── ... (domain md files)
├── roadmaps/                  # EXECUTION: Active tracking (Ralph-compatible)
│   ├── proof-of-harness/
│   ├── trust-vnext/
│   └── docs-ia/
├── openclaw/                  # MIRROR: Reference docs (Do not edit logic here)
├── oracle/                    # RESEARCH: Raw LLM outputs & brainstorms
└── archive/                   # GRAVEYARD: Superseded docs
```

### Indexing Rules
1.  **Searchable**: `specs/`, `prds/`, `roadmaps/` should be indexed by default.
2.  **Ignored**: `openclaw/` (unless specifically looking for upstream constraints), `oracle/` (noise), `archive/`.

---

## 2. Docs Status Convention

To prevent confusion between "what is" and "what might be," every major document in `specs/`, `roadmaps/`, and `plans/` MUST generally start with a standard blockquote status header.

### Status Banner Format is Markdown Blockquote
This renders distinctly in GitHub/Markdown readers without breaking formatting.

```markdown
> **TYPE**: [Spec | Plan | Guide | PRD | Roadmap]
> **STATUS**: [Canonical | Active | Draft | Deprecated | Archived]
> **OWNER**: [@clawbureau/core | @clawbureau/labor | etc.]
> **LAST VERIFIED**: YYYY-MM-DD
```

### Definitions
- **Canonical**: The source of truth. Code must align with this.
- **Active**: Currently being worked on or valid, but subject to change.
- **Draft**: Proposal stage, do not implement yet.
- **Deprecated**: Still exists but avoid new dependencies.
- **Archived**: Historical context only.

### Requirement
**Must** be present on:
- All files in `docs/specs/`
- Root `README.md` files in `docs/roadmaps/*/`
- All files in `docs/plans/`

---

## 3. Canonical Reading Map

Add this to `docs/README.md`.

### 👩‍💻 New Contributor (5–10 min)
1.  **Start**: `docs/guides/WORKSPACE.md` (Setup, sibling repos, mental model)
2.  **Rules**: `docs/specs/GIT_WORKFLOW.md` (Branch naming, proof rules)
3.  **Map**: `docs/ecosystem/ECOSYSTEM-MAP.md` (What services exist)

### 💰 Marketplace Engineer (Bounties/Ledger)
1.  **Logic**: `docs/specs/AGENT_ECONOMY.md` (The money math & flows)
2.  **Product**: `docs/prds/clawbounties.md` & `docs/prds/clawledger.md`
3.  **Wiring**: `docs/specs/INTERCONNECTION.md` (Events, shared schema rules)

### 🛡️ Trust/PoH Engineer (Proxy/Verify)
1.  **Core**: `docs/roadmaps/proof-of-harness/README.md` (Current execution context)
2.  **Spec**: `docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md` (The PoH protocol)
3.  **Components**: `docs/prds/clawverify.md` & `docs/prds/clawproxy.md`

### 🤖 OpenClaw Integration Engineer
1.  **Bridge**: `docs/specs/OPENCLAW_BRIDGE.md` (How we fit into OpenClaw)
2.  **Reference**: `docs/openclaw/10-extensions-and-plugins.md` (Upstream constraints)

---

## 4. Audit & Classification

| Current File | New Location | Status | Action |
| :--- | :--- | :--- | :--- |
| `docs/AGENT_ECONOMY_MVP_SPEC.md` | `docs/specs/AGENT_ECONOMY.md` | **Canonical** | **Move & Rename** |
| `docs/ARCHITECTURE.md` | `docs/specs/ARCHITECTURE.md` | **Canonical** | **Move** |
| `docs/INTERCONNECTION.md` | `docs/specs/INTERCONNECTION.md` | **Canonical** | **Move** |
| `docs/GIT_STRATEGY.md` | `docs/specs/GIT_WORKFLOW.md` | **Canonical** | **Move & Rename** (Merge `PARALLEL_EXECUTION` context here) |
| `docs/PARALLEL_EXECUTION.md` | `docs/archive/PARALLEL_EXECUTION.md` | **Archived** | **Archive** (Merge key points into GIT_WORKFLOW first) |
| `docs/OPENCLAW_INTEGRATION.md` | `docs/specs/OPENCLAW_BRIDGE.md` | **Canonical** | **Move & Rename** |
| `docs/PRD_INDEX.md` | `docs/prds/README.md` | **Active** | **Move & Rename** |
| `docs/CLAWPROVIDERS_SEO_PLAN.md` | `docs/plans/CLAWPROVIDERS_SEO.md` | **Draft** | **Move** |
| `docs/JOINCLAW_PLAN.md` | `docs/plans/JOINCLAW_STRATEGY.md` | **Draft** | **Move** |
| `docs/ecosystem/AGENTS.md` | `docs/guides/WORKSPACE.md` | **Active** | **Move & Rename** |
| `docs/ecosystem/chat-ideas.md` | `docs/oracle/archive/chat-ideas.md` | **Archived** | **Move** (Context is now in roadmaps) |
| `docs/ecosystem/cloudflare-moltworker.md` | `docs/oracle/archive/moltworker-ref.md` | **Reference** | **Move** |
| `docs/roadmaps/README.md` | `docs/roadmaps/README.md` | **Active** | **Keep** (Update links) |

---

## 5. PR Implementation Plan

We will execute this in a specific sequence to maintain `ralph` compatibility.

### Step 1: Directory Scaffolding & Safe Moves
*Rationale: Create structure without breaking links immediately.*
1.  Create `docs/specs/`, `docs/guides/`, `docs/plans/`, `docs/archive/`.
2.  Move file-by-file (using `git mv` to preserve history).

### Step 2: Content Updates & Linking
*Rationale: Fix the broken references.*
1.  **Update Root README**: Rewrite `docs/README.md` with new Reading Map and IA explanation.
2.  **Update PRD Index**: Rename `PRD_INDEX.md` to `docs/prds/README.md` and check names.
3.  **Global Find & Replace**:
    - Search for `docs/ecosystem/AGENTS.md` -> Replace with `docs/guides/WORKSPACE.md`.
    - Search for `AGENT_ECONOMY_MVP_SPEC.md` -> Replace with `docs/specs/AGENT_ECONOMY.md`.
    - Search for `OPENCLAW_INTEGRATION.md` -> `docs/specs/OPENCLAW_BRIDGE.md`.

### Step 3: Status Banners
*Rationale: Apply the new convention.*
1.  Iterate through `docs/specs/*` and prepend the Status Banner.
2.  Iterate through `docs/plans/*` and prepend Draft/Plan banners.

### Mapping List for Scripting
```bash
mkdir -p docs/specs docs/guides docs/plans docs/archive
git mv docs/AGENT_ECONOMY_MVP_SPEC.md docs/specs/AGENT_ECONOMY.md
git mv docs/ARCHITECTURE.md docs/specs/ARCHITECTURE.md
git mv docs/INTERCONNECTION.md docs/specs/INTERCONNECTION.md
git mv docs/GIT_STRATEGY.md docs/specs/GIT_WORKFLOW.md
git mv docs/OPENCLAW_INTEGRATION.md docs/specs/OPENCLAW_BRIDGE.md
git mv docs/PARALLEL_EXECUTION.md docs/archive/PARALLEL_EXECUTION.md
git mv docs/CLAWPROVIDERS_SEO_PLAN.md docs/plans/CLAWPROVIDERS_SEO.md
git mv docs/JOINCLAW_PLAN.md docs/plans/JOINCLAW_STRATEGY.md
git mv docs/ecosystem/AGENTS.md docs/guides/WORKSPACE.md
git mv docs/ecosystem/chat-ideas.md docs/oracle/chat-ideas-archive.md
git mv docs/ecosystem/cloudflare-moltworker.md docs/oracle/moltworker-ref.md
git mv docs/PRD_INDEX.md docs/prds/README.md
```
