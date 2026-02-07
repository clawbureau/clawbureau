## 1) Alignment scorecard (PRD ↔ trackers/roadmaps ↔ schemas)

Source inputs used:
- PRD index: `docs/PRD_INDEX.md`
- PRD↔tracker matrix (generated): `docs/roadmaps/docs-ia/oracle/2026-02-07/PRD_EXECUTION_MATRIX.md`
- Canonical roadmap rules: `docs/README.md`, `docs/roadmaps/README.md`, `docs/_templates/DOC_RULES.md`
- Schemas: `packages/schema/README.md` + referenced schema files under `packages/schema/**`
- Service trackers (where present): `services/*/prd.json` + `services/*/progress.txt`
- PoH roadmaps/spec: `docs/roadmaps/proof-of-harness/*`, `docs/roadmaps/trust-vnext/*`

### Scorecard table (one row per PRD/domain)

Legend:
- **Has execution tracker?** = service-level tracker (`services/<svc>/{prd.json,progress.txt}`) or roadmap tracker (`docs/roadmaps/<topic>/{prd.json,progress.txt}`)
- **References schemas?** = explicit schema `$id` or concrete schema filenames mentioned in the PRD text
- **Drift severity** considers: missing tracker link, outdated terminology vs schemas/services, and whether PRD could mislead implementation

| PRD file | Has execution tracker? (where) | References schemas? (which) | Drift severity | What is stale / mismatched | Recommended action |
|---|---|---|---|---|---|
| `docs/prds/clawadvisory.md` | **No** (matrix shows none) | None explicit | **MED** | No tracker; “Status: Draft” but no required status block; no schema anchors | Add status banner + add “Implementation status” section (explicit “not started”) |
| `docs/prds/clawbounties.md` | **Yes**: `services/clawbounties/prd.json` + `services/clawbounties/progress.txt` | Mentions proof tiers + commit proof conceptually, but no schema IDs; partially conflicts with v2 schema terms | **HIGH** | PRD says canonical `min_proof_tier`, but service tracker notes implement `min_poh_tier` gating (see `services/clawbounties/prd.json` CBT-US-013) while schema v2 has both (`packages/schema/bounties/*.v2.json`); money fields in PRD are non-specific vs v2 “USD minor unit strings” (`packages/schema/README.md`) | **Update** + add tracker link; add explicit schema references (bounties v2 + PoH proof bundle/commit proof) |
| `docs/prds/clawbureau.md` | **No** (matrix: `services/clawbureau` but no tracker files) | None explicit | **MED** | No execution tracker; PRD could be confused with docs hub reality in `docs/README.md` | Add status banner + link to any roadmap or create service tracker stub (without breaking pattern) |
| `docs/prds/clawcareers.md` | **No** | None | **LOW/MED** | Aspirational; no tracker | Add status banner (“Aspirational”) |
| `docs/prds/clawclaim.md` | **Yes**: `services/clawclaim/prd.json` + `services/clawclaim/progress.txt` | None explicit (should reference identity/message schemas if/when added) | **MED** | PRD includes platform claims/owner attestations/CST bootstrap as MVP, but service tracker shows only CCL-US-001..003 done; PRD lacks link to tracker and lacks “implemented vs planned” callout | Update (add Implementation Status + link to tracker; mark what’s shipped: challenges/bind/revoke only) |
| `docs/prds/clawcontrols.md` | **No** | None | **MED** | Heavily referenced by other systems (WPC/token policy) but no tracker; terminology overlaps with Trust vNext (WPC registry story `docs/roadmaps/trust-vnext/prd.json` CCO-US-021) | Add status banner + link to `docs/roadmaps/trust-vnext/README.md` (planned work) |
| `docs/prds/clawcuts.md` | **Yes**: `services/clawcuts/prd.json` + `services/clawcuts/progress.txt` | None explicit (should reference bounties/escrow v2 money conventions) | **MED** | PRD scope says fee policy definitions/apply fees/reporting; service tracker shows simulation endpoints implemented (CCU-US-005/007) but PRD doesn’t say what exists | Update (implementation status + link to tracker; add schema/money convention references) |
| `docs/prds/clawdelegate.md` | **No** | None | **LOW/MED** | Aspirational; no tracker | Add status banner (“Aspirational”) |
| `docs/prds/clawea.md` | **No** | None explicit (should reference `packages/schema/poh/execution_attestation.v1.json`) | **MED** | Closely tied to Trust vNext story `CEA-US-010` in `docs/roadmaps/trust-vnext/prd.json`; PRD doesn’t link that roadmap or the attestation schema | Update (link to trust-vnext + reference `packages/schema/poh/execution_attestation.v1.json`) |
| `docs/prds/clawescrow.md` | **Yes**: `services/escrow/prd.json` + `services/escrow/progress.txt` | None explicit (should reference `packages/schema/escrow/escrow.v{1,2}.json`) | **MED** | PRD reads like unimplemented draft; service tracker shows API v1 + public docs shipped (CES-US-008 etc). Also money conventions drift vs v2 USD-minor schemas | Update + add tracker link + reference escrow v2 schema + note what’s shipped |
| `docs/prds/clawforhire.md` | **No** | None | **LOW/MED** | Aspirational; no tracker | Add status banner |
| `docs/prds/clawgang.md` | **No** | None | **LOW** | Aspirational | Add status banner |
| `docs/prds/clawgrant.md` | **No** | None | **LOW/MED** | Aspirational; depends on `clawadvisory` which is also untracked | Add status banner (and consider linking to future roadmap if created) |
| `docs/prds/clawincome.md` | **No** | None | **LOW** | Aspirational | Add status banner |
| `docs/prds/clawinsure.md` | **No** | None | **LOW** | Aspirational | Add status banner |
| `docs/prds/clawintel.md` | **No** | None | **LOW/MED** | Aspirational; terminology overlaps owner attestation signals but no linkage to identity schemas | Add status banner |
| `docs/prds/clawledger.md` | **Yes**: `services/ledger/prd.json` + `services/ledger/progress.txt` | None explicit (should reference ledger/bucket contracts + money conventions; schemas not shown for ledger in provided set) | **MED** | PRD “implementation notes” conflict with shipped details (haircuts differ: PRD suggests Gemini 50%/FAL 70%, service progress uses gemini=7000bps, fal=6000bps in `services/ledger/prd.json` CLD-US-011 notes); PRD lacks “shipped vs planned” | Update (align notes to shipped behavior; add tracker link) |
| `docs/prds/clawlogs.md` | **No** | None | **MED** | Referenced as dependency across many domains; but no service/tracker; may mislead readers into assuming it exists | Add status banner (“Not implemented”) + consider move to archive **only if** not planned soon |
| `docs/prds/clawmanage.md` | **No** | None | **LOW/MED** | Aspirational | Add status banner |
| `docs/prds/clawmerch.md` | **No** | None | **LOW** | Aspirational | Add status banner |
| `docs/prds/clawportfolio.md` | **No** | None | **MED** | Mentions PoH/commit proofs/owner verification features that *do* exist in other services, but portfolio itself has no tracker; should link `clawverify` + PoH schemas | Add status banner + link to `services/clawverify/*` and PoH schema docs as dependencies |
| `docs/prds/clawproviders.md` | **No** | None | **LOW/MED** | Aspirational | Add status banner |
| `docs/prds/clawproxy.md` | **Yes**: `services/clawproxy/prd.json` + `services/clawproxy/progress.txt` | Mentions `packages/schema/auth/scoped_token_claims.v1.json` conceptually (token format), but doesn’t cite `$id` | **MED/HIGH** | PRD “Implementation notes” around CST header naming conflict with shipped hardening: service story CPX-US-015 explicitly supports `Authorization: Bearer <JWT>` + provider keys via `X-Provider-API-Key` (`services/clawproxy/prd.json`, `services/clawproxy/progress.txt`) | Update PRD to reflect current header semantics + add tracker + cite schema `$id` |
| `docs/prds/clawrep.md` | **No** | None | **MED** | Depends on proof tier weighting and owner verification, but has no tracker; terminology must align with canonical tiers (see `docs/roadmaps/trust-vnext/prd.json` POH-US-013) | Add status banner + link to `docs/roadmaps/trust-vnext/prd.json` POH-US-013 |
| `docs/prds/clawscope.md` | **Yes**: `services/clawscope/prd.json` + `services/clawscope/progress.txt` | Mentions scoped token claims; should cite `packages/schema/auth/scoped_token_claims.v1.json` (and `$id`) | **MED** | PRD says observability is MVP, but service tracker focuses on issuance/introspection/revocation/JWKS; PRD lacks “implemented vs planned” and no tracker link | Update + add tracker link + explicit schema reference (`$id` in `packages/schema/auth/scoped_token_claims.v1.json`) |
| `docs/prds/clawsettle.md` | **No** | None | **LOW/MED** | Aspirational; no tracker | Add status banner |
| `docs/prds/clawsig.md` | **No** | None | **MED** | PRD asserts RFC 8785 canonicalization requirement, but repo policy is only “preferred” in PoH spec (`docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md`); no tracker exists | Add status banner + link to PoH/trust-vnext decisions (canonicalization story) |
| `docs/prds/clawsilo.md` | **No** | None | **LOW/MED** | Aspirational; depends on proof bundles; no tracker | Add status banner |
| `docs/prds/clawsupply.md` | **No** | None | **LOW/MED** | Aspirational; no tracker | Add status banner |
| `docs/prds/clawtrials.md` | **No** | None | **LOW/MED** | Aspirational; no tracker | Add status banner |
| `docs/prds/clawverify.md` | **Yes**: `services/clawverify/prd.json` + `services/clawverify/progress.txt`; also tightly coupled to PoH roadmaps `docs/roadmaps/proof-of-harness/*` | Explicitly cites: `packages/schema/identity/owner_attestation.v1.json`, `packages/schema/poh/commit_proof.v1.json`, `packages/schema/auth/scoped_token_claims.v1.json` | **HIGH** | Major semantics drift: service implements **trust_tier** ladder `unknown/basic/verified/attested/full` (`services/clawverify/prd.json` CVF-US-007 notes) while PRD (and schemas/marketplace) talk in **PoH tiers** `self/gateway/sandbox`; PRD doesn’t clearly state mapping; also PRD includes future “OpenClaw tool plugin” but no tracker/story in service PRD | Update (add a canonical “PoH tier output + mapping” section; add links to PoH roadmap and trust-vnext hardening stories) |
| `docs/prds/joinclaw.md` | **No** (matrix: `services/joinclaw` exists but no tracker files) | None | **MED** | Could be mistaken for current onboarding; no tracker | Add status banner + create tracker stub or link to docs roadmap if it’s just docs work |

**Are PRDs being kept up to date?**
- For **implemented services**, the *service trackers* are up to date (they show shipped work), but the **domain PRDs under `docs/prds/` are not being maintained** as “safe summaries”: they generally lack (a) required status blocks per `docs/_templates/DOC_RULES.md`, (b) a link to the execution tracker, and (c) schema-version anchors.
- For **non-implemented domains**, PRDs are inherently aspirational and need explicit labeling to avoid being mistaken for current truth.

---

## 2) Systemic drift patterns

1) **Tier terminology split-brain**
   - Marketplace/PRDs/schemas talk **proof tiers**: `self | gateway | sandbox` (e.g. `packages/schema/bounties/bounty.v2.json`, `docs/prds/clawbounties.md`).
   - `clawverify` implementation talks **trust tiers**: `unknown < basic < verified < attested < full` (`services/clawverify/prd.json` CVF-US-007).
   - Trust vNext explicitly calls out the need to align semantics (story `POH-US-013` in `docs/roadmaps/trust-vnext/prd.json`).

2) **`min_poh_tier` (legacy int) vs `min_proof_tier` (enum)**
   - Schema v2 introduces `min_proof_tier` and deprecates `min_poh_tier` (`packages/schema/bounties/*.v2.json`; `packages/schema/prd.json` AEM-US-001).
   - Service tracker for clawbounties still documents integer gating flows (`services/clawbounties/prd.json` CBT-US-013 notes).
   - PRD `docs/prds/clawbounties.md` asserts `min_proof_tier` is canonical—this is *directionally correct*, but needs to reflect current shipped API behavior and any compatibility behavior.

3) **Money schema v1→v2 conversion drift**
   - Repo-level schema policy: v2 uses **USD-only** and **integer strings in minor units** (`packages/schema/README.md`).
   - Many PRDs still describe money as generic “reward” without specifying minor-unit strings or USD-only, which is now implementation-driving for marketplace/escrow flows.

4) **PoH receipt format drift in the PoH spec**
   - `docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md` contains a “Current gap” describing a receipt format mismatch between clawproxy and clawverify (section 5.3).
   - That gap was resolved by POH-US-009 (“canonical `_receipt_envelope` … fail-closed allowlisting”) in `docs/roadmaps/proof-of-harness/prd.json` and logged in `docs/roadmaps/proof-of-harness/progress.txt`.
   - This is a concrete doc-vs-implementation drift inside a spec that readers will treat as current.

5) **Auth header semantics changed after PRDs were written**
   - `clawproxy` now supports CST in `Authorization: Bearer <JWT>` and provider keys in `X-Provider-API-Key` (`services/clawproxy/prd.json` CPX-US-015; `services/clawproxy/progress.txt`).
   - `docs/prds/clawproxy.md` still presents the older “pick one header name” guidance and doesn’t clearly match the shipped semantics.

6) **Status block convention not applied to PRDs**
   - `docs/_templates/DOC_RULES.md` says “Anything that can be mistaken for current truth must start with a status block.”
   - PRDs use a lightweight inline “Status: Draft” but not the standardized block used elsewhere (see `docs/README.md` / roadmaps).

---

## 3) What “kept up to date” should mean (canonical truth model)

Grounding in repo policy (`docs/_templates/DOC_RULES.md` and `docs/README.md`):

### Canonical sources (what type of truth)
1) **Reality (binding, “true today”)**
   - **Code + schemas** are canonical current truth (`docs/_templates/DOC_RULES.md`).
   - Concretely: `packages/schema/**` (and the service code that implements them).

2) **Execution (what is being done / what shipped)**
   - **Roadmaps + per-service trackers** are canonical execution truth:
     - `docs/roadmaps/*/{prd.json,progress.txt}` (repo-level initiatives)
     - `services/*/{prd.json,progress.txt}` (service delivery)
   - These should be the authoritative “status and history.”

3) **Intent (what we want)**
   - **Domain PRDs** (`docs/prds/*.md`) are canonical intent, **but must not pretend to be current behavior**.

### Definition: “Up to date” for a PRD
A PRD is “kept up to date” if it satisfies all of the following:

1) **Has a status block + last reviewed date**
   - Using the repo’s status block convention (`docs/_templates/STATUS_BLOCK.md`, referenced by `docs/_templates/DOC_RULES.md`).

2) **Links to execution tracker**
   - If implemented or in-flight: link to the canonical tracker:
     - service: `services/<svc>/prd.json` + `services/<svc>/progress.txt`
     - roadmap: `docs/roadmaps/<topic>/README.md` (and/or `prd.json`)

3) **Separates “Shipped behavior” vs “Aspirational requirements”**
   - A short “Shipped today” section that never contradicts schemas/code.
   - A separate “Planned” section that references tracker story IDs.

4) **Schema anchoring for any API/data contract claim**
   - When PRD references a field like `min_proof_tier`, or receipt envelope formats, it must cite the schema `$id` (or at minimum the schema filename under `packages/schema/**`).

### What must be updated when schemas change
When a schema change is introduced (especially a new v2):
- Update **PRDs for affected domains** to:
  - reference the new schema IDs
  - note migration/compat behavior if v1 still exists
- Update **integration-facing docs** if they exist (service `/docs`, `/skill.md`, etc. are tracked in service progress logs; PRDs should just link)

### What must be updated when a roadmap story completes
When a story flips to “passes: true” in:
- `docs/roadmaps/*/prd.json` **or** `services/*/prd.json`

…then update the relevant PRD(s) by:
- adding a one-line “Shipped” bullet in “Implementation status”
- removing/rewriting any “current gap” claims that are no longer true (notably in `docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md`)

---

## 4) Pragmatic enforcement / maintenance mechanism (minimal friction)

### A. Add a lightweight “PRD lint” CI job
Create a script + CI workflow that enforces **only** the high-signal, low-ambiguity rules:

1) **Every `docs/prds/*.md` must include:**
   - a status block header (per `docs/_templates/STATUS_BLOCK.md`)
   - an “Implementation status” section containing **either**:
     - a link to `services/<svc>/prd.json` (and `progress.txt`) **or**
     - a link to a roadmap folder `docs/roadmaps/<topic>/README.md` **or**
     - explicit text: “No execution tracker yet” (for aspirational domains)

2) **Schema reference validation (grep-based)**
   - If a PRD contains `https://schemas.clawbureau.org/` strings, verify those `$id`s exist in `packages/schema/**` by scanning JSON files’ `$id`.
   - (Pragmatic: no need to validate semantic correctness—just existence.)

3) **Optional: “implemented service must link tracker”**
   - If `services/<name>/` exists and contains `prd.json`, then `docs/prds/<domain>.md` must link it.

Where to wire it:
- New workflow (example): `.github/workflows/prd-alignment.yml`
- New script (example): `scripts/docs/lint-prds.mjs`

### B. Add “review cadence” tagging
- Require `Last reviewed: YYYY-MM-DD` in PRD status blocks.
- CI can warn (not fail) if older than N days (e.g. 90/180). Keep it as a warning to avoid toil.

### C. Close the loop from trackers to PRDs (human process)
- When updating `services/*/progress.txt`, add a checkbox: “Updated PRD implementation status link/section”.
- This is a process change, not automation-heavy, and matches the repo’s “append-only progress log” discipline (`docs/roadmaps/README.md`).

---

## 5) Concrete next PR plan (small PRs, exact files, suggested order)

### PR 1 — Fix the most dangerous “spec is wrong today” drift (PoH receipt gap)
**Goal:** Remove/replace stale “current gap” text now resolved by POH-US-009.

Files:
- **Update:** `docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md`
  - Rewrite section **5.3 “Current gap (important)”** to reflect POH-US-009 completion from:
    - `docs/roadmaps/proof-of-harness/prd.json` (POH-US-009 passes true)
    - `docs/roadmaps/proof-of-harness/progress.txt` (2026-02-06/07 entries)
  - Ensure it states: clawproxy emits `_receipt_envelope` as `SignedEnvelope<GatewayReceiptPayload>`, signer DID allowlist required in clawverify.
- (Optional) Add a short “Version note / last aligned with POH-US-009 on 2026-02-07”.

### PR 2 — Add status blocks + tracker links for implemented services’ PRDs (highest ROI)
**Goal:** Make the PRDs safe entry points without rewriting everything.

Files (edit each PRD to add: status block + “Implementation status” with links):
- `docs/prds/clawbounties.md` → link `services/clawbounties/prd.json`, `services/clawbounties/progress.txt`; cite `packages/schema/bounties/*.v2.json`, `packages/schema/poh/proof_bundle.v1.json`, `packages/schema/poh/commit_proof.v1.json`
- `docs/prds/clawproxy.md` → link `services/clawproxy/prd.json`, `services/clawproxy/progress.txt`; cite `packages/schema/auth/scoped_token_claims.v1.json` (and ideally the `$id`)
- `docs/prds/clawverify.md` → link `services/clawverify/prd.json`, `services/clawverify/progress.txt`; link PoH roadmap `docs/roadmaps/proof-of-harness/README.md` and trust-vnext `docs/roadmaps/trust-vnext/README.md`
- `docs/prds/clawscope.md` → link `services/clawscope/prd.json`, `services/clawscope/progress.txt`; cite `packages/schema/auth/scoped_token_claims.v1.json`
- `docs/prds/clawcuts.md` → link `services/clawcuts/prd.json`, `services/clawcuts/progress.txt`
- `docs/prds/clawclaim.md` → link `services/clawclaim/prd.json`, `services/clawclaim/progress.txt`
- `docs/prds/clawledger.md` → link `services/ledger/prd.json`, `services/ledger/progress.txt`
- `docs/prds/clawescrow.md` → link `services/escrow/prd.json`, `services/escrow/progress.txt`; cite `packages/schema/escrow/escrow.v2.json`

### PR 3 — Terminology normalization patches (targeted edits, not a rewrite)
**Goal:** Reduce tier and header confusion.

Files:
- `docs/prds/clawverify.md`
  - Add a small canonical section: “Outputs: trust_tier vs poh_tier” and define mapping (source: `services/clawverify/prd.json` CVF-US-012 notes about poh_tier mapping).
- `docs/prds/clawbounties.md`
  - Explicitly state what is shipped today regarding `min_poh_tier` vs `min_proof_tier` (source: `services/clawbounties/prd.json` CBT-US-017 and CBT-US-013 notes + schemas in `packages/schema/bounties/*.v2.json`).
- `docs/prds/clawproxy.md`
  - Update CST/provider-key header guidance to match shipped CPX-US-015 in `services/clawproxy/prd.json`.

### PR 4 — Add status blocks for all remaining PRDs (bulk mechanical)
**Goal:** Make aspirational docs unmistakable.

Files:
- All remaining `docs/prds/*.md` not covered above:
  - Add status block with **Status: ASPIRATIONAL** (or similar), owner, last reviewed, and “No execution tracker yet”.
  - Add a one-line pointer to the relevant roadmap if it exists (often `docs/roadmaps/trust-vnext/README.md` for trust/policy-heavy domains like `clawcontrols`, `clawea`, `clawrep`).

(Do **not** archive yet unless you have a “not planned” decision; the safer immediate step is explicit labeling.)

### PR 5 — CI enforcement (minimal checks)
**Goal:** Prevent drift from re-accumulating.

Files:
- **Add:** `scripts/docs/lint-prds.mjs` (new)
- **Add:** `.github/workflows/prd-alignment.yml` (new)
- (Optional) Update contributing docs if they exist; at minimum add a note to `docs/_templates/DOC_RULES.md` that PRDs must link trackers and schemas.

---

### Bottom line

- **Alignment today:** strong at the **tracker + schema** layer for PoH/marketplace primitives, but **weak at the PRD layer**: PRDs are mostly unlinked, not status-blocked, and several contain terminology/behavior claims that no longer match shipped reality (notably PoH receipt gap text in `docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md`, and tier semantics mismatch around `clawverify` vs marketplace).
- **Fastest fix:** update the PoH spec gap, then mechanically add PRD status blocks + tracker links + schema anchors for the implemented services’ PRDs. After that, add CI to keep it from regressing.
