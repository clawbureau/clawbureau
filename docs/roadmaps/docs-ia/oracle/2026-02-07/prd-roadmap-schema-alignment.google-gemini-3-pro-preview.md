# Oracle Audit: PRD ↔ Roadmap ↔ Schema Alignment

This audit compares the high-level intent (`docs/prds/`), the execution reality (`services/*/prd.json`), and the data contracts (`packages/schema/`).

## 1. Alignment Scorecard

**Legend:**
*   🟢 **Aligned:** Code execution matches PRD intent.
*   🟡 **Drift (Low/Med):** Version mismatch (e.g., v1 vs v2) or feature lag.
*   🔴 **Stale/Future:** Document exists, but no implementation exists (Aspirational).

| Domain | Tracker (Execution) | Schema Ref | Drift | Status / Recommended Action |
| :--- | :--- | :--- | :--- | :--- |
| **clawbounties** | `services/clawbounties/prd.json` (Active) | `bounties/*.v2.json` | 🟢 LOW | **Active.** PRD accurately reflects implemented stories (CBT-US-001..021). **Action:** Update PRD to explicitly reference schema v2 (USD minor units). |
| **clawverify** | `services/clawverify/prd.json` (Active) | `poh/*.v1.json`, `identity/*.v1.json` | 🟢 LOW | **Active.** PRD matches implementation (US-001..014). **Action:** Keep. Add header link to `services/clawverify`. |
| **clawproxy** | `services/clawproxy/prd.json` (Active) | `poh/receipt_binding.v1.json` | 🟢 LOW | **Active.** PRD matches code (Ed25519 signing, CST auth). **Action:** Keep. |
| **clawledger** | `services/ledger/prd.json` (Active) | N/A (Internal D1) | 🟡 MED | **Active.** Service dir is `ledger`, PRD is `clawledger`. PRD mentions "Reserve Asset Registry" (CLD-US-010) which is implemented. **Action:** Rename service dir to `clawledger` eventually, or alias in index. |
| **clawescrow** | `services/escrow/prd.json` (Active) | `escrow/*.v2.json` | 🟡 MED | **Active.** Service dir is `escrow`. Implements v2 schemas and milestones. **Action:** explicit link to v2 schemas in PRD. |
| **clawclaim** | `services/clawclaim/prd.json` (Active) | `identity` (implied) | 🟡 MED | **Partial.** Core binding (US-001/002/003) done. Platform claims (US-004) & Tokens (US-008) are `passes: false`. **Action:** Add "Implementation Status" banner listing pending stories. |
| **clawcuts** | `services/clawcuts/prd.json` (Active) | N/A (Internal Policy) | 🟢 LOW | **Active.** Fee simulation (US-005) matches code. **Action:** Keep. |
| **clawscope** | `services/clawscope/prd.json` (Active) | `auth/scoped_token*.v1.json` | 🟢 LOW | **Active.** CST issuance/introspection matches schema. **Action:** Keep. |
| **clawreputation** | *None* | *None* | 🔴 HIGH | **Aspirational.** PRD exists, no service. Referenced by `clawbounties` (US-009). **Action:** Mark as "Planned". |
| **clawtrials** | *None* | *None* | 🔴 HIGH | **Aspirational.** Logic lives inside `clawescrow` service (dispute window) for now. **Action:** Mark as "Future Service" (currently internal to Escrow). |
| **clawsilo** | *None* | *None* | 🔴 HIGH | **Hybrid.** PRD exists. Logic partially implied by `clawverify` audit logs. **Action:** Mark as "Future". |
| **trust-vnext** | `docs/roadmaps/trust-vnext/` | `poh/*.v1.json` | 🟡 MED | **In Progress.** Roadmap defines the next steps for `clawverify`/`clawproxy`. **Action:** Ensure PRDs link to this roadmap for future features. |
| **Other .coms** | *None* | *None* | 🔴 FUTURE | (clawadvisory, clawcareers, etc.) Pure intent. **Action:** Add "Concept / Draft" banner. |

## 2. Systemic Drift Patterns

1.  **Schema Versioning Gap (The "v2" Drift):**
    *   **Drift:** `clawbounties` and `clawescrow` implemented **v2 schemas** (USD minor units, `min_proof_tier` enum) to solve floating-point and compatibility issues. The textual PRDs (`docs/prds/*.md`) generally describe the *features* but often imply v1 or generic implementations.
    *   **Risk:** Integrators reading the PRD might assume floating-point or legacy fields.
    *   **Fix:** PRDs must link to the *schema definition* as the single source of truth for data shapes.

2.  **Service Naming Mismatch:**
    *   **Drift:** Domains use `claw[name]`. Service directories use `services/[name]` (e.g., `services/ledger` vs `clawledger.com`).
    *   **Risk:** CI scripts/tooling relying on folder naming conventions may break.
    *   **Fix:** Normalize service directory names to match domain names (`services/clawledger`) OR encode the mapping in `PRD_INDEX.md`.

3.  **"Done" vs "Planned" Ambiguity:**
    *   **Drift:** `clawclaim` PRD lists "Platform Claims" (GitHub/X binding) as a core feature. The execution tracker (`prd.json`) explicitly marks it `passes: false`.
    *   **Risk:** Stakeholders assume features exist because they are in the PRD User Stories list.
    *   **Fix:** PRDs must dynamically signal status or explicitly separate "MVP (Implemented)" from "Roadmap (Planned)".

## 3. Definition of "Up to Date" & Truth Model

To maintain sanity without perfect automation, we define the **Canonical Truth Hierarchy**:

1.  **Code & Schemas (`packages/schema/*`)**: The absolute truth of data shapes and API contracts.
    *   *Update trigger:* Hard requirement. Code change = Schema change.
2.  **Execution Trackers (`services/*/prd.json` + `progress.txt`)**: The authoritative record of "what is built."
    *   *Update trigger:* Automated by Ralph (`ralph.sh`) usage. If a test passes, this is truth.
3.  **Active Roadmaps (`docs/roadmaps/*`)**: The authoritative record of "what we are building right now."
    *   *Update trigger:* Weekly planning.
4.  **Domain PRDs (`docs/prds/*.md`)**: The authoritative record of **Product Intent and Context**.
    *   *Role:* They describe *why* and *how it fits together*. They are NOT API references.
    *   *Up to Date means:* The "Status" header is correct, and links to the Roadmap/Tracker are valid. We accept that detailed US lists in MD files will lag behind `prd.json`.

## 4. Maintenance / CI Proposal

**Goal:** Pragmatic drift detection, not perfect synchronization.

1.  **The "Status Banner" Rule (CI Check):**
    *   Logic: If `docs/prds/{name}.md` exists:
        *   Check if `services/{name}/prd.json` exists.
        *   If YES: Ensure PRD has a generic "Implementation Status: ACTIVE" badge linking to the service.
        *   If NO: Ensure PRD has "Status: DRAFT / CONCEPT" header.
    *   *Benefit:* Readers immediately know if code exists.

2.  **Schema Linkage:**
    *   PRDs should not copy-paste JSON shapes. They must link to `packages/schema/{domain}/{file}.vX.json`.

3.  **Tracker Consistency:**
    *   CI Script matches `docs/PRD_INDEX.md` list against `services/*` folders to ensure the index isn't missing active services.

## 5. Next PR Plan

**Objective:** Synchronize the documentation state with the execution state (Ralph outputs) described in the prompt.

**PR 1: Architecture & Naming Cleanup**
*   **Move:** `services/ledger` -> `services/clawledger` (Align with domain/PRD).
*   **Move:** `services/escrow` -> `services/clawescrow` (Align with domain/PRD).
*   **Update:** `docs/PRD_INDEX.md` to reflect these exact paths.

**PR 2: Status Injection**
*   **Update:** `docs/prds/clawbounties.md`:
    *   Add Header: "✅ **Active Service:** [`services/clawbounties`](../../services/clawbounties/)"
    *   Add Schema Link: "Contract: [`bounty.v2.json`](../../packages/schema/bounties/bounty.v2.json)"
*   **Update:** `docs/prds/clawverify.md`, `clawproxy.md`, `clawledger.md`, `clawescrow.md`, `clawcuts.md`, `clawclaim.md`, `clawscope.md` with similar active headers.
*   **Update:** `docs/prds/clawreputation.md`, `clawtrials.md` etc.:
    *   Add Header: "⚠️ **Status: CONCEPT** (No active service)"

**PR 3: Trust vNext Linkage**
*   **Update:** `docs/prds/clawverify.md` and `docs/prds/clawproxy.md` to explicitly link to `docs/roadmaps/trust-vnext/` for "Future Work" (Confidential Computing, Witnessed Web). This strictly separates implemented features from the roadmap.

**Recommended execution order:** PR 2 (Highest value/lowest risk) -> PR 1 (Hygiene) -> PR 3 (Context).
