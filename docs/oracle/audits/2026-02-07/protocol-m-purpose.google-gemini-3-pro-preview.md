### What is `protocol-m` for now?

**Type:** Superseded Planning Artifact / Proto-Spec.

`protocol-m` is the **precursor** to the current Agent Economy and Proof-of-Harness architecture. It was the "Phase 1" vision for getting DIDs and signing into OpenClaw. It has effectively been replaced by the more comprehensive `docs/specs/agent-economy/MVP.md` and `packages/schema/poh/*`.

However, it contains **technical specifics** (Crypto Golden Vectors, Rotation Logic) that are missing from the current high-level specs.

### Overlap & Gaps

| Feature | `protocol-m` (Legacy) | `clawbureau` (Monorepo) | Status |
| :--- | :--- | :--- | :--- |
| **Vision** | "Instant Verification" on Moltbook | Agent Economy MVP + PoH | **Superseded**. `clawbureau` is the implementation path. |
| **Identity** | `did:key` (Ed25519) | `did:key` (Ed25519) | **Aligned**. |
| **Verification** | `m1` Envelope (Simple) | `proof_bundle.v1` (Complex) | **Superseded** by `packages/schema/poh`. |
| **Test Vectors** | **`golden-vector.json`** | *Missing / Implicit* | **GAP.** The monorepo needs this authoritative test vector. |
| **Rotation** | **`did_rotation` spec** | *Implicit / Planned* | **GAP.** Explicit rotation certificate schema is defined in Protocol M but not yet in `packages/schema/identity`. |
| **Implementation** | Standalone CLI | `did-work` Skill | **Aligned.** `STRATEGIC_PLAN.md` defines the `did-work` skill, which effectively implements Protocol M. |

### Recommendation

**Do not implement `protocol-m` as a standalone project.**

Instead, **archive it** into the monorepo and **extract** the cryptographic assets (Golden Vector) and schema logic (Rotation) into the active codebase. The "Protocol M" vision is simply the "Identity & Verification" subset of `did-work`.

### Concrete Plan (Next Steps)

Execute these 3 PRs to consolidate truth into the monorepo.

#### PR 1: Archive Protocol M Docs
Move the planning context into the monorepo archive so the external folder can be deleted.
- **Move:** `../protocol-m/*.md` → `docs/archive/protocol-m/`.
- **Note:** Add a `migration_note.md` in that folder stating: "Technically superseded by `docs/specs/agent-economy/MVP.md`; kept for Identity/Rotation reference."

#### PR 2: Adopt the Golden Vector
The `golden-vector.json` is critical for ensuring `clawverify` correctness across languages.
- **Copy:** `../protocol-m/golden-vector.json` → `packages/schema/fixtures/golden_vector_ed25519_jcs.json`.
- **Task:** Create a test in `services/clawverify` that strictly validates this vector (matches `verification_steps` in the JSON). This creates the "Golden Gate" mentioned in `docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md`.

#### PR 3: Adopt Key Rotation Schema
The active specs mention rotation but lack the schema. Protocol M has it defined.
- **Create:** `packages/schema/identity/did_rotation.v1.json`.
- **Content:** Adapt the canonical `did_rotation` schema from `protocol-m/PRD-phase-1.md` (Section 7).
- **Update:** `packages/schema/README.md` to list it under `identity/`.

### Summary
1. **Archive** `protocol-m` text to `docs/archive/`.
2. **Extract** `golden-vector.json` to `packages/schema/fixtures/`.
3. **Delete** the external `protocol-m` folder.
4. **Build** the `did-work` skill (per `STRATEGIC_PLAN.md`) as the implementation vehicle.
