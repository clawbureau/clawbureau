## What it is

`/Users/gfw/clawd/02-Projects/protocol-m/` is a **planning-only spec bundle** for “Protocol M — Phase 1” with no implementation. It aimed to ship a *user-visible* “instant verification” workflow centered on:

- **Agent identity:** local Ed25519 keypair → `did:key` derivation.  
- **Deterministic signing:** RFC 8785 JCS canonicalization + Ed25519 signatures over canonical JSON.  
- **Portable proof format:** an `m1` JSON “signature envelope” for artifacts, plus a domain-separated message signing format for Moltbook binding.  
- **Key rotation:** continuity via a rotation certificate signed by both old+new keys.  
- **Golden vector:** a single authoritative cross-implementation test vector that gates correctness.  
- **Intended delivery vehicle(s):**
  - Originally: standalone Rust CLI / OpenClaw core PR (explicitly crossed out in README).  
  - Revised: **OpenClaw skill published to ClawHub** in TypeScript/Node (README + IMPLEMENTATION-PLAN).  
  - There’s also an intermediate “OpenClaw extension” plan (REVISED-SCOPE) that assumes contributing `packages/protocol-m` into upstream OpenClaw.  

Primary docs/files in that folder:
- `README.md` (overview, architecture, envelope example, milestones) **[File: ../../protocol-m/README.md]**
- `PRD-phase-1.md` (normative crypto spec, CLI contract, Moltbook API/UI requirements, rotation cert spec, exit codes) **[File: ../../protocol-m/PRD-phase-1.md]**
- `REVISED-SCOPE.md` (reframes as OpenClaw extension; PR strategy) **[File: ../../protocol-m/REVISED-SCOPE.md]**
- `IMPLEMENTATION-PLAN.md` (detailed skill implementation plan; file layout; tests; dependencies) **[File: ../../protocol-m/IMPLEMENTATION-PLAN.md]**
- `golden-vector.json` (authoritative golden vector) **[File: ../../protocol-m/golden-vector.json]**

## Overlap with monorepo

### 1) Identity + signing are already “owned concepts” in the monorepo
The monorepo is already structured around **agent DID identity + signed evidence + fail-closed verification** as core primitives for the agent economy and PoH:

- PoH spec explicitly assumes an **agent DID (initially `did:key` Ed25519)** and focuses on binding identity → harness → run logs → gateway receipts → proof bundle verification **[File: docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md]**.
- The marketplace MVP spec uses **DID-based accounts** and “signed artifacts / proof bundles / commit proofs / receipts” as its trust substrate **[File: docs/specs/agent-economy/MVP.md]**.
- The OpenClaw integration plan makes DID identity first-class and maps services to OpenClaw plugins/skills, emphasizing “skills are docs, plugins are code” (important mismatch with Protocol M’s “skill as executable tool” framing) **[File: docs/integration/OPENCLAW_INTEGRATION.md]**.

### 2) Protocol M’s artifact envelope (`m1`) conflicts with monorepo envelope strategy
Protocol M defines a bespoke `m1` envelope:

```json
{ "version":"m1", "type":"artifact_signature", "algo":"ed25519", ... "signature":"<base64>" }
```

**[File: ../../protocol-m/PRD-phase-1.md]**

Whereas the monorepo’s PoH system standardizes around a **SignedEnvelope** pattern (e.g., receipts embedded in proof bundles with fields like `envelope_version`, `payload_hash_b64u`, `signature_b64u`, `algorithm`, `signer_did`) **[File: packages/schema/poh/proof_bundle.v1.json]**.

So: even when the underlying crypto choices overlap (Ed25519 + canonical JSON), the **wire formats are not aligned**.

### 3) “Instant verification on Moltbook” is not a monorepo priority path
Protocol M Phase 1 is explicitly a **Moltbook** feature: DID challenge binding + verified badge + signed posts **[File: ../../protocol-m/PRD-phase-1.md]**.

The monorepo’s active roadmap is **PoH + marketplace + clawproxy/clawverify + OpenClaw provider/recorder integration** (Proof-of-Harness roadmap + oracle synthesis) **[File: docs/roadmaps/proof-of-harness/README.md]**, **[File: docs/roadmaps/proof-of-harness/oracle/2026-02-07/next-building-blocks-plan.gpt-5.2-pro.md]**.

### 4) Protocol M overlaps partially with “From Protocol M → Agent Economy” but is superseded as a plan
The strategic plan doc explicitly uses “From Protocol M → OpenClaw Contribution → Agent Economy” framing, but recommends a **TypeScript skill** approach (did-work) and Cloudflare services, not the Moltbook Phase 1 delivery **[File: docs/ecosystem/STRATEGIC_PLAN.md]**.

In practice, the monorepo has moved on to:
- PoH schemas (`packages/schema/poh/*`) **[File: packages/schema/README.md]**
- identity attestations (`packages/schema/identity/*`) **[File: packages/schema/identity/owner_attestation.v1.json]**
- commit proofs (`packages/schema/poh/commit_proof.v1.json`) **[File: packages/schema/poh/commit_proof.v1.json]**
…which are outside Protocol M Phase 1 scope.

## Gaps / unique value (what `protocol-m` still contributes)

1) **A crisp, implementation-grade “micro-spec” for basic signing**
Protocol M has unusually complete, low-level, testable definitions for:
- did:key derivation bytes (`0xed01 || pubkey`)  
- canonicalization rules (RFC 8785 JCS)  
- signing procedure (“blank signature then JCS then sign”)  
- deterministic golden vector gating

**[File: ../../protocol-m/PRD-phase-1.md]**, **[File: ../../protocol-m/golden-vector.json]**

This is still useful as a **crypto correctness anchor**, even if the monorepo’s *envelopes* differ.

2) **Rotation certificate concept (minimal continuity)**
Protocol M’s Phase 1 rotation certificate is a concrete, minimal continuity design **[File: ../../protocol-m/PRD-phase-1.md]**.
The monorepo currently focuses more on PoH receipts/event chains/URM; it doesn’t surface an equivalent “did rotation cert” schema in the provided files.

3) **Operator UX: CLI contract + stable exit codes**
Protocol M’s CLI surface + exit code contract is detailed and automation-friendly **[File: ../../protocol-m/PRD-phase-1.md]**. The monorepo docs are more service/roadmap/spec oriented.

4) **Moltbook binding flow**
If Moltbook remains strategically relevant later, Protocol M has a complete end-to-end binding model (challenge signing domain separation + server DB/API + UI semantics) **[File: ../../protocol-m/PRD-phase-1.md]**. None of the monorepo docs prioritize that integration today.

## Recommendation

**Treat `protocol-m` as a reference artifact and archive it into the monorepo** (do not keep it as an active separate planning repo).

Rationale:
- The monorepo is explicitly intended to be the **primary source of truth** (your constraint).
- Protocol M Phase 1 is **mostly superseded** by the monorepo’s PoH + marketplace + OpenClaw integration direction and schemas.
- Keeping a sibling planning folder encourages **spec drift** (especially since Protocol M defines envelope formats that differ from `packages/schema/poh/*`).
- It still has real value as an archived “Phase 1 attempt” and as a **golden-vector + rotation idea source**, so archive (not delete) is the right preservation move.

Concretely:
- Move contents into `docs/archive/protocol-m-phase-1/` (verbatim, with provenance).
- Extract only the parts that are still useful into active monorepo docs/schemas:
  - golden vector / crypto rules → identity/signing spec note (or test fixtures)
  - rotation certificate → either adopt as a schema under `packages/schema/identity/` or explicitly reject/replace with a monorepo-native approach.

## Next steps (small PRs)

### PR 1 — Archive Protocol M into monorepo (verbatim, preserved)
- Create: `docs/archive/protocol-m-phase-1/`
- Copy in these files unchanged (retain original filenames):
  - `README.md` **[from: ../../protocol-m/README.md]**
  - `PRD-phase-1.md` **[from: ../../protocol-m/PRD-phase-1.md]**
  - `REVISED-SCOPE.md` **[from: ../../protocol-m/REVISED-SCOPE.md]**
  - `IMPLEMENTATION-PLAN.md` **[from: ../../protocol-m/IMPLEMENTATION-PLAN.md]**
  - `golden-vector.json` **[from: ../../protocol-m/golden-vector.json]**
- Add `docs/archive/protocol-m-phase-1/ARCHIVE_NOTE.md` with:
  - “Archived on <date>”
  - what replaced it (links to):
    - PoH roadmap/spec **[docs/roadmaps/proof-of-harness/README.md]**, **[docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md]**
    - Agent Economy MVP **[docs/specs/agent-economy/MVP.md]**
    - OpenClaw integration plan **[docs/integration/OPENCLAW_INTEGRATION.md]**
    - Schemas root **[packages/schema/README.md]**
  - explicit warning: “Protocol M `m1` envelopes are not the monorepo canonical SignedEnvelope format.”

### PR 2 — Add a monorepo “Identity + basic signing” bridge doc (active)
Create an active doc that reconciles terms:
- Proposed: `docs/specs/identity/basic-signing.md`
- Contents:
  - Confirm canonical choices: `did:key` Ed25519, JCS usage scope (where required vs optional).
  - Decide: do we standardize on **SignedEnvelope** everywhere (recommended), and treat Protocol M’s `m1` as historical?
  - Include the golden vector as an appendix reference.

Cite/align with:
- Protocol M crypto steps **[../../protocol-m/PRD-phase-1.md]**
- PoH’s canonical JSON guidance **[docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md]**
- Existing schema envelope expectations **[packages/schema/poh/proof_bundle.v1.json]**

### PR 3 — Promote the golden vector into an automated test fixture (if you have a crypto lib)
If the monorepo has (or will have) a shared crypto/util package, add:
- `packages/<crypto-or-verify-lib>/fixtures/protocol-m-golden-vector.json`
- A test that asserts:
  - did:key derivation
  - JCS canonical string matches
  - Ed25519 signature matches

Source: **[../../protocol-m/golden-vector.json]**.

If no shared crypto package exists yet, park it under:
- `packages/schema/fixtures/` or `docs/fixtures/` with a note “used when crypto lib lands”.

### PR 4 — Decide rotation: adopt, adapt, or reject (explicitly)
One of:
- **Adopt**: add `packages/schema/identity/did_rotation.v1.json` based on Protocol M’s rotation cert **[../../protocol-m/PRD-phase-1.md]**.
- **Adapt**: reframe rotation as a SignedEnvelope payload (monorepo style) rather than Protocol M’s inline `signatureOld/signatureNew`.
- **Reject** (but document): add a note in `docs/specs/identity/basic-signing.md` stating rotation continuity will be handled via a different mechanism (e.g., `did:web` controller docs, or clawclaim bindings), and Protocol M rotation is archived only.

### PR 5 — Update strategic docs to point to the archive (remove ambiguity)
- In `docs/ecosystem/STRATEGIC_PLAN.md`, add a short line under the Protocol M section:
  - “Protocol M Phase 1 planning docs archived at `docs/archive/protocol-m-phase-1/`; active work is PoH + OpenClaw integration + agent economy.”
  - Source: **[docs/ecosystem/STRATEGIC_PLAN.md]**

This makes “Protocol M” stop being a parallel, implied-active plan.

---

If you want one sharper decision beyond archiving: **rename “Protocol M” references in active docs to “DID Work / PoH identity primitives”** and treat “Protocol M Phase 1” as the historical name for an earlier Moltbook-centric concept. That reduces ongoing naming drift while keeping the artifact preserved.
