## Executive summary

A “replay” in a trust platform cannot mean “bit-identical LLM output,” because OpenClaw’s harness includes dynamic prompt construction (bootstrap `.md` files, skills snapshot, tool schemas/policy, runtime/time, provider routing/failover) and because LLM providers are intrinsically non-deterministic. Your trust platform should therefore define replay as **evidence re-validation** under a clearly-scoped verification goal: *policy compliance*, *artifact reproducibility*, and *audit-trace integrity*—not token-for-token regeneration.

Concretely:

- Treat the harness as two separable commitments:
  1) **Prompt Pack**: workspace/personality/skills documents + prompt inputs that materially shape behavior (per OpenClaw system prompt construction in `docs/openclaw/5.2-system-prompt.md`).
  2) **Harness Pack**: runtime/tooling/sandbox/provider routing configuration + versions.
- Record and commit to:
  - the **static pack roots** (Merkle roots over pack contents),
  - and the **per-turn rendered system prompt hash** (hash of the exact final prompt text sent to the model for that turn).
- Verification and disputes rely on:
  - **tamper-evident event chain** (already in PoH spec `docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md` and schema `packages/schema/poh/proof_bundle.v1.json`),
  - **gateway receipts** binding LLM calls to events (`ADAPTER_SPEC_v1.md`),
  - **sandbox attestation** that the measured pack roots + rendered prompt hashes were actually loaded/executed (future `clawea`, see `docs/prds/clawea.md` and schema placeholder `packages/schema/poh/execution_attestation.v1.json`),
  - and **artifact-level reproducibility** (tests/CI/build checks) rather than matching model text.

This fails-closed: missing/unknown schema, missing roots, unverifiable receipts, or unmeasured prompts => verification fails.

---

## Definitions (replay taxonomy)

### 0) First principles
A “replay” is an attempt to answer: **what claim are we trying to re-establish?** In an agent economy, there are multiple distinct claims:

- *Integrity*: “These artifacts/logs/receipts correspond to a specific run.”
- *Compliance*: “The run followed declared policy constraints.”
- *Outcome validity*: “The deliverable meets objective criteria (tests/build/rubric).”
- *Attribution*: “This agent DID produced/submitted this evidence.”
- *Environment*: “It ran under a declared isolation regime (sandbox).”

Because LLM outputs are non-deterministic, a replay must be scoped to one (or more) of these claims.

### 1) Deterministic reproduction (bit-identical)
**Definition:** Re-run and obtain bit-for-bit identical outputs (including the model’s generated text/tool calls).

- **Feasibility:** generally **not achievable** with third-party LLM APIs due to sampling/provider nondeterminism, tokenization differences, backend updates, and OpenClaw runtime variability (e.g., time section, failover routing) described in `docs/openclaw/5.2-system-prompt.md` and `docs/openclaw/5.1-agent-execution-flow.md`.
- **Use:** only for deterministic subcomponents (hashing, Merkle roots, event chain hashing, artifact builds if reproducible).
- **Policy:** do not make escrow release or dispute outcomes depend on this.

### 2) Policy compliance verification (recommended core “replay” meaning)
**Definition:** Re-validate that the recorded run evidence proves adherence to declared constraints, without requiring identical model tokens.

Examples:
- Tool calls were allowed by the declared tool policy layers (OpenClaw tool gating described in `docs/openclaw/5.1-agent-execution-flow.md`).
- Sandbox mode and workspace access matched declared settings (`docs/openclaw/5.2-system-prompt.md` “Sandbox” section inclusion; and broader sandboxing docs referenced there).
- LLM calls were routed through clawproxy with receipts bound to run/event (`docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md`).

### 3) Behavioral similarity checks (optional, explicitly non-deterministic)
**Definition:** Re-run with same packs/config and check that behavior is “similar enough” under a metric.

- Examples: judge model scoring, rubric evaluation, or invariants (“never used exec”, “did not access network”).
- **Explicitly not fail-safe** as a sole verifier because it can be gamed and is probabilistic.
- Useful for dispute triage, not automatic settlement.

### 4) Artifact-level reproducibility (tests/CI/builds) — code path
**Definition:** Independently reproduce *delivered artifacts* from declared inputs, then run deterministic checks.

- For code bounties: patch applies to a declared repo state; tests pass in a declared build environment.
- This aligns with marketplace MVP goals in `docs/AGENT_ECONOMY_MVP_SPEC.md` (“verify results deterministically (tests / commit proof / receipts)”).

### 5) Audit trace verification (tamper-evident provenance)
**Definition:** Verify that the event chain, receipts, prompt measurements, and artifact hashes are internally consistent and signed/attested.

- Event chain hashing rules are defined in `docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md`.
- Proof bundle structure is in `packages/schema/poh/proof_bundle.v1.json`.
- This is the strongest “replay” you can do without demanding deterministic LLM outputs.

---

## Proposed evidence model additions (design that does **not** rely on deterministic model outputs)

### A) What to verify instead of “same output”
#### For code deliverables (deterministic settlement path)
1) **Repo state binding**
   - Evidence: `repo_commit` (or content hash) + patch/diff hash.
   - Verification: patch applies cleanly; resulting tree hash matches submitted artifact hash (optional).
2) **Objective execution results**
   - Evidence: test command(s), exit codes, junit/json outputs, coverage summaries; all hashed and listed as artifacts.
   - Verification: re-run tests in verifier-controlled sandbox/CI using the committed repo state.
3) **Build reproducibility (optional but strong)**
   - Evidence: container image digest, lockfiles, build logs, output binary hashes.
   - Verification: reproduce build from scratch; compare output hashes.

#### For non-code deliverables (inherently subjective)
1) **Provenance + integrity**
   - Evidence: signed artifacts (documents), citations, source URLs, data snapshots with hashes.
2) **Rubric evaluation**
   - Evidence: rubric definition + judge results + judge model receipts (if judged via clawproxy).
   - Verification: re-run rubric on the submitted artifacts; optionally use multiple judges and a quorum policy.
3) **Dispute workflow**
   - Escalate to human/arbitration with the audit trace and selective disclosure of prompt pack components.

### B) Record the *actual prompt sent* without revealing it
OpenClaw builds the system prompt dynamically from tools, bootstrap `.md` files (AGENTS.md/SOUL.md/TOOLS.md/IDENTITY.md), skills prompt, sandbox/runtime/time, etc. (`docs/openclaw/5.2-system-prompt.md`).

Because the verifier often must not see raw prompt content, the run must include:

- **Static commitments**
  - `prompt_pack_root_hash` (Merkle root of prompt pack files + normalized metadata)
  - `harness_pack_root_hash` (Merkle root of harness config inputs + versions)
- **Per-turn measurements**
  - `rendered_system_prompt_hash_b64u` for each `llm_call` event (hash of *exact bytes* sent as system prompt)
  - `tools_schema_hash_b64u` for each call (hash of JSON tool schema payload sent to model)
  - `model_config_hash_b64u` (provider+model+params; also capture failover choice)

This allows strong integrity checks and dispute reconstruction *without requiring deterministic model text regeneration*.

### C) Nondeterminism callouts → changed verification strategy
Where nondeterminism forces non-replay:
- **Sampling/provider nondeterminism**: cannot expect identical assistant tokens.
- **Provider routing/failover** (documented in `docs/openclaw/5.1-agent-execution-flow.md`): even “same config” can select different fallback models due to rate limits/billing errors.
- **Dynamic time/timezone injection** (`docs/openclaw/5.2-system-prompt.md` “Current Date & Time”): prompt changes across replays unless frozen/recorded.
- **Memory search results** (referenced in `docs/openclaw/5.1-agent-execution-flow.md`): retrieval can change if index changes or query differs.

Therefore:
- Verification must key off **recorded measurements and receipts**, not regenerated outputs.
- If you want replayability, you must **record the resolved dynamic inputs** (time string used, chosen model, memory search results hash, skills snapshot version, etc.) as evidence.

---

## Prompt Pack / Harness Pack scheme (concrete)

### 1) Pack types
#### Prompt Pack (workspace-controlled behavioral material)
Includes content that changes “who the agent is” and “how it behaves,” per OpenClaw’s system prompt assembly (`docs/openclaw/5.2-system-prompt.md`):

- Bootstrap files actually loaded (case-insensitive resolution):
  - `AGENTS.md`, `SOUL.md`, `TOOLS.md`, `IDENTITY.md` (and any configured custom bootstrap files)
- Skills snapshot inputs/outputs (see skills system in `docs/openclaw/6.3-skills-system.md`):
  - formatted skills XML prompt (the `<available_skills>` block)
  - list of resolved skills + their `SKILL.md` file hashes
  - any skill env overrides snapshot metadata (hashes only unless disclosed)
- Tool summaries that appear in prompt (“Tooling” section) (hash of `coreToolSummaries` + plugin summaries)
- Any configured `extraSystemPrompt` (group/subagent context) (`docs/openclaw/5.2-system-prompt.md` “Extra System Prompt”)
- Optional: “documentation paths” section inputs if they materially affect behavior

**Not included in Prompt Pack root (instead measured per-run/turn):**
- Current time string
- Hostname / OS line
- Model name selection (can change due to failover)
- Sandbox live URLs (noVNC, browser bridge)

Those are *runtime measurements*; commit them in the run manifest as hashes/claims.

#### Harness Pack (execution + policy material)
Includes:
- Harness identity: `openclaw` + version/commit
- Effective OpenClaw config subset that materially affects behavior:
  - tools allow/deny profiles, provider routing policy, sandbox settings, memorySearch enabled/disabled
  - plugin list + versions that affect tools/networking/providers
- Tool schema generation version + ordering (tool order is defined in system prompt builder; see `docs/openclaw/5.2-system-prompt.md` tool order)
- Canonicalization/hashing algorithms used (JCS/RFC8785, SHA-256)

### 2) Canonical hashing + commitments
Use **two-level commitments**:

#### (a) `prompt_root_hash` (Merkle root over prompt pack entries)
Each entry leaf hash:
```
leaf = SHA256( "prompt-pack-leaf-v1" || path || 0x00 || sha256(file_bytes) || 0x00 || content_type || 0x00 || normalization_flags )
```
Then compute Merkle root with deterministic ordering by `path` (bytewise).

#### (b) `config_hash_b64u` (stable hash over harness config)
Compute from a canonical JSON object using RFC 8785 JCS (recommended in `docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md` “Canonical JSON” open question):

```
config_hash = SHA256( JCS({
  harness_id,
  harness_version,
  openclaw_effective_config_subset,
  plugin_versions,
  hashing_algorithms,
  tool_schema_version,
  prompt_builder_version
}))
```

#### (c) Per-turn `system_prompt_render_hash_b64u`
For each `llm_call` event, hash the **exact system prompt bytes** used for that call:
- This directly captures OpenClaw’s dynamic assembly result (`buildAgentSystemPrompt` described in `docs/openclaw/5.2-system-prompt.md`), without revealing it publicly.

### 3) Handling sensitive prompt packs (encryption + selective disclosure)
You need three disclosure modes:

1) **Public commitment only (default)**
   - Publish: `prompt_root_hash`, plus optional size metadata and section hashes.
   - Do **not** publish plaintext prompt files.

2) **Encrypted pack escrow (dispute-ready)**
   - Store encrypted prompt pack bundle in your storage (e.g., clawsilo).
   - Encrypt with hybrid encryption:
     - Random DEK (symmetric) encrypts tarball
     - DEK encrypted to one or more recipients (buyer, arbitrator, clawea attester) using their public keys.
   - Publish only:
     - ciphertext hash
     - `prompt_root_hash`
     - recipient set (DIDs) who can decrypt (optional)

3) **Selective disclosure via Merkle proofs**
   - Reveal specific files/sections (e.g., AGENTS.md) with:
     - plaintext bytes
     - leaf hash proof path to `prompt_root_hash`
   - Optionally disclose *redacted* text with a “redaction manifest” and commit to redaction boundaries (more complex; can be v2).

### 4) Binding to URM + event chain + receipts + attestation
Bind everything to the run using existing PoH structures:

- **Event chain** (already in `packages/schema/poh/proof_bundle.v1.json`):
  - Include events:
    - `run_start` contains `prompt_root_hash`, `config_hash_b64u`, and runtime measurement claims.
    - Each `llm_call` payload includes:
      - `rendered_system_prompt_hash_b64u`
      - `tools_schema_hash_b64u`
      - `model_config_hash_b64u`
- **Gateway receipts**:
  - Each receipt already supports `binding.run_id` and `binding.event_hash_b64u` (`packages/schema/poh/proof_bundle.v1.json` receipts.binding).
  - Add `binding.prompt_root_hash` and/or `binding.system_prompt_render_hash` in a future receipt binding schema revision (or include in receipt `metadata`) to tighten linkage.
- **URM (your “Universal Run Manifest”)**:
  - URM should include:
    - `prompt_pack_ref` (hashes + optional encrypted blob ref)
    - `harness_pack_ref`
    - `event_chain_root_hash`
    - `receipts_root_hash`
    - `artifacts_root_hash`
- **Execution attestation (clawea)**:
  - Attestation claims include the same hashes so verifiers can match them.

---

## Attestation claims (clawea): “loaded this exact prompt pack” without revealing it

### 1) How the attester verifies pack load (no public disclosure)
Because you don’t have a TEE in v0 (explicit in `docs/prds/clawea.md` “Non-Goals (v0) - Full TEE v0”), the attester must be trusted as an *authority* that:
- controls the sandbox runtime and loader
- can observe what was mounted/loaded
- signs claims about measured hashes

Mechanism:
1) The job submission provides **only commitments** publicly:
   - `prompt_root_hash`
   - `config_hash_b64u`
2) The actual prompt pack may be provided to clawea either:
   - plaintext over mutually-authenticated channel, or
   - encrypted to the clawea attester DID (preferred)
3) The clawea loader:
   - decrypts (if needed),
   - reconstructs the Merkle tree,
   - verifies computed `prompt_root_hash` equals the declared one (fail-closed),
   - computes per-turn `rendered_system_prompt_hash_b64u` as it injects the prompt into the model call path,
   - records those hashes into the event chain or a sidecar log root,
   - signs an execution attestation referencing these hashes.

This proves “this pack was loaded” by **measurement**, not by revealing content.

### 2) Required attestation claims (v1)
Extend `packages/schema/poh/execution_attestation.v1.json` usage with specific required fields (some can go in `runtime_metadata` until schema tightens):

Core bindings:
- `execution_type = "sandbox_execution"` (already in schema)
- `agent_did` (already)
- `attester_did` (already)
- `run_id` (recommended to require for clawea tier)
- `proof_bundle_hash_b64u` (recommended to require for clawea tier)

Prompt/harness measurement claims (add to `runtime_metadata` now; later first-class):
- `prompt_root_hash_b64u`
- `harness_config_hash_b64u` (your `config_hash_b64u`)
- `prompt_ciphertext_hash_b64u` (if encrypted blob supplied)
- `rendered_system_prompt_hashes`:
  - either a list of `(event_id|event_hash) -> prompt_hash`
  - or a Merkle root over these per-turn prompt hashes: `system_prompt_hash_root_b64u`

Execution environment claims:
- sandbox image digest (container rootfs hash)
- network/egress policy hash
- workspace mount mode (none/ro/rw) consistent with OpenClaw semantics (`docs/openclaw/5.2-system-prompt.md` “Sandbox” section describes workspace access)
- tool policy hash enforced in sandbox
- resource limits (cpu/mem/time)

Audit/log claims:
- `event_chain_root_hash_b64u`
- `artifact_root_hash_b64u`
- optional `clawlogs` log root (explicitly desired by `docs/prds/clawea.md` CEA-US-007)

Fail-closed tier rule:
- To claim `sandbox` trust tier, verifiers require an allowlisted attester DID + matching hash bindings.

---

## Minimum schema + verifier changes needed (fail-closed)

### 1) New schema objects
1) `packages/schema/poh/prompt_pack.v1.json` (new)
   - Defines:
     - `pack_id`
     - `pack_version`
     - `prompt_root_hash_b64u`
     - `entries[]` (path, content_hash, content_type, size_bytes) — optional to publish; can be omitted publicly
     - `encryption` block (optional): ciphertext hash + recipients
2) `packages/schema/poh/harness_pack.v1.json` (new)
   - Defines:
     - `harness_id`, `harness_version`
     - `config_hash_b64u`
     - optional structured “effective config subset” (could be private/encrypted similarly)

### 2) Additions to URM / proof bundle metadata
You already have `metadata.harness.config_hash_b64u` in `packages/schema/poh/proof_bundle.v1.json`. Minimal additions:

- In `ProofBundlePayload.metadata` (or URM once you add an URM schema as suggested in `docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md` §6.2):
  - `prompt_root_hash_b64u`
  - `harness_config_hash_b64u` (may reuse existing `metadata.harness.config_hash_b64u`)
  - optional references:
    - `prompt_pack_ref` (resource hash + storage locator)
    - `harness_pack_ref`
- In event payloads (not the chain header), for `llm_call`:
  - `rendered_system_prompt_hash_b64u`
  - `tools_schema_hash_b64u`
  - `model_config_hash_b64u`

### 3) Verifier rule changes (clawverify / marketplace)
Fail-closed rules to add:

1) **Event chain recomputation must be enforced**
   - `docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md` notes a current gap: verifier should recompute `event_hash_b64u` from canonical headers.
   - Make this mandatory for any tier above `self`.

2) **Receipt linkage enforcement**
   - For `gateway` tier:
     - require ≥1 receipt with `binding.run_id == run_id` and `binding.event_hash_b64u` matching an event in the chain (already shaped in `packages/schema/poh/proof_bundle.v1.json`).
   - If receipt format mismatch still exists (called out in `ADAPTER_SPEC_v1.md` §5.3), fail-closed: do not grant `gateway`.

3) **Prompt/harness measurement presence**
   - For higher assurance (and especially disputes), require:
     - `prompt_root_hash_b64u` present at `run_start`
     - per `llm_call` prompt hash present
   - If missing: still may validate artifact hashes, but cannot validate “same harness inputs,” so downgrade tier or mark “insufficient harness evidence”.

4) **Sandbox tier enforcement**
   - Require execution attestation whose bindings match:
     - `run_id`, `proof_bundle_hash_b64u`, `prompt_root_hash_b64u`, `config_hash_b64u`, and `event_chain_root_hash_b64u`.

---

## Roadmap (8–12 staged steps to “replay-safe / dispute-safe”)

1) **Define replay goals in policy**
   - Document that “replay” means *audit-trace + policy + artifact verification*, not identical model output.
   - Encode in marketplace rules (aligns with MVP philosophy in `docs/AGENT_ECONOMY_MVP_SPEC.md`).

2) **Add per-turn prompt measurement in OpenClaw harness adapter**
   - Compute `rendered_system_prompt_hash_b64u` for each model call from the exact system prompt text produced by the builder described in `docs/openclaw/5.2-system-prompt.md`.
   - Record in `llm_call` event payload.

3) **Implement Prompt Pack builder + Merkle root**
   - Resolve which bootstrap files were loaded (AGENTS.md/SOUL.md/TOOLS.md/IDENTITY.md; see `docs/openclaw/5.2-system-prompt.md` “Bootstrap Files and Context Injection”).
   - Include skills snapshot artifacts per `docs/openclaw/6.3-skills-system.md`.
   - Compute `prompt_root_hash_b64u`.

4) **Implement Harness Pack effective-config hashing**
   - Extract “effective config subset” (tool policies, sandbox config, provider routing, plugin versions).
   - Compute `config_hash_b64u`.
   - Populate `metadata.harness.config_hash_b64u` (already supported in `packages/schema/poh/proof_bundle.v1.json`).

5) **Schema additions**
   - Add `prompt_pack.v1.json` + `harness_pack.v1.json`.
   - Add optional fields to URM/proof bundle metadata for `prompt_root_hash_b64u`.
   - Add event payload fields for prompt/tools/model config hashes.

6) **Verifier upgrades (fail-closed)**
   - Recompute event chain hashes per `docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md` §4.2.
   - Enforce receipt linkage to event hash for `gateway` tier.
   - Enforce presence/consistency of prompt/harness hashes when claimed.

7) **Sensitive pack storage + encryption**
   - Store encrypted prompt pack blobs (and optionally harness pack blobs) with ciphertext hash.
   - Support recipient-encrypted DEKs for arbitrators/clawea.

8) **Dispute flow v1 (selective disclosure)**
   - Build tooling to disclose:
     - a single bootstrap file, or
     - a skills SKILL.md,
     - with Merkle proof to `prompt_root_hash_b64u`.
   - Establish a dispute playbook: what must be revealed under what conditions.

9) **Artifact-level reproducibility pipeline (code lane)**
   - Standardize how tests/builds are captured as artifacts (hash + signed).
   - Add deterministic re-run in verifier-controlled sandbox/CI.
   - Make escrow release depend on these deterministic checks, not model text.

10) **Receipt format unification**
   - Resolve the known mismatch called out in `docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md` §5.3:
     - either have clawproxy emit `SignedEnvelope<GatewayReceiptPayload>`,
     - or teach clawverify to verify the existing receipt format.
   - Until done, fail-closed: no `gateway` tier.

11) **clawea attestation MVP**
   - Implement sandbox runner that measures:
     - `prompt_root_hash_b64u`, `config_hash_b64u`, `event_chain_root_hash_b64u`
     - optional `system_prompt_hash_root_b64u`
   - Emit `execution_attestation.v1` (schema exists: `packages/schema/poh/execution_attestation.v1.json`), with these claims in `runtime_metadata` initially.

12) **Tier policy + automation**
   - Marketplace enforces:
     - `self` tier: signature + artifact hashes only
     - `gateway` tier: valid linked receipts
     - `sandbox` tier: valid linked clawea attestation
   - Add “insufficient evidence” states to drive manual review rather than false acceptance.

---

If you want, I can also draft the exact field names and canonical JSON structures to minimize future schema churn (especially where to place `prompt_root_hash_b64u`: proof bundle metadata vs URM vs event payload), but the above is implementable with minimal disruption to `packages/schema/poh/proof_bundle.v1.json` and aligns with the OpenClaw prompt construction reality documented in `docs/openclaw/5.2-system-prompt.md`.
