## Executive summary (target architecture + why it works)

### What we are building
A 2026 **agent trust platform / agent economy** where buyers can pay remote agents while getting **cryptographically-verifiable, non-gameable evidence** about (a) *who* ran, (b) *what policy/harness* they ran under, (c) *what model/tool/egress actions* occurred, and (d) *what artifacts* were produced—**without requiring bit-identical LLM output replay**.

### Core mechanism: Proof-of-Harness (PoH) as “binding across domains”
PoH works when we bind these things into a single, fail-closed verification story:

1) **Identity**: an agent DID signs the proof bundle.  
2) **Execution trace integrity**: an **event chain** is hash-linked and verifier **recomputes** each event hash (required by `docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md` §4.2 and currently missing in `services/clawverify/src/verify-proof-bundle.ts`).  
3) **Model usage integrity**: LLM calls routed via `clawproxy` produce **signed receipt envelopes** (`services/clawproxy/src/receipt.ts`) bound to `run_id` and `event_hash_b64u` (`packages/schema/poh/receipt_binding.v1.json`).  
4) **Policy binding**: receipts include `policy_hash` + `token_scope_hash_b64u` (policy + CST) extracted and injected in `services/clawproxy/src/index.ts`.  
5) **Output integrity**: a URM commits to content hashes for inputs/outputs (`packages/schema/poh/urm.v1.json`) and is referenced by hash in the proof bundle (`packages/schema/poh/proof_bundle.v1.json`).

### OpenClaw-first “enforcement by construction”
For high trust tiers we do not rely on “the agent remembered to do X.” We enforce via integration points:

- **Provider plugin**: OpenClaw routes all model calls through `@openclaw/provider-clawproxy` (`packages/openclaw-provider-clawproxy/src/provider.ts`), which injects binding headers automatically.  
- **Recorder plugin**: OpenClaw recorder emits event chain + URM + proof bundle (`packages/openclaw-provider-clawproxy/src/recorder.ts`).  
- **Sandbox runner**: `clawea` provides **sandbox-attested execution** (`docs/prds/clawea.md`) and issues **execution attestations** (`packages/schema/poh/execution_attestation.v1.json`).  
- **Verifier**: `clawverify` verifies all evidence **fail-closed** (`docs/prds/clawverify.md`, `services/clawverify/src/verify-proof-bundle.ts`, `services/clawverify/src/verify-receipt.ts`).

### Subscription auth reality (ChatGPT/Gemini/Claude web)
Web/subscription sessions authenticate via cookies/proprietary tokens, so **local “web run proof” is forgeable** under our threat model. Therefore:

- **Do not treat subscription-web runs as “gateway tier.”**  
- Provide a *path* to higher trust via: (a) **witnessed web** (controlled remote browser runner) and/or (b) **attested execution** (sandbox/TEE) that can observe decrypted web traffic and sign “web receipts.”  
(See `docs/roadmaps/proof-of-harness/oracle/2026-02-07/subscription-auth.gpt-5.2-pro.md`.)

### Nondeterminism: define replay as “evidence re-validation”
We explicitly do **not** require reproducing model tokens. “Replay” means:

- re-validate signatures, hashes, bindings, policies, and attestations, and
- re-run **deterministic checks** (tests/builds/rubrics) against submitted artifacts.  
To support OpenClaw’s dynamic system prompt composition (bootstrap/personality `.md`, skills, tool schemas), we add **prompt-pack commitments** and per-call **rendered system prompt hashes** (see `docs/roadmaps/proof-of-harness/oracle/2026-02-07/replay-nondeterminism.gpt-5.2-pro.md` and `.../openclaw-system-prompt-integrity.gpt-5.2-pro.md`).

### Why it’s hard to cheat
The system is non-gameable *when*:
- event hashes are recomputed (closing the biggest current hole),
- receipts are signature-verified and bound to recomputed event hashes,
- policy hashes and token scope hashes are enforced against job contracts, and
- high-tier runs happen in sandbox/TEE environments that constrain egress and tools.

This aligns with PoH tiering in `docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md` and marketplace gating in `docs/AGENT_ECONOMY_MVP_SPEC.md` (`min_proof_tier`).

---

## Tier model (marketplace-facing, consistent system-wide)

> **Tier labels (canonical):** `self | gateway-receipted | sandbox-attested | tee-attested | witnessed-web (optional)`

### Tier 0 — `self`
**Proves**
- Proof bundle is signed by an agent DID (authorship/accountability).
- Artifacts/URM hashes match what was submitted (if URM/artifacts retrievable by hash).

**Does NOT prove**
- Model calls happened via any gateway.
- Tool/network constraints were enforced.
- Completeness of logs (agent can omit events).
- Confidentiality against the worker’s machine/operator.

### Tier 1 — `gateway-receipted`
**Proves**
- At least N LLM calls were made through an allowlisted `clawproxy` signer, with receipts that are:
  - signature-valid (`services/clawverify/src/verify-receipt.ts`),
  - bound to `run_id` and a specific event hash in the bundle (`services/clawverify/src/verify-proof-bundle.ts`),
  - and (after hardening) bound to **recomputed** event hashes per `ADAPTER_SPEC_v1.md` §4.2.

**Does NOT prove**
- The agent did not also call models off-gateway.
- Tools/egress were constrained (unless separately attested/receipted).
- Subscription-web usage authenticity.

### Tier 2 — `sandbox-attested`
**Proves**
- Everything in Tier 1 **plus** an allowlisted execution attestation asserts the run executed in a sandbox with stated properties (egress policy, workspace mount rules, etc.) using `packages/schema/poh/execution_attestation.v1.json` (see `docs/prds/clawea.md`).

**Does NOT prove**
- Confidentiality against the sandbox operator/admin (unless you trust the operator).
- TEE-level memory confidentiality.

### Tier 3 — `tee-attested`
**Proves**
- Everything in Tier 2 **plus** remote attestation evidence that execution occurred inside a TEE with measured code/policy.

**Does NOT prove**
- Absolute security against side channels/supply chain; claims must be explicitly enumerated in attestation.

### Optional Tier — `witnessed-web` (policy-defined; never equals gateway by default)
**Proves**
- A trusted witness service (allowlisted signer) observed a web/subscription session interaction and signed “web receipt” evidence bound to a run/event chain.

**Does NOT prove**
- Provider-issued API receipts (unless provider partners sign).
- That web session maps to a specific backend model beyond what witness can reliably infer.

(Subscription-web evidence must not upgrade to Tier 1 unless it produces an allowlisted, cryptographically verifiable receipt/attestation; see `.../subscription-auth.gpt-5.2-pro.md`.)

---

## Evidence model (end-to-end) + schema deltas

### End-to-end evidence objects
1) **Proof bundle envelope (agent-signed)**  
- Current: `SignedEnvelope<ProofBundlePayload>` verified by `services/clawverify/src/verify-proof-bundle.ts`.  
- Schema: `packages/schema/poh/proof_bundle.v1.json`.

2) **Event chain (tamper-evident log)**  
- Schema: `packages/schema/poh/proof_bundle.v1.json` (`event_chain`) and `packages/schema/poh/event_chain.v1.json`.  
- Must verify:
  - linkage (`prev_hash_b64u`),
  - run_id consistency,
  - **recomputed event_hash_b64u** per `docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md` §4.2 (currently missing).

3) **URM (Universal Run Manifest)**  
- Schema exists: `packages/schema/poh/urm.v1.json`.  
- Must be **materialized** (fetched or included) and hashed to match `ProofBundlePayload.urm.resource_hash_b64u` (`packages/schema/poh/proof_bundle.v1.json`).  
(Currently `clawverify` only validates URM reference shape in `services/clawverify/src/verify-proof-bundle.ts`.)

4) **Gateway receipts (LLM call receipts)**  
- Canonical format: `SignedEnvelope<GatewayReceiptPayload>` generated in `services/clawproxy/src/receipt.ts` (`generateReceiptEnvelope()`), attached by `attachReceiptEnvelope()`.  
- Binding: `packages/schema/poh/receipt_binding.v1.json`.  
- Verification: `services/clawverify/src/verify-receipt.ts` + binding check in `services/clawverify/src/verify-proof-bundle.ts`.

5) **Policy bindings** (job-required)
- Receipt binding fields: `policy_hash`, `token_scope_hash_b64u` (schemas: `packages/schema/poh/proof_bundle.v1.json` receipt binding object; canonical definition: `packages/schema/poh/receipt_binding.v1.json`).
- Marketplace must verify these match the job’s pinned policy/contract.

6) **Prompt-pack commitments (OpenClaw reality)**
- Needed because OpenClaw system prompt is dynamically composed (bootstrap/personality `.md`, skills, tool schemas; see `docs/openclaw/5.2-system-prompt.md` referenced in oracle docs).  
- Evidence to add:
  - `prompt_root_hash_b64u` (Merkle root over prompt-pack inputs),
  - per-`llm_call`: `rendered_system_prompt_hash_b64u`,
  - `tool_schema_hash_b64u`,
  - `model_config_hash_b64u` (provider/model/params/failover resolution).  
(Design described in `docs/roadmaps/proof-of-harness/oracle/2026-02-07/replay-nondeterminism.gpt-5.2-pro.md` and `.../openclaw-system-prompt-integrity.gpt-5.2-pro.md`.)

7) **Egress receipts (non-LLM network)**
- Add mediated egress proxy receipts for confidential consulting: `egress_receipt` envelope type, signed by allowlisted egress authority, bound to run/event.

8) **Execution attestations**
- Schema: `packages/schema/poh/execution_attestation.v1.json`.  
- Must be a **signed envelope** (not a shape-only “reference”) for fail-closed verification.

9) **Web receipts (subscription/web witness)**
- Add `web_receipt` envelope type (witness-signed), bound to run/event chain, for witnessed-web tiering.

### Required schema deltas (concrete)
1) **Proof bundle v2 (or v1 additive if possible)**
Update `packages/schema/poh/proof_bundle.v1.json` to support additional evidence without overloading `receipts[]`:
- Add:
  - `execution_attestations?: SignedEnvelope<ExecutionAttestationPayload>[]`
  - `egress_receipts?: SignedEnvelope<EgressReceiptPayload>[]`
  - `web_receipts?: SignedEnvelope<WebReceiptPayload>[]`
  - `prompt_commitments?: { prompt_root_hash_b64u, harness_config_hash_b64u, ... }` (or reference via URM inputs)
- Or more future-proof: `evidence_envelopes?: SignedEnvelope<unknown>[]` with strict `envelope_type` allowlist in verifier.

2) **New schema files**
- `packages/schema/poh/web_receipt.v1.json` (witness-signed web/session evidence)  
- `packages/schema/poh/egress_receipt.v1.json` (non-LLM network mediation evidence)  
- `packages/schema/poh/system_prompt_report.v1.json` *or* `prompt_pack.v1.json` + `harness_pack.v1.json` (as proposed in `.../replay-nondeterminism.gpt-5.2-pro.md`)

3) **Attestation handling**
- Replace `attestations: AttestationReference[]` (currently shape-only validated in `services/clawverify/src/verify-proof-bundle.ts`) with:
  - `attestation_envelopes?: SignedEnvelope<ExecutionAttestationPayload | OwnerAttestationPayload | ...>[]`
so signatures can be verified fail-closed.

4) **Receipt binding extension (optional but recommended)**
Extend `packages/schema/poh/receipt_binding.v1.json` to optionally include:
- `prompt_root_hash_b64u`
- `rendered_system_prompt_hash_b64u`
so gateway receipts can be bound to prompt commitments (helps with OpenClaw prompt injection resistance and replay semantics).

---

## Contract / policy model (sensitive consulting)

### Objects (and how they bind)
1) **CWC — Confidential Work Contract (buyer ↔ worker)**
- A signed, immutable contract describing:
  - required tier (`sandbox-attested` default for PII/sensitive repos),
  - egress allowlist policy,
  - tool policy profile,
  - disclosure mode (hash-only receipts, encrypted prompt packs),
  - verification requirements (must have receipts bound, must have attestation, etc.).  
(Concept and fields outlined in `docs/roadmaps/proof-of-harness/oracle/2026-02-07/confidential-consulting.gpt-5.2-pro.md`.)

2) **WPC — Work Policy Contract (runtime-enforceable policy)**
- Must be hashable (RFC8785 JCS → SHA-256) and referenced by `policy_hash` in receipts (injected by `services/clawproxy/src/index.ts`, enforced by `services/clawproxy/src/policy.ts`).  
- Make WPC a first-class signed object served by `clawcontrols` (`docs/prds/clawcontrols.md`).

3) **DC — Delegation Contract (agent hiring agent; optional for consulting)**
- Lives in `clawdelegate` (`docs/prds/clawdelegate.md`).
- Produces delegated CSTs with narrow scope/spend/time.

4) **CST bindings (Scoped Tokens)**
- `clawproxy` already validates CSTs and requires `token_scope_hash_b64u` claim when token is used (`services/clawproxy/src/index.ts`).
- For consulting, CST should include:
  - `sub = worker_did`
  - `job_id / mission_id`
  - `policy_hash_b64u`
  - `delegation_id` (if delegated)
  - deterministic `token_scope_hash_b64u` (already required by proxy).

### Binding rules (mechanical, fail-closed)
- **Job pins**:
  - marketplace stores `cwc_hash_b64u`, `wpc_hash_b64u`, and expected `token_scope_hash_b64u` (or a token policy that derives it).
- **Receipts must satisfy**:
  - `binding.policy_hash == wpc_hash_b64u`
  - `binding.token_scope_hash_b64u == expected_token_scope_hash_b64u`
  - (optional hardening) `receipt.client_did == worker_did` as a signed receipt claim (see red-team issue #9 in `docs/roadmaps/proof-of-harness/oracle/2026-02-07/redteam.gpt-5.2-pro.md`).
- **URM must include**:
  - `job_ref` / bounty id
  - `cwc_hash_b64u`, `wpc_hash_b64u`
  - `prompt_root_hash_b64u` (or a reference to the prompt report object)
  - input repo commit hash(es) and output artifact hashes.

### Confidentiality reality statement (must be explicit in product)
- Without TEEs, we can prove **mediated egress + receipted LLM usage + sandbox constraints** (Tier 2) but cannot prove the worker/operator didn’t observe plaintext on their machine. This is consistent with PoH non-goals in `docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md` §1 and the consulting oracle writeup.

---

## Enforcement-by-construction architecture (OpenClaw-first)

### Where to enforce (components)
1) **OpenClaw provider plugin (`@openclaw/provider-clawproxy`)**
- Forces model calls through `clawproxy` and injects PoH binding headers (`packages/openclaw-provider-clawproxy/src/provider.ts`).
- Must additionally inject:
  - policy headers (`X-Policy-Hash`, `X-Confidential-Mode`, `X-Receipt-Privacy-Mode`) consistent with `services/clawproxy/src/policy.ts`.

2) **OpenClaw recorder plugin**
- Emits event chain, URM, proof bundle (`packages/openclaw-provider-clawproxy/src/recorder.ts`).
- Must record prompt commitments (prompt root + per-call prompt hash) for nondeterminism/replay semantics.

3) **clawea sandbox runner**
- Runs jobs in sandbox, enforces network/tool constraints, produces execution attestation (`docs/prds/clawea.md`, `packages/schema/poh/execution_attestation.v1.json`).

4) **clawproxy**
- Enforces WPC provider/model allowlists and confidential-mode privacy behavior (`services/clawproxy/src/policy.ts`).
- Issues signed gateway receipts (`services/clawproxy/src/receipt.ts`).
- Must implement durable idempotency (currently in-memory in `services/clawproxy/src/idempotency.ts`).

5) **clawverify**
- Fail-closed verifier that recomputes event hashes, verifies receipts, verifies attestations, enforces tier semantics (`services/clawverify/src/verify-proof-bundle.ts`).

### Preventing prompt injection & “repo-as-adversary”: the Airlock pattern
Mechanically treat all buyer inputs (repo/files/issues) as **untrusted**:
- **Split identity/policy context from job repo context** so repo cannot become bootstrap/system authority (attack detailed in `docs/roadmaps/proof-of-harness/oracle/2026-02-07/prompt-injection-redteam.gpt-5.2-pro.md` and the “Airlock Pattern” doc `.../prompt-injection-redteam.google-gemini-3-pro-preview.md`).
- Enforce in OpenClaw:
  - Bootstrap/personality `.md` come from a **trusted identity root**, not the job workspace.
  - Disable workspace skill auto-discovery for sensitive tiers.
  - Block buyer-origin directives from changing security posture.

**Capability gating (recommended for sensitive tiers)**  
Planner/executor split + tool capability tokens:
- Planner reads untrusted repo; executor can act but only with gate-issued, parameter-scoped tokens.
- Prevents “model got tricked” from directly invoking dangerous tools.

### Preventing exfiltration & policy downgrade
- **Network default deny** in sandbox; only:
  - `clawproxy` for LLM calls
  - allowlisted endpoints via mediated egress proxy producing `egress_receipt`.
- DLP/redaction:
  - `clawproxy` already supports redaction rules (`services/clawproxy/src/policy.ts`) and forces hash-only receipts in confidential mode.
  - Add artifact output scanning before submission (block secrets/PII if policy requires).

---

## Verification hardening work (do now; fail-closed correctness)

These are “must fix” to avoid accidental over-trust (many are called out directly in red-team: `docs/roadmaps/proof-of-harness/oracle/2026-02-07/redteam.gpt-5.2-pro.md`).

### `clawverify` correctness hardening
1) **Recompute `event_hash_b64u` for every event** (blocker)  
- Implement canonical hash per `docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md` §4.2.  
- File: `services/clawverify/src/verify-proof-bundle.ts` (`validateEventChain()`).

2) **Enforce DID equality: `envelope.signer_did === payload.agent_did`**  
- Currently missing (red-team attack #3).  
- File: `services/clawverify/src/verify-proof-bundle.ts`.

3) **Strict JSON schema validation (Ajv)**
- Today verification is partial and can miss `additionalProperties:false` constraints present in `packages/schema/poh/proof_bundle.v1.json`.  
- Add Ajv validation for proof bundles, receipts, URM, attestations/envelopes.

4) **Attestation signature verification or disable tier uplift**
- Today `validateAttestation()` is shape-only; `computeTrustTier()` treats it as meaningful (`services/clawverify/src/verify-proof-bundle.ts`).  
- Until attestation envelopes are verified against an allowlist, **do not** allow attestations to raise trust tier.

5) **Receipt numeric validation hardening**
- Use `Number.isFinite` for `tokens_input`, `tokens_output`, `latency_ms` in `services/clawverify/src/verify-receipt.ts` (NaN/Infinity bypass called out in red-team).

6) **Uniqueness + size limits**
- Enforce unique `event_id` within run, unique `receipt_id` within bundle.
- Add max sizes: events/receipts count, metadata bytes, string lengths to prevent verifier DoS.

7) **Semantic binding checks**
- Require the receipt-bound event hash refers to an `llm_call` event type (or allowlist).
- Enforce timestamp monotonicity and receipt timestamp within skew window relative to event timestamp.

### `clawproxy` hardening
8) **Durable idempotency + replay protection**
- Replace in-memory nonce cache (`services/clawproxy/src/idempotency.ts`) with durable KV/DO keyed by `(signer_kid, nonce)` and store request fingerprint hash.
- Fail closed on “same nonce, different request.”

9) **Clarify CST vs provider key header rules**
- `services/clawproxy/src/index.ts` currently infers CST from Authorization if it “looks like JWT.”
- For high tiers, define **strict mode**: CST only accepted via `X-CST` (or a single canonical header), provider keys only via `X-Provider-API-Key`, never ambiguous.

### Marketplace (stateful) hardening
10) **Replay DB**
- Store seen `(agent_did, run_id)` and `(receipt signer_did, receipt_id)` to reject duplicates across submissions (red-team attack #10/#11).

11) **Policy pin enforcement**
- For sensitive jobs, enforce `binding.policy_hash` and `binding.token_scope_hash_b64u` match the posted job’s pinned values; otherwise reject.

---

## Roadmap: 16 concrete stories (12–20), with ownership, AC, dependencies

> ID prefixes suggested by you: POH, CPX, CVF, CEA, CCO, CDL (+ CWC for consulting contracts)

1) **CVF-US-021 — Recompute event hashes (fail-closed)**
- **Owner:** clawverify  
- **Files:** `services/clawverify/src/verify-proof-bundle.ts`, spec `docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md`  
- **AC:** bundle INVALID if any `event_hash_b64u != SHA256(JCS(canonical header))`; gateway tier impossible unless chain valid.  
- **Deps:** none (blocker for many).

2) **CVF-US-022 — Enforce signer DID == payload agent DID**
- **Owner:** clawverify  
- **Files:** `services/clawverify/src/verify-proof-bundle.ts`  
- **AC:** INVALID if `envelope.signer_did !== payload.agent_did`.  
- **Deps:** none.

3) **CVF-US-023 — Disable attestation tier uplift until signatures verified**
- **Owner:** clawverify  
- **Files:** `services/clawverify/src/verify-proof-bundle.ts`  
- **AC:** attestations do not affect tier unless verified as signed envelopes against allowlist.  
- **Deps:** none.

4) **CVF-US-024 — Ajv strict schema validation for proof_bundle + receipt**
- **Owner:** clawverify  
- **Files:** `services/clawverify/src/*`, schemas `packages/schema/poh/*.json`  
- **AC:** unknown fields rejected; validation errors return deterministic codes.  
- **Deps:** none.

5) **CVF-US-025 — Receipt numeric + size hardening**
- **Owner:** clawverify  
- **Files:** `services/clawverify/src/verify-receipt.ts`, `verify-proof-bundle.ts`  
- **AC:** reject NaN/Infinity; enforce max receipts/events/metadata sizes.  
- **Deps:** #4 (recommended), but can be parallel.

6) **POH-US-013 — Align tier semantics to marketplace tiers**
- **Owner:** PoH / clawverify + marketplace  
- **Files:** `services/clawverify/src/verify-proof-bundle.ts`, `docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md`, `docs/AGENT_ECONOMY_MVP_SPEC.md`  
- **AC:** output tier is exactly `self|gateway-receipted|sandbox-attested|tee-attested|witnessed-web?` (or output “components + derived tier”).  
- **Deps:** #1–#3.

7) **CPX-US-031 — Durable idempotency store**
- **Owner:** clawproxy  
- **Files:** `services/clawproxy/src/idempotency.ts`, `services/clawproxy/src/index.ts`  
- **AC:** cross-instance safe; duplicate nonce returns same receipt only if request fingerprint matches; otherwise reject.  
- **Deps:** none.

8) **POH-US-014 — Marketplace replay DB**
- **Owner:** marketplace (clawbounties)  
- **AC:** reject reused `(agent_did, run_id)` or `(receipt_id, signer)`; log reason.  
- **Deps:** none (but becomes more valuable after #7).

9) **POH-US-015 — URM materialization + CAS retrieval contract**
- **Owner:** PoH + marketplace storage  
- **Files:** `packages/schema/poh/urm.v1.json`, `packages/schema/poh/proof_bundle.v1.json`, verifier changes  
- **AC:** verifier fetches URM bytes (by URI or submission upload), hashes to `resource_hash_b64u`, fails closed if missing.  
- **Deps:** #4.

10) **POH-US-016 — Prompt commitment evidence (OpenClaw)**
- **Owner:** OpenClaw integration  
- **Files:** `packages/openclaw-provider-clawproxy/src/recorder.ts` (+ OpenClaw runtime integration as needed), docs `docs/OPENCLAW_INTEGRATION.md`  
- **AC:** for each run:
  - compute `prompt_root_hash_b64u`,
  - record per `llm_call` `rendered_system_prompt_hash_b64u`,
  - include references in URM inputs or proof bundle metadata.  
- **Deps:** #9 (URM usable for carrying this cleanly).

11) **POH-US-017 — New schema: system_prompt_report / prompt_pack**
- **Owner:** PoH schemas  
- **Files:** add `packages/schema/poh/system_prompt_report.v1.json` (or `prompt_pack.v1.json`, `harness_pack.v1.json`)  
- **AC:** strict schemas; verifier allowlists versions/types.  
- **Deps:** none (but used by #10).

12) **CPX-US-032 — Strict auth header mode (CST vs provider keys)**
- **Owner:** clawproxy  
- **Files:** `services/clawproxy/src/index.ts`  
- **AC:** in “high-trust mode,” CST only via canonical header, provider key only via `X-Provider-API-Key`; ambiguous Authorization rejected.  
- **Deps:** none.

13) **CCO-US-021 — WPC registry API (signed policies)**
- **Owner:** clawcontrols  
- **Files:** `docs/prds/clawcontrols.md` (implementation), new schema `packages/schema/policy/work_policy_contract.v1.json`  
- **AC:** POST returns `policy_hash_b64u`; GET returns signed policy envelope; policy hashing uses JCS+SHA-256.  
- **Deps:** #4 (schema discipline).

14) **CWC-US-001 — Confidential Work Contract schema + signing**
- **Owner:** consulting/marketplace  
- **Files:** new `packages/schema/consulting/confidential_work_contract.v1.json`  
- **AC:** buyer signs, worker countersigns; contract pins `wpc_hash_b64u`, required tier, verification requirements.  
- **Deps:** #13 recommended.

15) **CEA-US-010 — clawea sandbox attestation MVP**
- **Owner:** clawea  
- **Files:** `docs/prds/clawea.md`, `packages/schema/poh/execution_attestation.v1.json`  
- **AC:** runs produce a signed execution attestation bound to `run_id` and `proof_bundle_hash_b64u`; verifier checks allowlisted attester DID.  
- **Deps:** #1–#3, #9.

16) **POH-US-018 — Subscription/web witnessed receipts (v2)**
- **Owner:** PoH + witness runner service  
- **Files:** new `packages/schema/poh/web_receipt.v1.json`, proof bundle schema extension, verifier support  
- **AC:** witness-signed `web_receipt` bound to run/event; tier only upgrades if witness signer allowlisted; never equals gateway by default.  
- **Deps:** #1, #4, #6.

(Parallel but important enabling work: streaming shim rewrite for external CLIs, per `packages/clawsig-adapters/src/shim.ts` buffering limitation described in `docs/roadmaps/proof-of-harness/oracle/2026-02-07/harness-enforcement.google-gemini-3-pro-preview.md`.)

---

## Docs / code changes checklist (files to update)

### Verification (clawverify)
- `services/clawverify/src/verify-proof-bundle.ts`
  - recompute event hashes (per `docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md` §4.2)
  - enforce signer DID == payload agent DID
  - remove attestation tier uplift unless signature-verified
  - add semantic binding checks + limits
- `services/clawverify/src/verify-receipt.ts`
  - `Number.isFinite` numeric checks
  - strict schema validation hook (Ajv)
- `docs/prds/clawverify.md` (update tier semantics + invariants)

### Receipts / proxy (clawproxy)
- `services/clawproxy/src/idempotency.ts` (durable idempotency backend)
- `services/clawproxy/src/index.ts` (strict CST/provider-key header rules, replay-safe nonce behavior)
- `services/clawproxy/src/receipt.ts` (optional: bind prompt hashes into receipt binding/metadata)
- `docs/prds/clawproxy.md` (document strict mode + binding extensions)

### Schemas
- Update (or version-bump) `packages/schema/poh/proof_bundle.v1.json` to include new envelope arrays (web/egress/attestation) or add `proof_bundle.v2.json`.
- Add:
  - `packages/schema/poh/web_receipt.v1.json`
  - `packages/schema/poh/egress_receipt.v1.json`
  - `packages/schema/poh/system_prompt_report.v1.json` (or `prompt_pack.v1.json`, `harness_pack.v1.json`)
  - `packages/schema/policy/work_policy_contract.v1.json`
  - `packages/schema/consulting/confidential_work_contract.v1.json`

### OpenClaw integration
- `packages/openclaw-provider-clawproxy/src/provider.ts` (add policy headers; optionally prompt hash headers)
- `packages/openclaw-provider-clawproxy/src/recorder.ts` (prompt commitments; ensure only canonical `_receipt_envelope` counts toward gateway tier)
- `docs/OPENCLAW_INTEGRATION.md` (Airlock pattern + policy-driven enforcement)

### External harness adapters
- `packages/clawsig-adapters/src/shim.ts` (rewrite to streaming passthrough; currently buffers request/response)
- `docs/roadmaps/proof-of-harness/HARNESS_REGISTRY.md` (update limitations once shim is streaming-safe)

### Marketplace spec alignment
- `docs/AGENT_ECONOMY_MVP_SPEC.md`
  - tier names/definitions
  - `min_proof_tier` mapping to evidence requirements
  - replay definition (“evidence re-validation,” not token replay)

---

## Unknowns (explicit) + what to measure/validate

1) **Subscription/web feasibility** (ChatGPT/Gemini/Claude web): confirm by traffic capture; do not design around provider-signed web receipts until proven. (Per `.../subscription-auth.gpt-5.2-pro.md`.)  
2) **Receipt completeness**: gateway receipts prove some calls, not all—measure `llm_call` events vs verified receipts (require 1:1 match for Tier 1 if you want stronger meaning).  
3) **URM availability**: enforce CAS upload/retention; measure URM/artifact fetch success rate and hash mismatch rate.  
4) **Prompt commitment stability**: validate that OpenClaw prompt-pack hashing is canonical and consistent across versions; measure mismatch rates after upgrades.

If you want, I can convert the above into a single “policy matrix” table: per job type (code bounty vs confidential consulting vs web-witnessed) → minimum evidence set → fail/upgrade rules, all mapped to the tier model and the concrete verifier invariants in `clawverify`.
