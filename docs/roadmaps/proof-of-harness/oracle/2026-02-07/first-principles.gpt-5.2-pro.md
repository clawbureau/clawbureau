## Executive summary (≈1 page)

**What PoH must prove in an agent-run world (2026):** not that “an output exists,” but that a specific **agent identity** executed a specific **run** under a declared **harness + policy**, used specific **models/tools** in a way that is **tamper-evident**, and produced **outputs** that are **cryptographically bound** to that run. This is fundamentally a **binding** problem across five domains:

1) **Identity** — who is accountable for the run (agent DID; key custody; delegation).  
2) **Execution integrity** — that the run log wasn’t edited/reordered and corresponds to a real execution (tamper-evident chain; optionally third-party execution attestation).  
3) **Model usage integrity** — that claimed LLM calls occurred via an accountable gateway with enforceable policy (signed gateway receipts bound to run + event).  
4) **Tool usage integrity** — that filesystem/network/process/tool actions that matter were captured and constrained (tool-call events; sandbox policies; optional sandbox attestation).  
5) **Output integrity** — that the submitted artifacts are exactly what the run produced (content hashes + binding to event chain + URM).

**Minimum viable PoH (fail-closed where possible):**  
- Always require an **agent-signed proof bundle envelope** plus at least one of {**URM reference**, **event chain**, **receipts**, **attestations**} (as per schema) — but for any marketplace automation you should require a **policy-chosen minimum set** (e.g., for “gateway tier”, require *both* event chain and receipt binding verification). See `packages/schema/poh/proof_bundle.v1.json`.  
- For “gateway-tier” trust, require: **(a) recomputed event hashes**, **(b) receipt signature allowlist**, **(c) receipt binding to run_id + event_hash**, **(d) nonce/idempotency that is not local-only**.

**Current architecture strengths:**  
- Good core objects: **URM + event chain + signed gateway receipt envelopes + allowlists + binding enforcement** are the right primitives (`docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md`).  
- `clawproxy` already emits canonical `_receipt_envelope` objects via `generateReceiptEnvelope()` (`services/clawproxy/src/receipt.ts`) with binding fields from headers (`services/clawproxy/src/idempotency.ts`).  
- `clawverify` is already fail-closed on unknown envelope versions/types/algos and has receipt signer allowlisting (`services/clawverify/src/verify-receipt.ts`), and it enforces receipt↔event-chain binding membership (`services/clawverify/src/verify-proof-bundle.ts`).

**Key robustness gaps (highest impact fixes):**
1) **Event hash recomputation is missing in verification**, so an attacker can fabricate `event_hash_b64u` values and still satisfy “membership” checks. This is explicitly noted as a gap in `docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md` and is true in `services/clawverify/src/verify-proof-bundle.ts` (it validates linkage but does not recompute hashes from canonical headers).  
2) **Idempotency nonce cache is in-memory** (`services/clawproxy/src/idempotency.ts`), so cross-instance replay/duplication is possible in production.  
3) **Trust-tier semantics mismatch:** the spec targets `self | gateway | sandbox` (`docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md`), while `clawverify` computes `basic | verified | attested | full` (`services/clawverify/src/verify-proof-bundle.ts`). This will create policy confusion and accidental over-trust.  
4) **URM is only a reference in the proof bundle** (`packages/schema/poh/proof_bundle.v1.json`), so output verification depends on availability and authenticity of the URM document and referenced artifacts (`packages/schema/poh/urm.v1.json`). You need a clear fetch/availability + content-address enforcement plan.

**Roadmap direction:**  
- First harden **verification correctness** (event hash recomputation, tier gating), then harden **receipt issuance** (durable idempotency, key rotation, anti-replay), then expand toward **sandbox/TEE attestations** (`packages/schema/poh/execution_attestation.v1.json`) and tool-policy enforcement.

---

## 1) From first principles: what PoH should prove (2026)

Below are the *claims* PoH should let a verifier assert, separated by domain. The goal is not “absolute truth,” but **bounded, automatable accountability** under adversarial workers.

### A. Identity (accountability)
**Claim:** “This run is attributable to Agent X (DID), who is responsible for the artifacts and declarations.”

**What must be provable:**
- The proof bundle was signed by the agent DID key (non-repudiation).
- Optionally: the agent key was authorized for this job (delegation, workforce org, stake identity).

**What PoH does *not* prove by default:** that the key wasn’t stolen, that the human is who they claim, or that the harness binary wasn’t modified (non-goal noted in `docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md`).

### B. Execution integrity (run log integrity)
**Claim:** “The run log is append-only and wasn’t edited/reordered after the fact; it represents a single coherent run.”

**What must be provable:**
- Events are hash-linked (tamper-evident chain).
- `run_id` is consistent across the chain.
- **Critically:** `event_hash_b64u` values are **recomputed** from canonical headers (spec §4.2 in `docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md`) and must match.

**What it still doesn’t prove without third-party attestation:** that the logged events are complete (an agent can omit events) or that the run happened in a constrained environment.

### C. Model usage integrity (LLM call integrity)
**Claim:** “These LLM calls happened via an allowlisted gateway that enforced declared policy, and the calls are bound to this run.”

**What must be provable:**
- Each counted receipt is signed by an allowlisted gateway key (`services/clawverify/src/verify-receipt.ts`).
- Receipts contain binding fields tying them to `run_id` and the triggering `event_hash_b64u` (`packages/schema/poh/receipt_binding.v1.json`).
- Receipts cannot be replayed across runs because binding is checked against the run’s event chain (`services/clawverify/src/verify-proof-bundle.ts`).
- Optionally: policy enforcement occurred (receipt includes `policy_hash`, `token_scope_hash_b64u`).

**What it doesn’t prove:** that the harness didn’t also call models directly outside the gateway. That’s a separate “completeness” problem (mitigate via sandboxing/egress controls/attestation).

### D. Tool usage integrity (environment/tool action integrity)
**Claim:** “The agent’s non-LLM actions that matter (file writes, commands, network calls, tool invocations) were recorded and/or constrained.”

**What must be provable (in tiers):**
- At minimum: tool-call events exist and are hash-chained.
- Stronger: the harness ran under a sandbox policy with auditable configuration hash (`harness.config_hash_b64u` in `packages/schema/poh/urm.v1.json` and proof bundle metadata in `packages/schema/poh/proof_bundle.v1.json`).
- Strongest: third-party **execution attestation** that the sandbox/TEE enforced egress + filesystem constraints (`packages/schema/poh/execution_attestation.v1.json`).

### E. Output integrity (artifact binding)
**Claim:** “The submitted artifacts correspond exactly to what the run produced.”

**What must be provable:**
- Outputs are content-addressed (hashes) in the URM (`packages/schema/poh/urm.v1.json`).
- The URM is bound to the proof bundle (either by including URM hash in bundle, or by bundling URM, or by a retrieval+hash check against `URMReference.resource_hash_b64u` in `packages/schema/poh/proof_bundle.v1.json`).
- Optional: `artifact_written` events include payload hashes that correspond to the actual artifact hashes (cross-binding event chain ↔ URM ↔ artifacts).

---

## 2) Minimum evidence objects (required vs optional)

These are the *evidence objects* a verifier consumes. “Optional” means optional at the schema layer, but you should treat many as **policy-required** for automation.

### Core evidence objects

1) **Proof Bundle Envelope (agent-signed)** — *required for PoH as a system primitive*  
- Object: `SignedEnvelope<ProofBundlePayload>`  
- Schema: `packages/schema/poh/proof_bundle.v1.json`  
- Verification: signature over `payload_hash_b64u` (already in `services/clawverify/src/verify-proof-bundle.ts`).

2) **Event chain** — *policy-required for any binding-based guarantees*  
- Object: `event_chain: EventChainEntry[]` inside the proof bundle payload  
- Schema: in bundle (`packages/schema/poh/proof_bundle.v1.json`) and standalone (`packages/schema/poh/event_chain.v1.json`)  
- Verification must include:
  - linkage (`prev_hash_b64u`) **and**
  - recomputation of each `event_hash_b64u` from canonical header (spec §4.2, `docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md`).

3) **Gateway receipt envelopes** — *policy-required for “gateway-tier” model usage integrity*  
- Object: `SignedEnvelope<GatewayReceiptPayload>[]`  
- Schema: embedded in `packages/schema/poh/proof_bundle.v1.json`  
- Issuance: `_receipt_envelope` emitted by `clawproxy` (`services/clawproxy/src/receipt.ts`)  
- Verification: `services/clawverify/src/verify-receipt.ts` + binding enforcement in `services/clawverify/src/verify-proof-bundle.ts`.

4) **URM document and/or URM reference** — *policy-required for output integrity*  
- Object: URM document (`packages/schema/poh/urm.v1.json`) + reference in bundle (`URMReference` in `packages/schema/poh/proof_bundle.v1.json`)  
- Minimum for integrity: verifier must be able to fetch the URM bytes and verify `resource_hash_b64u`.

### Optional / tier-elevating evidence objects

5) **Execution attestation (sandbox / TEE)** — *optional now; required for “sandbox tier” later*  
- Schema: `packages/schema/poh/execution_attestation.v1.json`  
- Verification: allowlisted attester DID(s), expiry, binding to `run_id` and/or `proof_bundle_hash_b64u`.

6) **Tool-call payloads / logs** (beyond hashes) — optional but valuable for audits  
- You can keep payloads external and only hash them in the chain; disclose selectively.

7) **Policy / token artifacts** (WPC, CST claims) — optional but important for enterprise/compliance  
- You currently bind `policy_hash` and `token_scope_hash_b64u` into receipts (`services/clawproxy/src/index.ts`, `services/clawproxy/src/receipt.ts`).

### Recommended “minimum sets” by tier (policy-level)

- **Self tier:** proof bundle signature + URM (retrievable) + event chain (recomputed).  
- **Gateway tier:** self tier + ≥1 receipt envelope that is signature-valid **and** bound to event chain + run_id.  
- **Sandbox tier:** gateway tier + execution attestation that binds to run/bundle and asserts isolation properties.

(These tiers are defined in `docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md`; note the mismatch with current `clawverify` tier labels.)

---

## 3) Threat model: top attack vectors & mitigations (by evidence type)

Assume malicious workers with full control of their local machine and harness, and incentive to (a) fake work, (b) replay others’ work, (c) hide policy violations, (d) exfiltrate secrets, (e) claim higher trust tier than warranted.

### A. Identity evidence (agent DID signature)

**Attacks**
- **Key theft / key sharing:** attacker submits bundles signed by someone else’s DID.  
- **Delegation confusion:** a legitimate agent key is used by an unapproved sub-agent or stolen CI environment.  
- **Sybil flooding:** many DIDs created to farm reputation.

**Mitigations**
- Support **key rotation + revocation** policy (marketplace-level), and track DID reputation separately from PoH.  
- Add **job-scoped delegation**: a marketplace-issued capability token binding agent DID ↔ job ID ↔ expiry.  
- Require stronger custody for high-stakes tiers (hardware-backed keys, or at least encrypted keystore + 2FA).  
- **Measure:** rate of DID churn, bundles per DID, anomaly detection on signer activity.

**Unknowns**
- How you’ll manage DID lifecycle (revocation, rotation, recovery) without centralizing too much power.

---

### B. Event chain evidence (execution log integrity)

**Attacks**
- **Fabricated chains:** generate an event chain after the fact with plausible events.  
- **Omitted events:** do real work but omit disallowed tool/network actions.  
- **Event hash forgery exploiting verifier weakness:** if verifier doesn’t recompute `event_hash_b64u`, attacker can set arbitrary hashes and still pass linkage/binding membership. (This is a current gap; see below.)  
- **Timestamp lies:** backdate/forward-date events to satisfy SLAs or hide timeouts.

**Mitigations**
- Verifier must **recompute every `event_hash_b64u`** from canonical headers (spec §4.2 in `docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md`). Fail closed if mismatch.  
- Consider adding an **event chain root commitment** into the URM (`event_chain_root_hash_b64u` already exists in `packages/schema/poh/urm.v1.json`) and enforce consistency.  
- Add a monotonic-time policy: timestamps must be non-decreasing; optionally bound to receipt timestamps.  
- For stronger integrity/completeness: require **sandbox execution attestation** (third-party) for higher tier.

**Unknowns**
- Completeness is not solvable with pure client-side logs; you need attested enforcement or network egress constraints.

---

### C. Gateway receipt evidence (model usage integrity)

**Attacks**
- **Receipt replay across runs:** reuse a valid receipt from another run to claim gateway tier.  
- **Receipt farming:** call the gateway with benign prompts to collect receipts, then do actual work off-gateway.  
- **Nonce/idempotency abuse:** exploit weak idempotency to duplicate or confuse receipt issuance.  
- **Allowlist confusion / key rotation failure:** accept receipts from an attacker-controlled DID if allowlist is misconfigured.  
- **Direct-to-provider bypass:** do policy-violating calls outside clawproxy and only route a subset through clawproxy.

**Mitigations**
- Keep current binding requirement: receipt must include `binding.run_id` and `binding.event_hash_b64u` and verifier must check membership (already implemented in `services/clawverify/src/verify-proof-bundle.ts`).  
- **But binding is only meaningful if event hashes are recomputed** (fix required).  
- Replace in-memory nonce cache with **Durable Objects / KV** (or equivalent) in production (`services/clawproxy/src/idempotency.ts`).  
- Enforce **receipt signer allowlist** (already fail-closed in `services/clawverify/src/verify-receipt.ts`). Add operational controls for key rotation.  
- To mitigate bypass: for higher tiers require sandbox/egress controls, or require that the harness runs in an environment where outbound LLM endpoints are blocked except clawproxy.

**Unknowns**
- How to quantify “receipt coverage” (what fraction of LLM calls were through gateway) without attested egress controls.

---

### D. URM + artifact evidence (output integrity)

**Attacks**
- **Artifact substitution:** claim output hashes in URM but submit different bytes.  
- **URM unavailability:** verifier can’t fetch URM bytes, so output integrity can’t be checked.  
- **URM equivocation:** present different URM contents at the same URM ID if storage isn’t content-addressed.  
- **Path spoofing:** claim you modified certain files but submit a patch affecting others (or hidden files).

**Mitigations**
- Treat URM and outputs as **content-addressed blobs**. Verifier must fetch bytes and hash them to match `resource_hash_b64u` (`packages/schema/poh/proof_bundle.v1.json`) and `outputs[].hash_b64u` (`packages/schema/poh/urm.v1.json`). Fail closed if missing.  
- Require a marketplace-side upload flow where the artifact bytes are stored under their hash (CAS), eliminating equivocation.  
- Cross-bind URM ↔ event chain: require `artifact_written` events whose payload hash commits to (type, path, content hash).  
- **Measure:** percent of bundles where URM/artifacts are retrievable; hash mismatch rates.

**Unknowns**
- Your storage trust model: who hosts URM/artifacts, retention windows, and how verifiers fetch them deterministically.

---

### E. Tool usage evidence (tool-call integrity)

**Attacks**
- **Out-of-band execution:** run commands outside the harness tool wrapper; omit events.  
- **Log forgery:** claim tool calls occurred but they didn’t; or hide network calls.  
- **Policy evasion:** tools allowed by harness config hash, but harness binary modified to ignore policies.  
- **Prompt injection to tools** isn’t a PoH forgery per se, but it causes unsafe actions while logs look “legit.”

**Mitigations**
- For meaningful tool integrity you need one of:
  1) **Sandbox/attested runtime** (best), or  
  2) OS-level enforcement (container with seccomp/AppArmor + audited wrapper), or  
  3) Very limited claims (self-tier only; don’t automate trust).
- Include **harness config hash** and make it meaningful (tool policy, routing, sandbox mode), as already suggested in `docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md` and present in schemas.  
- For high stakes: require **execution attestation** (`packages/schema/poh/execution_attestation.v1.json`) that asserts egress and filesystem constraints.

**Unknowns**
- Which tool actions are “in-scope” across harnesses; standardization pressure will rise as agent ecosystems diversify.

---

## 4) Evaluation of current architecture + gaps (and best improvements)

### What you have that’s directionally correct

1) **Canonical receipt envelopes** emitted by clawproxy  
- `clawproxy` generates `_receipt_envelope` as `SignedEnvelope<GatewayReceiptPayload>` in `services/clawproxy/src/receipt.ts` (`generateReceiptEnvelope()`), with `signer_did` set to a `did:key:...` (`signingContext.didKey`).  
- This matches what `clawverify` verifies in `services/clawverify/src/verify-receipt.ts`.

2) **Receipt↔event-chain binding enforcement** exists  
- `clawverify` checks that `binding.run_id` matches the chain run_id and that `binding.event_hash_b64u` is present in the bundle event chain (`services/clawverify/src/verify-proof-bundle.ts`).

3) **Fail-closed allowlisting for receipt signers** exists  
- If `allowlistedSignerDids` is missing/empty, receipts are invalid (`services/clawverify/src/verify-receipt.ts`).

4) **Adapters and SDKs inject binding headers**  
- SDK: `packages/clawproof-sdk/src/run.ts` (`X-Run-Id`, `X-Event-Hash`, `X-Idempotency-Key`)  
- External harness shim: `packages/clawproof-adapters/src/shim.ts` forwards via session and captures receipts  
- OpenClaw provider: `packages/openclaw-provider-clawproxy/src/provider.ts` injects headers.

### Critical gaps / weaknesses

#### Gap 1 — Event hash recomputation is missing in verification (high severity)
- The spec calls this out: “Current gap… does not recompute `event_hash_b64u`” (`docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md`).  
- The verifier currently only checks linkage (`prev_hash_b64u`) and base64url formatting in `validateEventChain()` (`services/clawverify/src/verify-proof-bundle.ts`), but **never recomputes `event_hash_b64u`** from `{event_id, run_id, event_type, timestamp, payload_hash_b64u, prev_hash_b64u}`.
- Consequence: an attacker can fabricate arbitrary `event_hash_b64u` values and still:
  - maintain linkage (by setting `prev_hash_b64u` to the previous arbitrary hash), and
  - satisfy receipt binding membership (receipt binds to attacker-chosen hashes).

**Best fix:** implement canonical recomputation (ideally RFC 8785 JCS as per spec) and fail closed on mismatch.

#### Gap 2 — Idempotency is not production-grade (medium/high severity)
- `clawproxy` nonce cache is in-memory (`services/clawproxy/src/idempotency.ts`), explicitly “demo/MVP”.  
- Consequence: multi-region / multi-instance deployments allow nonce reuse and receipt duplication or confusion.

**Best fix:** Durable Objects/KV-backed nonce registry keyed by (gateway signer key id + nonce) with TTL, and include more request fingerprinting (see roadmap).

#### Gap 3 — Trust tier semantics mismatch (policy risk)
- Spec defines `self | gateway | sandbox` (`docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md`).  
- Verifier outputs `basic | verified | attested | full` (`computeTrustTier()` in `services/clawverify/src/verify-proof-bundle.ts`).  
- Consequence: accidental over-trust when product/marketplace thinks “verified == gateway-tier” (it may not).

**Best fix:** align `clawverify` output tiers to the spec tiers (or output both: “components + policy-derived tier”).

#### Gap 4 — URM reference without retrieval/availability contract (automation blocker)
- Proof bundle contains only a URM reference (`packages/schema/poh/proof_bundle.v1.json`).  
- If URM/artifacts aren’t reliably retrievable and content-addressed, output integrity can’t be verified.

**Best fix:** define a canonical CAS fetch scheme (URI conventions, required inclusion rules, or bundle URM inline for smaller manifests).

#### Gap 5 — Receipt format transition ambiguity (operational risk)
- `clawproxy` still supports legacy `_receipt` and also emits `_receipt_envelope` (`services/clawproxy/src/index.ts`, `services/clawproxy/src/receipt.ts`).  
- SDK/adapters sometimes “bridge” legacy receipts into envelope shapes (`packages/clawproof-sdk/src/run.ts`, `packages/clawproof-adapters/src/session.ts`, `packages/openclaw-provider-clawproxy/src/recorder.ts`), but those bridged envelopes are **not cryptographically verifiable** (signature fields may be `unsigned` or signer DID mismatched).
- Consequence: confusion, and downstream systems might mistakenly treat presence of “receipts” as gateway proof unless they check `receipts_valid`.

**Best fix:** policy: gateway tier only counts `_receipt_envelope`-verified receipts; optionally stop bundling bridged legacy receipts or mark them explicitly as “unverified legacy”.

---

## 5) Roadmap: next 5–10 incremental stories (secure + adoptable)

Each story is incremental and keeps adoption feasible while pushing toward fail-closed automation.

### Story 1 — Verify event hashes (blocker fix)
**Change:** In `clawverify`, recompute `event_hash_b64u` for every event using canonical header rules (spec §4.2 in `docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md`).  
**Where:** `services/clawverify/src/verify-proof-bundle.ts` (`validateEventChain`).  
**Acceptance:** Any mismatch fails `event_chain_valid`; gateway receipts cannot count without valid event chain.

### Story 2 — Align trust tier outputs to spec tiers
**Change:** Replace/augment `basic|verified|attested|full` with `self|gateway|sandbox` (or output both).  
**Where:** `services/clawverify/src/verify-proof-bundle.ts` (`computeTrustTier`).  
**Acceptance:** Deterministic tier mapping:
- `self`: valid bundle signature + valid event chain + URM retrievable (policy-chosen).  
- `gateway`: `self` + at least N verified-and-bound receipts.  
- `sandbox`: `gateway` + verified execution attestation.

### Story 3 — Durable idempotency + anti-replay hardening
**Change:** Replace in-memory nonce cache (`services/clawproxy/src/idempotency.ts`) with Durable Objects / KV.  
**Add:** bind idempotency to additional fingerprints (provider + request_hash_b64u or payload hash) to prevent nonce reuse across distinct calls.  
**Acceptance:** Multi-instance safe; replay attempts observable; fail closed on duplicate-with-different-request.

### Story 4 — Make URM/artifact verification first-class
**Change:** Define and implement a URM/artifact retrieval contract:
- CAS store keyed by hash, or
- inline URM bytes in proof bundle for small manifests.  
**Where:** schema already exists (`packages/schema/poh/urm.v1.json`); implement verifier fetching and hash checking against `URMReference.resource_hash_b64u` (`packages/schema/poh/proof_bundle.v1.json`).  
**Acceptance:** Verifier can deterministically validate output hashes for automated review.

### Story 5 — Receipt policy enforcement: require canonical `_receipt_envelope` for gateway tier
**Change:** Stop treating bridged legacy receipts as “receipts present.” If `receipt_envelope` is missing, it must not contribute to gateway tier.  
**Where:** SDK/adapters: `packages/clawproof-sdk/src/run.ts`, `packages/clawproof-adapters/src/session.ts`, OpenClaw recorder `packages/openclaw-provider-clawproxy/src/recorder.ts`.  
**Acceptance:** Gateway tier requires signature-valid envelopes from allowlisted signers; legacy receipts may be stored only as debug artifacts.

### Story 6 — Key rotation + signer discovery that stays fail-closed
**Change:** Introduce a rotation mechanism:
- Maintain allowlisted signer DIDs with effective dates.
- Optionally publish a signed gateway keyset document.  
**Where:** `services/clawverify/src/verify-receipt.ts` allowlist handling.  
**Acceptance:** Rotation doesn’t break verification; unknown keys fail closed; operational tooling for updating allowlists.

### Story 7 — Tool-call standardization (minimal cross-harness schema)
**Change:** Define a minimal canonical set of tool event payload schemas (even if payloads remain external) so verifiers can reason about “write/exec/network” classes.  
**Where:** extend adapter spec (`docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md`) and adapters.  
**Acceptance:** Verifier can compute basic policy checks (e.g., “no network tool events”) without harness-specific parsing.

### Story 8 — Sandbox execution attestation MVP
**Change:** Implement an allowlisted attester that signs `ExecutionAttestation v1` (`packages/schema/poh/execution_attestation.v1.json`) binding to `run_id` and/or bundle hash.  
**Acceptance:** “sandbox tier” becomes real: attestation required + validated; includes egress policy claims.

### Story 9 — Coverage metrics + fraud analytics (measure unknowns)
**Change:** Add explicit metrics emission:
- receipt_count vs llm_call events,
- tool_call event rates,
- missing URM fetch rate,
- replay/duplicate nonce attempts,
- distribution of harness IDs (`docs/roadmaps/proof-of-harness/harnesses.mjs`).  
**Acceptance:** Dashboards that answer: “How often can workers bypass gateway/tool logging and still pass current checks?”

### Story 10 — Optional: privacy-preserving receipt/content disclosure
**Change:** Standardize how encrypted/hash-only receipts are handled end-to-end; ensure policy modes are verifiable (receipt already includes privacy mode in `services/clawproxy/src/receipt.ts`, and policy logic in `services/clawproxy/src/policy.ts`).  
**Acceptance:** Enterprise can require hash-only receipts; selective disclosure path exists without weakening integrity.

---

## Explicit unknowns to call out (and what to verify/measure)

1) **Completeness:** Without sandbox/egress controls, you cannot prove the agent didn’t do extra unlogged work.  
→ Measure: correlation between observed tool logs and outcomes; adoption of sandbox tier.

2) **URM/artifact availability:** If URMs aren’t reliably retrievable, output integrity becomes best-effort.  
→ Measure: URM fetch success rate; artifact hash mismatch rate.

3) **Receipt coverage:** Receipts prove some calls happened, not that *all* calls happened via gateway.  
→ Measure: `llm_call` events vs verified receipts; require 1:1 matching for gateway tier.

4) **Key custody and delegation:** DID signatures are only as strong as key management.  
→ Measure: anomaly detection, device binding, rotation cadence, compromise events.

---

If you want, I can translate this into a concrete **policy matrix** (per job type: minimum evidence requirements + fail-closed rules) and a set of **verifier invariants** (must-hold properties) that you can turn into tests.
