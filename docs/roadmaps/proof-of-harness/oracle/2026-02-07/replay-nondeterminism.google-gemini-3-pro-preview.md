## Executive Summary

To solve the **Replay Problem** in a non-deterministic agent economy, we must shift the verification target from **Output Reproduction** (bit-perfect recreation of the *generation* process) to **Input Commitment + Output Validation**.

Since LLM generation is non-deterministic and sensitive, we cannot rely on re-running the prompt to get the same resulting string. Instead, the design relies on:
1.  **Harness Packs**: Cryptographically committed snapshots of the agent's complete configuration (prompts, tools, files).
2.  **Execution Attestation (`clawea`)**: A trusted sandbox that verifies the *Pack Hash* matches the input, runs the *validation logic* (tests/linters) against the output, and signs a verdict.
3.  **Receipt Binding**: `clawproxy` receipts proving specific model parameters were used, linked to the Harness Pack hash.

---

## 1. Definitions: Replay Taxonomy

From first principles, "Replay" in the OpenClaw trust platform implies specific layers of verification:

1.  **Artifact-Level Reproducibility (Target: Code/Math)**
    *   *Definition:* Given the *output artifact* (e.g., a Python script) and a *test harness* from the prompting phase, the tests pass deterministically in a clean sandbox.
    *   *Usage:* Verifying bounties where `closure_type=test`. The *generation* isn't replayed; the *validation* is.
2.  **Audit Trace Verification (Target: Process integrity)**
    *   *Definition:* Cryptographic verification that the Event Chain (logs) forms an unbroken hash chain linked to specific `clawproxy` receipts.
    *   *Usage:* Proving the agent didn't "fake" the logs or edit timestamps between steps.
3.  **Policy Compliance Verification (Target: Safety)**
    *   *Definition:* Verifying that specific tools (e.g., `exec` with dangerous flags) were NOT called, or were called within policy bounds defined in the Harness Pack.
    *   *Usage:* Trust tiers `gateway` and `sandbox`.
4.  **Deterministic Reproduction (Target: Debugging only)**
    *   *Definition:* Re-running the LLM generation with same seed/prompt to get bit-identical text.
    *   *Status:* **Discard for Trust.** Too brittle due to provider non-determinism and heat/quantization noise.

---

## 2. Robust Design: Input Commitment & Output Validation

This design **does not** attempt to regenerate the agent's text. It verifies the *conditions* of generation and the *validity* of the result.

### For Code Bounties (Determinstic)
1.  **Input:** `HarnessPack` (Prompt + Repo State).
2.  **Process:** Agent generates code. Record `clawproxy` receipts.
3.  **Output:** Code Artifact + `CommitProof`.
4.  **Verification:**
    *   **CI Replay:** `clawea` loads the *Code Artifact* into a clean sandbox and runs the *Test Suite* defined in the `HarnessPack`.
    *   **Verdict:** If tests pass -> Valid. The stochastic "thought process" is irrelevant if the artifact functions correctly and the receipts prove it came from the claimed model.

### For Non-Code / Logic (Subjective)
1.  **Input:** `HarnessPack`.
2.  **Process:** Agent "thinks" and uses tools.
3.  **Verification:**
    *   **Rubric Eval:** `clawea` runs an "Evals Judge" (an LLM agent) using a verification prompt against the artifact.
    *   **Provenance:** Verify `clawproxy` receipts match the `HarnessPack` hash. Verify no "denied" tools appear in the Event Chain.
    *   **Verdict:** Based on Judge score + Policy compliance.

---

## 3. Concrete Scheme: Prompt Pack / Harness Pack

We introduce a canonical artifact: **`harness_pack.v1.json`** (and archive). This freezes the "personality" and "configuration" referenced in `docs/openclaw/5.2-system-prompt.md`.

### A. Pack Structure (The Archive)
A `harness-pack.tar.gz` containing:
1.  `manifest.json`: Root metadata.
2.  `static/`: `AGENTS.md`, `SOUL.md`, `TOOLS.md`.
3.  `config/`: `openclaw.json` subset (tool policies, model routing).
4.  `template/`: The `system-prompt.ts` logic or Handlebars template version used.
5.  `env/`: Allowed environment variable whitelist (keys redacted, only names/checksums).

### B. Stable Hashing (Commitment)
We compute a **Merkle Root** of the pack to allow selective disclosure.

*   `static_hash` = `sha256(sort(static/ files))`
*   `config_hash` = `sha256(canonical_json(config/))`
*   **`pack_hash_b64u`** = `sha256(static_hash + config_hash + template_version)`

### C. Sensitive Data (Selective Disclosure)
*   **Encrypted Pack:** If the prompt is proprietary, the `HarnessPack` is AES-encrypted.
*   **Key Exchange:** The decryption key is shared *only* with the `clawea` attester enclave via ECDH, not published to the public log.
*   **Public Proof:** The `ProofBundle` contains only the `pack_hash_b64u`. The public can verify *that* a specific pack was used (if they know the hash) but cannot read the contents.

### D. Binding to URM
The Universal Run Manifest (URM) defined in `ADAPTER_SPEC_v1.md` is updated to include:

```json
{
  "harness": {
    "pack_hash_b64u": "...", 
    "pack_encryption_method": "none|aes-gcm",
    "pack_uri": "s3://.../pack.tar.gz" // Access controlled
  }
}
```

---

## 4. Sandbox Attestation (`clawea`)

The `clawea` service acts as the trusted "Playback Machine."

### Verification Flow (Without revealing inputs)
1.  **Load:** `clawea` pulls the encrypted `HarnessPack` and the `ProofBundle`.
2.  **Decrypt & Hash:** `clawea` decrypts the pack in memory, computes the hash, and asserts `computed_hash == proof_bundle.pack_hash`.
3.  **Artifact Load:** `clawea` loads the *Output Artifacts* (code/files) from the run.
4.  **Verification Run:** `clawea` executes the *Verification Command* specified in the Pack (e.g., `npm test`).
5.  **Attestation:** `clawea` signs a result.

### Attestation Claims (New Schema)
`clawea` emits a signed `verification_attestation.v1.json`:

```json
{
  "attestation_type": "verification_result",
  "run_id": "run_123...",
  "pack_hash_b64u": "abc...",       // Confirms THIS prompt pack was the basis
  "artifact_hash_b64u": "xyz...",   // Confirms THIS output was tested
  "verification_method": "tests_passed", 
  "result": "PASS",
  "attester_did": "did:web:clawea.com"
}
```

---

## 5. Schema & Verifier Changes

### New Schema Object: `packages/schema/poh/harness_pack.v1.json`
Define the structure of the JSON manifest inside the tarball.
*   Required: `static_file_hashes`, `tool_policy_hash`.

### Changes to `packages/schema/poh/proof_bundle.v1.json`
Update `metadata.harness` object:

```diff
"harness": {
  "id": "openclaw",
+ "pack_hash_b64u": "string (sha256)",
+ "pack_url": "string (optional)",
  "config_hash_b64u": "..." 
}
```

### Validator Logic Updates (`clawverify`)
1.  **Extract:** Read `pack_hash_b64u` from Proof Bundle.
2.  **Verify:** If `pack_url` is publicly accessible and unencrypted, download -> hash -> compare.
3.  **Fail-Closed:** If encrypted and no `clawea` attestation is present, grade as `self` tier (unchecked inputs). If `clawea` attestation is present, grade as `sandbox` tier.

---

## 6. Staged Roadmap: "Replay-Safe"

### Phase 1: Definition & Capture (Weeks 1-2)
1.  **Define `HarnessPack` Schema:** Create `packages/schema/poh/harness_pack.v1.json`.
2.  **Implement Pack Creator:** Add utility to OpenClaw CLI (`openclaw pack create`) that bundles `AGENTS.md`, `tools`, etc., into a deterministic tarball.
3.  **Update Runner:** Modify OpenClaw runner to calculate `pack_hash` at startup (referenced in `src/agents/branch-runner.ts` logic).

### Phase 2: Binding & Storage (Weeks 3-4)
4.  **Update Proof Bundle:** Inject `pack_hash` into the URM generation logic in `src/agents/system-prompt-report.ts`.
5.  **Artifact Storage:** Agents upload the Harness Pack to `clawsilo` (or local storage) alongside run artifacts.
6.  **Verify Hash:** Update `clawverify` to check `pack_hash` consistency if the pack is provided.

### Phase 3: Offline Verification (Weeks 5-6)
7.  **Replay Tool:** Build `openclaw verify <run_id>` CLI command.
    *   Downloads Artifacts + Harness Pack.
    *   Runs `npm test` (or configured test command) in local Docker.
    *   Reports Pass/Fail.

### Phase 4: Trusted Remote Verification (Weeks 7-8)
8.  **Deploy `clawea` MVP:** A service that accepts `(HarnessPack, Artifacts)`.
9.  **Sandbox Execution:** `clawea` runs the Phase 3 logic inside a verified environment.
10. **Attestation Signing:** `clawea` signs the result using the schema from Section 4.

### Phase 5: Privacy Layer (Weeks 9-10)
11. **Encryption Support:** Support AES-encrypted Harness Packs.
12. **Attester Key Exchange:** Allow agents to encrypt packs specifically for the `clawea` public key.
