## 1) Decisions (2–3 directions worth doing vs not doing)

### Do #1 — **Port/centralize redaction at the PoH recorder/session layer (pre-hash)**
**Why it’s worth it**
- Prevents “toxic proofs”: if secrets/PII enter the immutable event payload (even if only as hashed JSON), you’ve still created a durable linkage risk and accidental disclosure risk when payloads are ever materialized/debugged.
- Enforces the constraint “Prefer harness-level enforcement/instrumentation over wrappers”.
- Directly leverages mature patterns in `agentlog/redact.py` (File 3) and its ordering/idempotence assumptions.

**Where it lands**
- In the shared adapter runtime (`packages/clawsig-adapters/src/session.ts`, File 10) and/or OpenClaw recorder (`packages/openclaw-provider-clawproxy/src/recorder.ts`, File 11), so *all* harnesses benefit.

**Fail-closed / non-gameable**
- This does **not** uplift tier; it only reduces risk. Safe-by-default.

---

### Do #2 — **Add a “verified vs unverified” local verifier workflow for OpenClaw users (agentlog-side)**
**Why it’s worth it**
- Users need a crisp answer: “Is this session actually gateway-tier verifiable or just local logs?”
- `agentlog` already normalizes OpenClaw/Pi/Claude/Codex logs into `AgentEvent` (`agentlog/parsers/*`, Files 4–8). The missing piece is a *PoH-aware* verifier command that:
  - verifies proof bundle + URM hashes (materialization rules)
  - verifies gateway receipt envelopes (allowlisted signer DID)
  - verifies receipt binding to `(run_id, event_hash)` (per PoH spec)
- This creates real “trust platform value” without shipping transcripts: it yields a **local badge** and **redacted derived artifacts only**.

**Where it lands**
- New `agentlog verify` command that looks for PoH artifacts produced by OpenClaw runs (proof bundle envelope + URM), then uses existing Claw verification logic (either by importing a verification library or shelling to `clawverify` if available).

**Fail-closed / non-gameable**
- If artifacts are missing, invalid, or unverifiable: status is **UNVERIFIED** (no partial credit).

---

### Do #3 — **Emit “Trust Pulse” derived artifacts (redacted + bounded) and attach them to URM metadata for UX—explicitly non-tier-affecting**
**Why it’s worth it**
- Marketplace/buyers benefit from “what happened” (files touched, tools used, decision bullets) without decrypting or reading raw chains.
- `agentlog` already has the extraction concept (“Pulse signals”: decisions/files/tools) in the repo analysis (File 1) and it enforces “redact before indexing” (File 3 + comment).
- URM explicitly supports freeform `metadata` (schema `packages/schema/poh/urm.v1.json`, File 12). We can carry a minimal summary there.

**Hard rule**
- **Semantic summaries MUST NOT uplift proof tier** (your constraint). So:
  - treat as **self-reported metadata**
  - verifier ignores it for tier derivation
  - size-limited, schema-tagged, and redacted

---

### Don’t do — **Retroactive PoH bundle generation from raw JSONL logs (high gameability)**
(Repo analysis proposal #5; File 1)
- Raw local logs are mutable (“Self-Reported” in File 1). Generating “Self-tier bundles” from them invites fake history and “trust-washing”.
- Even if labeled `self_retroactive`, it will be misunderstood and misused.
- If you ever do it, it should live as a clearly separate “archive format” not a PoH bundle, and must never feed tiering.

### Don’t do (for tier) — **Git commit linkage as a trust uplift mechanism**
(Repo analysis proposal #4; File 1)
- Helpful as *additional context*, but it’s still gameable (rewriting commit times, forged authorship, unsigned commits).
- OK as a **non-uplift UI hint** later; not worth spending vNext budget on until you require signed commits + trusted timestamping.

---

## 2) Proposed roadmap items (add to `docs/roadmaps/trust-vnext/prd.json`)

Below are stories to append to `userStories` in File 15 (`docs/roadmaps/trust-vnext/prd.json`). IDs chosen to fit existing naming.

---

### **POH-US-020 — Pre-hash redaction middleware in adapter session/recorder**
**Title:** Pre-hash redaction for PoH event payloads + URM metadata (adapter-runtime enforced)  
**Description:** As a platform, we must redact secrets/PII before any payload is hashed into the event chain or stored in URM metadata, to prevent toxic proofs and accidental disclosure.  
**Acceptance Criteria:**
- Implement a redaction utility in `packages/clawsig-adapters` that ports patterns/order from `agentlog/redact.py` (File 3).
- `recordEvent()` in `packages/clawsig-adapters/src/session.ts` (File 10) redacts the payload **before** `hashJsonB64u()` is computed.
- `finalize()` redacts `FinalizeOptions.urmMetadata` before embedding into URM (File 10, URM creation).
- Redaction is:
  - deterministic
  - bounded (max output length)
  - idempotent-ish (running twice doesn’t expand content)
- Add unit tests:
  - known token patterns (JWT, Bearer, sk-*, ghp_*, etc.) are redacted
  - payload hash changes when secrets present (i.e., secrets don’t survive)
  - ensure tool payloads with normal text are not over-redacted
- Backwards compatibility:
  - feature-gated initially with `redactionMode: 'off'|'on'` default `'on'` for new harness versions; document that hashes differ vs old bundles.

**Priority:** 1  
**Passes:** false (new)

---

### **OCL-US-004 — OpenClaw emits Trust Pulse artifact + URM pointer (non-tier)**
**Title:** OpenClaw “Trust Pulse” derived artifact (redacted) + URM metadata attachment  
**Description:** As an OpenClaw user/buyer, I want a small, redacted, derived summary of run actions (tools, files touched, counts) visible in the marketplace without exposing transcripts.  
**Acceptance Criteria:**
- OpenClaw integration emits a `trust_pulse.v1.json` artifact containing only:
  - tool names used + counts
  - relative file paths touched (allowlist patterns, no absolute home paths)
  - timestamps/durations at coarse granularity (optional)
  - optional decision bullets **only if they can be produced without including raw text**
- Artifact must be redacted using the same logic as POH-US-020 (ported from `agentlog/redact.py`, File 3).
- URM `metadata.trust_pulse` includes:
  - `artifact_hash_b64u`
  - `schema: 'trust_pulse.v1'`
  - `evidence_class: 'self_reported'`
  - `tier_uplift: false`
- Verifier (`clawverify`) and marketplace tiering must ignore this field for trust tier computation (explicit test).
- Size limits: hard cap (e.g., 32KB) for the pulse JSON and URM metadata pointer.
- No raw transcript content is included anywhere in pulse.

**Priority:** 2  
**Passes:** false (new)

---

### **AGL-US-001 — agentlog verify: local PoH status + fail-closed badge**
**Title:** `agentlog verify` for OpenClaw sessions (PoH/receipt verification + status)  
**Description:** As an OpenClaw user, I want a local command that tells me if a session is verifiably gateway-tier (or not), without uploading transcripts.  
**Acceptance Criteria:**
- Add `agentlog verify <session_or_run_dir>` command.
- It detects OpenClaw session logs and PoH artifacts (proof bundle envelope + URM) adjacent to the session (define/search standard locations).
- Verification is fail-closed:
  - If URM referenced but missing → UNVERIFIED (align with PoH URM materialization rules in `ADAPTER_SPEC_v1.md` §6.2; File 14 and CVF story POH-US-015 in File 15).
  - If receipt envelopes present but signer DID not allowlisted → UNVERIFIED.
  - If receipt binding doesn’t match event chain (`binding.run_id` + `binding.event_hash_b64u`) → UNVERIFIED.
- Output is **derived only**: prints status + counts; never prints raw message content.
- Add tests with fixtures:
  - valid bundle+urm+receipt → VERIFIED_GATEWAY
  - tampered event chain → UNVERIFIED
  - missing URM → UNVERIFIED
  - receipt signer not allowlisted → UNVERIFIED

**Priority:** 3  
**Passes:** false (new)

---

## 3) Implementation plan (2–3 phases, PR-sized steps)

### Phase 1 (Safety foundation): **Pre-hash redaction + strict bounded metadata**
Goal: ensure PoH artifacts are safe to share/store; no secrets land in hashed payloads or URM metadata.

#### PR 1.1 — Port `agentlog` redaction into TS and wire into adapter session
**Scope**
- Add `packages/clawsig-adapters/src/redact.ts` (new) implementing the rules/order from `agentlog/redact.py` (File 3).
- Update `packages/clawsig-adapters/src/session.ts` (File 10):
  - In `recordEvent()`: redact `input.payload` before hashing.
  - In `finalize()`: redact `options.urmMetadata` before embedding into URM.

**Files likely touched**
- `packages/clawsig-adapters/src/redact.ts` (new)
- `packages/clawsig-adapters/src/session.ts` (File 10)
- (Maybe) `packages/clawsig-adapters/src/types.ts` to add an optional config flag like `redactionMode`.

**Tests needed**
- Unit tests for `redact.ts` mirroring patterns from File 3:
  - JWT, Bearer, `sk-ant-`, `sk-`, `ghp_`, `github_pat_`, `AIza...`, private key blocks, email, URL token params, KV secrets.
- Tests for `session.recordEvent()`:
  - same input payload with secret → stored hash corresponds to redacted payload, not original.
- Tests for `finalize()`:
  - URM `metadata` is redacted and size-bounded.

**Backwards compatibility**
- Hashes will change vs old bundles when payloads contained secrets. That’s intended.
- To reduce surprise:
  - add `redactionMode` default `'on'` for harness version bump
  - document in release notes that old proofs remain verifiable; new proofs safer.

---

#### PR 1.2 — Apply same redaction to OpenClaw recorder (if it bypasses adapters)
OpenClaw has its own recorder implementation in `packages/openclaw-provider-clawproxy/src/recorder.ts` (File 11) that parallels `session.ts`.

**Scope**
- Mirror the same redaction behavior in `createRecorder().recordEvent()` and in URM metadata embedding inside `finalize()`.

**Files likely touched**
- `packages/openclaw-provider-clawproxy/src/recorder.ts` (File 11)
- Possibly shared utility extraction if you want one canonical implementation.

**Tests needed**
- Same as PR 1.1 but in the OpenClaw recorder test suite (whatever runner exists).
- Regression: ensure proof bundle still schema-valid (Ajv strict; see CVF-US-024 in File 15).

**Backwards compatibility**
- Same hashing change considerations.

---

### Phase 2 (User-visible trust value): **Trust Pulse artifact + URM pointer**
Goal: give marketplace/users high-signal “what happened” without transcripts; ensure it cannot uplift tier.

#### PR 2.1 — Define a minimal `trust_pulse.v1` schema (optional but recommended)
**Scope**
- Add schema file for pulse artifact (kept small, no freeform transcript fields).
- Register schema in verifier registry if you have one; but do **not** require it for bundle validity (optional artifact).

**Files likely touched**
- `packages/schema/...` (new schema file, e.g. `packages/schema/trust/trust_pulse.v1.json`)
- Verifier schema registry (where CVF-US-024 added Ajv validators; referenced in File 15 notes)

**Tests needed**
- Ajv validation unit tests:
  - reject unknown fields
  - enforce size/array bounds
  - ensure paths are relative-only (pattern)

**Backwards compatibility**
- Optional artifact; no impact on existing bundles.

#### PR 2.2 — Emit pulse artifact from OpenClaw run + attach pointer into URM metadata
**Scope**
- During OpenClaw finalize:
  - generate `trust_pulse.v1.json` (derived only)
  - hash it as an output `ResourceDescriptor`
  - add URM metadata pointer `metadata.trust_pulse = { schema, artifact_hash_b64u, ... }`
- Enforce:
  - no absolute paths
  - no raw tool outputs
  - redaction applied (Phase 1 utility)

**Files likely touched**
- OpenClaw integration layer that assembles `FinalizeOptions.outputs` and `urmMetadata`
  - likely around `packages/openclaw-provider-clawproxy/...` (File 11 shows recorder only; you’ll need the caller site that passes `FinalizeOptions`)

**Tests needed**
- Unit/integration:
  - pulse artifact contains only allowed fields
  - no tool result text included
  - URM metadata includes pointer and is under size cap

**Backwards compatibility**
- Optional; older consumers ignore URM metadata fields (URM allows `metadata` object; File 12).

---

### Phase 3 (Fail-closed verification UX): **agentlog verify**
Goal: local, derived-only verification status for OpenClaw sessions.

#### PR 3.1 — Implement `agentlog verify` command (derived-only output)
**Scope**
- Add a CLI subcommand that:
  - finds PoH artifacts produced by OpenClaw near the session directory
  - calls verification (preferred: import a verification library; fallback: spawn `clawverify` binary/service)
  - prints: tier, receipt count, run_id, signer DIDs (no transcript)

**Files likely touched (agentlog repo)**
- `agentlog/cli.py` (not provided, but referenced in analysis File 1)
- New module: `agentlog/verify.py` (new)
- Potential small additions to parsers only for locating session/run directories (OpenClaw sessions already parsed by `agentlog/parsers/openclaw.py`, File 8)

**Tests needed**
- Fixture-based tests:
  - valid proof bundle envelope + URM + receipt envelope → VERIFIED_GATEWAY
  - missing URM when referenced → fail-closed UNVERIFIED
  - receipt signer DID not allowlisted → UNVERIFIED
  - tampered event chain hash mismatch (recomputed) → UNVERIFIED (align with CVF-US-021 semantics in File 15)

**Backwards compatibility**
- Pure additive CLI feature.

---

## 4) Security model (self-reported vs cryptographically verifiable + guardrails)

### Evidence classification

**Cryptographically verifiable (can uplift tier)**
1. **Gateway receipt envelopes** (`_receipt_envelope`) captured by shim/session:
   - Signature verifiable (Ed25519) and signer DID allowlisted (PoH spec §5.3; File 14).
   - Binding verifiable to event chain via `binding.run_id` + `binding.event_hash_b64u` (File 14).
   - Implemented extraction in adapter runtime (`extractReceiptEnvelope()` in `packages/clawsig-adapters/src/session.ts`, File 10) and streaming shim collection in `packages/clawsig-adapters/src/shim.ts` (File 9).

2. **Event chain integrity**
   - Verifier recomputes `event_hash_b64u` and rejects mismatches (CVF-US-021 already “passes”; File 15).
   - This prevents tampered chains from claiming receipt linkage.

**Self-reported (must NOT uplift tier)**
1. **Local raw JSONL logs** from harnesses (agentlog inputs; File 2 and analysis File 1):
   - mutable by the user; cannot be used for tiering.

2. **URM metadata** (`urm.metadata`, File 12) and any derived summaries:
   - signed only by agent DID (self-assertion).
   - useful for UX, audit hints, search; **not** for tier uplift.

3. **Trust Pulse / semantic summaries**
   - explicitly marked `evidence_class: self_reported` and `tier_uplift: false`.

### Guardrails to prevent false tier uplift (fail-closed + non-gameable)
- **Tier derivation rule (strict):**
  - `gateway` tier requires ≥1 **verified** gateway receipt envelope with:
    - allowlisted `signer_did`
    - correct signature
    - correct binding to bundle `(run_id, event_hash_b64u)`
  - Anything else (pulse metadata, agentlog stats, git hints) **ignored for tier**.
- **Schema strictness + bounds** (already a trust-vNext theme; CVF-US-024/025 in File 15):
  - enforce caps on metadata sizes and object counts so pulse cannot be used for DoS or smuggling.
- **No “verified” flags from producer**
  - never accept a producer-provided `verified: true` field; verification is computed by verifier only.
- **Redaction-before-hash**
  - prevents secrets from being embedded into hashed payloads/URM and later leaked via debugging/tooling.
- **Marketplace replay controls** (already implemented; POH-US-014 passes in File 15)
  - blocks reusing `(agent_did, run_id)` or `(receipt_signer_did, receipt_id)` to inflate.

---

## 5) Developer UX (OpenClaw user experience)

### Default behaviors (safe-by-default)
- **Redaction ON by default** for PoH payload hashing and URM metadata (POH-US-020).
- **Trust Pulse generation ON by default** but:
  - derived-only
  - redacted
  - bounded
  - labeled non-tier (`tier_uplift: false`)
- **No transcript export**
  - Users never need to upload JSONL logs; only proof bundle + URM + optional pulse artifact.

### What an OpenClaw user sees
1. Run OpenClaw normally (with clawproxy provider plugin + recorder).
2. On completion, OpenClaw outputs:
   - proof bundle envelope + URM (as today’s PoH flow; see File 10 / File 11 finalize shapes)
   - optional `trust_pulse.v1.json` artifact
3. User (or CI) runs:
   - `agentlog verify ~/.openclaw/.../sessions/<id>/` → prints:
     - `VERIFIED_GATEWAY` or `UNVERIFIED`
     - receipt count
     - run_id
     - reasons on failure (missing URM, untrusted signer, binding mismatch), without any message content

### Flags / configuration knobs
- `--poh.redaction=on|off` (default on; off only for controlled debugging)
- `--trust-pulse=on|off` (default on)
- `--trust-pulse.decisions=off|on` (default off if there’s any risk it pulls in prompt-like text; keep minimal initially)
- `AGENTLOG_GATEWAY_SIGNER_ALLOWLIST=did:key:...` (agentlog verify should mirror clawverify allowlist semantics)

### Skills / ecosystem impact
- No change required for OpenClaw “skills” besides:
  - ensuring tool instrumentation emits enough structured info to count tool/file touches without including file contents.
- External harnesses using the shim (`packages/clawsig-adapters/src/shim.ts`, File 9) benefit automatically from:
  - safer recorded payloads (Phase 1)
  - verifiable receipts capture (already present)

---

### Summary of “real trust-platform value”
- **Immediate safety uplift**: pre-hash redaction at the recorder/session layer (leveraging `agentlog/redact.py`, File 3) reduces toxic-proof risk across all harnesses.
- **User-visible verification**: `agentlog verify` gives OpenClaw users a local, fail-closed truth badge without transcript exfiltration.
- **Marketplace UX uplift without tier gaming**: Trust Pulse provides high-signal “what happened” in URM metadata/artifacts, explicitly non-tier and strictly bounded/redacted.

If you want, I can also draft the exact JSON fragments to append into `docs/roadmaps/trust-vnext/prd.json` (File 15) in-place (matching the existing schema/fields like `priority`, `passes`, `notes`).
