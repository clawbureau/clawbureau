# R45 Canonical Synthesis — Binary Semantic Evidence (Defensive)

Date: 2026-02-17
Source runs:
- `r45-binary-sem-a.md` (accepted for depth)
- `r45-binary-sem-c.md` (accepted as canonical base)
- `r45-binary-sem-s.md` (rejected as final artifact; policy-language donor only)

## 0) Canonical decisions

1. **Canonical schema family name**: `binary_semantic_evidence` (not `binary_semantic_attestation`).
2. **Canonical verdict enum**: `VALID | INVALID | PARTIAL | INAPPLICABLE | UNKNOWN`.
3. **Fail-closed mapping**:
   - `INVALID` and `UNKNOWN` are hard fail states for trust uplift.
   - `PARTIAL` is non-fail but cannot uplift above constrained tier.
4. **No probabilistic security decisions**:
   - No floating confidence thresholds in the verifier decision boundary.
5. **Additive migration only**:
   - New proof-bundle field must be optional in v1.

---

## 1) Architecture v1 (deterministic)

### Stage A — Binary ingestion + structural normalization
Inputs:
- binary bytes
- expected bundle hash context
- expected runtime arch/os context

Outputs:
- normalized `binary_profile`
  - `target_architecture`
  - `linkage` (`STATIC|DYNAMIC|UNKNOWN`)
  - `symbols` (`STRIPPED|INTACT|UNKNOWN`)
  - `is_sip_protected`

Invariants:
- hash binding must be exact
- parser is bounded and deterministic
- unsupported architecture yields `INAPPLICABLE`, not synthetic success/failure

### Stage B — Causal chain reconstruction
Inputs:
- runtime process telemetry receipts/events
- parent-chain inheritance metadata

Outputs:
- deterministic `causality_metrics`
  - `merkle_chain_intact`
  - `unattested_children_spawned`

Invariants:
- parent/child hash linkage is deterministic
- missing required edges are explicit, never inferred as true

### Stage C — Bounded semantic extraction
Inputs:
- normalized code/data regions
- bounded CFG traversal budget

Outputs:
- deterministic `extracted_claims`
  - `network_egress`
  - `dynamic_code_generation`
  - values: `PRESENT|ABSENT|UNKNOWN`

Invariants:
- traversal budget exhaustion maps to `UNKNOWN`
- no heuristic string parsing in security decisions

### Stage D — Contradiction gate
Inputs:
- static `extracted_claims`
- dynamic verified evidence (e.g. receipt class proving network egress)

Outputs:
- contradiction verdict + reason code

Invariant:
- dynamic verified contradiction against static `ABSENT` => deterministic `INVALID`

### Stage E — Policy state machine
Output:
- final verdict + reason code

Invariant:
- identical input evidence => identical output verdict/reason

---

## 2) Canonical schemas (v1)

### 2.1 `packages/schema/poh/binary_semantic_evidence.v1.json`

Required top-level fields:
- `evidence_version: "1"`
- `binary_hash_b64u`
- `binary_profile`
- `extracted_claims`
- `causality_metrics`
- `forensic_metrics`

Key constraints:
- `additionalProperties: false` at all levels
- base64url fields constrained by regex + min length
- claim enums are strict (`PRESENT|ABSENT|UNKNOWN`)

### 2.2 `packages/schema/poh/binary_semantic_evidence_envelope.v1.json`

Required envelope fields:
- `envelope_version: "1"`
- `envelope_type: "binary_semantic_evidence"`
- `payload`
- `payload_hash_b64u`
- `hash_algorithm`
- `signature_b64u`
- `algorithm`
- `signer_did`
- `issued_at`

### 2.3 Additive proof-bundle patch

Add optional field to `proof_bundle.v1.json`:
- `binary_semantic_evidence_attestations: SignedEnvelope<BinarySemanticEvidence>[]`

No existing required fields are changed.

---

## 3) Deterministic verifier state machine (canonical precedence)

Order is authoritative:

1. **UNKNOWN**
   - missing mandatory input/evidence dependencies
   - traversal/extraction budget exhaustion

2. **INVALID**
   - signature/hash mismatch
   - merkle chain broken
   - unattested child process spawned
   - static/dynamic contradiction
   - static-hook spoof condition

3. **INAPPLICABLE**
   - unsupported architecture
   - SIP-protected execution path where instrumentation is structurally blocked

4. **PARTIAL**
   - structurally valid but reduced forensic confidence (e.g. stripped symbols)

5. **VALID**
   - all required checks pass without contradiction

### Reason code baseline
- `MISSING_DEPENDENCY`
- `SIGNATURE_MISMATCH`
- `HASH_MISMATCH`
- `MERKLE_CHAIN_BROKEN`
- `UNATTESTED_CHILD_PROCESS`
- `CAPABILITY_EXCEEDS_STATIC_PROOF`
- `STATIC_HOOK_SPOOFING`
- `STATIC_ANALYSIS_TIMEOUT`
- `UNSUPPORTED_ARCH`
- `SIP_RESTRICTION_INAPPLICABLE`
- `STRIPPED_SYMBOLS`
- `SEMANTICS_VERIFIED`

---

## 4) Normalized adversarial matrix

1. Hash replay/mismatch -> `INVALID/HASH_MISMATCH`
2. Parent-chain tamper -> `INVALID/MERKLE_CHAIN_BROKEN`
3. Env stripping child escape -> `INVALID/UNATTESTED_CHILD_PROCESS`
4. Static says no network, runtime proves network -> `INVALID/CAPABILITY_EXCEEDS_STATIC_PROOF`
5. Static binary spoofing dynamic hooks -> `INVALID/STATIC_HOOK_SPOOFING`
6. CFG budget exhaustion -> `UNKNOWN/STATIC_ANALYSIS_TIMEOUT`
7. Unsupported arch -> `INAPPLICABLE/UNSUPPORTED_ARCH`
8. SIP-protected path -> `INAPPLICABLE/SIP_RESTRICTION_INAPPLICABLE`
9. Stripped but otherwise coherent -> `PARTIAL/STRIPPED_SYMBOLS`

---

## 5) Roadmap insertion (recommended)

Add to `docs/roadmaps/clawcompiler/prd.json`:

### CEC-US-004 — Canonical binary semantic evidence contract
- Add canonical schema IDs + additive proof-bundle field
- Ensure deterministic reason-code contract and strict enums

### CEC-US-005 — Runtime verification path in clawverify
- Add verifier endpoint/path for binary semantic evidence envelope
- Enforce deterministic precedence and fail-closed mapping

### CEC-US-006 — Conformance fixture suite
- Add canonical fixture corpus for all normalized adversarial classes
- CI runner must assert deterministic verdict + reason code

All should start as `passes:false` until implemented and merged.

---

## 6) Non-goals

- No offensive binary exploitation instructions
- No key extraction / credential interception workflows
- No non-deterministic narrative scoring inside security decision boundary
