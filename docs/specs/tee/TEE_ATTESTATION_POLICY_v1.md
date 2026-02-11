> **Type:** Spec
> **Status:** ACTIVE
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-11
> **Source of truth:** `packages/schema/poh/execution_attestation.v1.json` + `services/clawverify/src/verify-execution-attestation.ts`

# TEE Execution Attestation Policy v1

This spec defines the **minimum policy contract** for `execution_type=tee_execution` attestations.

Goals:
1. Standardize `runtime_metadata.tee` fields for evidence references + measurements.
2. Enforce fail-closed allowlist/revocation policy for TEE roots and TCB versions.
3. Be explicit about confidentiality vs integrity trade-offs across common TEEs.

---

## 1) Runtime metadata fields (execution_attestation.v1)

For `payload.execution_type = "tee_execution"`, `payload.runtime_metadata.tee` is required with:

- `attestation_type`
  - enum: `sgx_quote | tdx_quote | sev_snp_report | nitro_attestation_doc | generic_tee`
- `root_id`
  - string root-of-trust identifier for policy checks
- `tcb_version`
  - string TCB version identifier for policy checks
- `evidence_ref`
  - `{ resource_type, resource_hash_b64u, uri? }`
- `measurements`
  - at minimum `{ measurement_hash_b64u }`
  - optional digests: `runtime_digest_b64u`, `kernel_digest_b64u`
- optional `tcb`
  - `{ status?, advisory_ids? }`

All fields are validated by schema and verifier (fail-closed).

---

## 2) Allowlist + revocation strategy

`clawverify` policy gates for `tee_execution`:

- `TEE_ATTESTATION_ROOT_ALLOWLIST` (required)
- `TEE_ATTESTATION_TCB_ALLOWLIST` (required)
- `TEE_ATTESTATION_ROOT_REVOKED` (optional denylist)
- `TEE_ATTESTATION_TCB_REVOKED` (optional denylist)

### Verification behavior

For `tee_execution`, verifier flow is:

1. Envelope/payload schema validation (strict, standalone Ajv)
2. Signature + hash verification
3. Policy checks:
   - missing allowlists => `DEPENDENCY_NOT_CONFIGURED`
   - revoked root/TCB => `REVOKED`
   - non-allowlisted root/TCB => `CLAIM_NOT_FOUND`

No soft fallback path exists. Policy failures are INVALID.

### Operational guidance

- Keep allowlists small and explicitly versioned.
- Rotate root/TCB lists via staged rollout (staging first, then prod).
- Treat revocation lists as emergency controls.
- Record policy changes in deployment logs/progress docs.

---

## 3) Confidentiality vs integrity trade-offs (TEE families)

This table is a policy-facing summary, not a vendor security claim.

| TEE family | Integrity signal | Confidentiality posture | Typical caveats |
|---|---|---|---|
| Intel SGX | Quote + enclave measurement | Strong enclave memory isolation | EPC limits, side-channel hardening required |
| Intel TDX | TD measurement + quote | Strong VM-level isolation from host | Ecosystem maturity and tooling variance |
| AMD SEV-SNP | Guest measurement + attestation report | Strong VM memory encryption/isolation | Firmware/PSP trust chain handling |
| AWS Nitro Enclaves | Attestation document + PCR-like measurements | Strong enclave isolation in Nitro model | AWS-specific operational model |

### Interpretation rules

- **Integrity**: attestation proves measured code/config claims under a trusted root/TCB policy.
- **Confidentiality**: depends on runtime model, side-channel posture, and operational controls.
- TEE evidence should be treated as a **stronger execution claim**, not absolute secrecy.

---

## 4) Relation to PoH tiers

- `tee_execution` attestations are evidence inputs to raise proof confidence.
- Tier uplift logic remains in verifier policy and should remain fail-closed.
- Model identity axis remains orthogonal to PoH tier.
