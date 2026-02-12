> **Type:** Protocol reference
> **Status:** LIVE
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-12

# Claw Protocol v0.1 — Reason Code Registry

All protocol components MUST return deterministic, machine-readable reason codes. This document is the canonical registry.

## Response shape for deny/error semantics

All protocol-level denials MUST include the following machine-readable fields:

```json
{
  "ok": false,
  "error": {
    "code": "REASON_CODE",
    "message": "Human-readable explanation",
    "details": {}
  }
}
```

- `code` — MUST be a registered reason code from this document (SCREAMING_SNAKE_CASE).
- `message` — SHOULD be human-readable but MUST NOT contain secrets.
- `details` — OPTIONAL; additional structured context (e.g. expected vs. actual hash).

Verification outputs (CLI, conformance) use the flattened shape:

```json
{
  "status": "PASS" | "FAIL",
  "reason_code": "REASON_CODE",
  "reason": "Human-readable explanation"
}
```

## Fail-closed rule

Unknown reason codes MUST be treated as failures by consumers. Implementations MUST NOT invent ad-hoc codes without registering them here.

---

## Protocol-core codes

These codes are emitted by the protocol's verification layer (clawverify, clawverify-core, clawverify-cli) and are the primary conformance surface.

### PASS / OK

| Code | Meaning |
|------|---------|
| `OK` | Verification passed |
| `VALID` | Schema/signature/chain valid |
| `PASS` | Conformance vector passed |

### SIGNATURE_*

| Code | Meaning |
|------|---------|
| `SIGNATURE_INVALID` | Ed25519/envelope signature verification failed |

### SCHEMA_*

| Code | Meaning |
|------|---------|
| `SCHEMA_VALIDATION_FAILED` | JSON schema validation failed |
| `UNKNOWN_SCHEMA_ID` | Schema ID not recognized |
| `UNKNOWN_SCHEMA_VERSION` | Schema version not recognized |
| `DEPRECATED_SCHEMA` | Schema version is deprecated |

### UNKNOWN_*

| Code | Meaning |
|------|---------|
| `UNKNOWN_VERSION` | Envelope/protocol version not recognized (fail-closed) |
| `UNKNOWN_TYPE` | Envelope type not recognized (fail-closed) |
| `UNKNOWN_ALGO` | Signature algorithm not recognized (fail-closed) |
| `UNKNOWN_ALGORITHM` | Hash/crypto algorithm not recognized |
| `UNKNOWN_ENVELOPE_TYPE` | Envelope type field not recognized |
| `UNKNOWN_ENVELOPE_VERSION` | Envelope version field not recognized |
| `UNKNOWN_HASH_ALGORITHM` | Hash algorithm not recognized |

### HASH_*

| Code | Meaning |
|------|---------|
| `HASH_MISMATCH` | Content hash does not match declared hash |
| `HASH_CHAIN_BREAK` | Event chain hash linkage is broken |

### INVALID_*

| Code | Meaning |
|------|---------|
| `INVALID` | Generic validation failure |
| `INVALID_DID` | DID is malformed or unresolvable |
| `INVALID_DID_FORMAT` | DID format not supported (e.g. not did:key with Ed25519) |
| `INVALID_JSON` | Input is not valid JSON |
| `INVALID_ROOT` | Merkle/hash root is invalid |

### MALFORMED_*

| Code | Meaning |
|------|---------|
| `MALFORMED_ENVELOPE` | Envelope structure is incomplete or corrupt |
| `MISSING_REQUIRED_FIELD` | Required field missing from envelope |
| `MISSING_EVENT_FIELD` | Required field missing from event chain entry |

### CANONICALIZATION_*

| Code | Meaning |
|------|---------|
| `CANONICALIZATION_ERROR` | JCS canonicalization failed |

### DEPENDENCY_*

| Code | Meaning |
|------|---------|
| `DEPENDENCY_MISSING` | Required dependency (CLI, config, signer) not available |
| `DEPENDENCY_NOT_CONFIGURED` | Governance/allowlist dependency not configured |

### BUNDLE_*

| Code | Meaning |
|------|---------|
| `PROOF_BUNDLE_INVALID` | Proof bundle envelope verification failed |
| `PROOF_BUNDLE_AGENT_MISMATCH` | Bundle agent DID does not match expected |
| `PROOF_BUNDLE_AGENT_ROTATED` | Bundle agent DID was rotated (rotation cert present) |
| `MISSING_PROOF_BUNDLE` | Expected proof bundle not present |
| `INCONSISTENT_RUN_ID` | Run IDs across bundle elements are inconsistent |
| `EMPTY_CHAIN` | Event chain has no entries |

### RECEIPT_*

| Code | Meaning |
|------|---------|
| `RECEIPT_BINDING_MISMATCH` | Receipt binding (run_id/event_hash) does not match bundle |
| `RECEIPT_VERIFICATION_FAILED` | Individual receipt envelope verification failed |

### URM_*

| Code | Meaning |
|------|---------|
| `URM_MISSING` | URM file required but not found |
| `URM_MISMATCH` | URM content does not match bundle reference |

### SIDE_EFFECT_*

| Code | Meaning |
|------|---------|
| `SIDE_EFFECT_UNKNOWN_CLASS` | Side-effect receipt effect_class not recognized |
| `SIDE_EFFECT_AGENT_MISMATCH` | Side-effect receipt agent_did does not match bundle |

### HUMAN_APPROVAL_*

| Code | Meaning |
|------|---------|
| `HUMAN_APPROVAL_UNKNOWN_TYPE` | Approval type not recognized |
| `HUMAN_APPROVAL_AGENT_MISMATCH` | Approval receipt agent_did does not match bundle |
| `HUMAN_APPROVAL_EXPIRED` | Minted capability has expired |

### CAPABILITY_*

| Code | Meaning |
|------|---------|
| `CAPABILITY_DENIED` | Capability request denied by policy |
| `CAPABILITY_REQUIRES_APPROVAL` | Capability requires human approval |
| `CAPABILITY_SCOPE_EXCEEDED` | Requested scope exceeds policy limits |
| `CAPABILITY_PREFLIGHT_FAIL` | Preflight check failed |

### COMMIT_*

| Code | Meaning |
|------|---------|
| `COMMIT_MESSAGE_INVALID` | Commit sig message format invalid (expected `commit:<sha>`) |
| `COMMIT_NOT_FOUND` | Signed commit SHA not found in checkout |

### OWNER_ATTESTATION_*

| Code | Meaning |
|------|---------|
| `OWNER_ATTESTATION_INVALID` | Owner attestation signature/schema invalid |
| `OWNER_ATTESTATION_EXPIRED` | Owner attestation has expired |
| `OWNER_ATTESTATION_SUBJECT_MISMATCH` | Attestation subject does not match expected DID |
| `OWNER_ATTESTATION_SUBJECT_ROTATED` | Attestation subject was rotated |
| `OWNER_NOT_VERIFIED` | Owner verification failed |
| `MISSING_OWNER_ATTESTATION` | Owner attestation required but not present |

### MODEL_IDENTITY_*

| Code | Meaning |
|------|---------|
| `MODEL_IDENTITY_HASH_MISMATCH` | Model identity hash does not match |
| `MODEL_IDENTITY_VERIFY_FAILED` | Model identity verification failed |
| `MODEL_IDENTITY_MISSING_DEFAULTED` | No model identity evidence; defaulted to opaque |
| `MODEL_IDENTITY_OPAQUE` | Model identity cannot be verified (opaque) |
| `MODEL_IDENTITY_HETEROGENEOUS` | Multiple different models in a single bundle |

### EXECUTION_ATTESTATION_*

| Code | Meaning |
|------|---------|
| `EXECUTION_ATTESTATION_INVALID` | Execution attestation signature/schema invalid |
| `EXECUTION_ATTESTATION_AGENT_MISMATCH` | Attestation agent DID mismatch |
| `EXECUTION_ATTESTATION_BUNDLE_HASH_MISMATCH` | Attestation bundle hash mismatch |
| `EXECUTION_ATTESTATION_VERIFIED` | Execution attestation verified (informational) |

### DID_ROTATION_*

| Code | Meaning |
|------|---------|
| `DID_ROTATION_CERT_INVALID` | Rotation certificate signature invalid |
| `DID_ROTATION_CERTS_AMBIGUOUS` | Multiple rotation certs with conflicting claims |

### INCLUSION_*

| Code | Meaning |
|------|---------|
| `INCLUSION_PROOF_INVALID` | Log inclusion proof verification failed |

---

## Infrastructure codes

These codes are emitted by protocol-adjacent services and are part of the deny semantics surface.

### CONFIG_*

| Code | Meaning |
|------|---------|
| `CONFIG_ERROR` | Service configuration error |
| `ADMIN_KEY_NOT_CONFIGURED` | Admin key not set in environment |
| `SIGNING_NOT_CONFIGURED` | Signing keys not configured |
| `CONTROL_PLANE_NOT_CONFIGURED` | Control plane binding not configured |

### REPLAY_*

| Code | Meaning |
|------|---------|
| `IDEMPOTENCY_CONFLICT` | Idempotency key already used with different payload |
| `IDEMPOTENCY_KEY_REUSED` | Idempotency key reused (fingerprint match — safe replay) |
| `IDEMPOTENCY_FINGERPRINT_MISMATCH` | Nonce reused with different payload fingerprint |
| `REPLAY_RECEIPT_ID_REUSED` | Receipt ID already ingested |
| `REPLAY_RUN_ID_REUSED` | Run ID already ingested |
| `REPLAY_PROTECTION_FAILED` | Generic replay protection failure |

### DENY (policy / scope / delegation)

| Code | Meaning |
|------|---------|
| `POLICY_VIOLATION` | Policy rule violated |
| `POLICY_NONCOMPLIANT` | Request does not comply with policy |
| `POLICY_MISSING` | Required policy not present |
| `SCOPE_NOT_ALLOWED` | Requested scope exceeds granted capabilities |
| `SENSITIVE_SCOPE_NOT_ALLOWED` | Sensitive scope requires additional authorization |
| `DELEGATION_SPEND_CAP_EXCEEDED` | Delegation spend cap would be exceeded |
| `DELEGATION_REVOKED` | Delegation has been revoked |
| `DELEGATION_EXPIRED` | Delegation has expired |
| `DELEGATION_POLICY_MISMATCH` | Delegation policy hash does not match |

### TOKEN_*

| Code | Meaning |
|------|---------|
| `TOKEN_EXPIRED` | Token TTL exceeded |
| `TOKEN_REVOKED` | Token has been revoked |
| `TOKEN_MALFORMED` | Token cannot be parsed |
| `TOKEN_SIGNATURE_INVALID` | Token signature verification failed |
| `TOKEN_SCOPE_HASH_MISMATCH` | Token scope hash does not match claims |
| `TOKEN_UNKNOWN_KID` | Token key ID not in known keyset |
| `TOKEN_KID_EXPIRED` | Token key ID has expired |
| `TOKEN_INSUFFICIENT_SCOPE` | Token scope does not cover requested action |

### AUTH_*

| Code | Meaning |
|------|---------|
| `UNAUTHORIZED` | Authentication required |
| `FORBIDDEN` | Authenticated but not authorized |
| `BLOCKED_MISSING_AUTH` | Request blocked — no auth header |
| `BLOCKED_UNKNOWN_PROVIDER` | Provider not in allowlist |

### INTERNAL_*

| Code | Meaning |
|------|---------|
| `INTERNAL_ERROR` | Unrecoverable internal error |
| `CRYPTO_ERROR` | Cryptographic operation failed |
| `PARSE_ERROR` | Input parsing failed |
| `DB_READ_FAILED` | Database read failed |
| `DB_WRITE_FAILED` | Database write failed |
| `FETCH_FAILED` | Upstream fetch failed |
| `UPSTREAM_ERROR` | Upstream service error |

---

## Adding new codes

1. Add the code to this document under the appropriate category.
2. Use SCREAMING_SNAKE_CASE.
3. Prefix with the category (e.g. `TOKEN_`, `POLICY_`, `SCHEMA_`).
4. Add a conformance vector if the code is emitted by the verifier.
5. Codes are additive-only — never remove or rename existing codes.

---

## Conformance

The offline verifier (clawverify-cli) MUST only return registered reason codes. The conformance suite (`scripts/protocol/run-claw-protocol-conformance.mjs`) validates that each vector produces the expected registered code.
