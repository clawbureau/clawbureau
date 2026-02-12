> **Type:** Integration Spec
> **Status:** DRAFT
> **Version:** 1.0
> **Owner:** @clawbureau/core
> **Date:** 2026-02-12
> **Dependencies:** Clawsig Protocol v0.1, EIP-8004 (Trustless Agents), proof_bundle.v1.json
> **Strategic context:** `docs/strategy/GEMINI_DEEP_THINK_REVIEW_2026-02-12.md`

# Clawsig x EIP-8004 Integration Spec v1

## 0. Purpose

This document defines how the Clawsig Protocol integrates with EIP-8004 (Trustless Agents) so that Claw Bureau operates as a **standard Validation Oracle** in the EIP-8004 ecosystem.

EIP-8004 provides three on-chain registries:

1. **Identity Registry** -- ERC-721 agent identity with `agentURI` pointing to an off-chain registration file.
2. **Reputation Registry** -- On-chain feedback signals from principals and peers.
3. **Validation Registry** -- Generic hooks for independent work verification (re-execution, zkML, TEE attestation, or protocol-based validation like Clawsig).

Clawsig slots into registry (3): the Validation Registry. Agents register their identity on-chain via EIP-8004, perform work under Clawsig protocol constraints (WPC + receipts + proof bundles), and `clawverify` posts deterministic PASS/FAIL results to the Validation Registry contract.

---

## 1. Agent Registration File: Declaring Clawsig Support

### 1.1 EIP-8004 Registration File

EIP-8004 agents publish a JSON registration file at the URI referenced by their on-chain `agentURI`. This file declares capabilities, service endpoints, and supported trust models.

To declare Clawsig verification support, the registration file includes:

```json
{
  "agentId": "0x00000000000000000000000000000000000000000000000000000000000002a1",
  "name": "acme-code-agent",
  "version": "2.1.0",
  "supportedTrust": [
    "clawsig-verification"
  ],
  "services": [
    {
      "name": "ClawsigVerification",
      "type": "validation-oracle",
      "endpoint": "https://clawverify.com/v1/validate",
      "protocolVersion": "0.1",
      "conformanceVersion": "23"
    }
  ],
  "clawsig": {
    "discoveryUrl": "https://acme-agent.example.com/.well-known/clawsig.json",
    "defaultCoverage": "MTS",
    "supportedReceiptTypes": [
      "gateway",
      "tool",
      "side_effect",
      "human_approval"
    ]
  }
}
```

### 1.2 Field Definitions

| Field | Required | Description |
|-------|----------|-------------|
| `supportedTrust[]` | YES | MUST include `"clawsig-verification"` to declare Clawsig oracle support |
| `services[].name` | YES | MUST be `"ClawsigVerification"` for the Clawsig oracle entry |
| `services[].type` | YES | MUST be `"validation-oracle"` |
| `services[].endpoint` | YES | URL of the clawverify API endpoint |
| `services[].protocolVersion` | YES | Clawsig Protocol version (e.g. `"0.1"`) |
| `services[].conformanceVersion` | YES | Conformance test vector version (e.g. `"23"`) |
| `clawsig.discoveryUrl` | NO | URL to `.well-known/clawsig.json` (see Deliverable 3) |
| `clawsig.defaultCoverage` | NO | Default coverage level: `"M"`, `"MT"`, or `"MTS"` |
| `clawsig.supportedReceiptTypes` | NO | Array of receipt classes the agent emits |

### 1.3 Trust Model Identifier

The canonical trust model identifier for Clawsig in EIP-8004 is:

```
clawsig-verification
```

This string is used in:
- `supportedTrust[]` arrays in agent registration files
- Validation Registry contract calls (as the `validationType` parameter)
- Discovery and capability negotiation

---

## 2. Proof Bundle to EIP-8004 Validation Record Mapping

### 2.1 Validation Registry Contract Interface

The EIP-8004 Validation Registry exposes:

```solidity
interface IValidationRegistry {
    function submitValidation(
        uint256 agentId,
        string calldata validationType,
        bytes32 evidenceHash,
        bool passed,
        string calldata reason
    ) external;

    event ValidationSubmitted(
        uint256 indexed agentId,
        address indexed oracle,
        string validationType,
        bytes32 evidenceHash,
        bool passed,
        string reason,
        uint256 timestamp
    );
}
```

### 2.2 Mapping: proof_bundle.v1 to Validation Record

| Validation Registry Field | Source from Clawsig | Derivation |
|---------------------------|---------------------|------------|
| `agentId` | `proof_bundle.eip8004_agent_id` | Direct mapping. uint256 tokenId from Identity Registry |
| `validationType` | Constant | `"clawsig-verification"` |
| `evidenceHash` | `proof_bundle` | `keccak256(sha256(JCS(proof_bundle)))` -- double hash for EVM compatibility |
| `passed` | Verification result | `true` if clawverify returns `status: "PASS"`, `false` otherwise |
| `reason` | Verification result | Clawsig reason code (e.g. `"PASS"`, `"SIGNATURE_INVALID"`, `"HASH_MISMATCH"`) |

### 2.3 Evidence Hash Derivation

The `evidenceHash` posted on-chain is derived deterministically:

```
1. Canonicalize the proof bundle payload using JCS (RFC 8785)
2. Compute SHA-256 of the canonical bytes (the native Clawsig hash)
3. Compute keccak256 of the SHA-256 digest (for EVM-native verification)
4. The result is the bytes32 evidenceHash
```

This allows:
- Off-chain parties to verify the evidence hash using standard Clawsig tooling (SHA-256 + JCS)
- On-chain contracts to reference the evidence hash natively (keccak256)
- Deterministic re-derivation from the proof bundle alone (no oracle trust required for hash verification)

### 2.4 Verification Result Payload

When clawverify evaluates a proof bundle, it produces a `VerificationResult`:

```json
{
  "status": "PASS",
  "reason_code": "PASS",
  "reason": "All checks passed",
  "bundle_id": "bundle_abc123",
  "agent_did": "did:key:z6Mk...",
  "eip8004_agent_id": "0x02a1",
  "evidence_hash_hex": "0xabcdef...",
  "coverage": "MTS",
  "checks": {
    "schema_valid": true,
    "signatures_valid": true,
    "event_chain_valid": true,
    "receipt_bindings_valid": true,
    "policy_compliant": true
  },
  "timestamp": "2026-02-12T21:00:00Z"
}
```

The oracle adapter extracts `eip8004_agent_id`, `evidence_hash_hex`, `status`, and `reason_code` and submits the on-chain transaction.

---

## 3. Oracle Submission Flow

### 3.1 End-to-End Flow

```
Agent (EIP-8004 registered)
  |
  |  1. Performs work, collects receipts
  |  2. Builds proof_bundle with eip8004_agent_id + eip8004_registry
  v
clawverify.com/v1/validate
  |
  |  3. Deterministic PASS/FAIL evaluation
  |  4. Returns VerificationResult
  v
Clawsig Oracle Adapter (off-chain service)
  |
  |  5. Extracts agentId, evidenceHash, passed, reason
  |  6. Calls IValidationRegistry.submitValidation()
  v
EIP-8004 Validation Registry (on-chain)
  |
  |  7. Emits ValidationSubmitted event
  |  8. Updates agent's validation record
  v
Consumers (marketplaces, DAOs, other agents)
  |
  |  9. Query validation history for agent
  |  10. Make trust decisions based on PASS/FAIL record
```

### 3.2 Oracle Adapter Requirements

The Clawsig Oracle Adapter is an off-chain service that:

1. **Listens** for verified proof bundles (via clawverify webhook or polling)
2. **Extracts** the EIP-8004 fields from the bundle and verification result
3. **Submits** the validation record to the on-chain registry
4. **Signs** the transaction with the oracle's registered key

**Security properties:**
- The oracle MUST be registered in the Validation Registry's allowlist
- The oracle MUST NOT modify the verification result -- it is a transparent relay
- The evidence hash is independently verifiable by any party with the proof bundle
- Failed verifications MUST be submitted (FAIL results are as important as PASS)

### 3.3 Batching and Gas Optimization

For high-throughput scenarios:
- The oracle adapter MAY batch multiple validation submissions into a single transaction using `submitValidationBatch()`
- Batched submissions MUST maintain per-agent evidenceHash integrity
- The oracle SHOULD submit within a configurable time window (default: 5 minutes from verification completion)

---

## 4. Identity Mapping: ERC-721 agentId to agent_did

### 4.1 Dual Identity Model

Clawsig Protocol uses `did:key` as its native identity for cryptographic operations (signing, verification). EIP-8004 uses ERC-721 `agentId` (uint256 tokenId) as on-chain identity.

These are complementary, not conflicting:

| Layer | Identity | Purpose |
|-------|----------|---------|
| Cryptographic (signing) | `did:key:z6Mk...` | Signs proof bundles, receipts, envelopes |
| On-chain (reputation) | ERC-721 `agentId` | Receives validation records, reputation signals |
| Discovery | `agentURI` | Points to registration file with both identities |

### 4.2 Binding Rules

The proof bundle binds both identities:

```json
{
  "bundle_version": "1",
  "bundle_id": "...",
  "agent_did": "did:key:z6MktzmKpfCNcKSUp7qzTrZK3c89QFvhgmK7V1GXxMH9m8XW",
  "eip8004_agent_id": "673",
  "eip8004_registry": "eip155:1:0x1234...abcd",
  ...
}
```

**Binding requirements:**
1. `agent_did` MUST always be present (required by protocol)
2. `eip8004_agent_id` is OPTIONAL -- only present for EIP-8004-registered agents
3. When `eip8004_agent_id` is present, `eip8004_registry` SHOULD also be present
4. The `eip8004_registry` uses CAIP-10 format: `eip155:<chainId>:<contractAddress>`

### 4.3 Identity Verification

When a proof bundle includes EIP-8004 fields, the verifier performs additional checks:

1. **Format check:** `eip8004_agent_id` MUST be a decimal string representing a uint256
2. **Registry format check:** `eip8004_registry` MUST match CAIP-10 pattern `eip155:<chainId>:<0xAddress>`
3. **Cross-reference (optional, online mode):** If the verifier has chain access, it MAY verify that the `agentURI` registration file at the on-chain `agentId` includes the same `agent_did` in its Clawsig configuration -- this proves the EIP-8004 identity owner authorized this DID

**Fail-closed behavior:**
- Invalid `eip8004_agent_id` format: `INVALID_EIP8004_AGENT_ID` (FAIL)
- Invalid `eip8004_registry` format: `INVALID_EIP8004_REGISTRY` (FAIL)
- Cross-reference mismatch (online mode): `EIP8004_DID_MISMATCH` (FAIL)
- Fields absent: No error. Verification proceeds with `did:key` only.

### 4.4 Backwards Compatibility

Systems without EIP-8004 continue to work exactly as before:

| Scenario | `agent_did` | `eip8004_agent_id` | `eip8004_registry` | Behavior |
|----------|-------------|---------------------|---------------------|----------|
| No EIP-8004 | `did:key:z6Mk...` | absent | absent | Standard Clawsig verification. No on-chain submission. |
| EIP-8004 registered | `did:key:z6Mk...` | `"673"` | `"eip155:1:0x1234..."` | Full verification + on-chain validation record submission |
| EIP-8004, no registry | `did:key:z6Mk...` | `"673"` | absent | Verification passes but oracle cannot determine target chain. Logged as warning. |

**Key guarantee:** The `agent_did` field remains the **required** identity primitive. EIP-8004 fields are additive. No existing proof bundles, verification flows, or offline CLI usage breaks.

---

## 5. New Reason Codes

The following reason codes are added to the Clawsig Reason Code Registry for EIP-8004 integration:

| Code | Category | Severity | Description |
|------|----------|----------|-------------|
| `INVALID_EIP8004_AGENT_ID` | `INVALID_*` | FAIL | `eip8004_agent_id` present but not a valid uint256 decimal string |
| `INVALID_EIP8004_REGISTRY` | `INVALID_*` | FAIL | `eip8004_registry` present but does not match CAIP-10 format |
| `EIP8004_DID_MISMATCH` | `INVALID_*` | FAIL | On-chain agentURI registration file does not include the bundle's `agent_did` |
| `EIP8004_REGISTRY_UNREACHABLE` | `DEPENDENCY_*` | WARN | Could not reach on-chain registry for cross-reference (online mode only, non-fatal) |
| `EIP8004_ORACLE_SUBMIT_FAILED` | `DEPENDENCY_*` | WARN | Validation record submission to on-chain registry failed (non-fatal to verification) |

---

## 6. Discovery: `.well-known/clawsig.json`

Any agent domain MAY publish a `.well-known/clawsig.json` file to advertise Clawsig capabilities and verification endpoints. See:
- `docs/specs/clawsig-protocol/WELL_KNOWN_CLAWSIG_v1.md`

The EIP-8004 registration file's `clawsig.discoveryUrl` SHOULD point to this file.

---

## 7. Security Considerations

### 7.1 Oracle Trust Model

The Clawsig Oracle Adapter is a **trusted relay** in the on-chain submission path. Its trust properties:

- **Verification integrity:** The oracle does not perform verification -- `clawverify` does. The oracle relays the result.
- **Evidence hash:** Independently re-derivable from the proof bundle. Any party can verify the oracle posted the correct hash.
- **Liveness:** If the oracle is offline, verification still works (offline CLI, hosted API). Only on-chain record submission is delayed.
- **Censorship resistance:** The oracle MUST submit both PASS and FAIL results. An oracle that selectively omits FAIL results can be detected by comparing off-chain verification logs with on-chain records.

### 7.2 DID-to-agentId Binding Integrity

The binding between `did:key` and ERC-721 `agentId` is established by the agent owner publishing both in the registration file at `agentURI`. This is:

- **Owner-attested:** Only the agentId owner can update the registration file
- **Publicly verifiable:** Anyone can fetch `agentURI` and check the DID
- **Revocable:** Owner can remove the DID from the registration file at any time

The binding is NOT cryptographically enforced on-chain (the DID private key does not sign an on-chain transaction). For higher assurance, a future extension could require an on-chain `bindDID(agentId, didSignature)` transaction.

### 7.3 Replay Protection

Proof bundles include `bundle_id` (unique) and `timestamp`. The Validation Registry SHOULD reject duplicate `evidenceHash` submissions for the same `agentId` to prevent replay. The oracle adapter MUST track submitted evidence hashes.

---

## 8. Implementation Phases

### Phase 1: Design (this document) -- Current
- Define integration spec
- Update proof_bundle schema with optional EIP-8004 fields
- Define `.well-known/clawsig.json` standard
- Add reason codes to registry

### Phase 2: Oracle Adapter (future)
- Build `@clawbureau/eip8004-oracle-adapter` package
- Implement `submitValidation()` contract call
- Deploy oracle adapter service
- Register oracle in Validation Registry allowlist

### Phase 3: On-Chain Verification (future)
- Deploy `ClawsigValidationOracle.sol` contract (lightweight adapter)
- Implement batched submission
- Add on-chain replay protection
- Gas optimization for high-throughput scenarios

### Phase 4: Cross-Reference Verification (future)
- Add online mode to clawverify that checks agentURI for DID binding
- Implement `bindDID()` on-chain function for cryptographic DID binding
- Add chain-aware reason codes

---

## Appendix A: CAIP-10 Format Reference

CAIP-10 (Chain Agnostic Improvement Proposal 10) defines a way to identify an account on any blockchain:

```
<namespace>:<chain_id>:<account_address>
```

For EIP-8004 on Ethereum:
```
eip155:1:0x1234567890abcdef1234567890abcdef12345678
```

For EIP-8004 on Base:
```
eip155:8453:0x1234567890abcdef1234567890abcdef12345678
```

---

## Appendix B: Example Full Flow

```
1. Agent "acme-code-agent" is registered on EIP-8004 Identity Registry
   - agentId: 673
   - agentURI: https://acme.example.com/agent.json
   - Registration file includes: supportedTrust: ["clawsig-verification"]

2. Agent performs a code review task:
   - Routes LLM calls through clawproxy (model receipts)
   - Records tool calls (tool receipts)
   - Records file writes (side-effect receipts)
   - Gets human approval to push (human approval receipt)

3. Agent builds proof_bundle:
   {
     "bundle_version": "1",
     "bundle_id": "pb_acme_2026-02-12_001",
     "agent_did": "did:key:z6MktzmKpfCNcKSUp7qzTrZK3c89QFvhgmK7V1GXxMH9m8XW",
     "eip8004_agent_id": "673",
     "eip8004_registry": "eip155:1:0xAbCdEf...",
     "event_chain": [...],
     "receipts": [...],
     "tool_receipts": [...],
     "side_effect_receipts": [...]
   }

4. Bundle submitted to clawverify.com/v1/validate
   - Schema validation: PASS
   - Signature verification: PASS
   - Event chain integrity: PASS
   - Receipt bindings: PASS
   - Result: { "status": "PASS", "reason_code": "PASS" }

5. Oracle Adapter receives verification result:
   - Extracts agentId: 673
   - Computes evidenceHash: keccak256(sha256(JCS(proof_bundle)))
   - Calls submitValidation(673, "clawsig-verification", evidenceHash, true, "PASS")

6. Validation Registry emits ValidationSubmitted event
   - Any marketplace, DAO, or agent can query: "Has agent 673 been validated?"
   - Response: [{ validationType: "clawsig-verification", passed: true, timestamp: ... }]
```
