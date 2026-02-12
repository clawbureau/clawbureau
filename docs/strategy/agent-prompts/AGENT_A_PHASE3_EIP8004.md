# Agent A Dispatch: Phase 3 — EIP-8004 Integration Design

## Context

Read these files first:
- `docs/strategy/GEMINI_DEEP_THINK_REVIEW_2026-02-12.md` — strategic mandate
- `docs/strategy/PIVOT_EXECUTION_PLAN.md` — execution plan
- `docs/specs/clawsig-protocol/CLAWSIG_PROTOCOL_v0.1.md` — current protocol spec
- `docs/specs/clawsig-protocol/REASON_CODE_REGISTRY.md` — reason codes
- `packages/schema/poh/proof_bundle.v1.json` — proof bundle schema

## Background: EIP-8004

EIP-8004 (Trustless Agents) defines three on-chain registries:
1. **Identity Registry** — ERC-721 agent identity with `agentURI` → registration file
2. **Reputation Registry** — On-chain feedback signals
3. **Validation Registry** — Generic hooks for re-execution, zkML, TEE attestation

The Validation Registry is designed for exactly what Clawsig does: independent verification of agent work. Claw Bureau should become **the standard Validation Oracle** for EIP-8004.

## Your Mission

Design the integration between Clawsig Protocol and EIP-8004. Produce:

### Deliverable 1: Integration Spec
`docs/specs/eip-8004/CLAWSIG_EIP8004_INTEGRATION_v1.md`

Must cover:
- How an EIP-8004 agent registration file references Clawsig verification
  ```json
  {
    "supportedTrust": ["clawsig-verification"],
    "services": [
      { "name": "ClawsigVerification", "endpoint": "https://clawverify.com/v1/validate" }
    ]
  }
  ```
- How `proof_bundle.v1.json` maps to EIP-8004 validation records
- How `clawverify` posts PASS/FAIL results to the Validation Registry contract
- How the ERC-721 `agentId` (uint256 tokenId) maps to our `agent_did` field
- Backwards compatibility: systems without EIP-8004 still work with `did:key`

### Deliverable 2: Schema Update
Update `proof_bundle.v1.json` to optionally include:
```json
{
  "eip8004_agent_id": { "type": "string", "description": "ERC-721 tokenId from EIP-8004 Identity Registry" },
  "eip8004_registry": { "type": "string", "description": "CAIP-10 address of the Identity Registry contract" }
}
```

### Deliverable 3: `.well-known/clawsig.json` Standard
Define the standard discovery file for any domain:
```json
{
  "version": "1",
  "verification_endpoint": "https://clawverify.com/v1/validate",
  "policy_endpoint": "https://clawea.com/v1/policies",
  "supported_receipt_types": ["gateway", "tool", "side_effect", "human_approval"],
  "conformance_version": "23",
  "reason_code_registry": "https://clawprotocol.org/reason-codes"
}
```

### Deliverable 4: npm Publishing
Finally publish the two blocked packages:
- `@clawbureau/clawsig-adapters@0.1.0` to npm
- `@openclaw/provider-clawproxy@0.1.0` to npm

## Constraints
- Do NOT build Solidity contracts yet — design doc only for the on-chain part
- DO publish the npm packages — this is adoption-critical
- Keep `did:key` as primary identity — EIP-8004 agentId is optional enhancement
- All schema changes must be additive (no breaking changes)
