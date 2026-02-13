> **Type:** Spec
> **Status:** CANONICAL
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-13
> **Source of truth:** this spec + referenced schemas (`packages/schema/**`) + verifier behavior (`services/clawverify/**`)
> **Supersedes:** strategy doc version (docs/strategy/GEMINI_DEEP_THINK_ROUND6_SPEC_AND_LAUNCH_2026-02-12.md Part A)
> **Audit trail:** Fixes derived from Gemini Deep Think Round 7 launch readiness audit
>
> **Scope:**
> - Canonical specification for the Clawsig Protocol v1.0.
> - Supersedes strategy doc version. All normative language lives here.
> - Four normative ambiguities resolved (RT Log anchoring, circular trust,
>   unresolvable context keys, receipt array ordering).

# The Clawsig Protocol v1.0

```text
Network Working Group                                        Claw Bureau
Internet-Draft                                         February 12, 2026
Intended status: Standards Track
Category: Security
Expires: August 16, 2026

             The Clawsig Protocol: Cryptographic Provenance
                       for Autonomous AI Agents
                        draft-clawsig-core-01

Abstract

   As autonomous AI agents increasingly execute software engineering and
   infrastructure operations, traditional static analysis of their output
   has proven insufficient for security and compliance. The Clawsig
   Protocol defines a cryptographic standard for capturing, bounding, and
   verifying the execution provenance of AI agents. It shifts the security
   paradigm from "intelligence verification" to "causal execution
   provenance" by tightly binding Model (M), Tool (T), and Side-Effect (S)
   boundaries into an offline-verifiable Merkle DAG.

Status of This Memo

   This Internet-Draft is submitted in full conformance with the
   provisions of BCP 78 and BCP 79.

Table of Contents

   1.  Introduction
   2.  Terminology
   3.  Cryptographic Primitives
   4.  Core Data Structures
   5.  Work Policy Contract (WPC)
   6.  Proof Tiers
   7.  Verification Algorithm
   8.  Receipt Transparency (RT) Log
   9.  Kinematic Proof of Model (KPoM)
   10. Sentinel Behavioral Analysis
   11. Multi-Agent Orchestration
   12. Compliance Mapping
   13. Agent Passport
   14. Security Considerations
   15. IANA Considerations
   16. Conformance
   17. Normative References

1. Introduction

   AI agents do not just generate text; they execute code, mutate databases,
   and traverse networks. Relying on model providers to self-attest to the
   safety of their agents introduces a critical conflict of interest and
   fails to capture the full execution context.

   The Clawsig Protocol introduces the "Causality Moat." It does not attempt
   to prove that an agent's reasoning was flawless. Instead, it proves exactly
   which model was used, which tools were invoked, what side-effects occurred,
   and whether those actions complied with a cryptographically pinned Work
   Policy Contract (WPC). By treating the agent runtime as a deterministic
   state machine and emitting hash-linked receipts, Clawsig provides Fortune
   500 enterprises with mathematical guarantees of agent blast-radius.

   The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
   "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
   document are to be interpreted as described in RFC 2119.

2. Terminology

   * Proof Bundle: The root JSON artifact (proof_bundle.v1) containing all
     receipts and the event chain.
   * Gateway Receipt: A cryptographically signed attestation from a trusted
     LLM proxy proving token usage, timing, and model identity.
   * Tool Receipt: A hash-only record of a local tool invocation.
   * Side Effect Receipt: A hash-only record of an environmental mutation
     (e.g., network egress, filesystem write).
   * Human Approval Receipt: A signed capability-minting event demonstrating
     human-in-the-loop oversight.
   * Delegation Receipt: A pointer embedding the hash of a subordinate
     agent's proof bundle, forming a multi-agent Merkle DAG.
   * Event Chain: The causally-ordered, hash-linked timeline of a run.
   * Work Policy Contract (WPC): An IAM-style JSON AST defining constraints.
   * Receipt Transparency (RT) Log: An append-only Merkle tree recording
     all gateway receipts globally.
   * Kinematic Fingerprint: A hardware-level timing signature (TTFT/ITL)
     verifying the physical origin of a streaming LLM response.
   * Sentinel Anomaly Report: An embedding-based threat evaluation of an
     agent's execution trajectory.
   * Proof Tier: A classification (self/gateway/sandbox) representing the
     strength of the execution observation.
   * Agent Passport: A W3C Verifiable Credential summarizing an agent's RT
     Log history.
   * Conformance Claim: A machine-readable declaration of protocol support.
   * Trusted Log Directory: A WPC-scoped list of RT Log operator identities
     whose inclusion proofs a verifier accepts.

3. Cryptographic Primitives

   Implementations MUST conform to the following cryptographic standards:

   * Signatures: Ed25519 (RFC 8032). Chosen for deterministic signatures
     and immunity to ECDSA nonce-reuse vulnerabilities.
   * Identity: did:key with Multicodec 0xed01 prefix for Ed25519.
   * Canonicalization: JSON Canonicalization Scheme (JCS) per RFC 8785.
   * Hashing: SHA-256 (FIPS 180-4).
   * Encoding: Base64url without padding (RFC 4648 Section 5) for all
     binary data, hashes, and signatures.
   * Envelope: All attestations MUST be wrapped in a Signed Envelope:
     { envelope_version, envelope_type, payload, payload_hash_b64u,
       hash_algorithm, signature_b64u, algorithm, signer_did, issued_at }.

4. Core Data Structures

   4.1 proof_bundle.v1
   The proof_bundle MUST contain bundle_version, bundle_id, agent_did,
   event_chain, and at least one receipt array (receipts, tool_receipts,
   side_effect_receipts, human_approval_receipts, delegation_receipts).

   4.2 event_chain.v1
   An array of events establishing Lamport causal ordering. Each event MUST
   contain prev_hash_b64u (null for the first event) and event_hash_b64u =
   SHA-256(JCS(event)).

   4.3 gateway_receipt.v1
   MUST contain provider, model, request_hash_b64u, response_hash_b64u,
   and binding (linking to the event chain). MUST contain
   metadata.log_inclusion_proof to achieve 'gateway' tier. MAY contain
   metadata.kinematic_fingerprint and metadata.x402_payment_ref (which
   enables bidirectional cross-commitment).

   4.4 tool_receipt.v1
   MUST contain hash_algorithm, tool_name, args_hash_b64u, and
   result_hash_b64u. Raw payloads MUST NOT be included to preserve privacy.

   4.5 side_effect_receipt.v1
   MUST contain effect_class (network_egress, filesystem_write,
   external_api_write), target_digest, request_digest, and
   response_digest.

   4.6 human_approval_receipt.v1
   MUST include approval_type, approver_subject, and scope_hash_b64u.
   MAY include policy_hash_b64u to pin the minted capability.

   4.7 delegation_receipt.v1
   MUST include delegator_did, delegate_did, and
   delegate_bundle_hash_b64u to construct the Merkle DAG linking swarms.

   4.8 kinematic_fingerprint.v1
   Embedded in gateway metadata. MUST contain ttft_ms, itl_p50_ms,
   itl_p95_ms, itl_stddev_ms, and burst_signature_b64u.

   4.9 sentinel_anomaly_report.v1
   Embedded in VaaS responses. Contains threat_score (0.0 to 1.0)
   and anomaly_type.

   4.10 log_inclusion_proof.v1
   MUST contain tree_size, leaf_hash_b64u, root_hash_b64u, audit_path,
   and a valid root_signature from the RT Log operator.

5. Work Policy Contract (WPC)

   The WPC defines the operational boundaries of the agent. WPC v1 uses
   flat JSON arrays for backwards compatibility. WPC v2 utilizes an AWS
   IAM-style Domain Specific Language (DSL).

   * Evaluation Semantics: Default Deny. If no statement explicitly
     allows an action, it is DENIED.
   * Explicit Deny Wins: A Deny statement ALWAYS overrides an Allow
     statement.
   * Strict Intersection: If inherits is set to a parent policy hash,
     the verifier MUST load the parent. The action is allowed ONLY IF
     Parent(action) == ALLOW && Child(action) == ALLOW.
   * Built-in Context Keys: Evaluators MUST inject runtime context (e.g.,
     Context:Hour, SideEffect:TargetDomain, Receipt:ProofTier).
   * Policy Hash: policy_hash_b64u = sha256_b64u(JCS(payload)).

   If a WPC Condition references a Context Key that the Evaluator
   cannot resolve at verification time, the Condition MUST evaluate
   to false (Fail-Closed). This ensures that policies requiring
   runtime context that is unavailable to offline verifiers will
   default to the most restrictive interpretation.

   Implementations SHOULD document which Context Keys they support.
   The following Context Keys are REQUIRED for Full conformance:
   Context:Hour, Context:DayOfWeek, SideEffect:TargetDomain,
   Receipt:ProofTier, Receipt:GatewayDid.

   5.1 Trusted Log Directory

   The WPC MAY include a trusted_log_directory array listing the
   did:key identifiers of RT Log operators whose inclusion proofs
   the verifier accepts. If omitted, verifiers MUST accept proofs
   signed by any RT Log operator whose root key is independently
   verifiable (e.g., published at /.well-known/clawsig on the
   operator's domain).

   This design enables federated RT Log operation: enterprises MAY
   operate private RT Logs and list them in their WPC, while the
   public Claw Bureau RT Log serves as the default for open-source
   projects.

6. Proof Tiers

   Verifiers MUST compute the objective Proof Tier based on evidence:
   * self (Tier 1): Bundle is cryptographically intact and signed by
     agent_did. No external validation.
   * gateway (Tier 2): Bundle contains at least one gateway_receipt
     whose signature verifies against the trusted Gateway Allowlist AND
     whose binding perfectly matches the event_chain, WITH a valid
     log_inclusion_proof.
   * sandbox (Tier 3): Bundle contains a valid execution_attestation
     from a hardware-isolated runtime (e.g., Cloudflare Sandbox).

7. Verification Algorithm

   Any Clawsig-compliant verifier MUST execute the following steps in order:
   1. Parse and Schema Validate: Run strict Ajv (Draft 2020-12) validation.
      Reject unknown fields (additionalProperties: false).

      Before canonicalization via JCS (RFC 8785), all arrays of
      receipts (receipts, tool_receipts, side_effect_receipts,
      human_approval_receipts, delegation_receipts) MUST be
      lexicographically sorted by receipt_id. This ensures
      deterministic hash computation regardless of emission order.

      Verifiers MUST reject bundles where receipt arrays are not
      sorted, with reason code UNSORTED_RECEIPT_ARRAY.

   2. Verify Root Signatures: Verify the Ed25519 signature of the bundle
      envelope. Ensure signer_did == payload.agent_did.
   3. Verify Event Chain Integrity: Recompute every event_hash_b64u.
      Traverse the chain to ensure prev_hash_b64u links are unbroken.
   4. Verify Receipt Bindings: For every receipt, ensure
      binding.event_hash_b64u exists in the verified Event Chain.
   5. Verify Gateway Trust: Extract gateway_receipt envelopes. Verify
      signatures. Check signer_did against GATEWAY_RECEIPT_SIGNER_DIDS.
   6. Verify RT Log Inclusion: Extract log_inclusion_proof. Recompute
      Merkle path up to root_hash_b64u. Verify root signature.
   7. TOCTOU Check: Assert that context_hash_b64u on side-effect write
      receipts matches the preceding tool read receipt results.
   8. Evaluate WPC: Replay all tool and side-effect receipts against the
      pinned WPC AST. If a Deny is triggered, FAIL (POLICY_VIOLATION).
   9. DAG Resolution: If delegation_receipts exist, fetch and recursively
      verify delegate_bundle_hash_b64u. If child is INVALID, parent is
      INVALID (Strict Liability Cascade).
   10. Compute Tier: Assign the highest cryptographically proven tier.
   11. Output: Return PASS / FAIL with strict mapped REASON_CODE.

8. Receipt Transparency (RT) Log

   To prevent key-compromise forgery, gateways MUST synchronously submit
   receipt hashes to an append-only Merkle tree prior to returning the receipt.
   * Verifiers MUST treat a gateway_receipt without a valid
     log_inclusion_proof as Tier 1 (self), degrading its trust.
   * The RT Log SHOULD anchor its root_hash_b64u periodically to a
     public decentralized ledger (e.g., an EVM L2 such as Base) via
     oracle signature to provide cross-chain immutability. Version 1.0
     implementations MAY defer anchoring. When anchoring is implemented,
     the anchor transaction MUST include the tree_size, root_hash_b64u,
     and epoch timestamp.

   Multiple RT Log operators MAY exist. Verifiers determine which
   logs to trust via the TrustedLogDirectory in the applicable WPC.
   If no TrustedLogDirectory is specified, the verifier SHOULD
   accept proofs from any log operator whose signing key is
   discoverable via /.well-known/clawsig.

9. Kinematic Proof of Model (KPoM)

   To prevent model spoofing (e.g., passing off local LLaMA-8B as Claude
   3.5 Sonnet), gateways MAY attach a kinematic_fingerprint.v1.
   * The gateway measures Time-To-First-Token (TTFT) and Inter-Token
     Latency (ITL).
   * The gateway applies a Kolmogorov-Smirnov (K-S) test against the
     known Bimodal Distribution of the claimed provider's hardware.
   * The gateway validates L4 TCP ASNs to prevent residential IP spoofing
     of cloud-provider APIs.

10. Sentinel Behavioral Analysis

   Proof bundles MAY be embedded into a dense vector space to detect
   prompt-injected or anomalous execution trajectories.
   * Semantic Compilation: The event chain is flattened into a semantic
     string: [LLM:claude] [TOOL:read_env] [EFFECT:network_egress].
   * KNN Detection: The string is embedded. A K-Nearest Neighbors search
     against the global RT Log database yields an Anomaly Score. Distance
     < 0.15 to a known POLICY_VIOLATION trace MUST flag the run as
     HIGH_RISK.
   * Sybil Resistance: Ingestion into the Sentinel model REQUIRES Proof of
     Economic Stake (x402 payment ref or Enterprise CST).

11. Multi-Agent Orchestration

   Multi-agent workflows form a Merkle DAG.
   * When Agent A delegates to Agent B, Agent A MUST embed
     bundle_hash_B in its delegation_receipt.
   * Strict Liability Cascade: If Agent B violates policy, Agent B's
     bundle is INVALID. Consequently, Agent A's bundle is INVALID. The
     orchestrator bears strict liability for its supply chain.
   * Lamport causal ordering is enforced by embedding child bundle hashes
     into parent event chains.

12. Compliance Mapping

   Verifiers MAY output a compliance_report.v1.json translating
   cryptographic constraints into enterprise frameworks.
   * SOC2 CC6.2 -> Evaluated via side_effect_receipt network egress.
   * SOC2 CC8.1 -> Evaluated via presence of proof_bundle on Git commit.
   * EU AI Act Art 14 -> Evaluated via human_approval_receipt.

13. Agent Passport

   Agent history is aggregated from the RT Log into a W3C Verifiable
   Credential (agent_passport.v1.json). This Passport MAY be mapped
   to an EIP-8004 Agent NFT agentURI to bridge off-chain verification
   with on-chain identity and payment logic.

14. Security Considerations

   * 14.1 Kinematic Spoofing: Mitigated by K-S continuous distribution testing
     and L4 ASN validation at the gateway edge.
   * 14.2 Sentinel Poisoning: Mitigated by Economic Sybil Resistance (x402 stake).
   * 14.3 RT Log Manipulation: Mitigated by periodic decentralized ledger
     anchoring (see Section 8). Version 1.0 implementations without anchoring
     rely on the append-only Merkle tree and operator key transparency.
   * 14.4 Gateway Key Compromise: Mitigated by WebCrypto non-extractable keys
     rotated every 24 hours. The Epoch Cutoff rule invalidates any receipt not
     included in the RT Log prior to compromise detection.
   * 14.5 Proof Bundle Replay: Mitigated by strict Git SHA binding;
     commit_proof.commit_sha MUST match the PR HEAD SHA exactly.
   * 14.6 Wrapper Evasion: Mitigated by Node.js --import socket-level
     interception. If bypassed, no gateway receipt is generated.
   * 14.7 Privacy Attacks: Mitigated by 16-byte Ephemeral Run Salts prepended
     to all payload hashes, preventing rainbow table attacks.
   * 14.8 DoS on Verification: Mitigated by Edge-Level Hashcash (Proof of Work)
     required on unauthenticated POST requests.
   * 14.9 Social Attacks ("Clawsig Inside"): Mitigated by the Live Heartbeat Badge
     requiring continuous RT log submissions to stay active.
   * 14.10 SDK Supply Chain: Mitigated by zero-dependency architecture and NPM
     Provenance (--provenance) enforcement.
   * 14.11 TOCTOU Attacks: Mitigated by Causal Integrity Hashes; git_commit
     receipts must reference the exact result_hash_b64u of the preceding
     read_file receipt.

15. IANA Considerations

   This document requests the registration of the application/clawsig+json
   media type and the /.well-known/clawsig URI for discovering repository
   WPC configurations and gateway public keys.

16. Conformance

   Implementations declare conformance levels:
   * Basic: Can statically verify offline proof bundles.
   * Gateway: Can emit cryptographically bound gateway receipts.
   * Full: Implements RT Log verification, KPoM, and Sentinel.

   The reference implementation (clawverify.com) claims Gateway
   conformance level as of v1.0. Full conformance (including KPoM
   K-S testing and L2 anchoring) is planned for v1.1.

   Implementations MUST declare their conformance level in the
   /.well-known/clawsig discovery document.

17. Normative References
   [RFC2119] Bradner, S., "Key words for use in RFCs to Indicate
             Requirement Levels", BCP 14, RFC 2119, March 1997.
   [RFC4648] Josefsson, S., "The Base16, Base32, and Base64 Data
             Encodings", RFC 4648, October 2006.
   [RFC8032] Josefsson, S., and I. Liusvaara, "Edwards-Curve Digital
             Signature Algorithm (EdDSA)", RFC 8032, January 2017.
   [RFC8785] Rundgren, A., Jordan, B., and S. Erdtman, "JSON
             Canonicalization Scheme (JCS)", RFC 8785, June 2020.

Authors' Addresses
   Claw Bureau Core Protocol Team
   URI: https://clawsig.com
```
