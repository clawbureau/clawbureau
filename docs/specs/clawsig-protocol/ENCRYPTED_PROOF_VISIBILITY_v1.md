> **Type:** Spec
> **Status:** DRAFT
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-21
> **Source of truth:** this spec + `packages/schema/poh/proof_bundle.v2.json` + `packages/schema/poh/encrypted_proof_payload.v1.json`
> **Depends on:** `CLAWSIG_PROTOCOL_v1.0.md` (parent protocol spec)
>
> **Scope:**
> - Defines the encrypted proof visibility extension for proof bundle v2.
> - Specifies cryptographic construction, visibility modes, key wrapping, and decryption flow.
> - Does NOT change public-layer verification — verifiers never need decryption keys.

# Encrypted Proof Visibility v1

```text
Network Working Group                                        Claw Bureau
Internet-Draft                                         February 21, 2026
Intended status: Standards Track
Category: Security

             Encrypted Proof Visibility for Clawsig Proof Bundles
                        draft-clawsig-epv-01

Abstract

   Clawsig proof bundles prove execution provenance through hash-only
   receipts: tool argument digests, response digests, and side-effect
   target digests. This design preserves privacy — raw commands, file
   paths, and LLM prompts never appear in the public bundle. However,
   this makes bundles unreadable for authorized human review. An inspector
   can verify THAT actions occurred, but not WHAT those actions were.

   This specification defines an encrypted visibility layer for proof
   bundle v2. Authorized viewers (operators, bounty requesters, auditors)
   can decrypt a sealed payload to recover full plaintext details, while
   the public verification surface remains unchanged.
```

## Table of Contents

1. [Motivation](#1-motivation)
2. [Architecture](#2-architecture)
3. [Cryptographic Construction](#3-cryptographic-construction)
4. [Visibility Modes](#4-visibility-modes)
5. [Schema Definitions](#5-schema-definitions)
6. [Verification](#6-verification)
7. [Decryption Flow](#7-decryption-flow)
8. [Security Properties](#8-security-properties)
9. [Backward Compatibility](#9-backward-compatibility)
10. [Auditor Mode: Selective Disclosure](#10-auditor-mode-selective-disclosure)
11. [Conformance Requirements](#11-conformance-requirements)
12. [Security Considerations](#12-security-considerations)

---

## 1. Motivation

### 1.1 The Inspector Problem

Current proof bundles (v1) contain hash-only fields by design:

- `args_hash_b64u` instead of the actual tool arguments
- `request_hash_b64u` instead of the LLM prompt
- `target_digest` instead of the filesystem path or network endpoint

This is privacy-correct. An agent working on proprietary code should not embed
source code into a publicly verifiable artifact. However, it creates a
readability gap:

| Viewer need | v1 capability | Gap |
|---|---|---|
| "Did the agent call any tool?" | Proven (tool_receipts exist) | None |
| "Which file did the agent write?" | Not visible (only hash) | Path hidden |
| "What command did the agent run?" | Not visible (only hash) | Command hidden |
| "Did the LLM suggest something dangerous?" | Not visible (only hash) | Prompt/completion hidden |

For bounty requesters reviewing delivered work, for compliance teams auditing
agent actions, and for operators debugging failures, hash-only bundles are
insufficient. They need selective access to the underlying plaintext.

### 1.2 Design Goals

1. **Zero-knowledge public layer.** The public verification surface MUST NOT
   change. Verifiers MUST NOT need any decryption key.
2. **Per-viewer access control.** Each authorized viewer receives an
   independently wrapped key. Revoking one viewer does not affect others.
3. **Forward secrecy.** Compromise of a viewer's long-term key does not
   retroactively expose bundles encrypted with prior ephemeral keys (within
   the ECDH construction).
4. **Backward compatibility.** v1 bundles remain valid. A v2 bundle with no
   `encrypted_payload` is semantically identical to v1.
5. **Fail-closed.** If `visibility` is non-public but `encrypted_payload` or
   `viewer_keys` is missing, the bundle MUST be rejected as malformed.

---

## 2. Architecture

A v2 proof bundle has two layers:

```
+------------------------------------------------------------------+
|  Proof Bundle v2 (JSON)                                          |
|                                                                  |
|  PUBLIC LAYER (always present)                                   |
|  +------------------------------------------------------------+  |
|  | bundle_version: "2"                                        |  |
|  | bundle_id, agent_did                                       |  |
|  | event_chain: [ hash-linked events ]                        |  |
|  | receipts: [ signed gateway receipt envelopes ]             |  |
|  | tool_receipts: [ hash-only tool receipts ]                 |  |
|  | side_effect_receipts: [ hash-only side-effect receipts ]   |  |
|  | human_approval_receipts, delegation_receipts, ...          |  |
|  | metadata: { harness, sentinels }                           |  |
|  +------------------------------------------------------------+  |
|                                                                  |
|  ENCRYPTED LAYER (present when visibility != "public")           |
|  +------------------------------------------------------------+  |
|  | visibility: "owner" | "requester" | "auditor"              |  |
|  | encrypted_payload:                                         |  |
|  |   ciphertext_b64u: AES-256-GCM(plaintext)                 |  |
|  |   iv_b64u: 12-byte nonce                                  |  |
|  |   tag_b64u: 16-byte auth tag                               |  |
|  |   plaintext_hash_b64u: SHA-256(plaintext)                  |  |
|  |                                                            |  |
|  | viewer_keys: [                                             |  |
|  |   { viewer_did, ephemeral_pub, wrapped_key, role },        |  |
|  |   { viewer_did, ephemeral_pub, wrapped_key, role },        |  |
|  | ]                                                          |  |
|  +------------------------------------------------------------+  |
+------------------------------------------------------------------+
```

The public layer is identical to v1 in structure and verification semantics.
The encrypted layer is purely additive. Removing it yields a valid public-only
bundle.

---

## 3. Cryptographic Construction

### 3.1 Algorithms

| Purpose | Algorithm | Parameters |
|---|---|---|
| Payload encryption | AES-256-GCM (NIST SP 800-38D) | 256-bit key, 96-bit IV, 128-bit tag |
| Key agreement | X25519 ECDH (RFC 7748) | 32-byte keys |
| Key derivation | HKDF-SHA256 (RFC 5869) | See Section 3.4 |
| Ed25519-to-X25519 | RFC 7748 Section 6.1 (birational map) | — |
| Plaintext integrity | SHA-256 (FIPS 180-4) | 256-bit digest |
| Binary encoding | Base64url without padding (RFC 4648 Section 5) | — |

### 3.2 Content Encryption

The plaintext is the JCS-canonicalized (RFC 8785) JSON bytes of an
`encrypted_proof_payload.v1` object.

```
content_key     := CSPRNG(32 bytes)                   // AES-256 key
iv              := CSPRNG(12 bytes)                   // GCM nonce
plaintext       := JCS(encrypted_proof_payload)       // canonical JSON bytes
aad             := UTF-8("clawsig-epv-v1:" || bundle_id)
(ciphertext, tag) := AES-256-GCM-Encrypt(content_key, iv, plaintext, aad)
plaintext_hash  := SHA-256(plaintext)
```

The `content_key` is a single random AES-256 key generated per bundle. It is
NOT stored in the bundle directly — it is wrapped individually for each
authorized viewer via the `viewer_keys` array.

**Additional Authenticated Data (AAD).** The AAD binds the ciphertext to the
specific bundle, preventing ciphertext transplant attacks where an attacker
swaps encrypted payloads between bundles. The AAD is the UTF-8 encoding of
the string `"clawsig-epv-v1:"` concatenated with the `bundle_id`.

### 3.3 Key Wrapping (Per-Viewer)

For each authorized viewer with DID `viewer_did`:

```
ephemeral_sk    := CSPRNG(32 bytes)                   // X25519 private key
ephemeral_pk    := X25519_BasePoint(ephemeral_sk)     // X25519 public key

viewer_ed25519_pk := resolve_did_key(viewer_did)      // Ed25519 public key
viewer_x25519_pk  := Ed25519_to_X25519(viewer_ed25519_pk)  // birational map

shared_secret   := X25519(ephemeral_sk, viewer_x25519_pk)  // 32-byte ECDH
```

A fresh ephemeral keypair MUST be generated for EACH viewer_key slot. Reusing
an ephemeral key across viewers would allow any viewer who knows their own
private key to recover the shared secret for other viewers if the ephemeral
key is reused.

### 3.4 Key Derivation (HKDF)

```
salt            := ephemeral_pk || viewer_x25519_pk   // 64 bytes
info            := UTF-8("clawsig-epv-v1-wrap")
wrapping_key    := HKDF-SHA256(
                     ikm   = shared_secret,           // 32 bytes
                     salt  = salt,
                     info  = info,
                     L     = 32                        // 256 bits
                   )
```

The salt includes both public keys to ensure domain separation: even if two
viewers share the same DID (which MUST NOT happen), different ephemeral keys
produce different salts.

### 3.5 Key Wrapping Encryption

The content key is encrypted for each viewer:

```
wrap_iv         := CSPRNG(12 bytes)
wrap_aad        := UTF-8("clawsig-epv-v1-key:" || viewer_did)
(wrapped_key, wrap_tag) := AES-256-GCM-Encrypt(
                             wrapping_key,
                             wrap_iv,
                             content_key,             // 32 bytes plaintext
                             wrap_aad
                           )
```

The resulting `viewer_keys` entry:

```json
{
  "viewer_did": "did:key:z6Mk...",
  "ephemeral_public_key_b64u": base64url(ephemeral_pk),
  "wrapped_key_b64u": base64url(wrapped_key),
  "wrapped_key_iv_b64u": base64url(wrap_iv),
  "wrapped_key_tag_b64u": base64url(wrap_tag),
  "role": "owner",
  "key_derivation": "X25519-HKDF-SHA256"
}
```

---

## 4. Visibility Modes

### 4.1 `public`

No encrypted payload. The bundle contains only hash-only receipts (equivalent
to v1). The `encrypted_payload` and `viewer_keys` fields MUST be absent.

### 4.2 `owner`

Encrypted for the operator's persistent DID only. The `viewer_keys` array
contains exactly one entry with `role: "owner"` and the operator's DID.

Use case: the operator wants to retain readable proof bundles for their own
records while publishing hash-only bundles publicly.

### 4.3 `requester`

Encrypted for the operator AND the bounty requester. The `viewer_keys` array
contains at least two entries:
- One with `role: "owner"` (operator DID)
- One with `role: "requester"` (requester DID)

Use case: a bounty requester needs to review what the agent actually did to
fulfill their task. The requester can decrypt the full plaintext; other
marketplace participants see only hashes.

### 4.4 `auditor`

Selective disclosure mode. The encrypted payload is structured so that the
`auditor`-role viewer receives a REDACTED version of the plaintext. See
Section 10 for the redaction algorithm.

Use case: a compliance auditor needs to verify that no prohibited actions
occurred (e.g., no exfiltration to unexpected hosts) without seeing full
command arguments or LLM prompts.

### 4.5 Mode Constraints

| Mode | `encrypted_payload` | `viewer_keys` | Min viewer_keys |
|---|---|---|---|
| `public` | MUST be absent | MUST be absent | 0 |
| `owner` | MUST be present | MUST be present | 1 (owner) |
| `requester` | MUST be present | MUST be present | 2 (owner + requester) |
| `auditor` | MUST be present | MUST be present | 1 (auditor) |

Producers MAY include additional viewer_key slots beyond the minimum (e.g.,
a `requester` bundle could also include an `auditor` slot). The `role` field
is advisory — it does not restrict what the viewer can decrypt. All viewers
with a valid `viewer_keys` entry can decrypt the same `encrypted_payload`
ciphertext.

For differential disclosure (auditor sees less), see Section 10.

---

## 5. Schema Definitions

### 5.1 Proof Bundle v2

Schema: `packages/schema/poh/proof_bundle.v2.json`

Schema ID: `https://schemas.clawbureau.org/claw.poh.proof_bundle.v2.json`

Extends proof_bundle.v1 with these additional properties:

| Field | Type | Required | Description |
|---|---|---|---|
| `schema_version` | `const "proof_bundle.v2"` | No | Explicit v2 tag. Absent on legacy v1. |
| `visibility` | `enum` | No | Access control mode. Default: `"public"`. |
| `encrypted_payload` | `object` | Conditional | AES-256-GCM ciphertext. Required when visibility is non-public. |
| `encrypted_payload.ciphertext_b64u` | `string` | Yes (in object) | Base64url ciphertext. |
| `encrypted_payload.iv_b64u` | `string` | Yes (in object) | Base64url 12-byte IV. |
| `encrypted_payload.tag_b64u` | `string` | Yes (in object) | Base64url 16-byte GCM tag. |
| `encrypted_payload.plaintext_hash_b64u` | `string` | No | SHA-256 of plaintext for decryption verification. |
| `viewer_keys` | `array` | Conditional | Per-viewer wrapped AES key. Required when visibility is non-public. |

The `bundle_version` field accepts `"1"` or `"2"`. When `"1"`, the v2-specific
fields SHOULD be absent (the bundle is a legacy v1 bundle parsed by a v2-aware
consumer).

### 5.2 Encrypted Proof Payload v1

Schema: `packages/schema/poh/encrypted_proof_payload.v1.json`

Schema ID: `https://schemas.clawbureau.org/claw.poh.encrypted_proof_payload.v1.json`

This is the plaintext structure that gets JCS-canonicalized and AES-256-GCM
encrypted into `encrypted_payload.ciphertext_b64u`. All fields are optional —
producers include only the categories relevant to the run.

| Field | Type | Description |
|---|---|---|
| `payload_version` | `const "1"` | Schema version. |
| `bundle_id` | `string` | MUST match enclosing bundle's `bundle_id`. |
| `tool_calls` | `array<ToolCallDetail>` | Plaintext tool call arguments and results. |
| `commands` | `array<CommandDetail>` | Plaintext shell commands. |
| `file_operations` | `array<FileOpDetail>` | Plaintext file paths and operations. |
| `network_connections` | `array<NetworkDetail>` | Plaintext network endpoints. |
| `llm_interactions` | `array<LLMDetail>` | Plaintext prompts/completions. |
| `human_approvals` | `array<ApprovalDetail>` | Plaintext approval descriptions. |
| `run_summary` | `object` | High-level run description and outcome. |

Each array entry includes a `receipt_id` field that links back to the
corresponding receipt in the public layer, enabling cross-reference between
the hash-only public receipt and its plaintext counterpart.

---

## 6. Verification

**Public-layer verification is unchanged.** Verifiers operate on the public
layer only and MUST NOT require access to `encrypted_payload` or
`viewer_keys`.

Verification of a v2 bundle follows the same algorithm defined in
CLAWSIG_PROTOCOL_v1.0.md Section 7, with these additions:

1. If `bundle_version` is `"2"` and `schema_version` is `"proof_bundle.v2"`,
   the verifier SHOULD validate the v2 JSON schema.
2. If `visibility` is non-public, the verifier MUST check that
   `encrypted_payload` and `viewer_keys` are present (fail-closed).
3. If `visibility` is `"public"`, the verifier MUST check that
   `encrypted_payload` and `viewer_keys` are absent.
4. The verifier MUST NOT attempt decryption.
5. The verifier MAY record `visibility` mode in its verification report.

**Reason codes** (additions to the reason code registry):

| Code | Category | Description |
|---|---|---|
| `EPV_PAYLOAD_MISSING` | FAIL | Non-public visibility but encrypted_payload absent |
| `EPV_VIEWER_KEYS_MISSING` | FAIL | Non-public visibility but viewer_keys absent |
| `EPV_PUBLIC_HAS_PAYLOAD` | FAIL | Public visibility but encrypted_payload present |
| `EPV_EMPTY_VIEWER_KEYS` | FAIL | viewer_keys array present but empty |
| `EPV_DUPLICATE_VIEWER` | WARN | Same viewer_did appears multiple times |
| `EPV_UNKNOWN_VISIBILITY` | FAIL | Unrecognized visibility mode |

---

## 7. Decryption Flow

A viewer with DID `my_did` and Ed25519 private key `my_ed25519_sk` decrypts
a v2 bundle as follows:

### 7.1 Locate Viewer Key Slot

```
slot := viewer_keys.find(vk => vk.viewer_did === my_did)
if slot is null:
    ABORT("No viewer_key slot for this DID")
```

### 7.2 Derive Shared Secret

```
my_x25519_sk       := Ed25519_to_X25519_Private(my_ed25519_sk)
ephemeral_pk        := base64url_decode(slot.ephemeral_public_key_b64u)
shared_secret       := X25519(my_x25519_sk, ephemeral_pk)
```

### 7.3 Derive Wrapping Key

```
my_ed25519_pk       := Ed25519_PublicKey(my_ed25519_sk)
my_x25519_pk        := Ed25519_to_X25519(my_ed25519_pk)
salt                := ephemeral_pk || my_x25519_pk       // 64 bytes
info                := UTF-8("clawsig-epv-v1-wrap")
wrapping_key        := HKDF-SHA256(shared_secret, salt, info, 32)
```

### 7.4 Unwrap Content Key

```
wrapped_key         := base64url_decode(slot.wrapped_key_b64u)
wrap_iv             := base64url_decode(slot.wrapped_key_iv_b64u)
wrap_tag            := base64url_decode(slot.wrapped_key_tag_b64u)
wrap_aad            := UTF-8("clawsig-epv-v1-key:" || my_did)
content_key         := AES-256-GCM-Decrypt(wrapping_key, wrap_iv,
                         wrapped_key || wrap_tag, wrap_aad)
if decryption fails:
    ABORT("Key unwrap failed — wrong key or tampered slot")
```

### 7.5 Decrypt Payload

```
ciphertext          := base64url_decode(encrypted_payload.ciphertext_b64u)
iv                  := base64url_decode(encrypted_payload.iv_b64u)
tag                 := base64url_decode(encrypted_payload.tag_b64u)
aad                 := UTF-8("clawsig-epv-v1:" || bundle_id)
plaintext           := AES-256-GCM-Decrypt(content_key, iv,
                         ciphertext || tag, aad)
if decryption fails:
    ABORT("Payload decryption failed — wrong content key or tampered payload")
```

### 7.6 Verify Plaintext Integrity

```
if encrypted_payload.plaintext_hash_b64u is present:
    expected := base64url_decode(encrypted_payload.plaintext_hash_b64u)
    actual   := SHA-256(plaintext)
    if expected != actual:
        ABORT("Plaintext hash mismatch — decryption produced unexpected output")
```

### 7.7 Parse Plaintext

```
payload := JSON.parse(plaintext)
// payload conforms to encrypted_proof_payload.v1.json
// Verify: payload.bundle_id === bundle.bundle_id
```

---

## 8. Security Properties

### 8.1 Forward Secrecy

Each `viewer_keys` slot uses a fresh ephemeral X25519 keypair. Compromise of
a viewer's long-term Ed25519 key allows decryption of future bundles (until
key rotation), but does NOT retroactively expose past bundles unless the
attacker also obtained the ephemeral private keys (which are discarded after
key wrapping).

Note: this is "weak" forward secrecy (per-bundle ephemeral, not per-session).
True forward secrecy would require an interactive key exchange, which is
incompatible with offline bundle creation.

### 8.2 Key Separation

Each viewer receives an independently derived wrapping key:
- Independent ephemeral keypair (different `ephemeral_public_key_b64u`)
- Independent HKDF salt (includes both public keys)
- Independent AES-256-GCM wrapping (different `wrapped_key_iv_b64u`)

Compromise of one viewer's slot does not expose another viewer's wrapping key.
However, all viewers decrypt the same `content_key`, so any single viewer
compromise exposes the payload for that bundle.

### 8.3 No Plaintext in Public Layer

The encrypted payload contains ALL plaintext details. The public layer
contains ONLY:
- Hashes (args_hash_b64u, result_hash_b64u, request_hash_b64u, etc.)
- Structural metadata (tool_name, effect_class, provider, model)
- Timing (timestamp, latency_ms)
- DIDs (agent_did, signer_did)

Structural metadata (tool names, effect classes) is intentionally public — it
enables meaningful verification without decryption.

### 8.4 Ciphertext Binding

The AAD for payload encryption includes the `bundle_id`, preventing an attacker
from transplanting an encrypted payload from one bundle to another. The AAD
for key wrapping includes the `viewer_did`, preventing an attacker from
moving a wrapped key slot to a different viewer's DID.

### 8.5 Replay and Substitution Resistance

- **IV uniqueness.** Each bundle MUST use a fresh 12-byte CSPRNG IV. IV reuse
  with the same key breaks AES-GCM confidentiality and authenticity.
- **Content key uniqueness.** Each bundle MUST use a fresh 32-byte CSPRNG
  content key. Key reuse across bundles (even with different IVs) weakens
  the GCM construction and must be avoided.
- **Tag verification.** GCM authentication tags prevent both payload
  modification and ciphertext truncation.

---

## 9. Backward Compatibility

### 9.1 v1 Bundles in v2 Consumers

A v2-aware consumer (SDK, verifier, inspector) MUST accept v1 bundles
unchanged. A v1 bundle has:
- `bundle_version: "1"`
- No `schema_version`, `visibility`, `encrypted_payload`, or `viewer_keys`

The consumer treats this as `visibility: "public"` implicitly.

### 9.2 v2 Bundles in v1 Consumers

A v1-only consumer will reject a v2 bundle because:
- `bundle_version: "2"` does not match `const: "1"`
- Unknown properties `schema_version`, `visibility`, `encrypted_payload`,
  `viewer_keys` violate `additionalProperties: false`

This is the correct fail-closed behavior. v1 consumers SHOULD upgrade to the
v2 schema to process v2 bundles.

### 9.3 v2 Public Bundles

A v2 bundle with `visibility: "public"` (or absent visibility) and no
`encrypted_payload` is semantically identical to v1. The only difference is
`bundle_version: "2"` and optional `schema_version: "proof_bundle.v2"`.

### 9.4 Envelope Compatibility

The `proof_bundle_envelope.v1.json` wraps a proof bundle payload with a
signed envelope. A v2 proof bundle envelope SHOULD reference the v2 payload
schema. Existing v1 envelopes continue to work for v1 payloads.

---

## 10. Auditor Mode: Selective Disclosure

### 10.1 Concept

The `auditor` visibility mode provides selective disclosure: auditors see
enough to verify compliance without seeing sensitive content.

### 10.2 Redaction Rules

When producing an `auditor`-visibility bundle, the producer MUST apply
these redactions to the plaintext before encryption:

| Field | Auditor sees | Redacted |
|---|---|---|
| `tool_calls[].tool_name` | Yes | — |
| `tool_calls[].arguments` | No | Replaced with `{ "_redacted": true }` |
| `tool_calls[].result_summary` | No | Replaced with `"[REDACTED]"` |
| `commands[].command` | First token only | Arguments replaced with `[REDACTED]` |
| `commands[].exit_code` | Yes | — |
| `commands[].working_directory` | Directory depth only | e.g., `"[depth:3]"` |
| `file_operations[].operation` | Yes | — |
| `file_operations[].path` | Filename only | Directory components replaced |
| `file_operations[].size_bytes` | Yes | — |
| `network_connections[].remote_host` | Yes | — |
| `network_connections[].remote_port` | Yes | — |
| `network_connections[].protocol` | Yes | — |
| `network_connections[].url` | Host + path depth | Query params removed |
| `llm_interactions[].provider` | Yes | — |
| `llm_interactions[].model` | Yes | — |
| `llm_interactions[].prompt_summary` | No | Replaced with `"[REDACTED]"` |
| `llm_interactions[].completion_summary` | No | Replaced with `"[REDACTED]"` |
| `llm_interactions[].prompt_tokens` | Yes | — |
| `llm_interactions[].completion_tokens` | Yes | — |
| `llm_interactions[].cost_usd` | Yes | — |

### 10.3 Dual-Payload Bundles

When a bundle has both `owner`/`requester` AND `auditor` viewers, the producer
MUST encrypt TWO separate payloads is NOT supported in v1 of this spec
(single `encrypted_payload` field). Instead, the auditor viewer receives a
wrapped key for the same ciphertext, and the producer MUST apply auditor
redaction to the ENTIRE payload.

If full-detail access is needed for some viewers AND redacted access for
auditors in the same bundle, use `visibility: "requester"` and issue a
separate `auditor`-visibility bundle with the redacted payload. Producers
SHOULD link related bundles via matching `bundle_id` prefixes or a
`related_bundle_id` field in metadata.

---

## 11. Conformance Requirements

### 11.1 Producer Requirements

A conformant EPV producer MUST:

1. Generate `content_key` and `iv` from a CSPRNG (e.g., `crypto.getRandomValues`).
2. Generate one fresh ephemeral X25519 keypair per `viewer_keys` slot.
3. Discard ephemeral private keys after wrapping.
4. Canonicalize the plaintext via JCS (RFC 8785) before encryption.
5. Include `plaintext_hash_b64u` for decryption verification.
6. Set `key_derivation: "X25519-HKDF-SHA256"` on every viewer_key slot.
7. Use base64url without padding for all binary fields.
8. Populate `bundle_id` in the encrypted payload matching the outer bundle.

### 11.2 Consumer Requirements

A conformant EPV consumer MUST:

1. Reject bundles where `visibility` is non-public but `encrypted_payload`
   or `viewer_keys` is missing (fail-closed).
2. Reject bundles where `visibility` is `"public"` but `encrypted_payload`
   is present.
3. Verify `plaintext_hash_b64u` after decryption if present.
4. Verify `payload.bundle_id` matches the outer bundle's `bundle_id`.
5. Treat decryption failure as a hard error (do not fall back to partial data).

### 11.3 Verifier Requirements

A conformant verifier MUST:

1. Validate v2 schema when `schema_version: "proof_bundle.v2"` is present.
2. Check visibility/encrypted_payload/viewer_keys consistency (Section 6).
3. NOT attempt decryption.
4. Report EPV-specific reason codes (Section 6).

---

## 12. Security Considerations

### 12.1 Key Management

Viewer private keys MUST be stored with the same security as DID signing keys
(typically `~/.clawsecrets/` with `600` permissions). Key compromise allows
decryption of all bundles where the compromised DID appears in `viewer_keys`.

### 12.2 Bundle Size

Encrypted payloads increase bundle size. For a typical agent run with 50 tool
calls, the encrypted payload adds approximately 20-50 KB (compressed). Bundles
SHOULD NOT exceed 10 MB total. Producers MAY truncate `result_summary` and
`stdout_summary` fields to stay within limits.

### 12.3 Metadata Leakage

The `visibility` field itself is public. An observer can determine that a
bundle has encrypted content and how many viewers have access (from the length
of `viewer_keys`). The viewer DIDs are also public. This is by design — the
existence of encrypted content is not secret, only its content.

### 12.4 Quantum Considerations

X25519 ECDH and AES-256-GCM are not quantum-resistant. A future version of
this spec MAY introduce post-quantum key encapsulation (e.g., ML-KEM/Kyber).
For now, the 256-bit security level provides adequate protection against
classical attacks.

---

## Appendix A: Reference Implementation Notes

### Ed25519-to-X25519 Conversion

In Node.js with `@noble/curves`:

```ts
import { edwardsToMontgomeryPub, edwardsToMontgomeryPriv } from '@noble/curves/ed25519';

const x25519Pub = edwardsToMontgomeryPub(ed25519PublicKey);
const x25519Priv = edwardsToMontgomeryPriv(ed25519PrivateKey);
```

In libsodium:

```c
crypto_sign_ed25519_pk_to_curve25519(x25519_pk, ed25519_pk);
crypto_sign_ed25519_sk_to_curve25519(x25519_sk, ed25519_sk);
```

### HKDF-SHA256

In Node.js with `@noble/hashes`:

```ts
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';

const wrappingKey = hkdf(sha256, sharedSecret, salt, info, 32);
```

### AES-256-GCM

In Web Crypto API:

```ts
const key = await crypto.subtle.importKey('raw', contentKey, 'AES-GCM', false, ['encrypt']);
const ciphertext = await crypto.subtle.encrypt(
  { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
  key,
  plaintext
);
// Note: Web Crypto appends the tag to the ciphertext.
// Split: ciphertext_bytes = result.slice(0, -16), tag = result.slice(-16)
```
