> **Type:** Protocol Spec
> **Status:** DRAFT
> **Version:** 1.0
> **Owner:** @clawbureau/core
> **Date:** 2026-02-12
> **Dependencies:** Clawsig Protocol v0.1, CLAWSIG_EIP8004_INTEGRATION_v1

# `.well-known/clawsig.json` Discovery Standard v1

## 0. Purpose

This document defines a standard discovery file that any domain can publish to advertise its Clawsig Protocol capabilities. The file follows the IETF `.well-known` URI convention (RFC 8615) and enables automated discovery of verification endpoints, policy services, and protocol capabilities.

---

## 1. Location

The file MUST be served at:

```
https://<domain>/.well-known/clawsig.json
```

**Requirements:**
- MUST be served over HTTPS (TLS required)
- MUST return `Content-Type: application/json`
- MUST return HTTP 200 on success
- SHOULD return HTTP 404 if the domain does not support Clawsig (absence is valid)
- MUST NOT require authentication to fetch (public discovery)
- SHOULD include `Cache-Control` headers (recommended: `max-age=3600`)

---

## 2. Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://schemas.clawbureau.org/well-known.clawsig.v1.json",
  "title": ".well-known/clawsig.json v1",
  "type": "object",
  "required": ["version"],
  "additionalProperties": false,
  "properties": {
    "version": {
      "const": "1",
      "description": "Schema version. Always '1' for this spec."
    },
    "verification_endpoint": {
      "type": "string",
      "format": "uri",
      "description": "URL of the clawverify API endpoint for bundle validation."
    },
    "policy_endpoint": {
      "type": "string",
      "format": "uri",
      "description": "URL of the WPC policy registry endpoint."
    },
    "capability_endpoint": {
      "type": "string",
      "format": "uri",
      "description": "URL of the CST (Capability Scoped Token) issuance endpoint."
    },
    "supported_receipt_types": {
      "type": "array",
      "items": {
        "type": "string",
        "enum": ["gateway", "tool", "side_effect", "human_approval", "web"]
      },
      "description": "Receipt classes this domain's agents emit."
    },
    "default_coverage": {
      "type": "string",
      "enum": ["M", "MT", "MTS"],
      "description": "Default coverage level for agents on this domain."
    },
    "conformance_version": {
      "type": "string",
      "pattern": "^[0-9]+$",
      "description": "Clawsig conformance test vector version supported."
    },
    "protocol_version": {
      "type": "string",
      "description": "Clawsig Protocol version supported (e.g. '0.1')."
    },
    "reason_code_registry": {
      "type": "string",
      "format": "uri",
      "description": "URL of the reason code registry this domain follows."
    },
    "agent_did": {
      "type": "string",
      "pattern": "^did:",
      "description": "Primary DID for the agent or service at this domain."
    },
    "eip8004": {
      "type": "object",
      "description": "EIP-8004 integration details, if the domain's agent is EIP-8004 registered.",
      "properties": {
        "agent_id": {
          "type": "string",
          "pattern": "^[0-9]+$",
          "description": "ERC-721 tokenId from EIP-8004 Identity Registry."
        },
        "registry": {
          "type": "string",
          "pattern": "^eip155:[0-9]+:0x[0-9a-fA-F]{40}$",
          "description": "CAIP-10 address of the EIP-8004 Identity Registry contract."
        },
        "agent_uri": {
          "type": "string",
          "format": "uri",
          "description": "URL of the EIP-8004 agent registration file."
        }
      }
    },
    "public_keys": {
      "type": "array",
      "description": "Public keys used by this domain for signing receipts and bundles.",
      "items": {
        "type": "object",
        "required": ["kid", "did"],
        "properties": {
          "kid": {
            "type": "string",
            "description": "Key identifier."
          },
          "did": {
            "type": "string",
            "pattern": "^did:key:",
            "description": "did:key representation of the public key."
          },
          "algorithm": {
            "type": "string",
            "enum": ["Ed25519"],
            "description": "Signing algorithm."
          },
          "use": {
            "type": "string",
            "enum": ["receipt-signing", "bundle-signing", "both"],
            "description": "What this key is used for."
          },
          "expires_at": {
            "type": "string",
            "format": "date-time",
            "description": "Key expiration time (optional)."
          }
        }
      }
    },
    "contact": {
      "type": "string",
      "description": "Contact email or URL for the domain operator."
    }
  }
}
```

---

## 3. Examples

### 3.1 Minimal: Agent Domain

An agent domain that supports Clawsig verification through the hosted clawverify service:

```json
{
  "version": "1",
  "verification_endpoint": "https://clawverify.com/v1/validate",
  "supported_receipt_types": ["gateway", "tool", "side_effect", "human_approval"],
  "default_coverage": "MTS",
  "conformance_version": "23",
  "protocol_version": "0.1"
}
```

### 3.2 Full: EIP-8004 Registered Agent

An agent with EIP-8004 on-chain identity, custom policy endpoint, and published keys:

```json
{
  "version": "1",
  "verification_endpoint": "https://clawverify.com/v1/validate",
  "policy_endpoint": "https://clawea.com/v1/policies",
  "capability_endpoint": "https://clawea.com/v1/capabilities",
  "supported_receipt_types": ["gateway", "tool", "side_effect", "human_approval"],
  "default_coverage": "MTS",
  "conformance_version": "23",
  "protocol_version": "0.1",
  "reason_code_registry": "https://clawprotocol.org/reason-codes",
  "agent_did": "did:key:z6MktzmKpfCNcKSUp7qzTrZK3c89QFvhgmK7V1GXxMH9m8XW",
  "eip8004": {
    "agent_id": "673",
    "registry": "eip155:1:0x1234567890abcdef1234567890abcdef12345678",
    "agent_uri": "https://acme-agent.example.com/agent.json"
  },
  "public_keys": [
    {
      "kid": "primary-2026",
      "did": "did:key:z6MktzmKpfCNcKSUp7qzTrZK3c89QFvhgmK7V1GXxMH9m8XW",
      "algorithm": "Ed25519",
      "use": "both"
    }
  ],
  "contact": "security@acme-agent.example.com"
}
```

### 3.3 Verification Service Domain

clawverify.com itself publishing its own discovery file:

```json
{
  "version": "1",
  "verification_endpoint": "https://clawverify.com/v1/validate",
  "supported_receipt_types": ["gateway", "tool", "side_effect", "human_approval", "web"],
  "conformance_version": "23",
  "protocol_version": "0.1",
  "reason_code_registry": "https://clawprotocol.org/reason-codes",
  "contact": "https://clawverify.com/support"
}
```

### 3.4 Enterprise with Self-Hosted Verifier

An enterprise running their own clawverify instance:

```json
{
  "version": "1",
  "verification_endpoint": "https://verify.internal.corp.example.com/v1/validate",
  "policy_endpoint": "https://policy.internal.corp.example.com/v1/policies",
  "capability_endpoint": "https://auth.internal.corp.example.com/v1/capabilities",
  "supported_receipt_types": ["gateway", "tool", "side_effect", "human_approval"],
  "default_coverage": "MTS",
  "conformance_version": "23",
  "protocol_version": "0.1"
}
```

---

## 4. Discovery Flow

### 4.1 Client Discovery Algorithm

When a client (agent, marketplace, CI system) wants to discover Clawsig capabilities for a domain:

```
1. Extract domain from agent identity or service URL
2. Fetch GET https://<domain>/.well-known/clawsig.json
3. If 200: parse JSON, validate against schema
4. If 404: domain does not advertise Clawsig support (not an error)
5. If other error: retry with backoff, then treat as unsupported
```

### 4.2 Caching

Clients SHOULD cache the discovery file according to HTTP cache headers. Recommended minimum cache: 1 hour. Recommended maximum: 24 hours.

### 4.3 Validation

Clients MUST validate the discovery file against the schema in section 2 before using it. Unknown fields MUST be ignored (forward compatibility). Missing optional fields MUST NOT cause errors.

---

## 5. Relationship to EIP-8004

The `.well-known/clawsig.json` file complements the EIP-8004 agent registration file:

| Mechanism | Purpose | Location |
|-----------|---------|----------|
| EIP-8004 registration file | Declares agent identity, capabilities, trust models | At `agentURI` (any URL) |
| `.well-known/clawsig.json` | Declares domain-level Clawsig capabilities | `https://<domain>/.well-known/clawsig.json` |

An EIP-8004 registration file's `clawsig.discoveryUrl` SHOULD point to the `.well-known/clawsig.json` file. This creates a two-level discovery:

1. **Agent-level:** EIP-8004 registration file declares per-agent Clawsig support
2. **Domain-level:** `.well-known/clawsig.json` declares domain-wide defaults and endpoints

When both exist, per-agent settings in the EIP-8004 registration file take precedence over domain-level defaults.

---

## 6. Security Considerations

### 6.1 TLS Required

The file MUST be served over HTTPS. HTTP-only responses MUST be rejected by clients.

### 6.2 No Authentication

The file is public and MUST NOT require authentication. It contains discovery metadata, not secrets.

### 6.3 Content Integrity

For high-security deployments, the domain MAY sign the discovery file:
- Include a `_signature` field (not in schema, treated as extension)
- Sign the JCS-canonicalized file (excluding `_signature`) with the domain's DID key
- Clients that require signed discovery can verify against `public_keys[].did`

### 6.4 Key Rotation

When rotating keys listed in `public_keys[]`:
1. Add the new key to the array
2. Keep the old key until all outstanding receipts signed with it have been verified
3. Remove the old key after the grace period
4. Update `expires_at` on old keys to signal deprecation

---

## 7. IANA Considerations

If this standard achieves broad adoption, the `.well-known/clawsig.json` URI suffix SHOULD be registered with IANA per RFC 8615:

- **URI suffix:** `clawsig.json`
- **Change controller:** Claw Bureau / Clawsig Protocol maintainers
- **Specification document:** This document
- **Related information:** Clawsig Protocol v0.1
