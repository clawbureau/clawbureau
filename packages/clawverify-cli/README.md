# @clawbureau/clawverify-cli

Verify any **Clawsig Protocol** proof bundle offline in one command. No network access, no API keys, no trust assumptions — just cryptographic verification.

## Install

```bash
npm install -g @clawbureau/clawverify-cli
```

## Usage

### Verify a proof bundle

```bash
clawverify verify proof-bundle --input run_xxx-bundle.json
```

Output:
```json
{
  "status": "PASS",
  "reason_code": "OK",
  "component_results": {
    "schema_valid": true,
    "signature_valid": true,
    "hash_chain_valid": true,
    "tool_receipts_valid": true,
    "tool_receipts_count": 3,
    "side_effect_receipts_valid": true,
    "human_approval_receipts_valid": true
  }
}
```

### Verify a commit signature

```bash
clawverify verify commit-sig --input proofs/.../commit.sig.json
```

### Verify an export bundle

```bash
clawverify verify export-bundle --input identity-export.json
```

## Options

| Flag | Description |
|------|-------------|
| `--input <path>` | Path to the artifact to verify (required) |
| `--config <path>` | Path to verifier config file (optional) |
| `--urm <path>` | Path to URM file for proof bundle verification (optional, auto-detected) |
| `--json` | Output raw JSON (default: pretty-printed) |

## Verifier config

The config file controls which signer DIDs are trusted:

```json
{
  "version": 1,
  "trusted_signer_dids": [
    "did:key:z6Mk..."
  ],
  "require_receipt_binding": false,
  "max_event_chain_gap_ms": 86400000
}
```

Without a config file, the CLI performs structural verification only (schema, signatures, hash chains) without enforcing signer allowlists.

## What it verifies

| Artifact | Checks |
|----------|--------|
| **Proof bundle** | Schema validation, Ed25519 signature, event chain hash integrity, receipt binding, tool receipt validation, side-effect receipt validation, human approval receipt validation, signer DID allowlist |
| **Commit signature** | JCS-canonicalized envelope, Ed25519 signature, DID extraction, message format |
| **Export bundle** | Schema validation, signature chain, identity proofs |

## Fail-closed behavior

The verifier is fail-closed by design:
- Unknown schema versions → `FAIL` (`UNKNOWN_VERSION`)
- Unknown hash algorithms → `FAIL` (`UNKNOWN_HASH_ALGORITHM`)
- Missing required fields → `FAIL` (`SCHEMA_VALIDATION_FAILED`)
- Unknown envelope format → `FAIL` (`MALFORMED_ENVELOPE`)

This ensures that new artifact types can't bypass verification by exploiting parser leniency.

## Reason codes

All failures include a machine-readable `reason_code`. The full registry is at:
[`REASON_CODE_REGISTRY.md`](https://github.com/clawbureau/clawbureau/blob/main/docs/specs/clawsig-protocol/REASON_CODE_REGISTRY.md)

## Programmatic API

```ts
import { verifyProofBundle } from '@clawbureau/clawverify-core';

const result = verifyProofBundle(bundleJson, config);
if (result.status === 'FAIL') {
  console.error(`Verification failed: ${result.reason_code}`);
}
```

## Conformance

This CLI is tested against the Clawsig Protocol conformance suite (22 vectors). Run it yourself:

```bash
node scripts/protocol/run-clawsig-protocol-conformance.mjs
```

## License

MIT
