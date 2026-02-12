# @clawbureau/clawverify-core

Pure, offline-capable verification primitives for the **Clawsig Protocol**. Zero network dependencies — just cryptographic verification.

## Install

```bash
npm install @clawbureau/clawverify-core
```

## Usage

```ts
import { verifyProofBundle } from '@clawbureau/clawverify-core';

const bundle = JSON.parse(fs.readFileSync('run_xxx-bundle.json', 'utf-8'));
const result = verifyProofBundle(bundle);

console.log(result.status);      // 'PASS' or 'FAIL'
console.log(result.reason_code); // 'OK', 'SIGNATURE_INVALID', etc.
```

## What it verifies

- JSON schema validation (fail-closed on unknown versions)
- Ed25519 signature verification (did:key extraction)
- Event chain hash integrity (SHA-256)
- Tool receipt validation (version, algorithm, agent DID, required fields)
- Side-effect receipt validation (effect class, version, required fields)
- Human approval receipt validation (approval type, agent DID, required fields)
- Signer DID allowlist enforcement (optional, via config)
- Export bundle and log inclusion proof verification

## Fail-closed by design

Unknown schema versions, hash algorithms, or envelope formats produce `FAIL` — never silently pass.

## License

MIT
