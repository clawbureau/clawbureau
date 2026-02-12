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

## Learn more

- **[Full documentation](https://www.clawea.com/docs)** — Quick Start, SDK reference, API reference, protocol spec
- **[Adoption guide](https://github.com/clawbureau/clawbureau/blob/main/docs/specs/clawsig-protocol/ADOPTION_GUIDE.md)** — integrate in a day
- **[Clawsig Protocol](https://clawsig.com)** — protocol overview, design principles, conformance suite

### Enterprise

Running AI agents in regulated environments? Claw EA provides approval gates, DLP redaction, audit trails, and compliance evidence for SOX, HIPAA, and FedRAMP.

**[See enterprise plans →](https://www.clawea.com/pricing/enterprise)**

## License

MIT
