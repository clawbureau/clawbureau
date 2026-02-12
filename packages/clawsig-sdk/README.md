# @clawbureau/clawsig-sdk

Lightweight SDK for emitting **verifiable proof bundles** from any Node.js agent. Five lines to go from raw LLM calls to a cryptographically signed, offline-verifiable evidence pack.

## Quickstart

```ts
import { createClawsigRun } from '@clawbureau/clawsig-sdk';

const run = await createClawsigRun({
  agentDid: 'did:key:z6Mk...',       // Your agent's DID
  proxyUrl: 'https://proxy.example.com',
  keyFile: '.clawsig-key.json',       // Ed25519 JWK
});

// Record an LLM call
const response = await run.callLLM({
  model: 'claude-sonnet-4-20250514',
  messages: [{ role: 'user', content: 'Explain proof bundles' }],
});

// Finalize → signed proof bundle + URM
const bundle = await run.finalize();
console.log(bundle.path); // artifacts/poh/.../run_xxx-bundle.json
```

## What it records

| Method | Receipt type | Coverage level |
|--------|-------------|----------------|
| `callLLM()` | Gateway receipt | M (model) |
| `recordToolCall()` | Tool receipt | MT (model + tools) |
| `recordSideEffect()` | Side-effect receipt | MTS (+ side-effects) |
| `recordHumanApproval()` | Human approval receipt | MTS (+ approvals) |
| `finalize()` | Proof bundle + URM | — |

## API

### `createClawsigRun(options)`

Creates a new proof run. Options:

```ts
interface ClawsigRunOptions {
  agentDid: string;          // Agent DID (did:key:...)
  proxyUrl: string;          // Clawsig proxy URL
  keyFile?: string;          // Path to Ed25519 JWK key file
  outputDir?: string;        // Output directory (default: artifacts/poh/<branch>/)
  branchName?: string;       // Git branch name for output path
}
```

### `run.callLLM(params)`

Proxies an LLM call through the gateway and records a gateway receipt.

```ts
const response = await run.callLLM({
  model: 'claude-sonnet-4-20250514',
  messages: [{ role: 'user', content: '...' }],
  // All standard OpenAI-compatible params supported
});
```

### `run.recordToolCall(params)`

Records a tool invocation as a hash-only receipt (arguments and results are digested, not stored).

```ts
run.recordToolCall({
  tool_name: 'file_read',
  args_digest: 'sha256:abc123...',    // SHA-256 of JSON-serialized args
  result_digest: 'sha256:def456...',  // SHA-256 of JSON-serialized result
  duration_ms: 42,
});
```

### `run.recordSideEffect(params)`

Records a side-effect (network call, file write, external API write).

```ts
run.recordSideEffect({
  effect_class: 'network_egress',     // or 'filesystem_write', 'external_api_write'
  target_digest: 'sha256:...',        // Digest of target URL/path
  request_digest: 'sha256:...',
  response_digest: 'sha256:...',
  vendor_id: 'api.github.com',
  bytes_written: 1024,
});
```

### `run.recordHumanApproval(params)`

Records a human approval decision that gates capability minting.

```ts
run.recordHumanApproval({
  approval_type: 'explicit_approve',  // or 'explicit_deny', 'auto_approve', 'timeout_deny'
  scope_hash_b64u: '...',             // Scope being approved
  plan_hash_b64u: '...',              // Hash of the proposed plan
  approver_subject: 'user@example.com',
  capability_minted: true,
});
```

### `run.finalize()`

Finalizes the run, signs the proof bundle, and writes all artifacts.

Returns:
```ts
interface FinalizeResult {
  path: string;           // Path to proof bundle JSON
  urmPath: string;        // Path to URM (Universal Receipt Manifest)
  trustPulsePath: string; // Path to trust pulse
  runId: string;          // Run UUID
  eventCount: number;     // Number of events in the chain
  receiptCount: number;   // Number of gateway receipts
}
```

## Verification

Proof bundles produced by this SDK can be verified offline with:

```bash
npx @clawbureau/clawverify-cli verify proof-bundle --input run_xxx-bundle.json
```

Or programmatically:

```ts
import { verifyProofBundle } from '@clawbureau/clawverify-core';
const result = verifyProofBundle(bundleJson, config);
// result.status === 'PASS' | 'FAIL'
```

## Coverage levels

The Clawsig Protocol defines three coverage levels:

- **M** (Model): Gateway receipts prove which model was called
- **MT** (Model + Tools): Tool receipts prove which tools were invoked
- **MTS** (Model + Tools + Side-effects): Side-effect and human approval receipts prove what external effects occurred and who approved them

## License

MIT
