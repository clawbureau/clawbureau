# @clawbureau/clawproof-adapters

External harness adapters for Proof-of-Harness (PoH). Wrapper scripts and a shared runtime that route LLM calls through clawproxy and produce verifiable proof bundles from external agent harnesses.

## Supported Harnesses

| Harness | ID | Proxy Env Var |
|---------|-----|---------------|
| Claude Code | `claude-code` | `ANTHROPIC_BASE_URL` |
| Codex | `codex` | `OPENAI_BASE_URL` |
| Pi | `pi` | `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL` |
| Opencode | `opencode` | `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL` |
| Factory Droid | `factory-droid` | `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL` |

## Quick Start

### 1. Set up environment

```bash
export CLAWPROOF_PROXY_URL=https://proxy.clawbureau.com
export CLAWPROOF_PROXY_TOKEN=your-token  # optional
```

### 2. Run with wrapper

```bash
# Generic wrapper (specify harness ID)
clawproof-wrap claude-code -- claude "fix the bug in auth.ts"

# Or use the convenience scripts
clawproof-claude-code -- claude "fix the bug in auth.ts"
clawproof-codex -- codex "implement the feature"
clawproof-pi -- pi "run the tests"
clawproof-opencode -- opencode "refactor the module"
clawproof-factory-droid -- factory-droid run --task "build feature"
```

### 3. Proof artifacts

After the run completes, proof artifacts are written to `.clawproof/`:

```
.clawproof/
  run_<uuid>-bundle.json   # Signed proof bundle (SignedEnvelope<ProofBundlePayload>)
  run_<uuid>-urm.json      # Universal Run Manifest
```

## How It Works

1. **Shim routing**: The wrapper starts a local shim HTTP server and sets provider base URL env vars (`ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`) to point to it. The harness CLI talks to the shim using normal OpenAI/Anthropic SDK requests.

2. **Gateway forwarding + PoH binding**: The shim forwards each request to `clawproxy`. For non-streaming calls it uses the shared session runtime (`session.proxyLLMCall()`); for streaming/SSE calls it forwards the response body without buffering. In both cases it injects PoH binding headers (`X-Run-Id`, `X-Event-Hash`, `X-Idempotency-Key`).

3. **Receipt collection**: `clawproxy` issues canonical signed `_receipt_envelope` objects. For JSON responses these are returned as fields; for streaming/SSE responses they are delivered as SSE comment trailers (which the shim strips from the harness-facing stream while recording the receipts for the proof bundle).

4. **Event chain**: The adapter records `run_start`/`tool_call`/`run_end` plus one `llm_call` event per model request into a hash-linked event chain (SHA-256, deterministic key order per PoH Adapter Spec §4.2).

5. **Proof bundle**: On completion, the adapter assembles a `SignedEnvelope<ProofBundlePayload>` containing the event chain, receipts, URM reference, and harness metadata — signed with the agent's Ed25519 DID key.

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `CLAWPROOF_PROXY_URL` | Yes | — | clawproxy base URL |
| `CLAWPROOF_PROXY_TOKEN` | No | — | Bearer token for proxy auth |
| `CLAWPROOF_KEY_FILE` | No | `.clawproof-key.json` | Path to Ed25519 JWK key file |
| `CLAWPROOF_OUTPUT_DIR` | No | `.clawproof/` | Directory for proof artifacts |

## Key Management

On first run, the adapter generates an Ed25519 key pair and saves it as a JWK file (default: `.clawproof-key.json`). The agent DID is derived from the public key: `did:key:z<base58btc(0xed01 + pubkey)>`.

To use an existing key, set `CLAWPROOF_KEY_FILE` to the path of a JWK file containing `{ publicKey, privateKey }`.

## Programmatic Usage

```typescript
import { createSession, getAdapter, generateKeyPair } from '@clawbureau/clawproof-adapters';

const keyPair = await generateKeyPair();
const adapter = getAdapter('claude-code')!;

const session = await createSession({
  proxyBaseUrl: 'https://proxy.clawbureau.com',
  keyPair,
  harness: adapter.HARNESS,
});

// Record events
await session.recordEvent({ eventType: 'run_start', payload: { task: 'fix bug' } });

// Proxy an LLM call (routes through clawproxy, collects receipt)
const result = await session.proxyLLMCall({
  provider: 'anthropic',
  model: 'claude-sonnet-4-5-20250929',
  body: { messages: [{ role: 'user', content: 'Hello' }], max_tokens: 100 },
});

await session.recordEvent({ eventType: 'run_end', payload: { status: 'ok' } });

// Finalize — produces signed proof bundle + URM
const proof = await session.finalize({
  inputs: [{ type: 'task', hashB64u: '...' }],
  outputs: [{ type: 'patch', hashB64u: '...' }],
});

console.log(JSON.stringify(proof.envelope, null, 2));
```

## Architecture

```
packages/clawproof-adapters/
├── bin/                           # Shell wrapper scripts
│   ├── clawproof-wrap.sh          # Generic wrapper (harness-id -- command)
│   ├── clawproof-claude-code.sh   # Claude Code convenience wrapper
│   ├── clawproof-codex.sh         # Codex convenience wrapper
│   ├── clawproof-pi.sh            # Pi convenience wrapper
│   ├── clawproof-opencode.sh      # Opencode convenience wrapper
│   └── clawproof-factory-droid.sh # Factory Droid convenience wrapper
├── src/
│   ├── index.ts                   # Package entry point + exports
│   ├── types.ts                   # All type definitions
│   ├── crypto.ts                  # Ed25519, SHA-256, DID, JWK utilities
│   ├── session.ts                 # Core adapter session runtime
│   ├── shim.ts                    # Local shim HTTP server for base URL overrides
│   ├── cli.ts                     # CLI runner (orchestrates lifecycle)
│   └── adapters/
│       ├── index.ts               # Adapter registry
│       ├── claude-code.ts         # Claude Code adapter
│       ├── codex.ts               # Codex adapter
│       ├── pi.ts                  # Pi adapter
│       ├── opencode.ts            # Opencode adapter
│       └── factory-droid.ts       # Factory Droid adapter
└── package.json
```

## Relationship to Other Packages

- **@openclaw/provider-clawproxy**: The reference OpenClaw plugin (POH-US-005/006). This adapter package provides the same proof bundle capabilities for non-OpenClaw harnesses.
- **packages/schema/poh/**: JSON schemas for proof bundles, event chains, URMs. The adapter output conforms to these schemas.
- **services/clawverify**: Verifies proof bundles produced by these adapters.
- **services/clawproxy**: The proxy that receipts LLM calls.
