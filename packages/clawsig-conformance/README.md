# @clawbureau/clawsig-conformance

Conformance test runner and GitHub Action for the **Clawsig Inside** program.

Validates that AI agent frameworks emit correct [Clawsig Protocol](https://clawsig.com) proof bundles. Frameworks that pass earn the "Clawsig Inside" badge and are listed in the [Clawsig Directory](https://clawsig.com/directory).

## What the Conformance Test Checks

1. **Mock proxy** -- starts a local HTTP server mimicking OpenAI/Anthropic APIs
2. **Agent spawn** -- runs your agent command with env vars pointing at the mock proxy
3. **Bundle discovery** -- looks for `.clawsig/proof_bundle.json` in the working directory
4. **Cryptographic verification** -- verifies the bundle using `@clawbureau/clawverify-core` (Ed25519 signatures, hash chain integrity, receipt validation)
5. **Tier check** -- confirms the proof tier meets your expected minimum

### Result fields

| Field | Description |
|---|---|
| `passed` | Overall pass/fail |
| `bundle_found` | Was a proof bundle found at the expected path? |
| `bundle_valid` | Did the bundle pass cryptographic verification? |
| `tier` | Detected proof tier (`self`, `gateway`, `sandbox`, `tee`) |
| `tier_meets_expected` | Does the detected tier meet your minimum? |
| `event_chain_length` | Number of events in the proof bundle event chain |
| `receipt_count` | Total receipts (gateway + tool + side-effect + human approval) |
| `errors` | List of human-readable error messages |

## Quick Start (GitHub Action)

Add to your CI workflow:

```yaml
name: Clawsig Conformance
on: [push, pull_request]

jobs:
  conformance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm ci

      - name: Clawsig Conformance Test
        uses: clawbureau/clawsig-conformance-action@v1
        with:
          agent_command: 'npm run test:agent'
          expected_tier: 'self'
          timeout: '60'
```

### Action Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `agent_command` | Yes | -- | Command to run your agent |
| `expected_tier` | No | `self` | Minimum proof tier (`self`, `gateway`, `sandbox`, `tee`) |
| `timeout` | No | `60` | Timeout in seconds |
| `output_path` | No | `.clawsig/proof_bundle.json` | Where the agent writes its proof bundle |

### Action Outputs

| Output | Description |
|---|---|
| `passed` | `true` or `false` |
| `tier` | Detected tier or `none` |
| `bundle_found` | `true` or `false` |
| `bundle_valid` | `true` or `false` |
| `event_chain_length` | Number of events |
| `receipt_count` | Number of receipts |

## Quick Start (Programmatic)

```typescript
import { runConformanceTest } from '@clawbureau/clawsig-conformance';

const result = await runConformanceTest({
  agentCommand: 'node my-agent.js',
  expectedTier: 'self',
  timeout: 60,
});

console.log(result.passed);    // true/false
console.log(result.tier);      // 'self', 'gateway', etc.
console.log(result.errors);    // [] if passed
```

## How It Works

1. Starts a **mock LLM proxy** on a random local port
2. Sets `OPENAI_BASE_URL` and `ANTHROPIC_BASE_URL` to point at the mock
3. Spawns your agent command as a child process
4. The mock returns canned responses and emits mock gateway receipts via `X-Clawsig-Receipt`
5. On agent exit, reads `.clawsig/proof_bundle.json`
6. Verifies the bundle cryptographically with `@clawbureau/clawverify-core`
7. Checks the proof tier against your expected minimum

The mock proxy is fully self-contained -- **no external network calls**.

### Environment Variables Set by the Runner

| Variable | Value |
|---|---|
| `OPENAI_BASE_URL` | `http://127.0.0.1:{port}/v1/proxy/openai` |
| `OPENAI_API_BASE` | Same as above (legacy) |
| `ANTHROPIC_BASE_URL` | `http://127.0.0.1:{port}/v1/proxy/anthropic` |
| `CLAWSIG_CONFORMANCE_TEST` | `1` |
| `CLAWSIG_MOCK_PROXY_URL` | `http://127.0.0.1:{port}` |
| `CLAWSIG_MOCK_PROXY_PORT` | `{port}` |

## Earning the "Clawsig Inside" Badge

1. **Integrate** `@clawbureau/clawsig-sdk` (or `npx clawsig wrap`) so your framework emits proof bundles
2. **Add the conformance test** to your CI using the GitHub Action
3. **Pass the test** -- the Action submits a certification claim
4. **Get listed** on [clawsig.com/directory](https://clawsig.com/directory):

```markdown
[![Clawsig Inside](https://api.clawverify.com/v1/badges/conformance/gateway.svg)](https://clawsig.com/directory)
```

### Tier Levels

| Tier | What it proves |
|---|---|
| `self` | Agent signs its own proof bundle (DID + Ed25519) |
| `gateway` | LLM calls routed through a trusted gateway with independent receipts |
| `sandbox` | Agent ran in an isolated sandbox with attestations |
| `tee` | Agent ran in a Trusted Execution Environment (hardware attestation) |

### Certification Lifecycle

- **Verified** -- passes conformance, listed in directory
- **Expired** -- no passing run in 90 days
- **Revoked** -- manual revocation (policy violation)

## Schemas

- Conformance Claim: [`packages/schema/certification/conformance_claim.v1.json`](../schema/certification/conformance_claim.v1.json)
- Directory Entry: [`packages/schema/certification/directory_entry.v1.json`](../schema/certification/directory_entry.v1.json)

## License

MIT
