> **Type:** Guide
> **Status:** CANONICAL
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-12
> **Source of truth:** `packages/clawsig-sdk/`, `packages/clawverify-cli/`, `packages/clawverify-core/`
>
> **Scope:**
> - How to integrate the Clawsig Protocol into third-party agents, CI/CD, and security tooling.
> - Not a replacement for the protocol spec — see `CLAWSIG_PROTOCOL_v0.1.md` for normative definitions.

# Clawsig Protocol — Adoption Guide

> How to integrate verifiable proof bundles into your agent framework, CI/CD pipeline, or enterprise security stack in a day.

## Table of contents

1. [For agent framework authors](#1-for-agent-framework-authors)
2. [For enterprise security teams](#2-for-enterprise-security-teams)
3. [For CI/CD pipelines](#3-for-cicd-pipelines)
4. [For identity (BYO identity)](#4-for-identity-byo-identity)
5. [Conformance testing](#5-conformance-testing)
6. [Architecture overview](#6-architecture-overview)

---

## 1. For agent framework authors

You have an agent framework that calls LLMs, invokes tools, and produces side-effects. You want every run to emit a cryptographically signed proof bundle that anyone can verify offline.

### Step 1: Install the SDK

```bash
npm install @clawbureau/clawsig-sdk
```

### Step 2: Wrap your LLM dispatcher

Replace direct LLM API calls with `run.callLLM()`. This routes calls through the clawsig proxy, which records gateway receipts.

```ts
import { createClawsigRun } from '@clawbureau/clawsig-sdk';

// At the start of each agent session
const run = await createClawsigRun({
  agentDid: agent.did,
  proxyUrl: process.env.CLAWSIG_PROXY_URL,
  keyFile: '.clawsig-key.json',
});

// Replace: const response = await llm.chat(messages);
// With:
const response = await run.callLLM({
  model: 'claude-sonnet-4-20250514',
  messages,
});
```

### Step 3: Wrap your tool dispatcher

After each tool invocation, call `recordToolCall()`. Arguments and results are hashed — raw content never enters the proof bundle.

```ts
import { createHash } from 'node:crypto';

function sha256(data: string): string {
  return 'sha256:' + createHash('sha256').update(data).digest('hex');
}

// In your tool dispatcher:
const toolResult = await executeTool(toolName, toolArgs);

run.recordToolCall({
  tool_name: toolName,
  args_digest: sha256(JSON.stringify(toolArgs)),
  result_digest: sha256(JSON.stringify(toolResult)),
  duration_ms: elapsed,
});
```

### Step 4: Record side-effects (optional, Coverage MTS)

If your agent makes network calls, writes files, or calls external APIs:

```ts
run.recordSideEffect({
  effect_class: 'network_egress', // or 'filesystem_write', 'external_api_write'
  target_digest: sha256(targetUrl),
  request_digest: sha256(requestBody),
  response_digest: sha256(responseBody),
  vendor_id: 'api.github.com',
  bytes_written: responseBody.length,
});
```

### Step 5: Record human approvals (optional, Coverage MTS)

If your agent has a human-in-the-loop approval gate:

```ts
run.recordHumanApproval({
  approval_type: 'explicit_approve', // or 'explicit_deny', 'auto_approve', 'timeout_deny'
  scope_hash_b64u: scopeHash,
  plan_hash_b64u: planHash,
  approver_subject: 'user@company.com',
  capability_minted: true,
});
```

### Step 6: Finalize

At session end, finalize to produce the signed proof bundle:

```ts
const result = await run.finalize();
// result.path → artifacts/poh/.../run_xxx-bundle.json
// result.urmPath → .../run_xxx-urm.json (Universal Receipt Manifest)
```

### Coverage levels

| Level | What's proven | Methods needed |
|-------|---------------|----------------|
| **M** | Which model was called, when, by whom | `callLLM` + `finalize` |
| **MT** | + which tools were invoked | + `recordToolCall` |
| **MTS** | + what side-effects occurred, who approved them | + `recordSideEffect` + `recordHumanApproval` |

You can start at **M** and incrementally add coverage. Each level is additive.

---

## 2. For enterprise security teams

You receive proof bundles from agent runs and want to verify them as part of your audit/compliance pipeline.

### Offline verification (no network required)

```bash
# Install the verifier
npm install -g @clawbureau/clawverify-cli

# Verify a single proof bundle
clawverify verify proof-bundle --input run_xxx-bundle.json

# Verify with a trusted signer allowlist
clawverify verify proof-bundle --input run_xxx-bundle.json --config verifier-config.json
```

### Verifier config for your organization

Create a config file that allowlists your organization's signer DIDs:

```json
{
  "version": 1,
  "trusted_signer_dids": [
    "did:key:z6MkYourProductionSignerDID...",
    "did:key:z6MkYourStagingSignerDID..."
  ],
  "require_receipt_binding": false,
  "max_event_chain_gap_ms": 86400000
}
```

Without this config, the verifier still checks structural integrity (schema, signatures, hash chains) but doesn't enforce a signer allowlist.

### SIEM/GRC integration

The proof bundle is a self-contained JSON file. Feed it to your SIEM as structured data:

```json
{
  "proof_bundle_version": "0.1.0",
  "run_id": "run_xxx",
  "agent_did": "did:key:z6Mk...",
  "events": [ /* hash-chained event sequence */ ],
  "receipts": [ /* gateway receipts from proxy */ ],
  "tool_receipts": [ /* hash-only tool invocation records */ ],
  "side_effect_receipts": [ /* hash-only side-effect records */ ],
  "human_approval_receipts": [ /* approval decisions */ ],
  "signature": "base58-ed25519-sig"
}
```

Key fields for SIEM rules:
- `agent_did` — who ran the agent
- `events[].event_type` — what happened (llm_call, tool_call, etc.)
- `tool_receipts[].tool_name` — which tools were invoked
- `side_effect_receipts[].effect_class` — what external effects occurred
- `human_approval_receipts[].approval_type` — who approved what

### Batch verification

```bash
# Verify all proof bundles in a directory
find artifacts/poh -name '*-bundle.json' -exec clawverify verify proof-bundle --input {} \;
```

### Programmatic verification (Node.js)

```ts
import { verifyProofBundle } from '@clawbureau/clawverify-core';
import fs from 'node:fs';

const bundle = JSON.parse(fs.readFileSync('run_xxx-bundle.json', 'utf-8'));
const config = JSON.parse(fs.readFileSync('verifier-config.json', 'utf-8'));

const result = verifyProofBundle(bundle, config);
if (result.status === 'FAIL') {
  console.error(`FAIL: ${result.reason_code}`);
  // Forward to incident response
}
```

---

## 3. For CI/CD pipelines

Add proof bundle verification as a quality gate on pull requests — just like we do on the Clawbureau monorepo itself.

### GitHub Actions: Claw Verified PR check

Add this workflow to your repository:

```yaml
# .github/workflows/clawsig-verified-pr.yml
name: clawsig-verified-pr

on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install clawverify
        run: npm install -g @clawbureau/clawverify-cli

      - name: Verify proof bundles
        run: |
          BUNDLES=$(find artifacts/poh -name '*-bundle.json' 2>/dev/null)
          if [ -z "$BUNDLES" ]; then
            echo "No proof bundles found — skipping verification"
            exit 0
          fi
          FAIL=0
          for bundle in $BUNDLES; do
            echo "Verifying: $bundle"
            if ! clawverify verify proof-bundle --input "$bundle"; then
              FAIL=1
            fi
          done
          exit $FAIL

      - name: Verify commit signatures
        run: |
          SIGS=$(find proofs -name 'commit.sig.json' 2>/dev/null)
          if [ -z "$SIGS" ]; then
            echo "No commit signatures found — skipping"
            exit 0
          fi
          for sig in $SIGS; do
            echo "Verifying: $sig"
            clawverify verify commit-sig --input "$sig"
          done
```

### Observe vs. enforce mode

- **Observe mode** (default): The check runs but doesn't block merges. Use this while onboarding.
- **Enforce mode**: Add `clawsig-verified-pr` as a required status check on your default branch.

Our own repository uses enforce mode. See [CLAW_VERIFIED_PR_PIPELINE.md](../foundations/CLAW_VERIFIED_PR_PIPELINE.md) for the full setup.

### Working example

This repository is itself a working example of the pipeline:
- Workflow: [`.github/workflows/clawsig-verified-pr.yml`](../../.github/workflows/clawsig-verified-pr.yml)
- Runner script: [`scripts/protocol/run-clawsig-verified-pr.mjs`](../../scripts/protocol/run-clawsig-verified-pr.mjs)
- Verifier config: [`packages/schema/fixtures/clawverify.config.clawbureau.v1.json`](../../packages/schema/fixtures/clawverify.config.clawbureau.v1.json)

---

## 4. For identity (BYO identity)

The Clawsig Protocol doesn't require DID migration. It supports multiple identity formats:

| Format | Example | Use case |
|--------|---------|----------|
| `did:key:z6Mk...` | Decentralized identifier | Cross-org verification |
| OIDC subject | `https://accounts.google.com\|12345` | Enterprise SSO |
| Service account | `sa:production-agent@company.iam` | Cloud-native agents |
| Email | `agent@company.com` | Simple setups |
| GitHub | `github:org/repo` | CI/CD pipelines |

### How identity binds to receipts

- **Agent DID** (`agent_did` field): Signs the proof bundle. Must be a `did:key` for Ed25519 signature verification.
- **Approver subject** (`approver_subject` field): The human who approved an action. Can be any supported format — maps to the CST `sub` claim.
- **CST subject** (`sub` claim): The token subject. Supports all formats above.

### If you already use OIDC

Your existing OIDC subjects map directly to the `approver_subject` field in human approval receipts. No DID migration needed for human approvers.

For the **agent identity** (the `agent_did` field), you do need a `did:key` — but this is just an Ed25519 keypair generated once per agent:

```bash
# Generate a key (one-time setup)
node -e "
  const { generateKeyPairSync } = require('node:crypto');
  const kp = generateKeyPairSync('ed25519');
  const jwk = kp.privateKey.export({ format: 'jwk' });
  console.log(JSON.stringify(jwk));
" > .clawsig-key.json
```

---

## 5. Conformance testing

If you're implementing your own verifier or SDK, validate against the Clawsig Protocol conformance suite.

### Conformance vectors

The suite includes 22 test vectors covering:

| Category | Vectors | Tests |
|----------|---------|-------|
| Proof bundles | 10 | Valid bundle, wrong signer, missing field, unknown hash algorithm, empty event chain, tool receipt failures, side-effect failures, human approval failures |
| Export bundles | 3 | Valid, tampered, wrong version |
| Commit signatures | 5 | Valid, tampered message, bad DID, unknown version, invalid message |
| Tool receipts | 2 | Bad version, agent DID mismatch |
| Side-effect receipts | 1 | Bad effect class |
| Human approval receipts | 1 | Bad approval type |

### Running the suite

```bash
# Clone the repo
git clone https://github.com/clawbureau/clawbureau
cd clawbureau

# Install deps
cd packages/clawverify-core && npm ci && npm run build && cd ../..
cd packages/clawverify-cli && npm ci && npm run build && cd ../..

# Run conformance
node scripts/protocol/run-clawsig-protocol-conformance.mjs
```

Output: `artifacts/conformance/clawsig-protocol/<timestamp>/summary.json`

### Vector format

Each vector is a JSON file in `packages/schema/fixtures/protocol-conformance/`:

```json
{
  "vector_id": "proof_bundle_valid_minimal",
  "kind": "proof_bundle",
  "expected_status": "PASS",
  "expected_reason_code": "OK",
  "input": { /* the artifact to verify */ }
}
```

The manifest at `packages/schema/fixtures/protocol-conformance/manifest.v1.json` lists all vectors with their expected outcomes.

---

## 6. Architecture overview

```
┌─────────────────────────────────────────────────────────┐
│                    Agent Framework                       │
│                                                         │
│  ┌──────────┐  ┌──────────────┐  ┌────────────────┐    │
│  │ callLLM  │  │recordToolCall│  │recordSideEffect│    │
│  └────┬─────┘  └──────┬───────┘  └───────┬────────┘    │
│       │               │                  │              │
│  ┌────▼───────────────▼──────────────────▼────────┐     │
│  │              ClawsigRun (SDK)                   │    │
│  │  • Event chain (hash-linked)                    │    │
│  │  • Receipt collection                           │    │
│  │  • Ed25519 signing                              │    │
│  └──────────────────┬─────────────────────────────┘     │
│                     │ finalize()                        │
│                     ▼                                   │
│  ┌─────────────────────────────────────────────────┐    │
│  │              Proof Bundle (JSON)                 │    │
│  │  • Signed event chain                           │    │
│  │  • Gateway receipts                             │    │
│  │  • Tool receipts (hash-only)                    │    │
│  │  • Side-effect receipts (hash-only)             │    │
│  │  • Human approval receipts                      │    │
│  └─────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│                    Verification                          │
│                                                         │
│  clawverify verify proof-bundle --input bundle.json     │
│                                                         │
│  Checks:                                                │
│    ✓ JSON schema validation (fail-closed on unknown)    │
│    ✓ Ed25519 signature verification                     │
│    ✓ Event chain hash integrity                         │
│    ✓ Tool receipt validation                            │
│    ✓ Side-effect receipt validation                     │
│    ✓ Human approval receipt validation                  │
│    ✓ Signer DID allowlist (if config provided)          │
│                                                         │
│  Output: { status: "PASS"|"FAIL", reason_code: "..." }  │
└─────────────────────────────────────────────────────────┘
```

### Key design principles

1. **Offline by default**: Verification requires zero network access. The proof bundle is self-contained.
2. **Fail-closed**: Unknown versions, algorithms, or fields → FAIL. No silent pass-through.
3. **Hash-only privacy**: Tool arguments, results, and side-effect payloads are digested. Raw content never enters the proof bundle.
4. **Additive coverage**: Start at M (model only), add MT (tools), then MTS (side-effects + approvals). Each level is backward-compatible.
5. **Identity-pluggable**: Agent identity uses `did:key` for signatures. Human approvers can use any supported format (OIDC, email, service account).

---

## Next steps

- **Protocol spec**: [`CLAWSIG_PROTOCOL_v0.1.md`](CLAWSIG_PROTOCOL_v0.1.md)
- **Reason code registry**: [`REASON_CODE_REGISTRY.md`](REASON_CODE_REGISTRY.md)
- **SDK reference**: [`packages/clawsig-sdk/README.md`](../../packages/clawsig-sdk/README.md)
- **CLI reference**: [`packages/clawverify-cli/README.md`](../../packages/clawverify-cli/README.md)
- **Conformance suite**: [`packages/schema/fixtures/protocol-conformance/manifest.v1.json`](../../packages/schema/fixtures/protocol-conformance/manifest.v1.json)
