# Claw Bureau

**Verifiable agent infrastructure.** Proof bundles, tool receipts, capability negotiation, and offline verification for AI agents — powered by the [Clawsig Protocol](https://clawsig.com).

[![conformance](https://github.com/clawbureau/clawbureau/actions/workflows/clawsig-protocol-conformance.yml/badge.svg)](https://github.com/clawbureau/clawbureau/actions/workflows/clawsig-protocol-conformance.yml)
[![verify](https://github.com/clawbureau/clawbureau/actions/workflows/clawsig-verified-pr.yml/badge.svg)](https://github.com/clawbureau/clawbureau/actions/workflows/clawsig-verified-pr.yml)
[![npm: clawsig-sdk](https://img.shields.io/npm/v/@clawbureau/clawsig-sdk?label=clawsig-sdk)](https://www.npmjs.com/package/@clawbureau/clawsig-sdk)
[![npm: clawverify-cli](https://img.shields.io/npm/v/@clawbureau/clawverify-cli?label=clawverify-cli)](https://www.npmjs.com/package/@clawbureau/clawverify-cli)

---

## Quick start

```bash
# 1. Install the SDK
npm install @clawbureau/clawsig-sdk

# 2. Emit a verifiable proof bundle from your agent
```

```ts
import { createClawsigRun } from '@clawbureau/clawsig-sdk';

const run = await createClawsigRun({ agentDid, proxyUrl, keyFile });
const response = await run.callLLM({ model: 'claude-sonnet-4-20250514', messages });
run.recordToolCall({ tool_name: 'file_read', args_digest, result_digest, duration_ms });
const bundle = await run.finalize();
```

```bash
# 3. Verify offline
npx @clawbureau/clawverify-cli verify proof-bundle --input bundle.json
# → { "status": "PASS", "reason_code": "OK" }
```

## Clawsig Protocol

Cryptographically signed proof bundles for AI agent actions. Every receipt is hash-only (raw content never enters bundles), every verification is offline, and every unknown input fails closed.

| Coverage | What's proven | SDK method |
|----------|---------------|------------|
| **M** | Which model was called, when, by whom | `callLLM()` |
| **MT** | + which tools were invoked | `recordToolCall()` |
| **MTS** | + side-effects + human approvals | `recordSideEffect()` + `recordHumanApproval()` |

**Current coverage: MTS** · 8 receipt schemas · 22 conformance vectors · 400+ reason codes

### Key resources

- **[Protocol spec](docs/specs/clawsig-protocol/CLAWSIG_PROTOCOL_v0.1.md)** — normative definitions, 5 primitives, coverage matrix
- **[Adoption guide](docs/specs/clawsig-protocol/ADOPTION_GUIDE.md)** — integrate in a day (agent authors, security teams, CI/CD)
- **[Reason code registry](docs/specs/clawsig-protocol/REASON_CODE_REGISTRY.md)** — machine-readable error codes
- **[Conformance suite](packages/schema/fixtures/protocol-conformance/manifest.v1.json)** — 22 test vectors

### npm packages

| Package | Description |
|---------|-------------|
| [`@clawbureau/clawsig-sdk`](https://www.npmjs.com/package/@clawbureau/clawsig-sdk) | Emit proof bundles from any Node.js agent |
| [`@clawbureau/clawverify-cli`](https://www.npmjs.com/package/@clawbureau/clawverify-cli) | Verify proof bundles offline in one command |
| [`@clawbureau/clawverify-core`](https://www.npmjs.com/package/@clawbureau/clawverify-core) | Verification primitives (programmatic API) |

---

## For enterprise

Running AI agents in regulated environments? **[Claw EA](https://www.clawea.com)** wraps the Clawsig Protocol with enterprise controls:

- **Readiness assessment** — [assess your rollout readiness](https://www.clawea.com/assessment) in 2 minutes
- **Approval gates, DLP, kill switches** — [see all controls](https://www.clawea.com/controls)
- **SOX, HIPAA, FedRAMP mapping** — [compliance evidence](https://www.clawea.com/resources/compliance-mapping)
- **Security review pack** — [architecture, threat model, proof artifacts](https://www.clawea.com/trust/security-review)
- **Pricing** — [starter ($49/mo), team ($249/mo), enterprise (custom)](https://www.clawea.com/pricing)

## Documentation

Full docs, implementation guides, and API reference:

- **[Documentation hub](https://www.clawea.com/docs)** — Quick Start, SDK, API, Protocol Spec, Security
- **[GitHub Actions proof pipeline](https://www.clawea.com/guides/github-actions-proof-pipeline)** — CI integration in 30 minutes
- **[Okta scoped tokens](https://www.clawea.com/guides/okta-scoped-tokens)** — identity-scoped agent permissions
- **[Case study: dogfooding](https://www.clawea.com/case-studies/dogfood-claw-bureau)** — 3 agents, 190+ PRs, 12 services

[![Claw EA](https://img.shields.io/badge/Claw_EA-docs-blue)](https://www.clawea.com/docs)
[![deployment](https://img.shields.io/badge/status-operational-brightgreen)](https://www.clawea.com/status)

---

## Monorepo structure

```
├── packages/
│   ├── clawsig-sdk/          # Proof bundle SDK
│   ├── clawsig-adapters/     # Harness wrappers (Claude Code, Codex, Pi, etc.)
│   ├── clawverify-core/      # Offline verification primitives
│   ├── clawverify-cli/       # Verifier CLI
│   └── schema/               # JSON schemas + conformance vectors
├── services/
│   ├── clawproxy/            # LLM gateway proxy (receipt issuance)
│   ├── clawverify/           # Online verification service
│   ├── clawclaim/            # Identity registry
│   ├── clawscope/            # Observability + audit logs
│   ├── clawcontrols/         # Policy engine
│   ├── clawdelegate/         # Delegation control plane
│   ├── clawbounties/         # Agent marketplace
│   ├── clawrep/              # Reputation engine
│   ├── clawtrials/           # Arbitration service
│   ├── clawsettle/           # Payment settlements
│   ├── escrow/               # Escrow service
│   ├── ledger/               # Financial ledger
│   ├── clawsig-www/          # clawsig.com landing page
│   └── ...
├── docs/
│   ├── specs/                # Protocol + domain specs
│   ├── prds/                 # Domain PRDs (36 services)
│   ├── roadmaps/             # Delivery trackers
│   └── WHAT_TO_READ.md       # Reading paths by audience
├── scripts/                  # Smoke tests, protocol tools
├── artifacts/                # Conformance evidence, PoH bundles
└── proofs/                   # DID commit signatures
```

## Roadmap status

| Roadmap | Stories | Status |
|---------|---------|--------|
| [Clawsig Protocol](docs/roadmaps/clawsig-protocol/) | 12/12 | ✅ Complete |
| [Proof of Harness](docs/roadmaps/proof-of-harness/) | 20/20 | ✅ Complete |
| [Trust vNext](docs/roadmaps/trust-vnext/) | 59/59 | ✅ Complete |
| [Docs IA](docs/roadmaps/docs-ia/) | 4/4 | ✅ Complete |

## What to read

See **[docs/WHAT_TO_READ.md](docs/WHAT_TO_READ.md)** for reading paths by audience:
- New contributor · Marketplace engineer · Trust/PoH engineer · OpenClaw integration · **Protocol adopter** · Economy/risk dev · Enterprise buyer

---

## Private submodules

Some services are maintained in private repos and included as git submodules (e.g., `services/clawea`).

```bash
git submodule update --init --recursive
```

## License

MIT
