# Protocol M: OpenClaw Extension (Revised Scope)

**Date:** 2026-01-31
**Context:** Protocol M is being built as a **contribution to the existing openclaw/openclaw project**, not a standalone implementation.

## What OpenClaw Is

OpenClaw ([github.com/openclaw/openclaw](https://github.com/openclaw/openclaw)) is a self-hosted personal AI assistant platform that:
- Connects to multiple messaging channels (WhatsApp, Telegram, Discord, Slack, etc.)
- Provides a WebSocket-based gateway at `ws://127.0.0.1:18789`
- Built with Node.js/TypeScript as a monorepo (pnpm workspace)
- Includes agent runtime, skills system, automation, voice capabilities
- MIT licensed, welcomes community PRs

## Protocol M as an OpenClaw Extension

Instead of building OpenClaw from scratch, we're **adding identity + provenance features** to the existing platform.

### What We're Contributing

**1. Identity Package (`packages/protocol-m` or `packages/identity`)**
- Ed25519 key generation and encrypted storage
- `did:key` derivation (multicodec 0xed01 + base58btc)
- Key rotation with cryptographic continuity

**2. Signing & Verification**
- Sign messages sent across channels
- RFC 8785 JCS canonical signing
- Offline verification of signed artifacts
- Signature envelope schema (version `m1`)

**3. CLI Extensions**
```bash
openclaw identity init          # Generate did:key
openclaw identity show          # Display current identity
openclaw identity rotate        # Rotate keys with proof
openclaw sign <file>            # Sign any artifact
openclaw verify <file> <sig>    # Verify signature
openclaw sign-message <text>    # Sign challenge for binding
```

**4. Moltbook Integration**
- New channel: `extensions/moltbook`
- DID binding via challenge-response
- Post signing with signature envelopes
- Verified badge support

**5. Cross-Platform Identity Proof**
- Prove the same agent operates across WhatsApp, Telegram, Discord
- Portable reputation tied to cryptographic identity
- Agents can build verifiable history

### Technical Architecture

**Package Structure:**
```
packages/
  protocol-m/
    src/
      identity/       # Key generation, DID derivation
      signing/        # Signature envelope creation
      verification/   # Offline verification logic
      storage/        # Encrypted key storage
      rotation/       # Key rotation certificates
    cli/
      commands/       # CLI command implementations
    __tests__/
      golden.test.ts  # Golden vector gate
```

**Integration Points:**
- Extend `src/agent/runtime.ts` to support signing outbound messages
- Add identity commands to `openclaw.mjs` CLI
- Create `extensions/moltbook` channel for social integration
- Add skill for Moltbook interaction

**Dependencies to Add:**
- `@noble/ed25519` - Ed25519 signing (pure JS, no native deps)
- `@stablelib/base58` - Base58 encoding for did:key
- `canonicalize` - RFC 8785 JSON Canonical Serialization
- (OpenClaw already has crypto storage patterns we can reuse)

### PR Strategy

**Phase 1: Core Identity (PR #1)**
- Add `packages/protocol-m` with identity + signing
- CLI commands: `identity init/show/rotate`
- Tests including golden vector gate
- Documentation for identity management

**Phase 2: Message Signing (PR #2)**
- Extend agent runtime to sign outbound messages
- Add `--sign` flag to message commands
- Verification helpers for other agents

**Phase 3: Moltbook Integration (PR #3)**
- Add `extensions/moltbook` channel
- DID binding flow
- Post verification
- Skill for social interaction

**Phase 4: Cross-Platform Proof (PR #4)**
- Link identity across channels
- Reputation aggregation
- Identity portability helpers

### Alignment with OpenClaw Philosophy

From their README: "AI/vibe-coded contributions encouraged."

Protocol M fits OpenClaw's vision:
- **Local-first:** Keys stored locally, encrypted at rest
- **Self-hosted:** No external dependencies for signing/verification
- **Multi-channel:** Identity works across all OpenClaw channels
- **Tool-oriented:** Adds cryptographic primitives as new tools
- **Community-driven:** Open source, MIT licensed

### Updated Milestones

- **M0:** Fork openclaw/openclaw, set up dev environment
- **M1:** Implement `packages/protocol-m` core (identity + signing)
- **M2:** Add CLI commands and golden vector tests
- **M3:** Create PR #1 to openclaw/openclaw
- **M4:** (After merge) Implement Moltbook extension
- **M5:** Create PR #2 for Moltbook integration

### Key Differences from Original PRD

| Original PRD | Revised (OpenClaw Extension) |
|--------------|------------------------------|
| Build Rust CLI from scratch | Add Node.js/TypeScript package to existing monorepo |
| Standalone `openclaw` binary | Extend existing `openclaw` CLI |
| New project architecture | Follow OpenClaw's existing patterns |
| Ship as v0.1.0-alpha | Contribute as PR to openclaw/openclaw |
| Cross-platform CI setup | Use OpenClaw's existing CI |

### Golden Vector Still Applies

The cryptographic spec (did:key, Ed25519, JCS, signature envelope schema) remains unchanged. Implementation is just in TypeScript instead of Rust.

### Next Steps

1. Fork openclaw/openclaw
2. Read CONTRIBUTING.md for their PR guidelines
3. Set up local dev environment (`pnpm install`)
4. Create `packages/protocol-m` scaffold
5. Implement golden vector test first (TDD)
6. Build identity + signing features
7. Submit PR with comprehensive tests + docs
