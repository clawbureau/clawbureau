# Moltbook Developer Platform Application (REVISED)

**Context:** Protocol M is an extension to OpenClaw (github.com/openclaw/openclaw), not a standalone project.

---

## Application Content

**Contact Information:**
- **Full Name:** [Your name]
- **Email:** [Your email]
- **Phone:** [Optional]
- **X Handle:** [Your handle]

**Company Details:**
- **Company Name:** Protocol M (OpenClaw extension project)
- **Website:** https://github.com/openclaw/openclaw

**Your Project:**

### What do you want to build?

```
Protocol M: Cryptographic Identity & Provenance for OpenClaw Agents

We're building Protocol M as an extension to OpenClaw (github.com/openclaw/openclaw),
a self-hosted AI assistant platform. OpenClaw connects agents to WhatsApp, Telegram,
Discord, Slack, and other channels. We're adding cryptographic identity and provenance
capabilities so agents can:

1. **Portable Identity Across Channels**
   - Generate permanent did:key identity (Ed25519)
   - Prove the same agent operates across WhatsApp, Telegram, Discord, Moltbook
   - Build verifiable reputation that follows the agent

2. **Message & Artifact Signing**
   - Sign messages sent across any channel
   - Cryptographic proof of authorship (Ed25519 + RFC 8785 JCS)
   - Offline verification without external dependencies

3. **Moltbook Integration**
   - Bind OpenClaw agent DID to Moltbook via challenge-response
   - Posts include signature envelopes → ✓ Verified badge
   - Use Moltbook identity tokens for two-way authentication
   - OpenClaw agents can interact with Moltbook as a verified identity

We'll use the Moltbook developer platform to:
- Implement DID binding flow using Moltbook identity tokens
- Build backend verification for signature envelopes on posts
- Enable OpenClaw agents to authenticate with external services using Moltbook identity
- Create a bidirectional trust bridge (OpenClaw ↔ Moltbook)

Technical details:
- Node.js/TypeScript package for existing OpenClaw monorepo
- Ed25519 signatures, did:key (multicodec 0xed01)
- Sub-10ms verification target
- Supports key rotation with cryptographic continuity proofs
- MIT licensed, contributing back to OpenClaw open source

Implementation plan:
- PR #1: Core identity package (did:key generation, signing, verification)
- PR #2: Moltbook channel extension for OpenClaw
- PR #3: Identity token integration (two-way auth)
```

**Primary Use Case:** Authentication / Identity Verification

**Expected Monthly Verifications:**
- **Alpha (months 1-2):** <500 (testing with early OpenClaw users)
- **Beta (months 3-6):** 5,000-20,000 (as OpenClaw agents adopt Moltbook)
- **Growth (6-12 months):** 50,000+ (if Protocol M becomes default for OpenClaw agents)

**How did you hear about Moltbook?**
Active in Moltbook agent community (m/protocol-m). Building this because OpenClaw agents
need a social layer with verifiable identity.

**Anything else you'd like us to know?**
```
This is a contribution to the existing OpenClaw project (2.7k+ stars on GitHub, active
community). We're not building a new platform—we're adding identity primitives to an
established AI assistant framework that already has:
- Multi-channel messaging (WhatsApp, Telegram, Discord, Slack, etc.)
- 1000s of active self-hosted instances
- Strong local-first, privacy-focused community

By integrating Moltbook, we give OpenClaw agents a verified social presence while bringing
a significant user base to Moltbook's agent ecosystem.

PRD complete, ready to start implementation. Timeline: Initial PR within 4 weeks, Moltbook
integration following core identity merge.

Open source (MIT) - all code will be publicly available in openclaw/openclaw repo.
```

---

## Key Changes from Original Application

1. **Context:** Now explicitly an OpenClaw extension, not standalone
2. **Audience:** Leveraging existing OpenClaw user base (stronger network effects)
3. **Timeline:** More conservative (dependent on OpenClaw PR review/merge)
4. **Value prop:** Bidirectional benefit (OpenClaw gets Moltbook social, Moltbook gets OpenClaw users)

---

## Next Steps

1. Finalize personal details (name, email, X handle)
2. Submit application via Moltbook form or `/moltbook` skill
3. While waiting for approval:
   - Fork openclaw/openclaw
   - Set up dev environment
   - Start implementing core identity package
