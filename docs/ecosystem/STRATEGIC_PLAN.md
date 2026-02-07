# Claw Ecosystem Strategic Plan
## From Protocol M → OpenClaw Contribution → Agent Economy

**Date:** 2026-02-01
**Status:** Planning

---

## Executive Summary

We have **three interconnected assets**:

| Asset | What It Is | State |
|-------|-----------|-------|
| **OpenClaw** (github) | 140k★ TypeScript AI assistant | Production, community-driven |
| **Protocol M** (moltbook/) | Rust crypto + server implementation | Partial impl, 160+ user stories |
| **Claw Bureau** | 31 domains for ecosystem services | Registered, no deployments |

**The strategic question:** How do we turn these into a coherent contribution to OpenClaw and the agent economy?

---

## The Honest Assessment

### What's Actually Built
- ✅ OpenClaw CLI identity init/show (Rust, in moltbook/)
- ✅ Ed25519 signing/verification (Rust)
- ✅ JCS canonicalization (Rust)
- ✅ Basic Axum server scaffolding (Rust)
- ✅ 267+ passing tests (Rust)
- ✅ Comprehensive design docs

### What's NOT Built
- ❌ TypeScript integration with OpenClaw (the 140k★ repo)
- ❌ Gateway receipts (clawproxy.com)
- ❌ Bounty marketplace (clawbounties.com)
- ❌ Escrow system (clawescrow.com)
- ❌ Reputation system (clawrep.com)
- ❌ Any Cloudflare Workers deployment
- ❌ Any USDC integration

### The Reality Check
The prd.json has 160+ user stories but:
- Many are Rust-only implementations
- They don't touch the actual OpenClaw TypeScript codebase
- The "OpenClaw" in moltbook/ is a new Rust project, not the 140k★ TS project

---

## The Contribution Strategy

### Option A: "did-work" Skill for OpenClaw ⭐ RECOMMENDED

**What:** Build a TypeScript skill that adds DID Work Protocol to OpenClaw

**Why this wins:**
- Follows OpenClaw's existing skill architecture
- Immediately useful to 140k users
- Doesn't require convincing maintainers to adopt foreign code
- Can use Claw Bureau as backend services

**Scope:**
```
skills/
└── did-work/
    ├── SKILL.md           # Documentation
    ├── src/
    │   ├── index.ts       # Skill entry
    │   ├── identity.ts    # DID generation, storage
    │   ├── signing.ts     # Artifact/message signing
    │   ├── verify.ts      # Signature verification
    │   ├── bounties.ts    # Marketplace integration
    │   ├── escrow.ts      # Payment integration
    │   └── receipts.ts    # Gateway receipt collection
    └── package.json
```

### Option B: Deploy Claw Bureau MVP

**What:** Get core services running on Cloudflare

**Services in dependency order:**
1. **clawverify.com** - Verification API (pure function, no state)
2. **clawproxy.com** - Gateway receipts (stateless proxy)
3. **clawledger.com** - Balance tracking (needs D1/R2)
4. **clawescrow.com** - Payment holds (needs ledger)
5. **clawbounties.com** - Marketplace (needs escrow + ledger)
6. **clawrep.com** - Reputation (needs bounties data)

### Option C: Hybrid (A + B minimal)

**Recommended path:** Build the skill (A) with minimal backend (B)

---

## Phase 1: Foundation (Weeks 1-4)

### Week 1-2: OpenClaw Contribution

**PR #1: `did-work` skill scaffolding**
```typescript
// skills/did-work/src/identity.ts
import { generateKeyPair, publicKeyToDid } from './crypto';
import { encryptKey, decryptKey } from './keystore';

export async function initIdentity(force: boolean = false): Promise<string> {
  const { publicKey, privateKey } = await generateKeyPair();
  const did = publicKeyToDid(publicKey);
  // Store encrypted key
  await saveIdentity(did, privateKey, publicKey);
  return did;
}

// skills/did-work/src/signing.ts
export async function signArtifact(
  filePath: string,
  metadata?: Record<string, unknown>
): Promise<SignatureEnvelope> {
  const identity = await loadIdentity();
  const fileBytes = await readFile(filePath);
  const hash = sha256(fileBytes);
  const envelope = createEnvelope(identity.did, hash, metadata);
  const signature = sign(envelope, identity.privateKey);
  return { ...envelope, signature };
}
```

**Files to create:**
- `skills/did-work/SKILL.md`
- `skills/did-work/src/crypto.ts` (Ed25519 via @noble/ed25519)
- `skills/did-work/src/identity.ts`
- `skills/did-work/src/signing.ts`
- `skills/did-work/src/verify.ts`
- `skills/did-work/src/types.ts`

### Week 3-4: Minimal Backend

**Deploy on Cloudflare:**

1. **clawverify.com** (Worker)
```typescript
// Stateless verification endpoint
export default {
  async fetch(request: Request): Promise<Response> {
    const { envelope, content } = await request.json();
    const result = verifySignature(envelope, content);
    return Response.json(result);
  }
}
```

2. **clawproxy.com** (Worker)
```typescript
// Gateway receipt generation
export default {
  async fetch(request: Request): Promise<Response> {
    const llmRequest = await request.json();
    const startTime = Date.now();
    
    // Forward to actual provider
    const response = await forwardToProvider(llmRequest);
    
    // Generate receipt
    const receipt = {
      schema: 'did-work:gateway-receipt:v1',
      request_hash: sha256(JSON.stringify(llmRequest)),
      response_hash: sha256(JSON.stringify(response)),
      model: llmRequest.model,
      provider: detectProvider(request),
      timestamp: new Date().toISOString(),
      latency_ms: Date.now() - startTime,
    };
    
    // Sign receipt with proxy key
    receipt.signature = await signReceipt(receipt);
    
    return Response.json({
      ...response,
      _receipt: receipt
    });
  }
}
```

---

## Phase 2: Economics (Weeks 5-8)

### Keep It Simple: USDC + Stripe

**Don't build:**
- Custom tokens
- On-chain settlement (yet)
- Complex tokenomics

**Do build:**
1. Stripe checkout for buying credits
2. Credits tracked in D1/Postgres
3. USDC payouts via Circle API (optional)

### clawledger.com (D1 Database)

```sql
-- Simple ledger
CREATE TABLE accounts (
  did TEXT PRIMARY KEY,
  balance_credits REAL DEFAULT 0,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE ledger_events (
  id TEXT PRIMARY KEY,
  event_type TEXT, -- 'mint', 'burn', 'transfer', 'hold', 'release'
  from_did TEXT,
  to_did TEXT,
  amount REAL,
  metadata TEXT, -- JSON
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE escrow_holds (
  id TEXT PRIMARY KEY,
  bounty_id TEXT,
  holder_did TEXT,
  amount REAL,
  status TEXT DEFAULT 'held', -- 'held', 'released', 'cancelled'
  created_at TEXT,
  released_at TEXT
);
```

### clawbounties.com (MVP)

**Minimum viable marketplace:**
- List bounties (title, description, reward, deadline)
- Accept bounties (stake optional at first)
- Submit work (signed artifact)
- Approve/reject (requester only at first)
- Auto-release escrow on approval

---

## Phase 3: Trust (Weeks 9-12)

### Gateway Receipts Integration

Update `did-work` skill:
```typescript
// Configure in openclaw.json
{
  "skills": {
    "did-work": {
      "gateway": "https://clawproxy.com/v1",
      "autoReceipt": true
    }
  }
}

// Intercept LLM calls
export function wrapLLMCall(original: LLMCall): LLMCall {
  return async (request) => {
    const response = await fetch(config.gateway, {
      method: 'POST',
      body: JSON.stringify(request),
      headers: { 'X-Agent-DID': await getIdentity() }
    });
    const result = await response.json();
    if (result._receipt) {
      await storeReceipt(result._receipt);
    }
    return result;
  };
}
```

### Reputation Basics

```typescript
// clawrep.com - Simple reputation tracking
interface ReputationRecord {
  did: string;
  total_completed: number;
  total_disputed: number;
  total_value_settled: number; // in credits
  last_activity: string;
  trust_tier: 0 | 1 | 2 | 3;
}

// Trust tier rules (simple)
function calculateTrustTier(rep: ReputationRecord): number {
  if (rep.total_completed >= 100 && rep.total_disputed === 0) return 3;
  if (rep.total_completed >= 20 && rep.total_disputed <= 1) return 2;
  if (rep.total_completed >= 5) return 1;
  return 0;
}
```

---

## What We're NOT Building (Yet)

1. **Custom tokens (M-Credits as blockchain asset)**
   - USD-denominated credits are enough
   - Avoid regulatory complexity

2. **Compute-backed currency**
   - The oracle vision is interesting but premature
   - Focus on utility first, monetary theory later

3. **TEE/hardware attestation**
   - Gateway receipts are good enough for now
   - TEE can come when there's demand

4. **Full decentralization**
   - Centralized Postgres is fine for MVP
   - Merkle anchoring for audit trail
   - Full decentralization is a later problem

5. **Multi-round competitions**
   - Single-round bounties first
   - Multi-round adds complexity

---

## The OpenClaw PR Strategy

### PR #1: Skill Scaffolding
- Identity init/show
- Basic signing
- Local verification
- No backend required

### PR #2: Gateway Integration
- Receipt collection
- Proof bundle generation
- clawproxy.com integration

### PR #3: Bounty Tools
- `did_work.bounties_*` tools
- clawbounties.com integration
- Basic escrow

### PR #4: Agent Tools
- Tools for Pi agent runtime
- A2A work coordination
- Session-aware receipts

---

## Success Metrics

### Phase 1 (Weeks 1-4)
- [ ] `did-work` skill PR submitted
- [ ] clawverify.com deployed (Cloudflare)
- [ ] clawproxy.com deployed (Cloudflare)
- [ ] 10+ DIDs created by beta testers

### Phase 2 (Weeks 5-8)
- [ ] clawledger.com deployed (D1)
- [ ] clawbounties.com MVP deployed
- [ ] First bounty completed
- [ ] $100 volume through system

### Phase 3 (Weeks 9-12)
- [ ] Gateway receipts working end-to-end
- [ ] clawrep.com deployed
- [ ] Trust tiers implemented
- [ ] 50+ bounties completed

---

## Domain Allocation (31 domains)

### Phase 1 Priority
| Domain | Purpose | Status |
|--------|---------|--------|
| clawverify.com | Signature verification API | Deploy Week 2 |
| clawproxy.com | Gateway receipts | Deploy Week 3 |
| joinclaw.com | Landing/docs | Deploy Week 4 |

### Phase 2 Priority
| Domain | Purpose | Status |
|--------|---------|--------|
| clawledger.com | Balance/event tracking | Deploy Week 5 |
| clawescrow.com | Payment holds | Deploy Week 6 |
| clawbounties.com | Marketplace | Deploy Week 7 |

### Phase 3 Priority
| Domain | Purpose | Status |
|--------|---------|--------|
| clawrep.com | Reputation | Deploy Week 9 |
| clawclaim.com | Platform binding | Deploy Week 10 |
| clawsig.com | Public signing service | Deploy Week 11 |

### Later
| Domain | Future Purpose |
|--------|---------------|
| clawea.com | Execution attestation (Moltworker) |
| clawsilo.com | Encrypted artifact storage |
| clawdelegate.com | Approval workflows |
| clawintel.com | Collusion detection |
| clawtrials.com | Dispute arbitration |
| clawsettle.com | Cross-border settlement |
| clawincome.com | Tax exports |
| clawinsure.com | SLA insurance |
| clawadvisory.com | Governance |
| clawcontrols.com | Admin/ops |
| clawmanage.com | Account management |
| clawgrant.com | Protocol grants |
| clawforhire.com | A2A marketplace |
| clawproviders.com | Compute marketplace |
| clawcareers.com | Agent recruiting |
| clawcuts.com | Revenue sharing |
| clawgang.com | Community |
| clawportfolio.com | Agent profiles |
| clawmerch.com | Merchandise |
| clawscope.com | Analytics |
| clawsupply.com | Skills/capabilities |
| clawlogs.com | Audit logs |

---

## Next Actions

### This Week
1. [ ] Clone OpenClaw repo locally
2. [ ] Study existing skill architecture
3. [ ] Create `did-work` skill scaffold (TypeScript)
4. [ ] Port crypto functions from moltbook/openclaw-crypto to TS
5. [ ] Create PR draft for review

### Next Week
1. [ ] Set up Cloudflare Workers project
2. [ ] Deploy clawverify.com
3. [ ] Deploy clawproxy.com (basic)
4. [ ] Test end-to-end signing/verification

---

## The Vision (Grounded)

**Year 1:** OpenClaw skill + basic Claw Bureau services
- Agents can sign work
- Agents can participate in bounties
- Agents can build portable reputation

**Year 2:** Scale + refinement
- Multi-round competitions
- A2A tool leasing
- Enhanced verification

**Year 3+:** Maybe the bigger vision
- If there's real adoption, consider:
  - More sophisticated economics
  - Compute marketplace
  - Cross-platform reputation standard

**The principle:** Ship useful things. Don't over-engineer. Let adoption drive complexity.

---

## Files to Create

1. `/Users/gfw/clawd/02-Projects/clawbureau/skill-did-work/` - TypeScript skill
2. `/Users/gfw/clawd/02-Projects/clawbureau/workers/clawverify/` - CF Worker
3. `/Users/gfw/clawd/02-Projects/clawbureau/workers/clawproxy/` - CF Worker
4. `/Users/gfw/clawd/02-Projects/clawbureau/workers/clawledger/` - CF Worker + D1

---

*This plan prioritizes shipping over speculation. The oracle's compute-backing thesis is interesting but premature. Build trust infrastructure that works today; monetary theory can wait.*
