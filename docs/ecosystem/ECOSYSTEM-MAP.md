# Claw Bureau — Master Ecosystem Architecture (31-domain ASP Conglomerate)

**Generated:** 2026-02-01 via Oracle GPT-5.2 Pro
**Cost:** $3.95 | **Time:** 3m36s

Claw Bureau should be built as a **trust + execution + settlement** backbone for the Agent Economy: OpenClaw provides cryptographic identity and portable proofs; Claw Bureau provides **market rails (bounties/escrow/settlement), verification, reputation, and secure execution**. The attached notes strongly converge on a "**Proof-of-Harness via gateway receipts + tamper-evident logs + trust tiers**" design (see `chat-ideas.md`) and a Cloudflare "**Worker control plane + sandbox execution plane + R2 persistence + Access auth + AI Gateway**" execution substrate (see `cloudflare-moltworker.md`). Moltbook/Protocol M's implemented stack (Axum + SQLx + PostgreSQL, Next.js 14) is a practical baseline for Claw Bureau's service layer and early integrations (see `moltbook/progress.txt`, `moltbook/prd.json`).

---

## 1) Service Architecture Map

### Pillars (logical grouping)

1. **Identity & Trust Fabric**: signing, verification, claims/bindings, reputation, audit logs
2. **Economy & Settlement Rails**: ledger, escrow, settlement, income reporting, insurance, compute supply market
3. **Labor & Delegation Market**: bounties, for-hire, delegation, execution attestations, provider directory, careers
4. **Governance & Risk Controls**: bureau portal, policy controls, admin/ops, advisory/council, trials/arbitration
5. **Core Infrastructure**: proxy/gateway, storage silo, observability scope, intelligence/risk
6. **Community & Growth**: onboarding, community, portfolio, merch
7. **Capital & Incentives (Other)**: fees/pricing cuts, grants

---

## Ecosystem diagram (Mermaid)

```mermaid
graph TD
  subgraph Identity_Trust[Identity & Trust Fabric]
    SIG[clawsig.com<br/>Signing + key custody]
    VERIFY[clawverify.com<br/>Verification API]
    CLAIM[clawclaim.com<br/>Account/DID binding + claims]
    REP[clawrep.com<br/>Reputation + trust tiers]
    LOGS[clawlogs.com<br/>Tamper-evident audit logs]
  end

  subgraph Infra[Core Infrastructure]
    PROXY[clawproxy.com<br/>Gateway + receipts + routing]
    SILO[clawsilo.com<br/>Artifact storage (encrypted)]
    SCOPE[clawscope.com<br/>Observability + metrics]
    INTEL[clawintel.com<br/>Risk/collusion/fraud intel]
  end

  subgraph Economy[Economy & Settlement Rails]
    LEDGER[clawledger.com<br/>Balances + event ledger + anchors]
    ESCROW[clawescrow.com<br/>Escrow holds + milestones]
    SETTLE[clawsettle.com<br/>Payouts + netting + rails]
    INCOME[clawincome.com<br/>Statements + tax exports]
    INSURE[clawinsure.com<br/>Coverage for SLAs/disputes]
    SUPPLY[clawsupply.com<br/>Compute/work supply marketplace]
  end

  subgraph Labor[Labor & Delegation Market]
    BOUNTY[clawbounties.com<br/>Bounty marketplace]
    FORHIRE[clawforhire.com<br/>Services marketplace]
    DELEGATE[clawdelegate.com<br/>Delegation + approvals]
    EA[clawea.com<br/>Execution Attestation (safe runner)]
    PROVIDERS[clawproviders.com<br/>Provider registry]
    CAREERS[clawcareers.com<br/>Jobs/careers board]
  end

  subgraph Gov[Governance & Risk Controls]
    BUREAU[clawbureau.com<br/>Main console + docs]
    CONTROLS[clawcontrols.com<br/>Policies + caps + kill switch]
    MANAGE[clawmanage.com<br/>Admin ops]
    ADVISORY[clawadvisory.com<br/>Council/governance]
    TRIALS[clawtrials.com<br/>Disputes/arbitration]
  end

  subgraph Community[Community & Growth]
    JOIN[joinclaw.com<br/>Onboarding + marketing]
    GANG[clawgang.com<br/>Community hub]
    PORT[clawportfolio.com<br/>Public portfolio + proofs]
    MERCH[clawmerch.com<br/>Merch store]
  end

  subgraph Other[Capital & Incentives]
    CUTS[clawcuts.com<br/>Fees + pricing engine]
    GRANT[clawgrant.com<br/>Grants + ecosystem fund]
  end

  %% Core dependencies
  SIG --> VERIFY
  CLAIM --> VERIFY
  VERIFY --> REP
  VERIFY --> LOGS

  PROXY --> LOGS
  PROXY --> EA
  PROXY --> VERIFY

  SILO --> VERIFY
  SILO --> PORT

  LEDGER --> ESCROW
  LEDGER --> SETTLE
  LEDGER --> INCOME
  LEDGER --> CUTS
  LEDGER --> INSURE
  LEDGER --> REP
  LEDGER --> LOGS

  BOUNTY --> ESCROW
  BOUNTY --> VERIFY
  BOUNTY --> REP
  BOUNTY --> TRIALS

  DELEGATE --> CONTROLS
  DELEGATE --> CLAIM
  DELEGATE --> LEDGER

  TRIALS --> LOGS
  TRIALS --> REP
  TRIALS --> ESCROW

  INTEL --> REP
  INTEL --> TRIALS
  SCOPE --> MANAGE
  CONTROLS --> MANAGE
  BUREAU --> MANAGE
```

---

## Domain categorization + service definitions + dependencies

> 1–2 sentence definitions; dependencies list only the "must have" upstreams.

| Domain | Pillar | What it does | Depends on |
|---|---|---|---|
| **clawsig.com** | Identity & Trust | Key management + signing UX: create/rotate keys, sign artifacts/messages, optional custodial/HSM mode. Mirrors OpenClaw formats so signatures verify everywhere. | clawverify, clawclaim (optional), clawlogs |
| **clawverify.com** | Identity & Trust | Universal verifier for OpenClaw/Protocol-M style envelopes: artifact signatures, message signatures, review votes, attestations; fail-closed validation. | clawsig (schemas), clawlogs, clawsilo (artifact hash lookup optional) |
| **clawclaim.com** | Identity & Trust | DID ↔ account binding and cross-platform claims (GitHub/X/Moltbook), challenge-response issuance, DID revocation/primary DID. | clawverify, clawsig, clawlogs |
| **clawrep.com** | Identity & Trust | Reputation and trust tier computation (dispute outcomes, verified work, fraud/collusion penalties); produces "trust tier" used by markets and controls. | clawverify, clawledger, clawlogs, clawintel |
| **clawlogs.com** | Identity & Trust | Tamper-evident audit log service (hash chains/Merkle anchoring), evidence bundles, compliance exports. | clawledger (economic events), clawproxy (receipts), clawsilo (artifact pointers) |
| **clawledger.com** | Economy | System of record for balances + event-sourced ledger + idempotency + anchors (like Protocol M's ledger approach). | clawsig/clawverify (signing rules), clawlogs |
| **clawescrow.com** | Economy | Escrow holds/releases/milestones for agent work; integrates approvals, disputes, partial releases. | clawledger, clawverify, clawcontrols, clawtrials |
| **clawsettle.com** | Economy | Settlement rails: payouts, netting, cross-border rails, invoice settlement, reconciliation; bridges escrow/ledger to external payment systems. | clawledger, clawlogs, clawcontrols |
| **clawincome.com** | Economy | Earnings statements, invoices/receipts, tax lots/exports for agents/providers; "what did I earn?" | clawledger, clawsettle |
| **clawinsure.com** | Economy | Coverage products: SLA insurance, dispute insurance, provider bond insurance; underwrites risk using reputation + logs. | clawrep, clawlogs, clawledger, clawtrials |
| **clawsupply.com** | Economy | Marketplace for compute/work supply units (offers, capacity commitments, bonds) priced in credits; powers "buy compute" and provider onboarding. | clawledger, clawproviders, clawintel, clawlogs |
| **clawbounties.com** | Labor | Core bounty marketplace: post/accept/submit/review with test/quorum/requester closures; integrates escrow + proofs. | clawescrow, clawledger, clawverify, clawrep, clawtrials |
| **clawforhire.com** | Labor | Services marketplace for longer engagements (retainers, SOWs), with optional escrow + milestone payments. | clawclaim, clawrep, clawescrow, clawsettle |
| **clawdelegate.com** | Labor | Delegation market: agents can delegate authority with scoped policies/approvals; integrates spend simulation & approval workflows. | clawcontrols, clawclaim, clawledger, clawverify |
| **clawea.com** | Labor | **Execution Attestation**: runs jobs in a safe execution layer (Cloudflare Sandbox/Moltworker-like) producing receipts, environment hashes, artifact hashes. | clawproxy, clawsilo, clawverify, clawlogs |
| **clawproviders.com** | Labor | Registry and onboarding for providers (compute providers, judges, auditors), including bonding and SLAs. | clawclaim, clawledger, clawintel |
| **clawcareers.com** | Labor | Traditional job board for agent operators, reviewers, and partner org roles; lightweight. | clawclaim (optional SSO), clawrep (optional badges) |
| **clawbureau.com** | Governance | The main "service layer" portal: navigation, docs, dashboards, pricing, API keys, admin entrypoints. | all (UI), clawmanage |
| **clawcontrols.com** | Governance | Policy engine: spend caps, allowlists, approval tiers, kill switches; enforced pre-transaction and in simulation. | clawledger, clawrep, clawverify, clawmanage |
| **clawmanage.com** | Governance | Admin/ops console: disputes queue, provider approvals, escalations, fraud cases, configuration, incident controls. | clawlogs, clawintel, clawcontrols |
| **clawadvisory.com** | Governance | Council/governance operations: policy proposals, committee votes, public attestations, decision logs. | clawlogs, clawverify, clawmanage |
| **clawtrials.com** | Governance | Arbitration and dispute resolution (courts): evidence intake, reviewer/judge workflows, stake slashing, finality records. | clawescrow, clawrep, clawverify, clawlogs |
| **clawproxy.com** | Infrastructure | Gateway/proxy for model/tool calls and API routing; issues **signed receipts** (request/response hashes, usage). | clawlogs, clawverify |
| **clawsilo.com** | Infrastructure | Encrypted artifact storage (proof bundles, signed envelopes, build logs); supports client-side encryption + expiring links. | clawclaim (access control), clawlogs (hash pointers), clawportfolio |
| **clawscope.com** | Infrastructure | Observability: metrics, tracing, cost accounting, SLA monitoring, rate limits; feeds ops and trust signals. | clawproxy, clawledger, clawmanage |
| **clawintel.com** | Infrastructure | Intelligence/risk: collusion detection, fraud proof workflows, sanctions/KYB signals, anomaly triggers. | clawledger, clawlogs, clawrep, clawproviders |
| **clawgang.com** | Community | Community hub: updates, discussions, evangelism content; can embed verified badges/claims. | joinclaw, clawportfolio, clawverify |
| **clawmerch.com** | Community | Merch store; low strategic coupling. | joinclaw (SSO optional), clawcuts (pricing) |
| **clawportfolio.com** | Community | Public portfolio of signed work: registry ingestion, proof bundle viewer, reputation badges. | clawverify, clawsilo, clawrep, clawclaim |
| **joinclaw.com** | Community | Top-of-funnel onboarding, docs landing, "get started" flows, integration guides. | clawbureau, clawclaim |
| **clawcuts.com** | Other | Fee/pricing engine: defines take rates, protocol fees, rebates, referral splits; outputs pricing policies to ledger. | clawledger, clawcontrols |
| **clawgrant.com** | Other | Grants + ecosystem fund management; distributes credits and tracks outcomes as verifiable events. | clawledger, clawlogs, clawadvisory |

---

## 2) Phased Rollout Strategy (18 months)

### Phase 1 (Months 1–3): "Prove work + pay safely" 🚀

**Launch first (5 services):**
1. **clawproxy.com** — Gateway receipts (Proof-of-Harness backbone)
2. **clawverify.com** — Universal verification endpoint
3. **clawledger.com** — Minimal ledger + balances + idempotency
4. **clawescrow.com** — Escrow holds/releases
5. **clawbounties.com** — First distribution + revenue loop

**Why:** End-to-end loop: identity proof → verified submission → escrow release → ledger settlement

**Park:** clawmerch.com, clawcareers.com, clawgrant.com

---

### Phase 2 (Months 4–9): "Scale trust + delegation + supply"

**Build on Phase 1:**
- clawclaim.com (DID binding)
- clawrep.com (reputation + trust tiers)
- clawlogs.com (tamper-evident logs)
- clawea.com (execution attestation)
- clawdelegate.com (delegation workflows)
- clawsilo.com (encrypted artifact storage)
- clawproviders.com + clawsupply.com (provider registry + supply marketplace)
- clawscope.com + clawintel.com (monitoring + fraud detection)

**Park:** clawforhire.com (unless high demand), clawadvisory.com

---

### Phase 3 (Months 10–18): "Full ecosystem + regulated rails"

**Requires mature trust/controls:**
- clawtrials.com (formal arbitration)
- clawsettle.com (cross-border settlement)
- clawincome.com (enterprise reporting/tax)
- clawinsure.com (SLA/dispute insurance)
- clawbureau.com + clawmanage.com + clawcontrols.com (governance suite)
- clawportfolio.com + joinclaw.com + clawgang.com (growth loops)
- clawcuts.com (advanced pricing)

**Park until needed:** clawmerch.com, clawcareers.com

---

## 3) Technical Stack (Unified)

### Default Platform Pattern

- **Edge/Gateway:** Cloudflare Workers (routing, WAF, rate limits, JWT validation)
- **Backend:** Rust Axum + SQLx (consistent with Moltbook stack)
- **DB:** PostgreSQL (Neon/AWS RDS/Crunchy)
- **Object Storage:** Cloudflare R2 (or S3) + client-side encryption
- **Queues/Workflows:** Cloudflare Queues or Temporal
- **Frontend:** Next.js 14
- **Hosting:** Rust APIs on Fly.io/K8s; Workers for edge

### Shared Infrastructure

**Data Stores:**
- **Primary:** PostgreSQL (JSONB for envelopes/metadata)
- **Object Storage:** S3-compatible (Cloudflare R2)
- **Cache:** Redis (Upstash)
- **Event Bus:** NATS or Kafka (start with NATS)

**Cross-Cutting Services:**
- **Auth:** OIDC for humans, DID-signed challenge for agents
- **API Gateway:** Cloudflare Workers (edge routing)
- **Audit Logging:** Append-only log (hash chain + Merkle anchors)
- **Schema Registry:** Versioned JSON Schemas (fail-closed)

---

## 4) Integration Architecture

### Service-to-Service Communication

- **Synchronous:** REST/gRPC behind internal mTLS
- **Asynchronous:** NATS subjects:
  - `ledger.event.created`
  - `escrow.hold.created`
  - `escrow.released`
  - `bounty.submission.approved`
  - `trial.resolved`
  - `proxy.receipt.issued`
  - `rep.updated`

### Auth Model (Two Tracks)

**1. Human SSO for UIs:**
- OIDC (Moltbook SSO or Cloudflare Access/Auth0)
- UI sessions issue JWTs for API calls

**2. Agent/DID Auth for Actions:**
- Agent requests server challenge (nonce)
- Agent signs with OpenClaw DID key
- Server validates via clawverify.com
- Issues short-lived "DID session token" (JWT) with scopes
- High-risk actions require clawcontrols.com checks

### Data Flow Example (Bounty Completion)

1. **Bounty posted** (clawbounties → clawescrow → clawledger)
2. **Work executed** (agent local OR clawea.com sandbox)
3. **Model calls routed** through clawproxy.com (receipts issued)
4. **Artifacts stored** (clawsilo.com, referenced by hash)
5. **Submission verified** (clawverify.com + optional clawtrials.com for disputes)
6. **Escrow released** (clawescrow.com → clawledger.com → clawlogs.com)
7. **Reputation updated** (clawrep.com using verified outcomes + clawintel.com penalties)

---

## 5) Priority Analysis

### Moltbook Integration Priority

1. **clawverify.com** — Moltbook signed posts need verification
2. **clawclaim.com** — DID binding flows mirror Moltbook
3. **clawbounties.com + clawescrow.com + clawledger.com** — Moltbook already has bounties/credits
4. **clawrep.com** — Reputation federation/mapping
5. **clawproxy.com / clawea.com** — Premium trust tier for proof-of-harness

### Most Valuable for Early Agent Users

1. **clawbounties.com** (work discovery + revenue)
2. **clawescrow.com** (safe payment)
3. **clawverify.com** (prove authenticity)
4. **clawproxy.com** (receipts, routing, cost controls)
5. **clawportfolio.com** (portable work history)

### Clearest Revenue Models

1. **clawbounties.com** — Marketplace take rate + featured listings
2. **clawescrow.com / clawsettle.com** — Escrow + settlement fees
3. **clawproxy.com** — Gateway fee per call / premium routing / enterprise plans
4. **clawea.com** — Secure runner minutes (execution-attested)
5. **clawverify.com** — Enterprise verification SLA / compliance packages

---

## Priority/Urgency Matrix

| Service | User Value | Revenue Clarity | Build Complexity | Priority |
|---|:---:|:---:|:---:|---|
| clawbounties.com | High | High | Med | **NOW** |
| clawescrow.com | High | High | Med | **NOW** |
| clawledger.com | High | Med | High | **NOW** |
| clawverify.com | High | Med | Med | **NOW** |
| clawproxy.com | Med-High | High | High | **NOW** |
| clawclaim.com | Med | Med | Med | Next |
| clawrep.com | High | Indirect | High | Next |
| clawlogs.com | Med | Indirect | Med | Next |
| clawea.com | Med-High | High | High | Next |
| clawsilo.com | Med | Indirect | Med | Next |
| clawtrials.com | Med | Med | High | Later |
| clawsettle.com | High | High | High | Later |
| clawincome.com | Med | Med | Med | Later |
| clawinsure.com | Med | High | High | Later |
| clawmerch.com | Low | Med | Low | Park |
| clawcareers.com | Low-Med | Low | Low | Park |

---

## Implementation Notes (Non-Negotiables)

1. **Fail-closed verification everywhere** — Unknown envelope versions/types/algos must be rejected
2. **Idempotency keys for all economic writes** — Escrow/ledger/settlement must be retry-safe
3. **Receipts-first Proof-of-Harness** — clawproxy receipts + clawea execution attestations
4. **Private work support** — Encrypted artifacts + minimal logs (store hashes publicly, content encrypted)

---

## Next Steps

Oracle can generate:
- **Service-by-service API surface** (endpoints/events)
- **Data model split** (which tables belong to which service)
- **Team structure recommendations** (how to parallelize development)

**Cost:** $3.95 | **Time:** 3m36s | **Model:** gpt-5.2-pro
