# Gap Analysis: Gemini Prescribed vs Actually Shipped (2026-02-12)

## Status Legend
- SHIPPED = Code merged, tested
- DEPLOYED = Live on Cloudflare
- DESIGNED = Schema/spec exists, code not written
- MISSING = Not addressed at all

---

## Round 2 (P6-P10): Enterprise Moat

| # | Prescribed | Status | Notes |
|---|-----------|--------|-------|
| P6 | Causality Moat positioning + supply-side PRs to LangChain/CrewAI/Vercel | DESIGNED | PR template written in Round 6. Zero PRs actually submitted. |
| P7 | WPC v2 IAM-style JSON DSL | SHIPPED (PR #205) | Effect/Action/Resource/Condition, Strict Intersection. |
| P8 | Delegation receipt Merkle DAG | SHIPPED (PR #206) | delegation_receipt schema + strict liability cascade. |
| P9 | SOC2/EU AI Act compliance mapping | SHIPPED (PR #206) | compliance_report.v1.json generator. |
| P10 | Mandatory Receipt Transparency Log | SHIPPED (PR #204) | Merkle tree, inclusion proofs, epoch cutoff. |

**Round 2 gap: P6 (supply-side adoption PRs) = 0% executed.**

---

## Round 3: Viral Flywheel (7 Pillars)

| # | Prescribed | Status | Notes |
|---|-----------|--------|-------|
| 1 | Clawsig Public Ledger (D1/R2/Queue) | SHIPPED+DEPLOYED (PR #209) | VaaS API, D1 `clawsig-public-ledger`, R2 `clawsig-public-bundles`, Queue `ledger-ingest`. Live on `api.clawverify.com`. |
| 2 | Badge System (SVG badges on GitHub/npm) | SHIPPED+DEPLOYED (PR #209) | `GET /v1/badges/:run_id.svg`. Heartbeat badge logic in PR #211. |
| 3 | Agent Passport (W3C VC) | SHIPPED (PR #209) | `GET /v1/passports/:did`. Schema: `agent_passport.v1.json`. |
| 4 | VaaS API (`POST /v1/verify`) | SHIPPED+DEPLOYED (PR #209) | With compliance framework param. |
| 5 | `npx clawsig wrap` (one-line DX) | SHIPPED (PR #208) | Ed25519 ephemeral DID, MITM proxy, badge output. **Not tested e2e with real agent.** |
| 6 | Network Effect Schema | SHIPPED | Ledger -> Passport -> Badge -> Explorer all connected. |
| 7 | "Clawsig Inside" Conformance | SHIPPED (PR #210) | GitHub Action, mock LLM proxy, conformance test runner, certification schema. |

**Round 3 gap: `npx clawsig wrap` needs real-world e2e testing. npm packages need publish.**

---

## Round 4: Technical Moat (KPoM + Sentinel)

| # | Prescribed | Status | Notes |
|---|-----------|--------|-------|
| 1 | Literature review (zkML, fingerprinting, etc.) | SAVED | In Round 4 doc. Not actionable code. |
| 2 | Kinematic Proof of Model (KPoM) | SHIPPED (PR #211) | `clawproxy/src/kinematics.ts`, TTFT/ITL/burst. |
| 3 | Sentinel Trajectory Embeddings | SHIPPED (PR #213) | `services/sentinel/`, Vectorize, Workers AI, KNN. |
| 4 | PRM Data Syndicate | DESIGNED | Concept in Round 4. x402 yield mechanism exists in clawproxy. **No actual syndicate marketplace.** |
| 5 | L2 Merkle Root Anchoring | SHIPPED (PR #211) | `ClawsigRTAnchor.sol`, `clawlogs/src/cron-anchor.ts`. **Not deployed to Base.** |

**Round 4 gaps:**
- **Sentinel not deployed** (needs Vectorize index via dashboard)
- **L2 anchor contract not deployed** to Base Sepolia
- **PRM Syndicate** = concept only, no marketplace/yield contract

---

## Round 5: Red Team + GTM

### Part A: Red Team (11 attacks)

| # | Attack | Fix Status | Notes |
|---|--------|-----------|-------|
| 1 | Kinematic spoofing (artificial delays) | SHIPPED (PR #214 partial) | Burst signature exists. **K-S distribution test NOT implemented.** ASN validation NOT implemented. |
| 2 | Sentinel poisoning | MISSING | **Economic Sybil gate NOT implemented.** Queue accepts unauthenticated submissions. |
| 3 | RT Log manipulation | SHIPPED (PR #211) | L2 anchoring designed. **Contract not deployed.** |
| 4 | Gateway key compromise | SHIPPED (PR #204) | Mandatory RT. **WebCrypto non-extractable keys NOT implemented.** |
| 5 | Proof bundle replay | SHIPPED (PR #214) | Git SHA binding in claw-verified-app. |
| 6 | Wrapper evasion | SHIPPED (PR #214) | Socket-level `preload.mjs` interception. |
| 7 | Privacy attacks (public ledger) | SHIPPED (PR #214) | Ephemeral run salts. |
| 8 | DoS on VaaS | SHIPPED (PR #211) | Hashcash PoW on unauthenticated POSTs. |
| 9 | "Clawsig Inside" social attack | SHIPPED (PR #211) | Heartbeat badge (grays out if no recent runs). |
| 10 | SDK supply chain | SHIPPED (PR #211) | npm provenance workflow. |
| 11 | TOCTOU attacks | SHIPPED (PR #214) | Causal integrity hashes. |

**Red Team gaps:**
- Attack #1: K-S test + ASN validation on kinematics
- Attack #2: Economic Sybil gate on Sentinel ingest
- Attack #4: WebCrypto non-extractable ephemeral keys

### Part B: GTM (60-day plan)

| # | Prescribed | Status | Notes |
|---|-----------|--------|-------|
| 1 | Launch Day (HN/Twitter/Reddit) | DESIGNED (Round 6) | Copy written. Demo repo designed. Video not recorded. **Nothing posted.** |
| 2 | Demo repo (fork Express.js) | DESIGNED (Round 6) | Policy + CI workflow + expected output all specified. **Repo not created.** |
| 3 | First 100 users (supply-side PRs) | DESIGNED | 10 target repos identified. PR template written. **Zero PRs submitted.** |
| 4 | GitHub App deployment | SHIPPED (PR #203) | Code exists. **Not registered as GitHub App. Not deployed for public use.** |
| 5 | npm publish | NOT DONE | Packages exist locally. `npm-publish.yml` workflow exists. **Nothing on npmjs.com is current.** |
| 6 | Blog post | DESIGNED (Round 6) | Full draft. **Not published.** |
| 7 | Twitter thread | DESIGNED (Round 6) | 8 tweets. **Not posted.** |
| 8 | Enterprise pricing page | DESIGNED | Free/Pro/Enterprise tiers defined. **No billing integration.** |
| 9 | Cloudflare AI Gateway pitch | CONCEPT | Identified as "unfair advantage." **No proposal written.** |
| 10 | AVA (Agent Verification Alliance) | PLANNED (6-18mo) | Not actionable yet. |

**GTM gap: 100% designed, 0% executed.**

---

## Round 6: Protocol Spec + Launch Kit

| # | Prescribed | Status | Notes |
|---|-----------|--------|-------|
| 1 | Protocol Spec v1.0 (RFC-style) | SHIPPED (PR #215) | 17 sections, normative refs. Saved as strategy doc. **Not published to clawsig.com/spec.** |
| 2 | Demo repo | DESIGNED | Full spec. **Not created on GitHub.** |
| 3 | HN post | DESIGNED | Title + body. **Not posted.** |
| 4 | Blog post | DESIGNED | Full draft. **Not published.** |
| 5 | Twitter thread | DESIGNED | 8 tweets. **Not posted.** |
| 6 | README for clawsig.com | DESIGNED | Full markdown. **Not deployed.** |
| 7 | Supply-side PR template | DESIGNED | Complete with package.json diff. **Zero PRs.** |

---

## Summary: What's Actually Missing

### Category 1: BLOCKING (must fix before launch)

1. **npm publish** — `@clawbureau/clawsig-sdk`, `clawverify-cli`, `clawverify-core`, `clawsig-conformance` all need current versions on npmjs.com. `npx clawsig wrap` cannot work without this.
2. **GitHub App registration** — Code exists but no GitHub App is registered. Need to create app, get credentials, deploy with secrets.
3. **`npx clawsig wrap` e2e test** — Never tested against a real agent. The MITM proxy, receipt generation, and badge output need validation.
4. **clawsig.com/spec page** — Protocol spec exists as markdown. Needs to be served from `clawsig-www` or a new worker.

### Category 2: HIGH VALUE (ship within launch week)

5. **Express.js demo repo** — Fork, add prompt injection issue, add `.clawsig/policy.json`, add CI workflow. This IS the launch.
6. **K-S distribution test** on kinematics (Red Team Attack #1 fix)
7. **Sentinel Vectorize index** — Create via dashboard, then deploy sentinel worker
8. **DNS propagation** — Verify `explorer.clawsig.com` and `api.clawverify.com` resolve

### Category 3: GTM EXECUTION (post-launch)

9. **HN post** — Copy is ready. Need demo video first.
10. **Supply-side PRs** to 10 target repos
11. **Blog post** on clawsig.com
12. **Twitter thread**
13. **Sybil gate** on Sentinel ingest
14. **WebCrypto non-extractable keys** on clawproxy
15. **L2 anchor contract** deploy to Base Sepolia
16. **PRM Syndicate** marketplace (longer-term)
