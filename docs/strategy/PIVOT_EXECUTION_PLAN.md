# Pivot Execution Plan: Nation-State to Notary

> Canonical execution plan derived from Gemini Deep Think Review (2026-02-12).
> All agents reference this document. No work outside this plan without approval.

---

## Execution Phases

### Phase 0: Document & Archive (Agent: Coordinator)
**Goal:** Preserve institutional knowledge before teardown.

- [x] P0-1: Save Gemini review as canonical strategy (`docs/strategy/`) — PR #196
- [x] P0-2: Create this execution plan — PR #196
- [x] P0-3: Archive current service inventory with final health status — PR #196
- [x] P0-4: Tag git with `v0-nation-state` — tag pushed to origin
- [x] P0-5: Update MEMORY.md with strategic pivot decision

### Phase 1: The Purge — Service Teardown (Agent A: Protocol)
**Goal:** Remove dead weight services from deployment. Code stays in git history.

**Undeploy (remove Workers, keep code in repo as `services/_archived/`):**
- [x] P1-1: `clawbounties` — marketplace — PR #197
- [x] P1-2: `clawescrow` / `escrow` — payment holds — PR #197
- [x] P1-3: `clawledger` / `ledger` — double-entry ledger — PR #197
- [x] P1-4: `clawsettle` — Stripe settlement — PR #197
- [x] P1-5: `clawcuts` — fee engine — PR #197
- [x] P1-6: `clawclaim` — identity binding — PR #197
- [x] P1-7: `clawrep` — reputation — PR #197
- [x] P1-8: `clawtrials` — arbitration — PR #197
- [x] P1-9: `clawincome` — revenue aggregation — PR #197
- [x] P1-10: `clawinsure` — SLA insurance — PR #197
- [x] P1-11: `clawdelegate` — identity delegation — PR #197
- [x] P1-12: `claw-domains` — landing pages — PR #197

**Keep deployed (the Diamond):**
- `clawverify` — Trust Oracle (enhance)
- `clawproxy` — Data Plane (enhance with x402)
- `clawcontrols` — absorb into clawea
- `clawscope` — absorb into clawea
- `clawlogs` — absorb into clawverify
- `clawea-www` — pivot to enterprise dashboard + protocol standard site

**DNS:** Park all killed domains. Point to a "Claw Bureau has evolved" page.

### Phase 2: Domain Consolidation (Agent D: Marketing)
**Goal:** 31 domains down to 4 pillars.

- [x] P2-1: `clawsig.com` IS the protocol standard site (already live, no .org needed)
- [ ] P2-2: Enhance `clawsig.com` — Clawsig specs, schemas, reason codes, CLI docs
- [ ] P2-3: Refocus `clawverify.com` — Trust Oracle landing + API docs
- [ ] P2-4: Refocus `clawproxy.com` — Data Plane landing + developer quickstart
- [ ] P2-5: Refocus `clawea.com` — Enterprise dashboard (absorb clawcontrols + clawscope UI)
- [ ] P2-6: Park 27 killed domains with redirect/placeholder
- [ ] P2-7: Update all npm package READMEs to point to 5-domain structure (clawsig/verify/proxy/ea/bureau)

### Phase 3: Protocol Hardening (Agent A: Protocol)
**Goal:** Make Clawsig the standard validation oracle for EIP-8004.

- [x] P3-1: EIP-8004 integration design — PR #198
- [x] P3-2: Add `supportedTrust: ["clawsig"]` to agent registration file spec — PR #198
- [x] P3-3: Define `.well-known/clawsig.json` standard — PR #198
- [ ] P3-4: Publish clawverify as EIP-8004 Validation Oracle contract adapter (deferred — needs Solidity)
- [x] P3-5: Update proof_bundle schema with EIP-8004 `agentId` field — PR #198
- [x] P3-6: `@clawbureau/clawsig-adapters` npm prep (private:true removed) — PR #198, needs `npm publish`
- [x] P3-7: `@openclaw/provider-clawproxy` npm prep (private:true removed) — PR #198, needs `npm publish`

### Phase 4: x402 Integration (Agent A: Protocol)
**Goal:** Make clawproxy a native x402 Resource Server.

- [x] P4-1: x402 integration design — PR #200 (`docs/specs/x402/CLAWPROXY_X402_INTEGRATION_v1.md`)
- [x] P4-2: x402 module + types added to clawproxy — PR #200 (`services/clawproxy/src/x402.ts`)
- [x] P4-3: x402 payment verification middleware (fail-closed) — PR #200
- [x] P4-4: Gateway Receipt with x402 payment ref + hash cross-commitment — PR #200
- [ ] P4-5: Test with Base testnet (needs wallet + facilitator setup)
- [x] P4-6: Document x402 + Clawsig flow — PR #200

### Phase 5: The MVP Wedge — Claw Verified GitHub App (Agent A + D)
**Goal:** First external users via CI/CD integration.

- [ ] P5-1: Build GitHub App that triggers on PR events
- [ ] P5-2: App checks for `proof_bundle.json` in PR
- [ ] P5-3: Runs `@clawbureau/clawverify-cli` offline against repo's `.clawsig/policy.json` (WPC)
- [ ] P5-4: Posts "Claw Verified" check status (pass/fail with reason codes)
- [ ] P5-5: Build `clawsig init` flow that scaffolds `.clawsig/` in any repo
- [ ] P5-6: Landing page on clawprotocol.org for the GitHub App
- [ ] P5-7: Submit to GitHub Marketplace
- [ ] P5-8: Write "Getting Started" guide: install app, add WPC, get first verified PR

### Phase 6: Enterprise Policy Dashboard (Agent D: Marketing → becomes Product)
**Goal:** Monetizable SaaS — visual WPC authoring + fleet management.

- [ ] P6-1: Design WPC policy builder UI (visual drag-drop constraints)
- [ ] P6-2: Absorb clawcontrols WPC registry into clawea.com
- [ ] P6-3: Absorb clawscope CST issuance into clawea.com
- [ ] P6-4: Build SIEM integration (Splunk, Datadog, PagerDuty webhook)
- [ ] P6-5: Build verification-gated Stripe payout trigger
- [ ] P6-6: Pricing page for enterprise tier

---

## Agent Lane Reassignment

| Agent | Old Lane | New Lane |
|-------|----------|----------|
| Agent A | Protocol / Trust / Verification | Protocol hardening + x402 + EIP-8004 integration |
| Agent C | Economy / Risk / Settlement | **DISSOLVED** — no economy lane needed |
| Agent D | Marketing (clawea-www) | Product (enterprise dashboard + GitHub App UX) |

Agent C's engineering capacity redirects to Agent A (protocol integration work is the bottleneck).

---

## Success Metrics

| Metric | Current | Target (30 days) |
|--------|---------|-------------------|
| Live services | 16 | 4 (verify, proxy, ea, protocol site) |
| Domains active | 16+ | 4 |
| Marketing pages | 157 | ~20 (focused on protocol + enterprise) |
| npm packages | 3 published | 5 published (+ adapters + openclaw provider) |
| External users | 0 | 10+ GitHub repos with Claw Verified |
| GitHub App installs | 0 | 50+ |
| EIP-8004 integration | None | Design doc + reference implementation |
| x402 integration | None | Working testnet demo |

---

## Deep Think Prompt Checkpoints

At key milestones, generate new `/deep-think-prompt` outputs and submit to Gemini for validation:

1. **After Phase 1 complete:** "Review our teardown. Did we miss anything that should be killed?"
2. **After Phase 3 design:** "Review our EIP-8004 integration design. Is this the right approach?"
3. **After Phase 5 MVP:** "Review our GitHub App. What's missing for developer adoption?"
4. **After Phase 6 design:** "Review our enterprise dashboard design. Will CISOs buy this?"
