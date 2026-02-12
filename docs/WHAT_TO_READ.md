> **Type:** Index
> **Status:** ACTIVE
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-12
> **Source of truth:** `docs/README.md`
>
> **Scope:**
> - Fast reading paths by audience.
> - Not a replacement for PRDs/roadmaps.

# What to read (by audience)

## New contributor (5–10 minutes)

1. `docs/README.md`
2. `docs/ecosystem/AGENTS.md` (workspace + current status caveats)
3. `docs/foundations/INTERCONNECTION.md`
4. `docs/foundations/GIT_STRATEGY.md`
5. `docs/roadmaps/README.md`
6. `docs/specs/clawsig-protocol/CLAWSIG_PROTOCOL_v0.1.md`

## Marketplace engineer (clawbounties / escrow / ledger)

1. `docs/specs/agent-economy/MVP.md`
2. PRDs:
   - `docs/prds/clawbounties.md`
   - `docs/prds/clawescrow.md`
   - `docs/prds/clawledger.md`
3. `docs/foundations/INTERCONNECTION.md`

## Trust / PoH engineer (clawproxy / clawverify / protocol)

1. `docs/specs/clawsig-protocol/CLAWSIG_PROTOCOL_v0.1.md`
2. `docs/roadmaps/clawsig-protocol/README.md`
3. `docs/roadmaps/proof-of-harness/README.md`
4. `docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md`
5. `docs/roadmaps/proof-of-harness/HARNESS_REGISTRY.md`
6. `docs/roadmaps/trust-vnext/README.md`
7. PRDs:
   - `docs/prds/clawcontrols.md`
   - `docs/prds/clawscope.md`
   - `docs/prds/clawproxy.md`
   - `docs/prds/clawverify.md`

## OpenClaw integration engineer

1. `docs/integration/OPENCLAW_INTEGRATION.md`
2. `docs/openclaw/README.md`
3. Start with:
   - `docs/openclaw/10-extensions-and-plugins.md`
   - `docs/openclaw/6.2-tool-security-and-sandboxing.md`
   - `docs/openclaw/9.3-directives.md`

## Protocol adopter (third-party agent framework / tool author)

> You want to emit verifiable proof bundles from your own agent or verify bundles produced by others.

1. `docs/specs/clawsig-protocol/ADOPTION_GUIDE.md` — **start here** (integration in a day)
2. `docs/specs/clawsig-protocol/CLAWSIG_PROTOCOL_v0.1.md` — normative spec
3. `packages/clawsig-sdk/README.md` — SDK API reference + quickstart
4. `packages/clawverify-cli/README.md` — offline verifier CLI
5. `docs/specs/clawsig-protocol/REASON_CODE_REGISTRY.md` — error codes
6. `packages/schema/fixtures/protocol-conformance/manifest.v1.json` — conformance vectors
7. `docs/foundations/CLAW_VERIFIED_PR_PIPELINE.md` — CI integration example

## Economy / risk developer (clawsettle / clawdelegate / escrow)

> You work on the economic layer: payments, settlements, delegation, risk controls.

1. `docs/specs/agent-economy/MVP.md` — economy architecture
2. PRDs:
   - `docs/prds/clawsettle.md` — settlements + disputes
   - `docs/prds/clawdelegate.md` — delegation control plane
   - `docs/prds/clawescrow.md` — escrow service
   - `docs/prds/clawledger.md` — ledger service
3. `docs/specs/payments/MACHINE_PAYMENT_SETTLEMENT_v1.md` — settlement spec
4. `docs/foundations/INTERCONNECTION.md` — service dependencies
5. `docs/roadmaps/trust-vnext/README.md` — economy roadmap tracker

## Enterprise buyer (clawea / security review)

> You're evaluating Clawbureau for enterprise deployment.

1. `docs/prds/clawea-enterprise.md` — enterprise platform overview
2. `docs/specs/clawsig-protocol/ADOPTION_GUIDE.md` §2 — security team guide
3. `docs/specs/clawsig-protocol/CLAWSIG_PROTOCOL_v0.1.md` §5 — Claw Verified supply-chain trust
4. `docs/foundations/ARCHITECTURE.md` — service topology
5. `docs/specs/clawsig-protocol/REASON_CODE_REGISTRY.md` — fail-closed error contract
6. `docs/foundations/DEPLOYMENT_RUNBOOK.md` — operational procedures
7. Security Review Pack → [clawea.com/security](https://clawea.com/security) (external)
