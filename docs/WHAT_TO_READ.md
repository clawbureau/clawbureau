> **Type:** Index
> **Status:** ACTIVE
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-18
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
6. `docs/specs/clawsig-protocol/CLAWSIG_PROTOCOL_v1.0.md`

## Marketplace engineer (clawbounties / escrow / ledger)

1. `docs/specs/agent-economy/MVP.md`
2. PRDs:
   - `docs/prds/clawbounties.md`
   - `docs/prds/clawescrow.md`
   - `docs/prds/clawledger.md`
3. `docs/foundations/INTERCONNECTION.md`

## Trust / PoH engineer (clawproxy / clawverify / protocol)

1. `docs/specs/clawsig-protocol/CLAWSIG_PROTOCOL_v1.0.md`
2. `docs/specs/clawsig-protocol/CHANGELOG.md` (`v0.2.0` section)
3. `docs/roadmaps/clawsig-protocol-v0.2/README.md`
4. `docs/roadmaps/proof-of-harness/README.md`
5. `docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md`
6. `docs/roadmaps/proof-of-harness/HARNESS_REGISTRY.md`
7. `docs/roadmaps/trust-vnext/README.md`
8. PRDs:
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
2. `docs/specs/clawsig-protocol/CLAWSIG_PROTOCOL_v1.0.md` — normative spec
3. `docs/specs/clawsig-protocol/CHANGELOG.md` — shipped version deltas (`v0.2.0`)
4. `docs/roadmaps/clawsig-protocol-v0.2/README.md` — execution tracker + status
5. `scripts/protocol/run-clawsig-v0.2-quickstart.mjs` — executable quickstart runner
6. `packages/clawsig-sdk/README.md` — SDK API reference + quickstart
7. `packages/clawverify-cli/README.md` — offline verifier CLI
8. `docs/specs/clawsig-protocol/REASON_CODE_REGISTRY.md` — error codes
9. `docs/examples/integrations/README.md` — copy/paste starter packs (Node/GitHub/Enterprise CI)
10. `packages/schema/fixtures/protocol-conformance/manifest.v1.json` — conformance vectors
11. `docs/foundations/CLAW_VERIFIED_PR_PIPELINE.md` — CI integration example

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
2. `docs/pilot/clawsig-v0.2-enterprise-pilot-pack.md` — 30-day pilot plan + evidence requirements
3. `docs/specs/clawsig-protocol/ADOPTION_GUIDE.md` §2 — security team guide
4. `docs/specs/clawsig-protocol/CLAWSIG_PROTOCOL_v1.0.md` §5 — Claw Verified supply-chain trust
5. `docs/foundations/ARCHITECTURE.md` — service topology
6. `docs/specs/clawsig-protocol/REASON_CODE_REGISTRY.md` — fail-closed error contract
7. `docs/foundations/DEPLOYMENT_RUNBOOK.md` — operational procedures
8. Security Review Pack → [clawea.com/security](https://clawea.com/security) (external)
