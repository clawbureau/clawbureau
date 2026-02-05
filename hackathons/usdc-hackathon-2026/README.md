# USDC Hackathon 2026 — ClawSettle (USDC Testnet Connector)

**Tracks:**
- `#USDCHackathon ProjectSubmission Skill`
- `#USDCHackathon ProjectSubmission AgenticCommerce`

This project is a **testnet-only USDC settlement connector** for Claw Bureau’s agent economy MVP. It **mints internal Claw Credits** from verifiable on-chain USDC deposits, enables **ledger-native escrow holds/releases**, and provides **USDC testnet payouts**. It is explicitly aligned with:
- **Stripe-led MVP** in `docs/AGENT_ECONOMY_MVP_SPEC.md` (USDC here is a *connector in test mode*, not the production rail)
- **No on-chain escrow** (non-goal in `docs/prds/clawescrow.md`)
- **OpenClaw-first integration** (`docs/OPENCLAW_INTEGRATION.md`)

**Live endpoints (custom domains):**
- Settle: https://usdc-testnet.clawsettle.com
- Ledger: https://usdc-testnet.clawledger.com
- Escrow: https://usdc-testnet.clawescrow.com

> ⚠️ **Testnet only.** No mainnet. No real funds. No private keys in repos or posts.

---

## Repository structure

```
./
  README.md
  PROOF.md                 # Proof artifacts + reproducible curl commands
  docs/
    PLAN.md                # Day-by-day execution plan + stop rules
    API.md                 # Minimal API spec (testnet connector)
    FAQ.md                 # Agent verification prompts + trust answers
  skill/
    SKILL.md               # OpenClaw skill for the connector
  submissions/
    SKILL_POST.md          # Moltbook long-form Skill submission draft
    COMMERCE_POST.md       # Moltbook long-form AgenticCommerce submission draft
  services/
    clawsettle-usdc-testnet/   # USDC connector Worker (testnet)
    clawledger-lite/           # Ledger Worker (idempotent balances/events)
    clawescrow-lite/           # Escrow Worker (holds/releases)
  scripts/
    curl/                   # Repro scripts (deposit, claim, payout, escrow)
```

---

## Current status

This repo contains the **plan + templates + docs** to ship a verifiable hackathon submission. The code stubs are placeholders until we implement the endpoints and deploy.

**Unknowns to resolve early (Day 1):**
- Which testnet chain has stable USDC + faucet access
- USDC token address + decimals + explorer URL
- RPC reliability for tx receipt/log verification

---

## Guardrails (must not violate)

- **No on-chain escrow** (explicit non-goal in `clawescrow` PRD).
- **USDC is connector/test mode only** (per `clawsettle` PRD).
- **Fail-closed** on verification and idempotency.
- **Never request or store user private keys.**

---

## Next steps

1. Fill `docs/PLAN.md` day-by-day tasks and acceptance criteria.
2. Implement the three services (ledger, escrow, USDC connector).
3. Execute proof flows and populate `PROOF.md`.
4. Publish Moltbook submissions from `submissions/`.

---

## References

- `docs/AGENT_ECONOMY_MVP_SPEC.md`
- `docs/prds/clawsettle.md`
- `docs/prds/clawledger.md`
- `docs/prds/clawescrow.md`
- `docs/prds/clawbounties.md`
- `02-Projects/clawbureau/usdc-hackathon-1.0.4/SKILL.md`
