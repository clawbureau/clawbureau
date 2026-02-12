# Agent A Dispatch: Phase 4 — x402 Integration on clawproxy

## Context

Read these files first:
- `docs/strategy/GEMINI_DEEP_THINK_REVIEW_2026-02-12.md` — strategic mandate
- `services/clawproxy/src/index.ts` — current clawproxy implementation
- `services/clawproxy/prd.json` — current story tracker
- `packages/schema/poh/gateway_receipt.v1.json` — receipt schema

## Background: x402

x402 is Coinbase's open standard for HTTP-native payments:
1. Client requests resource
2. Server responds `402 Payment Required` + payment requirements header
3. Client creates payment (EVM/Solana/fiat) and retries with payment proof
4. Server verifies payment via facilitator, fulfills request
5. Server settles via facilitator

SDKs: `@x402/core`, `@x402/evm`, `@x402/hono` (Cloudflare Workers use Hono)

## Your Mission

Make `clawproxy` a native x402 Resource Server. When an agent wants verifiable LLM inference, the flow becomes:

1. Agent sends `POST /v1/proxy/:provider` to clawproxy
2. If no valid payment: clawproxy responds `402 Payment Required` with x402 headers
3. Agent pays via x402 facilitator (USDC on Base is the default)
4. Agent retries with `PAYMENT-SIGNATURE` header
5. clawproxy verifies payment, proxies to LLM provider, returns response + Clawsig Gateway Receipt
6. Receipt includes `x402_payment_ref` field linking to the payment

### Deliverable 1: Integration Design
`docs/specs/x402/CLAWPROXY_X402_INTEGRATION_v1.md`

Must cover:
- x402 payment flow on Cloudflare Workers (using `@x402/hono`)
- Pricing model: how to set per-request prices (token-based? fixed per call?)
- Which x402 scheme to use (`exact` for fixed-price, `upto` for token-metered)
- Facilitator selection (Coinbase default vs. self-hosted)
- How x402 coexists with existing CST-based auth (CST = pre-paid, x402 = pay-per-call)
- Gateway Receipt schema extension to include payment reference

### Deliverable 2: Gateway Receipt Extension
Add optional x402 fields to `gateway_receipt.v1.json`:
```json
{
  "x402_payment_ref": { "type": "string", "description": "x402 payment transaction hash or facilitator reference" },
  "x402_amount_minor": { "type": "integer", "description": "Amount paid in minor units" },
  "x402_currency": { "type": "string", "description": "Payment currency (e.g., USDC)" },
  "x402_network": { "type": "string", "description": "Payment network (e.g., base, ethereum)" }
}
```

### Deliverable 3: Prototype Implementation
Add x402 middleware to clawproxy:
- Install `@x402/core` and `@x402/hono`
- Add `X402_ENABLED` environment flag (default: false)
- When enabled, requests without CST or x402 payment get `402`
- When disabled, existing CST auth continues to work unchanged

### Constraints
- x402 is **opt-in** — existing CST auth must keep working
- Start with Base testnet (USDC) — do not use mainnet
- Do NOT remove existing rate limiting or DID-based auth
- The receipt MUST include payment reference when x402 is used
- Cloudflare Workers compatibility required (no Node.js-only deps)
