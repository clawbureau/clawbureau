# Clawproxy x402 Integration v1

> x402 internet-native payments on clawproxy, making every LLM call payable via crypto.

## Overview

clawproxy becomes an x402 Resource Server. Agents without a CST (enterprise pre-paid) or BYOK key can pay per-call using the x402 protocol. This creates a permissionless pay-as-you-go path to LLM inference with full Clawsig receipt coverage.

## Auth Hierarchy

When a request arrives at clawproxy, it is classified in this order:

1. **CST (Claw Scoped Token)** — Enterprise pre-paid. Highest priority. No payment needed.
2. **BYOK (Bring Your Own Key)** — Agent provides its own API key. No payment needed.
3. **x402 Payment** — Agent includes `X-Payment` header. Verified via facilitator, then proxied.
4. **None** — If `X402_ENABLED=true`, return `402 Payment Required` with pricing. Otherwise return `401 Unauthorized`.

CST and BYOK auth paths are completely unchanged. x402 is additive.

## Payment Flow

```
Agent                    clawproxy                 Facilitator         LLM Provider
  |                          |                          |                    |
  |-- POST /v1/chat -------->|                          |                    |
  |   X-Payment: <payload>   |                          |                    |
  |   X-Idempotency-Key: abc |                          |                    |
  |                          |-- POST /verify --------->|                    |
  |                          |<-- { valid: true } ------|                    |
  |                          |                          |                    |
  |                          |-- POST /v1/chat ---------|------>|            |
  |                          |<-- streaming response ---|------<|            |
  |<-- streaming response ---|                          |                    |
  |                          |                          |                    |
  |                          |-- POST /settle --------->|                    |
  |                          |   actual_amount_minor    |                    |
  |                          |<-- { tx_hash } ----------|                    |
  |                          |                          |                    |
  |                          | [emit GatewayReceipt     |                    |
  |                          |  with x402 metadata]     |                    |
```

## Bidirectional Hash Cross-Commitment

Per Gemini Deep Think Problem 1 resolution:

1. The agent commits its `X-Idempotency-Key` into the x402 `PaymentPayload` metadata
2. clawproxy verifies the idempotency key matches between the payment and the request
3. The `GatewayReceipt` includes `x402_payment_auth_hash_b64u = sha256_b64u(PaymentPayload)`
4. Neither the payment nor the receipt can be replayed or split

## Schema Extensions

### gateway_receipt.v1.json (optional fields)

| Field | Type | Description |
|-------|------|-------------|
| `x402_payment_ref` | string | Transaction hash or facilitator reference |
| `x402_amount_minor` | integer | Settled amount in minor units |
| `x402_currency` | string | Payment currency (e.g., USDC) |
| `x402_network` | string | Payment network (e.g., base, base-sepolia) |
| `x402_payment_auth_hash_b64u` | string | SHA-256 hash of PaymentPayload (cross-commitment) |

All fields are optional. Receipts without x402 fields remain valid for CST/BYOK flows.

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `X402_ENABLED` | `false` | Enable x402 payment acceptance |
| `X402_FACILITATOR_URL` | `https://x402.org/facilitator` | Facilitator endpoint |
| `X402_RESOURCE_WALLET` | (required when enabled) | Wallet address for payments |
| `X402_PRICE_TABLE` | `{}` | JSON: model -> pricing |
| `X402_NETWORK` | `base-sepolia` | Payment network |
| `X402_DEFAULT_MAX_AMOUNT_MINOR` | `100000` | Default max per request (0.10 USDC) |

### Price Table Format

```json
{
  "openai/gpt-4o": {
    "input_per_1k_minor": 250,
    "output_per_1k_minor": 1000,
    "max_request_minor": 500000
  },
  "anthropic/claude-sonnet-4": {
    "input_per_1k_minor": 300,
    "output_per_1k_minor": 1500,
    "max_request_minor": 750000
  }
}
```

## Fail-Closed Behavior

- If `X402_ENABLED=true` but `X402_RESOURCE_WALLET` is not set: all x402 requests are rejected (402)
- If facilitator is unreachable: payment is rejected (502)
- If payment verification fails: request is rejected (402)
- If settlement fails after LLM call: receipt is still issued with `x402_payment_ref: "pending:..."` — settlement is retried async
- CST auth never falls through to x402 — separate code paths

## Coexistence with CST

| Scenario | Auth Used | Payment |
|----------|-----------|---------|
| CST header present | CST | Pre-paid enterprise |
| BYOK key present | BYOK | Agent's own API key |
| X-Payment header present | x402 | Per-call crypto |
| Nothing, x402 enabled | None | 402 Payment Required |
| Nothing, x402 disabled | None | 401 Unauthorized |

## Future: Mainnet Deployment

1. Set `X402_NETWORK=base` and `X402_FACILITATOR_URL` to production Coinbase facilitator
2. Configure real `X402_RESOURCE_WALLET` with USDC on Base
3. Populate `X402_PRICE_TABLE` with production pricing
4. Monitor settlement via facilitator dashboard
