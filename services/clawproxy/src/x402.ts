/**
 * x402 Internet-Native Payments for clawproxy (Phase 4)
 *
 * Implements RFC x402 payment flow on Cloudflare Workers:
 * - 402 Payment Required responses with pricing requirements
 * - Payment header verification via facilitator
 * - Settlement after LLM call completion
 * - Gateway Receipt metadata for payment-proof binding
 *
 * Design per: docs/strategy/GEMINI_DEEP_THINK_HARD_PROBLEMS_2026-02-12.md (Problem 1)
 * Spec per: docs/specs/x402/CLAWPROXY_X402_INTEGRATION_v1.md
 */

import type { Env } from './types';

// ---------- Types ----------

export interface X402PaymentPayload {
  /** x402 payment signature from agent */
  paymentSignature: string;
  /** Encoded payment payload (base64) */
  paymentPayload: string;
  /** Amount authorized in minor units */
  amountMinor: number;
  /** Currency (e.g., USDC) */
  currency: string;
  /** Network (e.g., base, base-sepolia) */
  network: string;
}

export interface X402PaymentRequirements {
  /** Wallet address to receive payment */
  payTo: string;
  /** Maximum amount in minor units */
  maxAmountMinor: number;
  /** Currency */
  currency: string;
  /** Network */
  network: string;
  /** Payment scheme: exact or upto */
  scheme: 'exact' | 'upto';
  /** Facilitator URL */
  facilitatorUrl: string;
  /** Resource description */
  resource: string;
  /** Idempotency key binding */
  idempotencyKey?: string;
}

export interface X402PaymentContext {
  /** Original payment payload for receipt binding */
  payload: X402PaymentPayload;
  /** Whether payment was verified by facilitator */
  verified: boolean;
  /** Facilitator settlement reference (populated after settlement) */
  settlementRef?: string;
  /** Actual amount settled in minor units */
  settledAmountMinor?: number;
}

export interface X402ReceiptMetadata {
  x402_payment_ref: string;
  x402_amount_minor: number;
  x402_currency: string;
  x402_network: string;
  /** sha256_b64u of the payment payload — bidirectional hash cross-commitment */
  x402_payment_auth_hash_b64u: string;
}

// ---------- Config ----------

const DEFAULT_FACILITATOR_URL = 'https://x402.org/facilitator';
const DEFAULT_NETWORK = 'base-sepolia';
const DEFAULT_MAX_AMOUNT_MINOR = 100_000; // 0.10 USDC
const DEFAULT_CURRENCY = 'USDC';

// ---------- Feature flag ----------

export function isX402Enabled(env: Env): boolean {
  return env.X402_ENABLED === 'true' || env.X402_ENABLED === '1';
}

// ---------- Payment detection ----------

/**
 * Check if the request contains an x402 payment header.
 * x402 spec uses `X-PAYMENT` or `Payment` header.
 */
export function hasX402Payment(request: Request): boolean {
  return !!(request.headers.get('x-payment') || request.headers.get('payment'));
}

/**
 * Extract the x402 payment from request headers.
 */
export function extractX402Payment(request: Request): X402PaymentPayload | null {
  const raw = request.headers.get('x-payment') || request.headers.get('payment');
  if (!raw) return null;

  try {
    // x402 payment header is base64-encoded JSON
    const decoded = JSON.parse(atob(raw));
    return {
      paymentSignature: decoded.signature || decoded.paymentSignature || '',
      paymentPayload: raw, // Keep original for hashing
      amountMinor: decoded.amount || decoded.amountMinor || 0,
      currency: decoded.currency || DEFAULT_CURRENCY,
      network: decoded.network || DEFAULT_NETWORK,
    };
  } catch {
    return null;
  }
}

// ---------- 402 Payment Required response ----------

/**
 * Build a 402 Payment Required response with pricing requirements.
 * Sent when x402 is enabled and request has no CST, no BYOK, and no payment.
 */
export function buildPaymentRequiredResponse(
  env: Env,
  model: string,
  idempotencyKey?: string,
): Response {
  const requirements: X402PaymentRequirements = {
    payTo: env.X402_RESOURCE_WALLET || '',
    maxAmountMinor: getModelPrice(env, model),
    currency: DEFAULT_CURRENCY,
    network: env.X402_NETWORK || DEFAULT_NETWORK,
    scheme: 'upto',
    facilitatorUrl: env.X402_FACILITATOR_URL || DEFAULT_FACILITATOR_URL,
    resource: `llm:${model}`,
    ...(idempotencyKey ? { idempotencyKey } : {}),
  };

  return new Response(JSON.stringify({
    error: 'payment_required',
    message: 'This endpoint requires x402 payment. Include a Payment header with your request.',
    requirements,
  }), {
    status: 402,
    headers: {
      'Content-Type': 'application/json',
      'X-Payment-Requirements': btoa(JSON.stringify(requirements)),
    },
  });
}

// ---------- Payment verification ----------

/**
 * Verify x402 payment via the facilitator.
 * Fast, stateless verification — checks signature and authorization.
 */
export async function verifyX402Payment(
  env: Env,
  payment: X402PaymentPayload,
  idempotencyKey?: string,
): Promise<{ valid: boolean; reason?: string }> {
  const facilitatorUrl = env.X402_FACILITATOR_URL || DEFAULT_FACILITATOR_URL;

  try {
    const resp = await fetch(`${facilitatorUrl}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        payment: payment.paymentPayload,
        resource_wallet: env.X402_RESOURCE_WALLET,
        ...(idempotencyKey ? { idempotency_key: idempotencyKey } : {}),
      }),
    });

    if (!resp.ok) {
      const body = await resp.text().catch(() => '');
      return { valid: false, reason: `facilitator_rejected: ${resp.status} ${body.slice(0, 200)}` };
    }

    const result = await resp.json() as { valid?: boolean; reason?: string };
    return { valid: result.valid === true, reason: result.reason };
  } catch (err) {
    // Fail closed — if facilitator is unreachable, reject payment
    return { valid: false, reason: `facilitator_unreachable: ${String(err)}` };
  }
}

// ---------- Settlement ----------

/**
 * Settle x402 payment after LLM call completes.
 * For `upto` scheme, settles the actual amount used.
 */
export async function settleX402Payment(
  env: Env,
  payment: X402PaymentPayload,
  actualAmountMinor: number,
): Promise<{ settled: boolean; ref?: string }> {
  const facilitatorUrl = env.X402_FACILITATOR_URL || DEFAULT_FACILITATOR_URL;

  try {
    const resp = await fetch(`${facilitatorUrl}/settle`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        payment: payment.paymentPayload,
        resource_wallet: env.X402_RESOURCE_WALLET,
        actual_amount_minor: actualAmountMinor,
      }),
    });

    if (!resp.ok) {
      // Settlement failure is non-fatal for the proxy response.
      // The receipt records the authorized amount; settlement is async.
      return { settled: false };
    }

    const result = await resp.json() as { transaction_hash?: string; ref?: string };
    return { settled: true, ref: result.transaction_hash || result.ref };
  } catch {
    return { settled: false };
  }
}

// ---------- Receipt metadata ----------

/**
 * Build x402 metadata fields for the GatewayReceipt.
 * Implements bidirectional hash cross-commitment per Gemini Deep Think Problem 1.
 */
export async function buildX402ReceiptMetadata(
  ctx: X402PaymentContext,
): Promise<X402ReceiptMetadata> {
  // Hash the original payment payload for cross-commitment binding
  const payloadBytes = new TextEncoder().encode(ctx.payload.paymentPayload);
  const hashBuffer = await crypto.subtle.digest('SHA-256', payloadBytes);
  const hashArray = new Uint8Array(hashBuffer);

  // base64url encode (no padding)
  const b64u = btoa(String.fromCharCode(...hashArray))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

  return {
    x402_payment_ref: ctx.settlementRef || `pending:${ctx.payload.paymentSignature.slice(0, 16)}`,
    x402_amount_minor: ctx.settledAmountMinor || ctx.payload.amountMinor,
    x402_currency: ctx.payload.currency,
    x402_network: ctx.payload.network,
    x402_payment_auth_hash_b64u: b64u,
  };
}

// ---------- Pricing ----------

interface ModelPrice {
  input_per_1k_minor: number;
  output_per_1k_minor: number;
  max_request_minor: number;
}

/**
 * Get the max price for a model request (used for `upto` scheme).
 */
function getModelPrice(env: Env, model: string): number {
  if (env.X402_PRICE_TABLE) {
    try {
      const table = JSON.parse(env.X402_PRICE_TABLE) as Record<string, ModelPrice>;
      if (table[model]) {
        return table[model].max_request_minor;
      }
    } catch { /* ignore malformed table, use default */ }
  }
  return Number(env.X402_DEFAULT_MAX_AMOUNT_MINOR) || DEFAULT_MAX_AMOUNT_MINOR;
}

/**
 * Estimate actual cost from token counts (for settlement).
 */
export function estimateTokenCost(
  env: Env,
  model: string,
  inputTokens: number,
  outputTokens: number,
): number {
  if (env.X402_PRICE_TABLE) {
    try {
      const table = JSON.parse(env.X402_PRICE_TABLE) as Record<string, ModelPrice>;
      if (table[model]) {
        const p = table[model];
        return Math.ceil(
          (inputTokens / 1000) * p.input_per_1k_minor +
          (outputTokens / 1000) * p.output_per_1k_minor
        );
      }
    } catch { /* use default */ }
  }
  // Conservative default: 0.01 USDC per 1k tokens
  return Math.ceil(((inputTokens + outputTokens) / 1000) * 10);
}
