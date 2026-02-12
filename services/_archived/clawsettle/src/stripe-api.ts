/**
 * ECON-SETTLE-002: Stripe API client for PaymentIntent creation and Connect transfers.
 *
 * Uses Stripe HTTP API directly (no SDK dependency for Workers compatibility).
 * All amounts in minor units (cents). Fail-closed on any Stripe error.
 */

import type { Env } from './types';
import { ClawSettleError } from './stripe';

const STRIPE_API_BASE = 'https://api.stripe.com/v1';

function requireStripeKey(env: Env): string {
  const key = env.STRIPE_SECRET_KEY?.trim();
  if (!key) {
    throw new ClawSettleError(
      'STRIPE_SECRET_KEY not configured',
      'STRIPE_NOT_CONFIGURED',
      503,
      { field: 'STRIPE_SECRET_KEY' }
    );
  }
  return key;
}

function encodeForm(params: Record<string, string>): string {
  return Object.entries(params)
    .filter(([, v]) => v !== undefined && v !== null)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join('&');
}

async function stripeRequest(
  key: string,
  method: string,
  path: string,
  params?: Record<string, string>,
  idempotencyKey?: string
): Promise<{ status: number; data: Record<string, unknown> }> {
  const url = `${STRIPE_API_BASE}${path}`;
  const headers: Record<string, string> = {
    'Authorization': `Bearer ${key}`,
    'Stripe-Version': '2024-12-18.acacia',
  };

  if (idempotencyKey) {
    headers['Idempotency-Key'] = idempotencyKey;
  }

  const init: RequestInit = { method, headers };

  if (params && (method === 'POST' || method === 'PUT')) {
    headers['Content-Type'] = 'application/x-www-form-urlencoded';
    init.body = encodeForm(params);
  }

  const res = await fetch(url, init);
  const text = await res.text();

  let data: Record<string, unknown>;
  try {
    data = JSON.parse(text);
  } catch {
    throw new ClawSettleError(
      `Stripe API returned non-JSON: ${text.slice(0, 200)}`,
      'STRIPE_API_ERROR',
      502,
    );
  }

  return { status: res.status, data };
}

// ---------------------------------------------------------------------------
// PaymentIntent — escrow funding inbound rail
// ---------------------------------------------------------------------------

export interface CreatePaymentIntentResult {
  payment_intent_id: string;
  client_secret: string;
  status: string;
  amount_minor: string;
  currency: string;
}

/**
 * Create a Stripe PaymentIntent for escrow funding.
 *
 * The caller must pass `metadata.escrow_id` and `metadata.account_id`
 * so the webhook handler can route the confirmed payment.
 */
export async function createPaymentIntent(
  env: Env,
  params: {
    amount_minor: string;
    currency: string;
    escrow_id: string;
    account_id: string;
    idempotency_key: string;
    metadata?: Record<string, string>;
  }
): Promise<CreatePaymentIntentResult> {
  const key = requireStripeKey(env);

  const formParams: Record<string, string> = {
    amount: params.amount_minor,
    currency: params.currency.toLowerCase(),
    'metadata[escrow_id]': params.escrow_id,
    'metadata[account_id]': params.account_id,
    'metadata[idempotency_key]': params.idempotency_key,
    'automatic_payment_methods[enabled]': 'true',
  };

  if (params.metadata) {
    for (const [k, v] of Object.entries(params.metadata)) {
      formParams[`metadata[${k}]`] = v;
    }
  }

  const { status, data } = await stripeRequest(
    key, 'POST', '/payment_intents', formParams, params.idempotency_key
  );

  if (status < 200 || status >= 300) {
    const errMsg = typeof data.error === 'object' && data.error !== null
      ? (data.error as Record<string, unknown>).message ?? 'Unknown Stripe error'
      : JSON.stringify(data);
    throw new ClawSettleError(
      `Stripe PaymentIntent creation failed: ${errMsg}`,
      'STRIPE_PAYMENT_INTENT_FAILED',
      502,
      { stripe_status: status, stripe_error: data.error },
    );
  }

  return {
    payment_intent_id: String(data.id),
    client_secret: String(data.client_secret),
    status: String(data.status),
    amount_minor: params.amount_minor,
    currency: params.currency,
  };
}

// ---------------------------------------------------------------------------
// Connect Transfer — worker payout outbound rail
// ---------------------------------------------------------------------------

export interface CreateTransferResult {
  transfer_id: string;
  amount_minor: string;
  currency: string;
  destination: string;
  status: string;
}

/**
 * Create a Stripe Connect Transfer to a connected account (worker payout).
 */
export async function createConnectTransfer(
  env: Env,
  params: {
    amount_minor: string;
    currency: string;
    destination_account_id: string;
    payout_id: string;
    idempotency_key: string;
    metadata?: Record<string, string>;
  }
): Promise<CreateTransferResult> {
  const key = requireStripeKey(env);

  const formParams: Record<string, string> = {
    amount: params.amount_minor,
    currency: params.currency.toLowerCase(),
    destination: params.destination_account_id,
    'metadata[payout_id]': params.payout_id,
    'metadata[idempotency_key]': params.idempotency_key,
  };

  if (params.metadata) {
    for (const [k, v] of Object.entries(params.metadata)) {
      formParams[`metadata[${k}]`] = v;
    }
  }

  const { status, data } = await stripeRequest(
    key, 'POST', '/transfers', formParams, params.idempotency_key
  );

  if (status < 200 || status >= 300) {
    const errMsg = typeof data.error === 'object' && data.error !== null
      ? (data.error as Record<string, unknown>).message ?? 'Unknown Stripe error'
      : JSON.stringify(data);
    throw new ClawSettleError(
      `Stripe Connect Transfer failed: ${errMsg}`,
      'STRIPE_TRANSFER_FAILED',
      502,
      { stripe_status: status, stripe_error: data.error },
    );
  }

  return {
    transfer_id: String(data.id),
    amount_minor: params.amount_minor,
    currency: params.currency,
    destination: params.destination_account_id,
    status: String(data.object === 'transfer' ? 'created' : data.status ?? 'unknown'),
  };
}

// ---------------------------------------------------------------------------
// Confirm PaymentIntent (for test-mode pm_card_visa)
// ---------------------------------------------------------------------------

export async function confirmPaymentIntent(
  env: Env,
  paymentIntentId: string,
  paymentMethodId: string
): Promise<{ status: string }> {
  const key = requireStripeKey(env);

  const { status, data } = await stripeRequest(
    key, 'POST', `/payment_intents/${paymentIntentId}/confirm`,
    { payment_method: paymentMethodId },
  );

  if (status < 200 || status >= 300) {
    throw new ClawSettleError(
      `Stripe PaymentIntent confirm failed`,
      'STRIPE_CONFIRM_FAILED',
      502,
      { stripe_status: status },
    );
  }

  return { status: String(data.status) };
}
