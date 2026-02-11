export interface Env {
  DB: D1Database;
  SETTLE_VERSION?: string;

  /** Deployment environment marker used by livemode guard (staging|production). */
  SETTLE_ENV?: string;

  /**
   * If true, production accepts Stripe test-mode events.
   * Defaults to false (fail-closed: production rejects test-mode events).
   */
  STRIPE_ALLOW_TESTMODE_EVENTS_IN_PROD?: string;

  /** Required for webhook signature verification (fail-closed). */
  STRIPE_WEBHOOK_SIGNING_SECRET?: string;

  /** Required for forwarding verified settlements to clawledger. */
  LEDGER_BASE_URL?: string;

  /** Required for calling clawledger admin ingest endpoint. */
  LEDGER_ADMIN_KEY?: string;

  /** Optional admin key for manual forwarding retry endpoints. */
  SETTLE_ADMIN_KEY?: string;

  /** Retry batch size for scheduled/manual outbox processing (default: 25). */
  FORWARDING_RETRY_BATCH_LIMIT?: string;

  /** Base retry delay in seconds for failed forwarding attempts (default: 15). */
  FORWARDING_RETRY_BASE_SECONDS?: string;

  /** Max retry delay in seconds for failed forwarding attempts (default: 300). */
  FORWARDING_RETRY_MAX_SECONDS?: string;
}

export interface ErrorResponse {
  error: string;
  code: string;
  details?: Record<string, unknown>;
}

export interface StripeEvent {
  id: string;
  type: string;
  created?: number;
  livemode?: boolean;
  data: {
    object: Record<string, unknown>;
  };
}

export type SettlementDirection = 'payin' | 'refund' | 'payout';
export type SettlementStatus = 'pending' | 'confirmed' | 'failed' | 'reversed';

export interface PaymentSettlementIngestPayload {
  provider: 'stripe';
  external_payment_id: string;
  direction: SettlementDirection;
  status: SettlementStatus;
  account_id: string;
  amount_minor: string;
  currency: string;
  network?: string;
  rail?: string;
  metadata?: Record<string, unknown>;
  provider_created_at?: string;
  provider_updated_at?: string;
  settled_at?: string;
}

export interface StripeWebhookRecord {
  event_id: string;
  event_type: string;
  idempotency_key: string;
  settlement_id?: string;
  response_json: string;
  processed_at: string;
}

export type StripeForwardingStatus = 'pending' | 'failed' | 'forwarded';

export interface StripeWebhookOutboxRecord {
  event_id: string;
  event_type: string;
  idempotency_key: string;
  livemode: boolean;
  settlement_payload_json: string;
  status: StripeForwardingStatus;
  attempts: number;
  next_retry_at?: string;
  last_attempted_at?: string;
  last_error_code?: string;
  last_error_message?: string;
  ledger_status?: number;
  settlement_id?: string;
  created_at: string;
  updated_at: string;
  forwarded_at?: string;
}

export interface StripeWebhookResponse {
  ok: true;
  deduped: boolean;
  event_id: string;
  event_type: string;
  idempotency_key: string;
  forwarded_to_ledger: boolean;
  ledger_status?: number;
  settlement_id?: string;
  retry_scheduled?: boolean;
  next_retry_at?: string;
}

export interface RetryForwardingResponse {
  ok: true;
  attempted: number;
  forwarded: number;
  failed: number;
}
