export interface Env {
  DB: D1Database;
  SETTLE_VERSION?: string;

  /** Required for webhook signature verification (fail-closed). */
  STRIPE_WEBHOOK_SIGNING_SECRET?: string;

  /** Required for forwarding verified settlements to clawledger. */
  LEDGER_BASE_URL?: string;

  /** Required for calling clawledger admin ingest endpoint. */
  LEDGER_ADMIN_KEY?: string;
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

export interface StripeWebhookResponse {
  ok: true;
  deduped: boolean;
  event_id: string;
  event_type: string;
  idempotency_key: string;
  forwarded_to_ledger: boolean;
  ledger_status?: number;
  settlement_id?: string;
}
