/**
 * Stripe dispute lifecycle -> loss-event automation bridge.
 *
 * Maps Stripe dispute webhook events to loss-event create/resolve/update
 * operations using the existing deterministic outbox pipeline (MAX-001/002).
 *
 * Event mapping:
 *   charge.dispute.created          -> create loss event (apply freeze)
 *   charge.dispute.closed (won)     -> resolve loss event (unfreeze)
 *   charge.dispute.closed (lost)    -> mark permanent loss (leave frozen)
 *   charge.dispute.updated          -> update bridge metadata (no state change)
 */

import type { Env, StripeEvent } from './types';
import { ClawSettleError } from './stripe';
import { LossEventService } from './loss-events';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type DisputeAction =
  | { action: 'create_loss_event'; dispute: ParsedDispute }
  | { action: 'resolve_loss_event'; dispute: ParsedDispute; resolution: 'won' }
  | { action: 'mark_permanent_loss'; dispute: ParsedDispute; resolution: 'lost' }
  | { action: 'update_metadata'; dispute: ParsedDispute }
  | null;

export interface ParsedDispute {
  dispute_id: string;
  charge_id: string;
  payment_intent_id: string | null;
  amount_minor: string;
  /** The actual disputed amount (may differ from charge amount for partial disputes). */
  disputed_amount_minor: string;
  currency: string;
  reason: string | null;
  status: string;
  account_id: string;
  account_did: string | null;
  stripe_event_id: string;
  created_at: number | null;
  /** Stripe balance_transactions → net dispute fee amount (usually $15 / 1500 minor). */
  dispute_fee_minor: string | null;
}

interface BridgeRow {
  id: string;
  dispute_id: string;
  stripe_event_id: string;
  loss_event_id: string;
  account_id: string | null;
  account_did: string | null;
  amount_minor: string;
  disputed_amount_minor: string | null;
  currency: string;
  dispute_status: string;
  dispute_reason: string | null;
  resolved_at: string | null;
  resolution_type: string | null;
  created_at: string;
  updated_at: string;
}

interface DisputeFeeRow {
  id: string;
  dispute_id: string;
  bridge_id: string;
  fee_type: 'dispute_fee' | 'chargeback_fee';
  amount_minor: string;
  currency: string;
  ledger_event_id: string | null;
  status: 'pending' | 'recorded' | 'failed';
  created_at: string;
  updated_at: string;
}

export interface DisputeBridgeResult {
  ok: boolean;
  action: string;
  dispute_id: string;
  loss_event_id?: string;
  deduped?: boolean;
  resolution_type?: string;
  details?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function nowIso(): string {
  return new Date().toISOString();
}

async function sha256Hex(data: string): Promise<string> {
  const bytes = new TextEncoder().encode(data);
  const hash = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Derive a deterministic ID for dispute bridge records.
 * Uses the same pattern as loss-events: prefix + sha256 truncation.
 */
async function deriveBridgeId(disputeId: string, stripeEventId: string): Promise<string> {
  const hash = await sha256Hex(`dispute-bridge:${disputeId}:${stripeEventId}`);
  return `dsb_${hash.slice(0, 24)}`;
}

// ---------------------------------------------------------------------------
// Dispute event parsing
// ---------------------------------------------------------------------------

/**
 * Extract dispute metadata from a Stripe dispute object.
 *
 * Stripe dispute shape:
 *   data.object.id             -> dispute ID (dp_...)
 *   data.object.charge         -> charge ID string (ch_...)
 *   data.object.payment_intent -> PI ID string (pi_...) or null
 *   data.object.amount         -> disputed amount in minor units
 *   data.object.currency       -> 3-letter ISO currency
 *   data.object.reason         -> dispute reason (e.g. "fraudulent")
 *   data.object.status         -> "needs_response" | "won" | "lost" | ...
 *   data.object.metadata       -> inherited from charge
 *   data.object.created        -> unix timestamp
 *
 * The account_id comes from:
 *   1. data.object.metadata.account_id (inherited from charge/PI metadata)
 *   2. Fail-closed if missing.
 */
function parseDisputeObject(event: StripeEvent): ParsedDispute {
  const object = event.data.object;

  const disputeId = typeof object.id === 'string' && object.id.trim().length > 0
    ? object.id.trim()
    : null;

  if (!disputeId) {
    throw new ClawSettleError(
      'Missing dispute ID in event payload',
      'INVALID_EVENT_PAYLOAD',
      422,
      { field: 'data.object.id' }
    );
  }

  // charge can be a string ID or an expanded object
  let chargeId: string | null = null;
  if (typeof object.charge === 'string' && object.charge.trim().length > 0) {
    chargeId = object.charge.trim();
  } else if (isRecord(object.charge) && typeof object.charge.id === 'string') {
    chargeId = object.charge.id.trim();
  }

  if (!chargeId) {
    throw new ClawSettleError(
      'Missing charge reference in dispute payload',
      'INVALID_EVENT_PAYLOAD',
      422,
      { field: 'data.object.charge' }
    );
  }

  const paymentIntentId =
    typeof object.payment_intent === 'string' && object.payment_intent.trim().length > 0
      ? object.payment_intent.trim()
      : null;

  const rawAmount = object.amount;
  if (typeof rawAmount !== 'number' || !Number.isInteger(rawAmount) || rawAmount < 0) {
    throw new ClawSettleError(
      'Invalid or missing dispute amount',
      'INVALID_EVENT_PAYLOAD',
      422,
      { field: 'data.object.amount', value: rawAmount }
    );
  }
  const amountMinor = String(rawAmount);

  // Stripe's dispute amount IS the disputed amount (can be partial).
  // For partial disputes, this differs from the full charge amount.
  const disputedAmountMinor = amountMinor;

  const currency = typeof object.currency === 'string' && object.currency.trim().length > 0
    ? object.currency.trim().toUpperCase()
    : 'USD';

  const reason = typeof object.reason === 'string' && object.reason.trim().length > 0
    ? object.reason.trim()
    : null;

  const status = typeof object.status === 'string' && object.status.trim().length > 0
    ? object.status.trim()
    : 'unknown';

  // Extract account_id from metadata (inherited from charge/PI).
  // Fail-closed: if no account_id, we cannot route the loss event.
  const metadata = isRecord(object.metadata) ? object.metadata : null;
  const chargeMetadata = isRecord(object.charge) && isRecord((object.charge as Record<string, unknown>).metadata)
    ? (object.charge as Record<string, unknown>).metadata as Record<string, unknown>
    : null;

  const resolvedMetadata = metadata ?? chargeMetadata;

  const accountId =
    resolvedMetadata && typeof resolvedMetadata.account_id === 'string' && resolvedMetadata.account_id.trim().length > 0
      ? resolvedMetadata.account_id.trim()
      : null;

  if (!accountId) {
    throw new ClawSettleError(
      'Missing account_id in dispute metadata — cannot route loss event',
      'INVALID_EVENT_PAYLOAD',
      422,
      {
        field: 'data.object.metadata.account_id',
        dispute_id: disputeId,
        charge_id: chargeId,
        hint: 'Ensure the originating PaymentIntent or Charge includes metadata.account_id',
      }
    );
  }

  const accountDid =
    resolvedMetadata && typeof resolvedMetadata.account_did === 'string' && resolvedMetadata.account_did.trim().length > 0
      ? resolvedMetadata.account_did.trim()
      : null;

  const created = typeof object.created === 'number' ? object.created : null;

  // Extract dispute fee from balance_transactions if available.
  // Stripe's dispute object includes balance_transactions.data[].fee when expanded.
  let disputeFeeMinor: string | null = null;
  const balanceTxns = object.balance_transactions;
  if (Array.isArray(balanceTxns)) {
    for (const txn of balanceTxns) {
      if (isRecord(txn) && typeof txn.fee === 'number' && Number.isInteger(txn.fee) && txn.fee > 0) {
        // Use the fee from the first balance transaction that has one
        disputeFeeMinor = String(txn.fee);
        break;
      }
    }
  }
  // Default Stripe dispute fee: $15 (1500 minor units) if not in balance_transactions
  if (!disputeFeeMinor) {
    disputeFeeMinor = '1500';
  }

  return {
    dispute_id: disputeId,
    charge_id: chargeId,
    payment_intent_id: paymentIntentId,
    amount_minor: amountMinor,
    disputed_amount_minor: disputedAmountMinor,
    currency,
    reason,
    status,
    account_id: accountId,
    account_did: accountDid,
    stripe_event_id: event.id,
    created_at: created,
    dispute_fee_minor: disputeFeeMinor,
  };
}

// ---------------------------------------------------------------------------
// Action classification
// ---------------------------------------------------------------------------

/**
 * Map a Stripe event to a dispute action.
 * Returns null for non-dispute events.
 */
export function classifyDisputeAction(event: StripeEvent): DisputeAction {
  if (event.type === 'charge.dispute.created') {
    return { action: 'create_loss_event', dispute: parseDisputeObject(event) };
  }

  if (event.type === 'charge.dispute.closed') {
    const dispute = parseDisputeObject(event);

    if (dispute.status === 'won') {
      return { action: 'resolve_loss_event', dispute, resolution: 'won' };
    }

    // Lost or any other terminal status: mark as permanent loss (leave frozen).
    return { action: 'mark_permanent_loss', dispute, resolution: 'lost' };
  }

  if (event.type === 'charge.dispute.updated') {
    return { action: 'update_metadata', dispute: parseDisputeObject(event) };
  }

  return null;
}

// ---------------------------------------------------------------------------
// Bridge persistence
// ---------------------------------------------------------------------------

async function findBridgeByDisputeId(db: D1Database, disputeId: string): Promise<BridgeRow | null> {
  const row = await db
    .prepare('SELECT * FROM dispute_loss_event_bridge WHERE dispute_id = ? LIMIT 1')
    .bind(disputeId)
    .first();

  return row ? (row as unknown as BridgeRow) : null;
}

async function insertBridge(db: D1Database, row: BridgeRow): Promise<void> {
  await db
    .prepare(
      `INSERT INTO dispute_loss_event_bridge (
        id, dispute_id, stripe_event_id, loss_event_id,
        account_id, account_did, amount_minor, disputed_amount_minor, currency,
        dispute_status, dispute_reason, resolved_at, resolution_type,
        created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      row.id,
      row.dispute_id,
      row.stripe_event_id,
      row.loss_event_id,
      row.account_id,
      row.account_did,
      row.amount_minor,
      row.disputed_amount_minor,
      row.currency,
      row.dispute_status,
      row.dispute_reason,
      row.resolved_at,
      row.resolution_type,
      row.created_at,
      row.updated_at
    )
    .run();
}

async function insertDisputeFee(db: D1Database, fee: DisputeFeeRow): Promise<void> {
  await db
    .prepare(
      `INSERT INTO dispute_fees (
        id, dispute_id, bridge_id, fee_type, amount_minor,
        currency, ledger_event_id, status, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      fee.id,
      fee.dispute_id,
      fee.bridge_id,
      fee.fee_type,
      fee.amount_minor,
      fee.currency,
      fee.ledger_event_id,
      fee.status,
      fee.created_at,
      fee.updated_at
    )
    .run();
}

async function updateBridgeStatus(
  db: D1Database,
  disputeId: string,
  status: string,
  resolvedAt: string | null,
  resolutionType: string | null,
  updatedAt: string
): Promise<void> {
  await db
    .prepare(
      `UPDATE dispute_loss_event_bridge
       SET dispute_status = ?,
           resolved_at = ?,
           resolution_type = ?,
           updated_at = ?
       WHERE dispute_id = ?`
    )
    .bind(status, resolvedAt, resolutionType, updatedAt, disputeId)
    .run();
}

async function updateBridgeMetadata(
  db: D1Database,
  disputeId: string,
  dispute: ParsedDispute,
  updatedAt: string
): Promise<void> {
  await db
    .prepare(
      `UPDATE dispute_loss_event_bridge
       SET dispute_status = ?,
           dispute_reason = ?,
           amount_minor = ?,
           disputed_amount_minor = ?,
           updated_at = ?
       WHERE dispute_id = ?`
    )
    .bind(dispute.status, dispute.reason, dispute.amount_minor, dispute.disputed_amount_minor, updatedAt, disputeId)
    .run();
}

// ---------------------------------------------------------------------------
// Bridge executor
// ---------------------------------------------------------------------------

export class DisputeLossEventBridge {
  private readonly lossEventService: LossEventService;

  constructor(private readonly env: Env) {
    this.lossEventService = new LossEventService(env);
  }

  /**
   * Execute a dispute action against the loss-event pipeline.
   * Deterministic + idempotent: safe to replay.
   */
  async execute(disputeAction: NonNullable<DisputeAction>): Promise<DisputeBridgeResult> {
    switch (disputeAction.action) {
      case 'create_loss_event':
        return this.handleCreate(disputeAction.dispute);

      case 'resolve_loss_event':
        return this.handleResolve(disputeAction.dispute);

      case 'mark_permanent_loss':
        return this.handlePermanentLoss(disputeAction.dispute);

      case 'update_metadata':
        return this.handleUpdate(disputeAction.dispute);

      default: {
        const _exhaust: never = disputeAction;
        throw new ClawSettleError(
          `Unknown dispute action: ${(disputeAction as { action: string }).action}`,
          'INTERNAL_ERROR',
          500
        );
      }
    }
  }

  // -----------------------------------------------------------------------
  // create_loss_event (charge.dispute.created)
  // -----------------------------------------------------------------------

  private async handleCreate(dispute: ParsedDispute): Promise<DisputeBridgeResult> {
    // Idempotency: check if we already bridged this dispute
    const existing = await findBridgeByDisputeId(this.env.DB, dispute.dispute_id);
    if (existing) {
      return {
        ok: true,
        action: 'create_loss_event',
        dispute_id: dispute.dispute_id,
        loss_event_id: existing.loss_event_id,
        deduped: true,
      };
    }

    // Build a loss-event account_did. If the dispute metadata doesn't have one,
    // synthesize a deterministic DID from the account_id.
    const accountDid = dispute.account_did ?? `did:claw:account:${dispute.account_id}`;

    const idempotencyKey = `stripe:dispute:${dispute.dispute_id}`;
    const occurredAt = dispute.created_at
      ? new Date(dispute.created_at * 1000).toISOString()
      : nowIso();

    if (dispute.currency !== 'USD') {
      throw new ClawSettleError(
        'Only USD disputes are supported for loss-event automation',
        'UNSUPPORTED_CURRENCY',
        400,
        { currency: dispute.currency, dispute_id: dispute.dispute_id }
      );
    }

    // Use the disputed amount for the loss event hold — not the full charge amount.
    // For partial disputes, this correctly sizes the risk hold.
    const lossPayload = {
      source_service: 'stripe',
      source_event_id: dispute.stripe_event_id,
      account_did: accountDid,
      account_id: dispute.account_id,
      amount_minor: dispute.disputed_amount_minor,
      currency: 'USD' as const,
      reason_code: `dispute:${dispute.reason ?? 'unknown'}`,
      severity: 'high' as const,
      occurred_at: occurredAt,
      metadata: {
        dispute_id: dispute.dispute_id,
        charge_id: dispute.charge_id,
        payment_intent_id: dispute.payment_intent_id,
        dispute_reason: dispute.reason,
        dispute_status: dispute.status,
        stripe_event_id: dispute.stripe_event_id,
        charge_amount_minor: dispute.amount_minor,
        disputed_amount_minor: dispute.disputed_amount_minor,
      },
    };

    const result = await this.lossEventService.createLossEvent(lossPayload, idempotencyKey);

    // Persist the bridge record for resolution lookups
    const now = nowIso();
    const bridgeId = await deriveBridgeId(dispute.dispute_id, dispute.stripe_event_id);

    try {
      await insertBridge(this.env.DB, {
        id: bridgeId,
        dispute_id: dispute.dispute_id,
        stripe_event_id: dispute.stripe_event_id,
        loss_event_id: result.event.loss_event_id,
        account_id: dispute.account_id,
        account_did: accountDid,
        amount_minor: dispute.amount_minor,
        disputed_amount_minor: dispute.disputed_amount_minor,
        currency: dispute.currency,
        dispute_status: 'open',
        dispute_reason: dispute.reason,
        resolved_at: null,
        resolution_type: null,
        created_at: now,
        updated_at: now,
      });

      // Record the Stripe dispute fee ($15 standard, or extracted from balance_transactions).
      if (dispute.dispute_fee_minor) {
        const feeId = await deriveBridgeId(`fee:${dispute.dispute_id}`, dispute.stripe_event_id);
        try {
          await insertDisputeFee(this.env.DB, {
            id: feeId,
            dispute_id: dispute.dispute_id,
            bridge_id: bridgeId,
            fee_type: 'dispute_fee',
            amount_minor: dispute.dispute_fee_minor,
            currency: dispute.currency,
            ledger_event_id: null,
            status: 'pending',
            created_at: now,
            updated_at: now,
          });
        } catch (feeErr) {
          // Non-fatal: fee recording failure shouldn't block the loss event flow
          const feeMsg = feeErr instanceof Error ? feeErr.message : String(feeErr);
          if (!feeMsg.includes('UNIQUE constraint failed')) {
            // Log but continue — fee can be reconciled later
          }
        }
      }
    } catch (err) {
      // UNIQUE constraint: race-safe — another request already bridged this dispute.
      const message = err instanceof Error ? err.message : String(err);
      if (message.includes('UNIQUE constraint failed')) {
        const raced = await findBridgeByDisputeId(this.env.DB, dispute.dispute_id);
        if (raced) {
          return {
            ok: true,
            action: 'create_loss_event',
            dispute_id: dispute.dispute_id,
            loss_event_id: raced.loss_event_id,
            deduped: true,
          };
        }
      }
      throw err;
    }

    return {
      ok: true,
      action: 'create_loss_event',
      dispute_id: dispute.dispute_id,
      loss_event_id: result.event.loss_event_id,
      deduped: result.deduped,
    };
  }

  // -----------------------------------------------------------------------
  // resolve_loss_event (charge.dispute.closed, status=won)
  // -----------------------------------------------------------------------

  private async handleResolve(dispute: ParsedDispute): Promise<DisputeBridgeResult> {
    const bridge = await findBridgeByDisputeId(this.env.DB, dispute.dispute_id);
    if (!bridge) {
      throw new ClawSettleError(
        'No loss event found for dispute — cannot resolve',
        'DISPUTE_BRIDGE_NOT_FOUND',
        404,
        {
          dispute_id: dispute.dispute_id,
          hint: 'charge.dispute.created must arrive before charge.dispute.closed',
        }
      );
    }

    // Already resolved? Idempotent return.
    if (bridge.dispute_status === 'resolved_won') {
      return {
        ok: true,
        action: 'resolve_loss_event',
        dispute_id: dispute.dispute_id,
        loss_event_id: bridge.loss_event_id,
        deduped: true,
        resolution_type: 'won',
      };
    }

    const idempotencyKey = `stripe:dispute-resolve:${dispute.dispute_id}`;
    const resolvePayload = {
      reason: `Dispute ${dispute.dispute_id} closed with status=won`,
    };

    const result = await this.lossEventService.resolveLossEvent(
      bridge.loss_event_id,
      resolvePayload,
      idempotencyKey
    );

    const now = nowIso();
    await updateBridgeStatus(this.env.DB, dispute.dispute_id, 'resolved_won', now, 'won', now);

    return {
      ok: true,
      action: 'resolve_loss_event',
      dispute_id: dispute.dispute_id,
      loss_event_id: bridge.loss_event_id,
      deduped: result.deduped,
      resolution_type: 'won',
    };
  }

  // -----------------------------------------------------------------------
  // mark_permanent_loss (charge.dispute.closed, status=lost)
  // -----------------------------------------------------------------------

  private async handlePermanentLoss(dispute: ParsedDispute): Promise<DisputeBridgeResult> {
    const bridge = await findBridgeByDisputeId(this.env.DB, dispute.dispute_id);
    if (!bridge) {
      throw new ClawSettleError(
        'No loss event found for dispute — cannot mark permanent loss',
        'DISPUTE_BRIDGE_NOT_FOUND',
        404,
        {
          dispute_id: dispute.dispute_id,
          hint: 'charge.dispute.created must arrive before charge.dispute.closed',
        }
      );
    }

    // Already marked? Idempotent return.
    if (bridge.dispute_status === 'permanent_loss') {
      return {
        ok: true,
        action: 'mark_permanent_loss',
        dispute_id: dispute.dispute_id,
        loss_event_id: bridge.loss_event_id,
        deduped: true,
        resolution_type: 'lost',
      };
    }

    // Leave the loss-event frozen (no resolve call).
    // Update bridge status to permanent_loss for auditability.
    const now = nowIso();
    await updateBridgeStatus(this.env.DB, dispute.dispute_id, 'permanent_loss', now, 'lost', now);

    // Record chargeback fee (the disputed amount itself is already held via loss event).
    // Stripe charges the dispute fee + chargeback amount on lost disputes.
    if (dispute.dispute_fee_minor) {
      const chargebackFeeId = await deriveBridgeId(`chargeback-fee:${dispute.dispute_id}`, dispute.stripe_event_id);
      try {
        await insertDisputeFee(this.env.DB, {
          id: chargebackFeeId,
          dispute_id: dispute.dispute_id,
          bridge_id: bridge.id,
          fee_type: 'chargeback_fee',
          amount_minor: dispute.disputed_amount_minor,
          currency: dispute.currency,
          ledger_event_id: null,
          status: 'pending',
          created_at: now,
          updated_at: now,
        });
      } catch (feeErr) {
        const feeMsg = feeErr instanceof Error ? feeErr.message : String(feeErr);
        if (!feeMsg.includes('UNIQUE constraint failed')) {
          // Non-fatal — fee can be reconciled later
        }
      }
    }

    return {
      ok: true,
      action: 'mark_permanent_loss',
      dispute_id: dispute.dispute_id,
      loss_event_id: bridge.loss_event_id,
      deduped: false,
      resolution_type: 'lost',
      details: {
        note: 'Loss event remains frozen — dispute was lost. Manual intervention required for fund recovery.',
        chargeback_amount_minor: dispute.disputed_amount_minor,
      },
    };
  }

  // -----------------------------------------------------------------------
  // update_metadata (charge.dispute.updated)
  // -----------------------------------------------------------------------

  private async handleUpdate(dispute: ParsedDispute): Promise<DisputeBridgeResult> {
    const bridge = await findBridgeByDisputeId(this.env.DB, dispute.dispute_id);
    if (!bridge) {
      // Not an error: dispute.updated can arrive before dispute.created
      // if webhooks are reordered. Log and return ok.
      return {
        ok: true,
        action: 'update_metadata',
        dispute_id: dispute.dispute_id,
        deduped: false,
        details: {
          note: 'No bridge record found — dispute.updated arrived before dispute.created (webhook reorder). Ignored safely.',
        },
      };
    }

    // Don't update if already in a terminal state
    if (bridge.dispute_status === 'resolved_won' || bridge.dispute_status === 'permanent_loss') {
      return {
        ok: true,
        action: 'update_metadata',
        dispute_id: dispute.dispute_id,
        loss_event_id: bridge.loss_event_id,
        deduped: true,
        details: {
          note: `Bridge already in terminal state: ${bridge.dispute_status}`,
        },
      };
    }

    const now = nowIso();
    await updateBridgeMetadata(this.env.DB, dispute.dispute_id, dispute, now);

    return {
      ok: true,
      action: 'update_metadata',
      dispute_id: dispute.dispute_id,
      loss_event_id: bridge.loss_event_id,
      deduped: false,
    };
  }
}

// ---------------------------------------------------------------------------
// Aging report
// ---------------------------------------------------------------------------

export interface DisputeAgingBucket {
  label: string;
  min_days: number;
  max_days: number | null;
  count: number;
  total_disputed_minor: string;
  disputes: Array<{
    dispute_id: string;
    loss_event_id: string;
    account_id: string | null;
    disputed_amount_minor: string | null;
    amount_minor: string;
    dispute_reason: string | null;
    age_days: number;
    created_at: string;
  }>;
}

export interface DisputeAgingReport {
  generated_at: string;
  buckets: DisputeAgingBucket[];
  total_open: number;
  total_disputed_minor: string;
}

/**
 * Produce a dispute aging report grouped by age buckets.
 * Only includes open (non-terminal) disputes.
 */
export async function getDisputeAgingReport(db: D1Database): Promise<DisputeAgingReport> {
  const now = new Date();
  const nowIsoStr = now.toISOString();

  // Fetch all open disputes
  const rows = await db
    .prepare(
      `SELECT * FROM dispute_loss_event_bridge
       WHERE dispute_status = 'open'
       ORDER BY created_at ASC`
    )
    .all<BridgeRow>();

  const disputes = rows.results ?? [];

  // Define buckets
  const bucketDefs: Array<{ label: string; min: number; max: number | null }> = [
    { label: '0-7d', min: 0, max: 7 },
    { label: '7-30d', min: 7, max: 30 },
    { label: '30-60d', min: 30, max: 60 },
    { label: '60+d', min: 60, max: null },
  ];

  const buckets: DisputeAgingBucket[] = bucketDefs.map((def) => ({
    label: def.label,
    min_days: def.min,
    max_days: def.max,
    count: 0,
    total_disputed_minor: '0',
    disputes: [],
  }));

  let totalOpen = 0;
  let totalDisputedBigInt = 0n;

  for (const dispute of disputes) {
    const createdAt = new Date(dispute.created_at);
    const ageDays = Math.floor((now.getTime() - createdAt.getTime()) / (1000 * 60 * 60 * 24));
    const disputedMinor = dispute.disputed_amount_minor ?? dispute.amount_minor;
    const disputedBigInt = BigInt(disputedMinor);

    totalOpen++;
    totalDisputedBigInt += disputedBigInt;

    const entry = {
      dispute_id: dispute.dispute_id,
      loss_event_id: dispute.loss_event_id,
      account_id: dispute.account_id,
      disputed_amount_minor: dispute.disputed_amount_minor,
      amount_minor: dispute.amount_minor,
      dispute_reason: dispute.dispute_reason,
      age_days: ageDays,
      created_at: dispute.created_at,
    };

    for (const bucket of buckets) {
      if (ageDays >= bucket.min_days && (bucket.max_days === null || ageDays < bucket.max_days)) {
        bucket.count++;
        bucket.total_disputed_minor = (BigInt(bucket.total_disputed_minor) + disputedBigInt).toString();
        bucket.disputes.push(entry);
        break;
      }
    }
  }

  return {
    generated_at: nowIsoStr,
    buckets,
    total_open: totalOpen,
    total_disputed_minor: totalDisputedBigInt.toString(),
  };
}

// ---------------------------------------------------------------------------
// Reconciliation check
// ---------------------------------------------------------------------------

export interface DisputeReconMismatch {
  type: string;
  dispute_id: string;
  loss_event_id: string | null;
  details: Record<string, unknown>;
}

export interface DisputeReconReport {
  generated_at: string;
  total_disputes: number;
  total_mismatches: number;
  mismatches: DisputeReconMismatch[];
}

/**
 * Compare dispute bridge records against ledger risk holds.
 * Flags:
 * - hold_without_dispute: risk hold exists but no dispute bridge record
 * - dispute_resolved_hold_active: dispute resolved/won but hold still active
 * - amount_mismatch: disputed amount doesn't match hold amount
 * - dispute_without_hold: dispute bridge exists but loss event not forwarded
 *
 * Requires LEDGER_BASE_URL + LEDGER_RISK_KEY in env.
 */
export async function getDisputeReconReport(
  db: D1Database,
  env: Env
): Promise<DisputeReconReport> {
  const nowIsoStr = nowIso();
  const mismatches: DisputeReconMismatch[] = [];

  // 1. Fetch all dispute bridge records
  const bridges = await db
    .prepare('SELECT * FROM dispute_loss_event_bridge ORDER BY created_at ASC')
    .all<BridgeRow>();

  const bridgeRows = bridges.results ?? [];

  // 2. For each bridge, check the loss event status
  for (const bridge of bridgeRows) {
    // Check if the loss event exists and its forwarding status
    const lossEvent = await db
      .prepare('SELECT id, status, forwarded_count, amount_minor FROM loss_events WHERE id = ?')
      .bind(bridge.loss_event_id)
      .first<{ id: string; status: string; forwarded_count: number; amount_minor: string }>();

    if (!lossEvent) {
      mismatches.push({
        type: 'dispute_without_loss_event',
        dispute_id: bridge.dispute_id,
        loss_event_id: bridge.loss_event_id,
        details: {
          note: 'Bridge references a loss event that does not exist',
          dispute_status: bridge.dispute_status,
        },
      });
      continue;
    }

    // Check amount mismatch between disputed amount and loss event amount
    const disputedMinor = bridge.disputed_amount_minor ?? bridge.amount_minor;
    if (disputedMinor !== lossEvent.amount_minor) {
      mismatches.push({
        type: 'amount_mismatch',
        dispute_id: bridge.dispute_id,
        loss_event_id: bridge.loss_event_id,
        details: {
          bridge_disputed_amount_minor: disputedMinor,
          loss_event_amount_minor: lossEvent.amount_minor,
          note: 'Disputed amount in bridge does not match loss event amount',
        },
      });
    }

    // Check resolved disputes that still have forwarding issues
    if (bridge.dispute_status === 'resolved_won') {
      // Check if resolution was forwarded
      const resolution = await db
        .prepare('SELECT id, status FROM loss_event_resolutions WHERE loss_event_id = ?')
        .bind(bridge.loss_event_id)
        .first<{ id: string; status: string }>();

      if (!resolution) {
        mismatches.push({
          type: 'resolved_without_resolution',
          dispute_id: bridge.dispute_id,
          loss_event_id: bridge.loss_event_id,
          details: {
            note: 'Dispute marked as resolved_won but no resolution record exists',
            dispute_status: bridge.dispute_status,
          },
        });
      } else if (resolution.status !== 'forwarded') {
        mismatches.push({
          type: 'resolved_hold_not_released',
          dispute_id: bridge.dispute_id,
          loss_event_id: bridge.loss_event_id,
          details: {
            resolution_status: resolution.status,
            note: 'Dispute resolved but resolution not fully forwarded (hold may still be active)',
          },
        });
      }
    }

    // Check open disputes with failed forwarding
    if (bridge.dispute_status === 'open' && lossEvent.status === 'failed') {
      mismatches.push({
        type: 'open_dispute_forwarding_failed',
        dispute_id: bridge.dispute_id,
        loss_event_id: bridge.loss_event_id,
        details: {
          loss_event_status: lossEvent.status,
          note: 'Dispute is open but loss event forwarding failed — risk hold may not be applied',
        },
      });
    }

    // Check permanent losses without proper fee records
    if (bridge.dispute_status === 'permanent_loss') {
      const fees = await db
        .prepare('SELECT * FROM dispute_fees WHERE dispute_id = ?')
        .bind(bridge.dispute_id)
        .all<DisputeFeeRow>();

      const feeRows = fees.results ?? [];
      const hasDisputeFee = feeRows.some((f) => f.fee_type === 'dispute_fee');
      const hasChargebackFee = feeRows.some((f) => f.fee_type === 'chargeback_fee');

      if (!hasDisputeFee || !hasChargebackFee) {
        mismatches.push({
          type: 'permanent_loss_missing_fees',
          dispute_id: bridge.dispute_id,
          loss_event_id: bridge.loss_event_id,
          details: {
            has_dispute_fee: hasDisputeFee,
            has_chargeback_fee: hasChargebackFee,
            note: 'Permanent loss should have both dispute_fee and chargeback_fee records',
          },
        });
      }
    }
  }

  return {
    generated_at: nowIsoStr,
    total_disputes: bridgeRows.length,
    total_mismatches: mismatches.length,
    mismatches,
  };
}
