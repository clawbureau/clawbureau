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
  currency: string;
  reason: string | null;
  status: string;
  account_id: string;
  account_did: string | null;
  stripe_event_id: string;
  created_at: number | null;
}

interface BridgeRow {
  id: string;
  dispute_id: string;
  stripe_event_id: string;
  loss_event_id: string;
  account_id: string | null;
  account_did: string | null;
  amount_minor: string;
  currency: string;
  dispute_status: string;
  dispute_reason: string | null;
  resolved_at: string | null;
  resolution_type: string | null;
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

  return {
    dispute_id: disputeId,
    charge_id: chargeId,
    payment_intent_id: paymentIntentId,
    amount_minor: amountMinor,
    currency,
    reason,
    status,
    account_id: accountId,
    account_did: accountDid,
    stripe_event_id: event.id,
    created_at: created,
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
        account_id, account_did, amount_minor, currency,
        dispute_status, dispute_reason, resolved_at, resolution_type,
        created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      row.id,
      row.dispute_id,
      row.stripe_event_id,
      row.loss_event_id,
      row.account_id,
      row.account_did,
      row.amount_minor,
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
           updated_at = ?
       WHERE dispute_id = ?`
    )
    .bind(dispute.status, dispute.reason, dispute.amount_minor, updatedAt, disputeId)
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

    const lossPayload = {
      source_service: 'stripe',
      source_event_id: dispute.stripe_event_id,
      account_did: accountDid,
      account_id: dispute.account_id,
      amount_minor: dispute.amount_minor,
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
        currency: dispute.currency,
        dispute_status: 'open',
        dispute_reason: dispute.reason,
        resolved_at: null,
        resolution_type: null,
        created_at: now,
        updated_at: now,
      });
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

    return {
      ok: true,
      action: 'mark_permanent_loss',
      dispute_id: dispute.dispute_id,
      loss_event_id: bridge.loss_event_id,
      deduped: false,
      resolution_type: 'lost',
      details: {
        note: 'Loss event remains frozen — dispute was lost. Manual intervention required for fund recovery.',
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
