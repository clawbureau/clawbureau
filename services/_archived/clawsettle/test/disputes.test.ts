import { describe, it, expect } from 'vitest';
import { classifyDisputeAction } from '../src/disputes';
import type { StripeEvent } from '../src/types';

function makeDisputeEvent(overrides: Partial<StripeEvent> & { objectOverrides?: Record<string, unknown> } = {}): StripeEvent {
  const { objectOverrides, ...rest } = overrides;
  return {
    id: 'evt_dispute_test_001',
    type: 'charge.dispute.created',
    created: 1707696000,
    livemode: false,
    data: {
      object: {
        id: 'dp_test_001',
        charge: 'ch_test_001',
        payment_intent: 'pi_test_001',
        amount: 5000,
        currency: 'usd',
        reason: 'fraudulent',
        status: 'needs_response',
        created: 1707696000,
        metadata: {
          account_id: 'acc_test_001',
          account_did: 'did:key:z6MkTest',
        },
        ...objectOverrides,
      },
    },
    ...rest,
  };
}

describe('classifyDisputeAction', () => {
  it('returns create_loss_event for charge.dispute.created', () => {
    const event = makeDisputeEvent({ type: 'charge.dispute.created' });
    const result = classifyDisputeAction(event);
    expect(result).not.toBeNull();
    expect(result!.action).toBe('create_loss_event');
    expect(result!.dispute.dispute_id).toBe('dp_test_001');
    expect(result!.dispute.charge_id).toBe('ch_test_001');
    expect(result!.dispute.amount_minor).toBe('5000');
    expect(result!.dispute.account_id).toBe('acc_test_001');
    expect(result!.dispute.account_did).toBe('did:key:z6MkTest');
    expect(result!.dispute.reason).toBe('fraudulent');
  });

  it('returns resolve_loss_event for charge.dispute.closed with status=won', () => {
    const event = makeDisputeEvent({
      type: 'charge.dispute.closed',
      objectOverrides: { status: 'won' },
    });
    const result = classifyDisputeAction(event);
    expect(result).not.toBeNull();
    expect(result!.action).toBe('resolve_loss_event');
    if (result!.action === 'resolve_loss_event') {
      expect(result!.resolution).toBe('won');
    }
  });

  it('returns mark_permanent_loss for charge.dispute.closed with status=lost', () => {
    const event = makeDisputeEvent({
      type: 'charge.dispute.closed',
      objectOverrides: { status: 'lost' },
    });
    const result = classifyDisputeAction(event);
    expect(result).not.toBeNull();
    expect(result!.action).toBe('mark_permanent_loss');
    if (result!.action === 'mark_permanent_loss') {
      expect(result!.resolution).toBe('lost');
    }
  });

  it('returns update_metadata for charge.dispute.updated', () => {
    const event = makeDisputeEvent({ type: 'charge.dispute.updated' });
    const result = classifyDisputeAction(event);
    expect(result).not.toBeNull();
    expect(result!.action).toBe('update_metadata');
  });

  it('returns null for non-dispute events', () => {
    const event = makeDisputeEvent({ type: 'payment_intent.succeeded' });
    const result = classifyDisputeAction(event);
    expect(result).toBeNull();
  });

  it('handles expanded charge object (charge is an object with .id)', () => {
    const event = makeDisputeEvent({
      objectOverrides: {
        charge: {
          id: 'ch_expanded_001',
          metadata: { account_id: 'acc_from_charge' },
        },
        metadata: undefined,
      },
    });
    const result = classifyDisputeAction(event);
    expect(result).not.toBeNull();
    expect(result!.dispute.charge_id).toBe('ch_expanded_001');
    // Falls through to charge.metadata when object.metadata is missing
    expect(result!.dispute.account_id).toBe('acc_from_charge');
  });

  it('throws INVALID_EVENT_PAYLOAD when account_id is missing from all metadata sources', () => {
    const event = makeDisputeEvent({
      objectOverrides: {
        metadata: {},
        charge: 'ch_no_metadata',
      },
    });
    expect(() => classifyDisputeAction(event)).toThrowError(/account_id/);
  });

  it('throws INVALID_EVENT_PAYLOAD when dispute has no charge reference', () => {
    const event = makeDisputeEvent({
      objectOverrides: {
        charge: null,
      },
    });
    expect(() => classifyDisputeAction(event)).toThrowError(/charge/);
  });

  it('throws INVALID_EVENT_PAYLOAD when dispute amount is invalid', () => {
    const event = makeDisputeEvent({
      objectOverrides: {
        amount: -100,
      },
    });
    expect(() => classifyDisputeAction(event)).toThrowError(/amount/);
  });

  // MPY-US-015: partial dispute + fee extraction tests

  it('extracts disputed_amount_minor equal to amount for standard disputes', () => {
    const event = makeDisputeEvent({ type: 'charge.dispute.created' });
    const result = classifyDisputeAction(event);
    expect(result).not.toBeNull();
    expect(result!.dispute.disputed_amount_minor).toBe('5000');
    expect(result!.dispute.amount_minor).toBe('5000');
  });

  it('extracts dispute fee from balance_transactions when present', () => {
    const event = makeDisputeEvent({
      objectOverrides: {
        balance_transactions: [
          { fee: 1500, type: 'adjustment' },
        ],
      },
    });
    const result = classifyDisputeAction(event);
    expect(result).not.toBeNull();
    expect(result!.dispute.dispute_fee_minor).toBe('1500');
  });

  it('extracts non-standard dispute fee from balance_transactions', () => {
    const event = makeDisputeEvent({
      objectOverrides: {
        balance_transactions: [
          { fee: 2500, type: 'adjustment' },
        ],
      },
    });
    const result = classifyDisputeAction(event);
    expect(result).not.toBeNull();
    expect(result!.dispute.dispute_fee_minor).toBe('2500');
  });

  it('defaults dispute fee to $15 (1500 minor) when balance_transactions absent', () => {
    const event = makeDisputeEvent({ type: 'charge.dispute.created' });
    const result = classifyDisputeAction(event);
    expect(result).not.toBeNull();
    expect(result!.dispute.dispute_fee_minor).toBe('1500');
  });

  it('uses disputed amount for loss event (partial dispute support)', () => {
    // For a $50 charge with only $30 disputed
    const event = makeDisputeEvent({
      objectOverrides: {
        amount: 3000, // $30 disputed of a $50 charge
      },
    });
    const result = classifyDisputeAction(event);
    expect(result).not.toBeNull();
    expect(result!.dispute.amount_minor).toBe('3000');
    expect(result!.dispute.disputed_amount_minor).toBe('3000');
    // In practice, charge_amount would come from the charge object — both are same
    // from Stripe's perspective (amount is the disputed amount, not charge amount)
  });
});
