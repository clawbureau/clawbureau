import { describe, expect, it } from 'vitest';
import { __internals } from '../src/worker';

describe('escrow resolution internals', () => {
  it('parses resolution decisions strictly', () => {
    expect(__internals.parseEscrowResolutionDecision('worker_award')).toBe('worker_award');
    expect(__internals.parseEscrowResolutionDecision('requester_refund')).toBe('requester_refund');
    expect(__internals.parseEscrowResolutionDecision('other')).toBeNull();
  });

  it('escrow cursor roundtrips', () => {
    const cursor = __internals.encodeEscrowCursor('2026-02-12T00:00:00.000Z', 'esc_123e4567-e89b-12d3-a456-426614174000');
    const decoded = __internals.decodeEscrowCursor(cursor);

    expect(decoded).toEqual({
      released_at: '2026-02-12T00:00:00.000Z',
      escrow_id: 'esc_123e4567-e89b-12d3-a456-426614174000',
    });
  });
});
