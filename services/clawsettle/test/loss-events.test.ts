import { describe, expect, it } from 'vitest';
import { ClawSettleError } from '../src/stripe';
import {
  assertLossEventAuth,
  isLossEventReadRequest,
  LossEventService,
} from '../src/loss-events';

describe('loss-events auth', () => {
  it('allows admin key for write endpoints', () => {
    const req = new Request('https://example.com/v1/loss-events', {
      method: 'POST',
      headers: {
        authorization: 'Bearer admin-token',
      },
    });

    expect(() =>
      assertLossEventAuth(req, { DB: {} as D1Database, SETTLE_ADMIN_KEY: 'admin-token' }, 'POST', '/v1/loss-events')
    ).not.toThrow();
  });

  it('allows read token for read endpoints', () => {
    const req = new Request('https://example.com/v1/loss-events', {
      method: 'GET',
      headers: {
        authorization: 'Bearer read-token',
      },
    });

    expect(() =>
      assertLossEventAuth(
        req,
        { DB: {} as D1Database, SETTLE_LOSS_READ_TOKEN: 'read-token' },
        'GET',
        '/v1/loss-events'
      )
    ).not.toThrow();
  });

  it('rejects read token on write endpoints', () => {
    const req = new Request('https://example.com/v1/loss-events', {
      method: 'POST',
      headers: {
        authorization: 'Bearer read-token',
      },
    });

    expect(() =>
      assertLossEventAuth(
        req,
        {
          DB: {} as D1Database,
          SETTLE_ADMIN_KEY: 'admin-token',
          SETTLE_LOSS_READ_TOKEN: 'read-token',
        },
        'POST',
        '/v1/loss-events'
      )
    ).toThrowError(ClawSettleError);
  });
});

describe('loss-events helpers', () => {
  it('detects read endpoints', () => {
    expect(isLossEventReadRequest('GET', '/v1/loss-events')).toBe(true);
    expect(isLossEventReadRequest('GET', '/v1/loss-events/outbox')).toBe(true);
    expect(isLossEventReadRequest('GET', '/v1/loss-events/lse_abc')).toBe(true);
    expect(isLossEventReadRequest('POST', '/v1/loss-events')).toBe(false);
  });

  it('parses retry body', () => {
    const parsed = LossEventService.parseRetryBody({ limit: 10, loss_event_id: 'lse_1' });
    expect(parsed).toEqual({ limit: 10, loss_event_id: 'lse_1' });
  });
});
