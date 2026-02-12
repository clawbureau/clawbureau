import { describe, expect, it } from 'vitest';

import {
  evaluateLedgerAuth,
  isSettlementVerificationReadRequest,
  parseAuthCandidates,
} from '../src/index';

describe('ledger settlement verification auth contract', () => {
  it('detects settlement verification read paths', () => {
    expect(isSettlementVerificationReadRequest('GET', '/v1/payments/settlements')).toBe(true);
    expect(
      isSettlementVerificationReadRequest(
        'GET',
        '/v1/payments/settlements/stripe/pay_123'
      )
    ).toBe(true);
    expect(isSettlementVerificationReadRequest('GET', '/accounts/id/acc_123')).toBe(true);

    expect(isSettlementVerificationReadRequest('POST', '/v1/payments/settlements')).toBe(false);
    expect(isSettlementVerificationReadRequest('GET', '/accounts')).toBe(false);
    expect(
      isSettlementVerificationReadRequest('GET', '/v1/payments/settlements/stripe')
    ).toBe(false);
  });

  it('extracts auth candidates from bearer and x-admin-key headers', () => {
    const request = new Request('https://clawledger.com/v1/payments/settlements', {
      headers: {
        Authorization: 'Bearer token_a',
        'x-admin-key': 'token_b',
      },
    });

    expect(parseAuthCandidates(request)).toEqual(['token_a', 'token_b']);
  });

  it('allows settlement read auth via dedicated verify token', () => {
    const request = new Request(
      'https://clawledger.com/v1/payments/settlements/stripe/pay_123',
      {
        headers: {
          Authorization: 'Bearer verify_token',
        },
      }
    );

    const decision = evaluateLedgerAuth({
      request,
      env: {
        DB: {} as D1Database,
        LEDGER_SETTLEMENT_VERIFY_TOKEN: 'verify_token',
      },
      method: 'GET',
      path: '/v1/payments/settlements/stripe/pay_123',
    });

    expect(decision).toEqual({ ok: true });
  });

  it('rejects verify token on mutating endpoints', () => {
    const request = new Request(
      'https://clawledger.com/v1/payments/settlements/ingest',
      {
        method: 'POST',
        headers: {
          Authorization: 'Bearer verify_token',
        },
      }
    );

    const decision = evaluateLedgerAuth({
      request,
      env: {
        DB: {} as D1Database,
        LEDGER_SETTLEMENT_VERIFY_TOKEN: 'verify_token',
      },
      method: 'POST',
      path: '/v1/payments/settlements/ingest',
    });

    expect(decision).toMatchObject({
      ok: false,
      status: 503,
      code: 'LEDGER_ADMIN_KEY_MISSING',
    });
  });

  it('allows admin key everywhere when present', () => {
    const request = new Request('https://clawledger.com/v1/payments/settlements/ingest', {
      method: 'POST',
      headers: {
        'x-admin-key': 'admin_token',
      },
    });

    const decision = evaluateLedgerAuth({
      request,
      env: {
        DB: {} as D1Database,
        LEDGER_ADMIN_KEY: 'admin_token',
        LEDGER_SETTLEMENT_VERIFY_TOKEN: 'verify_token',
      },
      method: 'POST',
      path: '/v1/payments/settlements/ingest',
    });

    expect(decision).toEqual({ ok: true });
  });

  it('accepts overlap admin keys from LEDGER_ADMIN_KEYS_JSON', () => {
    const request = new Request('https://clawledger.com/v1/payments/settlements/ingest', {
      method: 'POST',
      headers: {
        Authorization: 'Bearer overlap_admin_token',
      },
    });

    const decision = evaluateLedgerAuth({
      request,
      env: {
        DB: {} as D1Database,
        LEDGER_ADMIN_KEY: 'primary_admin_token',
        LEDGER_ADMIN_KEYS_JSON: JSON.stringify(['overlap_admin_token']),
      },
      method: 'POST',
      path: '/v1/payments/settlements/ingest',
    });

    expect(decision).toEqual({ ok: true });
  });

  it('fails closed on invalid LEDGER_ADMIN_KEYS_JSON', () => {
    const request = new Request('https://clawledger.com/v1/payments/settlements', {
      headers: {
        Authorization: 'Bearer admin_token',
      },
    });

    const decision = evaluateLedgerAuth({
      request,
      env: {
        DB: {} as D1Database,
        LEDGER_ADMIN_KEYS_JSON: '{invalid json',
      },
      method: 'GET',
      path: '/v1/payments/settlements',
    });

    expect(decision).toMatchObject({
      ok: false,
      status: 503,
      code: 'LEDGER_ADMIN_KEY_CONFIG_INVALID',
    });
  });

  it('fails closed with unauthorized when keys are configured but mismatch', () => {
    const request = new Request('https://clawledger.com/v1/payments/settlements', {
      headers: {
        Authorization: 'Bearer wrong',
      },
    });

    const decision = evaluateLedgerAuth({
      request,
      env: {
        DB: {} as D1Database,
        LEDGER_ADMIN_KEY: 'admin_token',
        LEDGER_SETTLEMENT_VERIFY_TOKEN: 'verify_token',
      },
      method: 'GET',
      path: '/v1/payments/settlements',
    });

    expect(decision).toMatchObject({
      ok: false,
      status: 401,
      code: 'UNAUTHORIZED',
    });
  });
});
