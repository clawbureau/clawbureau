import { describe, expect, it } from 'vitest';

import { buildX402ReceiptMetadata } from '../src/x402';

describe('x402 receipt metadata binding', () => {
  it('emits deterministic x402 metadata including payment auth hash', async () => {
    const out = await buildX402ReceiptMetadata({
      payload: {
        paymentSignature: 'sig_x402_test',
        paymentPayload: 'eyJzaWduYXR1cmUiOiJzaWdfMDAxIn0=',
        amountMinor: 100,
        currency: 'USDC',
        network: 'base-sepolia',
      },
      verified: true,
      settlementRef: '0xsettlement001',
      settledAmountMinor: 99,
    });

    expect(out.x402_payment_ref).toBe('0xsettlement001');
    expect(out.x402_amount_minor).toBe(99);
    expect(out.x402_currency).toBe('USDC');
    expect(out.x402_network).toBe('base-sepolia');
    expect(out.x402_payment_auth_hash_b64u).toMatch(/^[A-Za-z0-9_-]{8,}$/);
  });

  it('changes payment auth hash when payment payload changes', async () => {
    const a = await buildX402ReceiptMetadata({
      payload: {
        paymentSignature: 'sig_x402_a',
        paymentPayload: 'eyJwYXltZW50IjoiYSJ9',
        amountMinor: 1,
        currency: 'USDC',
        network: 'base-sepolia',
      },
      verified: true,
    });

    const b = await buildX402ReceiptMetadata({
      payload: {
        paymentSignature: 'sig_x402_b',
        paymentPayload: 'eyJwYXltZW50IjoiYiJ9',
        amountMinor: 1,
        currency: 'USDC',
        network: 'base-sepolia',
      },
      verified: true,
    });

    expect(a.x402_payment_auth_hash_b64u).not.toBe(b.x402_payment_auth_hash_b64u);
  });
});
