import { describe, expect, it } from 'vitest';
import { __internals } from '../src/index';

describe('clawinsure internals', () => {
  it('parses positive minor values', () => {
    expect(__internals.parseMinor('100', 'amount').toString()).toBe('100');
    expect(() => __internals.parseMinor('0', 'amount')).toThrowError(/greater than zero/);
    expect(__internals.parseMinor('0', 'amount', { allowZero: true }).toString()).toBe('0');
  });

  it('stable stringification is deterministic', () => {
    const first = __internals.stableStringify({ b: 1, a: { z: true, y: false } });
    const second = __internals.stableStringify({ a: { y: false, z: true }, b: 1 });
    expect(first).toBe(second);
  });

  it('computes bounded risk score', () => {
    expect(__internals.computeRiskScore({ tier: 3, dispute_rate_bps: 0 })).toBe(20);
    expect(__internals.computeRiskScore({ tier: 0, dispute_rate_bps: 9000 })).toBeGreaterThanOrEqual(80);
  });

  it('computes premium with deterministic bps math', () => {
    const out = __internals.computePremiumQuote({
      coverage_amount_minor: 10_000n,
      coverage_type: 'sla',
      risk_score: 55,
    });

    expect(out.premium_bps).toBeGreaterThan(0);
    expect(out.premium_minor).toBeGreaterThan(0n);
    expect(out.risk_multiplier_bps).toBe(8925);
  });

  it('enforces non-empty evidence refs', () => {
    expect(() =>
      __internals.parseClaimEvidence({
        proof_bundle_hash_b64u: 'abc',
        receipt_refs: [],
        artifact_refs: ['art:1'],
      })
    ).toThrowError(/receipt_refs/);

    const parsed = __internals.parseClaimEvidence({
      proof_bundle_hash_b64u: 'abc',
      receipt_refs: ['receipt:1'],
      artifact_refs: ['artifact:1'],
    });

    expect(parsed.receipt_refs).toEqual(['receipt:1']);
    expect(parsed.artifact_refs).toEqual(['artifact:1']);
  });
});
