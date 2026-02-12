import { describe, expect, it } from 'vitest';
import { __internals } from '../src/index';

describe('clawcuts core math', () => {
  it('rounds fee amounts up using ceil', () => {
    const result = __internals.computeFee(101n, 500, 0n);
    expect(result.feeMinor).toBe(6n);
    expect(result.floorApplied).toBe(false);
  });

  it('applies minimum floor deterministically', () => {
    const result = __internals.computeFee(100n, 100, 2n);
    expect(result.feeMinor).toBe(2n);
    expect(result.floorApplied).toBe(true);
  });

  it('analyzes snapshot using stored splits without recomputation', () => {
    const snapshot = {
      policy_id: 'bounties_v1',
      policy_version: '1',
      policy_hash_b64u: 'hash',
      buyer_total_minor: '1050',
      worker_net_minor: '1000',
      fees: [
        {
          kind: 'platform',
          payer: 'buyer' as const,
          amount_minor: '50',
          rate_bps: 500,
          min_fee_minor: '0',
          floor_applied: false,
          splits: [
            {
              kind: 'platform' as const,
              account: 'clearing:clawcuts',
              bucket: 'F' as const,
              amount_minor: '30',
            },
            {
              kind: 'referral' as const,
              account: 'did:key:zRef',
              bucket: 'A' as const,
              amount_minor: '20',
              referrer_did: 'did:key:zRef',
            },
          ],
        },
      ],
    };

    const analysis = __internals.analyzeSnapshotForApply(snapshot, 'clearing:clawcuts');

    expect(analysis.principal_minor).toBe(1000n);
    expect(analysis.total_fee_minor).toBe(50n);
    expect(analysis.referral_fee_minor).toBe(20n);
    expect(analysis.platform_retained_minor).toBe(30n);
    expect(analysis.transfers).toHaveLength(2);
  });

  it('stable stringifier is deterministic for key ordering', () => {
    const a = __internals.stableStringify({ b: 1, a: { z: true, y: false } });
    const b = __internals.stableStringify({ a: { y: false, z: true }, b: 1 });
    expect(a).toBe(b);
  });
});
