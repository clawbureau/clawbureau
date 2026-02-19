import { describe, expect, it } from 'vitest';
import { getReasonCodeExplanation } from '../src/reason-codes.js';

describe('getReasonCodeExplanation', () => {
  it('returns normalized explanation for known reason codes', () => {
    const result = getReasonCodeExplanation(' pow_required ');

    expect(result).not.toBeNull();
    expect(result?.reason_code).toBe('POW_REQUIRED');
    expect(result?.title.length).toBeGreaterThan(0);
    expect(result?.remediation_steps.length).toBeGreaterThan(0);
  });

  it('returns null for unknown reason codes', () => {
    expect(getReasonCodeExplanation('UNKNOWN_REASON')).toBeNull();
    expect(getReasonCodeExplanation('')).toBeNull();
    expect(getReasonCodeExplanation(null)).toBeNull();
  });
});
