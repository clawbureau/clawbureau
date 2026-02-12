import { describe, expect, it } from 'vitest';

import { parseMarketplaceCstResponse } from '../src/marketplace-cst';

describe('parseMarketplaceCstResponse', () => {
  it('accepts cwc_auth.cst', () => {
    const parsed = parseMarketplaceCstResponse({
      cwc_auth: {
        cst: ' jwt_cwc ',
        token_scope_hash_b64u: 'x',
        policy_hash_b64u: ' pol ',
        mission_id: ' bty_123 ',
      },
    });

    expect(parsed.kind).toBe('cwc');
    expect(parsed.cst).toBe('jwt_cwc');
    expect(parsed.policy_hash_b64u).toBe('pol');
    expect(parsed.mission_id).toBe('bty_123');
  });

  it('accepts job_auth.cst', () => {
    const parsed = parseMarketplaceCstResponse({
      job_auth: {
        cst: ' jwt_job ',
        token_scope_hash_b64u: 'x',
        mission_id: ' bty_456 ',
      },
    });

    expect(parsed.kind).toBe('job');
    expect(parsed.cst).toBe('jwt_job');
    expect(parsed.mission_id).toBe('bty_456');
  });

  it('prefers cwc_auth over job_auth when both exist', () => {
    const parsed = parseMarketplaceCstResponse({
      job_auth: { cst: 'jwt_job', token_scope_hash_b64u: 'x' },
      cwc_auth: { cst: 'jwt_cwc', token_scope_hash_b64u: 'x' },
    });

    expect(parsed.kind).toBe('cwc');
    expect(parsed.cst).toBe('jwt_cwc');
  });

  it('throws on invalid shape', () => {
    expect(() => parseMarketplaceCstResponse(null)).toThrow(/expected a JSON object/i);
    expect(() => parseMarketplaceCstResponse({})).toThrow(/missing cwc_auth\.cst or job_auth\.cst/i);
  });
});
