import test from 'node:test';
import assert from 'node:assert/strict';

import { parseMarketplaceCstResponse } from '../dist/marketplace-cst.js';

test('parseMarketplaceCstResponse: accepts cwc_auth', () => {
  const parsed = parseMarketplaceCstResponse({
    cwc_auth: {
      cst: ' jwt_cwc ',
      token_scope_hash_b64u: 'x',
      policy_hash_b64u: ' pol ',
      mission_id: ' bty_123 ',
    },
  });

  assert.equal(parsed.kind, 'cwc');
  assert.equal(parsed.cst, 'jwt_cwc');
  assert.equal(parsed.policy_hash_b64u, 'pol');
  assert.equal(parsed.mission_id, 'bty_123');
});

test('parseMarketplaceCstResponse: accepts job_auth', () => {
  const parsed = parseMarketplaceCstResponse({
    job_auth: {
      cst: ' jwt_job ',
      token_scope_hash_b64u: 'x',
      mission_id: ' bty_456 ',
    },
  });

  assert.equal(parsed.kind, 'job');
  assert.equal(parsed.cst, 'jwt_job');
  assert.equal(parsed.mission_id, 'bty_456');
});

test('parseMarketplaceCstResponse: throws on invalid shape', () => {
  assert.throws(() => parseMarketplaceCstResponse(null), /expected a JSON object/i);
  assert.throws(() => parseMarketplaceCstResponse({}), /missing cwc_auth\.cst or job_auth\.cst/i);
});
