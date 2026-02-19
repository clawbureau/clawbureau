import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { buildDecisionPastePayload, mapManagerDecisionToRecommendation } from './lib/decision-paste.mjs';

test('manager decision mapping yields expected recommendations', () => {
  assert.equal(mapManagerDecisionToRecommendation('promote'), 'APPROVE');
  assert.equal(mapManagerDecisionToRecommendation('iterate'), 'REQUEST_CHANGES');
  assert.equal(mapManagerDecisionToRecommendation('reject'), 'REJECT');
  assert.equal(mapManagerDecisionToRecommendation('unknown'), 'REJECT');
});

test('decision paste payload includes one-click links and recommendation', () => {
  const payload = buildDecisionPastePayload({
    arenaReport: { arena_id: 'arena_123' },
    contender: {
      contender_id: 'contender_codex_pi',
      label: 'Codex + Pi',
      manager_review_path: path.resolve('artifacts/arena/arena_bty_arena_001/contenders/contender_codex_pi/manager-review.json'),
    },
    managerReview: {
      decision: 'promote',
      confidence: 0.91,
      reason_codes: ['ARENA_READY_TO_PROMOTE'],
      recommended_next_action: 'Promote as default contender.',
    },
    reviewPaste: 'summary body',
    arenaBaseUrl: 'https://staging.clawsig-explorer.com',
    artifactsBaseUrl: 'https://cdn.example.com',
  });

  assert.equal(payload.recommendation, 'APPROVE');
  assert.equal(payload.links.length >= 3, true);
  assert.equal(payload.bodyMarkdown.includes('One-click links'), true);
  assert.equal(payload.bodyMarkdown.includes('Recommendation: **APPROVE**'), true);
});
