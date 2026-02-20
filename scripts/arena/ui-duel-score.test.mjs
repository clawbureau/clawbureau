import { test } from 'node:test';
import assert from 'node:assert/strict';
import { computeUiDuelScores } from './lib/ui-duel-score.mjs';

test('ui duel scoring fails closed when hard gates fail', () => {
  const result = computeUiDuelScores({
    journey: {
      flows: { browse: true, details: true, claim: false, submit: true },
      timings_ms: { browse: 500, details: 500, claim: 1200, submit: 900 },
      friction_events: 2,
      console: { error_count: 1, warn_count: 2 },
      runtime_errors: ['boom'],
      accessibility: { critical_violations: 1 },
    },
    lighthouse: {
      categories: {
        performance_score: 0.95,
        accessibility_score: 0.98,
      },
      metrics: {
        cls: 0.03,
      },
    },
  });

  assert.equal(result.hard_gate_passed, false);
  assert.equal(result.final_score, 0);
  assert.ok(result.reason_codes.includes('ARENA_UI_DUEL_GATE_CORE_FLOWS_FAIL'));
  assert.ok(result.reason_codes.includes('ARENA_UI_DUEL_GATE_RUNTIME_ERRORS'));
  assert.ok(result.reason_codes.includes('ARENA_UI_DUEL_GATE_A11Y_CRITICAL'));
});

test('ui duel scoring returns weighted score when all hard gates pass', () => {
  const result = computeUiDuelScores({
    journey: {
      flows: { browse: true, details: true, claim: true, submit: true },
      timings_ms: { browse: 600, details: 700, claim: 1100, submit: 1300 },
      friction_events: 0,
      console: { error_count: 0, warn_count: 1 },
      runtime_errors: [],
      accessibility: { critical_violations: 0 },
    },
    lighthouse: {
      categories: {
        performance_score: 0.88,
        accessibility_score: 0.95,
      },
      metrics: {
        cls: 0.01,
      },
    },
  });

  assert.equal(result.hard_gate_passed, true);
  assert.ok(result.final_score > 0);
  assert.equal(result.reason_codes.length, 0);
});
