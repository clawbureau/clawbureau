import { describe, expect, it } from 'vitest';
import { arenaComparePage, arenaIndexPage, arenaMissionPage, sampleArenaMissionSummary, sampleArenaReport } from '../src/pages/arena.js';

describe('arena pages', () => {
  it('renders contender compare table, check matrix, and copy actions', () => {
    const report = sampleArenaReport('arena_bty_arena_001');
    expect(report).not.toBeNull();

    const html = arenaComparePage(report!);

    expect(html).toContain('Arena Compare: arena_bty_arena_001');
    expect(html).toContain('Contenders table');
    expect(html).toContain('Contract check matrix');
    expect(html).toContain('Copy Review Paste');
    expect(html).toContain('Copy Manager JSON');
    expect(html).toContain('review-paste-contender_codex_pi');
    expect(html).toContain('manager-review-contender_codex_pi');
    expect(html).toContain('contender_codex_pi');
    expect(html).toContain('ac_contract_binding');
    expect(html).toContain('Winner rationale + tradeoffs');
    expect(html).toContain('Delegation insights');
    expect(html).toContain('Default route');
    expect(html).toContain('Decision review thread');
    expect(html).toContain('APPROVE');
    expect(html).toContain('Proof card');
    expect(html).toContain('Outcome calibration');
    expect(html).toContain('Arena ROI dashboard');
    expect(html).toContain('Routing autopilot');
    expect(html).toContain('winner stability');
    expect(html).toContain('Routing policy optimizer');
    expect(html).toContain('Contract Copilot');
    expect(html).toContain('Contract language optimizer');
    expect(html).toContain('Global contract rewrites');
    expect(html).toContain('Outcome feedback feed');
    expect(html).toContain('Reviewer decision');
    expect(html).toContain('Top decision taxonomy tags');
  });

  it('renders mission control dashboard with KPI gate posture', () => {
    const html = arenaMissionPage(sampleArenaMissionSummary());

    expect(html).toContain('Arena Mission Control');
    expect(html).toContain('KPI Gate');
    expect(html).toContain('claim success');
    expect(html).toContain('proof valid rate');
    expect(html).toContain('Throughput + backlog');
    expect(html).toContain('Gate thresholds');
    expect(html).toContain('ARENA_MISSION_KPI_PASS');
  });

  it('renders arena index rows and fallback empty state', () => {
    const withRows = arenaIndexPage([
      {
        arena_id: 'arena_bty_arena_001',
        bounty_id: 'bty_arena_001',
        contract_id: 'contract_arena_001',
        generated_at: '2026-02-19T15:10:00.000Z',
        winner_contender_id: 'contender_codex_pi',
        reason_code: 'ARENA_WINNER_SELECTED',
      },
    ]);

    expect(withRows).toContain('Bounty Arena Index');
    expect(withRows).toContain('/arena/arena_bty_arena_001');
    expect(withRows).toContain('ARENA_WINNER_SELECTED');

    const empty = arenaIndexPage([]);
    expect(empty).toContain('No arena comparisons indexed yet');
    expect(empty).toContain('run-bounty-arena.mjs');
  });
});
