import { describe, expect, it } from 'vitest';
import { arenaComparePage, arenaIndexPage, sampleArenaReport } from '../src/pages/arena.js';

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
    expect(html).toContain('contender_codex_pi');
    expect(html).toContain('ac_contract_binding');
    expect(html).toContain('Winner rationale + tradeoffs');
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
