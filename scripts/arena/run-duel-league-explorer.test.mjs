import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

describe('AGP-US-087 duel league explorer page', () => {
  it('explorer arena-league page exists', () => {
    const content = readFileSync(
      resolve(import.meta.dirname, '../../services/clawsig-explorer/src/pages/arena-league.ts'),
      'utf8',
    );
    assert.ok(content.includes('arenaLeaguePage'), 'missing arenaLeaguePage export');
    assert.ok(content.includes('arenaLeagueUnavailablePage'), 'missing unavailable page');
    assert.ok(content.includes('win_rate'), 'missing win_rate rendering');
    assert.ok(content.includes('rankBadge'), 'missing rank badges');
    assert.ok(content.includes('Standings'), 'missing standings section');
  });

  it('explorer index routes /arena/league', () => {
    const content = readFileSync(
      resolve(import.meta.dirname, '../../services/clawsig-explorer/src/index.ts'),
      'utf8',
    );
    assert.ok(content.includes("'/arena/league'"), 'missing /arena/league route');
    assert.ok(content.includes('fetchDuelLeague'), 'missing fetchDuelLeague call');
    assert.ok(content.includes('arenaLeaguePage'), 'missing arenaLeaguePage call');
  });

  it('api.ts has DuelLeagueView types', () => {
    const content = readFileSync(
      resolve(import.meta.dirname, '../../services/clawsig-explorer/src/api.ts'),
      'utf8',
    );
    assert.ok(content.includes('interface DuelLeagueEntryView'), 'missing entry interface');
    assert.ok(content.includes('interface DuelLeagueView'), 'missing league interface');
    assert.ok(content.includes('fetchDuelLeague'), 'missing fetch function');
    assert.ok(content.includes('/v1/arena/duel-league'), 'missing endpoint path');
  });

  it('page renders standings table with expected columns', () => {
    const content = readFileSync(
      resolve(import.meta.dirname, '../../services/clawsig-explorer/src/pages/arena-league.ts'),
      'utf8',
    );
    const expectedColumns = ['Rank', 'Contender', 'Record', 'Win Rate', 'Duels', 'Avg Score', 'Model', 'Harness', 'Cost'];
    for (const col of expectedColumns) {
      assert.ok(content.includes(col), `missing column: ${col}`);
    }
  });

  it('leader card renders with trophy emoji', () => {
    const content = readFileSync(
      resolve(import.meta.dirname, '../../services/clawsig-explorer/src/pages/arena-league.ts'),
      'utf8',
    );
    assert.ok(content.includes('Current Leader'), 'missing leader heading');
    assert.ok(content.includes('&#x1F3C6;'), 'missing trophy emoji');
  });
});
