import { esc, layout, type PageMeta } from '../layout.js';
import type { DuelLeagueView, DuelLeagueEntryView } from '../api.js';

function pct(value: number): string {
  return `${(value * 100).toFixed(1)}%`;
}

function num(value: number): string {
  return value.toFixed(2);
}

function rankBadge(index: number): string {
  if (index === 0) return '<span style="color:#fbbf24;font-size:1.2em" title="1st">&#x1F947;</span>';
  if (index === 1) return '<span style="color:#94a3b8;font-size:1.2em" title="2nd">&#x1F948;</span>';
  if (index === 2) return '<span style="color:#d97706;font-size:1.2em" title="3rd">&#x1F949;</span>';
  return `<span class="dim">#${index + 1}</span>`;
}

function winRateColor(rate: number): string {
  if (rate >= 0.6) return '#4ade80';
  if (rate >= 0.4) return '#fbbf24';
  return '#f87171';
}

function renderLeaderCard(leader: DuelLeagueView['leader']): string {
  if (!leader) return '<p class="dim">No leader determined yet.</p>';
  return `
    <div class="card" style="padding:1rem;border-left:3px solid #fbbf24">
      <h3 style="margin:0 0 0.5rem">
        <span style="font-size:1.3em">&#x1F3C6;</span>
        Current Leader: <code>${esc(leader.contender_id)}</code>
      </h3>
      <p style="margin:0;font-size:0.88rem">
        ${leader.label ? `<span class="dim">${esc(leader.label)}</span> &mdash; ` : ''}
        <strong>${leader.wins}</strong> wins
        &bull; <strong style="color:${winRateColor(leader.win_rate)}">${pct(leader.win_rate)}</strong> win rate
        &bull; avg score <strong>${num(leader.avg_score)}</strong>
      </p>
    </div>`;
}

function renderStandings(entries: DuelLeagueEntryView[]): string {
  if (entries.length === 0) {
    return '<p class="dim">No contenders in the league yet. Run duel batches to populate standings.</p>';
  }

  const rows = entries.map((e, i) => {
    const record = `${e.wins}W ${e.losses}L ${e.draws}D`;
    return `
      <tr>
        <td>${rankBadge(i)}</td>
        <td><code>${esc(e.contender_id)}</code>${e.label ? `<br><span class="dim" style="font-size:0.78rem">${esc(e.label)}</span>` : ''}</td>
        <td style="font-family:monospace">${esc(record)}</td>
        <td style="color:${winRateColor(e.win_rate)};font-weight:600">${pct(e.win_rate)}</td>
        <td>${e.duels}</td>
        <td>${num(e.avg_score)}</td>
        <td>${e.model ? esc(e.model) : '<span class="dim">—</span>'}</td>
        <td>${e.harness ? esc(e.harness) : '<span class="dim">—</span>'}</td>
        <td>${e.total_cost_usd > 0 ? `$${num(e.total_cost_usd)}` : '<span class="dim">—</span>'}</td>
      </tr>`;
  }).join('');

  return `
    <table class="runs-table">
      <thead><tr>
        <th>Rank</th>
        <th>Contender</th>
        <th>Record</th>
        <th>Win Rate</th>
        <th>Duels</th>
        <th>Avg Score</th>
        <th>Model</th>
        <th>Harness</th>
        <th>Cost</th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

export function arenaLeaguePage(league: DuelLeagueView): string {
  const content = `
    <div style="margin-bottom:1.5rem">
      <h2 style="margin:0 0 0.3rem">Arena Duel League</h2>
      <p class="dim" style="margin:0">
        ${league.entries.length} contenders &mdash;
        computed ${esc(league.computed_at.replace('T', ' ').slice(0, 19))} UTC
      </p>
    </div>

    <section style="margin-bottom:1.5rem">
      ${renderLeaderCard(league.leader)}
    </section>

    <section style="margin-bottom:1.5rem">
      <h3>Standings</h3>
      ${renderStandings(league.entries)}
    </section>

    ${league.reason_codes.length > 0 ? `
    <section style="margin-bottom:1rem">
      <h4>Reason Codes</h4>
      <p class="dim">${league.reason_codes.map((c) => `<code>${esc(c)}</code>`).join(', ')}</p>
    </section>` : ''}

    <div style="margin-top:1rem">
      <a href="/arena" style="color:#60a5fa">&larr; Back to Arena</a>
      &nbsp;|&nbsp;
      <a href="/arena/roi" style="color:#60a5fa">ROI Dashboard</a>
      &nbsp;|&nbsp;
      <a href="/arena/mission" style="color:#60a5fa">Mission Dashboard</a>
    </div>
  `;

  const meta: PageMeta = {
    title: 'Arena Duel League',
    description: `${league.entries.length} contenders competing in the arena duel league`,
    path: '/arena/league',
  };

  return layout(meta, content);
}

export function arenaLeagueUnavailablePage(): string {
  const content = `
    <h2>Arena Duel League</h2>
    <p class="dim">League data is currently unavailable. The upstream bounties service may be unreachable.</p>
    <a href="/arena" style="color:#60a5fa">&larr; Back to Arena</a>
  `;
  const meta: PageMeta = { title: 'Arena Duel League', description: 'League unavailable', path: '/arena/league' };
  return layout(meta, content);
}
