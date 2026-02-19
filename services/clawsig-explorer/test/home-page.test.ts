import { describe, expect, it } from 'vitest';
import { homePage, statsPage, type HomePageData } from '../src/pages/home.js';

const sampleData: HomePageData = {
  stats: {
    total_runs: 1200,
    total_agents: 55,
    runs_24h: 200,
    fail_runs_24h: 10,
    fail_rate_24h: 0.05,
    top_fail_reason_codes: [
      { reason_code: 'HASH_MISMATCH', count: 4 },
      { reason_code: 'POW_INVALID', count: 3 },
    ],
  },
  recent_runs: [
    {
      run_id: 'run_1',
      agent_did: 'did:key:z6Mkh1234567890',
      proof_tier: 'gateway',
      status: 'PASS',
      created_at: '2026-02-19T00:00:00.000Z',
    },
    {
      run_id: 'run_2',
      agent_did: 'did:key:z6Mkh1234567891',
      proof_tier: 'sandbox',
      status: 'FAIL',
      created_at: '2026-02-19T00:05:00.000Z',
    },
  ],
};

const emptyData: HomePageData = {
  stats: {
    total_runs: 0,
    total_agents: 0,
    runs_24h: 0,
    fail_runs_24h: 0,
    fail_rate_24h: 0,
    top_fail_reason_codes: [],
  },
  recent_runs: [],
};

describe('home/stats pages', () => {
  it('renders reliability ops snapshot and triage links', () => {
    const html = homePage(sampleData);

    expect(html).toContain('Reliability Ops Snapshot');
    expect(html).toContain('Top fail reason');
    expect(html).toContain('/runs?status=FAIL&reason_code=HASH_MISMATCH');
    expect(html).toContain('Recent Failures');
  });

  it('renders stats page reliability section', () => {
    const html = statsPage(sampleData);

    expect(html).toContain('Reliability Status');
    expect(html).toContain('Open failure feed');
    expect(html).toContain('Top Failure Reason Codes (24h)');
  });

  it('renders conversion-focused empty states for zero-data scenarios', () => {
    const homeHtml = homePage(emptyData);
    const statsHtml = statsPage(emptyData);

    expect(homeHtml).toContain('Ledger is live, but no public runs are indexed yet');
    expect(homeHtml).toContain('Copy quickstart command');
    expect(statsHtml).toContain('No network activity captured yet');
    expect(statsHtml).toContain('Open quickstart docs');
  });
});
