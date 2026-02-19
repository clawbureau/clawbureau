import { describe, expect, it } from 'vitest';
import { opsDashboardPage } from '../src/pages/ops.js';

describe('opsDashboardPage', () => {
  it('renders domain health, synthetic status, and diagnostics sections', () => {
    const html = opsDashboardPage({
      stats: {
        total_runs: 100,
        total_agents: 10,
        runs_24h: 20,
        fail_runs_24h: 2,
        fail_rate_24h: 0.1,
        top_fail_reason_codes: [
          { reason_code: 'HASH_MISMATCH', count: 2 },
        ],
        diagnostics_7d: {
          runs_7d: 120,
          fail_runs_7d: 6,
          fail_rate_7d: 0.05,
          top_fail_reason_codes_7d: [
            { reason_code: 'POW_INVALID', count: 3 },
          ],
          daily: [],
        },
      },
      domain_health: [
        {
          host: 'api.clawverify.com',
          url: 'https://api.clawverify.com/health',
          ok: true,
          status: 200,
          latency_ms: 42,
          reason_code: 'OK',
        },
      ],
      synthetic_statuses: [
        {
          workflow: 'clawsig-surface-synthetic-smoke.yml',
          ok: true,
          status: 'completed',
          conclusion: 'success',
          updated_at: '2026-02-19T00:00:00.000Z',
          html_url: 'https://github.com/clawbureau/clawbureau/actions/runs/1',
        },
      ],
    });

    expect(html).toContain('Operations Dashboard');
    expect(html).toContain('Domain Health');
    expect(html).toContain('Latest Synthetic Status');
    expect(html).toContain('Top Fail Reasons (7d)');
    expect(html).toContain('/runs?status=FAIL&reason_code=POW_INVALID');
  });
});
