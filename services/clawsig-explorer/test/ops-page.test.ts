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
      synthetic_history: [
        {
          workflow: 'clawsig-surface-synthetic-smoke.yml',
          run_id: 101,
          status: 'completed',
          conclusion: 'success',
          created_at: '2026-02-19T00:00:00.000Z',
          updated_at: '2026-02-19T00:01:00.000Z',
          html_url: 'https://github.com/clawbureau/clawbureau/actions/runs/101',
          head_sha: 'abcdef123456',
          artifacts_url: 'https://github.com/clawbureau/clawbureau/actions/runs/101#artifacts',
        },
      ],
      canary_history: [
        {
          workflow: 'clawsig-canary-seed.yml',
          run_id: 102,
          status: 'completed',
          conclusion: 'success',
          created_at: '2026-02-19T00:02:00.000Z',
          updated_at: '2026-02-19T00:03:00.000Z',
          html_url: 'https://github.com/clawbureau/clawbureau/actions/runs/102',
          head_sha: 'abcdef123456',
          artifacts_url: 'https://github.com/clawbureau/clawbureau/actions/runs/102#artifacts',
        },
      ],
      guarded_deploy_history: [
        {
          workflow: 'clawsig-guarded-deploy.yml',
          run_id: 103,
          status: 'completed',
          conclusion: 'success',
          created_at: '2026-02-19T00:04:00.000Z',
          updated_at: '2026-02-19T00:05:00.000Z',
          html_url: 'https://github.com/clawbureau/clawbureau/actions/runs/103',
          head_sha: 'abcdef123456',
          artifacts_url: 'https://github.com/clawbureau/clawbureau/actions/runs/103#artifacts',
        },
      ],
      recent_failed_runs: [
        {
          run_id: 'run_fail_1',
          bundle_hash_b64u: 'hash_1',
          agent_did: 'did:key:agent-1',
          proof_tier: 'gateway',
          status: 'FAIL',
          reason_code: 'POW_INVALID',
          failure_class: 'none',
          verification_source: 'clawverify_api',
          auth_mode: 'pow',
          created_at: '2026-02-19 01:00:00',
        },
      ],
    });

    expect(html).toContain('Operations Dashboard');
    expect(html).toContain('Domain Health');
    expect(html).toContain('Synthetic Trend (latest runs)');
    expect(html).toContain('Canary Seed History');
    expect(html).toContain('Recent Failed Routes + Reason Codes');
    expect(html).toContain('Latest Artifact Bundles');
    expect(html).toContain('/runs?status=FAIL&reason_code=POW_INVALID');
  });
});
