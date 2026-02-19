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
      slo_health: {
        generated_at: '2026-02-19T00:05:00.000Z',
        target_success_rate: 0.99,
        error_budget_fraction: 0.01,
        thresholds: {
          warn_burn_rate_24h: 1,
          warn_burn_rate_7d: 1,
          critical_burn_rate_24h: 2,
          critical_burn_rate_7d: 1.5,
        },
        windows: {
          window_24h: {
            window: '24h',
            runs: 20,
            fail_runs: 2,
            fail_rate: 0.1,
            error_budget_fraction: 0.01,
            burn_rate: 10,
          },
          window_7d: {
            window: '7d',
            runs: 120,
            fail_runs: 6,
            fail_rate: 0.05,
            error_budget_fraction: 0.01,
            burn_rate: 5,
          },
        },
        severity: 'critical',
        status: 'degraded',
        reason_code: 'SLO_CRITICAL_BURNRATE_MULTIWINDOW',
        domain_degraded_hosts: [],
        failing_workflows: [],
        notes: [],
      },
    });

    expect(html).toContain('Operations Dashboard');
    expect(html).toContain('Domain Health');
    expect(html).toContain('SLO Burn-Rate Guardrails');
    expect(html).toContain('SLO_CRITICAL_BURNRATE_MULTIWINDOW');
    expect(html).toContain('/ops/slo-health.json');
    expect(html).toContain('Synthetic Trend (latest runs)');
    expect(html).toContain('Incident Mode');
    expect(html).toContain('Incident Priority: Failing Routes + Reason Buckets');
    expect(html).toContain('Incident Priority: Latest Artifact Bundles');
    expect(html).not.toContain('Canary Seed History');
    expect(html).toContain('/runs?status=FAIL&reason_code=POW_INVALID');
  });

  it('keeps full history layout when SLO is healthy', () => {
    const html = opsDashboardPage({
      stats: {
        total_runs: 10,
        total_agents: 2,
        runs_24h: 10,
        fail_runs_24h: 0,
        fail_rate_24h: 0,
        top_fail_reason_codes: [],
        diagnostics_7d: {
          runs_7d: 70,
          fail_runs_7d: 0,
          fail_rate_7d: 0,
          top_fail_reason_codes_7d: [],
          daily: [],
        },
      },
      domain_health: [],
      synthetic_statuses: [],
      synthetic_history: [],
      canary_history: [],
      guarded_deploy_history: [],
      recent_failed_runs: [],
      slo_health: {
        generated_at: '2026-02-19T00:05:00.000Z',
        target_success_rate: 0.99,
        error_budget_fraction: 0.01,
        thresholds: {
          warn_burn_rate_24h: 1,
          warn_burn_rate_7d: 1,
          critical_burn_rate_24h: 2,
          critical_burn_rate_7d: 1.5,
        },
        windows: {
          window_24h: {
            window: '24h',
            runs: 10,
            fail_runs: 0,
            fail_rate: 0,
            error_budget_fraction: 0.01,
            burn_rate: 0,
          },
          window_7d: {
            window: '7d',
            runs: 70,
            fail_runs: 0,
            fail_rate: 0,
            error_budget_fraction: 0.01,
            burn_rate: 0,
          },
        },
        severity: 'ok',
        status: 'healthy',
        reason_code: 'SLO_HEALTHY',
        domain_degraded_hosts: [],
        failing_workflows: [],
        notes: [],
      },
    });

    expect(html).not.toContain('Incident Mode');
    expect(html).toContain('Canary Seed History');
    expect(html).toContain('Recent Failed Routes + Reason Codes');
  });
});
