import { describe, expect, it } from 'vitest';
import { deriveOpsSloHealth } from '../src/slo.js';

describe('deriveOpsSloHealth', () => {
  it('returns healthy status when burn rates are within budget', () => {
    const health = deriveOpsSloHealth({
      stats: {
        runs_24h: 100,
        fail_runs_24h: 1,
        fail_rate_24h: 0.009,
        diagnostics_7d: {
          runs_7d: 700,
          fail_runs_7d: 4,
          fail_rate_7d: 0.005,
        },
      },
      domainHealth: [
        { host: 'api.clawverify.com', ok: true },
      ],
      syntheticStatuses: [
        { workflow: 'clawsig-surface-synthetic-smoke.yml', ok: true },
      ],
    });

    expect(health.severity).toBe('ok');
    expect(health.reason_code).toBe('SLO_HEALTHY');
  });

  it('returns warn when burn rate exceeds warn threshold', () => {
    const health = deriveOpsSloHealth({
      stats: {
        runs_24h: 100,
        fail_runs_24h: 2,
        fail_rate_24h: 0.015,
        diagnostics_7d: {
          runs_7d: 700,
          fail_runs_7d: 7,
          fail_rate_7d: 0.009,
        },
      },
      domainHealth: [],
      syntheticStatuses: [],
    });

    expect(health.severity).toBe('warn');
    expect(health.reason_code).toBe('SLO_WARN_BURNRATE_24H');
  });

  it('returns critical with deterministic reason code when domain health degrades', () => {
    const health = deriveOpsSloHealth({
      stats: {
        runs_24h: 100,
        fail_runs_24h: 0,
        fail_rate_24h: 0,
        diagnostics_7d: {
          runs_7d: 700,
          fail_runs_7d: 0,
          fail_rate_7d: 0,
        },
      },
      domainHealth: [
        { host: 'api.clawverify.com', ok: false },
      ],
      syntheticStatuses: [],
    });

    expect(health.severity).toBe('critical');
    expect(health.reason_code).toBe('SLO_CRITICAL_DOMAIN_HEALTH_DEGRADED');
  });
});
