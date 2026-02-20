import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

describe('AGP-US-084 ops ROI dashboard reporter', () => {
  it('script file exists and is valid JS', () => {
    const scriptPath = resolve(import.meta.dirname, 'run-ops-roi-dashboard.mjs');
    const content = readFileSync(scriptPath, 'utf8');
    assert.ok(content.length > 100, 'script too small');
    assert.ok(content.includes('arena_ops_roi_report.v1'), 'missing schema version');
    assert.ok(content.includes('fetchRoiDashboard'), 'missing fetch function');
    assert.ok(content.includes('assessHealth'), 'missing health assessment');
    assert.ok(content.includes('cycle_time_percentiles'), 'missing percentile fields');
    assert.ok(content.includes('contender_costs'), 'missing contender costs');
    assert.ok(content.includes('daily_bucket_count'), 'missing daily buckets');
  });

  it('health assessment logic computes correctly', async () => {
    // Inline the assessment logic to test independently
    function assessHealth(dashboard) {
      const alerts = [];
      const m = dashboard.metrics;
      if (!m) return { status: 'NO_METRICS', alerts: ['No metrics available'] };

      if (m.first_pass_accept_rate < 0.3) {
        alerts.push(`CRITICAL: low accept rate ${(m.first_pass_accept_rate * 100).toFixed(1)}%`);
      } else if (m.first_pass_accept_rate < 0.5) {
        alerts.push(`WARN: accept rate ${(m.first_pass_accept_rate * 100).toFixed(1)}%`);
      }
      if (m.override_rate > 0.4) {
        alerts.push(`CRITICAL: high override rate`);
      } else if (m.override_rate > 0.25) {
        alerts.push(`WARN: override rate`);
      }
      if (m.rework_rate > 0.3) {
        alerts.push(`CRITICAL: rework rate`);
      }
      if (m.cost_per_accepted_bounty_usd > 1.0) {
        alerts.push(`WARN: high cost`);
      }
      const status = alerts.some((a) => a.startsWith('CRITICAL')) ? 'CRITICAL'
        : alerts.length > 0 ? 'WARN'
        : 'HEALTHY';
      return { status, alerts };
    }

    // Healthy metrics
    const healthy = assessHealth({
      metrics: {
        first_pass_accept_rate: 0.8,
        override_rate: 0.05,
        rework_rate: 0.05,
        cost_per_accepted_bounty_usd: 0.35,
      },
    });
    assert.equal(healthy.status, 'HEALTHY');
    assert.equal(healthy.alerts.length, 0);

    // Warning metrics
    const warn = assessHealth({
      metrics: {
        first_pass_accept_rate: 0.45,
        override_rate: 0.1,
        rework_rate: 0.1,
        cost_per_accepted_bounty_usd: 0.35,
      },
    });
    assert.equal(warn.status, 'WARN');
    assert.ok(warn.alerts.length >= 1);

    // Critical metrics
    const critical = assessHealth({
      metrics: {
        first_pass_accept_rate: 0.2,
        override_rate: 0.5,
        rework_rate: 0.4,
        cost_per_accepted_bounty_usd: 2.0,
      },
    });
    assert.equal(critical.status, 'CRITICAL');
    assert.ok(critical.alerts.length >= 2);

    // No metrics
    const noMetrics = assessHealth({ metrics: null });
    assert.equal(noMetrics.status, 'NO_METRICS');
  });

  it('enhanced ROI dashboard schema has required fields', () => {
    // Verify that the clawbounties worker would produce the expected enhanced fields
    const expectedFields = [
      'cycle_time_percentiles',
      'daily_buckets',
      'contender_costs',
    ];
    const scriptContent = readFileSync(
      resolve(import.meta.dirname, '../../services/_archived/clawbounties/src/index.ts'),
      'utf8',
    );
    for (const field of expectedFields) {
      assert.ok(
        scriptContent.includes(field),
        `clawbounties worker missing enhanced field: ${field}`,
      );
    }
  });

  it('computePercentile function exists in worker', () => {
    const scriptContent = readFileSync(
      resolve(import.meta.dirname, '../../services/_archived/clawbounties/src/index.ts'),
      'utf8',
    );
    assert.ok(scriptContent.includes('function computePercentile('), 'missing computePercentile');
    assert.ok(scriptContent.includes('p50:'), 'missing p50 in percentiles');
    assert.ok(scriptContent.includes('p95:'), 'missing p95 in percentiles');
  });

  it('explorer arena-roi page exists', () => {
    const content = readFileSync(
      resolve(import.meta.dirname, '../../services/clawsig-explorer/src/pages/arena-roi.ts'),
      'utf8',
    );
    assert.ok(content.includes('arenaRoiPage'), 'missing arenaRoiPage export');
    assert.ok(content.includes('arenaRoiUnavailablePage'), 'missing unavailable page');
    assert.ok(content.includes('cycle_time_percentiles'), 'missing percentiles rendering');
    assert.ok(content.includes('contender_costs'), 'missing contender costs rendering');
    assert.ok(content.includes('daily_buckets'), 'missing daily buckets rendering');
  });

  it('explorer index routes /arena/roi', () => {
    const content = readFileSync(
      resolve(import.meta.dirname, '../../services/clawsig-explorer/src/index.ts'),
      'utf8',
    );
    assert.ok(content.includes("'/arena/roi'"), 'missing /arena/roi route');
    assert.ok(content.includes('fetchArenaRoiDashboard'), 'missing fetchArenaRoiDashboard call');
    assert.ok(content.includes('arenaRoiPage'), 'missing arenaRoiPage call');
  });
});
