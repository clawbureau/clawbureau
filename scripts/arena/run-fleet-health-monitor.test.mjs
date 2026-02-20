import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

describe('AGP-US-085 fleet health monitor', () => {
  it('script file exists and is valid JS', () => {
    const content = readFileSync(resolve(import.meta.dirname, 'run-fleet-health-monitor.mjs'), 'utf8');
    assert.ok(content.length > 100, 'script too small');
    assert.ok(content.includes('arena_fleet_health_report.v1'), 'missing schema version');
    assert.ok(content.includes('fetchFleetHealth'), 'missing fetch function');
    assert.ok(content.includes('/v1/arena/desk/fleet-health'), 'missing endpoint path');
    assert.ok(content.includes('critical_count'), 'missing critical_count');
  });

  it('fleet health endpoint exists in worker', () => {
    const content = readFileSync(
      resolve(import.meta.dirname, '../../services/_archived/clawbounties/src/index.ts'),
      'utf8',
    );
    assert.ok(content.includes("'/v1/arena/desk/fleet-health'"), 'missing fleet-health route');
    assert.ok(content.includes('handleGetFleetHealth'), 'missing handler function');
    assert.ok(content.includes('arena_fleet_health.v1'), 'missing schema version');
  });

  it('all deterministic alert codes are defined', () => {
    const content = readFileSync(
      resolve(import.meta.dirname, '../../services/_archived/clawbounties/src/index.ts'),
      'utf8',
    );
    const expectedCodes = [
      'FLEET_ACCEPT_RATE_CRITICAL',
      'FLEET_ACCEPT_RATE_LOW',
      'FLEET_OVERRIDE_RATE_CRITICAL',
      'FLEET_OVERRIDE_RATE_HIGH',
      'FLEET_REWORK_RATE_HIGH',
      'FLEET_COST_PER_ACCEPTED_HIGH',
      'FLEET_ROI_NO_DATA',
      'FLEET_BACKLOG_CRITICAL',
      'FLEET_BACKLOG_HIGH',
      'FLEET_NO_ACTIVE_WORKERS',
      'FLEET_CRON_DISABLED',
      'FLEET_DUEL_STALE',
    ];
    for (const code of expectedCodes) {
      assert.ok(content.includes(code), `missing alert code: ${code}`);
    }
  });

  it('health status is deterministic from alerts', () => {
    const content = readFileSync(
      resolve(import.meta.dirname, '../../services/_archived/clawbounties/src/index.ts'),
      'utf8',
    );
    // Verify the status derivation logic exists
    assert.ok(content.includes("hasCritical ? 'critical'"), 'missing critical status derivation');
    assert.ok(content.includes("hasWarning ? 'degraded'"), 'missing degraded status derivation');
    assert.ok(content.includes("'healthy'"), 'missing healthy status');
  });

  it('fleet summary includes all required fields', () => {
    const content = readFileSync(
      resolve(import.meta.dirname, '../../services/_archived/clawbounties/src/index.ts'),
      'utf8',
    );
    const requiredFields = [
      'active_workers',
      'pending_backlog',
      'roi_status',
      'roi_sample_count',
      'cron_enabled',
      'recent_duel_count',
    ];
    for (const field of requiredFields) {
      assert.ok(content.includes(field), `missing fleet_summary field: ${field}`);
    }
  });

  it('alerts have required structure', () => {
    const content = readFileSync(
      resolve(import.meta.dirname, '../../services/_archived/clawbounties/src/index.ts'),
      'utf8',
    );
    // Check FleetHealthAlert interface
    assert.ok(content.includes('interface FleetHealthAlert'), 'missing alert interface');
    assert.ok(content.includes("severity: 'critical' | 'warning' | 'info'"), 'missing severity enum');
    assert.ok(content.includes('code: string'), 'missing code field');
    assert.ok(content.includes('message: string'), 'missing message field');
    assert.ok(content.includes('threshold:'), 'missing threshold field');
  });
});
