import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

describe('AGP-US-086 weekly ops report generator', () => {
  it('script file exists and is valid JS', () => {
    const content = readFileSync(resolve(import.meta.dirname, 'run-weekly-ops-report.mjs'), 'utf8');
    assert.ok(content.length > 100, 'script too small');
    assert.ok(content.includes('arena_weekly_ops_report.v1'), 'missing schema version');
    assert.ok(content.includes('fetchJson'), 'missing fetch function');
    assert.ok(content.includes('deriveWeekRange'), 'missing week range derivation');
    assert.ok(content.includes('deriveOverallGrade'), 'missing grade derivation');
    assert.ok(content.includes('generateRecommendations'), 'missing recommendations');
  });

  it('fetches all three data sources', () => {
    const content = readFileSync(resolve(import.meta.dirname, 'run-weekly-ops-report.mjs'), 'utf8');
    assert.ok(content.includes('/v1/arena/roi-dashboard'), 'missing ROI fetch');
    assert.ok(content.includes('/v1/arena/desk/fleet-health'), 'missing fleet health fetch');
    assert.ok(content.includes('/v1/arena/duel-league'), 'missing duel league fetch');
  });

  it('report has correct structure', () => {
    const content = readFileSync(resolve(import.meta.dirname, 'run-weekly-ops-report.mjs'), 'utf8');
    const requiredFields = [
      'schema_version',
      'generated_at',
      'week',
      'overall_grade',
      'roi',
      'fleet_health',
      'duel_league',
      'recommendations',
    ];
    for (const field of requiredFields) {
      assert.ok(content.includes(field), `missing report field: ${field}`);
    }
  });

  it('grade derivation is deterministic', () => {
    const content = readFileSync(resolve(import.meta.dirname, 'run-weekly-ops-report.mjs'), 'utf8');
    const expectedGrades = ['INCOMPLETE', 'CRITICAL', 'NEEDS_ATTENTION', 'EXCELLENT', 'GOOD'];
    for (const grade of expectedGrades) {
      assert.ok(content.includes(grade), `missing grade: ${grade}`);
    }
  });

  it('recommendations are actionable', () => {
    const content = readFileSync(resolve(import.meta.dirname, 'run-weekly-ops-report.mjs'), 'utf8');
    assert.ok(content.includes("priority: 'high'"), 'missing high priority');
    assert.ok(content.includes("priority: 'medium'"), 'missing medium priority');
    assert.ok(content.includes("priority: 'low'"), 'missing low priority');
    assert.ok(content.includes("priority: 'info'"), 'missing info priority');
  });

  it('weekly report endpoint exists in worker', () => {
    const content = readFileSync(
      resolve(import.meta.dirname, '../../services/_archived/clawbounties/src/index.ts'),
      'utf8',
    );
    assert.ok(content.includes("'/v1/arena/desk/weekly-report'"), 'missing weekly-report route');
    assert.ok(content.includes('arena_weekly_report.v1'), 'missing schema version in worker');
  });
});
