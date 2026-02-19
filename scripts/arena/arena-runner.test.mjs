import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runArena } from './lib/arena-runner.mjs';

const contract = JSON.parse(
  readFileSync(path.resolve('contracts/arena/bounty-contract.sample.v1.json'), 'utf8')
);
const contenders = JSON.parse(
  readFileSync(path.resolve('contracts/arena/contenders.sample.v1.json'), 'utf8')
);

test('arena runner produces deterministic rankings and winner rationale', () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'arena-runner-'));
  const outA = path.join(dir, 'a');
  const outB = path.join(dir, 'b');

  const reportA = runArena({
    contract,
    contenders,
    outputDir: outA,
    generatedAt: '2026-02-19T15:00:00.000Z',
    arenaIdOverride: 'arena_sample_compare_001',
  });

  const reportB = runArena({
    contract,
    contenders,
    outputDir: outB,
    generatedAt: '2026-02-19T15:00:00.000Z',
    arenaIdOverride: 'arena_sample_compare_001',
  });

  assert.equal(reportA.schema_version, 'arena_report.v1');
  assert.equal(reportA.contenders.length, 3);
  assert.equal(reportA.rankings.length, 3);
  assert.equal(typeof reportA.score_explain.formula.summary, 'string');
  assert.equal(Array.isArray(reportA.contenders[0].score_explain.evidence_links), true);
  assert.equal(reportA.winner.contender_id, reportB.winner.contender_id);
  assert.deepEqual(
    reportA.rankings.map((row) => ({ contender_id: row.contender_id, score: row.score, hard_gate_pass: row.hard_gate_pass })),
    reportB.rankings.map((row) => ({ contender_id: row.contender_id, score: row.score, hard_gate_pass: row.hard_gate_pass }))
  );

  const reportAOnDisk = JSON.parse(readFileSync(path.join(outA, 'arena-report.json'), 'utf8'));
  const reportBOnDisk = JSON.parse(readFileSync(path.join(outB, 'arena-report.json'), 'utf8'));

  assert.equal(reportAOnDisk.winner.contender_id, reportBOnDisk.winner.contender_id);
  assert.equal(reportAOnDisk.reason_codes.join(','), reportBOnDisk.reason_codes.join(','));

  rmSync(dir, { recursive: true, force: true });
});

test('arena runner fails closed when mandatory evidence_signals are missing', () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'arena-runner-missing-evidence-'));
  const out = path.join(dir, 'out');

  const invalidContenders = structuredClone(contenders);
  delete invalidContenders[0].evidence_signals;

  assert.throws(
    () => runArena({
      contract,
      contenders: invalidContenders,
      outputDir: out,
      generatedAt: '2026-02-19T15:00:00.000Z',
      arenaIdOverride: 'arena_missing_evidence',
    }),
    /evidence_signals/,
  );

  rmSync(dir, { recursive: true, force: true });
});

