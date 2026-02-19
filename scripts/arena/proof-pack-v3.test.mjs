import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  buildProofPackV3,
  validateProofPackV3Shape,
  writeProofPackArtifacts,
} from './lib/proof-pack-v3.mjs';

const sampleInput = {
  arena_id: 'arena_sample_001',
  generated_at: '2026-02-19T12:00:00.000Z',
  claim_binding: {
    bounty_id: 'bty_sample_001',
    contract_id: 'contract_sample_001',
    contract_hash_b64u: '9fUlg6xBkfyyjv4FIKR2Rjm3M2fW2Y8zW0y0kJ3Qn3A',
    claim_hash_b64u: '9fUlg6xBkfyyjv4FIKR2Rjm3M2fW2Y8zW0y0kJ3Qn3B',
    task_fingerprint: 'bugfix:typescript:api',
    objective_profile: 'balanced',
  },
  contender: {
    contender_id: 'contender_alpha',
    label: 'Alpha contender',
    model: 'gpt-5.2-codex',
    harness: 'pi',
    tools: ['rg', 'bash', 'read'],
    skills: ['cloudflare', 'ai-sdk'],
    plugins: ['did-work'],
    prompt: 'solve with fail-closed posture',
  },
  compliance_checks: [
    { criterion_id: 'ac_1', required: true, passed: true, reason_code: 'CHECK_OK' },
    { criterion_id: 'ac_2', required: true, passed: false, reason_code: 'TEST_MISSING' },
    { criterion_id: 'ac_3', required: false, passed: true, reason_code: 'CHECK_OK' },
  ],
  metrics: {
    quality_score: 83.12,
    risk_score: 42.1,
    efficiency_score: 76.44,
    latency_ms: 18342,
    cost_usd: 0.1912,
    autonomy_score: 71.9,
  },
  delivery_summary: 'Implements endpoint coverage and deterministic conflict handling.',
  evidence_links: [
    { label: 'PR', url: 'https://github.com/clawbureau/clawbureau/pull/999' },
    { label: 'Artifacts', url: 'https://example.com/artifacts/arena_sample_001' },
  ],
  insights: {
    bottlenecks: ['slow fixture generation'],
    contract_improvements: ['clarify acceptance test timeout'],
    next_delegation_hints: ['prefer contender with stronger test discipline'],
  },
};

test('proof pack shape validator accepts generated v3 payload', () => {
  const proofPack = buildProofPackV3(sampleInput);
  const validation = validateProofPackV3Shape(proofPack);
  assert.equal(validation.valid, true, validation.errors.join('; '));
  assert.equal(proofPack.compliance.mandatory_passed, 1);
  assert.equal(proofPack.compliance.mandatory_failed, 1);
});

test('proof pack artifact writing is deterministic for same input', () => {
  const proofPackA = buildProofPackV3(sampleInput);
  const proofPackB = buildProofPackV3(sampleInput);

  const dir = mkdtempSync(path.join(os.tmpdir(), 'arena-proof-v3-'));
  const outA = path.join(dir, 'a');
  const outB = path.join(dir, 'b');

  writeProofPackArtifacts(outA, proofPackA);
  writeProofPackArtifacts(outB, proofPackB);

  const aProof = readFileSync(path.join(outA, 'proof-pack.v3.json'), 'utf8');
  const bProof = readFileSync(path.join(outB, 'proof-pack.v3.json'), 'utf8');
  const aManager = readFileSync(path.join(outA, 'manager-review.json'), 'utf8');
  const bManager = readFileSync(path.join(outB, 'manager-review.json'), 'utf8');
  const aReviewPaste = readFileSync(path.join(outA, 'review-paste.md'), 'utf8');
  const bReviewPaste = readFileSync(path.join(outB, 'review-paste.md'), 'utf8');

  assert.equal(aProof, bProof);
  assert.equal(aManager, bManager);
  assert.equal(aReviewPaste, bReviewPaste);

  rmSync(dir, { recursive: true, force: true });
});

test('proof pack schema includes expected top-level required fields', () => {
  const schemaPath = path.resolve('packages/schema/arena/proof_pack.v3.json');
  const schema = JSON.parse(readFileSync(schemaPath, 'utf8'));
  const required = new Set(schema.required ?? []);

  for (const field of ['schema_version', 'claim_binding', 'contender', 'compliance', 'metrics', 'evidence', 'insights']) {
    assert.equal(required.has(field), true, `expected schema required field: ${field}`);
  }
});
