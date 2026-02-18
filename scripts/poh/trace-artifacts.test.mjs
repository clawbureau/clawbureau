import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';

function sha256B64u(value) {
  const digest = createHash('sha256').update(JSON.stringify(value)).digest('base64');
  return digest.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

async function writeJson(filePath, value) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

test('trace-artifacts reports timeline/tool summary + URM hash match + verify status', async () => {
  const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'artifact-tracer-test-'));
  const scriptPath = path.resolve('scripts/poh/trace-artifacts.mjs');

  const runId = 'run_test_001';
  const agentDid = 'did:key:z6MktzmKpfCNcKSUp7qzTrZK3c89QFvhgmK7V1GXxMH9m8XW';

  const urm = {
    urm_version: '1',
    urm_id: 'urm_test_001',
    run_id: runId,
    agent_did: agentDid,
    issued_at: '2026-02-18T00:00:00.000Z',
    harness: { id: 'pi', version: '1.0.0' },
    inputs: [],
    outputs: [],
  };

  const urmHash = sha256B64u(urm);

  const bundle = {
    envelope_version: '1',
    envelope_type: 'proof_bundle',
    payload: {
      bundle_version: '1',
      bundle_id: 'bundle_test_001',
      agent_did: agentDid,
      urm: {
        urm_version: '1',
        urm_id: urm.urm_id,
        resource_hash_b64u: urmHash,
        hash_algorithm: 'SHA-256',
      },
      event_chain: [
        {
          event_id: 'ev_1',
          run_id: runId,
          event_type: 'tool.call',
          timestamp: '2026-02-18T00:00:01.000Z',
          payload_hash_b64u: 'h_payload',
          prev_hash_b64u: null,
          event_hash_b64u: 'h_event_1',
        },
      ],
      receipts: [
        {
          envelope_type: 'gateway_receipt',
          payload: {
            provider: 'openai',
            model: 'gpt-4',
            binding: {
              attribution_confidence: 1.0,
              phase: 'execution',
            },
          },
        },
      ],
      coverage_attestations: [
        {
          payload: {
            metrics: {
              lineage: {
                unmonitored_spawns: 0,
                escapes_suspected: false,
              },
              egress: {
                unmediated_connections: 0,
              },
            },
          },
        },
      ],
      side_effect_receipts: [
        {
          receipt_version: '1',
          receipt_id: 'ser_1',
          effect_class: 'network_egress',
          target_digest: 'hash_side_effect_target',
          agent_did: agentDid,
          timestamp: '2026-02-18T00:00:01.200Z',
          binding: {
            attribution_confidence: 0.5,
            phase: 'execution',
          },
        },
      ],
      tool_receipts: [
        {
          receipt_version: '1',
          receipt_id: 'tr_1',
          tool_name: 'bash',
          result_status: 'success',
          hash_algorithm: 'SHA-256',
          agent_did: agentDid,
          timestamp: '2026-02-18T00:00:01.100Z',
        },
      ],
      metadata: {
        sentinels: {
          interpose_active: true,
          interpose_state: {
            cldd: {
              unmediated_connections: 2,
              unmonitored_spawns: 0,
              escapes_suspected: false,
            },
          },
        },
      },
    },
    payload_hash_b64u: 'h_payload_bundle',
    hash_algorithm: 'SHA-256',
    signature_b64u: 'sig',
    algorithm: 'Ed25519',
    signer_did: agentDid,
    issued_at: '2026-02-18T00:00:02.000Z',
  };

  const verify = {
    kind: 'proof_bundle',
    result: {
      status: 'INVALID',
      reason: 'CLDD discrepancy enforced',
      verified_at: '2026-02-18T00:00:03.000Z',
      risk_flags: ['COVERAGE_CLDD_DISCREPANCY'],
      component_results: {
        coverage_cldd_discrepancy: true,
        coverage_cldd_mismatch_fields: ['unmediated_connections'],
        coverage_cldd_claimed_metrics: {
          unmediated_connections: 2,
          unmonitored_spawns: 0,
          escapes_suspected: false,
        },
        coverage_cldd_attested_metrics: {
          unmediated_connections: 0,
          unmonitored_spawns: 0,
          escapes_suspected: false,
        },
      },
    },
    error: {
      code: 'COVERAGE_CLDD_DISCREPANCY_ENFORCED',
      message: 'Coverage enforcement is set to enforce and CLDD discrepancy was detected',
    },
  };

  const bundlePath = path.join(tempRoot, 'artifacts/poh/test-branch', `${runId}-bundle.json`);
  const urmPath = path.join(tempRoot, 'artifacts/poh/test-branch', `${runId}-urm.json`);
  const verifyPath = path.join(tempRoot, 'artifacts/poh/test-branch', `${runId}-verify.json`);

  await writeJson(bundlePath, bundle);
  await writeJson(urmPath, urm);
  await writeJson(verifyPath, verify);

  const stdout = execFileSync(
    process.execPath,
    [
      scriptPath,
      '--root',
      tempRoot,
      '--bundle',
      `artifacts/poh/test-branch/${runId}-bundle.json`,
      '--json',
    ],
    { encoding: 'utf8' }
  );

  const report = JSON.parse(stdout);

  assert.equal(report.trace.run_id, runId);
  assert.equal(report.trace.bundle.bundle_id, 'bundle_test_001');

  assert.equal(report.trace.bundle.event_timeline.length, 1);
  assert.equal(report.trace.bundle.event_timeline[0].event_type, 'tool.call');

  const toolSummary = report.trace.bundle.tool_summary.by_tool_name;
  assert.equal(toolSummary.length, 1);
  assert.equal(toolSummary[0].tool_name, 'bash');
  assert.equal(toolSummary[0].count, 1);

  assert.equal(report.trace.urm.hash_check_against_bundle_ref.match, true);

  const confidence = report.trace.delivery.confidence_distribution;
  assert.equal(confidence.total, 2);
  assert.equal(confidence.authoritative, 1);
  assert.equal(confidence.inferred, 1);

  const lowConfidence = report.trace.delivery.low_confidence_side_effects;
  assert.equal(lowConfidence.length, 1);
  assert.equal(lowConfidence[0].hash_first, 'hash_side_effect_target');
  assert.equal(lowConfidence[0].confidence, 0.5);

  const cldd = report.trace.delivery.cldd_discrepancy;
  assert.equal(cldd.discrepancy, true);
  assert.deepEqual(cldd.mismatch_fields, ['unmediated_connections']);
  assert.equal(cldd.enforcement_findings.length, 1);
  assert.equal(cldd.enforcement_findings[0].code, 'COVERAGE_CLDD_DISCREPANCY_ENFORCED');

  const verifyOut = report.trace.verification_results[0];
  assert.equal(verifyOut.status, 'INVALID');
  assert.equal(verifyOut.code, 'COVERAGE_CLDD_DISCREPANCY_ENFORCED');
});
