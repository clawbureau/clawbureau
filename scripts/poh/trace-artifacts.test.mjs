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
    status: 'PASS',
    reason_code: 'OK',
    reason: 'Proof bundle verified successfully',
    verified_at: '2026-02-18T00:00:03.000Z',
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

  const verifyOut = report.trace.verification_results[0];
  assert.equal(verifyOut.status, 'PASS');
  assert.equal(verifyOut.code, 'OK');
});
