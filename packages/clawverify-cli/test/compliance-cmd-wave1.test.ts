import * as fs from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';

import { describe, expect, it } from 'vitest';

import { runComplianceReport } from '../src/compliance-cmd.js';

interface CompilerOutput {
  runtime: {
    state: string;
    global_status: string;
    global_reason_code: string;
  };
  report?: {
    generated_at: string;
    controls: Array<{ control_id: string; status: string; reason_code?: string }>;
  };
  failure?: {
    reason_code: string;
    upstream_reason_code?: string;
  };
}

const VERIFIED_AT = '2026-01-01T00:00:00.000Z';

async function runComplianceFixture(
  fixture: unknown,
  outputName: string,
): Promise<CompilerOutput> {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'clawverify-compliance-wave1-'));
  const inputPath = path.join(tmpDir, 'input.json');
  const outputPath = path.join(tmpDir, outputName);

  await fs.writeFile(inputPath, JSON.stringify(fixture, null, 2), 'utf8');
  await runComplianceReport(inputPath, 'soc2', outputPath);

  const outputRaw = await fs.readFile(outputPath, 'utf8');
  return JSON.parse(outputRaw) as CompilerOutput;
}

describe('runComplianceReport Wave-1 authoritative compiler', () => {
  it('is deterministic for identical verified compiler inputs', async () => {
    const fixture = {
      envelope: {
        payload: {
          agent_did: 'did:key:agent-wave1',
          event_chain: [{ event_id: 'evt-1' }],
          receipts: [{ payload: { receipt_id: 'gw-1', model: 'model-approved' } }],
          tool_receipts: [{ receipt_id: 'tool-1', tool_name: 'edit' }],
          side_effect_receipts: [
            { receipt_id: 'se-1', effect_class: 'network_egress' },
          ],
          human_approval_receipts: [
            { receipt_id: 'ha-1', approval_type: 'explicit_approve' },
          ],
        },
      },
      policy: {
        policy_hash_b64u: 'policy-hash',
        allowed_models: ['model-approved'],
      },
      verification_fact: {
        status: 'VALID',
        reason_code: 'OK',
        reason: 'Proof bundle verified successfully',
        verified_at: VERIFIED_AT,
        verifier: 'clawverify-cli-test',
        agent_did: 'did:key:agent-wave1',
      },
    };

    const out1 = await runComplianceFixture(fixture, 'out1.json');
    const out2 = await runComplianceFixture(fixture, 'out2.json');

    expect(out1).toEqual(out2);
    expect(out1.runtime.state).toBe('COMPILED_PASS');
    expect(out1.runtime.global_status).toBe('PASS');
    expect(out1.report?.generated_at).toBe(VERIFIED_AT);
    expect(out1.report?.controls.every((c) => c.status === 'PASS')).toBe(true);
  });

  it('halts fail-closed when upstream verification is INVALID and deterministically maps reason codes', async () => {
    const fixture = {
      envelope: {
        payload: {
          agent_did: 'did:key:agent-wave1',
          receipts: [{ payload: { receipt_id: 'gw-1', model: 'model-approved' } }],
        },
      },
      verification_fact: {
        status: 'INVALID',
        reason_code: 'hash mismatch',
        reason: 'Bundle hash mismatch',
        verified_at: VERIFIED_AT,
        verifier: 'clawverify-cli-test',
        agent_did: 'did:key:agent-wave1',
      },
    };

    const out = await runComplianceFixture(fixture, 'out-invalid.json');

    expect(out.runtime.state).toBe('HALTED_UPSTREAM_INVALID');
    expect(out.runtime.global_status).toBe('FAIL');
    expect(out.runtime.global_reason_code).toBe('HASH_MISMATCH');
    expect(out.failure?.reason_code).toBe('HASH_MISMATCH');
    expect(out.failure?.upstream_reason_code).toBe('hash mismatch');
    expect(out.report).toBeUndefined();
  });

  it('rejects non-verifier-backed inputs fail-closed', async () => {
    const fixture = {
      envelope: {
        payload: {
          agent_did: 'did:key:agent-wave1',
          receipts: [{ payload: { receipt_id: 'gw-1', model: 'model-approved' } }],
        },
      },
      policy: {
        policy_hash_b64u: 'policy-hash',
        allowed_models: ['model-approved'],
      },
    };

    const out = await runComplianceFixture(fixture, 'out-missing-vf.json');

    expect(out.runtime.state).toBe('INPUT_REJECTED');
    expect(out.runtime.global_status).toBe('FAIL');
    expect(out.runtime.global_reason_code).toBe(
      'COMPILER_INPUT_MISSING_VERIFICATION_FACT',
    );
    expect(out.failure?.reason_code).toBe('COMPILER_INPUT_MISSING_VERIFICATION_FACT');
    expect(out.report).toBeUndefined();
  });

  it('rejects ad-hoc top-level PASS flags so raw bundles cannot masquerade as verified inputs', async () => {
    const fixture = {
      agent_did: 'did:key:agent-wave1',
      receipts: [{ payload: { receipt_id: 'gw-1', model: 'model-approved' } }],
      status: 'PASS',
      reason_code: 'OK',
      reason: 'forged',
      verified_at: VERIFIED_AT,
    };

    const out = await runComplianceFixture(fixture, 'out-forged-status.json');

    expect(out.runtime.state).toBe('INPUT_REJECTED');
    expect(out.runtime.global_reason_code).toBe(
      'COMPILER_INPUT_MISSING_VERIFICATION_FACT',
    );
    expect(out.failure?.reason_code).toBe('COMPILER_INPUT_MISSING_VERIFICATION_FACT');
  });

  it('rejects malformed bundle collection fields deterministically instead of throwing', async () => {
    const fixture = {
      envelope: {
        payload: {
          agent_did: 'did:key:agent-wave1',
          receipts: [{ payload: { receipt_id: 'gw-1', model: 'model-approved' } }],
          side_effect_receipts: {
            receipt_id: 'se-1',
            effect_class: 'network_egress',
          },
        },
      },
      verification_fact: {
        status: 'VALID',
        reason_code: 'OK',
        reason: 'Proof bundle verified successfully',
        verified_at: VERIFIED_AT,
        verifier: 'clawverify-cli-test',
        agent_did: 'did:key:agent-wave1',
      },
    };

    const out = await runComplianceFixture(fixture, 'out-malformed-bundle.json');

    expect(out.runtime.state).toBe('INPUT_REJECTED');
    expect(out.runtime.global_reason_code).toBe(
      'COMPILER_INPUT_MALFORMED_SIDE_EFFECT_RECEIPTS',
    );
    expect(out.failure?.reason_code).toBe(
      'COMPILER_INPUT_MALFORMED_SIDE_EFFECT_RECEIPTS',
    );
  });

  it('produces explicit deterministic missing-evidence outcomes instead of silent skips', async () => {
    const fixture = {
      envelope: {
        payload: {
          agent_did: 'did:key:agent-wave1',
          receipts: [{ payload: { receipt_id: 'gw-1', model: 'model-approved' } }],
          side_effect_receipts: [
            { receipt_id: 'se-1', effect_class: 'network_egress' },
          ],
        },
      },
      policy: {
        policy_hash_b64u: 'policy-hash',
        allowed_models: ['model-approved'],
      },
      verification_fact: {
        status: 'VALID',
        reason_code: 'OK',
        reason: 'Proof bundle verified successfully',
        verified_at: VERIFIED_AT,
        verifier: 'clawverify-cli-test',
        agent_did: 'did:key:agent-wave1',
      },
    };

    const out = await runComplianceFixture(fixture, 'out-missing-evidence.json');

    expect(out.runtime.state).toBe('COMPILED_FAIL');
    expect(out.runtime.global_status).toBe('FAIL');
    expect(out.runtime.global_reason_code).toBe(
      'CC7_1_MISSING_EVENT_CHAIN_AND_TOOL_RECEIPTS',
    );

    const cc71 = out.report?.controls.find((c) => c.control_id === 'CC7.1');
    const cc72 = out.report?.controls.find((c) => c.control_id === 'CC7.2');

    expect(cc71?.status).toBe('INSUFFICIENT_EVIDENCE');
    expect(cc71?.reason_code).toBe('CC7_1_MISSING_EVENT_CHAIN_AND_TOOL_RECEIPTS');
    expect(cc72?.status).toBe('INSUFFICIENT_EVIDENCE');
    expect(cc72?.reason_code).toBe('CC7_2_MISSING_EVENT_CHAIN');
  });
});
