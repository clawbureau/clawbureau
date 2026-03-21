import * as fs from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';

import { describe, expect, it } from 'vitest';

import { runComplianceReport } from '../src/compliance-cmd.js';
import { verifyCompiledReportFromFile } from '../src/verify.js';

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
  compiled_report?: {
    report_id: string;
    matrix_hash_b64u: string;
    evidence_refs: Record<string, string>;
    control_results: Array<{
      control_id: string;
      status: string;
      reason_codes: string[];
      evidence_hashes_b64u: string[];
      waiver_applied: boolean;
    }>;
  };
  compiled_report_envelope?: {
    envelope_type: string;
    payload_hash_b64u: string;
    signature_b64u: string;
    signer_did: string;
    issued_at: string;
    payload: Record<string, unknown>;
  };
  failure?: {
    reason_code: string;
    upstream_reason_code?: string;
  };
}

const VERIFIED_AT = '2026-01-01T00:00:00.000Z';
const BASE58_ALPHABET =
  '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Encode(bytes: Uint8Array): string {
  if (bytes.length === 0) return '';

  const digits: number[] = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i++) {
      const x = digits[i]! * 256 + carry;
      digits[i] = x % 58;
      carry = Math.floor(x / 58);
    }

    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }

  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) {
    digits.push(0);
  }

  return digits
    .reverse()
    .map((digit) => BASE58_ALPHABET[digit]!)
    .join('');
}

async function makeDidSignerFromSeed(seed: Uint8Array): Promise<{
  did: string;
  privateKeyPkcs8B64u: string;
}> {
  const pkcs8Header = new Uint8Array([
    0x30, 0x2e,
    0x02, 0x01, 0x00,
    0x30, 0x05,
    0x06, 0x03, 0x2b, 0x65, 0x70,
    0x04, 0x22,
    0x04, 0x20,
  ]);

  const pkcs8Bytes = new Uint8Array(pkcs8Header.length + seed.length);
  pkcs8Bytes.set(pkcs8Header);
  pkcs8Bytes.set(seed, pkcs8Header.length);

  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    pkcs8Bytes,
    { name: 'Ed25519' },
    true,
    ['sign'],
  );

  const exported = (await crypto.subtle.exportKey('pkcs8', privateKey)) as ArrayBuffer;
  const pkcs8B64u = Buffer.from(new Uint8Array(exported)).toString('base64url');

  const jwk = (await crypto.subtle.exportKey('jwk', privateKey)) as JsonWebKey;
  const publicKey = Buffer.from(String(jwk.x), 'base64url');
  const prefixed = new Uint8Array(2 + publicKey.length);
  prefixed[0] = 0xed;
  prefixed[1] = 0x01;
  prefixed.set(publicKey, 2);

  return {
    did: `did:key:z${base58Encode(prefixed)}`,
    privateKeyPkcs8B64u: pkcs8B64u,
  };
}

function mutateBase64Url(input: string): string {
  if (input.length === 0) return 'A';
  const head = input[0] === 'A' ? 'B' : 'A';
  return `${head}${input.slice(1)}`;
}

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

  it('emits deterministic compiled report + signed envelope for identical signed inputs', async () => {
    const seed = new Uint8Array(32);
    for (let i = 0; i < seed.length; i++) seed[i] = i + 1;
    const signer = await makeDidSignerFromSeed(seed);

    const fixture = {
      envelope: {
        payload: {
          agent_did: signer.did,
          event_chain: [{ event_id: 'evt-compiled-1' }],
          receipts: [{ payload: { receipt_id: 'gw-compiled-1', model: 'model-approved' } }],
          tool_receipts: [{ receipt_id: 'tool-compiled-1', tool_name: 'edit' }],
          side_effect_receipts: [{ receipt_id: 'se-compiled-1', effect_class: 'network_egress' }],
          human_approval_receipts: [{ receipt_id: 'ha-compiled-1', approval_type: 'explicit_approve' }],
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
        agent_did: signer.did,
      },
      compiled_report_signer: {
        signer_did: signer.did,
        private_key_pkcs8_b64u: signer.privateKeyPkcs8B64u,
        issued_at: VERIFIED_AT,
      },
    };

    const out1 = await runComplianceFixture(fixture, 'out-compiled-1.json');
    const out2 = await runComplianceFixture(fixture, 'out-compiled-2.json');

    expect(out1.compiled_report).toEqual(out2.compiled_report);
    expect(out1.compiled_report_envelope).toEqual(out2.compiled_report_envelope);
    expect(out1.compiled_report_envelope?.signer_did).toBe(signer.did);
    expect(out1.compiled_report_envelope?.issued_at).toBe(VERIFIED_AT);
  });

  it('rejects signer inputs whose private key does not match signer_did', async () => {
    const didSeed = new Uint8Array(32);
    const keySeed = new Uint8Array(32);
    for (let i = 0; i < didSeed.length; i++) {
      didSeed[i] = i + 61;
      keySeed[i] = 0xee - i;
    }

    const didSigner = await makeDidSignerFromSeed(didSeed);
    const keySigner = await makeDidSignerFromSeed(keySeed);

    const fixture = {
      envelope: {
        payload: {
          agent_did: didSigner.did,
          event_chain: [{ event_id: 'evt-compiled-mismatch' }],
          receipts: [{ payload: { receipt_id: 'gw-compiled-mismatch', model: 'model-approved' } }],
          tool_receipts: [{ receipt_id: 'tool-compiled-mismatch', tool_name: 'edit' }],
          side_effect_receipts: [{ receipt_id: 'se-compiled-mismatch', effect_class: 'network_egress' }],
          human_approval_receipts: [{ receipt_id: 'ha-compiled-mismatch', approval_type: 'explicit_approve' }],
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
        agent_did: didSigner.did,
      },
      compiled_report_signer: {
        signer_did: didSigner.did,
        private_key_pkcs8_b64u: keySigner.privateKeyPkcs8B64u,
        issued_at: VERIFIED_AT,
      },
    };

    const out = await runComplianceFixture(fixture, 'out-compiled-mismatch.json');

    expect(out.runtime.state).toBe('COMPILED_FAIL');
    expect(out.runtime.global_reason_code).toBe('COMPILER_SIGNER_DID_MISMATCH');
    expect(out.compiled_report).toBeDefined();
    expect(out.compiled_report_envelope).toBeUndefined();
    expect(out.failure?.reason_code).toBe('COMPILER_SIGNER_DID_MISMATCH');
  });

  it('rejects malformed compiled report refs instead of emitting unverifiable compiled reports', async () => {
    const fixture = {
      envelope: {
        payload: {
          agent_did: 'did:key:agent-wave1',
          event_chain: [{ event_id: 'evt-compiled-bad-refs' }],
          receipts: [{ payload: { receipt_id: 'gw-compiled-bad-refs', model: 'model-approved' } }],
          tool_receipts: [{ receipt_id: 'tool-compiled-bad-refs', tool_name: 'edit' }],
          side_effect_receipts: [{ receipt_id: 'se-compiled-bad-refs', effect_class: 'network_egress' }],
          human_approval_receipts: [{ receipt_id: 'ha-compiled-bad-refs', approval_type: 'explicit_approve' }],
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
      compiled_report_refs: {
        ontology_hash_b64u: 'not base64url!!!',
      },
    };

    const out = await runComplianceFixture(fixture, 'out-compiled-bad-refs.json');

    expect(out.runtime.state).toBe('INPUT_REJECTED');
    expect(out.runtime.global_reason_code).toBe(
      'COMPILER_INPUT_MALFORMED_COMPILED_REPORT_REFS',
    );
    expect(out.compiled_report).toBeUndefined();
    expect(out.compiled_report_envelope).toBeUndefined();
    expect(out.failure?.reason_code).toBe(
      'COMPILER_INPUT_MALFORMED_COMPILED_REPORT_REFS',
    );
  });

  it('verifies compiled report envelopes and emits deterministic FAIL reason codes', async () => {
    const seed = new Uint8Array(32);
    for (let i = 0; i < seed.length; i++) seed[i] = 0xaa - i;
    const signer = await makeDidSignerFromSeed(seed);

    const fixture = {
      envelope: {
        payload: {
          agent_did: signer.did,
          event_chain: [{ event_id: 'evt-compiled-2' }],
          receipts: [{ payload: { receipt_id: 'gw-compiled-2', model: 'model-approved' } }],
          tool_receipts: [{ receipt_id: 'tool-compiled-2', tool_name: 'edit' }],
          side_effect_receipts: [{ receipt_id: 'se-compiled-2', effect_class: 'network_egress' }],
          human_approval_receipts: [{ receipt_id: 'ha-compiled-2', approval_type: 'explicit_approve' }],
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
        agent_did: signer.did,
      },
      compiled_report_signer: {
        signer_did: signer.did,
        private_key_pkcs8_b64u: signer.privateKeyPkcs8B64u,
        issued_at: VERIFIED_AT,
      },
    };

    const out = await runComplianceFixture(fixture, 'out-compiled-verify.json');
    const envelope = out.compiled_report_envelope;
    expect(envelope).toBeDefined();

    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'clawverify-compiled-verify-'));
    const validPath = path.join(tmpDir, 'compiled-envelope-valid.json');
    await fs.writeFile(validPath, JSON.stringify({ envelope }, null, 2), 'utf8');

    const valid = await verifyCompiledReportFromFile({ inputPath: validPath });
    expect(valid.status).toBe('PASS');
    expect(valid.reason_code).toBe('OK');

    const signatureTampered = {
      ...(envelope as Record<string, unknown>),
      signature_b64u: mutateBase64Url(String((envelope as Record<string, unknown>).signature_b64u)),
    };
    const signaturePath = path.join(tmpDir, 'compiled-envelope-signature-tampered.json');
    await fs.writeFile(signaturePath, JSON.stringify({ envelope: signatureTampered }, null, 2), 'utf8');
    const signatureOut = await verifyCompiledReportFromFile({ inputPath: signaturePath });
    expect(signatureOut.status).toBe('FAIL');
    expect(signatureOut.reason_code).toBe('SIGNATURE_INVALID');

    const matrixTamperedEnvelope = JSON.parse(
      JSON.stringify(envelope),
    ) as Record<string, unknown>;
    const matrixPayload = matrixTamperedEnvelope.payload as Record<string, unknown>;
    matrixPayload.matrix_hash_b64u = mutateBase64Url(String(matrixPayload.matrix_hash_b64u));
    const matrixPath = path.join(tmpDir, 'compiled-envelope-matrix-tampered.json');
    await fs.writeFile(matrixPath, JSON.stringify({ envelope: matrixTamperedEnvelope }, null, 2), 'utf8');
    const matrixOut = await verifyCompiledReportFromFile({ inputPath: matrixPath });
    expect(matrixOut.status).toBe('FAIL');
    expect(matrixOut.reason_code).toBe('HASH_MISMATCH');

    const missingRefsEnvelope = JSON.parse(
      JSON.stringify(envelope),
    ) as Record<string, unknown>;
    const missingRefsPayload = missingRefsEnvelope.payload as Record<string, unknown>;
    delete missingRefsPayload.evidence_refs;
    const missingRefsPath = path.join(tmpDir, 'compiled-envelope-missing-refs.json');
    await fs.writeFile(missingRefsPath, JSON.stringify({ envelope: missingRefsEnvelope }, null, 2), 'utf8');
    const missingRefsOut = await verifyCompiledReportFromFile({ inputPath: missingRefsPath });
    expect(missingRefsOut.status).toBe('FAIL');
    expect(missingRefsOut.reason_code).toBe('MISSING_REQUIRED_FIELD');

    const schemaViolationEnvelope = JSON.parse(
      JSON.stringify(envelope),
    ) as Record<string, unknown>;
    const schemaViolationPayload = schemaViolationEnvelope.payload as Record<string, unknown>;
    schemaViolationPayload.overall_status = 'BROKEN_STATUS';
    const schemaViolationPath = path.join(tmpDir, 'compiled-envelope-schema-violation.json');
    await fs.writeFile(schemaViolationPath, JSON.stringify({ envelope: schemaViolationEnvelope }, null, 2), 'utf8');
    const schemaOut = await verifyCompiledReportFromFile({ inputPath: schemaViolationPath });
    expect(schemaOut.status).toBe('FAIL');
    expect(schemaOut.reason_code).toBe('SCHEMA_VALIDATION_FAILED');
  });
});
