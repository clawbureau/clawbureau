import * as fs from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';

import { describe, expect, it } from 'vitest';

import { jcsCanonicalize } from '@clawbureau/clawverify-core';
import { runComplianceReport } from '../src/compliance-cmd.js';
import { verifyCompiledReportFromFile } from '../src/verify.js';

interface CompiledReportNarrativeOutput {
  narrative_version: string;
  report_id: string;
  generated_at: string;
  authoritative: boolean;
  disclaimer: string;
  authoritative_matrix_hash_b64u: string;
  authoritative_report_hash_b64u: string;
  text: string;
  generator_provider?: string;
  generator_model?: string;
}

interface CompiledReportOutput {
  report_id: string;
  compiler_version: string;
  overall_status: string;
  matrix_hash_b64u: string;
  evidence_refs: Record<string, string>;
  control_results: Array<{
    control_id: string;
    status: string;
    reason_codes: string[];
    evidence_hashes_b64u: string[];
    waiver_applied: boolean;
  }>;
  narrative?: CompiledReportNarrativeOutput;
}

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
  compiled_report?: CompiledReportOutput;
  compiled_report_envelope?: {
    envelope_type: string;
    payload_hash_b64u: string;
    signature_b64u: string;
    signer_did: string;
    issued_at: string;
    payload: CompiledReportOutput;
  };
  failure?: {
    reason_code: string;
    upstream_reason_code?: string;
  };
}

const VERIFIED_AT = '2026-01-01T00:00:00.000Z';
const COMPILED_EVIDENCE_NARRATIVE_DISCLAIMER =
  'NON_NORMATIVE: This narrative is explanatory only and is not authoritative compliance evidence. Authoritative determinations are in compiled_evidence_report.control_results.';
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

async function sha256B64uFromCanonical(value: unknown): Promise<string> {
  const canonical = jcsCanonicalize(value);
  const bytes = new TextEncoder().encode(canonical);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Buffer.from(new Uint8Array(digest)).toString('base64url');
}

async function importPkcs8PrivateKey(pkcs8B64u: string): Promise<CryptoKey> {
  const bytes = Buffer.from(pkcs8B64u, 'base64url');
  return crypto.subtle.importKey('pkcs8', bytes, { name: 'Ed25519' }, false, ['sign']);
}

function authoritativeReportView(
  report: CompiledReportOutput,
): Omit<CompiledReportOutput, 'narrative'> {
  const { narrative: _ignoredNarrative, ...authoritative } = report;
  return authoritative;
}

async function authoritativeReportHashB64u(
  report: CompiledReportOutput,
): Promise<string> {
  return sha256B64uFromCanonical(authoritativeReportView(report));
}

async function resignCompiledEnvelope(
  envelope: {
    payload: CompiledReportOutput;
    payload_hash_b64u: string;
    signature_b64u: string;
  },
  signerPrivateKeyPkcs8B64u: string,
): Promise<void> {
  const payloadHashB64u = await sha256B64uFromCanonical(envelope.payload);
  const signerKey = await importPkcs8PrivateKey(signerPrivateKeyPkcs8B64u);
  const signature = await crypto.subtle.sign(
    'Ed25519',
    signerKey,
    new TextEncoder().encode(payloadHashB64u),
  );

  envelope.payload_hash_b64u = payloadHashB64u;
  envelope.signature_b64u = Buffer.from(new Uint8Array(signature)).toString('base64url');
}

async function makeSignedWaiver(args: {
  signerDid: string;
  signerPrivateKeyPkcs8B64u: string;
  framework: string;
  controlId: string;
  bundleHashB64u: string;
  agentDid: string;
  waiverKind: 'COMPENSATING_CONTROL' | 'HUMAN_EXCEPTION';
  waiverId: string;
  issuedAt: string;
  expiresAt: string;
}) {
  const waiverPayload = {
    waiver_version: '1',
    waiver_id: args.waiverId,
    framework: args.framework,
    control_id: args.controlId,
    bundle_hash_b64u: args.bundleHashB64u,
    agent_did: args.agentDid,
    waiver_kind: args.waiverKind,
    issued_at: args.issuedAt,
    expires_at: args.expiresAt,
  };

  const payloadHashB64u = await sha256B64uFromCanonical(waiverPayload);
  const signerKey = await importPkcs8PrivateKey(args.signerPrivateKeyPkcs8B64u);
  const signature = await crypto.subtle.sign(
    'Ed25519',
    signerKey,
    new TextEncoder().encode(payloadHashB64u),
  );

  return {
    ...waiverPayload,
    payload_hash_b64u: payloadHashB64u,
    hash_algorithm: 'SHA-256',
    signature_b64u: Buffer.from(new Uint8Array(signature)).toString('base64url'),
    algorithm: 'Ed25519',
    signer_did: args.signerDid,
  };
}

async function runComplianceFixture(
  fixture: unknown,
  outputName: string,
  framework: string = 'soc2',
): Promise<CompilerOutput> {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'clawverify-compliance-wave1-'));
  const inputPath = path.join(tmpDir, 'input.json');
  const outputPath = path.join(tmpDir, outputName);

  await fs.writeFile(inputPath, JSON.stringify(fixture, null, 2), 'utf8');
  await runComplianceReport(inputPath, framework, outputPath);

  const outputRaw = await fs.readFile(outputPath, 'utf8');
  return JSON.parse(outputRaw) as CompilerOutput;
}

function buildAiExecutionFixture(agentDid: string) {
  const effectivePolicyHashB64u = 'policy_hash_axa_001';

  return {
    envelope: {
      payload: {
        agent_did: agentDid,
        event_chain: [{ event_id: 'evt-axa-1' }],
        side_effect_receipts: [
          { receipt_id: 'se-axa-1', effect_class: 'network_egress' },
        ],
        human_approval_receipts: [
          { receipt_id: 'har-axa-1', approval_type: 'explicit_approve' },
        ],
        coverage_attestations: [{ payload: { attestation_id: 'cov-axa-1' } }],
        metadata: {
          policy_binding: {
            effective_policy_hash_b64u: effectivePolicyHashB64u,
          },
          sentinels: {
            egress_policy_receipt: {
              payload: {
                receipt_id: 'epr-axa-1',
                proofed_mode: true,
                direct_provider_access_blocked: true,
              },
            },
          },
          data_handling: {
            receipts: [
              {
                payload: {
                  receipt_id: 'dhr-axa-1',
                  enforcement: { mode: 'enforced' },
                },
              },
            ],
          },
          reviewer_signoff_receipts: [
            {
              payload: {
                receipt_id: 'rsr-axa-1',
                decision: 'needs_changes',
              },
            },
          ],
        },
      },
    },
    policy: {
      policy_hash_b64u: effectivePolicyHashB64u,
    },
    verification_fact: {
      status: 'VALID',
      reason_code: 'OK',
      reason: 'Proof bundle verified successfully',
      verified_at: VERIFIED_AT,
      verifier: 'clawverify-cli-test',
      agent_did: agentDid,
    },
  };
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

  it('emits optional non-authoritative narrative plane with stable authoritative bindings when enabled', async () => {
    const seed = new Uint8Array(32);
    for (let i = 0; i < seed.length; i++) seed[i] = i + 9;
    const signer = await makeDidSignerFromSeed(seed);

    const fixture = {
      envelope: {
        payload: {
          agent_did: signer.did,
          event_chain: [{ event_id: 'evt-narrative-enabled-1' }],
          receipts: [{ payload: { receipt_id: 'gw-narrative-enabled-1', model: 'model-approved' } }],
          tool_receipts: [{ receipt_id: 'tool-narrative-enabled-1', tool_name: 'edit' }],
          side_effect_receipts: [{ receipt_id: 'se-narrative-enabled-1', effect_class: 'network_egress' }],
          human_approval_receipts: [{ receipt_id: 'ha-narrative-enabled-1', approval_type: 'explicit_approve' }],
        },
      },
      policy: {
        policy_hash_b64u: 'policy-hash',
        allowed_models: ['model-approved'],
      },
      narrative_runtime: {
        enabled: true,
        generator_provider: 'clawcompiler-runtime',
        generator_model: 'narrative-v1-deterministic',
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

    const out = await runComplianceFixture(fixture, 'out-narrative-enabled.json');
    const compiledReport = out.compiled_report;

    expect(compiledReport).toBeDefined();
    expect(compiledReport?.narrative).toBeDefined();
    expect(compiledReport?.narrative?.authoritative).toBe(false);
    expect(compiledReport?.narrative?.disclaimer).toBe(
      COMPILED_EVIDENCE_NARRATIVE_DISCLAIMER,
    );
    expect(compiledReport?.narrative?.report_id).toBe(compiledReport?.report_id);
    expect(compiledReport?.narrative?.authoritative_matrix_hash_b64u).toBe(
      compiledReport?.matrix_hash_b64u,
    );

    const authoritativeHash = await authoritativeReportHashB64u(
      compiledReport as CompiledReportOutput,
    );
    expect(compiledReport?.narrative?.authoritative_report_hash_b64u).toBe(
      authoritativeHash,
    );

    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'clawverify-narrative-happy-'));
    const envelopePath = path.join(tmpDir, 'compiled-envelope-narrative-enabled.json');
    await fs.writeFile(
      envelopePath,
      JSON.stringify({ envelope: out.compiled_report_envelope }, null, 2),
      'utf8',
    );

    const verified = await verifyCompiledReportFromFile({ inputPath: envelopePath });
    expect(verified.status).toBe('PASS');
    expect(verified.reason_code).toBe('OK');
  });

  it('respects policy/config gates that disable narrative generation', async () => {
    const seed = new Uint8Array(32);
    for (let i = 0; i < seed.length; i++) seed[i] = i + 13;
    const signer = await makeDidSignerFromSeed(seed);

    const fixture = {
      envelope: {
        payload: {
          agent_did: signer.did,
          event_chain: [{ event_id: 'evt-narrative-disabled-1' }],
          receipts: [{ payload: { receipt_id: 'gw-narrative-disabled-1', model: 'model-approved' } }],
          tool_receipts: [{ receipt_id: 'tool-narrative-disabled-1', tool_name: 'edit' }],
          side_effect_receipts: [{ receipt_id: 'se-narrative-disabled-1', effect_class: 'network_egress' }],
          human_approval_receipts: [{ receipt_id: 'ha-narrative-disabled-1', approval_type: 'explicit_approve' }],
        },
      },
      policy: {
        policy_hash_b64u: 'policy-hash',
        allowed_models: ['model-approved'],
        disable_narrative_generation: true,
      },
      narrative_runtime: {
        enabled: true,
        generator_provider: 'clawcompiler-runtime',
        generator_model: 'narrative-v1-deterministic',
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

    const out = await runComplianceFixture(fixture, 'out-narrative-disabled.json');

    expect(out.runtime.state).toBe('COMPILED_PASS');
    expect(out.compiled_report?.narrative).toBeUndefined();
  });

  it('fails closed on narrative disclaimer/authoritative/binding mismatches', async () => {
    const seed = new Uint8Array(32);
    for (let i = 0; i < seed.length; i++) seed[i] = i + 17;
    const signer = await makeDidSignerFromSeed(seed);

    const fixture = {
      envelope: {
        payload: {
          agent_did: signer.did,
          event_chain: [{ event_id: 'evt-narrative-mismatch-1' }],
          receipts: [{ payload: { receipt_id: 'gw-narrative-mismatch-1', model: 'model-approved' } }],
          tool_receipts: [{ receipt_id: 'tool-narrative-mismatch-1', tool_name: 'edit' }],
          side_effect_receipts: [{ receipt_id: 'se-narrative-mismatch-1', effect_class: 'network_egress' }],
          human_approval_receipts: [{ receipt_id: 'ha-narrative-mismatch-1', approval_type: 'explicit_approve' }],
        },
      },
      policy: {
        policy_hash_b64u: 'policy-hash',
        allowed_models: ['model-approved'],
      },
      narrative_runtime: {
        enabled: true,
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

    const out = await runComplianceFixture(fixture, 'out-narrative-mismatch-base.json');
    expect(out.compiled_report_envelope).toBeDefined();

    const baseEnvelope = JSON.parse(
      JSON.stringify(out.compiled_report_envelope),
    ) as NonNullable<CompilerOutput['compiled_report_envelope']>;

    const variants: Array<{
      name: string;
      mutate: (payload: CompiledReportOutput) => void;
      expectedReasonCode: string;
    }> = [
      {
        name: 'authoritative-flag',
        mutate: (payload) => {
          if (!payload.narrative) throw new Error('expected narrative');
          payload.narrative.authoritative = true;
        },
        expectedReasonCode: 'SCHEMA_VALIDATION_FAILED',
      },
      {
        name: 'disclaimer',
        mutate: (payload) => {
          if (!payload.narrative) throw new Error('expected narrative');
          payload.narrative.disclaimer = 'Narrative is authoritative now.';
        },
        expectedReasonCode: 'SCHEMA_VALIDATION_FAILED',
      },
      {
        name: 'binding-hash',
        mutate: (payload) => {
          if (!payload.narrative) throw new Error('expected narrative');
          payload.narrative.authoritative_report_hash_b64u = mutateBase64Url(
            payload.narrative.authoritative_report_hash_b64u,
          );
        },
        expectedReasonCode: 'HASH_MISMATCH',
      },
    ];

    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'clawverify-narrative-mismatch-'));

    for (const variant of variants) {
      const envelope = JSON.parse(
        JSON.stringify(baseEnvelope),
      ) as NonNullable<CompilerOutput['compiled_report_envelope']>;
      variant.mutate(envelope.payload);
      await resignCompiledEnvelope(envelope, signer.privateKeyPkcs8B64u);

      const envelopePath = path.join(tmpDir, `compiled-envelope-${variant.name}.json`);
      await fs.writeFile(envelopePath, JSON.stringify({ envelope }, null, 2), 'utf8');

      const verification = await verifyCompiledReportFromFile({ inputPath: envelopePath });
      expect(verification.status).toBe('FAIL');
      expect(verification.reason_code).toBe(variant.expectedReasonCode);
    }
  });

  it('keeps authoritative outcomes unchanged even when narrative text conflicts', async () => {
    const seed = new Uint8Array(32);
    for (let i = 0; i < seed.length; i++) seed[i] = i + 19;
    const signer = await makeDidSignerFromSeed(seed);

    const fixture = {
      envelope: {
        payload: {
          agent_did: signer.did,
          receipts: [{ payload: { receipt_id: 'gw-narrative-conflict-1', model: 'model-approved' } }],
          side_effect_receipts: [{ receipt_id: 'se-narrative-conflict-1', effect_class: 'network_egress' }],
        },
      },
      policy: {
        policy_hash_b64u: 'policy-hash',
        allowed_models: ['model-approved'],
      },
      narrative_runtime: {
        enabled: true,
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

    const out = await runComplianceFixture(fixture, 'out-narrative-conflict.json');
    expect(out.runtime.state).toBe('COMPILED_FAIL');
    expect(out.compiled_report?.overall_status).toBe('FAIL_CLOSED_INVALID_EVIDENCE');
    expect(
      out.compiled_report?.control_results.some(
        (control) => control.status === 'FAIL_CLOSED_INVALID_EVIDENCE',
      ),
    ).toBe(true);

    const envelope = JSON.parse(
      JSON.stringify(out.compiled_report_envelope),
    ) as NonNullable<CompilerOutput['compiled_report_envelope']>;

    if (!envelope.payload.narrative) {
      throw new Error('expected narrative payload for conflict test');
    }

    envelope.payload.narrative.text =
      'Narrative claim: everything passed. This claim is non-authoritative.';
    await resignCompiledEnvelope(envelope, signer.privateKeyPkcs8B64u);

    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'clawverify-narrative-conflict-'));
    const envelopePath = path.join(tmpDir, 'compiled-envelope-narrative-conflict.json');
    await fs.writeFile(envelopePath, JSON.stringify({ envelope }, null, 2), 'utf8');

    const verification = await verifyCompiledReportFromFile({ inputPath: envelopePath });
    expect(verification.status).toBe('PASS');
    expect(envelope.payload.overall_status).toBe('FAIL_CLOSED_INVALID_EVIDENCE');
    expect(
      envelope.payload.control_results.some(
        (control) => control.status === 'FAIL_CLOSED_INVALID_EVIDENCE',
      ),
    ).toBe(true);
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

    const overallMismatchEnvelope = JSON.parse(
      JSON.stringify(envelope),
    ) as Record<string, unknown>;
    const overallMismatchPayload = overallMismatchEnvelope.payload as Record<string, unknown>;
    overallMismatchPayload.overall_status = 'FAIL';
    const overallMismatchPath = path.join(tmpDir, 'compiled-envelope-overall-mismatch.json');
    await fs.writeFile(overallMismatchPath, JSON.stringify({ envelope: overallMismatchEnvelope }, null, 2), 'utf8');
    const overallMismatchOut = await verifyCompiledReportFromFile({ inputPath: overallMismatchPath });
    expect(overallMismatchOut.status).toBe('FAIL');
    expect(overallMismatchOut.reason_code).toBe('SCHEMA_VALIDATION_FAILED');

    const partialWithoutWaiverEnvelope = JSON.parse(
      JSON.stringify(envelope),
    ) as Record<string, unknown>;
    const partialWithoutWaiverPayload = partialWithoutWaiverEnvelope.payload as Record<string, unknown>;
    partialWithoutWaiverPayload.compiler_version = 'clawcompiler-runtime-v1-wave3';
    partialWithoutWaiverPayload.overall_status = 'PARTIAL';
    const partialWithoutWaiverControl = (partialWithoutWaiverPayload.control_results as Array<Record<string, unknown>>)[0]!;
    partialWithoutWaiverControl.status = 'PARTIAL';
    partialWithoutWaiverControl.waiver_applied = false;
    partialWithoutWaiverControl.reason_codes = ['CONTROL_PREDICATE_FAILED'];
    const partialWithoutWaiverPath = path.join(tmpDir, 'compiled-envelope-partial-without-waiver.json');
    await fs.writeFile(partialWithoutWaiverPath, JSON.stringify({ envelope: partialWithoutWaiverEnvelope }, null, 2), 'utf8');
    const partialWithoutWaiverOut = await verifyCompiledReportFromFile({ inputPath: partialWithoutWaiverPath });
    expect(partialWithoutWaiverOut.status).toBe('FAIL');
    expect(partialWithoutWaiverOut.reason_code).toBe('SCHEMA_VALIDATION_FAILED');
  });

  it('produces deterministic AI execution assurance pack outcomes from verifier-backed evidence', async () => {
    const fixture = buildAiExecutionFixture('did:key:agent-axa-deterministic');

    const out1 = await runComplianceFixture(
      fixture,
      'out-axa-deterministic-1.json',
      'ai-execution-v1',
    );
    const out2 = await runComplianceFixture(
      fixture,
      'out-axa-deterministic-2.json',
      'ai-execution-v1',
    );

    expect(out1).toEqual(out2);
    expect(out1.runtime.state).toBe('COMPILED_PASS');
    expect(out1.compiled_report?.compiler_version).toBe('clawcompiler-runtime-v1-wave3');
    expect(out1.compiled_report?.overall_status).toBe('PASS');

    const nonPassControl = out1.compiled_report?.control_results.find(
      (control) => control.status !== 'PASS',
    );
    expect(nonPassControl).toBeUndefined();
  });

  it('does not overclaim AI execution assurance controls when upstream evidence is missing', async () => {
    const fixture = {
      envelope: {
        payload: {
          agent_did: 'did:key:agent-axa-no-overclaim',
          event_chain: [{ event_id: 'evt-axa-overclaim-1' }],
        },
      },
      policy: {
        policy_hash_b64u: 'policy_hash_axa_no_overclaim_001',
      },
      verification_fact: {
        status: 'VALID',
        reason_code: 'OK',
        reason: 'Proof bundle verified successfully',
        verified_at: VERIFIED_AT,
        verifier: 'clawverify-cli-test',
        agent_did: 'did:key:agent-axa-no-overclaim',
      },
    };

    const out = await runComplianceFixture(
      fixture,
      'out-axa-no-overclaim.json',
      'ai-execution-v1',
    );

    expect(out.runtime.state).toBe('COMPILED_FAIL');

    const controlById = new Map(
      (out.report?.controls ?? []).map((control) => [control.control_id, control]),
    );

    expect(controlById.get('AXA.POLICY.1')?.status).toBe('FAIL');
    expect(controlById.get('AXA.APPROVAL.1')?.status).toBe('FAIL');
    expect(controlById.get('AXA.EGRESS.1')?.status).toBe('FAIL');
    expect(controlById.get('AXA.DLP.1')?.status).toBe('FAIL');
    expect(controlById.get('AXA.ATTESTATION.1')?.status).toBe('FAIL');
    expect(controlById.get('AXA.REVIEW.1')?.status).toBe('FAIL');
  });

  it('fails closed when compiler input policy hash disagrees with verified bundle policy binding', async () => {
    const fixture = buildAiExecutionFixture('did:key:agent-axa-policy-mismatch');
    fixture.policy.policy_hash_b64u = 'policy_hash_axa_mismatch_001';

    const out = await runComplianceFixture(
      fixture,
      'out-axa-policy-mismatch.json',
      'ai-execution-v1',
    );

    expect(out.runtime.state).toBe('COMPILED_FAIL');
    expect(out.runtime.global_reason_code).toBe('AXA_POLICY_FAIL_POLICY_HASH_MISMATCH');

    const policyControl = out.report?.controls.find(
      (control) => control.control_id === 'AXA.POLICY.1',
    );
    expect(policyControl?.status).toBe('FAIL');
    expect(policyControl?.reason_code).toBe('AXA_POLICY_FAIL_POLICY_HASH_MISMATCH');
  });

  it('applies signed waivers only as FAIL -> PARTIAL degradations', async () => {
    const waiverSignerSeed = new Uint8Array(32);
    for (let i = 0; i < waiverSignerSeed.length; i++) waiverSignerSeed[i] = i + 101;
    const waiverSigner = await makeDidSignerFromSeed(waiverSignerSeed);

    const fixture = buildAiExecutionFixture('did:key:agent-axa-waiver');
    fixture.envelope.payload.metadata.reviewer_signoff_receipts = [];

    const bundleHashB64u = await sha256B64uFromCanonical(fixture.envelope.payload);
    const waiver = await makeSignedWaiver({
      signerDid: waiverSigner.did,
      signerPrivateKeyPkcs8B64u: waiverSigner.privateKeyPkcs8B64u,
      framework: 'CLAW_AI_EXECUTION_ASSURANCE_V1',
      controlId: 'AXA.REVIEW.1',
      bundleHashB64u,
      agentDid: fixture.envelope.payload.agent_did,
      waiverKind: 'HUMAN_EXCEPTION',
      waiverId: 'waiver-axa-review-001',
      issuedAt: '2025-12-01T00:00:00.000Z',
      expiresAt: '2026-12-01T00:00:00.000Z',
    });

    const waivedFixture = {
      ...fixture,
      waivers: [waiver],
    };

    const out = await runComplianceFixture(
      waivedFixture,
      'out-axa-waiver-valid.json',
      'ai-execution-v1',
    );

    const waivedControl = out.compiled_report?.control_results.find(
      (control) => control.control_id === 'AXA.REVIEW.1',
    );

    expect(waivedControl?.status).toBe('PARTIAL');
    expect(waivedControl?.waiver_applied).toBe(true);
    expect(waivedControl?.reason_codes).toContain('WAIVER_APPLIED_SIGNED');
    expect(waivedControl?.reason_codes).toContain('RESIDUAL_HUMAN_EXCEPTION_APPLIED');
    expect(out.compiled_report?.overall_status).toBe('PARTIAL');
  });

  it('fails closed on invalid, mismatched, and expired signed waivers', async () => {
    const waiverSignerSeed = new Uint8Array(32);
    for (let i = 0; i < waiverSignerSeed.length; i++) waiverSignerSeed[i] = i + 131;
    const waiverSigner = await makeDidSignerFromSeed(waiverSignerSeed);

    const fixture = buildAiExecutionFixture('did:key:agent-axa-waiver-invalid');
    fixture.envelope.payload.metadata.reviewer_signoff_receipts = [];

    const bundleHashB64u = await sha256B64uFromCanonical(fixture.envelope.payload);

    const validWaiver = await makeSignedWaiver({
      signerDid: waiverSigner.did,
      signerPrivateKeyPkcs8B64u: waiverSigner.privateKeyPkcs8B64u,
      framework: 'CLAW_AI_EXECUTION_ASSURANCE_V1',
      controlId: 'AXA.REVIEW.1',
      bundleHashB64u,
      agentDid: fixture.envelope.payload.agent_did,
      waiverKind: 'COMPENSATING_CONTROL',
      waiverId: 'waiver-axa-invalid-base',
      issuedAt: '2025-12-01T00:00:00.000Z',
      expiresAt: '2026-12-01T00:00:00.000Z',
    });

    const passTargetWaiver = await makeSignedWaiver({
      signerDid: waiverSigner.did,
      signerPrivateKeyPkcs8B64u: waiverSigner.privateKeyPkcs8B64u,
      framework: 'CLAW_AI_EXECUTION_ASSURANCE_V1',
      controlId: 'AXA.POLICY.1',
      bundleHashB64u,
      agentDid: fixture.envelope.payload.agent_did,
      waiverKind: 'COMPENSATING_CONTROL',
      waiverId: 'waiver-axa-invalid-pass-target',
      issuedAt: '2025-12-01T00:00:00.000Z',
      expiresAt: '2026-12-01T00:00:00.000Z',
    });

    const passTargetOut = await runComplianceFixture(
      {
        ...fixture,
        waivers: [passTargetWaiver],
      },
      'out-axa-waiver-invalid-pass-target.json',
      'ai-execution-v1',
    );

    expect(passTargetOut.runtime.state).toBe('COMPILED_FAIL');
    expect(passTargetOut.runtime.global_reason_code).toBe('WAIVER_TARGET_NOT_FAIL');

    const signatureInvalid = {
      ...validWaiver,
      signature_b64u: mutateBase64Url(validWaiver.signature_b64u),
    };

    const signatureOut = await runComplianceFixture(
      {
        ...fixture,
        waivers: [signatureInvalid],
      },
      'out-axa-waiver-invalid-signature.json',
      'ai-execution-v1',
    );

    expect(signatureOut.runtime.state).toBe('COMPILED_FAIL');
    expect(signatureOut.runtime.global_reason_code).toBe('WAIVER_SIGNATURE_INVALID');

    const bundleMismatchWaiver = {
      ...validWaiver,
      waiver_id: 'waiver-axa-invalid-bundle',
      bundle_hash_b64u: mutateBase64Url(validWaiver.bundle_hash_b64u),
    };

    const bundleMismatchOut = await runComplianceFixture(
      {
        ...fixture,
        waivers: [bundleMismatchWaiver],
      },
      'out-axa-waiver-invalid-bundle.json',
      'ai-execution-v1',
    );

    expect(bundleMismatchOut.runtime.state).toBe('COMPILED_FAIL');
    expect(bundleMismatchOut.runtime.global_reason_code).toBe('WAIVER_BUNDLE_HASH_MISMATCH');

    const expiredWaiver = await makeSignedWaiver({
      signerDid: waiverSigner.did,
      signerPrivateKeyPkcs8B64u: waiverSigner.privateKeyPkcs8B64u,
      framework: 'CLAW_AI_EXECUTION_ASSURANCE_V1',
      controlId: 'AXA.REVIEW.1',
      bundleHashB64u,
      agentDid: fixture.envelope.payload.agent_did,
      waiverKind: 'COMPENSATING_CONTROL',
      waiverId: 'waiver-axa-invalid-expired',
      issuedAt: '2025-01-01T00:00:00.000Z',
      expiresAt: '2025-06-01T00:00:00.000Z',
    });

    const expiredOut = await runComplianceFixture(
      {
        ...fixture,
        waivers: [expiredWaiver],
      },
      'out-axa-waiver-invalid-expired.json',
      'ai-execution-v1',
    );

    expect(expiredOut.runtime.state).toBe('COMPILED_FAIL');
    expect(expiredOut.runtime.global_reason_code).toBe('WAIVER_EXPIRED');
  });
});
