import { describe, expect, it } from 'vitest';

import {
  compileAndSignCompiledEvidenceReport,
  verifyCompiledEvidenceReport,
} from '../src/verify-compiled-report';
import { jcsCanonicalize } from '../src/jcs';

const BASE58_ALPHABET =
  '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const COMPILED_EVIDENCE_NARRATIVE_DISCLAIMER =
  'NON_NORMATIVE: This narrative is explanatory only and is not authoritative compliance evidence. Authoritative determinations are in compiled_evidence_report.control_results.';

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
    .map((d) => BASE58_ALPHABET[d]!)
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

  const exportedPkcs8 = (await crypto.subtle.exportKey('pkcs8', privateKey)) as ArrayBuffer;
  const privateKeyPkcs8B64u = Buffer.from(new Uint8Array(exportedPkcs8)).toString('base64url');

  const jwk = (await crypto.subtle.exportKey('jwk', privateKey)) as JsonWebKey;
  const publicKeyBytes = Buffer.from(String(jwk.x), 'base64url');

  const prefixed = new Uint8Array(2 + publicKeyBytes.length);
  prefixed[0] = 0xed;
  prefixed[1] = 0x01;
  prefixed.set(publicKeyBytes, 2);

  return {
    did: `did:key:z${base58Encode(prefixed)}`,
    privateKeyPkcs8B64u,
  };
}

function mutateBase64Url(input: string): string {
  if (input.length === 0) return 'A';
  const head = input[0] === 'A' ? 'B' : 'A';
  return `${head}${input.slice(1)}`;
}

async function sha256B64uFromCanonical(value: unknown): Promise<string> {
  const canonical = jcsCanonicalize(value);
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(canonical),
  );
  return Buffer.from(new Uint8Array(digest)).toString('base64url');
}

async function importPkcs8PrivateKey(pkcs8B64u: string): Promise<CryptoKey> {
  const bytes = Buffer.from(pkcs8B64u, 'base64url');
  return crypto.subtle.importKey('pkcs8', bytes, { name: 'Ed25519' }, false, ['sign']);
}

async function resignEnvelopeWithPayload(
  envelope: Record<string, unknown>,
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

function authoritativeReportView(payload: Record<string, unknown>): Record<string, unknown> {
  const clone = JSON.parse(JSON.stringify(payload)) as Record<string, unknown>;
  delete clone.narrative;
  return clone;
}

function buildPayload() {
  return {
    report_version: '1',
    report_id: 'cer_wave2_compiled_report_test',
    compiled_at: '2026-01-01T00:00:00.000Z',
    compiler_version: 'clawcompiler-runtime-v1-wave2',
    evidence_refs: {
      proof_bundle_hash_b64u: 'cHJvb2ZfYnVuZGxlX2hhc2hfdGVzdA',
      ontology_hash_b64u: 'b250b2xvZ3lfaGFzaF90ZXN0',
      mapping_rules_hash_b64u: 'bWFwcGluZ19ydWxlc19oYXNoX3Rlc3Q',
      verify_result_hash_b64u: 'dmVyaWZ5X3Jlc3VsdF9oYXNoX3Rlc3Q',
    },
    overall_status: 'PASS',
    matrix_hash_b64u: 'placeholder_will_be_recomputed',
    control_results: [
      {
        control_id: 'CC6.1',
        status: 'PASS',
        reason_codes: ['CONTROL_PREDICATE_SATISFIED'],
        evidence_hashes_b64u: ['ZXZpZGVuY2VfaGFzaF90ZXN0'],
        waiver_applied: false,
      },
    ],
  };
}

describe('compiled evidence report compile/verify', () => {
  it('canonicalizes + signs payloads and verifies envelopes', async () => {
    const seed = new Uint8Array(32);
    for (let i = 0; i < seed.length; i++) seed[i] = i + 11;
    const signer = await makeDidSignerFromSeed(seed);

    const compiled = await compileAndSignCompiledEvidenceReport({
      payload: buildPayload(),
      signer: {
        signer_did: signer.did,
        private_key_pkcs8_b64u: signer.privateKeyPkcs8B64u,
        issued_at: '2026-01-01T00:00:00.000Z',
      },
    });

    expect(compiled.result.status).toBe('VALID');
    expect(compiled.envelope?.signer_did).toBe(signer.did);

    const verified = await verifyCompiledEvidenceReport(compiled.envelope);
    expect(verified.result.status).toBe('VALID');
    expect(verified.report_id).toBe('cer_wave2_compiled_report_test');
  });

  it('rejects signer keys that do not match signer DID during compile', async () => {
    const didSeed = new Uint8Array(32);
    const keySeed = new Uint8Array(32);
    for (let i = 0; i < didSeed.length; i++) {
      didSeed[i] = i + 71;
      keySeed[i] = 0xdd - i;
    }

    const didSigner = await makeDidSignerFromSeed(didSeed);
    const keySigner = await makeDidSignerFromSeed(keySeed);

    const compiled = await compileAndSignCompiledEvidenceReport({
      payload: buildPayload(),
      signer: {
        signer_did: didSigner.did,
        private_key_pkcs8_b64u: keySigner.privateKeyPkcs8B64u,
      },
    });

    expect(compiled.result.status).toBe('INVALID');
    expect(compiled.error?.code).toBe('SIGNATURE_INVALID');
    expect(compiled.envelope).toBeUndefined();
  });

  it('rejects waiver semantics in wave2 payloads', async () => {
    const seed = new Uint8Array(32);
    for (let i = 0; i < seed.length; i++) seed[i] = i + 81;
    const signer = await makeDidSignerFromSeed(seed);

    const payload = buildPayload();
    payload.control_results[0]!.waiver_applied = true;

    const compiled = await compileAndSignCompiledEvidenceReport({
      payload,
      signer: {
        signer_did: signer.did,
        private_key_pkcs8_b64u: signer.privateKeyPkcs8B64u,
      },
    });

    expect(compiled.result.status).toBe('INVALID');
    expect(compiled.error?.code).toBe('SCHEMA_VALIDATION_FAILED');
    expect(compiled.error?.field).toBe('payload.control_results[0].waiver_applied');
  });

  it('accepts wave3 PARTIAL + waiver semantics and verifies signed envelopes', async () => {
    const seed = new Uint8Array(32);
    for (let i = 0; i < seed.length; i++) seed[i] = i + 86;
    const signer = await makeDidSignerFromSeed(seed);

    const payload = buildPayload();
    payload.compiler_version = 'clawcompiler-runtime-v1-wave3';
    payload.overall_status = 'PARTIAL';
    payload.control_results[0] = {
      ...payload.control_results[0],
      status: 'PARTIAL',
      reason_codes: [
        'CONTROL_PREDICATE_FAILED',
        'WAIVER_APPLIED_SIGNED',
        'RESIDUAL_HUMAN_EXCEPTION_APPLIED',
      ],
      waiver_applied: true,
    };

    const compiled = await compileAndSignCompiledEvidenceReport({
      payload,
      signer: {
        signer_did: signer.did,
        private_key_pkcs8_b64u: signer.privateKeyPkcs8B64u,
      },
    });

    expect(compiled.result.status).toBe('VALID');
    expect(compiled.envelope?.payload.compiler_version).toBe('clawcompiler-runtime-v1-wave3');
    expect(compiled.envelope?.payload.overall_status).toBe('PARTIAL');
    expect(compiled.envelope?.payload.control_results[0]?.waiver_applied).toBe(true);

    const verified = await verifyCompiledEvidenceReport(compiled.envelope);
    expect(verified.result.status).toBe('VALID');
  });

  it('rejects wave3 PARTIAL controls that omit waiver markers or waiver_applied=true', async () => {
    const seed = new Uint8Array(32);
    for (let i = 0; i < seed.length; i++) seed[i] = i + 91;
    const signer = await makeDidSignerFromSeed(seed);

    const payload = buildPayload();
    payload.compiler_version = 'clawcompiler-runtime-v1-wave3';
    payload.overall_status = 'PARTIAL';
    payload.control_results[0] = {
      ...payload.control_results[0],
      status: 'PARTIAL',
      reason_codes: ['CONTROL_PREDICATE_FAILED'],
      waiver_applied: false,
    };

    const compiled = await compileAndSignCompiledEvidenceReport({
      payload,
      signer: {
        signer_did: signer.did,
        private_key_pkcs8_b64u: signer.privateKeyPkcs8B64u,
      },
    });

    expect(compiled.result.status).toBe('INVALID');
    expect(compiled.error?.code).toBe('SCHEMA_VALIDATION_FAILED');
    expect(compiled.error?.field).toBe('payload.control_results[0].waiver_applied');
  });

  it('rejects overall_status values that do not match the control matrix', async () => {
    const seed = new Uint8Array(32);
    for (let i = 0; i < seed.length; i++) seed[i] = i + 96;
    const signer = await makeDidSignerFromSeed(seed);

    const payload = buildPayload();
    payload.overall_status = 'FAIL';

    const compiled = await compileAndSignCompiledEvidenceReport({
      payload,
      signer: {
        signer_did: signer.did,
        private_key_pkcs8_b64u: signer.privateKeyPkcs8B64u,
      },
    });

    expect(compiled.result.status).toBe('INVALID');
    expect(compiled.error?.code).toBe('SCHEMA_VALIDATION_FAILED');
    expect(compiled.error?.field).toBe('payload.overall_status');
  });

  it('fails closed on narrative authoritative/disclaimer/binding mismatches', async () => {
    const seed = new Uint8Array(32);
    for (let i = 0; i < seed.length; i++) seed[i] = i + 18;
    const signer = await makeDidSignerFromSeed(seed);

    const compiledBase = await compileAndSignCompiledEvidenceReport({
      payload: buildPayload(),
      signer: {
        signer_did: signer.did,
        private_key_pkcs8_b64u: signer.privateKeyPkcs8B64u,
      },
    });

    expect(compiledBase.result.status).toBe('VALID');

    const canonicalPayload = JSON.parse(
      JSON.stringify(compiledBase.envelope!.payload),
    ) as Record<string, unknown>;

    const narrativeBase = {
      narrative_version: '1',
      report_id: String(canonicalPayload.report_id),
      generated_at: String(canonicalPayload.compiled_at),
      authoritative: false,
      disclaimer: COMPILED_EVIDENCE_NARRATIVE_DISCLAIMER,
      authoritative_matrix_hash_b64u: String(canonicalPayload.matrix_hash_b64u),
      authoritative_report_hash_b64u: await sha256B64uFromCanonical(
        authoritativeReportView(canonicalPayload),
      ),
      text: 'Deterministic non-authoritative narrative summary.',
    };

    const authoritativeMismatch = await compileAndSignCompiledEvidenceReport({
      payload: {
        ...canonicalPayload,
        narrative: {
          ...narrativeBase,
          authoritative: true,
        },
      },
      signer: {
        signer_did: signer.did,
        private_key_pkcs8_b64u: signer.privateKeyPkcs8B64u,
      },
    });

    expect(authoritativeMismatch.result.status).toBe('INVALID');
    expect(authoritativeMismatch.error?.code).toBe('SCHEMA_VALIDATION_FAILED');
    expect(authoritativeMismatch.error?.field).toBe('payload.narrative.authoritative');

    const disclaimerMismatch = await compileAndSignCompiledEvidenceReport({
      payload: {
        ...canonicalPayload,
        narrative: {
          ...narrativeBase,
          disclaimer: 'Narrative is authoritative now.',
        },
      },
      signer: {
        signer_did: signer.did,
        private_key_pkcs8_b64u: signer.privateKeyPkcs8B64u,
      },
    });

    expect(disclaimerMismatch.result.status).toBe('INVALID');
    expect(disclaimerMismatch.error?.code).toBe('SCHEMA_VALIDATION_FAILED');
    expect(disclaimerMismatch.error?.field).toBe('payload.narrative.disclaimer');

    const bindingMismatch = await compileAndSignCompiledEvidenceReport({
      payload: {
        ...canonicalPayload,
        narrative: {
          ...narrativeBase,
          authoritative_report_hash_b64u: mutateBase64Url(
            narrativeBase.authoritative_report_hash_b64u,
          ),
        },
      },
      signer: {
        signer_did: signer.did,
        private_key_pkcs8_b64u: signer.privateKeyPkcs8B64u,
      },
    });

    expect(bindingMismatch.result.status).toBe('INVALID');
    expect(bindingMismatch.error?.code).toBe('HASH_MISMATCH');
    expect(bindingMismatch.error?.field).toBe(
      'payload.narrative.authoritative_report_hash_b64u',
    );
  });

  it('treats narrative text as non-authoritative and preserves authoritative outcomes', async () => {
    const seed = new Uint8Array(32);
    for (let i = 0; i < seed.length; i++) seed[i] = i + 19;
    const signer = await makeDidSignerFromSeed(seed);

    const payload = buildPayload();
    payload.overall_status = 'FAIL';
    payload.control_results[0] = {
      ...payload.control_results[0],
      status: 'FAIL',
      reason_codes: ['CONTROL_PREDICATE_FAILED'],
    };

    const compiled = await compileAndSignCompiledEvidenceReport({
      payload,
      signer: {
        signer_did: signer.did,
        private_key_pkcs8_b64u: signer.privateKeyPkcs8B64u,
      },
    });

    expect(compiled.result.status).toBe('VALID');

    const envelope = JSON.parse(JSON.stringify(compiled.envelope)) as Record<string, unknown>;
    const envelopePayload = envelope.payload as Record<string, unknown>;

    const narrative = {
      narrative_version: '1',
      report_id: String(envelopePayload.report_id),
      generated_at: String(envelopePayload.compiled_at),
      authoritative: false,
      disclaimer: COMPILED_EVIDENCE_NARRATIVE_DISCLAIMER,
      authoritative_matrix_hash_b64u: String(envelopePayload.matrix_hash_b64u),
      authoritative_report_hash_b64u: await sha256B64uFromCanonical(
        authoritativeReportView(envelopePayload),
      ),
      text: 'Narrative claim: all controls passed. This claim is non-authoritative.',
    };

    envelopePayload.narrative = narrative;
    await resignEnvelopeWithPayload(envelope, signer.privateKeyPkcs8B64u);

    const verified = await verifyCompiledEvidenceReport(envelope);
    expect(verified.result.status).toBe('VALID');
    expect((envelopePayload.overall_status as string)).toBe('FAIL');
    expect(
      (envelopePayload.control_results as Array<Record<string, unknown>>)[0]?.status,
    ).toBe('FAIL');
  });

  it('returns deterministic SIGNATURE_INVALID on signature mismatch', async () => {
    const seed = new Uint8Array(32);
    for (let i = 0; i < seed.length; i++) seed[i] = i + 21;
    const signer = await makeDidSignerFromSeed(seed);

    const compiled = await compileAndSignCompiledEvidenceReport({
      payload: buildPayload(),
      signer: {
        signer_did: signer.did,
        private_key_pkcs8_b64u: signer.privateKeyPkcs8B64u,
      },
    });

    const envelope = {
      ...(compiled.envelope as Record<string, unknown>),
      signature_b64u: mutateBase64Url(String(compiled.envelope?.signature_b64u ?? '')),
    };

    const verified = await verifyCompiledEvidenceReport(envelope);
    expect(verified.result.status).toBe('INVALID');
    expect(verified.error?.code).toBe('SIGNATURE_INVALID');
  });

  it('returns deterministic HASH_MISMATCH on matrix hash mismatch', async () => {
    const seed = new Uint8Array(32);
    for (let i = 0; i < seed.length; i++) seed[i] = i + 31;
    const signer = await makeDidSignerFromSeed(seed);

    const compiled = await compileAndSignCompiledEvidenceReport({
      payload: buildPayload(),
      signer: {
        signer_did: signer.did,
        private_key_pkcs8_b64u: signer.privateKeyPkcs8B64u,
      },
    });

    const envelope = JSON.parse(JSON.stringify(compiled.envelope)) as Record<string, unknown>;
    const payload = envelope.payload as Record<string, unknown>;
    payload.matrix_hash_b64u = mutateBase64Url(String(payload.matrix_hash_b64u));

    const verified = await verifyCompiledEvidenceReport(envelope);
    expect(verified.result.status).toBe('INVALID');
    expect(verified.error?.code).toBe('HASH_MISMATCH');
  });

  it('returns deterministic MISSING_REQUIRED_FIELD when refs are missing', async () => {
    const seed = new Uint8Array(32);
    for (let i = 0; i < seed.length; i++) seed[i] = i + 41;
    const signer = await makeDidSignerFromSeed(seed);

    const compiled = await compileAndSignCompiledEvidenceReport({
      payload: buildPayload(),
      signer: {
        signer_did: signer.did,
        private_key_pkcs8_b64u: signer.privateKeyPkcs8B64u,
      },
    });

    const envelope = JSON.parse(JSON.stringify(compiled.envelope)) as Record<string, unknown>;
    const payload = envelope.payload as Record<string, unknown>;
    delete payload.evidence_refs;

    const verified = await verifyCompiledEvidenceReport(envelope);
    expect(verified.result.status).toBe('INVALID');
    expect(verified.error?.code).toBe('MISSING_REQUIRED_FIELD');
  });

  it('returns deterministic SCHEMA_VALIDATION_FAILED on schema violations', async () => {
    const seed = new Uint8Array(32);
    for (let i = 0; i < seed.length; i++) seed[i] = i + 51;
    const signer = await makeDidSignerFromSeed(seed);

    const compiled = await compileAndSignCompiledEvidenceReport({
      payload: buildPayload(),
      signer: {
        signer_did: signer.did,
        private_key_pkcs8_b64u: signer.privateKeyPkcs8B64u,
      },
    });

    const envelope = JSON.parse(JSON.stringify(compiled.envelope)) as Record<string, unknown>;
    const payload = envelope.payload as Record<string, unknown>;
    payload.overall_status = 'BROKEN_STATUS';

    const verified = await verifyCompiledEvidenceReport(envelope);
    expect(verified.result.status).toBe('INVALID');
    expect(verified.error?.code).toBe('SCHEMA_VALIDATION_FAILED');
  });
});
