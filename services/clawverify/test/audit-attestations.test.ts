import { describe, expect, it } from 'vitest';

import { base64UrlEncode, computeHash } from '../src/crypto';
import { verifyDerivationAttestation } from '../src/verify-derivation-attestation';
import { verifyAuditResultAttestation } from '../src/verify-audit-result-attestation';

const BASE58_ALPHABET =
  '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Encode(bytes: Uint8Array): string {
  if (bytes.length === 0) return '';

  const digits: number[] = [0];

  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i++) {
      const x = digits[i] * 256 + carry;
      digits[i] = x % 58;
      carry = Math.floor(x / 58);
    }
    while (carry) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }

  // Leading zeros
  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) {
    digits.push(0);
  }

  return digits
    .reverse()
    .map((d) => BASE58_ALPHABET[d])
    .join('');
}

async function makeDidKeyEd25519(): Promise<{
  did: string;
  privateKey: CryptoKey;
}> {
  const keypair = await crypto.subtle.generateKey('Ed25519', true, [
    'sign',
    'verify',
  ]);

  const publicKeyBytes = new Uint8Array(
    await crypto.subtle.exportKey('raw', keypair.publicKey)
  );

  const prefixed = new Uint8Array(2 + publicKeyBytes.length);
  prefixed[0] = 0xed;
  prefixed[1] = 0x01;
  prefixed.set(publicKeyBytes, 2);

  const did = `did:key:z${base58Encode(prefixed)}`;
  return { did, privateKey: keypair.privateKey };
}

async function signEnvelope(payload: unknown, signer: { did: string; privateKey: CryptoKey }, envelope_type: string) {
  const payloadHash = await computeHash(payload, 'SHA-256');
  const msg = new TextEncoder().encode(payloadHash);
  const sigBytes = new Uint8Array(await crypto.subtle.sign('Ed25519', signer.privateKey, msg));

  return {
    envelope_version: '1',
    envelope_type,
    payload,
    payload_hash_b64u: payloadHash,
    hash_algorithm: 'SHA-256',
    signature_b64u: base64UrlEncode(sigBytes),
    algorithm: 'Ed25519',
    signer_did: signer.did,
    issued_at: '2026-02-11T00:00:00Z',
  };
}

describe('CVF-US-017: derivation attestation verification', () => {
  it('verifies a valid derivation attestation envelope (allowlisted signer)', async () => {
    const signer = await makeDidKeyEd25519();

    const payload: any = {
      derivation_version: '1',
      derivation_id: 'drv_001',
      issued_at: '2026-02-11T00:00:00Z',
      input_model: {
        model_identity_version: '1',
        tier: 'openweights_hashable',
        model: { provider: 'self_hosted', name: 'llama-3.1-8b' },
      },
      output_model: {
        model_identity_version: '1',
        tier: 'openweights_hashable',
        model: { provider: 'self_hosted', name: 'llama-3.1-8b-q4' },
      },
      transform: {
        kind: 'quantize',
        code_hash_b64u: 'abcdEFGHijklMNOP',
        params_hash_b64u: 'qrstUVWXyz012345',
      },
    };

    const envelope = await signEnvelope(payload, signer, 'derivation_attestation');

    const out = await verifyDerivationAttestation(envelope, {
      allowlistedSignerDids: [signer.did],
    });

    expect(out.result.status).toBe('VALID');
    expect(out.derivation_id).toBe('drv_001');
    expect(out.transform_kind).toBe('quantize');
    expect(out.input_model?.provider).toBe('self_hosted');
    expect(out.output_model?.name).toBe('llama-3.1-8b-q4');
  });

  it('fails closed when signer allowlist is not configured', async () => {
    const signer = await makeDidKeyEd25519();

    const payload: any = {
      derivation_version: '1',
      derivation_id: 'drv_002',
      issued_at: '2026-02-11T00:00:00Z',
      input_model: {
        model_identity_version: '1',
        tier: 'closed_opaque',
        model: { provider: 'openai', name: 'gpt-test' },
      },
      output_model: {
        model_identity_version: '1',
        tier: 'closed_opaque',
        model: { provider: 'openai', name: 'gpt-test' },
      },
      transform: { kind: 'other' },
    };

    const envelope = await signEnvelope(payload, signer, 'derivation_attestation');

    const out = await verifyDerivationAttestation(envelope, {
      allowlistedSignerDids: [],
    });

    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('DEPENDENCY_NOT_CONFIGURED');
  });

  it('rejects hash mismatch', async () => {
    const signer = await makeDidKeyEd25519();

    const payload: any = {
      derivation_version: '1',
      derivation_id: 'drv_003',
      issued_at: '2026-02-11T00:00:00Z',
      input_model: {
        model_identity_version: '1',
        tier: 'closed_opaque',
        model: { provider: 'openai', name: 'gpt-test' },
      },
      output_model: {
        model_identity_version: '1',
        tier: 'closed_opaque',
        model: { provider: 'openai', name: 'gpt-test' },
      },
      transform: { kind: 'other' },
    };

    const envelope: any = await signEnvelope(payload, signer, 'derivation_attestation');
    envelope.payload_hash_b64u = 'AAAAAAAAAAAAAAAAAAAAAA';

    const out = await verifyDerivationAttestation(envelope, {
      allowlistedSignerDids: [signer.did],
    });

    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('HASH_MISMATCH');
  });

  it('rejects schema-invalid payloads', async () => {
    const signer = await makeDidKeyEd25519();

    // Missing transform.kind (required)
    const payload: any = {
      derivation_version: '1',
      derivation_id: 'drv_004',
      issued_at: '2026-02-11T00:00:00Z',
      input_model: {
        model_identity_version: '1',
        tier: 'closed_opaque',
        model: { provider: 'openai', name: 'gpt-test' },
      },
      output_model: {
        model_identity_version: '1',
        tier: 'closed_opaque',
        model: { provider: 'openai', name: 'gpt-test' },
      },
      transform: {},
    };

    const envelope = await signEnvelope(payload, signer, 'derivation_attestation');

    const out = await verifyDerivationAttestation(envelope, {
      allowlistedSignerDids: [signer.did],
    });

    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('SCHEMA_VALIDATION_FAILED');
  });
});

describe('CVF-US-018: audit result attestation verification', () => {
  it('verifies a valid audit result attestation envelope (allowlisted signer)', async () => {
    const signer = await makeDidKeyEd25519();

    const payload: any = {
      audit_version: '1',
      audit_id: 'audit_001',
      issued_at: '2026-02-11T00:00:00Z',
      audit_pack: { pack_hash_b64u: 'packHASHb64u_12345678' },
      model: {
        model_identity_version: '1',
        tier: 'closed_opaque',
        model: { provider: 'openai', name: 'gpt-5.2' },
      },
      audit_code: { code_hash_b64u: 'codeHASHb64u_12345678' },
      dataset: {
        dataset_id: 'mmlu',
        dataset_hash_b64u: 'dataHASHb64u_12345678',
        access: 'public',
      },
      protocol: {
        name: 'mmlu-v1',
        config_hash_b64u: 'cfgHASHb64u_12345678',
      },
      result: {
        status: 'pass',
        results_hash_b64u: 'resultsHASHb64u_12345678',
      },
    };

    const envelope = await signEnvelope(payload, signer, 'audit_result_attestation');

    const out = await verifyAuditResultAttestation(envelope, {
      allowlistedSignerDids: [signer.did],
    });

    expect(out.result.status).toBe('VALID');
    expect(out.audit_id).toBe('audit_001');
    expect(out.audit_pack_hash_b64u).toBe('packHASHb64u_12345678');
    expect(out.model?.provider).toBe('openai');
    expect(out.result_status).toBe('pass');
    expect(out.results_hash_b64u).toBe('resultsHASHb64u_12345678');
  });

  it('rejects signer not allowlisted', async () => {
    const signer = await makeDidKeyEd25519();

    const payload: any = {
      audit_version: '1',
      audit_id: 'audit_002',
      issued_at: '2026-02-11T00:00:00Z',
      model: {
        model_identity_version: '1',
        tier: 'closed_opaque',
        model: { provider: 'openai', name: 'gpt-5.2' },
      },
      audit_code: { code_hash_b64u: 'codeHASHb64u_ABCDEFGH' },
      dataset: {
        dataset_id: 'mmlu',
        dataset_hash_b64u: 'dataHASHb64u_ABCDEFGH',
        access: 'public',
      },
      protocol: {
        name: 'mmlu-v1',
        config_hash_b64u: 'cfgHASHb64u_ABCDEFGH',
      },
      result: {
        status: 'warn',
        results_hash_b64u: 'resultsHASHb64u_ABCDEFGH',
      },
    };

    const envelope = await signEnvelope(payload, signer, 'audit_result_attestation');

    const out = await verifyAuditResultAttestation(envelope, {
      allowlistedSignerDids: ['did:key:z6MkOther'],
    });

    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('CLAIM_NOT_FOUND');
  });

  it('rejects schema-invalid payloads', async () => {
    const signer = await makeDidKeyEd25519();

    // Missing audit_code.code_hash_b64u (required)
    const payload: any = {
      audit_version: '1',
      audit_id: 'audit_003',
      issued_at: '2026-02-11T00:00:00Z',
      model: {
        model_identity_version: '1',
        tier: 'closed_opaque',
        model: { provider: 'openai', name: 'gpt-5.2' },
      },
      audit_code: {},
      dataset: {
        dataset_id: 'mmlu',
        dataset_hash_b64u: 'dataHASHb64u_12345678',
        access: 'public',
      },
      protocol: {
        name: 'mmlu-v1',
        config_hash_b64u: 'cfgHASHb64u_12345678',
      },
      result: {
        status: 'fail',
        results_hash_b64u: 'resultsHASHb64u_12345678',
      },
    };

    const envelope = await signEnvelope(payload, signer, 'audit_result_attestation');

    const out = await verifyAuditResultAttestation(envelope, {
      allowlistedSignerDids: [signer.did],
    });

    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('SCHEMA_VALIDATION_FAILED');
  });
});
