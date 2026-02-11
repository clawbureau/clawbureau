import { describe, expect, it } from 'vitest';

import inclusionFixture from '../../../packages/schema/fixtures/log_inclusion_proof_golden.v1.json';
import exportFixture from '../../../packages/schema/fixtures/export_bundle_golden.v1.json';
import { base64UrlEncode, computeHash } from '../src/crypto';
import { jcsCanonicalize } from '../src/jcs';
import { verifyExportBundle } from '../src/verify-export-bundle';

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
    while (carry) {
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

async function makeDidKeyFromSeed(seed: Uint8Array): Promise<{
  did: string;
  privateKey: CryptoKey;
}> {
  const pkcs8Header = new Uint8Array([
    0x30, 0x2e,
    0x02, 0x01, 0x00,
    0x30, 0x05,
    0x06, 0x03, 0x2b, 0x65, 0x70,
    0x04, 0x22,
    0x04, 0x20,
  ]);

  const pkcs8Key = new Uint8Array(pkcs8Header.length + seed.length);
  pkcs8Key.set(pkcs8Header);
  pkcs8Key.set(seed, pkcs8Header.length);

  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    pkcs8Key,
    { name: 'Ed25519' },
    true,
    ['sign'],
  );

  const jwk = (await crypto.subtle.exportKey('jwk', privateKey)) as JsonWebKey;
  const publicKeyBytes = Buffer.from(String(jwk.x), 'base64url');

  const prefixed = new Uint8Array(2 + publicKeyBytes.length);
  prefixed[0] = 0xed;
  prefixed[1] = 0x01;
  prefixed.set(publicKeyBytes, 2);

  const did = `did:key:z${base58Encode(prefixed)}`;
  return { did, privateKey };
}

async function signEnvelope(payload: unknown, signer: { did: string; privateKey: CryptoKey }, envelopeType: string) {
  const payloadHash = await computeHash(payload, 'SHA-256');
  const sigBytes = new Uint8Array(
    await crypto.subtle.sign('Ed25519', signer.privateKey, new TextEncoder().encode(payloadHash)),
  );

  return {
    envelope_version: '1',
    envelope_type: envelopeType,
    payload,
    payload_hash_b64u: payloadHash,
    hash_algorithm: 'SHA-256',
    signature_b64u: base64UrlEncode(sigBytes),
    algorithm: 'Ed25519',
    signer_did: signer.did,
    issued_at: '2026-02-11T00:00:00.000Z',
  };
}

async function sha256B64u(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return base64UrlEncode(new Uint8Array(digest));
}

async function makeManifestEntry(path: string, value: unknown) {
  const canonical = jcsCanonicalize(value);
  return {
    path,
    sha256_b64u: await sha256B64u(canonical),
    content_type: 'application/json',
    size_bytes: new TextEncoder().encode(canonical).byteLength,
  };
}

function mutateB64u(value: string): string {
  const first = value[0] === 'A' ? 'B' : 'A';
  return `${first}${value.slice(1)}`;
}

type GoldenInclusionProof = {
  inclusion_proof_v1: {
    proof_version: '1';
    log_id: string;
    tree_size: number;
    leaf_hash_b64u: string;
    root_hash_b64u: string;
    audit_path: string[];
    root_published_at: string;
    root_signature: { signer_did: string; sig_b64u: string };
    metadata: { leaf_index: number; merkle_algorithm: string };
  };
};

const goldenProof = (inclusionFixture as GoldenInclusionProof).inclusion_proof_v1;

async function buildExportBundle(opts?: { tamperManifest?: boolean; tamperInclusionProof?: boolean }) {
  const seed = new Uint8Array(32);
  for (let i = 0; i < seed.length; i++) seed[i] = i + 1;
  const signer = await makeDidKeyFromSeed(seed);

  const e1PayloadHash = await computeHash({ type: 'run_start' }, 'SHA-256');
  const e1Header = {
    event_id: 'evt_export_001',
    run_id: 'run_export_001',
    event_type: 'run_start',
    timestamp: '2026-02-11T00:00:00.000Z',
    payload_hash_b64u: e1PayloadHash,
    prev_hash_b64u: null as string | null,
  };
  const e1Hash = await computeHash(e1Header, 'SHA-256');

  const proofBundlePayload = {
    bundle_version: '1',
    bundle_id: 'bundle_export_001',
    agent_did: signer.did,
    event_chain: [
      {
        ...e1Header,
        event_hash_b64u: e1Hash,
      },
    ],
  };

  const proofBundleEnvelope = await signEnvelope(proofBundlePayload, signer, 'proof_bundle');

  const derivationPayload: any = {
    derivation_version: '1',
    derivation_id: 'drv_export_001',
    issued_at: '2026-02-11T00:00:00.000Z',
    input_model: {
      model_identity_version: '1',
      tier: 'closed_opaque',
      model: { provider: 'openai', name: 'gpt-5.2' },
    },
    output_model: {
      model_identity_version: '1',
      tier: 'closed_opaque',
      model: { provider: 'openai', name: 'gpt-5.2' },
    },
    transform: { kind: 'other' },
    clawlogs: {
      inclusion_proof: JSON.parse(JSON.stringify(goldenProof)),
    },
  };

  if (opts?.tamperInclusionProof) {
    derivationPayload.clawlogs.inclusion_proof.audit_path[0] =
      mutateB64u(derivationPayload.clawlogs.inclusion_proof.audit_path[0]);
  }

  const derivationEnvelope = await signEnvelope(
    derivationPayload,
    signer,
    'derivation_attestation',
  );

  const artifacts = {
    proof_bundle_envelope: proofBundleEnvelope,
    derivation_attestation_envelopes: [derivationEnvelope],
  };

  const manifestEntries = [
    await makeManifestEntry('artifacts/proof_bundle_envelope.json', proofBundleEnvelope),
    await makeManifestEntry(
      'artifacts/derivation_attestation_envelopes/0.json',
      derivationEnvelope,
    ),
  ];

  if (opts?.tamperManifest) {
    manifestEntries[0] = {
      ...manifestEntries[0],
      sha256_b64u: mutateB64u(manifestEntries[0]!.sha256_b64u),
    };
  }

  const bundle = {
    export_version: '1',
    export_id: 'exp_001',
    created_at: '2026-02-11T00:00:00.000Z',
    issuer_did: signer.did,
    manifest: {
      manifest_version: '1',
      generated_at: '2026-02-11T00:00:00.000Z',
      entries: manifestEntries,
    },
    artifacts,
    bundle_hash_b64u: '',
    hash_algorithm: 'SHA-256' as const,
    signature_b64u: '',
    algorithm: 'Ed25519' as const,
    issued_at: '2026-02-11T00:00:00.000Z',
  };

  const signable = {
    export_version: bundle.export_version,
    export_id: bundle.export_id,
    created_at: bundle.created_at,
    issuer_did: bundle.issuer_did,
    manifest: bundle.manifest,
    artifacts: bundle.artifacts,
    issued_at: bundle.issued_at,
  };

  bundle.bundle_hash_b64u = await sha256B64u(jcsCanonicalize(signable));

  const sigBytes = new Uint8Array(
    await crypto.subtle.sign('Ed25519', signer.privateKey, new TextEncoder().encode(bundle.bundle_hash_b64u)),
  );
  bundle.signature_b64u = base64UrlEncode(sigBytes);

  return { bundle, signer };
}

type ExportBundleFixture = {
  bundle: any;
};

const goldenExportBundle = (exportFixture as ExportBundleFixture).bundle;

describe('POHVN-US-007: export bundle verification', () => {
  it('verifies the golden export bundle fixture', async () => {
    const out = await verifyExportBundle(goldenExportBundle, {
      allowlistedDerivationAttestationSignerDids: [goldenExportBundle.issuer_did],
    });

    expect(out.result.status).toBe('VALID');
    expect(out.export_id).toBe(goldenExportBundle.export_id);
  });

  it('verifies a valid export bundle with included derivation attestation + inclusion proof', async () => {
    const { bundle, signer } = await buildExportBundle();

    const out = await verifyExportBundle(bundle, {
      allowlistedDerivationAttestationSignerDids: [signer.did],
    });

    expect(out.result.status).toBe('VALID');
    expect(out.export_id).toBe('exp_001');
    expect(out.manifest_entries_verified).toBe(2);
    expect(out.verified_components?.proof_bundle_valid).toBe(true);
    expect(out.verified_components?.derivation_attestations_verified).toBe(1);
  });

  it('fails closed when manifest hash is tampered', async () => {
    const { bundle, signer } = await buildExportBundle({ tamperManifest: true });

    const out = await verifyExportBundle(bundle, {
      allowlistedDerivationAttestationSignerDids: [signer.did],
    });

    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('HASH_MISMATCH');
  });

  it('fails closed when included inclusion proof is tampered', async () => {
    const { bundle, signer } = await buildExportBundle({ tamperInclusionProof: true });

    const out = await verifyExportBundle(bundle, {
      allowlistedDerivationAttestationSignerDids: [signer.did],
    });

    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('INCLUSION_PROOF_INVALID');
  });
});
