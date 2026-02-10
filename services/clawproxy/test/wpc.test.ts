import { afterEach, describe, expect, it, vi } from 'vitest';

import type { Env } from '../src/types';
import {
  computeWpcHashB64u,
  fetchWpcFromRegistry,
  type WorkPolicyContractEnvelopeV1,
  type WorkPolicyContractV1,
} from '../src/wpc';
import { didKeyFromEd25519PublicKeyBytes, signEd25519 } from '../src/crypto';

async function generateSignerDid(): Promise<{ did: string; privateKey: CryptoKey }> {
  const keyPair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, [
    'sign',
    'verify',
  ]);

  const publicKeyBytes = new Uint8Array(
    await crypto.subtle.exportKey('raw', keyPair.publicKey)
  );
  const did = didKeyFromEd25519PublicKeyBytes(publicKeyBytes);

  return { did, privateKey: keyPair.privateKey };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('WPC registry fetch + verification', () => {
  it('fetches and verifies a signed WPC envelope', async () => {
    const signer = await generateSignerDid();

    const policy: WorkPolicyContractV1 = {
      policy_version: '1',
      policy_id: 'policy_test',
      issuer_did: 'did:key:zIssuer',
      allowed_providers: ['openai'],
      allowed_models: ['gpt-*'],
      redaction_rules: [{ path: '$.messages[*].content', action: 'hash' }],
      receipt_privacy_mode: 'hash_only',
    };

    const policyHash = await computeWpcHashB64u(policy);

    const envelope: WorkPolicyContractEnvelopeV1 = {
      envelope_version: '1',
      envelope_type: 'work_policy_contract',
      payload: policy,
      payload_hash_b64u: policyHash,
      hash_algorithm: 'SHA-256',
      signature_b64u: await signEd25519(signer.privateKey, policyHash),
      algorithm: 'Ed25519',
      signer_did: signer.did,
      issued_at: new Date().toISOString(),
    };

    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        new Response(JSON.stringify({ ok: true, envelope }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        })
      )
    );

    const env = {
      WPC_REGISTRY_BASE_URL: 'https://clawcontrols.com',
      WPC_SIGNER_DIDS: signer.did,
    } as unknown as Env;

    const result = await fetchWpcFromRegistry(env, policyHash);

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error('expected ok');

    expect(result.policy_hash_b64u).toBe(policyHash);
    expect(result.policy.policy_id).toBe('policy_test');
    expect(result.envelope.signer_did).toBe(signer.did);
  });

  it('rejects a WPC signed by a non-allowlisted signer', async () => {
    const signer = await generateSignerDid();

    const policy: WorkPolicyContractV1 = {
      policy_version: '1',
      policy_id: 'policy_test',
      issuer_did: 'did:key:zIssuer',
    };

    const policyHash = await computeWpcHashB64u(policy);

    const envelope: WorkPolicyContractEnvelopeV1 = {
      envelope_version: '1',
      envelope_type: 'work_policy_contract',
      payload: policy,
      payload_hash_b64u: policyHash,
      hash_algorithm: 'SHA-256',
      signature_b64u: await signEd25519(signer.privateKey, policyHash),
      algorithm: 'Ed25519',
      signer_did: signer.did,
      issued_at: new Date().toISOString(),
    };

    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        new Response(JSON.stringify({ ok: true, envelope }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        })
      )
    );

    const env = {
      WPC_REGISTRY_BASE_URL: 'https://clawcontrols.com',
      WPC_SIGNER_DIDS: 'did:key:zOther',
    } as unknown as Env;

    const result = await fetchWpcFromRegistry(env, policyHash);

    expect(result.ok).toBe(false);
    if (result.ok) throw new Error('expected error');

    expect(result.errorCode).toBe('WPC_SIGNER_NOT_ALLOWED');
  });
});
