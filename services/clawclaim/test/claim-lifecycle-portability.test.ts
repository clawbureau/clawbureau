import { describe, expect, it } from 'vitest';
import bs58 from 'bs58';

import worker from '../src/index';

type KvValue = {
  value: string;
  expiresAtMs: number | null;
};

class MemoryKV {
  private data = new Map<string, KvValue>();

  async get(key: string): Promise<string | null> {
    const item = this.data.get(key);
    if (!item) return null;

    if (item.expiresAtMs !== null && Date.now() > item.expiresAtMs) {
      this.data.delete(key);
      return null;
    }

    return item.value;
  }

  async put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void> {
    const expiresAtMs =
      options?.expirationTtl && Number.isFinite(options.expirationTtl)
        ? Date.now() + options.expirationTtl * 1000
        : null;

    this.data.set(key, { value, expiresAtMs });
  }

  async delete(key: string): Promise<void> {
    this.data.delete(key);
  }

  async list(options?: { prefix?: string; limit?: number; cursor?: string }): Promise<any> {
    const prefix = options?.prefix ?? '';
    const limit = options?.limit ?? 1000;

    const keys = Array.from(this.data.keys())
      .filter((k) => k.startsWith(prefix))
      .sort()
      .slice(0, limit)
      .map((name) => ({ name }));

    return {
      keys,
      cursor: null,
      list_complete: true,
    };
  }
}

function base64UrlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function base58Encode(bytes: Uint8Array): string {
  return bs58.encode(bytes);
}

const ED25519_MULTICODEC_PREFIX = new Uint8Array([0xed, 0x01]);

async function createDidKeyPair() {
  const kp = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  const rawPub = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
  const prefixed = new Uint8Array(ED25519_MULTICODEC_PREFIX.length + rawPub.length);
  prefixed.set(ED25519_MULTICODEC_PREFIX, 0);
  prefixed.set(rawPub, ED25519_MULTICODEC_PREFIX.length);

  return {
    did: `did:key:z${base58Encode(prefixed)}`,
    privateKey: kp.privateKey,
  };
}

async function signMessage(privateKey: CryptoKey, message: string): Promise<string> {
  const bytes = new TextEncoder().encode(message);
  const sig = await crypto.subtle.sign('Ed25519', privateKey, bytes);
  return base64UrlEncode(new Uint8Array(sig));
}

function makeEnv(overrides: Record<string, unknown> = {}) {
  return {
    CLAIM_VERSION: 'test',
    CLAIM_CHALLENGE_TTL_SECONDS: '600',
    CLAIM_EXPORT_SIGNING_KEY: 'claim-export-signing-key-test',
    CLAIM_EXPORT_MAX_AGE_SECONDS: '86400',
    CLAIM_STORE: new MemoryKV() as unknown as KVNamespace,
    ...overrides,
  };
}

async function call(env: any, path: string, init?: RequestInit) {
  const req = new Request(`https://clawclaim.test${path}`, init);
  const res = await worker.fetch(req, env);
  const json = (await res.json()) as Record<string, any>;
  return { res, json };
}

async function bindDid(env: any, did: string, privateKey: CryptoKey) {
  const challenge = await call(env, '/v1/challenges', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ did }),
  });

  expect(challenge.res.status).toBe(200);

  const signature = await signMessage(privateKey, String(challenge.json.message ?? ''));

  const bind = await call(env, '/v1/bind', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      did,
      challenge_id: challenge.json.challenge_id,
      signature_b64u: signature,
    }),
  });

  expect(bind.res.status).toBe(200);
}

async function issueControlPlaneChallenge(env: any, body: Record<string, unknown>) {
  const challenge = await call(env, '/v1/control-plane/challenges', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  expect(challenge.res.status).toBe(200);
  return challenge.json;
}

async function registerController(env: any, owner: { did: string; privateKey: CryptoKey }, controllerDid: string) {
  const challenge = await issueControlPlaneChallenge(env, {
    owner_did: owner.did,
    purpose: 'register_controller',
    controller_did: controllerDid,
  });

  const signature = await signMessage(owner.privateKey, String(challenge.message ?? ''));

  const register = await call(env, '/v1/control-plane/controllers/register', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      owner_did: owner.did,
      controller_did: controllerDid,
      challenge_id: challenge.challenge_id,
      signature_b64u: signature,
    }),
  });

  expect(register.res.status).toBe(200);
}

async function registerAgent(
  env: any,
  owner: { did: string; privateKey: CryptoKey },
  controllerDid: string,
  agentDid: string
) {
  const challenge = await issueControlPlaneChallenge(env, {
    owner_did: owner.did,
    purpose: 'register_agent',
    controller_did: controllerDid,
    agent_did: agentDid,
  });

  const signature = await signMessage(owner.privateKey, String(challenge.message ?? ''));

  const register = await call(
    env,
    `/v1/control-plane/controllers/${encodeURIComponent(controllerDid)}/agents/register`,
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        owner_did: owner.did,
        agent_did: agentDid,
        challenge_id: challenge.challenge_id,
        signature_b64u: signature,
      }),
    }
  );

  expect(register.res.status).toBe(200);
}

describe('CCL-US-013/014/015 claim lifecycle + portability', () => {
  it('supports owner-confirmed controller rotation continuity with alias resolution', async () => {
    const env = makeEnv();

    const owner = await createDidKeyPair();
    const controllerOld = await createDidKeyPair();
    const controllerNew = await createDidKeyPair();
    const agent = await createDidKeyPair();

    await bindDid(env, owner.did, owner.privateKey);
    await bindDid(env, controllerOld.did, controllerOld.privateKey);
    await bindDid(env, controllerNew.did, controllerNew.privateKey);
    await bindDid(env, agent.did, agent.privateKey);

    await registerController(env, owner, controllerOld.did);
    await registerAgent(env, owner, controllerOld.did, agent.did);

    const rotationChallenge = await issueControlPlaneChallenge(env, {
      owner_did: owner.did,
      purpose: 'confirm_rotation',
      rotation_role: 'controller',
      from_did: controllerOld.did,
      to_did: controllerNew.did,
    });

    const rotationSig = await signMessage(owner.privateKey, String(rotationChallenge.message ?? ''));

    const confirmRotation = await call(env, '/v1/control-plane/rotations/confirm', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        owner_did: owner.did,
        rotation_role: 'controller',
        from_did: controllerOld.did,
        to_did: controllerNew.did,
        challenge_id: rotationChallenge.challenge_id,
        signature_b64u: rotationSig,
      }),
    });

    expect(confirmRotation.res.status).toBe(200);
    expect(confirmRotation.json.status).toBe('rotated');

    const chainReadOld = await call(
      env,
      `/v1/control-plane/controllers/${encodeURIComponent(controllerOld.did)}/agents/${encodeURIComponent(agent.did)}`,
      { method: 'GET' }
    );

    expect(chainReadOld.res.status).toBe(200);
    expect(chainReadOld.json.chain.controller_did).toBe(controllerNew.did);
    expect(chainReadOld.json.alias_resolution.resolved_controller_did).toBe(controllerNew.did);
  });

  it('enforces controller transfer freeze semantics and completes transfer state machine', async () => {
    const env = makeEnv();

    const ownerA = await createDidKeyPair();
    const ownerB = await createDidKeyPair();
    const controller = await createDidKeyPair();
    const agent = await createDidKeyPair();

    await bindDid(env, ownerA.did, ownerA.privateKey);
    await bindDid(env, ownerB.did, ownerB.privateKey);
    await bindDid(env, controller.did, controller.privateKey);
    await bindDid(env, agent.did, agent.privateKey);

    await registerController(env, ownerA, controller.did);
    await registerAgent(env, ownerA, controller.did, agent.did);

    const transferRequestChallenge = await issueControlPlaneChallenge(env, {
      owner_did: ownerA.did,
      purpose: 'transfer_controller_request',
      controller_did: controller.did,
      transfer_to_owner_did: ownerB.did,
    });

    const transferRequestSig = await signMessage(
      ownerA.privateKey,
      String(transferRequestChallenge.message ?? '')
    );

    const transferRequest = await call(
      env,
      `/v1/control-plane/controllers/${encodeURIComponent(controller.did)}/transfer/request`,
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          owner_did: ownerA.did,
          transfer_to_owner_did: ownerB.did,
          challenge_id: transferRequestChallenge.challenge_id,
          signature_b64u: transferRequestSig,
        }),
      }
    );

    expect(transferRequest.res.status).toBe(200);
    expect(transferRequest.json.status).toBe('transfer_pending');

    const frozenChallenge = await call(env, '/v1/control-plane/challenges', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        owner_did: ownerA.did,
        purpose: 'update_sensitive_policy',
        controller_did: controller.did,
      }),
    });

    expect(frozenChallenge.res.status).toBe(409);
    expect(frozenChallenge.json.error).toBe('CONTROLLER_TRANSFER_FROZEN');

    const transferConfirmChallenge = await issueControlPlaneChallenge(env, {
      owner_did: ownerB.did,
      purpose: 'transfer_controller_confirm',
      controller_did: controller.did,
      transfer_to_owner_did: ownerB.did,
    });

    const transferConfirmSig = await signMessage(
      ownerB.privateKey,
      String(transferConfirmChallenge.message ?? '')
    );

    const transferConfirm = await call(
      env,
      `/v1/control-plane/controllers/${encodeURIComponent(controller.did)}/transfer/confirm`,
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          owner_did: ownerB.did,
          transfer_to_owner_did: ownerB.did,
          challenge_id: transferConfirmChallenge.challenge_id,
          signature_b64u: transferConfirmSig,
        }),
      }
    );

    expect(transferConfirm.res.status).toBe(200);
    expect(transferConfirm.json.status).toBe('transferred');
    expect(transferConfirm.json.controller.owner_did).toBe(ownerB.did);
    expect(transferConfirm.json.controller.transfer_state).toBe('transferred');

    const postTransferChallenge = await call(env, '/v1/control-plane/challenges', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        owner_did: ownerB.did,
        purpose: 'update_sensitive_policy',
        controller_did: controller.did,
      }),
    });

    expect(postTransferChallenge.res.status).toBe(200);
  });

  it('exports/imports signed identity bundle and rejects tampered payloads', async () => {
    const env = makeEnv();

    const owner = await createDidKeyPair();
    const controller = await createDidKeyPair();
    const agent = await createDidKeyPair();

    await bindDid(env, owner.did, owner.privateKey);
    await bindDid(env, controller.did, controller.privateKey);
    await bindDid(env, agent.did, agent.privateKey);

    await registerController(env, owner, controller.did);
    await registerAgent(env, owner, controller.did, agent.did);

    const exportChallenge = await issueControlPlaneChallenge(env, {
      owner_did: owner.did,
      purpose: 'export_identity',
      controller_did: controller.did,
    });

    const exportSig = await signMessage(owner.privateKey, String(exportChallenge.message ?? ''));

    const exportRes = await call(env, '/v1/control-plane/identity/export', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        owner_did: owner.did,
        controller_did: controller.did,
        challenge_id: exportChallenge.challenge_id,
        signature_b64u: exportSig,
      }),
    });

    expect(exportRes.res.status).toBe(200);
    expect(exportRes.json.status).toBe('exported');

    const bundle = exportRes.json.export_bundle;

    const importChallenge = await issueControlPlaneChallenge(env, {
      owner_did: owner.did,
      purpose: 'import_identity',
      bundle_hash_b64u: bundle.bundle_hash_b64u,
    });

    const importSig = await signMessage(owner.privateKey, String(importChallenge.message ?? ''));

    const importRes = await call(env, '/v1/control-plane/identity/import', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        owner_did: owner.did,
        challenge_id: importChallenge.challenge_id,
        signature_b64u: importSig,
        bundle,
      }),
    });

    expect(importRes.res.status).toBe(200);
    expect(importRes.json.status).toBe('imported');

    const reimportChallenge = await issueControlPlaneChallenge(env, {
      owner_did: owner.did,
      purpose: 'import_identity',
      bundle_hash_b64u: bundle.bundle_hash_b64u,
    });

    const reimportSig = await signMessage(owner.privateKey, String(reimportChallenge.message ?? ''));

    const reimportRes = await call(env, '/v1/control-plane/identity/import', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        owner_did: owner.did,
        challenge_id: reimportChallenge.challenge_id,
        signature_b64u: reimportSig,
        bundle,
      }),
    });

    expect(reimportRes.res.status).toBe(200);
    expect(reimportRes.json.status).toBe('already_imported');

    const tamperChallenge = await issueControlPlaneChallenge(env, {
      owner_did: owner.did,
      purpose: 'import_identity',
      bundle_hash_b64u: bundle.bundle_hash_b64u,
    });

    const tamperSig = await signMessage(owner.privateKey, String(tamperChallenge.message ?? ''));

    const tamperedBundle = JSON.parse(JSON.stringify(bundle));
    tamperedBundle.payload.owner_did = 'did:key:zTampered';

    const tamperRes = await call(env, '/v1/control-plane/identity/import', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        owner_did: owner.did,
        challenge_id: tamperChallenge.challenge_id,
        signature_b64u: tamperSig,
        bundle: tamperedBundle,
      }),
    });

    expect(tamperRes.res.status).toBe(409);
    expect(tamperRes.json.error).toBe('IMPORT_BUNDLE_TAMPERED');
  });

  it('rejects stale identity import bundles fail-closed', async () => {
    const env = makeEnv({ CLAIM_EXPORT_MAX_AGE_SECONDS: '1' });

    const owner = await createDidKeyPair();
    const controller = await createDidKeyPair();

    await bindDid(env, owner.did, owner.privateKey);
    await bindDid(env, controller.did, controller.privateKey);

    await registerController(env, owner, controller.did);

    const exportChallenge = await issueControlPlaneChallenge(env, {
      owner_did: owner.did,
      purpose: 'export_identity',
      controller_did: controller.did,
    });

    const exportSig = await signMessage(owner.privateKey, String(exportChallenge.message ?? ''));
    const exportRes = await call(env, '/v1/control-plane/identity/export', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        owner_did: owner.did,
        controller_did: controller.did,
        challenge_id: exportChallenge.challenge_id,
        signature_b64u: exportSig,
      }),
    });

    expect(exportRes.res.status).toBe(200);
    const staleBundle = JSON.parse(JSON.stringify(exportRes.json.export_bundle));
    staleBundle.exported_at = 1;
    staleBundle.exported_at_iso = '1970-01-01T00:00:01.000Z';

    const importChallenge = await issueControlPlaneChallenge(env, {
      owner_did: owner.did,
      purpose: 'import_identity',
      bundle_hash_b64u: staleBundle.bundle_hash_b64u,
    });

    const importSig = await signMessage(owner.privateKey, String(importChallenge.message ?? ''));
    const staleRes = await call(env, '/v1/control-plane/identity/import', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        owner_did: owner.did,
        challenge_id: importChallenge.challenge_id,
        signature_b64u: importSig,
        bundle: staleBundle,
      }),
    });

    expect(staleRes.res.status).toBe(409);
    expect(staleRes.json.error).toBe('IMPORT_BUNDLE_STALE');
  });
});
