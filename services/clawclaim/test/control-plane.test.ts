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

function makeEnv() {
  return {
    CLAIM_VERSION: 'test',
    CLAIM_CHALLENGE_TTL_SECONDS: '600',
    CLAIM_STORE: new MemoryKV() as unknown as KVNamespace,
  };
}

async function call(env: any, path: string, init?: RequestInit) {
  const req = new Request(`https://clawclaim.test${path}`, init);
  const res = await worker.fetch(req, env);
  const json = (await res.json()) as Record<string, unknown>;
  return { res, json };
}

async function bindDid(env: any, did: string, privateKey: CryptoKey) {
  const challenge = await call(env, '/v1/challenges', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ did }),
  });

  expect(challenge.res.status).toBe(200);
  const message = String(challenge.json.message ?? '');
  const signature = await signMessage(privateKey, message);

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

describe('ICP-US-001 control-plane flows', () => {
  it('registers controller + agent chain using owner-signed control-plane challenges', async () => {
    const env = makeEnv();
    const owner = await createDidKeyPair();
    const controller = await createDidKeyPair();
    const agent = await createDidKeyPair();

    await bindDid(env, owner.did, owner.privateKey);
    await bindDid(env, controller.did, controller.privateKey);
    await bindDid(env, agent.did, agent.privateKey);

    const cpChallenge = await call(env, '/v1/control-plane/challenges', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        owner_did: owner.did,
        purpose: 'register_controller',
        controller_did: controller.did,
      }),
    });

    expect(cpChallenge.res.status).toBe(200);
    const cpSig = await signMessage(owner.privateKey, String(cpChallenge.json.message ?? ''));

    const registerController = await call(env, '/v1/control-plane/controllers/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        owner_did: owner.did,
        controller_did: controller.did,
        challenge_id: cpChallenge.json.challenge_id,
        signature_b64u: cpSig,
      }),
    });

    expect(registerController.res.status).toBe(200);
    expect(registerController.json.status).toBe('registered');

    const agentChallenge = await call(env, '/v1/control-plane/challenges', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        owner_did: owner.did,
        purpose: 'register_agent',
        controller_did: controller.did,
        agent_did: agent.did,
      }),
    });

    expect(agentChallenge.res.status).toBe(200);
    const agentSig = await signMessage(owner.privateKey, String(agentChallenge.json.message ?? ''));

    const registerAgent = await call(
      env,
      `/v1/control-plane/controllers/${encodeURIComponent(controller.did)}/agents/register`,
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          owner_did: owner.did,
          agent_did: agent.did,
          challenge_id: agentChallenge.json.challenge_id,
          signature_b64u: agentSig,
        }),
      }
    );

    expect(registerAgent.res.status).toBe(200);
    expect(registerAgent.json.status).toBe('registered');

    const chainRead = await call(
      env,
      `/v1/control-plane/controllers/${encodeURIComponent(controller.did)}/agents/${encodeURIComponent(agent.did)}`,
      { method: 'GET' }
    );

    expect(chainRead.res.status).toBe(200);
    expect(chainRead.json.status).toBe('ok');
    expect(chainRead.json.owner_did).toBe(owner.did);
  });

  it('fails closed when owner_did is not bound for control-plane challenge issuance', async () => {
    const env = makeEnv();
    const owner = await createDidKeyPair();
    const controller = await createDidKeyPair();

    const res = await call(env, '/v1/control-plane/challenges', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        owner_did: owner.did,
        purpose: 'register_controller',
        controller_did: controller.did,
      }),
    });

    expect(res.res.status).toBe(403);
    expect(res.json.error).toBe('OWNER_BINDING_REQUIRED');
  });

  it('fails closed on invalid sensitive policy update payload', async () => {
    const env = makeEnv();
    const owner = await createDidKeyPair();
    const controller = await createDidKeyPair();

    await bindDid(env, owner.did, owner.privateKey);
    await bindDid(env, controller.did, controller.privateKey);

    const cpChallenge = await call(env, '/v1/control-plane/challenges', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        owner_did: owner.did,
        purpose: 'register_controller',
        controller_did: controller.did,
      }),
    });
    const cpSig = await signMessage(owner.privateKey, String(cpChallenge.json.message ?? ''));

    const registerController = await call(env, '/v1/control-plane/controllers/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        owner_did: owner.did,
        controller_did: controller.did,
        challenge_id: cpChallenge.json.challenge_id,
        signature_b64u: cpSig,
      }),
    });
    expect(registerController.res.status).toBe(200);

    const policyChallenge = await call(env, '/v1/control-plane/challenges', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        owner_did: owner.did,
        purpose: 'update_sensitive_policy',
        controller_did: controller.did,
      }),
    });

    const policySig = await signMessage(owner.privateKey, String(policyChallenge.json.message ?? ''));

    const updatePolicy = await call(
      env,
      `/v1/control-plane/controllers/${encodeURIComponent(controller.did)}/sensitive-policy`,
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          owner_did: owner.did,
          challenge_id: policyChallenge.json.challenge_id,
          signature_b64u: policySig,
          allowed_sensitive_scopes: ['proxy:unsafe'],
        }),
      }
    );

    expect(updatePolicy.res.status).toBe(400);
    expect(updatePolicy.json.error).toBe('INVALID_SENSITIVE_POLICY');
  });
});
