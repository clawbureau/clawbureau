import type { Env } from './types';
import { didKeyFromEd25519PublicKeyBytes, importEd25519Key, sha256B64u, signEd25519 } from './crypto';
import { jcsCanonicalize } from './jcs';
import { isWorkPolicyContractV1, type SignedEnvelope, type WorkPolicyContractV1 } from './wpc';

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
    },
  });
}

function error(code: string, message: string, status: number): Response {
  return json({ ok: false, error: { code, message } }, status);
}

// Durable Object per-value storage limits are ~128KB; keep headroom for envelope overhead.
const MAX_WPC_BYTES = 64 * 1024;
const STORAGE_PREFIX = 'wpc:';

const B64U_RE = /^[A-Za-z0-9_-]+$/;
const SHA256_B64U_LEN = 43;

type StoredWpc = {
  envelope: SignedEnvelope<WorkPolicyContractV1>;
  created_at: string;
};

export class WpcRegistryDurableObject {
  private readonly state: DurableObjectState;
  private readonly env: Env;

  private signerDidKeyPromise: Promise<string> | null = null;
  private keyPairPromise: Promise<CryptoKey> | null = null;

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
  }

  private async getPrivateKey(): Promise<CryptoKey> {
    if (this.keyPairPromise) return this.keyPairPromise;

    this.keyPairPromise = (async () => {
      const raw = this.env.CONTROLS_SIGNING_KEY;
      if (!raw || raw.trim().length === 0) {
        throw new Error('CONTROLS_SIGNING_KEY not configured');
      }
      const kp = await importEd25519Key(raw.trim());
      return kp.privateKey;
    })();

    return this.keyPairPromise;
  }

  private async getSignerDidKey(): Promise<string> {
    if (this.signerDidKeyPromise) return this.signerDidKeyPromise;

    this.signerDidKeyPromise = (async () => {
      const raw = this.env.CONTROLS_SIGNING_KEY;
      if (!raw || raw.trim().length === 0) {
        throw new Error('CONTROLS_SIGNING_KEY not configured');
      }
      const kp = await importEd25519Key(raw.trim());
      return didKeyFromEd25519PublicKeyBytes(kp.publicKeyBytes);
    })();

    return this.signerDidKeyPromise;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === 'POST' && path === '/v1/wpc') {
      return this.handleCreate(request);
    }

    if (request.method === 'GET' && path.startsWith('/v1/wpc/')) {
      const policyHash = decodeURIComponent(path.slice('/v1/wpc/'.length));
      return this.handleGet(policyHash);
    }

    return error('NOT_FOUND', 'Not found', 404);
  }

  private async handleCreate(request: Request): Promise<Response> {
    // Read body (bounded)
    let text: string;
    try {
      text = await request.text();
    } catch {
      return error('BODY_READ_FAILED', 'Failed to read request body', 400);
    }

    const bodyBytes = new TextEncoder().encode(text);
    if (bodyBytes.length > MAX_WPC_BYTES) {
      return error('PAYLOAD_TOO_LARGE', `WPC body exceeds ${MAX_WPC_BYTES} bytes`, 413);
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      return error('INVALID_JSON', 'Request body must be valid JSON', 400);
    }

    if (!parsed || typeof parsed !== 'object') {
      return error('INVALID_REQUEST', 'Request body must be an object', 400);
    }

    const body = parsed as Record<string, unknown>;
    const wpc = body.wpc;

    if (!isWorkPolicyContractV1(wpc)) {
      return error('INVALID_WPC', 'WPC does not match work_policy_contract.v1 shape', 400);
    }

    let canonical: string;
    try {
      canonical = jcsCanonicalize(wpc);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return error('INVALID_WPC', `Failed to canonicalize WPC (JCS): ${msg}`, 400);
    }

    const policy_hash_b64u = await sha256B64u(canonical);
    const storageKey = `${STORAGE_PREFIX}${policy_hash_b64u}`;

    return this.state.blockConcurrencyWhile(async () => {
      const existing = (await this.state.storage.get(storageKey)) as StoredWpc | undefined;
      if (existing?.envelope) {
        return json({
          ok: true,
          existed: true,
          policy_hash_b64u,
          envelope: existing.envelope,
        });
      }

      let privateKey: CryptoKey;
      let signerDidKey: string;
      try {
        privateKey = await this.getPrivateKey();
        signerDidKey = await this.getSignerDidKey();
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return error('SIGNING_NOT_CONFIGURED', msg, 503);
      }

      const issuedAt = new Date().toISOString();

      // payload_hash_b64u is the policy hash by definition:
      // sha256(JCS(payload)) as base64url
      const payload_hash_b64u = policy_hash_b64u;

      const signature_b64u = await signEd25519(privateKey, payload_hash_b64u);

      const envelope: SignedEnvelope<WorkPolicyContractV1> = {
        envelope_version: '1',
        envelope_type: 'work_policy_contract',
        payload: wpc,
        payload_hash_b64u,
        hash_algorithm: 'SHA-256',
        signature_b64u,
        algorithm: 'Ed25519',
        signer_did: signerDidKey,
        issued_at: issuedAt,
      };

      const stored: StoredWpc = {
        envelope,
        created_at: issuedAt,
      };

      await this.state.storage.put(storageKey, stored);

      return json(
        {
          ok: true,
          existed: false,
          policy_hash_b64u,
          envelope,
        },
        201,
      );
    });
  }

  private async handleGet(policyHash: string): Promise<Response> {
    const normalized = policyHash.trim();
    if (!normalized) {
      return error('INVALID_POLICY_HASH', 'policy_hash_b64u must be non-empty', 400);
    }

    if (!B64U_RE.test(normalized)) {
      return error('INVALID_POLICY_HASH', 'policy_hash_b64u must be base64url (no padding)', 400);
    }

    if (normalized.length !== SHA256_B64U_LEN) {
      return error('INVALID_POLICY_HASH', `policy_hash_b64u must be SHA-256 base64url length ${SHA256_B64U_LEN}`, 400);
    }

    const storageKey = `${STORAGE_PREFIX}${normalized}`;

    const stored = (await this.state.storage.get(storageKey)) as StoredWpc | undefined;
    if (!stored?.envelope) {
      return error('WPC_NOT_FOUND', 'WPC not found', 404);
    }

    // Safety check: ensure stored payload hashes back to the key.
    try {
      const canonical = jcsCanonicalize(stored.envelope.payload);
      const hash = await sha256B64u(canonical);
      if (hash !== normalized) {
        return error('WPC_CORRUPTED', 'Stored WPC hash mismatch', 500);
      }
    } catch {
      return error('WPC_CORRUPTED', 'Stored WPC canonicalization failed', 500);
    }

    return json({ ok: true, policy_hash_b64u: normalized, envelope: stored.envelope });
  }
}
