import {
  didKeyToEd25519PublicKeyBytes,
  importEd25519PublicKeyFromBytes,
  verifyEd25519,
} from './crypto';

export interface Env {
  CLAIM_VERSION: string;
  CLAIM_CHALLENGE_TTL_SECONDS?: string;

  // storage (optional bindings)
  CLAIM_STORE?: KVNamespace;
}

interface ChallengeRecord {
  challenge_id: string;
  did: string;
  nonce: string;
  message: string;
  issued_at: number;
  exp: number;
}

interface BindDidRequest {
  did: string;
  challenge_id: string;
  signature_b64u: string;
}

interface BindingRecord {
  did: string;
  active: boolean;
  bound_at: number;
  bound_at_iso: string;
  challenge_id: string;
}

function parseIntOrDefault(value: string | undefined, d: number): number {
  if (!value) return d;
  const n = Number.parseInt(value, 10);
  return Number.isFinite(n) ? n : d;
}

function jsonResponse(body: unknown, status = 200, extraHeaders?: HeadersInit): Response {
  const headers = new Headers(extraHeaders);
  headers.set('content-type', 'application/json; charset=utf-8');
  return new Response(JSON.stringify(body, null, 2), { status, headers });
}

function textResponse(body: string, contentType: string, status = 200, version?: string): Response {
  const headers = new Headers({ 'content-type': contentType });
  if (version) headers.set('X-Claim-Version', version);
  return new Response(body, { status, headers });
}

function errorResponse(code: string, message: string, status = 400): Response {
  return jsonResponse({ error: code, message }, status);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

function challengeKey(challengeId: string): string {
  return `challenge:${challengeId}`;
}

function bindingKey(did: string): string {
  return `binding:${did}`;
}

function makeChallengeMessage(options: { challengeId: string; nonce: string; exp: number }): string {
  const { challengeId, nonce, exp } = options;
  // A stable, unambiguous signing message.
  return `clawclaim:bind:v1:${challengeId}:${nonce}:${exp}`;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === 'GET' && url.pathname === '/health') {
      return jsonResponse({ status: 'ok', service: 'clawclaim', version: env.CLAIM_VERSION });
    }

    if (request.method === 'GET' && url.pathname === '/skill.md') {
      const md = `# clawclaim (DID binding)\n\nEndpoints:\n- GET /health\n- POST /v1/challenges\n- POST /v1/bind\n\nChallenge flow:\n1) POST /v1/challenges to get a message.\n2) Sign the message with your DID key.\n3) POST /v1/bind to bind the DID.\n\n`;
      return textResponse(md, 'text/markdown; charset=utf-8', 200, env.CLAIM_VERSION);
    }

    // CCL-US-001 — Challenge issuance
    if (request.method === 'POST' && url.pathname === '/v1/challenges') {
      const kv = env.CLAIM_STORE;
      if (!kv) {
        return errorResponse('STORE_NOT_CONFIGURED', 'CLAIM_STORE KV binding is not configured', 503);
      }

      let body: unknown;
      try {
        body = await request.json();
      } catch {
        return errorResponse('INVALID_JSON', 'Request body must be valid JSON', 400);
      }

      if (typeof body !== 'object' || body === null) {
        return errorResponse('INVALID_REQUEST', 'Request body must be a JSON object', 400);
      }

      const did = (body as Record<string, unknown>).did;
      if (!isNonEmptyString(did)) {
        return errorResponse('INVALID_REQUEST', 'did is required', 400);
      }

      const ttlSec = parseIntOrDefault(env.CLAIM_CHALLENGE_TTL_SECONDS, 600);
      const nowSec = Math.floor(Date.now() / 1000);
      const exp = nowSec + ttlSec;

      const challenge_id = crypto.randomUUID();
      const nonce = crypto.randomUUID();
      const message = makeChallengeMessage({ challengeId: challenge_id, nonce, exp });

      const record: ChallengeRecord = {
        challenge_id,
        did: did.trim(),
        nonce,
        message,
        issued_at: nowSec,
        exp,
      };

      await kv.put(challengeKey(challenge_id), JSON.stringify(record), { expirationTtl: ttlSec });

      return jsonResponse({
        challenge_id,
        did: record.did,
        nonce,
        message,
        expires_at: exp,
        expires_in_sec: ttlSec,
      });
    }

    // CCL-US-002 — Bind DID
    if (request.method === 'POST' && url.pathname === '/v1/bind') {
      const kv = env.CLAIM_STORE;
      if (!kv) {
        return errorResponse('STORE_NOT_CONFIGURED', 'CLAIM_STORE KV binding is not configured', 503);
      }

      let body: unknown;
      try {
        body = await request.json();
      } catch {
        return errorResponse('INVALID_JSON', 'Request body must be valid JSON', 400);
      }

      if (typeof body !== 'object' || body === null) {
        return errorResponse('INVALID_REQUEST', 'Request body must be a JSON object', 400);
      }

      const b = body as Record<string, unknown>;

      const did = b.did;
      const challenge_id = b.challenge_id;
      const signature_b64u = b.signature_b64u;

      if (!isNonEmptyString(did)) {
        return errorResponse('INVALID_REQUEST', 'did is required', 400);
      }
      if (!isNonEmptyString(challenge_id)) {
        return errorResponse('INVALID_REQUEST', 'challenge_id is required', 400);
      }
      if (!isNonEmptyString(signature_b64u)) {
        return errorResponse('INVALID_REQUEST', 'signature_b64u is required', 400);
      }

      const challengeRaw = await kv.get(challengeKey(challenge_id));
      if (!challengeRaw) {
        return errorResponse('CHALLENGE_NOT_FOUND', 'Challenge not found (or expired)', 404);
      }

      let challenge: ChallengeRecord;
      try {
        challenge = JSON.parse(challengeRaw) as ChallengeRecord;
      } catch {
        return errorResponse('CHALLENGE_CORRUPT', 'Stored challenge is corrupt', 500);
      }

      const didTrimmed = did.trim();
      if (challenge.did !== didTrimmed) {
        return errorResponse('CHALLENGE_DID_MISMATCH', 'Challenge DID does not match request DID', 400);
      }

      const nowSec = Math.floor(Date.now() / 1000);
      if (nowSec > challenge.exp) {
        return errorResponse('CHALLENGE_EXPIRED', 'Challenge has expired', 401);
      }

      let publicKeyBytes: Uint8Array;
      try {
        publicKeyBytes = didKeyToEd25519PublicKeyBytes(didTrimmed);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        if (msg === 'UNSUPPORTED_DID') {
          return errorResponse('UNSUPPORTED_DID', 'Only did:key is supported for now', 400);
        }
        return errorResponse('INVALID_DID', 'Invalid DID format', 400);
      }

      const publicKey = await importEd25519PublicKeyFromBytes(publicKeyBytes);

      let valid = false;
      try {
        valid = await verifyEd25519(publicKey, signature_b64u, challenge.message);
      } catch {
        valid = false;
      }

      if (!valid) {
        return errorResponse('SIGNATURE_INVALID', 'Signature verification failed', 401);
      }

      const existing = await kv.get(bindingKey(didTrimmed));
      if (existing) {
        return jsonResponse({ status: 'already_bound', did: didTrimmed });
      }

      const binding: BindingRecord = {
        did: didTrimmed,
        active: true,
        bound_at: nowSec,
        bound_at_iso: new Date(nowSec * 1000).toISOString(),
        challenge_id: challenge.challenge_id,
      };

      await kv.put(bindingKey(didTrimmed), JSON.stringify(binding));
      await kv.delete(challengeKey(challenge_id));

      return jsonResponse({ status: 'bound', ...binding });
    }

    return errorResponse('NOT_FOUND', 'Not found', 404);
  },
};
