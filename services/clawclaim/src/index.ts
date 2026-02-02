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

type ChallengePurpose = 'bind' | 'revoke';

interface ChallengeRecord {
  challenge_id: string;
  did: string;
  nonce: string;
  message: string;
  issued_at: number;
  exp: number;
  purpose?: ChallengePurpose;
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

  revoked_at?: number;
  revoked_at_iso?: string;
  revoked_reason?: string;
  revoked_challenge_id?: string;
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

const MAX_REVOCATION_REASON_LENGTH = 256;
// Maximum 10-digit Unix timestamp used to invert timestamps for newest-first KV sorting.
const MAX_TIMESTAMP_FOR_INVERSION = 9_999_999_999;

const BINDING_EVENT_PREFIX = 'events:bindings:';

function bindingEventKey(eventAtSec: number, type: string, did: string, id: string): string {
  const invTs = String(MAX_TIMESTAMP_FOR_INVERSION - eventAtSec).padStart(10, '0');
  return `${BINDING_EVENT_PREFIX}${invTs}:${type}:${did}:${id}`;
}

function makeChallengeMessage(options: {
  purpose: ChallengePurpose;
  challengeId: string;
  nonce: string;
  exp: number;
}): string {
  const { purpose, challengeId, nonce, exp } = options;
  // A stable, unambiguous signing message.
  return `clawclaim:${purpose}:v1:${challengeId}:${nonce}:${exp}`;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === 'GET' && url.pathname === '/health') {
      return jsonResponse({ status: 'ok', service: 'clawclaim', version: env.CLAIM_VERSION });
    }

    if (request.method === 'GET' && url.pathname === '/skill.md') {
      const md = `# clawclaim (DID binding)\n\nEndpoints:\n- GET /health\n- POST /v1/challenges (purpose: bind|revoke)\n- POST /v1/bind\n- POST /v1/bindings/revoke\n\nBind flow:\n1) POST /v1/challenges { did } to get a message.\n2) Sign the message with your DID key.\n3) POST /v1/bind.\n\nRevoke flow:\n1) POST /v1/challenges { did, purpose: \"revoke\" } to get a message.\n2) Sign the message with your DID key.\n3) POST /v1/bindings/revoke.\n\n`;
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

      const purposeRaw = (body as Record<string, unknown>).purpose;
      const purpose =
        purposeRaw === undefined
          ? ('bind' as const)
          : typeof purposeRaw === 'string'
            ? purposeRaw.trim()
            : '';

      if (purpose !== 'bind' && purpose !== 'revoke') {
        return errorResponse('INVALID_REQUEST', 'purpose must be "bind" or "revoke"', 400);
      }

      const didTrimmed = did.trim();
      if (purpose === 'bind') {
        const existingRaw = await kv.get(bindingKey(didTrimmed));
        if (existingRaw) {
          try {
            const existing = JSON.parse(existingRaw) as BindingRecord;
            if (existing && typeof existing === 'object' && existing.active === false) {
              return errorResponse('BINDING_REVOKED', 'Binding has been revoked', 403);
            }
          } catch {
            // ignore parse errors; binding record may be legacy/unknown
          }
        }
      }

      const ttlSec = parseIntOrDefault(env.CLAIM_CHALLENGE_TTL_SECONDS, 600);
      const nowSec = Math.floor(Date.now() / 1000);
      const exp = nowSec + ttlSec;

      const challenge_id = crypto.randomUUID();
      const nonce = crypto.randomUUID();
      const message = makeChallengeMessage({ purpose, challengeId: challenge_id, nonce, exp });

      const record: ChallengeRecord = {
        challenge_id,
        did: didTrimmed,
        nonce,
        message,
        issued_at: nowSec,
        exp,
        purpose,
      };

      await kv.put(challengeKey(challenge_id), JSON.stringify(record), { expirationTtl: ttlSec });

      return jsonResponse({
        challenge_id,
        purpose,
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

      const challengePurpose = challenge.purpose ?? 'bind';
      if (challengePurpose !== 'bind') {
        return errorResponse('CHALLENGE_PURPOSE_MISMATCH', 'Challenge purpose must be "bind"', 400);
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

      const existingRaw = await kv.get(bindingKey(didTrimmed));
      if (existingRaw) {
        try {
          const existing = JSON.parse(existingRaw) as BindingRecord;
          if (existing && typeof existing === 'object' && existing.active === false) {
            return errorResponse('BINDING_REVOKED', 'Binding has been revoked', 403);
          }
        } catch {
          // ignore parse errors
        }

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

    // CCL-US-003 — Revoke binding
    if (request.method === 'POST' && url.pathname === '/v1/bindings/revoke') {
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
      const reason =
        typeof b.reason === 'string' ? b.reason.trim().slice(0, MAX_REVOCATION_REASON_LENGTH) : undefined;

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

      const challengePurpose = challenge.purpose ?? 'bind';
      if (challengePurpose !== 'revoke') {
        return errorResponse('CHALLENGE_PURPOSE_MISMATCH', 'Challenge purpose must be "revoke"', 400);
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

      const bindingRaw = await kv.get(bindingKey(didTrimmed));
      if (!bindingRaw) {
        return errorResponse('BINDING_NOT_FOUND', 'Binding not found', 404);
      }

      let binding: BindingRecord;
      try {
        binding = JSON.parse(bindingRaw) as BindingRecord;
      } catch {
        return errorResponse('BINDING_CORRUPT', 'Stored binding is corrupt', 500);
      }

      if (binding && typeof binding === 'object' && binding.active === false) {
        await kv.delete(challengeKey(challenge_id));
        return jsonResponse({
          status: 'already_revoked',
          did: didTrimmed,
          revoked_at: binding.revoked_at ?? null,
          revoked_at_iso: binding.revoked_at_iso ?? null,
        });
      }

      const revokedAtSec = nowSec;
      const revokedAtIso = new Date(revokedAtSec * 1000).toISOString();

      const updated: BindingRecord = {
        ...binding,
        did: didTrimmed,
        active: false,
        revoked_at: revokedAtSec,
        revoked_at_iso: revokedAtIso,
        revoked_reason: reason,
        revoked_challenge_id: challenge.challenge_id,
      };

      await kv.put(bindingKey(didTrimmed), JSON.stringify(updated));
      await kv.delete(challengeKey(challenge_id));

      const event = {
        type: 'binding_revoked',
        did: didTrimmed,
        revoked_at: revokedAtSec,
        revoked_at_iso: revokedAtIso,
        reason,
        challenge_id: challenge.challenge_id,
      };

      const eventKey = bindingEventKey(revokedAtSec, 'revoke', didTrimmed, challenge.challenge_id);
      await kv.put(eventKey, JSON.stringify(event));

      return jsonResponse({
        status: 'revoked',
        did: didTrimmed,
        revoked_at: revokedAtSec,
        revoked_at_iso: revokedAtIso,
        event_key: eventKey,
      });
    }

    return errorResponse('NOT_FOUND', 'Not found', 404);
  },
};
