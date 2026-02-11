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

type ChallengePurpose =
  | 'bind'
  | 'revoke'
  | 'register_controller'
  | 'register_agent'
  | 'update_sensitive_policy';

interface ChallengeRecord {
  challenge_id: string;
  did: string;
  nonce: string;
  message: string;
  issued_at: number;
  exp: number;
  purpose?: ChallengePurpose;
  controller_did?: string;
  agent_did?: string;
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

interface SensitiveAuthorizationPolicyRecord {
  policy_version: '1';
  mode: 'owner_bound';
  owner_did: string;
  allowed_sensitive_scopes: string[];
  policy_hash_b64u: string;
  updated_at: number;
  updated_at_iso: string;
}

interface ControllerRecord {
  controller_did: string;
  owner_did: string;
  active: boolean;
  registered_at: number;
  registered_at_iso: string;
  last_challenge_id: string;
  policy: SensitiveAuthorizationPolicyRecord;
}

interface ControllerAgentRecord {
  binding_version: '1';
  controller_did: string;
  agent_did: string;
  owner_did: string;
  active: boolean;
  registered_at: number;
  registered_at_iso: string;
  last_challenge_id: string;
  policy_hash_b64u: string;
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

function controllerKey(controllerDid: string): string {
  return `control-plane:controller:${controllerDid}`;
}

function controllerAgentKey(controllerDid: string, agentDid: string): string {
  return `control-plane:controller-agent:${controllerDid}:${agentDid}`;
}

function controllerAgentPrefix(controllerDid: string): string {
  return `control-plane:controller-agent:${controllerDid}:`;
}

const MAX_REVOCATION_REASON_LENGTH = 256;
const MAX_SCOPE_ITEMS = 64;
const MAX_SCOPE_ITEM_LENGTH = 128;
const DEFAULT_SENSITIVE_SCOPES = [
  'control:token:issue_sensitive',
  'control:token:revoke',
  'control:key:rotate',
  'control:policy:update',
] as const;
// Maximum 10-digit Unix timestamp used to invert timestamps for newest-first KV sorting.
const MAX_TIMESTAMP_FOR_INVERSION = 9_999_999_999;

const BINDING_EVENT_PREFIX = 'events:bindings:';
const CONTROL_PLANE_EVENT_PREFIX = 'events:control-plane:';

function bindingEventKey(eventAtSec: number, type: string, did: string, id: string): string {
  const invTs = String(MAX_TIMESTAMP_FOR_INVERSION - eventAtSec).padStart(10, '0');
  return `${BINDING_EVENT_PREFIX}${invTs}:${type}:${did}:${id}`;
}

function controlPlaneEventKey(eventAtSec: number, type: string, ownerDid: string, id: string): string {
  const invTs = String(MAX_TIMESTAMP_FOR_INVERSION - eventAtSec).padStart(10, '0');
  return `${CONTROL_PLANE_EVENT_PREFIX}${invTs}:${type}:${ownerDid}:${id}`;
}

function makeChallengeMessage(options: {
  purpose: ChallengePurpose;
  challengeId: string;
  nonce: string;
  exp: number;
  did?: string;
  controllerDid?: string;
  agentDid?: string;
}): string {
  const { purpose, challengeId, nonce, exp, did, controllerDid, agentDid } = options;

  if (purpose === 'bind' || purpose === 'revoke') {
    // Preserve legacy challenge message format for existing bind/revoke clients.
    return `clawclaim:${purpose}:v1:${challengeId}:${nonce}:${exp}`;
  }

  const didPart = did?.trim().length ? did.trim() : '-';
  const controllerPart = controllerDid?.trim().length ? controllerDid.trim() : '-';
  const agentPart = agentDid?.trim().length ? agentDid.trim() : '-';
  // A stable, unambiguous signing message for control-plane actions.
  return `clawclaim:${purpose}:v1:${challengeId}:${didPart}:${controllerPart}:${agentPart}:${nonce}:${exp}`;
}

function normalizeSensitiveScopes(input: unknown): string[] | null {
  if (input === undefined || input === null) {
    return [...DEFAULT_SENSITIVE_SCOPES];
  }

  if (!Array.isArray(input)) return null;

  const out: string[] = [];
  for (const raw of input) {
    if (typeof raw !== 'string') return null;
    const scope = raw.trim();
    if (!scope || scope.length > MAX_SCOPE_ITEM_LENGTH) return null;
    if (!scope.startsWith('control:')) return null;
    out.push(scope);
  }

  const deduped = Array.from(new Set(out)).sort();
  if (deduped.length === 0 || deduped.length > MAX_SCOPE_ITEMS) return null;
  return deduped;
}

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  const base64 = btoa(binary);
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

async function sha256B64uText(text: string): Promise<string> {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return base64UrlEncode(new Uint8Array(digest));
}

async function buildSensitiveAuthorizationPolicy(
  ownerDid: string,
  scopesInput: unknown,
  nowSec: number
): Promise<SensitiveAuthorizationPolicyRecord | null> {
  const scopes = normalizeSensitiveScopes(scopesInput);
  if (!scopes) return null;

  const canonical = JSON.stringify({
    policy_version: '1',
    mode: 'owner_bound',
    owner_did: ownerDid,
    allowed_sensitive_scopes: scopes,
  });

  const policyHash = await sha256B64uText(canonical);

  return {
    policy_version: '1',
    mode: 'owner_bound',
    owner_did: ownerDid,
    allowed_sensitive_scopes: scopes,
    policy_hash_b64u: policyHash,
    updated_at: nowSec,
    updated_at_iso: new Date(nowSec * 1000).toISOString(),
  };
}

async function getActiveBinding(kv: KVNamespace, did: string): Promise<BindingRecord | null> {
  const raw = await kv.get(bindingKey(did));
  if (!raw) return null;

  try {
    const parsed = JSON.parse(raw) as BindingRecord;
    if (parsed && typeof parsed === 'object' && parsed.active === true) {
      return parsed;
    }
    return null;
  } catch {
    return null;
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === 'GET' && url.pathname === '/health') {
      return jsonResponse({ status: 'ok', service: 'clawclaim', version: env.CLAIM_VERSION });
    }

    if (request.method === 'GET' && url.pathname === '/skill.md') {
      const md = `# clawclaim (identity control plane)\n\nEndpoints:\n- GET /health\n- POST /v1/challenges (purpose: bind|revoke)\n- POST /v1/bind\n- POST /v1/bindings/revoke\n- POST /v1/control-plane/challenges\n- POST /v1/control-plane/controllers/register\n- POST /v1/control-plane/controllers/{controller_did}/agents/register\n- POST /v1/control-plane/controllers/{controller_did}/sensitive-policy\n- GET /v1/control-plane/controllers/{controller_did}\n- GET /v1/control-plane/controllers/{controller_did}/agents\n- GET /v1/control-plane/controllers/{controller_did}/agents/{agent_did}\n\nBind flow:\n1) POST /v1/challenges { did } to get a message.\n2) Sign the message with your DID key.\n3) POST /v1/bind.\n\nControl-plane flow:\n1) Owner DID + controller/agent DIDs must be active bindings.\n2) POST /v1/control-plane/challenges for controller action messages.\n3) Owner signs challenge message, then submit registration/policy mutation endpoint.\n\n`;
      return textResponse(md, 'text/markdown; charset=utf-8', 200, env.CLAIM_VERSION);
    }

    // ICP-US-001 — Control-plane challenge issuance (owner signed)
    if (request.method === 'POST' && url.pathname === '/v1/control-plane/challenges') {
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
      const ownerDid = typeof b.owner_did === 'string' ? b.owner_did.trim() : '';
      const controllerDid = typeof b.controller_did === 'string' ? b.controller_did.trim() : '';
      const agentDid = typeof b.agent_did === 'string' ? b.agent_did.trim() : '';
      const purpose = typeof b.purpose === 'string' ? b.purpose.trim() : '';

      if (!ownerDid) {
        return errorResponse('INVALID_REQUEST', 'owner_did is required', 400);
      }

      if (
        purpose !== 'register_controller' &&
        purpose !== 'register_agent' &&
        purpose !== 'update_sensitive_policy'
      ) {
        return errorResponse(
          'INVALID_REQUEST',
          'purpose must be "register_controller", "register_agent", or "update_sensitive_policy"',
          400
        );
      }

      if (purpose === 'register_controller' && !controllerDid) {
        return errorResponse('INVALID_REQUEST', 'controller_did is required for register_controller', 400);
      }

      if (purpose === 'register_agent' && (!controllerDid || !agentDid)) {
        return errorResponse(
          'INVALID_REQUEST',
          'controller_did and agent_did are required for register_agent',
          400
        );
      }

      if (purpose === 'update_sensitive_policy' && !controllerDid) {
        return errorResponse('INVALID_REQUEST', 'controller_did is required for update_sensitive_policy', 400);
      }

      const ownerBinding = await getActiveBinding(kv, ownerDid);
      if (!ownerBinding) {
        return errorResponse('OWNER_BINDING_REQUIRED', 'owner_did must be an active binding', 403);
      }

      if (purpose === 'register_agent' || purpose === 'update_sensitive_policy') {
        const controllerRaw = await kv.get(controllerKey(controllerDid));
        if (!controllerRaw) {
          return errorResponse('CONTROLLER_NOT_FOUND', 'Controller is not registered', 404);
        }

        let controller: ControllerRecord;
        try {
          controller = JSON.parse(controllerRaw) as ControllerRecord;
        } catch {
          return errorResponse('CONTROLLER_RECORD_CORRUPT', 'Stored controller record is corrupt', 500);
        }

        if (controller.active !== true) {
          return errorResponse('CONTROLLER_INACTIVE', 'Controller is inactive', 403);
        }

        if (controller.owner_did !== ownerDid) {
          return errorResponse('CONTROLLER_OWNER_MISMATCH', 'owner_did does not control this controller', 403);
        }
      }

      const ttlSec = parseIntOrDefault(env.CLAIM_CHALLENGE_TTL_SECONDS, 600);
      const nowSec = Math.floor(Date.now() / 1000);
      const exp = nowSec + ttlSec;

      const challenge_id = crypto.randomUUID();
      const nonce = crypto.randomUUID();
      const message = makeChallengeMessage({
        purpose: purpose as ChallengePurpose,
        challengeId: challenge_id,
        nonce,
        exp,
        did: ownerDid,
        controllerDid: controllerDid || undefined,
        agentDid: agentDid || undefined,
      });

      const record: ChallengeRecord = {
        challenge_id,
        did: ownerDid,
        controller_did: controllerDid || undefined,
        agent_did: agentDid || undefined,
        nonce,
        message,
        issued_at: nowSec,
        exp,
        purpose: purpose as ChallengePurpose,
      };

      await kv.put(challengeKey(challenge_id), JSON.stringify(record), { expirationTtl: ttlSec });

      return jsonResponse({
        challenge_id,
        purpose,
        owner_did: ownerDid,
        controller_did: controllerDid || null,
        agent_did: agentDid || null,
        nonce,
        message,
        expires_at: exp,
        expires_in_sec: ttlSec,
      });
    }

    // ICP-US-001 — Controller registration
    if (request.method === 'POST' && url.pathname === '/v1/control-plane/controllers/register') {
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
      const ownerDid = typeof b.owner_did === 'string' ? b.owner_did.trim() : '';
      const controllerDid = typeof b.controller_did === 'string' ? b.controller_did.trim() : '';
      const challengeId = typeof b.challenge_id === 'string' ? b.challenge_id.trim() : '';
      const signatureB64u = typeof b.signature_b64u === 'string' ? b.signature_b64u.trim() : '';

      if (!ownerDid || !controllerDid || !challengeId || !signatureB64u) {
        return errorResponse(
          'INVALID_REQUEST',
          'owner_did, controller_did, challenge_id, and signature_b64u are required',
          400
        );
      }

      const challengeRaw = await kv.get(challengeKey(challengeId));
      if (!challengeRaw) {
        return errorResponse('CHALLENGE_NOT_FOUND', 'Challenge not found (or expired)', 404);
      }

      let challenge: ChallengeRecord;
      try {
        challenge = JSON.parse(challengeRaw) as ChallengeRecord;
      } catch {
        return errorResponse('CHALLENGE_CORRUPT', 'Stored challenge is corrupt', 500);
      }

      if (challenge.purpose !== 'register_controller') {
        return errorResponse(
          'CHALLENGE_PURPOSE_MISMATCH',
          'Challenge purpose must be "register_controller"',
          400
        );
      }

      if (challenge.did !== ownerDid || challenge.controller_did !== controllerDid) {
        return errorResponse('CHALLENGE_CONTEXT_MISMATCH', 'Challenge context does not match request', 400);
      }

      const nowSec = Math.floor(Date.now() / 1000);
      if (nowSec > challenge.exp) {
        return errorResponse('CHALLENGE_EXPIRED', 'Challenge has expired', 401);
      }

      const ownerBinding = await getActiveBinding(kv, ownerDid);
      if (!ownerBinding) {
        return errorResponse('OWNER_BINDING_REQUIRED', 'owner_did must be an active binding', 403);
      }

      const controllerBinding = await getActiveBinding(kv, controllerDid);
      if (!controllerBinding) {
        return errorResponse('CONTROLLER_BINDING_REQUIRED', 'controller_did must be an active binding', 403);
      }

      let publicKeyBytes: Uint8Array;
      try {
        publicKeyBytes = didKeyToEd25519PublicKeyBytes(ownerDid);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        if (msg === 'UNSUPPORTED_DID') {
          return errorResponse('UNSUPPORTED_DID', 'Only did:key is supported for now', 400);
        }
        return errorResponse('INVALID_DID', 'Invalid owner_did format', 400);
      }

      const publicKey = await importEd25519PublicKeyFromBytes(publicKeyBytes);

      let valid = false;
      try {
        valid = await verifyEd25519(publicKey, signatureB64u, challenge.message);
      } catch {
        valid = false;
      }

      if (!valid) {
        return errorResponse('SIGNATURE_INVALID', 'Signature verification failed', 401);
      }

      const existingRaw = await kv.get(controllerKey(controllerDid));
      if (existingRaw) {
        try {
          const existing = JSON.parse(existingRaw) as ControllerRecord;
          if (existing.owner_did !== ownerDid) {
            return errorResponse(
              'CONTROLLER_OWNER_MISMATCH',
              'controller_did is already registered to a different owner',
              409
            );
          }

          await kv.delete(challengeKey(challengeId));
          return jsonResponse({ status: 'already_registered', controller: existing });
        } catch {
          return errorResponse('CONTROLLER_RECORD_CORRUPT', 'Stored controller record is corrupt', 500);
        }
      }

      const policy = await buildSensitiveAuthorizationPolicy(ownerDid, b.allowed_sensitive_scopes, nowSec);
      if (!policy) {
        return errorResponse(
          'INVALID_SENSITIVE_POLICY',
          `allowed_sensitive_scopes must be a non-empty array of control:* scopes (<=${MAX_SCOPE_ITEMS} items, <=${MAX_SCOPE_ITEM_LENGTH} chars each)`,
          400
        );
      }

      const controller: ControllerRecord = {
        controller_did: controllerDid,
        owner_did: ownerDid,
        active: true,
        registered_at: nowSec,
        registered_at_iso: new Date(nowSec * 1000).toISOString(),
        last_challenge_id: challenge.challenge_id,
        policy,
      };

      await kv.put(controllerKey(controllerDid), JSON.stringify(controller));
      await kv.delete(challengeKey(challengeId));

      const event = {
        type: 'controller_registered',
        owner_did: ownerDid,
        controller_did: controllerDid,
        policy_hash_b64u: policy.policy_hash_b64u,
        occurred_at: nowSec,
        occurred_at_iso: new Date(nowSec * 1000).toISOString(),
      };

      const eventKey = controlPlaneEventKey(nowSec, 'controller-register', ownerDid, challenge.challenge_id);
      await kv.put(eventKey, JSON.stringify(event));

      return jsonResponse({
        status: 'registered',
        controller,
        event_key: eventKey,
      });
    }

    const registerAgentMatch = /^\/v1\/control-plane\/controllers\/([^/]+)\/agents\/register$/.exec(url.pathname);
    if (request.method === 'POST' && registerAgentMatch) {
      const kv = env.CLAIM_STORE;
      if (!kv) {
        return errorResponse('STORE_NOT_CONFIGURED', 'CLAIM_STORE KV binding is not configured', 503);
      }

      const controllerDid = decodeURIComponent(registerAgentMatch[1]!);

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
      const ownerDid = typeof b.owner_did === 'string' ? b.owner_did.trim() : '';
      const agentDid = typeof b.agent_did === 'string' ? b.agent_did.trim() : '';
      const challengeId = typeof b.challenge_id === 'string' ? b.challenge_id.trim() : '';
      const signatureB64u = typeof b.signature_b64u === 'string' ? b.signature_b64u.trim() : '';

      if (!ownerDid || !agentDid || !challengeId || !signatureB64u) {
        return errorResponse(
          'INVALID_REQUEST',
          'owner_did, agent_did, challenge_id, and signature_b64u are required',
          400
        );
      }

      const challengeRaw = await kv.get(challengeKey(challengeId));
      if (!challengeRaw) {
        return errorResponse('CHALLENGE_NOT_FOUND', 'Challenge not found (or expired)', 404);
      }

      let challenge: ChallengeRecord;
      try {
        challenge = JSON.parse(challengeRaw) as ChallengeRecord;
      } catch {
        return errorResponse('CHALLENGE_CORRUPT', 'Stored challenge is corrupt', 500);
      }

      if (challenge.purpose !== 'register_agent') {
        return errorResponse('CHALLENGE_PURPOSE_MISMATCH', 'Challenge purpose must be "register_agent"', 400);
      }

      if (
        challenge.did !== ownerDid ||
        challenge.controller_did !== controllerDid ||
        challenge.agent_did !== agentDid
      ) {
        return errorResponse('CHALLENGE_CONTEXT_MISMATCH', 'Challenge context does not match request', 400);
      }

      const nowSec = Math.floor(Date.now() / 1000);
      if (nowSec > challenge.exp) {
        return errorResponse('CHALLENGE_EXPIRED', 'Challenge has expired', 401);
      }

      const ownerBinding = await getActiveBinding(kv, ownerDid);
      if (!ownerBinding) {
        return errorResponse('OWNER_BINDING_REQUIRED', 'owner_did must be an active binding', 403);
      }

      const agentBinding = await getActiveBinding(kv, agentDid);
      if (!agentBinding) {
        return errorResponse('AGENT_BINDING_REQUIRED', 'agent_did must be an active binding', 403);
      }

      const controllerRaw = await kv.get(controllerKey(controllerDid));
      if (!controllerRaw) {
        return errorResponse('CONTROLLER_NOT_FOUND', 'Controller is not registered', 404);
      }

      let controller: ControllerRecord;
      try {
        controller = JSON.parse(controllerRaw) as ControllerRecord;
      } catch {
        return errorResponse('CONTROLLER_RECORD_CORRUPT', 'Stored controller record is corrupt', 500);
      }

      if (controller.active !== true) {
        return errorResponse('CONTROLLER_INACTIVE', 'Controller is inactive', 403);
      }

      if (controller.owner_did !== ownerDid) {
        return errorResponse('CONTROLLER_OWNER_MISMATCH', 'owner_did does not control this controller', 403);
      }

      let publicKeyBytes: Uint8Array;
      try {
        publicKeyBytes = didKeyToEd25519PublicKeyBytes(ownerDid);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        if (msg === 'UNSUPPORTED_DID') {
          return errorResponse('UNSUPPORTED_DID', 'Only did:key is supported for now', 400);
        }
        return errorResponse('INVALID_DID', 'Invalid owner_did format', 400);
      }

      const publicKey = await importEd25519PublicKeyFromBytes(publicKeyBytes);

      let valid = false;
      try {
        valid = await verifyEd25519(publicKey, signatureB64u, challenge.message);
      } catch {
        valid = false;
      }

      if (!valid) {
        return errorResponse('SIGNATURE_INVALID', 'Signature verification failed', 401);
      }

      const bindingRecordKey = controllerAgentKey(controllerDid, agentDid);
      const existingRaw = await kv.get(bindingRecordKey);
      if (existingRaw) {
        try {
          const existing = JSON.parse(existingRaw) as ControllerAgentRecord;
          if (existing.owner_did !== ownerDid) {
            return errorResponse(
              'CONTROLLER_AGENT_OWNER_MISMATCH',
              'Agent binding already exists with a different owner',
              409
            );
          }

          await kv.delete(challengeKey(challengeId));
          return jsonResponse({ status: 'already_registered', binding: existing });
        } catch {
          return errorResponse('CONTROLLER_AGENT_RECORD_CORRUPT', 'Stored controller-agent record is corrupt', 500);
        }
      }

      const agentBindingRecord: ControllerAgentRecord = {
        binding_version: '1',
        controller_did: controllerDid,
        agent_did: agentDid,
        owner_did: ownerDid,
        active: true,
        registered_at: nowSec,
        registered_at_iso: new Date(nowSec * 1000).toISOString(),
        last_challenge_id: challenge.challenge_id,
        policy_hash_b64u: controller.policy.policy_hash_b64u,
      };

      await kv.put(bindingRecordKey, JSON.stringify(agentBindingRecord));
      await kv.delete(challengeKey(challengeId));

      const event = {
        type: 'controller_agent_registered',
        owner_did: ownerDid,
        controller_did: controllerDid,
        agent_did: agentDid,
        policy_hash_b64u: controller.policy.policy_hash_b64u,
        occurred_at: nowSec,
        occurred_at_iso: new Date(nowSec * 1000).toISOString(),
      };

      const eventKey = controlPlaneEventKey(nowSec, 'agent-register', ownerDid, challenge.challenge_id);
      await kv.put(eventKey, JSON.stringify(event));

      return jsonResponse({ status: 'registered', binding: agentBindingRecord, event_key: eventKey });
    }

    const updatePolicyMatch = /^\/v1\/control-plane\/controllers\/([^/]+)\/sensitive-policy$/.exec(url.pathname);
    if (request.method === 'POST' && updatePolicyMatch) {
      const kv = env.CLAIM_STORE;
      if (!kv) {
        return errorResponse('STORE_NOT_CONFIGURED', 'CLAIM_STORE KV binding is not configured', 503);
      }

      const controllerDid = decodeURIComponent(updatePolicyMatch[1]!);

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
      const ownerDid = typeof b.owner_did === 'string' ? b.owner_did.trim() : '';
      const challengeId = typeof b.challenge_id === 'string' ? b.challenge_id.trim() : '';
      const signatureB64u = typeof b.signature_b64u === 'string' ? b.signature_b64u.trim() : '';

      if (!ownerDid || !challengeId || !signatureB64u) {
        return errorResponse(
          'INVALID_REQUEST',
          'owner_did, challenge_id, and signature_b64u are required',
          400
        );
      }

      const challengeRaw = await kv.get(challengeKey(challengeId));
      if (!challengeRaw) {
        return errorResponse('CHALLENGE_NOT_FOUND', 'Challenge not found (or expired)', 404);
      }

      let challenge: ChallengeRecord;
      try {
        challenge = JSON.parse(challengeRaw) as ChallengeRecord;
      } catch {
        return errorResponse('CHALLENGE_CORRUPT', 'Stored challenge is corrupt', 500);
      }

      if (challenge.purpose !== 'update_sensitive_policy') {
        return errorResponse(
          'CHALLENGE_PURPOSE_MISMATCH',
          'Challenge purpose must be "update_sensitive_policy"',
          400
        );
      }

      if (challenge.did !== ownerDid || challenge.controller_did !== controllerDid) {
        return errorResponse('CHALLENGE_CONTEXT_MISMATCH', 'Challenge context does not match request', 400);
      }

      const nowSec = Math.floor(Date.now() / 1000);
      if (nowSec > challenge.exp) {
        return errorResponse('CHALLENGE_EXPIRED', 'Challenge has expired', 401);
      }

      const ownerBinding = await getActiveBinding(kv, ownerDid);
      if (!ownerBinding) {
        return errorResponse('OWNER_BINDING_REQUIRED', 'owner_did must be an active binding', 403);
      }

      const controllerRaw = await kv.get(controllerKey(controllerDid));
      if (!controllerRaw) {
        return errorResponse('CONTROLLER_NOT_FOUND', 'Controller is not registered', 404);
      }

      let controller: ControllerRecord;
      try {
        controller = JSON.parse(controllerRaw) as ControllerRecord;
      } catch {
        return errorResponse('CONTROLLER_RECORD_CORRUPT', 'Stored controller record is corrupt', 500);
      }

      if (controller.active !== true) {
        return errorResponse('CONTROLLER_INACTIVE', 'Controller is inactive', 403);
      }

      if (controller.owner_did !== ownerDid) {
        return errorResponse('CONTROLLER_OWNER_MISMATCH', 'owner_did does not control this controller', 403);
      }

      let publicKeyBytes: Uint8Array;
      try {
        publicKeyBytes = didKeyToEd25519PublicKeyBytes(ownerDid);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        if (msg === 'UNSUPPORTED_DID') {
          return errorResponse('UNSUPPORTED_DID', 'Only did:key is supported for now', 400);
        }
        return errorResponse('INVALID_DID', 'Invalid owner_did format', 400);
      }

      const publicKey = await importEd25519PublicKeyFromBytes(publicKeyBytes);

      let valid = false;
      try {
        valid = await verifyEd25519(publicKey, signatureB64u, challenge.message);
      } catch {
        valid = false;
      }

      if (!valid) {
        return errorResponse('SIGNATURE_INVALID', 'Signature verification failed', 401);
      }

      const policy = await buildSensitiveAuthorizationPolicy(ownerDid, b.allowed_sensitive_scopes, nowSec);
      if (!policy) {
        return errorResponse(
          'INVALID_SENSITIVE_POLICY',
          `allowed_sensitive_scopes must be a non-empty array of control:* scopes (<=${MAX_SCOPE_ITEMS} items, <=${MAX_SCOPE_ITEM_LENGTH} chars each)`,
          400
        );
      }

      const updatedController: ControllerRecord = {
        ...controller,
        owner_did: ownerDid,
        last_challenge_id: challenge.challenge_id,
        policy,
      };

      await kv.put(controllerKey(controllerDid), JSON.stringify(updatedController));
      await kv.delete(challengeKey(challengeId));

      const event = {
        type: 'controller_policy_updated',
        owner_did: ownerDid,
        controller_did: controllerDid,
        policy_hash_b64u: policy.policy_hash_b64u,
        occurred_at: nowSec,
        occurred_at_iso: new Date(nowSec * 1000).toISOString(),
      };

      const eventKey = controlPlaneEventKey(nowSec, 'policy-update', ownerDid, challenge.challenge_id);
      await kv.put(eventKey, JSON.stringify(event));

      return jsonResponse({
        status: 'updated',
        controller: updatedController,
        event_key: eventKey,
      });
    }

    const getControllerAgentMatch = /^\/v1\/control-plane\/controllers\/([^/]+)\/agents\/([^/]+)$/.exec(url.pathname);
    if (request.method === 'GET' && getControllerAgentMatch) {
      const kv = env.CLAIM_STORE;
      if (!kv) {
        return errorResponse('STORE_NOT_CONFIGURED', 'CLAIM_STORE KV binding is not configured', 503);
      }

      const controllerDid = decodeURIComponent(getControllerAgentMatch[1]!);
      const agentDid = decodeURIComponent(getControllerAgentMatch[2]!);

      const controllerRaw = await kv.get(controllerKey(controllerDid));
      if (!controllerRaw) {
        return errorResponse('CONTROLLER_NOT_FOUND', 'Controller is not registered', 404);
      }

      let controller: ControllerRecord;
      try {
        controller = JSON.parse(controllerRaw) as ControllerRecord;
      } catch {
        return errorResponse('CONTROLLER_RECORD_CORRUPT', 'Stored controller record is corrupt', 500);
      }

      const bindingRaw = await kv.get(controllerAgentKey(controllerDid, agentDid));
      if (!bindingRaw) {
        return errorResponse('CONTROLLER_AGENT_NOT_FOUND', 'Agent is not registered under controller', 404);
      }

      let binding: ControllerAgentRecord;
      try {
        binding = JSON.parse(bindingRaw) as ControllerAgentRecord;
      } catch {
        return errorResponse('CONTROLLER_AGENT_RECORD_CORRUPT', 'Stored controller-agent record is corrupt', 500);
      }

      return jsonResponse({
        status: 'ok',
        owner_did: controller.owner_did,
        controller,
        agent_binding: binding,
        chain: {
          owner_did: controller.owner_did,
          controller_did: controller.controller_did,
          agent_did: binding.agent_did,
          policy_hash_b64u: controller.policy.policy_hash_b64u,
          active: controller.active === true && binding.active === true,
        },
      });
    }

    const listControllerAgentsMatch = /^\/v1\/control-plane\/controllers\/([^/]+)\/agents$/.exec(url.pathname);
    if (request.method === 'GET' && listControllerAgentsMatch) {
      const kv = env.CLAIM_STORE;
      if (!kv) {
        return errorResponse('STORE_NOT_CONFIGURED', 'CLAIM_STORE KV binding is not configured', 503);
      }

      const controllerDid = decodeURIComponent(listControllerAgentsMatch[1]!);
      const limit = Math.min(Math.max(parseIntOrDefault(url.searchParams.get('limit') ?? undefined, 50), 1), 200);
      const cursor = url.searchParams.get('cursor') ?? undefined;

      const controllerRaw = await kv.get(controllerKey(controllerDid));
      if (!controllerRaw) {
        return errorResponse('CONTROLLER_NOT_FOUND', 'Controller is not registered', 404);
      }

      const list = await kv.list({ prefix: controllerAgentPrefix(controllerDid), limit, cursor });
      const bindings: ControllerAgentRecord[] = [];

      for (const key of list.keys) {
        const raw = await kv.get(key.name);
        if (!raw) continue;

        try {
          bindings.push(JSON.parse(raw) as ControllerAgentRecord);
        } catch {
          // skip corrupt records in list output
        }
      }

      return jsonResponse({
        controller_did: controllerDid,
        bindings,
        cursor: 'cursor' in list ? list.cursor : null,
        list_complete: list.list_complete,
      });
    }

    const getControllerMatch = /^\/v1\/control-plane\/controllers\/([^/]+)$/.exec(url.pathname);
    if (request.method === 'GET' && getControllerMatch) {
      const kv = env.CLAIM_STORE;
      if (!kv) {
        return errorResponse('STORE_NOT_CONFIGURED', 'CLAIM_STORE KV binding is not configured', 503);
      }

      const controllerDid = decodeURIComponent(getControllerMatch[1]!);
      const controllerRaw = await kv.get(controllerKey(controllerDid));
      if (!controllerRaw) {
        return errorResponse('CONTROLLER_NOT_FOUND', 'Controller is not registered', 404);
      }

      let controller: ControllerRecord;
      try {
        controller = JSON.parse(controllerRaw) as ControllerRecord;
      } catch {
        return errorResponse('CONTROLLER_RECORD_CORRUPT', 'Stored controller record is corrupt', 500);
      }

      return jsonResponse({ status: 'ok', controller });
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
