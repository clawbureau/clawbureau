import {
  didKeyToEd25519PublicKeyBytes,
  importEd25519PublicKeyFromBytes,
  verifyEd25519,
} from './crypto';
import { handleClaimM5Routes } from './m5-identity';

export interface Env {
  CLAIM_VERSION: string;
  CLAIM_CHALLENGE_TTL_SECONDS?: string;
  CLAIM_EXPORT_SIGNING_KEY?: string;
  CLAIM_EXPORT_MAX_AGE_SECONDS?: string;

  // identity productization + scoped exchange dependencies
  CLAIM_SCOPE_BASE_URL?: string;
  CLAIM_SCOPE_ADMIN_KEY?: string;
  CLAIM_SCOPE_TIMEOUT_MS?: string;
  CLAIM_SCOPE_EXCHANGE_TTL_SECONDS?: string;
  CLAWVERIFY_BASE_URL?: string;
  CLAWVERIFY_TIMEOUT_MS?: string;
  CLAIM_CLAWLOGS_BASE_URL?: string;
  CLAIM_CLAWLOGS_ADMIN_KEY?: string;
  CLAIM_CLAWLOGS_MODE?: string;

  // storage (optional bindings)
  CLAIM_STORE?: KVNamespace;
  CLAIM_CACHE?: KVNamespace;

  // relational + export storage
  CLAIM_DB?: D1Database;
  CLAIM_AUDIT_EXPORTS?: R2Bucket;
}

type ChallengePurpose =
  | 'bind'
  | 'revoke'
  | 'register_controller'
  | 'register_agent'
  | 'update_sensitive_policy'
  | 'confirm_rotation'
  | 'transfer_controller_request'
  | 'transfer_controller_confirm'
  | 'export_identity'
  | 'import_identity';

type ControllerTransferState = 'active' | 'transfer_pending' | 'transferred';

type RotationRole = 'controller' | 'agent';

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
  context_parts?: string[];
  rotation_role?: RotationRole;
  from_did?: string;
  to_did?: string;
  transfer_to_owner_did?: string;
  bundle_hash_b64u?: string;
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

  transfer_state?: ControllerTransferState;
  transfer_to_owner_did?: string;
  transfer_requested_at?: number;
  transfer_requested_at_iso?: string;
  transferred_at?: number;
  transferred_at_iso?: string;
  transferred_from_owner_did?: string;

  rotated_from_did?: string;
  rotation_confirmed_at?: number;
  rotation_confirmed_at_iso?: string;
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

  rotated_from_did?: string;
  rotation_confirmed_at?: number;
  rotation_confirmed_at_iso?: string;
}

interface RotationAliasRecord {
  alias_version: '1';
  role: RotationRole;
  from_did: string;
  to_did: string;
  owner_did: string;
  active: boolean;
  confirmed_at: number;
  confirmed_at_iso: string;
  controller_did?: string;
}

interface IdentityExportBundlePayload {
  bundle_version: '1';
  owner_did: string;
  controller: ControllerRecord;
  agent_bindings: ControllerAgentRecord[];
  rotation_aliases: RotationAliasRecord[];
}

interface IdentityExportBundle {
  envelope_version: '1';
  envelope_type: 'identity_export_bundle';
  exported_at: number;
  exported_at_iso: string;
  bundle_hash_b64u: string;
  signature_algorithm: 'HMAC-SHA256';
  signature_b64u: string;
  payload: IdentityExportBundlePayload;
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

function rotationAliasKey(fromDid: string): string {
  return `control-plane:rotation-alias:${fromDid}`;
}

function rotationAliasPrefix(): string {
  return 'control-plane:rotation-alias:';
}

function exportBundleKey(bundleHashB64u: string): string {
  return `control-plane:export-bundle:${bundleHashB64u}`;
}

function importOperationKey(ownerDid: string, bundleHashB64u: string): string {
  return `control-plane:import-op:${ownerDid}:${bundleHashB64u}`;
}

const MAX_REVOCATION_REASON_LENGTH = 256;
const MAX_SCOPE_ITEMS = 64;
const MAX_SCOPE_ITEM_LENGTH = 128;
const MAX_CONTEXT_PARTS = 8;
const MAX_CONTEXT_PART_LENGTH = 256;
const BUNDLE_HASH_PATTERN = /^[A-Za-z0-9_-]{43}$/;
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
  contextParts?: string[];
}): string {
  const { purpose, challengeId, nonce, exp, did, controllerDid, agentDid, contextParts } = options;

  if (purpose === 'bind' || purpose === 'revoke') {
    // Preserve legacy challenge message format for existing bind/revoke clients.
    return `clawclaim:${purpose}:v1:${challengeId}:${nonce}:${exp}`;
  }

  const didPart = did?.trim().length ? did.trim() : '-';
  const controllerPart = controllerDid?.trim().length ? controllerDid.trim() : '-';
  const agentPart = agentDid?.trim().length ? agentDid.trim() : '-';
  const normalizedContext =
    Array.isArray(contextParts) && contextParts.length > 0
      ? contextParts.map((part) => part.trim()).filter((part) => part.length > 0)
      : [];

  // A stable, unambiguous signing message for control-plane actions.
  if (normalizedContext.length > 0) {
    return `clawclaim:${purpose}:v1:${challengeId}:${didPart}:${controllerPart}:${agentPart}:${normalizedContext.join('|')}:${nonce}:${exp}`;
  }

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

function canonicalStringify(value: unknown): string {
  if (value === null) return 'null';

  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('Non-finite number in canonicalStringify');
    return JSON.stringify(value);
  }
  if (typeof value === 'boolean') return value ? 'true' : 'false';

  if (Array.isArray(value)) {
    return `[${value.map((v) => canonicalStringify(v)).join(',')}]`;
  }

  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalStringify(obj[k])}`).join(',')}}`;
  }

  throw new Error(`Unsupported canonicalStringify type: ${typeof value}`);
}

function normalizeContextParts(input: unknown): string[] | null {
  if (input === undefined || input === null) return [];
  if (!Array.isArray(input)) return null;

  const out: string[] = [];
  for (const raw of input) {
    if (typeof raw !== 'string') return null;
    const part = raw.trim();
    if (!part || part.length > MAX_CONTEXT_PART_LENGTH) return null;
    out.push(part);
  }

  if (out.length > MAX_CONTEXT_PARTS) return null;
  return out;
}

function getControllerTransferState(controller: ControllerRecord): ControllerTransferState {
  return controller.transfer_state ?? 'active';
}

function isControllerFrozen(controller: ControllerRecord): boolean {
  return getControllerTransferState(controller) === 'transfer_pending';
}

async function resolveDidAlias(
  kv: KVNamespace,
  did: string,
  expectedRole?: RotationRole
): Promise<{ resolvedDid: string; aliases: RotationAliasRecord[] }> {
  let current = did;
  const aliases: RotationAliasRecord[] = [];

  for (let i = 0; i < 8; i++) {
    const raw = await kv.get(rotationAliasKey(current));
    if (!raw) break;

    let alias: RotationAliasRecord;
    try {
      alias = JSON.parse(raw) as RotationAliasRecord;
    } catch {
      break;
    }

    if (!alias || typeof alias !== 'object' || alias.active !== true) break;
    if (expectedRole && alias.role !== expectedRole) break;

    aliases.push(alias);

    if (!isNonEmptyString(alias.to_did) || alias.to_did === current) break;
    current = alias.to_did;
  }

  return { resolvedDid: current, aliases };
}

async function loadControllerRecord(kv: KVNamespace, controllerDid: string): Promise<ControllerRecord | null> {
  const raw = await kv.get(controllerKey(controllerDid));
  if (!raw) return null;
  try {
    return JSON.parse(raw) as ControllerRecord;
  } catch {
    return null;
  }
}

async function loadControllerRecordResolved(
  kv: KVNamespace,
  controllerDid: string
): Promise<{ controller: ControllerRecord; requestedDid: string; resolvedDid: string; aliases: RotationAliasRecord[] } | null> {
  const aliasResolution = await resolveDidAlias(kv, controllerDid, 'controller');
  const resolvedDid = aliasResolution.resolvedDid;
  const controller = await loadControllerRecord(kv, resolvedDid);
  if (!controller) return null;

  return {
    controller,
    requestedDid: controllerDid,
    resolvedDid,
    aliases: aliasResolution.aliases,
  };
}

async function signExportBundle(
  bundleHashB64u: string,
  env: Env
): Promise<{ ok: true; signature: string } | { ok: false; code: string; message: string }> {
  const secret = env.CLAIM_EXPORT_SIGNING_KEY?.trim();
  if (!secret) {
    return {
      ok: false,
      code: 'EXPORT_SIGNING_NOT_CONFIGURED',
      message: 'CLAIM_EXPORT_SIGNING_KEY is not configured',
    };
  }

  try {
    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );

    const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(bundleHashB64u));
    return { ok: true, signature: base64UrlEncode(new Uint8Array(sig)) };
  } catch {
    return {
      ok: false,
      code: 'EXPORT_SIGNING_FAILED',
      message: 'Failed to sign identity export bundle',
    };
  }
}

async function verifyExportBundleSignature(
  bundleHashB64u: string,
  signatureB64u: string,
  env: Env
): Promise<boolean> {
  const secret = env.CLAIM_EXPORT_SIGNING_KEY?.trim();
  if (!secret) return false;

  try {
    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );

    const padded = signatureB64u.replace(/-/g, '+').replace(/_/g, '/');
    const bytes = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
    const sig = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) sig[i] = bytes.charCodeAt(i);

    return await crypto.subtle.verify('HMAC', key, sig, new TextEncoder().encode(bundleHashB64u));
  } catch {
    return false;
  }
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
      const md = `# clawclaim (identity control plane)\n\nEndpoints:\n- GET /health\n- POST /v1/challenges (purpose: bind|revoke)\n- POST /v1/bind\n- POST /v1/bindings/revoke\n- POST /v1/control-plane/challenges\n- POST /v1/control-plane/controllers/register\n- POST /v1/control-plane/controllers/{controller_did}/agents/register\n- POST /v1/control-plane/controllers/{controller_did}/sensitive-policy\n- POST /v1/control-plane/rotations/confirm\n- POST /v1/control-plane/controllers/{controller_did}/transfer/request\n- POST /v1/control-plane/controllers/{controller_did}/transfer/confirm\n- POST /v1/control-plane/identity/export\n- POST /v1/control-plane/identity/import\n- GET /v1/control-plane/controllers/{controller_did}\n- GET /v1/control-plane/controllers/{controller_did}/agents\n- GET /v1/control-plane/controllers/{controller_did}/agents/{agent_did}\n\nM5 productization endpoints:\n- POST /v1/platform-claims/register\n- GET /v1/platform-claims/{owner_did}\n- POST /v1/accounts/{account_id}/primary-did\n- GET /v1/accounts/{account_id}/profile\n- GET /v1/bindings/audit\n- GET /v1/bindings/audit/export\n- POST /v1/owner-attestations/register\n- GET /v1/owner-attestations/{owner_did}\n- GET /v1/owner-attestations/lookup\n- POST /v1/scoped-tokens/challenges\n- POST /v1/scoped-tokens/exchange\n- POST /v1/orgs/{org_id}/roster-manifests\n- GET /v1/orgs/{org_id}/roster/latest\n\nBind flow:\n1) POST /v1/challenges { did } to get a message.\n2) Sign the message with your DID key.\n3) POST /v1/bind.\n\nControl-plane flow:\n1) Owner DID + controller/agent DIDs must be active bindings.\n2) POST /v1/control-plane/challenges for controller action messages.\n3) Owner signs challenge message, then submit registration/policy mutation endpoint.\n\nPortability flow:\n1) issue purpose-scoped challenge for rotation/transfer/export/import.\n2) sign challenge with owner DID key.\n3) call corresponding lifecycle endpoint (rotation confirm, transfer request/confirm, export/import).\n\n`;
      return textResponse(md, 'text/markdown; charset=utf-8', 200, env.CLAIM_VERSION);
    }

    const m5Response = await handleClaimM5Routes(request, env);
    if (m5Response) return m5Response;

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
      const purpose = typeof b.purpose === 'string' ? b.purpose.trim() : '';
      let controllerDid = typeof b.controller_did === 'string' ? b.controller_did.trim() : '';
      let agentDid = typeof b.agent_did === 'string' ? b.agent_did.trim() : '';

      const rotationRole = typeof b.rotation_role === 'string' ? b.rotation_role.trim() : '';
      const fromDid = typeof b.from_did === 'string' ? b.from_did.trim() : '';
      const toDid = typeof b.to_did === 'string' ? b.to_did.trim() : '';
      const transferToOwnerDid =
        typeof b.transfer_to_owner_did === 'string' ? b.transfer_to_owner_did.trim() : '';
      const bundleHashB64u = typeof b.bundle_hash_b64u === 'string' ? b.bundle_hash_b64u.trim() : '';

      const normalizedContextParts = normalizeContextParts(b.context_parts);
      if (!normalizedContextParts) {
        return errorResponse(
          'INVALID_CONTEXT_PARTS',
          `context_parts must be an array of at most ${MAX_CONTEXT_PARTS} non-empty strings (<=${MAX_CONTEXT_PART_LENGTH} chars each)`,
          400
        );
      }

      if (!ownerDid) {
        return errorResponse('INVALID_REQUEST', 'owner_did is required', 400);
      }

      if (
        purpose !== 'register_controller' &&
        purpose !== 'register_agent' &&
        purpose !== 'update_sensitive_policy' &&
        purpose !== 'confirm_rotation' &&
        purpose !== 'transfer_controller_request' &&
        purpose !== 'transfer_controller_confirm' &&
        purpose !== 'export_identity' &&
        purpose !== 'import_identity'
      ) {
        return errorResponse(
          'INVALID_REQUEST',
          'purpose must be one of register_controller, register_agent, update_sensitive_policy, confirm_rotation, transfer_controller_request, transfer_controller_confirm, export_identity, import_identity',
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

      if (purpose === 'confirm_rotation') {
        if (rotationRole !== 'controller' && rotationRole !== 'agent') {
          return errorResponse(
            'INVALID_REQUEST',
            'rotation_role must be "controller" or "agent" for confirm_rotation',
            400
          );
        }
        if (!fromDid || !toDid) {
          return errorResponse('INVALID_REQUEST', 'from_did and to_did are required for confirm_rotation', 400);
        }
        if (rotationRole === 'agent' && !controllerDid) {
          return errorResponse('INVALID_REQUEST', 'controller_did is required for agent rotation', 400);
        }
      }

      if (purpose === 'transfer_controller_request' || purpose === 'transfer_controller_confirm') {
        if (!controllerDid || !transferToOwnerDid) {
          return errorResponse(
            'INVALID_REQUEST',
            'controller_did and transfer_to_owner_did are required for transfer_controller_* purposes',
            400
          );
        }
      }

      if (purpose === 'export_identity' && !controllerDid) {
        return errorResponse('INVALID_REQUEST', 'controller_did is required for export_identity', 400);
      }

      if (purpose === 'import_identity') {
        if (!bundleHashB64u || !BUNDLE_HASH_PATTERN.test(bundleHashB64u)) {
          return errorResponse(
            'INVALID_REQUEST',
            'bundle_hash_b64u is required for import_identity and must be a base64url sha256 hash',
            400
          );
        }
      }

      const ownerBinding = await getActiveBinding(kv, ownerDid);
      if (!ownerBinding) {
        return errorResponse('OWNER_BINDING_REQUIRED', 'owner_did must be an active binding', 403);
      }

      let controller: ControllerRecord | null = null;
      let resolvedControllerDid = controllerDid;

      if (
        purpose === 'register_agent' ||
        purpose === 'update_sensitive_policy' ||
        purpose === 'transfer_controller_request' ||
        purpose === 'transfer_controller_confirm' ||
        purpose === 'export_identity' ||
        (purpose === 'confirm_rotation' && rotationRole === 'agent')
      ) {
        const resolved = await loadControllerRecordResolved(kv, controllerDid);
        if (!resolved) {
          return errorResponse('CONTROLLER_NOT_FOUND', 'Controller is not registered', 404);
        }

        controller = resolved.controller;
        resolvedControllerDid = resolved.resolvedDid;
        controllerDid = resolvedControllerDid;

        if (controller.active !== true) {
          return errorResponse('CONTROLLER_INACTIVE', 'Controller is inactive', 403);
        }

        if (purpose !== 'transfer_controller_confirm' && controller.owner_did !== ownerDid) {
          return errorResponse('CONTROLLER_OWNER_MISMATCH', 'owner_did does not control this controller', 403);
        }

        if (
          (purpose === 'register_agent' ||
            purpose === 'update_sensitive_policy' ||
            purpose === 'confirm_rotation' ||
            purpose === 'export_identity') &&
          isControllerFrozen(controller)
        ) {
          return errorResponse(
            'CONTROLLER_TRANSFER_FROZEN',
            'controller_did is transfer_pending and currently frozen for mutations',
            409
          );
        }
      }

      if (purpose === 'confirm_rotation') {
        const toBinding = await getActiveBinding(kv, toDid);
        if (!toBinding) {
          return errorResponse('ROTATION_TARGET_BINDING_REQUIRED', 'to_did must be an active binding', 403);
        }

        if (rotationRole === 'controller') {
          const resolvedFrom = await loadControllerRecordResolved(kv, fromDid);
          if (!resolvedFrom) {
            return errorResponse('CONTROLLER_NOT_FOUND', 'from_did controller is not registered', 404);
          }
          if (resolvedFrom.controller.owner_did !== ownerDid) {
            return errorResponse(
              'CONTROLLER_OWNER_MISMATCH',
              'owner_did does not control from_did controller',
              403
            );
          }

          if (isControllerFrozen(resolvedFrom.controller)) {
            return errorResponse(
              'CONTROLLER_TRANSFER_FROZEN',
              'controller_did is transfer_pending and currently frozen for mutations',
              409
            );
          }
        }

        if (rotationRole === 'agent') {
          const bindingRaw = await kv.get(controllerAgentKey(controllerDid, fromDid));
          if (!bindingRaw) {
            return errorResponse(
              'CONTROLLER_AGENT_NOT_FOUND',
              'from_did agent is not registered under controller',
              404
            );
          }
        }
      }

      if (purpose === 'transfer_controller_request') {
        if (!controller) {
          return errorResponse('CONTROLLER_NOT_FOUND', 'Controller is not registered', 404);
        }

        if (controller.owner_did !== ownerDid) {
          return errorResponse('CONTROLLER_OWNER_MISMATCH', 'owner_did does not control this controller', 403);
        }

        if (getControllerTransferState(controller) === 'transfer_pending') {
          return errorResponse(
            'TRANSFER_ALREADY_PENDING',
            'controller transfer is already pending',
            409
          );
        }

        const transferTargetBinding = await getActiveBinding(kv, transferToOwnerDid);
        if (!transferTargetBinding) {
          return errorResponse(
            'TRANSFER_TARGET_BINDING_REQUIRED',
            'transfer_to_owner_did must be an active binding',
            403
          );
        }
      }

      if (purpose === 'transfer_controller_confirm') {
        if (!controller) {
          return errorResponse('CONTROLLER_NOT_FOUND', 'Controller is not registered', 404);
        }

        if (getControllerTransferState(controller) !== 'transfer_pending') {
          return errorResponse('TRANSFER_NOT_PENDING', 'controller transfer is not pending', 409);
        }

        if (!controller.transfer_to_owner_did || controller.transfer_to_owner_did !== ownerDid) {
          return errorResponse(
            'TRANSFER_OWNER_MISMATCH',
            'owner_did must match pending transfer_to_owner_did',
            403
          );
        }

        if (transferToOwnerDid !== ownerDid) {
          return errorResponse(
            'TRANSFER_CONTEXT_MISMATCH',
            'transfer_to_owner_did must match owner_did for transfer confirmation',
            400
          );
        }
      }

      if (purpose === 'export_identity') {
        if (!controller) {
          return errorResponse('CONTROLLER_NOT_FOUND', 'Controller is not registered', 404);
        }

        if (agentDid) {
          const bindingRaw = await kv.get(controllerAgentKey(controllerDid, agentDid));
          if (!bindingRaw) {
            return errorResponse('CONTROLLER_AGENT_NOT_FOUND', 'agent_did is not registered under controller', 404);
          }
        }
      }

      let contextParts = [...normalizedContextParts];

      if (purpose === 'confirm_rotation') {
        contextParts = [
          `rotation_role=${rotationRole}`,
          `from_did=${fromDid}`,
          `to_did=${toDid}`,
          ...(controllerDid ? [`controller_did=${controllerDid}`] : []),
        ];
      }

      if (purpose === 'transfer_controller_request' || purpose === 'transfer_controller_confirm') {
        contextParts = [
          `transfer_to_owner_did=${transferToOwnerDid}`,
          `transfer_action=${purpose === 'transfer_controller_request' ? 'request' : 'confirm'}`,
        ];
      }

      if (purpose === 'export_identity') {
        contextParts = [
          `controller_did=${controllerDid}`,
          ...(agentDid ? [`agent_did=${agentDid}`] : []),
          'export_version=1',
        ];
      }

      if (purpose === 'import_identity') {
        contextParts = [`bundle_hash_b64u=${bundleHashB64u}`, 'import_version=1'];
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
        contextParts,
      });

      const record: ChallengeRecord = {
        challenge_id,
        did: ownerDid,
        controller_did: controllerDid || undefined,
        agent_did: agentDid || undefined,
        context_parts: contextParts,
        rotation_role: (rotationRole as RotationRole) || undefined,
        from_did: fromDid || undefined,
        to_did: toDid || undefined,
        transfer_to_owner_did: transferToOwnerDid || undefined,
        bundle_hash_b64u: bundleHashB64u || undefined,
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
        rotation_role: rotationRole || null,
        from_did: fromDid || null,
        to_did: toDid || null,
        transfer_to_owner_did: transferToOwnerDid || null,
        bundle_hash_b64u: bundleHashB64u || null,
        context_parts: contextParts,
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
        transfer_state: 'active',
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

      const requestedControllerDid = decodeURIComponent(registerAgentMatch[1]!);

      const controllerResolved = await loadControllerRecordResolved(kv, requestedControllerDid);
      if (!controllerResolved) {
        return errorResponse('CONTROLLER_NOT_FOUND', 'Controller is not registered', 404);
      }

      const controllerDid = controllerResolved.resolvedDid;

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

      const controller = controllerResolved.controller;

      if (controller.active !== true) {
        return errorResponse('CONTROLLER_INACTIVE', 'Controller is inactive', 403);
      }

      if (controller.owner_did !== ownerDid) {
        return errorResponse('CONTROLLER_OWNER_MISMATCH', 'owner_did does not control this controller', 403);
      }

      if (isControllerFrozen(controller)) {
        return errorResponse(
          'CONTROLLER_TRANSFER_FROZEN',
          'controller_did is transfer_pending and currently frozen for mutations',
          409
        );
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

      const requestedControllerDid = decodeURIComponent(updatePolicyMatch[1]!);

      const controllerResolved = await loadControllerRecordResolved(kv, requestedControllerDid);
      if (!controllerResolved) {
        return errorResponse('CONTROLLER_NOT_FOUND', 'Controller is not registered', 404);
      }

      const controllerDid = controllerResolved.resolvedDid;

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

      const controller = controllerResolved.controller;

      if (controller.active !== true) {
        return errorResponse('CONTROLLER_INACTIVE', 'Controller is inactive', 403);
      }

      if (controller.owner_did !== ownerDid) {
        return errorResponse('CONTROLLER_OWNER_MISMATCH', 'owner_did does not control this controller', 403);
      }

      if (isControllerFrozen(controller)) {
        return errorResponse(
          'CONTROLLER_TRANSFER_FROZEN',
          'controller_did is transfer_pending and currently frozen for mutations',
          409
        );
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

    const confirmRotationMatch = /^\/v1\/control-plane\/rotations\/confirm$/.exec(url.pathname);
    if (request.method === 'POST' && confirmRotationMatch) {
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
      const role = typeof b.rotation_role === 'string' ? b.rotation_role.trim() : '';
      const fromDid = typeof b.from_did === 'string' ? b.from_did.trim() : '';
      const toDid = typeof b.to_did === 'string' ? b.to_did.trim() : '';
      const controllerDidRaw = typeof b.controller_did === 'string' ? b.controller_did.trim() : '';
      const challengeId = typeof b.challenge_id === 'string' ? b.challenge_id.trim() : '';
      const signatureB64u = typeof b.signature_b64u === 'string' ? b.signature_b64u.trim() : '';

      if (!ownerDid || !fromDid || !toDid || !challengeId || !signatureB64u) {
        return errorResponse(
          'INVALID_REQUEST',
          'owner_did, from_did, to_did, challenge_id, and signature_b64u are required',
          400
        );
      }

      if (role !== 'controller' && role !== 'agent') {
        return errorResponse('INVALID_REQUEST', 'rotation_role must be "controller" or "agent"', 400);
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

      if (challenge.purpose !== 'confirm_rotation') {
        return errorResponse('CHALLENGE_PURPOSE_MISMATCH', 'Challenge purpose must be "confirm_rotation"', 400);
      }

      if (
        challenge.did !== ownerDid ||
        challenge.rotation_role !== role ||
        challenge.from_did !== fromDid ||
        challenge.to_did !== toDid
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

      const toBinding = await getActiveBinding(kv, toDid);
      if (!toBinding) {
        return errorResponse('ROTATION_TARGET_BINDING_REQUIRED', 'to_did must be an active binding', 403);
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

      const existingAliasRaw = await kv.get(rotationAliasKey(fromDid));
      if (existingAliasRaw) {
        try {
          const existingAlias = JSON.parse(existingAliasRaw) as RotationAliasRecord;
          if (existingAlias.active === true && existingAlias.to_did === toDid && existingAlias.role === role) {
            await kv.delete(challengeKey(challengeId));
            return jsonResponse({ status: 'already_confirmed', alias: existingAlias });
          }

          return errorResponse('ROTATION_CONFLICT', 'from_did already has a conflicting rotation alias', 409);
        } catch {
          return errorResponse('ROTATION_ALIAS_RECORD_CORRUPT', 'Stored rotation alias record is corrupt', 500);
        }
      }

      const nowIso = new Date(nowSec * 1000).toISOString();

      if (role === 'controller') {
        const controllerResolved = await loadControllerRecordResolved(kv, fromDid);
        if (!controllerResolved) {
          return errorResponse('CONTROLLER_NOT_FOUND', 'from_did controller is not registered', 404);
        }

        const fromControllerDid = controllerResolved.resolvedDid;
        const controller = controllerResolved.controller;

        if (controller.owner_did !== ownerDid) {
          return errorResponse(
            'CONTROLLER_OWNER_MISMATCH',
            'owner_did does not control from_did controller',
            403
          );
        }

        if (isControllerFrozen(controller)) {
          return errorResponse(
            'CONTROLLER_TRANSFER_FROZEN',
            'controller_did is transfer_pending and currently frozen for mutations',
            409
          );
        }

        const existingTarget = await kv.get(controllerKey(toDid));
        if (existingTarget) {
          return errorResponse('ROTATION_TARGET_CONFLICT', 'to_did is already registered as a controller', 409);
        }

        const rotatedController: ControllerRecord = {
          ...controller,
          controller_did: toDid,
          last_challenge_id: challenge.challenge_id,
          rotated_from_did: fromDid,
          rotation_confirmed_at: nowSec,
          rotation_confirmed_at_iso: nowIso,
        };

        const sourceController: ControllerRecord = {
          ...controller,
          active: false,
          rotated_from_did: controller.rotated_from_did,
          last_challenge_id: challenge.challenge_id,
        };

        await kv.put(controllerKey(toDid), JSON.stringify(rotatedController));
        await kv.put(controllerKey(fromControllerDid), JSON.stringify(sourceController));

        const list = await kv.list({ prefix: controllerAgentPrefix(fromControllerDid), limit: 500 });
        for (const key of list.keys) {
          const raw = await kv.get(key.name);
          if (!raw) continue;

          let binding: ControllerAgentRecord;
          try {
            binding = JSON.parse(raw) as ControllerAgentRecord;
          } catch {
            continue;
          }

          const updatedBinding: ControllerAgentRecord = {
            ...binding,
            controller_did: toDid,
            owner_did: ownerDid,
            policy_hash_b64u: rotatedController.policy.policy_hash_b64u,
            last_challenge_id: challenge.challenge_id,
          };

          await kv.put(controllerAgentKey(toDid, binding.agent_did), JSON.stringify(updatedBinding));

          const oldBinding: ControllerAgentRecord = {
            ...binding,
            active: false,
            last_challenge_id: challenge.challenge_id,
          };
          await kv.put(controllerAgentKey(fromControllerDid, binding.agent_did), JSON.stringify(oldBinding));
        }
      }

      if (role === 'agent') {
        if (!controllerDidRaw) {
          return errorResponse('INVALID_REQUEST', 'controller_did is required for agent rotation', 400);
        }

        const controllerResolved = await loadControllerRecordResolved(kv, controllerDidRaw);
        if (!controllerResolved) {
          return errorResponse('CONTROLLER_NOT_FOUND', 'Controller is not registered', 404);
        }

        const controllerDid = controllerResolved.resolvedDid;
        const controller = controllerResolved.controller;

        if (controller.owner_did !== ownerDid) {
          return errorResponse('CONTROLLER_OWNER_MISMATCH', 'owner_did does not control this controller', 403);
        }

        if (isControllerFrozen(controller)) {
          return errorResponse(
            'CONTROLLER_TRANSFER_FROZEN',
            'controller_did is transfer_pending and currently frozen for mutations',
            409
          );
        }

        const bindingRaw = await kv.get(controllerAgentKey(controllerDid, fromDid));
        if (!bindingRaw) {
          return errorResponse('CONTROLLER_AGENT_NOT_FOUND', 'from_did agent is not registered under controller', 404);
        }

        let binding: ControllerAgentRecord;
        try {
          binding = JSON.parse(bindingRaw) as ControllerAgentRecord;
        } catch {
          return errorResponse('CONTROLLER_AGENT_RECORD_CORRUPT', 'Stored controller-agent record is corrupt', 500);
        }

        const existingTargetBinding = await kv.get(controllerAgentKey(controllerDid, toDid));
        if (existingTargetBinding) {
          return errorResponse(
            'ROTATION_TARGET_CONFLICT',
            'to_did is already registered under this controller',
            409
          );
        }

        const rotatedBinding: ControllerAgentRecord = {
          ...binding,
          agent_did: toDid,
          owner_did: ownerDid,
          last_challenge_id: challenge.challenge_id,
          rotated_from_did: fromDid,
          rotation_confirmed_at: nowSec,
          rotation_confirmed_at_iso: nowIso,
        };

        const oldBinding: ControllerAgentRecord = {
          ...binding,
          active: false,
          last_challenge_id: challenge.challenge_id,
        };

        await kv.put(controllerAgentKey(controllerDid, toDid), JSON.stringify(rotatedBinding));
        await kv.put(controllerAgentKey(controllerDid, fromDid), JSON.stringify(oldBinding));
      }

      const alias: RotationAliasRecord = {
        alias_version: '1',
        role: role as RotationRole,
        from_did: fromDid,
        to_did: toDid,
        owner_did: ownerDid,
        active: true,
        confirmed_at: nowSec,
        confirmed_at_iso: nowIso,
        controller_did: role === 'agent' ? controllerDidRaw || challenge.controller_did : undefined,
      };

      await kv.put(rotationAliasKey(fromDid), JSON.stringify(alias));
      await kv.delete(challengeKey(challengeId));

      const event = {
        type: role === 'controller' ? 'controller_rotation_confirmed' : 'agent_rotation_confirmed',
        owner_did: ownerDid,
        from_did: fromDid,
        to_did: toDid,
        rotation_role: role,
        occurred_at: nowSec,
        occurred_at_iso: nowIso,
      };

      const eventKey = controlPlaneEventKey(nowSec, 'rotation-confirm', ownerDid, challenge.challenge_id);
      await kv.put(eventKey, JSON.stringify(event));

      return jsonResponse({
        status: 'rotated',
        rotation_role: role,
        alias,
        event_key: eventKey,
      });
    }

    const transferRequestMatch = /^\/v1\/control-plane\/controllers\/([^/]+)\/transfer\/request$/.exec(url.pathname);
    if (request.method === 'POST' && transferRequestMatch) {
      const kv = env.CLAIM_STORE;
      if (!kv) {
        return errorResponse('STORE_NOT_CONFIGURED', 'CLAIM_STORE KV binding is not configured', 503);
      }

      const requestedControllerDid = decodeURIComponent(transferRequestMatch[1]!);
      const controllerResolved = await loadControllerRecordResolved(kv, requestedControllerDid);
      if (!controllerResolved) {
        return errorResponse('CONTROLLER_NOT_FOUND', 'Controller is not registered', 404);
      }

      const controllerDid = controllerResolved.resolvedDid;
      const controller = controllerResolved.controller;

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
      const transferToOwnerDid =
        typeof b.transfer_to_owner_did === 'string' ? b.transfer_to_owner_did.trim() : '';
      const challengeId = typeof b.challenge_id === 'string' ? b.challenge_id.trim() : '';
      const signatureB64u = typeof b.signature_b64u === 'string' ? b.signature_b64u.trim() : '';

      if (!ownerDid || !transferToOwnerDid || !challengeId || !signatureB64u) {
        return errorResponse(
          'INVALID_REQUEST',
          'owner_did, transfer_to_owner_did, challenge_id, and signature_b64u are required',
          400
        );
      }

      if (controller.owner_did !== ownerDid) {
        return errorResponse('CONTROLLER_OWNER_MISMATCH', 'owner_did does not control this controller', 403);
      }

      if (getControllerTransferState(controller) === 'transfer_pending') {
        if (controller.transfer_to_owner_did === transferToOwnerDid) {
          return jsonResponse({ status: 'already_pending', controller });
        }
        return errorResponse('TRANSFER_ALREADY_PENDING', 'controller transfer is already pending', 409);
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

      if (challenge.purpose !== 'transfer_controller_request') {
        return errorResponse(
          'CHALLENGE_PURPOSE_MISMATCH',
          'Challenge purpose must be "transfer_controller_request"',
          400
        );
      }

      if (
        challenge.did !== ownerDid ||
        challenge.controller_did !== controllerDid ||
        challenge.transfer_to_owner_did !== transferToOwnerDid
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

      const targetBinding = await getActiveBinding(kv, transferToOwnerDid);
      if (!targetBinding) {
        return errorResponse(
          'TRANSFER_TARGET_BINDING_REQUIRED',
          'transfer_to_owner_did must be an active binding',
          403
        );
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

      const updatedController: ControllerRecord = {
        ...controller,
        transfer_state: 'transfer_pending',
        transfer_to_owner_did: transferToOwnerDid,
        transfer_requested_at: nowSec,
        transfer_requested_at_iso: new Date(nowSec * 1000).toISOString(),
        last_challenge_id: challenge.challenge_id,
      };

      await kv.put(controllerKey(controllerDid), JSON.stringify(updatedController));
      await kv.delete(challengeKey(challengeId));

      const event = {
        type: 'controller_transfer_requested',
        owner_did: ownerDid,
        controller_did: controllerDid,
        transfer_to_owner_did: transferToOwnerDid,
        occurred_at: nowSec,
        occurred_at_iso: new Date(nowSec * 1000).toISOString(),
      };

      const eventKey = controlPlaneEventKey(nowSec, 'transfer-request', ownerDid, challenge.challenge_id);
      await kv.put(eventKey, JSON.stringify(event));

      return jsonResponse({
        status: 'transfer_pending',
        controller: updatedController,
        event_key: eventKey,
      });
    }

    const transferConfirmMatch = /^\/v1\/control-plane\/controllers\/([^/]+)\/transfer\/confirm$/.exec(url.pathname);
    if (request.method === 'POST' && transferConfirmMatch) {
      const kv = env.CLAIM_STORE;
      if (!kv) {
        return errorResponse('STORE_NOT_CONFIGURED', 'CLAIM_STORE KV binding is not configured', 503);
      }

      const requestedControllerDid = decodeURIComponent(transferConfirmMatch[1]!);
      const controllerResolved = await loadControllerRecordResolved(kv, requestedControllerDid);
      if (!controllerResolved) {
        return errorResponse('CONTROLLER_NOT_FOUND', 'Controller is not registered', 404);
      }

      const controllerDid = controllerResolved.resolvedDid;
      const controller = controllerResolved.controller;

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
      const transferToOwnerDid =
        typeof b.transfer_to_owner_did === 'string' ? b.transfer_to_owner_did.trim() : '';
      const challengeId = typeof b.challenge_id === 'string' ? b.challenge_id.trim() : '';
      const signatureB64u = typeof b.signature_b64u === 'string' ? b.signature_b64u.trim() : '';

      if (!ownerDid || !challengeId || !signatureB64u) {
        return errorResponse(
          'INVALID_REQUEST',
          'owner_did, challenge_id, and signature_b64u are required',
          400
        );
      }

      if (transferToOwnerDid && transferToOwnerDid !== ownerDid) {
        return errorResponse(
          'TRANSFER_CONTEXT_MISMATCH',
          'transfer_to_owner_did must match owner_did for transfer confirmation',
          400
        );
      }

      if (getControllerTransferState(controller) === 'transferred' && controller.owner_did === ownerDid) {
        return jsonResponse({ status: 'already_transferred', controller });
      }

      if (getControllerTransferState(controller) !== 'transfer_pending') {
        return errorResponse('TRANSFER_NOT_PENDING', 'controller transfer is not pending', 409);
      }

      if (!controller.transfer_to_owner_did || controller.transfer_to_owner_did !== ownerDid) {
        return errorResponse(
          'TRANSFER_OWNER_MISMATCH',
          'owner_did must match pending transfer_to_owner_did',
          403
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

      if (challenge.purpose !== 'transfer_controller_confirm') {
        return errorResponse(
          'CHALLENGE_PURPOSE_MISMATCH',
          'Challenge purpose must be "transfer_controller_confirm"',
          400
        );
      }

      if (
        challenge.did !== ownerDid ||
        challenge.controller_did !== controllerDid ||
        challenge.transfer_to_owner_did !== ownerDid
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

      const previousOwnerDid = controller.owner_did;
      const updatedPolicy = await buildSensitiveAuthorizationPolicy(
        ownerDid,
        controller.policy.allowed_sensitive_scopes,
        nowSec
      );
      if (!updatedPolicy) {
        return errorResponse('INVALID_SENSITIVE_POLICY', 'Controller policy is invalid and cannot be transferred', 500);
      }

      const updatedController: ControllerRecord = {
        ...controller,
        owner_did: ownerDid,
        transfer_state: 'transferred',
        transfer_to_owner_did: ownerDid,
        transferred_from_owner_did: previousOwnerDid,
        transferred_at: nowSec,
        transferred_at_iso: new Date(nowSec * 1000).toISOString(),
        last_challenge_id: challenge.challenge_id,
        policy: updatedPolicy,
      };

      await kv.put(controllerKey(controllerDid), JSON.stringify(updatedController));

      const list = await kv.list({ prefix: controllerAgentPrefix(controllerDid), limit: 500 });
      for (const key of list.keys) {
        const raw = await kv.get(key.name);
        if (!raw) continue;

        let binding: ControllerAgentRecord;
        try {
          binding = JSON.parse(raw) as ControllerAgentRecord;
        } catch {
          continue;
        }

        const updatedBinding: ControllerAgentRecord = {
          ...binding,
          owner_did: ownerDid,
          policy_hash_b64u: updatedPolicy.policy_hash_b64u,
          last_challenge_id: challenge.challenge_id,
        };

        await kv.put(key.name, JSON.stringify(updatedBinding));
      }

      await kv.delete(challengeKey(challengeId));

      const event = {
        type: 'controller_transfer_confirmed',
        owner_did: ownerDid,
        previous_owner_did: previousOwnerDid,
        controller_did: controllerDid,
        occurred_at: nowSec,
        occurred_at_iso: new Date(nowSec * 1000).toISOString(),
      };

      const eventKey = controlPlaneEventKey(nowSec, 'transfer-confirm', ownerDid, challenge.challenge_id);
      await kv.put(eventKey, JSON.stringify(event));

      return jsonResponse({
        status: 'transferred',
        controller: updatedController,
        event_key: eventKey,
      });
    }

    if (request.method === 'POST' && url.pathname === '/v1/control-plane/identity/export') {
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
      const controllerDidRaw = typeof b.controller_did === 'string' ? b.controller_did.trim() : '';
      const agentDid = typeof b.agent_did === 'string' ? b.agent_did.trim() : '';
      const challengeId = typeof b.challenge_id === 'string' ? b.challenge_id.trim() : '';
      const signatureB64u = typeof b.signature_b64u === 'string' ? b.signature_b64u.trim() : '';

      if (!ownerDid || !controllerDidRaw || !challengeId || !signatureB64u) {
        return errorResponse(
          'INVALID_REQUEST',
          'owner_did, controller_did, challenge_id, and signature_b64u are required',
          400
        );
      }

      const controllerResolved = await loadControllerRecordResolved(kv, controllerDidRaw);
      if (!controllerResolved) {
        return errorResponse('CONTROLLER_NOT_FOUND', 'Controller is not registered', 404);
      }

      const controllerDid = controllerResolved.resolvedDid;
      const controller = controllerResolved.controller;

      if (controller.owner_did !== ownerDid) {
        return errorResponse('CONTROLLER_OWNER_MISMATCH', 'owner_did does not control this controller', 403);
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

      if (challenge.purpose !== 'export_identity') {
        return errorResponse('CHALLENGE_PURPOSE_MISMATCH', 'Challenge purpose must be "export_identity"', 400);
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

      let agentBindings: ControllerAgentRecord[] = [];
      if (agentDid) {
        const bindingRaw = await kv.get(controllerAgentKey(controllerDid, agentDid));
        if (!bindingRaw) {
          return errorResponse('CONTROLLER_AGENT_NOT_FOUND', 'agent_did is not registered under controller', 404);
        }

        try {
          agentBindings = [JSON.parse(bindingRaw) as ControllerAgentRecord];
        } catch {
          return errorResponse('CONTROLLER_AGENT_RECORD_CORRUPT', 'Stored controller-agent record is corrupt', 500);
        }
      } else {
        const list = await kv.list({ prefix: controllerAgentPrefix(controllerDid), limit: 500 });
        for (const key of list.keys) {
          const raw = await kv.get(key.name);
          if (!raw) continue;
          try {
            agentBindings.push(JSON.parse(raw) as ControllerAgentRecord);
          } catch {
            // skip corrupt records
          }
        }
      }

      const aliasList = await kv.list({ prefix: rotationAliasPrefix(), limit: 500 });
      const aliases: RotationAliasRecord[] = [];
      for (const key of aliasList.keys) {
        const raw = await kv.get(key.name);
        if (!raw) continue;
        try {
          const alias = JSON.parse(raw) as RotationAliasRecord;
          if (alias.owner_did === ownerDid) {
            aliases.push(alias);
          }
        } catch {
          // ignore corrupt alias records in export
        }
      }

      const payload: IdentityExportBundlePayload = {
        bundle_version: '1',
        owner_did: ownerDid,
        controller,
        agent_bindings: agentBindings,
        rotation_aliases: aliases,
      };

      const payloadCanonical = canonicalStringify(payload);
      const bundleHashB64u = await sha256B64uText(payloadCanonical);

      const signing = await signExportBundle(bundleHashB64u, env);
      if (!signing.ok) {
        return errorResponse(signing.code, signing.message, 503);
      }

      const exportBundle: IdentityExportBundle = {
        envelope_version: '1',
        envelope_type: 'identity_export_bundle',
        exported_at: nowSec,
        exported_at_iso: new Date(nowSec * 1000).toISOString(),
        bundle_hash_b64u: bundleHashB64u,
        signature_algorithm: 'HMAC-SHA256',
        signature_b64u: signing.signature,
        payload,
      };

      await kv.put(exportBundleKey(bundleHashB64u), JSON.stringify(exportBundle), {
        expirationTtl: parseIntOrDefault(env.CLAIM_EXPORT_MAX_AGE_SECONDS, 60 * 60 * 24),
      });
      await kv.delete(challengeKey(challengeId));

      const event = {
        type: 'identity_export_generated',
        owner_did: ownerDid,
        controller_did: controllerDid,
        bundle_hash_b64u: bundleHashB64u,
        occurred_at: nowSec,
        occurred_at_iso: new Date(nowSec * 1000).toISOString(),
      };

      const eventKey = controlPlaneEventKey(nowSec, 'identity-export', ownerDid, bundleHashB64u);
      await kv.put(eventKey, JSON.stringify(event));

      return jsonResponse({
        status: 'exported',
        export_bundle: exportBundle,
        event_key: eventKey,
      });
    }

    if (request.method === 'POST' && url.pathname === '/v1/control-plane/identity/import') {
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
      const challengeId = typeof b.challenge_id === 'string' ? b.challenge_id.trim() : '';
      const signatureB64u = typeof b.signature_b64u === 'string' ? b.signature_b64u.trim() : '';
      const bundleInput = b.bundle;

      if (!ownerDid || !challengeId || !signatureB64u || !bundleInput || typeof bundleInput !== 'object') {
        return errorResponse(
          'INVALID_REQUEST',
          'owner_did, challenge_id, signature_b64u, and bundle are required',
          400
        );
      }

      const bundle = bundleInput as IdentityExportBundle;
      if (
        bundle.envelope_version !== '1' ||
        bundle.envelope_type !== 'identity_export_bundle' ||
        bundle.signature_algorithm !== 'HMAC-SHA256' ||
        !BUNDLE_HASH_PATTERN.test(bundle.bundle_hash_b64u)
      ) {
        return errorResponse('IMPORT_BUNDLE_INVALID', 'Bundle envelope is invalid', 400);
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

      if (challenge.purpose !== 'import_identity') {
        return errorResponse('CHALLENGE_PURPOSE_MISMATCH', 'Challenge purpose must be "import_identity"', 400);
      }

      if (
        challenge.did !== ownerDid ||
        challenge.bundle_hash_b64u !== bundle.bundle_hash_b64u
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

      const payloadHash = await sha256B64uText(canonicalStringify(bundle.payload));
      if (payloadHash !== bundle.bundle_hash_b64u) {
        return errorResponse('IMPORT_BUNDLE_TAMPERED', 'bundle_hash_b64u does not match payload hash', 409);
      }

      const signatureValid = await verifyExportBundleSignature(
        bundle.bundle_hash_b64u,
        bundle.signature_b64u,
        env
      );
      if (!signatureValid) {
        return errorResponse('IMPORT_BUNDLE_SIGNATURE_INVALID', 'Bundle signature is invalid', 401);
      }

      const maxAgeSec = parseIntOrDefault(env.CLAIM_EXPORT_MAX_AGE_SECONDS, 60 * 60 * 24);
      if (bundle.exported_at + maxAgeSec < nowSec) {
        return errorResponse('IMPORT_BUNDLE_STALE', 'Bundle has expired and cannot be imported', 409);
      }

      if (bundle.payload.owner_did !== ownerDid) {
        return errorResponse('IMPORT_OWNER_MISMATCH', 'Bundle owner_did must match owner_did', 409);
      }

      if (bundle.payload.controller.active !== true) {
        return errorResponse('IMPORT_REVOKED_RECORD', 'Bundle controller record is inactive/revoked', 409);
      }

      for (const binding of bundle.payload.agent_bindings) {
        if (binding.active !== true) {
          return errorResponse('IMPORT_REVOKED_RECORD', 'Bundle contains inactive/revoked agent binding', 409);
        }
      }

      const importOpKey = importOperationKey(ownerDid, bundle.bundle_hash_b64u);
      const existingImport = await kv.get(importOpKey);
      if (existingImport) {
        await kv.delete(challengeKey(challengeId));
        return jsonResponse({ status: 'already_imported', bundle_hash_b64u: bundle.bundle_hash_b64u });
      }

      const controllerDid = bundle.payload.controller.controller_did;
      const existingControllerRaw = await kv.get(controllerKey(controllerDid));
      if (existingControllerRaw) {
        try {
          const existingController = JSON.parse(existingControllerRaw) as ControllerRecord;
          if (existingController.owner_did !== ownerDid) {
            return errorResponse(
              'IMPORT_CONTROLLER_CONFLICT',
              'Controller already exists with different owner',
              409
            );
          }
        } catch {
          return errorResponse('CONTROLLER_RECORD_CORRUPT', 'Stored controller record is corrupt', 500);
        }
      }

      const importedController: ControllerRecord = {
        ...bundle.payload.controller,
        owner_did: ownerDid,
        transfer_state: bundle.payload.controller.transfer_state ?? 'active',
      };

      const bindingsToWrite: Array<{ key: string; binding: ControllerAgentRecord }> = [];
      for (const binding of bundle.payload.agent_bindings) {
        const key = controllerAgentKey(controllerDid, binding.agent_did);
        const existingRaw = await kv.get(key);
        if (existingRaw) {
          try {
            const existing = JSON.parse(existingRaw) as ControllerAgentRecord;
            if (existing.owner_did !== ownerDid) {
              return errorResponse(
                'IMPORT_AGENT_CONFLICT',
                `Agent binding already exists with different owner for ${binding.agent_did}`,
                409
              );
            }
          } catch {
            return errorResponse('CONTROLLER_AGENT_RECORD_CORRUPT', 'Stored controller-agent record is corrupt', 500);
          }
        }

        const importedBinding: ControllerAgentRecord = {
          ...binding,
          owner_did: ownerDid,
          policy_hash_b64u: importedController.policy.policy_hash_b64u,
        };

        bindingsToWrite.push({ key, binding: importedBinding });
      }

      const aliasesToWrite: Array<{ key: string; alias: RotationAliasRecord }> = [];
      for (const alias of bundle.payload.rotation_aliases) {
        if (alias.active !== true || alias.owner_did !== ownerDid) continue;

        const key = rotationAliasKey(alias.from_did);
        const existingAliasRaw = await kv.get(key);
        if (existingAliasRaw) {
          try {
            const existingAlias = JSON.parse(existingAliasRaw) as RotationAliasRecord;
            if (existingAlias.to_did !== alias.to_did || existingAlias.role !== alias.role) {
              return errorResponse(
                'IMPORT_ALIAS_CONFLICT',
                `Rotation alias conflict for ${alias.from_did}`,
                409
              );
            }
          } catch {
            return errorResponse('ROTATION_ALIAS_RECORD_CORRUPT', 'Stored rotation alias record is corrupt', 500);
          }
        }

        aliasesToWrite.push({ key, alias });
      }

      await kv.put(controllerKey(controllerDid), JSON.stringify(importedController));
      for (const item of bindingsToWrite) {
        await kv.put(item.key, JSON.stringify(item.binding));
      }
      for (const item of aliasesToWrite) {
        await kv.put(item.key, JSON.stringify(item.alias));
      }

      await kv.put(
        importOpKey,
        JSON.stringify({
          imported_at: nowSec,
          imported_at_iso: new Date(nowSec * 1000).toISOString(),
          bundle_hash_b64u: bundle.bundle_hash_b64u,
        }),
        { expirationTtl: maxAgeSec }
      );
      await kv.delete(challengeKey(challengeId));

      const event = {
        type: 'identity_import_completed',
        owner_did: ownerDid,
        controller_did: controllerDid,
        bundle_hash_b64u: bundle.bundle_hash_b64u,
        occurred_at: nowSec,
        occurred_at_iso: new Date(nowSec * 1000).toISOString(),
      };

      const eventKey = controlPlaneEventKey(nowSec, 'identity-import', ownerDid, bundle.bundle_hash_b64u);
      await kv.put(eventKey, JSON.stringify(event));

      return jsonResponse({
        status: 'imported',
        bundle_hash_b64u: bundle.bundle_hash_b64u,
        controller_did: controllerDid,
        event_key: eventKey,
      });
    }

    const getControllerAgentMatch = /^\/v1\/control-plane\/controllers\/([^/]+)\/agents\/([^/]+)$/.exec(url.pathname);
    if (request.method === 'GET' && getControllerAgentMatch) {
      const kv = env.CLAIM_STORE;
      if (!kv) {
        return errorResponse('STORE_NOT_CONFIGURED', 'CLAIM_STORE KV binding is not configured', 503);
      }

      const requestedControllerDid = decodeURIComponent(getControllerAgentMatch[1]!);
      const requestedAgentDid = decodeURIComponent(getControllerAgentMatch[2]!);

      const controllerResolved = await loadControllerRecordResolved(kv, requestedControllerDid);
      if (!controllerResolved) {
        return errorResponse('CONTROLLER_NOT_FOUND', 'Controller is not registered', 404);
      }

      const controllerDid = controllerResolved.resolvedDid;
      const controller = controllerResolved.controller;

      const agentResolved = await resolveDidAlias(kv, requestedAgentDid, 'agent');
      const agentDid = agentResolved.resolvedDid;

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
        alias_resolution: {
          requested_controller_did: requestedControllerDid,
          resolved_controller_did: controllerDid,
          requested_agent_did: requestedAgentDid,
          resolved_agent_did: agentDid,
          controller_aliases: controllerResolved.aliases,
          agent_aliases: agentResolved.aliases,
        },
        chain: {
          owner_did: controller.owner_did,
          controller_did: controller.controller_did,
          agent_did: binding.agent_did,
          policy_hash_b64u: controller.policy.policy_hash_b64u,
          active: controller.active === true && binding.active === true,
          transfer_state: getControllerTransferState(controller),
        },
      });
    }

    const listControllerAgentsMatch = /^\/v1\/control-plane\/controllers\/([^/]+)\/agents$/.exec(url.pathname);
    if (request.method === 'GET' && listControllerAgentsMatch) {
      const kv = env.CLAIM_STORE;
      if (!kv) {
        return errorResponse('STORE_NOT_CONFIGURED', 'CLAIM_STORE KV binding is not configured', 503);
      }

      const requestedControllerDid = decodeURIComponent(listControllerAgentsMatch[1]!);
      const limit = Math.min(Math.max(parseIntOrDefault(url.searchParams.get('limit') ?? undefined, 50), 1), 200);
      const cursor = url.searchParams.get('cursor') ?? undefined;

      const controllerResolved = await loadControllerRecordResolved(kv, requestedControllerDid);
      if (!controllerResolved) {
        return errorResponse('CONTROLLER_NOT_FOUND', 'Controller is not registered', 404);
      }

      const controllerDid = controllerResolved.resolvedDid;
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
        requested_controller_did: requestedControllerDid,
        controller_did: controllerDid,
        transfer_state: getControllerTransferState(controllerResolved.controller),
        aliases: controllerResolved.aliases,
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

      const requestedControllerDid = decodeURIComponent(getControllerMatch[1]!);
      const controllerResolved = await loadControllerRecordResolved(kv, requestedControllerDid);
      if (!controllerResolved) {
        return errorResponse('CONTROLLER_NOT_FOUND', 'Controller is not registered', 404);
      }

      return jsonResponse({
        status: 'ok',
        requested_controller_did: requestedControllerDid,
        resolved_controller_did: controllerResolved.resolvedDid,
        aliases: controllerResolved.aliases,
        transfer_state: getControllerTransferState(controllerResolved.controller),
        controller: controllerResolved.controller,
      });
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
