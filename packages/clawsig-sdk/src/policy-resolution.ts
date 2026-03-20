import { base64UrlDecode, hashJsonB64u } from './crypto.js';
import type {
  AppliedPolicyLayerRef,
  EffectivePolicySnapshot,
  PolicyResolutionContext,
  SignedEnvelope,
  SignedLayerPolicy,
  SignedPolicyBundlePayload,
  SignedPolicyLayer,
  SignedPolicyScope,
  SignedPolicyStatement,
} from './types.js';

interface DidKeyMultibaseDecoded {
  codecPrefixValid: boolean;
  publicKeyBytes: Uint8Array | null;
}

const BASE58_ALPHABET =
  '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function isObjectRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

function isBase64Url(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z0-9_-]+$/.test(value);
}

function isIsoDateTime(value: unknown): value is string {
  return typeof value === 'string' && Number.isFinite(Date.parse(value));
}

function normalizeId(value: string): string {
  return value.trim();
}

function base58Decode(input: string): Uint8Array {
  const bytes: number[] = [0];
  for (const char of input) {
    const value = BASE58_ALPHABET.indexOf(char);
    if (value === -1) {
      throw new Error(`invalid base58 character: ${char}`);
    }
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] *= 58;
    }
    bytes[0] += value;
    let carry = 0;
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] += carry;
      carry = bytes[i] >> 8;
      bytes[i] &= 0xff;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  for (const char of input) {
    if (char !== '1') break;
    bytes.push(0);
  }
  return new Uint8Array(bytes.reverse());
}

function decodeDidKeyMultibase(did: string): DidKeyMultibaseDecoded {
  if (!did.startsWith('did:key:z')) {
    return { codecPrefixValid: false, publicKeyBytes: null };
  }
  try {
    const decoded = base58Decode(did.slice('did:key:z'.length));
    if (decoded.length < 3) {
      return { codecPrefixValid: false, publicKeyBytes: null };
    }
    const prefixValid = decoded[0] === 0xed && decoded[1] === 0x01;
    return {
      codecPrefixValid: prefixValid,
      publicKeyBytes: prefixValid ? decoded.slice(2) : null,
    };
  } catch {
    return { codecPrefixValid: false, publicKeyBytes: null };
  }
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const buf = bytes.buffer;
  if (buf instanceof ArrayBuffer) {
    return buf.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
  }
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function canonicalizeValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((entry) => canonicalizeValue(entry));
  }
  if (isObjectRecord(value)) {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value).sort((a, b) => a.localeCompare(b))) {
      out[key] = canonicalizeValue(value[key]);
    }
    return out;
  }
  return value;
}

async function canonicalHashB64u(value: unknown): Promise<string> {
  return await hashJsonB64u(canonicalizeValue(value));
}

function normalizeConditions(
  conditions: SignedPolicyStatement['conditions']
): SignedPolicyStatement['conditions'] | undefined {
  if (!conditions || !isObjectRecord(conditions)) return undefined;
  const normalized: Record<string, Record<string, string[]>> = {};
  for (const op of Object.keys(conditions).sort((a, b) => a.localeCompare(b))) {
    const rawConditionMap = conditions[op];
    if (!isObjectRecord(rawConditionMap)) {
      throw new Error(`policy condition operator ${op} must map to an object`);
    }
    const conditionMap: Record<string, string[]> = {};
    for (const key of Object.keys(rawConditionMap).sort((a, b) => a.localeCompare(b))) {
      const rawValues = rawConditionMap[key];
      if (!Array.isArray(rawValues)) {
        throw new Error(`policy condition key ${op}.${key} must be a string array`);
      }
      const values = rawValues
        .map((v) => {
          if (typeof v !== 'string' || v.trim().length === 0) {
            throw new Error(`policy condition value ${op}.${key} must be non-empty strings`);
          }
          return v.trim();
        })
        .sort((a, b) => a.localeCompare(b));
      conditionMap[key] = values;
    }
    normalized[op] = conditionMap;
  }
  return normalized;
}

function normalizeStatement(statement: SignedPolicyStatement): SignedPolicyStatement {
  if (!isNonEmptyString(statement.sid)) {
    throw new Error('policy statement.sid must be a non-empty string');
  }
  if (statement.effect !== 'Allow' && statement.effect !== 'Deny') {
    throw new Error(`policy statement ${statement.sid} has unsupported effect`);
  }
  if (!Array.isArray(statement.actions) || statement.actions.length === 0) {
    throw new Error(`policy statement ${statement.sid} must include at least one action`);
  }
  if (!Array.isArray(statement.resources) || statement.resources.length === 0) {
    throw new Error(`policy statement ${statement.sid} must include at least one resource`);
  }

  const actions = statement.actions
    .map((action) => {
      if (!isNonEmptyString(action)) {
        throw new Error(`policy statement ${statement.sid} contains an invalid action`);
      }
      return normalizeId(action);
    })
    .sort((a, b) => a.localeCompare(b));

  const resources = statement.resources
    .map((resource) => {
      if (!isNonEmptyString(resource)) {
        throw new Error(`policy statement ${statement.sid} contains an invalid resource`);
      }
      return normalizeId(resource);
    })
    .sort((a, b) => a.localeCompare(b));

  const conditions = normalizeConditions(statement.conditions);

  return {
    sid: normalizeId(statement.sid),
    effect: statement.effect,
    actions,
    resources,
    ...(conditions ? { conditions } : {}),
  };
}

export function normalizeSignedLayerPolicy(policy: SignedLayerPolicy): SignedLayerPolicy {
  if (!policy || !Array.isArray(policy.statements) || policy.statements.length === 0) {
    throw new Error('policy layer must contain a non-empty statements array');
  }

  const bySid = new Map<string, SignedPolicyStatement>();
  for (const rawStatement of policy.statements) {
    bySid.set(rawStatement.sid, normalizeStatement(rawStatement));
  }

  return {
    statements: [...bySid.values()].sort((a, b) => a.sid.localeCompare(b.sid)),
  };
}

export async function computeSignedPolicyLayerHashB64u(
  policy: SignedLayerPolicy
): Promise<string> {
  return await canonicalHashB64u(normalizeSignedLayerPolicy(policy));
}

function normalizeScope(raw: SignedPolicyScope): SignedPolicyScope {
  if (
    raw.scope_type !== 'org' &&
    raw.scope_type !== 'project' &&
    raw.scope_type !== 'task' &&
    raw.scope_type !== 'exception'
  ) {
    throw new Error('policy layer scope.scope_type must be org|project|task|exception');
  }
  if (!isNonEmptyString(raw.org_id)) {
    throw new Error('policy layer scope.org_id must be non-empty');
  }
  const normalized: SignedPolicyScope = {
    scope_type: raw.scope_type,
    org_id: normalizeId(raw.org_id),
  };

  if (raw.project_id !== undefined) {
    if (!isNonEmptyString(raw.project_id)) {
      throw new Error('policy layer scope.project_id must be non-empty when present');
    }
    normalized.project_id = normalizeId(raw.project_id);
  }
  if (raw.task_id !== undefined) {
    if (!isNonEmptyString(raw.task_id)) {
      throw new Error('policy layer scope.task_id must be non-empty when present');
    }
    normalized.task_id = normalizeId(raw.task_id);
  }
  if (raw.exception_id !== undefined) {
    if (!isNonEmptyString(raw.exception_id)) {
      throw new Error('policy layer scope.exception_id must be non-empty when present');
    }
    normalized.exception_id = normalizeId(raw.exception_id);
  }
  if (raw.priority !== undefined) {
    if (!Number.isInteger(raw.priority) || raw.priority < 0) {
      throw new Error('policy layer scope.priority must be a non-negative integer when present');
    }
    normalized.priority = raw.priority;
  }
  if (raw.expires_at !== undefined) {
    if (!isIsoDateTime(raw.expires_at)) {
      throw new Error('policy layer scope.expires_at must be ISO-8601 when present');
    }
    normalized.expires_at = raw.expires_at;
  }

  return normalized;
}

function normalizeApplyMode(raw: unknown): 'merge' | 'replace' {
  if (raw === undefined) return 'merge';
  if (raw === 'merge' || raw === 'replace') return raw;
  throw new Error('policy layer apply_mode must be merge|replace');
}

function normalizePolicyLayer(raw: SignedPolicyLayer): SignedPolicyLayer {
  if (!isNonEmptyString(raw.layer_id)) {
    throw new Error('policy layer layer_id must be non-empty');
  }
  if (!isBase64Url(raw.policy_hash_b64u) || raw.policy_hash_b64u.length < 8) {
    throw new Error('policy layer policy_hash_b64u must be base64url');
  }

  return {
    layer_id: normalizeId(raw.layer_id),
    scope: normalizeScope(raw.scope),
    apply_mode: normalizeApplyMode(raw.apply_mode),
    policy: normalizeSignedLayerPolicy(raw.policy),
    policy_hash_b64u: raw.policy_hash_b64u,
    ...(isObjectRecord(raw.metadata) ? { metadata: raw.metadata } : {}),
  };
}

function normalizePolicyBundlePayload(
  payload: SignedPolicyBundlePayload
): SignedPolicyBundlePayload {
  if (payload.policy_bundle_version !== '1') {
    throw new Error('policy bundle version must be "1"');
  }
  if (!isNonEmptyString(payload.bundle_id)) {
    throw new Error('policy bundle bundle_id must be non-empty');
  }
  if (!isNonEmptyString(payload.issuer_did) || !payload.issuer_did.startsWith('did:')) {
    throw new Error('policy bundle issuer_did must be a valid DID');
  }
  if (!isIsoDateTime(payload.issued_at)) {
    throw new Error('policy bundle issued_at must be ISO-8601');
  }
  if (payload.hash_algorithm !== 'SHA-256') {
    throw new Error('policy bundle hash_algorithm must be SHA-256');
  }
  if (!Array.isArray(payload.layers) || payload.layers.length === 0) {
    throw new Error('policy bundle layers must be a non-empty array');
  }

  return {
    policy_bundle_version: '1',
    bundle_id: normalizeId(payload.bundle_id),
    issuer_did: normalizeId(payload.issuer_did),
    issued_at: payload.issued_at,
    hash_algorithm: 'SHA-256',
    layers: payload.layers.map((layer) => normalizePolicyLayer(layer)),
    ...(isObjectRecord(payload.metadata) ? { metadata: payload.metadata } : {}),
  };
}

export async function computeSignedPolicyBundlePayloadHashB64u(
  payload: SignedPolicyBundlePayload
): Promise<string> {
  const normalizedPayload = normalizePolicyBundlePayload(payload);
  return await canonicalHashB64u(normalizedPayload);
}

export async function verifySignedPolicyBundleEnvelope(
  envelopeInput: unknown,
  verificationTimeIso = new Date().toISOString()
): Promise<SignedEnvelope<SignedPolicyBundlePayload>> {
  if (!isObjectRecord(envelopeInput)) {
    throw new Error('policy bundle envelope must be a JSON object');
  }

  const envelope = envelopeInput as Record<string, unknown>;
  if (envelope.envelope_version !== '1') {
    throw new Error('policy bundle envelope_version must be "1"');
  }
  if (envelope.envelope_type !== 'policy_bundle') {
    throw new Error('policy bundle envelope_type must be "policy_bundle"');
  }
  if (!isBase64Url(envelope.payload_hash_b64u) || envelope.payload_hash_b64u.length < 8) {
    throw new Error('policy bundle payload_hash_b64u must be base64url');
  }
  if (envelope.hash_algorithm !== 'SHA-256') {
    throw new Error('policy bundle hash_algorithm must be SHA-256');
  }
  if (envelope.algorithm !== 'Ed25519') {
    throw new Error('policy bundle algorithm must be Ed25519');
  }
  if (!isBase64Url(envelope.signature_b64u) || envelope.signature_b64u.length < 8) {
    throw new Error('policy bundle signature_b64u must be base64url');
  }
  if (!isNonEmptyString(envelope.signer_did) || !String(envelope.signer_did).startsWith('did:')) {
    throw new Error('policy bundle signer_did must be a valid DID');
  }
  if (!isIsoDateTime(envelope.issued_at)) {
    throw new Error('policy bundle envelope issued_at must be ISO-8601');
  }
  if (envelope.expires_at !== undefined) {
    if (!isIsoDateTime(envelope.expires_at)) {
      throw new Error('policy bundle envelope expires_at must be ISO-8601 when present');
    }
    if (Date.parse(verificationTimeIso) > Date.parse(String(envelope.expires_at))) {
      throw new Error('policy bundle envelope is expired for the verification time');
    }
  }

  if (!isObjectRecord(envelope.payload)) {
    throw new Error('policy bundle envelope payload must be an object');
  }
  const payload = normalizePolicyBundlePayload(
    envelope.payload as unknown as SignedPolicyBundlePayload
  );

  const computedPayloadHash = await canonicalHashB64u(payload);
  if (computedPayloadHash !== envelope.payload_hash_b64u) {
    throw new Error('policy bundle payload_hash_b64u mismatch');
  }

  const didDecoded = decodeDidKeyMultibase(String(envelope.signer_did));
  if (!didDecoded.codecPrefixValid || !didDecoded.publicKeyBytes) {
    throw new Error('policy bundle signer_did must be did:key with Ed25519 multicodec prefix');
  }

  const signatureBytes = base64UrlDecode(String(envelope.signature_b64u));
  if (signatureBytes.length !== 64) {
    throw new Error('policy bundle signature length must be 64 bytes');
  }

  const publicKey = await crypto.subtle.importKey(
    'raw',
    toArrayBuffer(didDecoded.publicKeyBytes),
    { name: 'Ed25519' },
    false,
    ['verify']
  );

  const signatureValid = await crypto.subtle.verify(
    { name: 'Ed25519' },
    publicKey,
    toArrayBuffer(signatureBytes),
    toArrayBuffer(new TextEncoder().encode(String(envelope.payload_hash_b64u)))
  );

  if (!signatureValid) {
    throw new Error('policy bundle signature verification failed');
  }

  for (const layer of payload.layers) {
    const computedLayerHash = await computeSignedPolicyLayerHashB64u(layer.policy);
    if (computedLayerHash !== layer.policy_hash_b64u) {
      throw new Error(`policy layer ${layer.layer_id} has a policy_hash_b64u mismatch`);
    }
  }

  return {
    envelope_version: '1',
    envelope_type: 'policy_bundle',
    payload,
    payload_hash_b64u: String(envelope.payload_hash_b64u),
    hash_algorithm: 'SHA-256',
    signature_b64u: String(envelope.signature_b64u),
    algorithm: 'Ed25519',
    signer_did: String(envelope.signer_did),
    issued_at: String(envelope.issued_at),
    ...(isIsoDateTime(envelope.expires_at) ? { expires_at: String(envelope.expires_at) } : {}),
  };
}

function normalizeResolutionContext(context: PolicyResolutionContext): {
  org_id: string;
  project_id?: string;
  task_id?: string;
  resolution_time: string;
} {
  if (!isNonEmptyString(context.org_id)) {
    throw new Error('policy resolution requires context.org_id');
  }
  const normalized = {
    org_id: normalizeId(context.org_id),
    resolution_time:
      isIsoDateTime(context.resolution_time) ? context.resolution_time : new Date().toISOString(),
  };
  if (context.project_id !== undefined) {
    if (!isNonEmptyString(context.project_id)) {
      throw new Error('policy resolution context.project_id must be non-empty when present');
    }
    (normalized as { project_id?: string }).project_id = normalizeId(context.project_id);
  }
  if (context.task_id !== undefined) {
    if (!isNonEmptyString(context.task_id)) {
      throw new Error('policy resolution context.task_id must be non-empty when present');
    }
    (normalized as { task_id?: string }).task_id = normalizeId(context.task_id);
  }
  return normalized as {
    org_id: string;
    project_id?: string;
    task_id?: string;
    resolution_time: string;
  };
}

function isLayerNotExpired(layer: SignedPolicyLayer, resolutionTimeIso: string): boolean {
  const expiresAt = layer.scope.expires_at;
  if (!expiresAt) return true;
  return Date.parse(expiresAt) >= Date.parse(resolutionTimeIso);
}

function matchOrgLayer(
  layers: SignedPolicyLayer[],
  orgId: string
): SignedPolicyLayer {
  const matches = layers
    .filter(
      (layer) => layer.scope.scope_type === 'org' && layer.scope.org_id === orgId
    )
    .sort((a, b) => a.layer_id.localeCompare(b.layer_id));
  if (matches.length === 0) {
    throw new Error(`no org policy layer found for org_id=${orgId}`);
  }
  if (matches.length > 1) {
    throw new Error(`multiple org policy layers found for org_id=${orgId}`);
  }
  return matches[0]!;
}

function matchProjectLayers(
  layers: SignedPolicyLayer[],
  context: { org_id: string; project_id?: string }
): SignedPolicyLayer[] {
  if (!context.project_id) return [];
  return layers
    .filter(
      (layer) =>
        layer.scope.scope_type === 'project' &&
        layer.scope.org_id === context.org_id &&
        layer.scope.project_id === context.project_id
    )
    .sort((a, b) => a.layer_id.localeCompare(b.layer_id));
}

function matchTaskLayers(
  layers: SignedPolicyLayer[],
  context: { org_id: string; project_id?: string; task_id?: string }
): SignedPolicyLayer[] {
  if (!context.task_id) return [];
  return layers
    .filter((layer) => {
      if (layer.scope.scope_type !== 'task') return false;
      if (layer.scope.org_id !== context.org_id) return false;
      if (layer.scope.task_id !== context.task_id) return false;
      if (layer.scope.project_id && layer.scope.project_id !== context.project_id) {
        return false;
      }
      return true;
    })
    .sort((a, b) => a.layer_id.localeCompare(b.layer_id));
}

function matchExceptionLayers(
  layers: SignedPolicyLayer[],
  context: { org_id: string; project_id?: string; task_id?: string; resolution_time: string }
): SignedPolicyLayer[] {
  return layers
    .filter((layer) => {
      if (layer.scope.scope_type !== 'exception') return false;
      if (layer.scope.org_id !== context.org_id) return false;
      if (!isLayerNotExpired(layer, context.resolution_time)) return false;
      if (layer.scope.project_id && layer.scope.project_id !== context.project_id) {
        return false;
      }
      if (layer.scope.task_id && layer.scope.task_id !== context.task_id) {
        return false;
      }
      return true;
    })
    .sort((a, b) => {
      const priorityA = a.scope.priority ?? 0;
      const priorityB = b.scope.priority ?? 0;
      if (priorityA !== priorityB) return priorityB - priorityA;
      return a.layer_id.localeCompare(b.layer_id);
    });
}

function applyLayer(
  statementMap: Map<string, SignedPolicyStatement>,
  layer: SignedPolicyLayer
): void {
  if ((layer.apply_mode ?? 'merge') === 'replace') {
    statementMap.clear();
  }
  for (const statement of layer.policy.statements) {
    statementMap.set(statement.sid, statement);
  }
}

function toAppliedLayerRef(layer: SignedPolicyLayer): AppliedPolicyLayerRef {
  return {
    layer_id: layer.layer_id,
    scope_type: layer.scope.scope_type,
    org_id: layer.scope.org_id,
    ...(layer.scope.project_id ? { project_id: layer.scope.project_id } : {}),
    ...(layer.scope.task_id ? { task_id: layer.scope.task_id } : {}),
    ...(layer.scope.exception_id ? { exception_id: layer.scope.exception_id } : {}),
    priority: layer.scope.priority ?? 0,
    apply_mode: layer.apply_mode ?? 'merge',
    policy_hash_b64u: layer.policy_hash_b64u,
  };
}

export interface ResolvedEffectivePolicy {
  effective_policy: SignedLayerPolicy;
  effective_policy_hash_b64u: string;
  effective_policy_snapshot: EffectivePolicySnapshot;
  signed_policy_bundle_envelope: SignedEnvelope<SignedPolicyBundlePayload>;
}

export async function resolveEffectivePolicyFromSignedBundle(
  envelopeInput: unknown,
  contextInput: PolicyResolutionContext
): Promise<ResolvedEffectivePolicy> {
  const context = normalizeResolutionContext(contextInput);
  const envelope = await verifySignedPolicyBundleEnvelope(
    envelopeInput,
    context.resolution_time
  );
  const layers = envelope.payload.layers;

  const orgLayer = matchOrgLayer(layers, context.org_id);
  const projectLayers = matchProjectLayers(layers, context);
  const taskLayers = matchTaskLayers(layers, context);
  const exceptionLayers = matchExceptionLayers(layers, context);

  const orderedLayers = [
    orgLayer,
    ...projectLayers,
    ...taskLayers,
    ...exceptionLayers,
  ];

  const statementMap = new Map<string, SignedPolicyStatement>();
  for (const layer of orderedLayers) {
    applyLayer(statementMap, layer);
  }

  const effectivePolicy: SignedLayerPolicy = {
    statements: [...statementMap.values()].sort((a, b) => a.sid.localeCompare(b.sid)),
  };

  if (effectivePolicy.statements.length === 0) {
    throw new Error('effective policy resolution produced an empty statement set');
  }

  const snapshot: EffectivePolicySnapshot = {
    snapshot_version: '1',
    resolver_version: 'org_project_task_exception.v1',
    context: {
      org_id: context.org_id,
      ...(context.project_id ? { project_id: context.project_id } : {}),
      ...(context.task_id ? { task_id: context.task_id } : {}),
    },
    source_bundle: {
      bundle_id: envelope.payload.bundle_id,
      issuer_did: envelope.payload.issuer_did,
      issued_at: envelope.payload.issued_at,
    },
    applied_layers: orderedLayers.map((layer) => toAppliedLayerRef(layer)),
    effective_policy: effectivePolicy,
  };

  const effectivePolicyHashB64u = await canonicalHashB64u(snapshot);

  return {
    effective_policy: effectivePolicy,
    effective_policy_hash_b64u: effectivePolicyHashB64u,
    effective_policy_snapshot: snapshot,
    signed_policy_bundle_envelope: envelope,
  };
}
