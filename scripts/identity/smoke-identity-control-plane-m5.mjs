#!/usr/bin/env node

import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const ED25519_MULTICODEC_PREFIX = new Uint8Array([0xed, 0x01]);

function parseArgs(argv) {
  const out = {
    env: 'staging',
    scopeAdminKey: process.env.SCOPE_ADMIN_KEY ?? '',
    outDir: '',
    clawclaimVersion: '',
    clawscopeVersion: '',
    clawverifyVersion: '',
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--env' && argv[i + 1]) {
      out.env = String(argv[++i]);
      continue;
    }
    if (arg === '--scope-admin-key' && argv[i + 1]) {
      out.scopeAdminKey = String(argv[++i]);
      continue;
    }
    if (arg === '--out-dir' && argv[i + 1]) {
      out.outDir = String(argv[++i]);
      continue;
    }
    if (arg === '--clawclaim-version' && argv[i + 1]) {
      out.clawclaimVersion = String(argv[++i]);
      continue;
    }
    if (arg === '--clawscope-version' && argv[i + 1]) {
      out.clawscopeVersion = String(argv[++i]);
      continue;
    }
    if (arg === '--clawverify-version' && argv[i + 1]) {
      out.clawverifyVersion = String(argv[++i]);
      continue;
    }
  }

  return out;
}

function timestampForPath(date = new Date()) {
  return date.toISOString().replace(/:/g, '-').replace(/\./g, '-');
}

function base58Encode(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new TypeError('base58Encode expects Uint8Array');
  if (bytes.length === 0) return '';

  const digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i++) {
      const x = (digits[i] << 8) + carry;
      digits[i] = x % 58;
      carry = (x / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }

  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) digits.push(0);

  return digits
    .reverse()
    .map((digit) => BASE58_ALPHABET[digit])
    .join('');
}

function b64u(bytes) {
  return Buffer.from(bytes)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function canonicalStringify(value) {
  if (value === null) return 'null';
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('Non-finite number in canonicalStringify');
    return JSON.stringify(value);
  }
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (Array.isArray(value)) return `[${value.map((v) => canonicalStringify(v)).join(',')}]`;
  if (typeof value === 'object') {
    const obj = value;
    const keys = Object.keys(obj).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalStringify(obj[k])}`).join(',')}}`;
  }
  throw new Error(`Unsupported canonicalStringify type: ${typeof value}`);
}

async function sha256B64u(text) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return b64u(new Uint8Array(digest));
}

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

async function signMessage(privateKey, message) {
  const bytes = new TextEncoder().encode(message);
  const sig = await crypto.subtle.sign('Ed25519', privateKey, bytes);
  return b64u(new Uint8Array(sig));
}

async function createSignedEnvelope({ envelopeType, payload, signerDid, privateKey }) {
  const payloadHash = await sha256B64u(JSON.stringify(payload));
  const signature = await signMessage(privateKey, payloadHash);

  return {
    envelope_version: '1',
    envelope_type: envelopeType,
    payload,
    payload_hash_b64u: payloadHash,
    hash_algorithm: 'SHA-256',
    signature_b64u: signature,
    algorithm: 'Ed25519',
    signer_did: signerDid,
    issued_at: new Date().toISOString(),
  };
}

async function request(url, { method = 'GET', headers = {}, body } = {}) {
  const res = await fetch(url, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });

  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }

  return {
    status: res.status,
    ok: res.ok,
    json,
    text,
    headers: Object.fromEntries(res.headers.entries()),
  };
}

function assertStatus(step, response, expected) {
  if (response.status !== expected) {
    const err = response.json && typeof response.json === 'object' ? response.json : { raw: response.text };
    throw new Error(`${step} expected HTTP ${expected}, got ${response.status}: ${JSON.stringify(err)}`);
  }
}

function pick(value, fields) {
  if (!value || typeof value !== 'object') return null;
  const out = {};
  for (const field of fields) {
    if (field in value) out[field] = value[field];
  }
  return out;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function bindDid(claimBase, did, privateKey) {
  const challenge = await request(`${claimBase}/v1/challenges`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: { did },
  });
  assertStatus('bindDid.challenge', challenge, 200);

  const signature = await signMessage(privateKey, String(challenge.json?.message ?? ''));

  const bind = await request(`${claimBase}/v1/bind`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: {
      did,
      challenge_id: challenge.json.challenge_id,
      signature_b64u: signature,
    },
  });
  assertStatus('bindDid.bind', bind, 200);

  return {
    challenge: pick(challenge.json, ['challenge_id', 'expires_in_sec']),
    bind: pick(bind.json, ['status', 'did', 'bound_at']),
  };
}

async function registerControlChain(claimBase, owner, controller, agent) {
  const controllerChallenge = await request(`${claimBase}/v1/control-plane/challenges`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: {
      owner_did: owner.did,
      purpose: 'register_controller',
      controller_did: controller.did,
    },
  });
  assertStatus('control.register_controller.challenge', controllerChallenge, 200);

  const controllerSig = await signMessage(
    owner.privateKey,
    String(controllerChallenge.json?.message ?? '')
  );

  const registerController = await request(`${claimBase}/v1/control-plane/controllers/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: {
      owner_did: owner.did,
      controller_did: controller.did,
      challenge_id: controllerChallenge.json.challenge_id,
      signature_b64u: controllerSig,
    },
  });
  assertStatus('control.register_controller', registerController, 200);

  const agentChallenge = await request(`${claimBase}/v1/control-plane/challenges`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: {
      owner_did: owner.did,
      purpose: 'register_agent',
      controller_did: controller.did,
      agent_did: agent.did,
    },
  });
  assertStatus('control.register_agent.challenge', agentChallenge, 200);

  const agentSig = await signMessage(owner.privateKey, String(agentChallenge.json?.message ?? ''));

  const registerAgent = await request(
    `${claimBase}/v1/control-plane/controllers/${encodeURIComponent(controller.did)}/agents/register`,
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: {
        owner_did: owner.did,
        agent_did: agent.did,
        challenge_id: agentChallenge.json.challenge_id,
        signature_b64u: agentSig,
      },
    }
  );
  assertStatus('control.register_agent', registerAgent, 200);

  return {
    register_controller: pick(registerController.json, ['status', 'owner_did', 'controller_did']),
    register_agent: pick(registerAgent.json, ['status', 'owner_did', 'controller_did', 'agent_did']),
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.env !== 'staging' && args.env !== 'prod') {
    throw new Error('--env must be staging or prod');
  }

  if (!args.scopeAdminKey || args.scopeAdminKey.trim().length === 0) {
    throw new Error('SCOPE_ADMIN_KEY is required (use --scope-admin-key or env var).');
  }

  const urls =
    args.env === 'prod'
      ? {
          clawclaim: 'https://clawclaim.com',
          clawscope: 'https://clawscope.com',
          clawverify: 'https://clawverify.com',
        }
      : {
          clawclaim: 'https://staging.clawclaim.com',
          clawscope: 'https://staging.clawscope.com',
          clawverify: 'https://staging.clawverify.com',
        };

  const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
  const timestamp = timestampForPath();
  const outDir =
    args.outDir ||
    path.join(rootDir, 'artifacts', 'smoke', 'identity-control-plane', `${timestamp}-${args.env}-m5`);
  mkdirSync(outDir, { recursive: true });

  const runId = `m5-${args.env}-${Date.now()}`;
  const orgId = `org-${runId}`;
  const accountId = `acct-${runId}`;
  const providerRef = `provider-ref-${runId}`;
  const missionId = `mission-${runId}`;
  const traceId = `trace-${runId}`;

  const result = {
    env: args.env,
    generated_at: new Date().toISOString(),
    urls,
    versions: {
      clawclaim: args.clawclaimVersion || null,
      clawscope: args.clawscopeVersion || null,
      clawverify: args.clawverifyVersion || null,
    },
    identities: {},
    steps: {},
  };

  const healthClaim = await request(`${urls.clawclaim}/health`);
  const healthScope = await request(`${urls.clawscope}/health`);
  const healthVerify = await request(`${urls.clawverify}/health`);

  if (!result.versions.clawclaim && typeof healthClaim.json?.version === 'string') {
    result.versions.clawclaim = healthClaim.json.version;
  }
  if (!result.versions.clawscope && typeof healthScope.json?.version === 'string') {
    result.versions.clawscope = healthScope.json.version;
  }
  if (!result.versions.clawverify && typeof healthVerify.json?.version === 'string') {
    result.versions.clawverify = healthVerify.json.version;
  }

  result.steps.health = {
    clawclaim: { status: healthClaim.status, ok: healthClaim.ok },
    clawscope: { status: healthScope.status, ok: healthScope.ok },
    clawverify: { status: healthVerify.status, ok: healthVerify.ok },
  };

  const owner = await createDidKeyPair();
  const controller = await createDidKeyPair();
  const agent = await createDidKeyPair();
  const member = await createDidKeyPair();

  result.identities = {
    owner_did: owner.did,
    controller_did: controller.did,
    agent_did: agent.did,
    member_did: member.did,
  };

  result.steps.bindings = {
    owner: await bindDid(urls.clawclaim, owner.did, owner.privateKey),
    controller: await bindDid(urls.clawclaim, controller.did, controller.privateKey),
    agent: await bindDid(urls.clawclaim, agent.did, agent.privateKey),
    member: await bindDid(urls.clawclaim, member.did, member.privateKey),
  };

  result.steps.control_chain = await registerControlChain(
    urls.clawclaim,
    owner,
    controller,
    agent
  );

  const handle = `smoke_${Date.now().toString(36)}`;
  const platformPayload = {
    message_version: '1',
    message_type: 'ownership_proof',
    message: `platform-proof:${owner.did}:github:${handle}`,
    nonce: `nonce_${Date.now()}`,
    audience: 'clawclaim:platform_claim',
    expires_at: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
  };

  const platformEnvelope = await createSignedEnvelope({
    envelopeType: 'message_signature',
    payload: platformPayload,
    signerDid: owner.did,
    privateKey: owner.privateKey,
  });

  const registerPlatform = await request(`${urls.clawclaim}/v1/platform-claims/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: {
      owner_did: owner.did,
      platform: 'github',
      handle,
      proof_url: `https://github.com/${handle}`,
      verification_envelope: platformEnvelope,
    },
  });
  assertStatus('platform_claim.register', registerPlatform, 200);

  const listPlatform = await request(
    `${urls.clawclaim}/v1/platform-claims/${encodeURIComponent(owner.did)}`,
    { method: 'GET' }
  );
  assertStatus('platform_claim.list', listPlatform, 200);

  result.steps.platform_claims = {
    register: pick(registerPlatform.json, ['status', 'claim']),
    list_count: Array.isArray(listPlatform.json?.claims) ? listPlatform.json.claims.length : 0,
  };

  const setPrimary = await request(
    `${urls.clawclaim}/v1/accounts/${encodeURIComponent(accountId)}/primary-did`,
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: {
        primary_did: owner.did,
        actor_did: owner.did,
      },
    }
  );
  assertStatus('primary_did.set', setPrimary, 200);

  const getProfile = await request(
    `${urls.clawclaim}/v1/accounts/${encodeURIComponent(accountId)}/profile`,
    { method: 'GET' }
  );
  assertStatus('primary_did.profile', getProfile, 200);

  result.steps.primary_did = {
    set: pick(setPrimary.json, ['status', 'account_id', 'primary_did']),
    profile: {
      status: getProfile.status,
      x_cache: getProfile.headers['x-cache'] ?? null,
      platform_claims: Array.isArray(getProfile.json?.platform_claims)
        ? getProfile.json.platform_claims.length
        : 0,
    },
  };

  const auditList = await request(`${urls.clawclaim}/v1/bindings/audit?limit=50`, { method: 'GET' });
  assertStatus('bindings.audit.list', auditList, 200);

  const auditExport = await request(`${urls.clawclaim}/v1/bindings/audit/export?format=csv&limit=200`, {
    method: 'GET',
  });
  assertStatus('bindings.audit.export', auditExport, 200);

  result.steps.binding_audit = {
    list_count: Array.isArray(auditList.json?.events) ? auditList.json.events.length : 0,
    export: pick(auditExport.json, ['status', 'key', 'format', 'rows', 'sha256']),
  };

  const attestationId = `att_${Date.now()}`;
  const ownerAttestationPayload = {
    attestation_version: '1',
    attestation_id: attestationId,
    subject_did: owner.did,
    provider_ref: providerRef,
    expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
  };

  const ownerAttestationEnvelope = await createSignedEnvelope({
    envelopeType: 'owner_attestation',
    payload: ownerAttestationPayload,
    signerDid: owner.did,
    privateKey: owner.privateKey,
  });

  const registerAttestation = await request(`${urls.clawclaim}/v1/owner-attestations/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: {
      owner_did: owner.did,
      attestation_id: attestationId,
      owner_provider: 'oauth',
      provider_ref: providerRef,
      verification_level: 'high',
      proof_url: 'https://example.com/attestation-proof',
      attestation_envelope: ownerAttestationEnvelope,
    },
  });
  assertStatus('owner_attestation.register', registerAttestation, 200);

  const listAttestations = await request(
    `${urls.clawclaim}/v1/owner-attestations/${encodeURIComponent(owner.did)}`,
    { method: 'GET' }
  );
  assertStatus('owner_attestation.list', listAttestations, 200);

  const lookupAttestation = await request(
    `${urls.clawclaim}/v1/owner-attestations/lookup?owner_provider=oauth&provider_ref=${encodeURIComponent(providerRef)}`,
    { method: 'GET' }
  );
  assertStatus('owner_attestation.lookup', lookupAttestation, 200);

  result.steps.owner_attestations = {
    register: pick(registerAttestation.json, ['status', 'attestation']),
    list_count: Array.isArray(listAttestations.json?.attestations)
      ? listAttestations.json.attestations.length
      : 0,
    lookup_count: Array.isArray(lookupAttestation.json?.attestations)
      ? lookupAttestation.json.attestations.length
      : 0,
  };

  const scopeChallenge = await request(`${urls.clawclaim}/v1/scoped-tokens/challenges`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: {
      owner_did: owner.did,
      aud: ['clawproxy'],
      scope: [
        'control:policy:update',
        'control:token:issue_sensitive',
        'control:token:revoke',
        'control:key:rotate',
      ],
      ttl_sec: 600,
      owner_attestation_id: attestationId,
      mission_id: missionId,
      controller_did: controller.did,
      agent_did: agent.did,
    },
  });
  assertStatus('scope_exchange.challenge', scopeChallenge, 200);

  const exchangeSig = await signMessage(owner.privateKey, String(scopeChallenge.json?.message ?? ''));

  const exchangeToken = await request(`${urls.clawclaim}/v1/scoped-tokens/exchange`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-scope-admin-key': args.scopeAdminKey,
    },
    body: {
      owner_did: owner.did,
      challenge_id: scopeChallenge.json.challenge_id,
      signature_b64u: exchangeSig,
    },
  });
  assertStatus('scope_exchange.exchange', exchangeToken, 200);

  const exchangeReplay = await request(`${urls.clawclaim}/v1/scoped-tokens/exchange`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-scope-admin-key': args.scopeAdminKey,
    },
    body: {
      owner_did: owner.did,
      challenge_id: scopeChallenge.json.challenge_id,
      signature_b64u: exchangeSig,
    },
  });
  assertStatus('scope_exchange.replay_denied', exchangeReplay, 409);

  const scopedToken = String(exchangeToken.json?.token ?? '');
  const scopedTokenHash = String(exchangeToken.json?.token_hash ?? '');
  if (!scopedToken || !scopedTokenHash) {
    throw new Error('scope_exchange.exchange returned empty token or token_hash');
  }

  result.steps.scope_exchange = {
    challenge: pick(scopeChallenge.json, ['challenge_id', 'owner_did', 'expires_at', 'ttl_sec']),
    exchange: pick(exchangeToken.json, [
      'status',
      'owner_did',
      'token_hash',
      'policy_version',
      'token_lane',
      'kid',
      'clawlogs_status',
    ]),
    replay_denied: {
      status: exchangeReplay.status,
      error: exchangeReplay.json?.error ?? null,
    },
  };

  const rosterMembers = [
    {
      member_did: member.did,
      team_role: 'builder',
    },
  ];
  const rosterIssuedAt = Math.floor(Date.now() / 1000);
  const rosterCanonical = {
    manifest_version: '1',
    org_id: orgId,
    owner_did: owner.did,
    issued_at: rosterIssuedAt,
    members: rosterMembers,
  };
  const rosterHash = await sha256B64u(canonicalStringify(rosterCanonical));
  const rosterSignature = await signMessage(
    owner.privateKey,
    `clawclaim:org_roster_manifest:v1:${rosterHash}`
  );

  const registerRoster = await request(
    `${urls.clawclaim}/v1/orgs/${encodeURIComponent(orgId)}/roster-manifests`,
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: {
        owner_did: owner.did,
        issued_at: rosterIssuedAt,
        members: rosterMembers,
        signature_b64u: rosterSignature,
      },
    }
  );
  assertStatus('org_roster.register', registerRoster, 200);

  const latestRoster = await request(
    `${urls.clawclaim}/v1/orgs/${encodeURIComponent(orgId)}/roster/latest`,
    { method: 'GET' }
  );
  assertStatus('org_roster.latest', latestRoster, 200);

  result.steps.org_roster = {
    register: pick(registerRoster.json, ['status', 'manifest']),
    latest: {
      status: latestRoster.status,
      members: Array.isArray(latestRoster.json?.members) ? latestRoster.json.members.length : 0,
      manifest: pick(latestRoster.json?.manifest, ['manifest_id', 'manifest_hash_b64u', 'member_count']),
    },
  };

  const adminHeaders = {
    authorization: `Bearer ${args.scopeAdminKey}`,
    'content-type': 'application/json',
  };

  const createAlertRule = await request(`${urls.clawscope}/v1/alerts/rules`, {
    method: 'POST',
    headers: adminHeaders,
    body: {
      metric_name: 'request_count',
      comparison: 'gte',
      threshold: 1,
      window_minutes: 120,
      route: '/v1/tokens/introspect',
      service: 'clawscope',
      mission_id: missionId,
    },
  });
  assertStatus('observability.alert_rule.create', createAlertRule, 201);

  const introspectActive = await request(`${urls.clawscope}/v1/tokens/introspect`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-trace-id': traceId,
      'x-correlation-id': runId,
    },
    body: { token: scopedToken },
  });
  assertStatus('observability.introspect.active', introspectActive, 200);

  const matrixAllowed = await request(`${urls.clawscope}/v1/tokens/introspect/matrix`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-trace-id': traceId,
      'x-correlation-id': runId,
    },
    body: { token: scopedToken, transition: 'token.revoke' },
  });
  assertStatus('observability.matrix.allowed', matrixAllowed, 200);

  const matrixUnknown = await request(`${urls.clawscope}/v1/tokens/introspect/matrix`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-trace-id': traceId,
      'x-correlation-id': runId,
    },
    body: { token: scopedToken, transition: 'transition.unknown' },
  });
  assertStatus('observability.matrix.unknown_transition', matrixUnknown, 400);

  const revokeToken = await request(`${urls.clawscope}/v1/tokens/revoke`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-cst': scopedToken,
    },
    body: {
      token_hash: scopedTokenHash,
      reason: `smoke_${runId}`,
    },
  });
  assertStatus('observability.revoke', revokeToken, 200);

  const introspectRevoked = await request(`${urls.clawscope}/v1/tokens/introspect`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-trace-id': traceId,
      'x-correlation-id': runId,
    },
    body: { token: scopedToken },
  });
  assertStatus('observability.introspect.revoked', introspectRevoked, 200);

  let traceReport = null;
  for (let attempt = 0; attempt < 12; attempt++) {
    const res = await request(`${urls.clawscope}/v1/traces/${encodeURIComponent(traceId)}`, {
      method: 'GET',
      headers: { authorization: `Bearer ${args.scopeAdminKey}` },
    });

    if (res.status === 200) {
      traceReport = res;
      break;
    }

    if (res.status !== 404) {
      throw new Error(
        `observability.trace expected HTTP 200 or 404 during retry window, got ${res.status}: ${res.text}`
      );
    }

    await sleep(2000);
  }

  if (!traceReport) {
    throw new Error(`observability.trace could not find trace_id after retries: ${traceId}`);
  }

  const tracesList = await request(
    `${urls.clawscope}/v1/traces?correlation_id=${encodeURIComponent(runId)}&limit=20`,
    {
      method: 'GET',
      headers: { authorization: `Bearer ${args.scopeAdminKey}` },
    }
  );
  assertStatus('observability.traces.list', tracesList, 200);

  const runRollups = await request(`${urls.clawscope}/v1/reports/rollups/run`, {
    method: 'POST',
    headers: adminHeaders,
    body: {},
  });
  assertStatus('observability.rollups.run', runRollups, 200);

  const dashboard = await request(`${urls.clawscope}/v1/metrics/dashboard`, {
    method: 'GET',
    headers: { authorization: `Bearer ${args.scopeAdminKey}` },
  });
  assertStatus('observability.dashboard', dashboard, 200);

  const usageJson = await request(`${urls.clawscope}/v1/reports/usage`, {
    method: 'GET',
    headers: { authorization: `Bearer ${args.scopeAdminKey}` },
  });
  assertStatus('observability.usage.json', usageJson, 200);

  const usageCsv = await request(`${urls.clawscope}/v1/reports/usage?format=csv`, {
    method: 'GET',
    headers: { authorization: `Bearer ${args.scopeAdminKey}` },
  });
  assertStatus('observability.usage.csv', usageCsv, 200);

  const alertsEvents = await request(`${urls.clawscope}/v1/alerts/events?limit=50`, {
    method: 'GET',
    headers: { authorization: `Bearer ${args.scopeAdminKey}` },
  });
  assertStatus('observability.alerts.events', alertsEvents, 200);

  const costReport = await request(`${urls.clawscope}/v1/analytics/cost`, {
    method: 'GET',
    headers: { authorization: `Bearer ${args.scopeAdminKey}` },
  });
  assertStatus('observability.analytics.cost', costReport, 200);

  const slaReport = await request(`${urls.clawscope}/v1/reports/sla`, {
    method: 'GET',
    headers: { authorization: `Bearer ${args.scopeAdminKey}` },
  });
  assertStatus('observability.sla', slaReport, 200);

  const missionAggregate = await request(
    `${urls.clawscope}/v1/missions/aggregate?mission_id=${encodeURIComponent(missionId)}`,
    {
      method: 'GET',
      headers: { authorization: `Bearer ${args.scopeAdminKey}` },
    }
  );
  assertStatus('observability.mission.aggregate', missionAggregate, 200);

  result.steps.observability = {
    alert_rule: pick(createAlertRule.json, ['status', 'rule']),
    introspect_active: pick(introspectActive.json, ['active', 'token_hash', 'kid', 'kid_source', 'mission_id']),
    matrix_allowed: pick(matrixAllowed.json, ['active', 'transition', 'transition_result']),
    matrix_unknown_transition: {
      status: matrixUnknown.status,
      error: matrixUnknown.json?.error ?? null,
    },
    revoke: pick(revokeToken.json, ['status', 'token_hash', 'revoked_at_iso']),
    introspect_revoked: pick(introspectRevoked.json, ['active', 'revoked', 'token_hash']),
    rollups: pick(runRollups.json, ['status', 'day', 'generated_at']),
    dashboard: pick(dashboard.json, ['status', 'window_minutes', 'requests_total', 'error_rate_percent']),
    usage_json_rows: Array.isArray(usageJson.json?.rows) ? usageJson.json.rows.length : 0,
    usage_csv: {
      status: usageCsv.status,
      report_key: usageCsv.headers['x-report-key'] ?? null,
      bytes: usageCsv.text.length,
    },
    alert_events_count: Array.isArray(alertsEvents.json?.events) ? alertsEvents.json.events.length : 0,
    cost_totals: pick(costReport.json?.totals, ['requests', 'compute_usd', 'storage_usd', 'total_usd']),
    trace_event_count: Array.isArray(traceReport.json?.events) ? traceReport.json.events.length : 0,
    traces_count: Array.isArray(tracesList.json?.traces) ? tracesList.json.traces.length : 0,
    sla_rows: Array.isArray(slaReport.json?.rows) ? slaReport.json.rows.length : 0,
    mission_rows: Array.isArray(missionAggregate.json?.rows) ? missionAggregate.json.rows.length : 0,
  };

  result.summary = {
    pass: true,
    stories: {
      clawclaim: [
        'CCL-US-004',
        'CCL-US-005',
        'CCL-US-006',
        'CCL-US-007',
        'CCL-US-008',
        'CCL-US-009',
      ],
      clawscope: [
        'CSC-US-007',
        'CSC-US-008',
        'CSC-US-009',
        'CSC-US-010',
        'CSC-US-011',
        'CSC-US-012',
        'CSC-US-013',
      ],
    },
    checks: {
      replay_denied: exchangeReplay.status === 409,
      unknown_transition_denied: matrixUnknown.status === 400,
      token_revoked_state: introspectRevoked.json?.revoked === true,
      trace_present: Array.isArray(traceReport.json?.events) && traceReport.json.events.length > 0,
    },
  };

  writeFileSync(path.join(outDir, 'result.json'), JSON.stringify(result, null, 2));

  const summary = [
    `identity-control-plane-m5 smoke (${args.env})`,
    `generated_at=${result.generated_at}`,
    `clawclaim_version=${result.versions.clawclaim ?? 'unknown'}`,
    `clawscope_version=${result.versions.clawscope ?? 'unknown'}`,
    `clawverify_version=${result.versions.clawverify ?? 'unknown'}`,
    `owner_did=${owner.did}`,
    `token_hash=${scopedTokenHash}`,
    `trace_id=${traceId}`,
    `usage_rows=${result.steps.observability.usage_json_rows}`,
    `alert_events=${result.steps.observability.alert_events_count}`,
    `mission_rows=${result.steps.observability.mission_rows}`,
    `status=PASS`,
  ].join('\n');

  writeFileSync(path.join(outDir, 'summary.txt'), `${summary}\n`);
  process.stdout.write(`${summary}\n`);
}

main().catch((err) => {
  const msg = err instanceof Error ? `${err.stack || err.message}` : String(err);
  process.stderr.write(`${msg}\n`);
  process.exit(1);
});
