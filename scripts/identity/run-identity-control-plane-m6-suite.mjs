#!/usr/bin/env node

import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const ED25519_MULTICODEC_PREFIX = new Uint8Array([0xed, 0x01]);

function parseArgs(argv) {
  const out = {
    env: 'staging',
    outSmokeDir: '',
    outOpsDir: '',
    clawclaimVersion: '',
    clawscopeVersion: '',
    clawverifyVersion: '',
    clawcontrolsVersion: '',
    clawproxyVersion: '',
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];

    if (arg === '--env' && argv[i + 1]) {
      out.env = String(argv[++i]);
      continue;
    }

    if (arg === '--out-smoke-dir' && argv[i + 1]) {
      out.outSmokeDir = String(argv[++i]);
      continue;
    }

    if (arg === '--out-ops-dir' && argv[i + 1]) {
      out.outOpsDir = String(argv[++i]);
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

    if (arg === '--clawcontrols-version' && argv[i + 1]) {
      out.clawcontrolsVersion = String(argv[++i]);
      continue;
    }

    if (arg === '--clawproxy-version' && argv[i + 1]) {
      out.clawproxyVersion = String(argv[++i]);
      continue;
    }
  }

  return out;
}

function timestampForPath(date = new Date()) {
  return date.toISOString().replace(/:/g, '-').replace(/\./g, '-');
}

function base58Encode(bytes) {
  if (!(bytes instanceof Uint8Array)) {
    throw new TypeError('base58Encode expects Uint8Array');
  }

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

  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) {
    digits.push(0);
  }

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

async function requestJson(url, { method = 'GET', headers = {}, body } = {}) {
  const response = await fetch(url, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });

  const text = await response.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }

  return {
    status: response.status,
    ok: response.ok,
    json,
    text,
  };
}

function assertStatus(step, response, expected) {
  if (response.status !== expected) {
    const error = response.json && typeof response.json === 'object' ? response.json : { raw: response.text };
    throw new Error(`${step} expected HTTP ${expected}, got ${response.status}: ${JSON.stringify(error)}`);
  }
}

function safePick(value, fields) {
  if (!value || typeof value !== 'object') return null;
  const out = {};
  for (const field of fields) {
    if (field in value) out[field] = value[field];
  }
  return out;
}

async function bindDid(claimBaseUrl, did, privateKey) {
  const challenge = await requestJson(`${claimBaseUrl}/v1/challenges`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: { did },
  });
  assertStatus('bindDid.challenge', challenge, 200);

  const signature = await signMessage(privateKey, String(challenge.json?.message ?? ''));

  const bind = await requestJson(`${claimBaseUrl}/v1/bind`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: {
      did,
      challenge_id: challenge.json.challenge_id,
      signature_b64u: signature,
    },
  });

  assertStatus('bindDid.bind', bind, 200);
}

function recordMatrixCase(collection, name, details) {
  const entry = { name, ...details };
  collection.push(entry);
  return entry;
}

function parseErrorCode(response) {
  if (response?.json && typeof response.json === 'object') {
    if (typeof response.json.error === 'string') return response.json.error;
    if (response.json.error && typeof response.json.error.code === 'string') return response.json.error.code;
  }
  return null;
}

function parseErrorMessage(response) {
  if (response?.json && typeof response.json === 'object') {
    if (typeof response.json.message === 'string') return response.json.message;
    if (response.json.error && typeof response.json.error.message === 'string') {
      return response.json.error.message;
    }
  }
  return response.text ?? null;
}

async function setupCanonicalControlToken(baseUrls) {
  const owner = await createDidKeyPair();
  const controller = await createDidKeyPair();
  const agent = await createDidKeyPair();

  await bindDid(baseUrls.clawclaim, owner.did, owner.privateKey);
  await bindDid(baseUrls.clawclaim, controller.did, controller.privateKey);
  await bindDid(baseUrls.clawclaim, agent.did, agent.privateKey);

  const controllerChallenge = await requestJson(`${baseUrls.clawclaim}/v1/control-plane/challenges`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: {
      owner_did: owner.did,
      purpose: 'register_controller',
      controller_did: controller.did,
    },
  });
  assertStatus('controllerChallenge', controllerChallenge, 200);

  const controllerSig = await signMessage(owner.privateKey, String(controllerChallenge.json?.message ?? ''));
  const registerController = await requestJson(`${baseUrls.clawclaim}/v1/control-plane/controllers/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: {
      owner_did: owner.did,
      controller_did: controller.did,
      challenge_id: controllerChallenge.json.challenge_id,
      signature_b64u: controllerSig,
      allowed_sensitive_scopes: [
        'control:token:issue_sensitive',
        'control:token:revoke',
        'control:policy:update',
        'control:key:rotate',
        'control:audit:read',
      ],
    },
  });
  assertStatus('registerController', registerController, 200);

  const agentChallenge = await requestJson(`${baseUrls.clawclaim}/v1/control-plane/challenges`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: {
      owner_did: owner.did,
      purpose: 'register_agent',
      controller_did: controller.did,
      agent_did: agent.did,
    },
  });
  assertStatus('agentChallenge', agentChallenge, 200);

  const agentSig = await signMessage(owner.privateKey, String(agentChallenge.json?.message ?? ''));
  const registerAgent = await requestJson(
    `${baseUrls.clawclaim}/v1/control-plane/controllers/${encodeURIComponent(controller.did)}/agents/register`,
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
  assertStatus('registerAgent', registerAgent, 200);

  const aud = Array.from(
    new Set([
      'clawproxy.com',
      'clawcontrols.com',
      'clawscope.com',
      new URL(baseUrls.clawproxy).hostname,
      new URL(baseUrls.clawcontrols).hostname,
      new URL(baseUrls.clawscope).hostname,
    ])
  );

  const exchangeChallenge = await requestJson(`${baseUrls.clawclaim}/v1/scoped-tokens/challenges`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: {
      owner_did: owner.did,
      aud,
      scope: [
        'proxy:call',
        'control:policy:update',
        'control:token:revoke',
        'control:audit:read',
        'control:key:rotate',
        'control:token:issue_sensitive',
      ],
      ttl_sec: 900,
      controller_did: controller.did,
      agent_did: agent.did,
      mission_id: `m6-conformance-${Date.now()}`,
    },
  });
  assertStatus('exchangeChallenge', exchangeChallenge, 200);

  const exchangeSig = await signMessage(owner.privateKey, String(exchangeChallenge.json?.message ?? ''));

  const exchanged = await requestJson(`${baseUrls.clawclaim}/v1/scoped-tokens/exchange`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: {
      owner_did: owner.did,
      challenge_id: exchangeChallenge.json.challenge_id,
      signature_b64u: exchangeSig,
    },
  });
  assertStatus('exchangeToken', exchanged, 200);

  return {
    owner,
    controller,
    agent,
    token: exchanged.json.token,
    token_hash: exchanged.json.token_hash,
    token_kid: exchanged.json.kid,
    issue_response: exchanged.json,
  };
}

async function runConformanceMatrix(baseUrls, canonical, matrix) {
  const legacyScopeRevoke = await requestJson(`${baseUrls.clawscope}/v1/tokens/revoke`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: 'Bearer legacy-admin-token',
    },
    body: {
      token_hash: canonical.token_hash,
      reason: 'conformance-legacy-check',
    },
  });

  recordMatrixCase(matrix, 'clawscope.revoke.legacy_rejected', {
    status: legacyScopeRevoke.status,
    error: parseErrorCode(legacyScopeRevoke),
    message: parseErrorMessage(legacyScopeRevoke),
    pass: legacyScopeRevoke.status === 401,
  });

  const scopeAuditLegacy = await requestJson(`${baseUrls.clawscope}/v1/audit/issuance?limit=1`, {
    headers: { authorization: 'Bearer legacy-admin-token' },
  });

  recordMatrixCase(matrix, 'clawscope.audit.legacy_rejected', {
    status: scopeAuditLegacy.status,
    error: parseErrorCode(scopeAuditLegacy),
    message: parseErrorMessage(scopeAuditLegacy),
    pass: scopeAuditLegacy.status === 401,
  });

  const scopeAuditCanonical = await requestJson(`${baseUrls.clawscope}/v1/audit/issuance?limit=1`, {
    headers: { 'x-cst': canonical.token },
  });

  recordMatrixCase(matrix, 'clawscope.audit.canonical_accepted', {
    status: scopeAuditCanonical.status,
    error: parseErrorCode(scopeAuditCanonical),
    message: parseErrorMessage(scopeAuditCanonical),
    pass: scopeAuditCanonical.status === 200,
  });

  const controlsLegacy = await requestJson(`${baseUrls.clawcontrols}/v1/wpc`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: 'Bearer legacy-admin-token',
    },
    body: {
      wpc: {
        policy_version: '1',
        policy_id: `pol_legacy_${Date.now()}`,
        issuer_did: canonical.owner.did,
        allowed_providers: ['openai'],
        allowed_models: ['gpt-5.*'],
        redaction_rules: [{ path: '$.messages[*].content', action: 'hash' }],
        receipt_privacy_mode: 'hash_only',
        egress_allowlist: [],
      },
    },
  });

  recordMatrixCase(matrix, 'clawcontrols.wpc.legacy_rejected', {
    status: controlsLegacy.status,
    error: parseErrorCode(controlsLegacy),
    message: parseErrorMessage(controlsLegacy),
    pass: controlsLegacy.status === 401,
  });

  const controlsCanonical = await requestJson(`${baseUrls.clawcontrols}/v1/wpc`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-cst': canonical.token,
    },
    body: {
      wpc: {
        policy_version: '1',
        policy_id: `pol_canonical_${Date.now()}`,
        issuer_did: canonical.owner.did,
        allowed_providers: ['openai'],
        allowed_models: ['gpt-5.*'],
        redaction_rules: [{ path: '$.messages[*].content', action: 'hash' }],
        receipt_privacy_mode: 'hash_only',
        egress_allowlist: [],
      },
    },
  });

  recordMatrixCase(matrix, 'clawcontrols.wpc.canonical_accepted', {
    status: controlsCanonical.status,
    error: parseErrorCode(controlsCanonical),
    message: parseErrorMessage(controlsCanonical),
    pass: controlsCanonical.status === 200 || controlsCanonical.status === 201,
  });

  const proxyLegacy = await requestJson(`${baseUrls.clawproxy}/v1/chat/completions`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-provider-api-key': 'dummy-key',
    },
    body: {
      model: 'openai/gpt-4o-mini',
      messages: [{ role: 'user', content: 'Conformance legacy check' }],
    },
  });

  recordMatrixCase(matrix, 'clawproxy.proxy.legacy_rejected', {
    status: proxyLegacy.status,
    error: parseErrorCode(proxyLegacy),
    message: parseErrorMessage(proxyLegacy),
    pass: parseErrorCode(proxyLegacy) === 'TOKEN_REQUIRED',
  });

  const proxyCanonical = await requestJson(`${baseUrls.clawproxy}/v1/chat/completions`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-cst': canonical.token,
    },
    body: {
      model: 'openai/gpt-4o-mini',
      messages: [{ role: 'user', content: 'Conformance canonical check' }],
    },
  });

  const proxyCanonicalCode = parseErrorCode(proxyCanonical);
  const proxyCanonicalAuthFailureCodes = new Set([
    'TOKEN_REQUIRED',
    'TOKEN_BAD_AUDIENCE',
    'TOKEN_INVALID_CLAIMS',
    'TOKEN_SIGNATURE_INVALID',
    'TOKEN_SCOPE_HASH_MISMATCH',
    'TOKEN_SCOPE_HASH_INVALID',
    'TOKEN_CONTROL_CHAIN_MISSING',
    'TOKEN_INSUFFICIENT_SCOPE',
    'TOKEN_CONTROL_SUBJECT_MISMATCH',
  ]);

  recordMatrixCase(matrix, 'clawproxy.proxy.canonical_accepted', {
    status: proxyCanonical.status,
    error: proxyCanonicalCode,
    message: parseErrorMessage(proxyCanonical),
    pass: !proxyCanonicalAuthFailureCodes.has(proxyCanonicalCode ?? ''),
  });

  const scopeRevokeCanonical = await requestJson(`${baseUrls.clawscope}/v1/tokens/revoke`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-cst': canonical.token,
    },
    body: {
      token_hash: canonical.token_hash,
      reason: 'conformance-canonical-check',
    },
  });

  const revokeStatus = scopeRevokeCanonical.json?.status;
  recordMatrixCase(matrix, 'clawscope.revoke.canonical_accepted', {
    status: scopeRevokeCanonical.status,
    error: parseErrorCode(scopeRevokeCanonical),
    message: parseErrorMessage(scopeRevokeCanonical),
    revoke_status: revokeStatus,
    pass: scopeRevokeCanonical.status === 200 && (revokeStatus === 'revoked' || revokeStatus === 'already_revoked'),
  });
}

async function runRecoveryDrill(baseUrls, canonical) {
  const exportChallenge = await requestJson(`${baseUrls.clawclaim}/v1/control-plane/challenges`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: {
      owner_did: canonical.owner.did,
      purpose: 'export_identity',
      controller_did: canonical.controller.did,
    },
  });
  assertStatus('recovery.exportChallenge', exportChallenge, 200);

  const exportSig = await signMessage(canonical.owner.privateKey, String(exportChallenge.json?.message ?? ''));

  const exported = await requestJson(`${baseUrls.clawclaim}/v1/control-plane/identity/export`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: {
      owner_did: canonical.owner.did,
      controller_did: canonical.controller.did,
      challenge_id: exportChallenge.json.challenge_id,
      signature_b64u: exportSig,
    },
  });
  assertStatus('recovery.export', exported, 200);

  const bundle = exported.json?.export_bundle;
  const bundleHash = bundle?.bundle_hash_b64u;

  const importChallenge = await requestJson(`${baseUrls.clawclaim}/v1/control-plane/challenges`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: {
      owner_did: canonical.owner.did,
      purpose: 'import_identity',
      bundle_hash_b64u: bundleHash,
    },
  });
  assertStatus('recovery.importChallenge', importChallenge, 200);

  const importSig = await signMessage(canonical.owner.privateKey, String(importChallenge.json?.message ?? ''));

  const tamperedBundle = structuredClone(bundle);
  if (tamperedBundle?.payload?.controller?.policy) {
    tamperedBundle.payload.controller.policy.policy_hash_b64u = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
  }

  const tamperedImport = await requestJson(`${baseUrls.clawclaim}/v1/control-plane/identity/import`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: {
      owner_did: canonical.owner.did,
      challenge_id: importChallenge.json.challenge_id,
      signature_b64u: importSig,
      bundle: tamperedBundle,
    },
  });

  const importChallengeValid = await requestJson(`${baseUrls.clawclaim}/v1/control-plane/challenges`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: {
      owner_did: canonical.owner.did,
      purpose: 'import_identity',
      bundle_hash_b64u: bundleHash,
    },
  });
  assertStatus('recovery.importChallengeValid', importChallengeValid, 200);

  const importSigValid = await signMessage(
    canonical.owner.privateKey,
    String(importChallengeValid.json?.message ?? '')
  );

  const imported = await requestJson(`${baseUrls.clawclaim}/v1/control-plane/identity/import`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: {
      owner_did: canonical.owner.did,
      challenge_id: importChallengeValid.json.challenge_id,
      signature_b64u: importSigValid,
      bundle,
    },
  });

  const importChallengeReplay = await requestJson(`${baseUrls.clawclaim}/v1/control-plane/challenges`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: {
      owner_did: canonical.owner.did,
      purpose: 'import_identity',
      bundle_hash_b64u: bundleHash,
    },
  });
  assertStatus('recovery.importChallengeReplay', importChallengeReplay, 200);

  const importSigReplay = await signMessage(
    canonical.owner.privateKey,
    String(importChallengeReplay.json?.message ?? '')
  );

  const replayImport = await requestJson(`${baseUrls.clawclaim}/v1/control-plane/identity/import`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: {
      owner_did: canonical.owner.did,
      challenge_id: importChallengeReplay.json.challenge_id,
      signature_b64u: importSigReplay,
      bundle,
    },
  });

  return {
    export: safePick(exported.json, ['status', 'event_key']),
    tampered_import: {
      status: tamperedImport.status,
      error: parseErrorCode(tamperedImport),
      message: parseErrorMessage(tamperedImport),
      pass: tamperedImport.status === 409 && parseErrorCode(tamperedImport) === 'IMPORT_BUNDLE_TAMPERED',
    },
    import_valid: {
      status: imported.status,
      body: imported.json,
      pass:
        imported.status === 200 &&
        (imported.json?.status === 'imported' || imported.json?.status === 'already_imported'),
    },
    import_replay: {
      status: replayImport.status,
      body: replayImport.json,
      pass: replayImport.status === 200 && replayImport.json?.status === 'already_imported',
    },
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.env !== 'staging' && args.env !== 'prod') {
    throw new Error('--env must be one of: staging | prod');
  }

  const baseUrls =
    args.env === 'prod'
      ? {
          clawclaim: 'https://clawclaim.com',
          clawscope: 'https://clawscope.com',
          clawverify: 'https://clawverify.com',
          clawcontrols: 'https://clawcontrols.com',
          clawproxy: 'https://clawproxy.com',
        }
      : {
          clawclaim: 'https://staging.clawclaim.com',
          clawscope: 'https://staging.clawscope.com',
          clawverify: 'https://staging.clawverify.com',
          clawcontrols: 'https://staging.clawcontrols.com',
          clawproxy: 'https://staging.clawproxy.com',
        };

  const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
  const timestamp = timestampForPath();

  const smokeDir =
    args.outSmokeDir || path.join(rootDir, 'artifacts', 'smoke', 'identity-control-plane', `${timestamp}-${args.env}`);
  const opsDir =
    args.outOpsDir || path.join(rootDir, 'artifacts', 'ops', 'identity-control-plane', `${timestamp}-${args.env}`);

  mkdirSync(smokeDir, { recursive: true });
  mkdirSync(opsDir, { recursive: true });

  const canonical = await setupCanonicalControlToken(baseUrls);

  const keyTransparencyLatest = await requestJson(`${baseUrls.clawscope}/v1/keys/transparency/latest`);
  const keyTransparencyHistory = await requestJson(`${baseUrls.clawscope}/v1/keys/transparency/history?limit=5`, {
    headers: { 'x-cst': canonical.token },
  });
  const keyTransparencyForced = await requestJson(`${baseUrls.clawscope}/v1/keys/transparency/snapshot`, {
    method: 'POST',
    headers: {
      'x-cst': canonical.token,
      'content-type': 'application/json',
    },
    body: {},
  });

  const keyTransparencyReport = {
    env: args.env,
    generated_at: new Date().toISOString(),
    latest: {
      status: keyTransparencyLatest.status,
      payload: keyTransparencyLatest.json,
    },
    history: {
      status: keyTransparencyHistory.status,
      payload: keyTransparencyHistory.json,
    },
    force_snapshot: {
      status: keyTransparencyForced.status,
      payload: keyTransparencyForced.json,
    },
    validations: {
      latest_has_active_kid: typeof keyTransparencyLatest.json?.active_kid === 'string',
      latest_has_accepted_kids: Array.isArray(keyTransparencyLatest.json?.accepted_kids),
      latest_signature_present: typeof keyTransparencyLatest.json?.signature_b64u === 'string',
      forced_snapshot_succeeded: keyTransparencyForced.status === 200,
    },
  };

  const revocationSlo = await requestJson(
    `${baseUrls.clawscope}/v1/reports/revocation-slo?window_hours=24&persist=true`,
    {
      headers: { 'x-cst': canonical.token },
    }
  );

  const revocationSloReport = {
    env: args.env,
    generated_at: new Date().toISOString(),
    status: revocationSlo.status,
    payload: revocationSlo.json,
    validations: {
      report_version: revocationSlo.json?.report_version === '1',
      has_latency: typeof revocationSlo.json?.latency_seconds === 'object',
      has_total_revocations: typeof revocationSlo.json?.total_revocations === 'number',
    },
  };

  const recoveryDrillReport = {
    env: args.env,
    generated_at: new Date().toISOString(),
    ...(await runRecoveryDrill(baseUrls, canonical)),
  };

  const matrix = [];
  await runConformanceMatrix(baseUrls, canonical, matrix);

  const conformance = {
    env: args.env,
    generated_at: new Date().toISOString(),
    urls: baseUrls,
    token_context: {
      owner_did: canonical.owner.did,
      controller_did: canonical.controller.did,
      agent_did: canonical.agent.did,
      token_hash: canonical.token_hash,
      token_kid: canonical.token_kid,
    },
    cases: matrix,
    summary: {
      total: matrix.length,
      passed: matrix.filter((entry) => entry.pass).length,
      failed: matrix.filter((entry) => !entry.pass).length,
    },
  };

  const deploySummary = {
    env: args.env,
    generated_at: new Date().toISOString(),
    deployment_versions: {
      clawclaim: args.clawclaimVersion || null,
      clawscope: args.clawscopeVersion || null,
      clawverify: args.clawverifyVersion || null,
      clawcontrols: args.clawcontrolsVersion || null,
      clawproxy: args.clawproxyVersion || null,
    },
    outputs: {
      conformance_matrix: path.join(smokeDir, 'conformance-matrix.json'),
      key_transparency_report: path.join(opsDir, 'key-transparency-report.json'),
      revocation_slo_report: path.join(opsDir, 'revocation-slo-report.json'),
      recovery_drill_report: path.join(opsDir, 'recovery-drill-report.json'),
    },
    pass: {
      conformance: conformance.summary.failed === 0,
      key_transparency:
        keyTransparencyReport.validations.latest_has_active_kid &&
        keyTransparencyReport.validations.latest_has_accepted_kids &&
        keyTransparencyReport.validations.latest_signature_present &&
        keyTransparencyReport.validations.forced_snapshot_succeeded,
      revocation_slo:
        revocationSloReport.status === 200 &&
        revocationSloReport.validations.report_version &&
        revocationSloReport.validations.has_latency,
      recovery_drill:
        recoveryDrillReport.tampered_import.pass &&
        recoveryDrillReport.import_valid.pass &&
        recoveryDrillReport.import_replay.pass,
    },
  };

  writeFileSync(path.join(smokeDir, 'conformance-matrix.json'), JSON.stringify(conformance, null, 2));
  writeFileSync(path.join(opsDir, 'key-transparency-report.json'), JSON.stringify(keyTransparencyReport, null, 2));
  writeFileSync(path.join(opsDir, 'revocation-slo-report.json'), JSON.stringify(revocationSloReport, null, 2));
  writeFileSync(path.join(opsDir, 'recovery-drill-report.json'), JSON.stringify(recoveryDrillReport, null, 2));
  writeFileSync(path.join(opsDir, 'deploy-summary.json'), JSON.stringify(deploySummary, null, 2));

  const finalSummary = {
    smoke_dir: smokeDir,
    ops_dir: opsDir,
    conformance_failed: conformance.summary.failed,
    overall_pass: Object.values(deploySummary.pass).every(Boolean),
  };

  process.stdout.write(`${JSON.stringify(finalSummary, null, 2)}\n`);

  if (!finalSummary.overall_pass) {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack || error.message : String(error));
  process.exitCode = 1;
});
