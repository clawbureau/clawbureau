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
    const error =
      response.json && typeof response.json === 'object' ? response.json : { raw: response.text };
    throw new Error(
      `${step} expected HTTP ${expected}, got ${response.status}: ${JSON.stringify(error)}`
    );
  }
}

function timestampForPath(date = new Date()) {
  return date.toISOString().replace(/:/g, '-').replace(/\./g, '-');
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

  return {
    challenge: safePick(challenge.json, ['challenge_id', 'expires_in_sec']),
    bind: safePick(bind.json, ['status', 'did', 'bound_at']),
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.env !== 'staging' && args.env !== 'prod') {
    throw new Error('--env must be one of: staging | prod');
  }

  if (!args.scopeAdminKey) {
    throw new Error('SCOPE_ADMIN_KEY is required (pass --scope-admin-key or env var).');
  }

  const baseUrls =
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
    args.outDir || path.join(rootDir, 'artifacts', 'smoke', 'identity-control-plane', `${timestamp}-${args.env}`);

  mkdirSync(outDir, { recursive: true });

  const result = {
    env: args.env,
    generated_at: new Date().toISOString(),
    urls: baseUrls,
    identities: {},
    steps: {},
    deterministic_error_codes: {},
    deployment_versions: {
      clawclaim: args.clawclaimVersion || null,
      clawscope: args.clawscopeVersion || null,
      clawverify: args.clawverifyVersion || null,
    },
  };

  const owner = await createDidKeyPair();
  const controller = await createDidKeyPair();
  const agent = await createDidKeyPair();

  result.identities = {
    owner_did: owner.did,
    controller_did: controller.did,
    agent_did: agent.did,
  };

  result.steps.bind_owner = await bindDid(baseUrls.clawclaim, owner.did, owner.privateKey);
  result.steps.bind_controller = await bindDid(baseUrls.clawclaim, controller.did, controller.privateKey);
  result.steps.bind_agent = await bindDid(baseUrls.clawclaim, agent.did, agent.privateKey);

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
      allowed_sensitive_scopes: ['control:token:issue_sensitive', 'control:key:rotate'],
    },
  });
  assertStatus('registerController', registerController, 200);

  result.steps.register_controller = safePick(registerController.json, ['status', 'event_key']);

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

  result.steps.register_agent = safePick(registerAgent.json, ['status', 'event_key']);

  const policyChallenge = await requestJson(`${baseUrls.clawclaim}/v1/control-plane/challenges`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: {
      owner_did: owner.did,
      purpose: 'update_sensitive_policy',
      controller_did: controller.did,
    },
  });
  assertStatus('policyChallenge', policyChallenge, 200);

  const policySig = await signMessage(owner.privateKey, String(policyChallenge.json?.message ?? ''));
  const updatePolicy = await requestJson(
    `${baseUrls.clawclaim}/v1/control-plane/controllers/${encodeURIComponent(controller.did)}/sensitive-policy`,
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: {
        owner_did: owner.did,
        challenge_id: policyChallenge.json.challenge_id,
        signature_b64u: policySig,
        allowed_sensitive_scopes: ['control:token:issue_sensitive', 'control:key:rotate'],
      },
    }
  );
  assertStatus('updatePolicy', updatePolicy, 200);

  result.steps.update_sensitive_policy = safePick(updatePolicy.json, ['status', 'event_key']);

  const chainRead = await requestJson(
    `${baseUrls.clawclaim}/v1/control-plane/controllers/${encodeURIComponent(controller.did)}/agents/${encodeURIComponent(agent.did)}`
  );
  assertStatus('chainRead', chainRead, 200);

  result.steps.chain_read = {
    status: chainRead.json?.status,
    chain: safePick(chainRead.json?.chain, [
      'owner_did',
      'controller_did',
      'agent_did',
      'policy_hash_b64u',
      'active',
    ]),
  };

  const canonicalIssue = await requestJson(`${baseUrls.clawscope}/v1/tokens/issue/canonical`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${args.scopeAdminKey}`,
      'content-type': 'application/json',
    },
    body: {
      sub: agent.did,
      owner_did: owner.did,
      controller_did: controller.did,
      agent_did: agent.did,
      aud: 'staging.clawproxy.com',
      scope: ['control:token:issue_sensitive'],
      ttl_sec: 600,
    },
  });
  assertStatus('canonicalIssue', canonicalIssue, 200);

  const canonicalToken = canonicalIssue.json.token;
  const canonicalTokenHash = canonicalIssue.json.token_hash;

  result.steps.canonical_issue = safePick(canonicalIssue.json, [
    'token_hash',
    'token_lane',
    'owner_did',
    'controller_did',
    'agent_did',
    'control_plane_policy_hash_b64u',
    'policy_hash_b64u',
    'token_scope_hash_b64u',
    'iat',
    'exp',
  ]);

  const introspectCanonical = await requestJson(`${baseUrls.clawscope}/v1/tokens/introspect`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: { token: canonicalToken },
  });
  assertStatus('introspectCanonical', introspectCanonical, 200);

  result.steps.introspect_canonical = safePick(introspectCanonical.json, [
    'active',
    'token_hash',
    'token_lane',
    'owner_did',
    'controller_did',
    'agent_did',
    'token_scope_hash_b64u',
  ]);

  const matrixCanonical = await requestJson(`${baseUrls.clawscope}/v1/tokens/introspect/matrix`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: { token: canonicalToken },
  });
  assertStatus('matrixCanonical', matrixCanonical, 200);

  result.steps.matrix_canonical = {
    active: matrixCanonical.json?.active,
    token_hash: matrixCanonical.json?.token_hash,
    token_issue_sensitive: matrixCanonical.json?.matrix?.['token.issue.sensitive'] ?? null,
    key_rotate: matrixCanonical.json?.matrix?.['key.rotate'] ?? null,
  };

  const legacySensitive = await requestJson(`${baseUrls.clawscope}/v1/tokens/issue`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${args.scopeAdminKey}`,
      'content-type': 'application/json',
    },
    body: {
      sub: agent.did,
      aud: 'staging.clawproxy.com',
      scope: ['control:token:issue_sensitive'],
      ttl_sec: 600,
    },
  });

  result.steps.legacy_sensitive_issue = {
    status: legacySensitive.status,
    error: legacySensitive.json?.error,
    message: legacySensitive.json?.message,
  };

  const legacyNonSensitive = await requestJson(`${baseUrls.clawscope}/v1/tokens/issue`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${args.scopeAdminKey}`,
      'content-type': 'application/json',
    },
    body: {
      sub: agent.did,
      aud: 'staging.clawproxy.com',
      scope: ['clawproxy:call'],
      ttl_sec: 600,
    },
  });
  assertStatus('legacyNonSensitiveIssue', legacyNonSensitive, 200);

  result.steps.legacy_non_sensitive_issue = safePick(legacyNonSensitive.json, [
    'token_hash',
    'token_lane',
    'legacy_exchange_mode',
    'migration_notice',
  ]);

  const rotationContract = await requestJson(`${baseUrls.clawscope}/v1/keys/rotation-contract`);
  assertStatus('rotationContract', rotationContract, 200);

  result.steps.rotation_contract = safePick(rotationContract.json, [
    'contract_version',
    'active_kid',
    'accepted_kids',
    'overlap_seconds',
    'revocation_stream_endpoint',
  ]);

  const verifyControlChain = await requestJson(`${baseUrls.clawverify}/v1/verify/control-chain`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: {
      owner_did: owner.did,
      controller_did: controller.did,
      agent_did: agent.did,
    },
  });
  assertStatus('verifyControlChain', verifyControlChain, 200);

  result.steps.verify_control_chain = {
    status: verifyControlChain.status,
    result: verifyControlChain.json?.result,
  };

  const verifyTokenControlValid = await requestJson(`${baseUrls.clawverify}/v1/verify/token-control`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: {
      token: canonicalToken,
      expected_owner_did: owner.did,
      expected_controller_did: controller.did,
      expected_agent_did: agent.did,
      required_audience: ['staging.clawproxy.com'],
      required_scope: ['control:token:issue_sensitive'],
      required_transitions: ['token.issue.sensitive'],
    },
  });
  assertStatus('verifyTokenControlValid', verifyTokenControlValid, 200);

  result.steps.verify_token_control_valid = {
    status: verifyTokenControlValid.status,
    result: verifyTokenControlValid.json?.result,
    token_lane: verifyTokenControlValid.json?.token_lane,
  };

  const verifyTokenControlDenied = await requestJson(`${baseUrls.clawverify}/v1/verify/token-control`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: {
      token: canonicalToken,
      required_transitions: ['key.rotate'],
    },
  });

  result.steps.verify_token_control_denied = {
    status: verifyTokenControlDenied.status,
    error: verifyTokenControlDenied.json?.error,
    result: verifyTokenControlDenied.json?.result,
  };

  const revokeCanonical = await requestJson(`${baseUrls.clawscope}/v1/tokens/revoke`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${args.scopeAdminKey}`,
      'content-type': 'application/json',
    },
    body: {
      token_hash: canonicalTokenHash,
      reason: 'identity-control-plane-smoke',
    },
  });
  assertStatus('revokeCanonical', revokeCanonical, 200);

  result.steps.revoke_canonical = safePick(revokeCanonical.json, [
    'status',
    'token_hash',
    'revoked_at',
    'event_key',
  ]);

  const revocationStream = await requestJson(
    `${baseUrls.clawscope}/v1/revocations/stream?limit=5`,
    {
      headers: {
        authorization: `Bearer ${args.scopeAdminKey}`,
      },
    }
  );
  assertStatus('revocationStream', revocationStream, 200);

  result.steps.revocation_stream = {
    stream_version: revocationStream.json?.stream_version,
    events_count: Array.isArray(revocationStream.json?.events) ? revocationStream.json.events.length : 0,
  };

  const verifyTokenControlRevoked = await requestJson(`${baseUrls.clawverify}/v1/verify/token-control`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: {
      token: canonicalToken,
      required_scope: ['control:token:issue_sensitive'],
    },
  });

  result.steps.verify_token_control_revoked = {
    status: verifyTokenControlRevoked.status,
    error: verifyTokenControlRevoked.json?.error,
    result: verifyTokenControlRevoked.json?.result,
  };

  result.deterministic_error_codes = {
    legacy_sensitive_issue: legacySensitive.json?.error ?? null,
    verify_token_control_denied: verifyTokenControlDenied.json?.error?.code ?? null,
    verify_token_control_revoked: verifyTokenControlRevoked.json?.error?.code ?? null,
  };

  const summaryLines = [
    `env: ${result.env}`,
    `generated_at: ${result.generated_at}`,
    `owner_did: ${result.identities.owner_did}`,
    `controller_did: ${result.identities.controller_did}`,
    `agent_did: ${result.identities.agent_did}`,
    '',
    `canonical_issue: ${result.steps.canonical_issue?.token_hash}`,
    `legacy_sensitive_issue_error: ${result.deterministic_error_codes.legacy_sensitive_issue}`,
    `verify_token_control_denied_error: ${result.deterministic_error_codes.verify_token_control_denied}`,
    `verify_token_control_revoked_error: ${result.deterministic_error_codes.verify_token_control_revoked}`,
  ];

  writeFileSync(path.join(outDir, 'result.json'), JSON.stringify(result, null, 2));
  writeFileSync(path.join(outDir, 'summary.txt'), `${summaryLines.join('\n')}\n`);

  console.log(JSON.stringify({ ok: true, out_dir: outDir }, null, 2));
}

main().catch((err) => {
  const message = err instanceof Error ? err.message : String(err);
  console.error(JSON.stringify({ ok: false, error: message }, null, 2));
  process.exit(1);
});
