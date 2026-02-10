#!/usr/bin/env node

/**
 * Smoke test: OpenRouter-through-fal via clawproxy (PoH receipts)
 *
 * Validates the end-to-end path:
 *   clawproxy (OpenAI compat) → fal OpenRouter router → _receipt_envelope → clawverify
 *
 * Usage:
 *   node scripts/poh/smoke-fal-openrouter-via-clawproxy.mjs --env staging
 *   node scripts/poh/smoke-fal-openrouter-via-clawproxy.mjs --env prod
 *
 * Required env vars:
 *   - FAL_KEY (fal.ai API key used by the fal OpenRouter router)
 *
 * Notes:
 * - This script performs real upstream calls and will incur usage costs.
 * - The gateway must forward auth upstream as: Authorization: Key <FAL_KEY>.
 */

import process from 'node:process';
import crypto from 'node:crypto';

function parseArgs(argv) {
  const args = new Map();
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) continue;
    const key = a.slice(2);
    const next = argv[i + 1];
    if (next && !next.startsWith('--')) {
      args.set(key, next);
      i++;
    } else {
      args.set(key, 'true');
    }
  }
  return args;
}

function assert(cond, msg) {
  if (!cond) throw new Error(`ASSERT_FAILED: ${msg}`);
}

function isRecord(x) {
  return typeof x === 'object' && x !== null && !Array.isArray(x);
}

function sha256B64u(utf8) {
  return crypto.createHash('sha256').update(utf8, 'utf8').digest('base64url');
}

// RFC 8785 (JCS) — keep in sync with services/clawproxy/src/jcs.ts
function jcsCanonicalize(value) {
  if (value === null) return 'null';

  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';

    case 'number':
      if (!Number.isFinite(value)) {
        throw new Error('Non-finite number not allowed in JCS');
      }
      return JSON.stringify(value);

    case 'string':
      return JSON.stringify(value);

    case 'object': {
      if (Array.isArray(value)) {
        return `[${value.map(jcsCanonicalize).join(',')}]`;
      }

      const obj = value;
      const keys = Object.keys(obj).sort();
      const parts = [];

      for (const k of keys) {
        parts.push(`${JSON.stringify(k)}:${jcsCanonicalize(obj[k])}`);
      }

      return `{${parts.join(',')}}`;
    }

    default:
      throw new Error(`Unsupported value type for JCS: ${typeof value}`);
  }
}

function assertModelIdentity(metadata, expectedModelLabel, ctx) {
  assert(isRecord(metadata), `${ctx} metadata missing`);

  const mi = metadata.model_identity;
  assert(isRecord(mi), `${ctx} missing payload.metadata.model_identity`);

  assert(mi.model_identity_version === '1', `${ctx} model_identity.model_identity_version expected "1", got ${String(mi.model_identity_version)}`);
  assert(mi.tier === 'closed_opaque', `${ctx} model_identity.tier expected closed_opaque, got ${String(mi.tier)}`);

  const m = mi.model;
  assert(isRecord(m), `${ctx} model_identity.model missing/invalid`);
  assert(typeof m.provider === 'string' && m.provider.trim().length > 0, `${ctx} model_identity.model.provider missing/invalid`);
  assert(typeof m.name === 'string' && m.name.trim().length > 0, `${ctx} model_identity.model.name missing/invalid`);
  assert(m.name === expectedModelLabel, `${ctx} model_identity.model.name expected ${expectedModelLabel}, got ${String(m.name)}`);

  const hash = metadata.model_identity_hash_b64u;
  assert(typeof hash === 'string' && hash.trim().length > 0, `${ctx} missing payload.metadata.model_identity_hash_b64u`);

  const expected = sha256B64u(jcsCanonicalize(mi));
  assert(hash === expected, `${ctx} model_identity_hash_b64u mismatch (expected ${expected}, got ${hash})`);
}

function assertVerifyModelIdentity(verifyJson, ctx) {
  assert(isRecord(verifyJson), `${ctx} response missing/invalid JSON`);

  assert(
    verifyJson.model_identity_tier === 'closed_opaque',
    `${ctx} model_identity_tier expected closed_opaque, got ${String(verifyJson.model_identity_tier)}`
  );

  const flags = verifyJson.risk_flags;
  assert(Array.isArray(flags), `${ctx} risk_flags missing/invalid`);
  assert(
    flags.includes('MODEL_IDENTITY_OPAQUE'),
    `${ctx} risk_flags missing MODEL_IDENTITY_OPAQUE`
  );
}

async function httpJson(url, init) {
  const res = await fetch(url, init);
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }
  return { res, status: res.status, text, json };
}

function getReceiptEnvelope(body) {
  if (!isRecord(body)) return null;
  const env = body._receipt_envelope;
  return isRecord(env) ? env : null;
}

function getEnvelopeMetadata(envelope) {
  if (!isRecord(envelope)) return null;
  const payload = envelope.payload;
  if (!isRecord(payload)) return null;
  const metadata = payload.metadata;
  return isRecord(metadata) ? metadata : null;
}

async function verifyReceipt(verifyBaseUrl, envelope) {
  const out = await httpJson(`${verifyBaseUrl.replace(/\/$/, '')}/v1/verify/receipt`, {
    method: 'POST',
    headers: { 'content-type': 'application/json; charset=utf-8' },
    body: JSON.stringify({ envelope }),
  });

  return out;
}

async function smoke() {
  const args = parseArgs(process.argv.slice(2));
  const envName = String(args.get('env') || 'staging').toLowerCase();
  const model = String(args.get('model') || 'openrouter/openai/gpt-4o-mini');

  const falKey = process.env.FAL_KEY;
  assert(typeof falKey === 'string' && falKey.trim().length > 0, 'Missing FAL_KEY env var');

  const proxyBaseUrl =
    envName === 'prod' || envName === 'production'
      ? 'https://clawproxy.com'
      : 'https://staging.clawproxy.com';

  const verifyBaseUrl =
    envName === 'prod' || envName === 'production'
      ? 'https://clawverify.com'
      : 'https://staging.clawverify.com';

  const expectedUpstreamModel = model.replace(/^openrouter\//i, '');

  // 1) chat/completions
  const chat = await httpJson(`${proxyBaseUrl}/v1/chat/completions`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'x-provider-api-key': falKey.trim(),
    },
    body: JSON.stringify({
      model,
      messages: [{ role: 'user', content: 'smoke: openrouter via fal via clawproxy' }],
      max_tokens: 1,
      temperature: 0,
    }),
  });

  assert(chat.status === 200, `chat/completions expected 200, got ${chat.status}: ${chat.text}`);

  const chatEnv = getReceiptEnvelope(chat.json);
  assert(chatEnv, 'chat/completions missing _receipt_envelope');

  const chatMeta = getEnvelopeMetadata(chatEnv);
  assert(chatMeta, 'chat/completions receipt envelope missing payload.metadata');
  assert(chatMeta.upstream === 'fal_openrouter', `chat/completions metadata.upstream expected fal_openrouter, got ${String(chatMeta.upstream)}`);
  assert(
    chatMeta.upstream_model === expectedUpstreamModel,
    `chat/completions metadata.upstream_model expected ${expectedUpstreamModel}, got ${String(chatMeta.upstream_model)}`
  );

  // CPX-US-016: model identity must be present and honest for closed providers.
  assertModelIdentity(chatMeta, model, 'chat/completions');

  const chatVerify = await verifyReceipt(verifyBaseUrl, chatEnv);
  assert(chatVerify.status === 200, `verify/receipt (chat) expected 200, got ${chatVerify.status}: ${chatVerify.text}`);
  assert(chatVerify.json?.result?.status === 'VALID', `verify/receipt (chat) expected VALID, got: ${chatVerify.text}`);
  assertVerifyModelIdentity(chatVerify.json, 'verify/receipt (chat)');

  // 2) responses
  const responses = await httpJson(`${proxyBaseUrl}/v1/responses`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'x-provider-api-key': falKey.trim(),
    },
    body: JSON.stringify({
      model,
      input: 'smoke: openrouter via fal via clawproxy',
      max_output_tokens: 1,
    }),
  });

  assert(responses.status === 200, `responses expected 200, got ${responses.status}: ${responses.text}`);

  const respEnv = getReceiptEnvelope(responses.json);
  assert(respEnv, 'responses missing _receipt_envelope');

  const respMeta = getEnvelopeMetadata(respEnv);
  assert(respMeta, 'responses receipt envelope missing payload.metadata');
  assert(respMeta.upstream === 'fal_openrouter', `responses metadata.upstream expected fal_openrouter, got ${String(respMeta.upstream)}`);
  assert(
    respMeta.upstream_model === expectedUpstreamModel,
    `responses metadata.upstream_model expected ${expectedUpstreamModel}, got ${String(respMeta.upstream_model)}`
  );

  // CPX-US-016: model identity must be present and honest for closed providers.
  assertModelIdentity(respMeta, model, 'responses');

  const respVerify = await verifyReceipt(verifyBaseUrl, respEnv);
  assert(respVerify.status === 200, `verify/receipt (responses) expected 200, got ${respVerify.status}: ${respVerify.text}`);
  assert(respVerify.json?.result?.status === 'VALID', `verify/receipt (responses) expected VALID, got: ${respVerify.text}`);
  assertVerifyModelIdentity(respVerify.json, 'verify/receipt (responses)');

  console.log(
    JSON.stringify(
      {
        ok: true,
        env: envName,
        model,
        proxyBaseUrl,
        verifyBaseUrl,
        chat: {
          status: chat.status,
          upstream: chatMeta.upstream,
          upstream_model: chatMeta.upstream_model,
          model_identity_tier: chatMeta.model_identity?.tier,
          model_identity_hash_b64u: chatMeta.model_identity_hash_b64u,
          verify_status: chatVerify.json?.result?.status,
          verify_model_identity_tier: chatVerify.json?.model_identity_tier,
        },
        responses: {
          status: responses.status,
          upstream: respMeta.upstream,
          upstream_model: respMeta.upstream_model,
          model_identity_tier: respMeta.model_identity?.tier,
          model_identity_hash_b64u: respMeta.model_identity_hash_b64u,
          verify_status: respVerify.json?.result?.status,
          verify_model_identity_tier: respVerify.json?.model_identity_tier,
        },
      },
      null,
      2
    )
  );
}

smoke().catch((err) => {
  console.error(err);
  process.exit(1);
});
