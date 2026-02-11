#!/usr/bin/env node

/**
 * Smoke test: CEA-US-010 sandbox execution attestation (end-to-end)
 *
 * Flow:
 *  1) Build a minimal self-signed proof_bundle envelope (agent DID + 1-event chain)
 *  2) Ask clawea to mint an execution_attestation bound to:
 *      - run_id (from event_chain[0].run_id)
 *      - proof_bundle_hash_b64u (proof_bundle.payload_hash_b64u)
 *  3) Verify the execution_attestation via clawverify
 *  4) Verify the proof bundle via clawverify, providing execution_attestations[]
 *     and assert proof_tier uplifts to sandbox
 *  5) Verify /v1/verify/agent with execution_attestations[] and assert uplift
 *
 * Usage:
 *   CLAWEA_TENANT_KEY=... node scripts/poh/smoke-execution-attestation.mjs --env staging --agent <agentId>
 *   CLAWEA_TENANT_KEY=... node scripts/poh/smoke-execution-attestation.mjs --env prod --agent <agentId>
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

function base64urlEncode(data) {
  return Buffer.from(data)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

const BASE58_ALPHABET =
  '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Encode(bytes) {
  if (bytes.length === 0) return '';

  const digits = [0];

  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i++) {
      const x = digits[i] * 256 + carry;
      digits[i] = x % 58;
      carry = Math.floor(x / 58);
    }
    while (carry) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }

  // leading zeros
  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) {
    digits.push(0);
  }

  return digits
    .reverse()
    .map((d) => BASE58_ALPHABET[d])
    .join('');
}

async function sha256B64uJson(value) {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  const hash = await crypto.subtle.digest('SHA-256', bytes);
  return base64urlEncode(new Uint8Array(hash));
}

async function makeDidKeyEd25519() {
  const keypair = await crypto.subtle.generateKey('Ed25519', true, [
    'sign',
    'verify',
  ]);

  const publicKeyBytes = new Uint8Array(
    await crypto.subtle.exportKey('raw', keypair.publicKey)
  );

  const prefixed = new Uint8Array(2 + publicKeyBytes.length);
  prefixed[0] = 0xed;
  prefixed[1] = 0x01;
  prefixed.set(publicKeyBytes, 2);

  const did = `did:key:z${base58Encode(prefixed)}`;
  return { did, privateKey: keypair.privateKey };
}

async function signB64uEd25519(privateKey, msg) {
  const msgBytes = new TextEncoder().encode(msg);
  const sigBuf = await crypto.subtle.sign({ name: 'Ed25519' }, privateKey, msgBytes);
  return base64urlEncode(new Uint8Array(sigBuf));
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

function resolveBaseUrls(envName) {
  const envNorm = envName === 'prod' ? 'production' : envName;

  const claweaBaseUrl =
    envNorm === 'staging'
      ? 'https://staging.clawea.com'
      : 'https://clawea.com';

  const clawverifyBaseUrl =
    envNorm === 'staging'
      ? 'https://staging.clawverify.com'
      : 'https://clawverify.com';

  return { claweaBaseUrl, clawverifyBaseUrl };
}

async function buildProofBundleEnvelope({ agentDid, agentPrivateKey, runId }) {
  // Build a minimal 1-event chain
  const e1PayloadHash = await sha256B64uJson({ type: 'llm_call' });
  const e1Header = {
    event_id: `evt_${crypto.randomUUID()}`,
    run_id: runId,
    event_type: 'llm_call',
    timestamp: new Date().toISOString(),
    payload_hash_b64u: e1PayloadHash,
    prev_hash_b64u: null,
  };
  const e1Hash = await sha256B64uJson(e1Header);

  const bundlePayload = {
    bundle_version: '1',
    bundle_id: `bundle_${crypto.randomUUID()}`,
    agent_did: agentDid,
    event_chain: [
      {
        ...e1Header,
        event_hash_b64u: e1Hash,
      },
    ],
  };

  const payloadHash = await sha256B64uJson(bundlePayload);
  const signature = await signB64uEd25519(agentPrivateKey, payloadHash);

  const envelope = {
    envelope_version: '1',
    envelope_type: 'proof_bundle',
    payload: bundlePayload,
    payload_hash_b64u: payloadHash,
    hash_algorithm: 'SHA-256',
    signature_b64u: signature,
    algorithm: 'Ed25519',
    signer_did: agentDid,
    issued_at: new Date().toISOString(),
  };

  return { envelope, payloadHash };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const envName = args.get('env') || 'staging';
  const agentId = args.get('agent') || process.env.CLAWEA_AGENT_ID;

  const tenantKey = process.env.CLAWEA_TENANT_KEY;
  assert(typeof tenantKey === 'string' && tenantKey.trim().length > 0, 'Missing CLAWEA_TENANT_KEY');
  assert(typeof agentId === 'string' && agentId.trim().length > 0, 'Missing --agent <agentId> (or CLAWEA_AGENT_ID)');

  const { claweaBaseUrl, clawverifyBaseUrl } = resolveBaseUrls(envName);

  // 1) Build proof bundle
  const agent = await makeDidKeyEd25519();
  const runId = `run_${crypto.randomUUID()}`;
  const { envelope: proofBundleEnvelope, payloadHash: proofBundleHash } = await buildProofBundleEnvelope({
    agentDid: agent.did,
    agentPrivateKey: agent.privateKey,
    runId,
  });

  // 2) Ask clawea to mint an execution attestation bound to the proof bundle
  const mint = await httpJson(`${claweaBaseUrl}/v1/agents/${agentId}/execution-attestation`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json; charset=utf-8',
      authorization: `Bearer ${tenantKey}`,
    },
    body: JSON.stringify({ proof_bundle_envelope: proofBundleEnvelope }),
  });

  assert(mint.status === 200, `clawea mint expected 200, got ${mint.status}: ${mint.text}`);
  assert(mint.json && mint.json.ok === true, 'clawea mint response missing ok=true');
  const execEnvelope = mint.json.envelope;
  const attesterDid = mint.json.attester_did;

  // 3) Verify execution attestation
  const vExec = await httpJson(`${clawverifyBaseUrl}/v1/verify/execution-attestation`, {
    method: 'POST',
    headers: { 'content-type': 'application/json; charset=utf-8' },
    body: JSON.stringify({ envelope: execEnvelope }),
  });

  // 4) Verify bundle with execution_attestations[] (uplift to sandbox)
  const vBundle = await httpJson(`${clawverifyBaseUrl}/v1/verify/bundle`, {
    method: 'POST',
    headers: { 'content-type': 'application/json; charset=utf-8' },
    body: JSON.stringify({
      envelope: proofBundleEnvelope,
      execution_attestations: [execEnvelope],
    }),
  });

  // 5) Verify agent with execution_attestations[] (uplift to sandbox)
  const vAgent = await httpJson(`${clawverifyBaseUrl}/v1/verify/agent`, {
    method: 'POST',
    headers: { 'content-type': 'application/json; charset=utf-8' },
    body: JSON.stringify({
      agent_did: agent.did,
      proof_bundle_envelope: proofBundleEnvelope,
      execution_attestations: [execEnvelope],
    }),
  });

  assert(vExec.status === 200, `verify execution attestation expected 200, got ${vExec.status}: ${vExec.text}`);
  assert(vExec.json?.result?.status === 'VALID', 'execution attestation should be VALID');

  assert(vBundle.status === 200, `verify bundle expected 200, got ${vBundle.status}: ${vBundle.text}`);
  assert(vBundle.json?.result?.status === 'VALID', 'bundle should be VALID');
  assert(vBundle.json?.result?.proof_tier === 'sandbox', `bundle proof_tier expected sandbox, got ${vBundle.json?.result?.proof_tier}`);

  assert(vAgent.status === 200, `verify agent expected 200, got ${vAgent.status}: ${vAgent.text}`);
  assert(vAgent.json?.result?.status === 'VALID', 'agent verify should be VALID');
  assert(vAgent.json?.proof_tier === 'sandbox', `agent proof_tier expected sandbox, got ${vAgent.json?.proof_tier}`);

  const out = {
    ok: true,
    env: envName,
    clawea_base_url: claweaBaseUrl,
    clawverify_base_url: clawverifyBaseUrl,
    agent_id: agentId,
    generated_agent_did: agent.did,
    run_id: runId,
    proof_bundle_hash_b64u: proofBundleHash,
    clawea_execution_attestation: {
      attester_did: attesterDid,
      signer_did: execEnvelope?.signer_did,
      payload_hash_b64u: execEnvelope?.payload_hash_b64u,
    },
    clawverify_verify_execution_attestation: {
      status: vExec.status,
      result_status: vExec.json?.result?.status,
    },
    clawverify_verify_bundle: {
      status: vBundle.status,
      result_status: vBundle.json?.result?.status,
      proof_tier: vBundle.json?.result?.proof_tier,
    },
    clawverify_verify_agent: {
      status: vAgent.status,
      result_status: vAgent.json?.result?.status,
      proof_tier: vAgent.json?.proof_tier,
    },
  };

  console.log(JSON.stringify(out, null, 2));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
