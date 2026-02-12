#!/usr/bin/env node
/**
 * Generate protocol conformance fixtures (offline).
 *
 * This script is intentionally deterministic:
 * - fixed Ed25519 seeds for agent + gateway signer
 * - fixed timestamps
 */

import * as fs from 'node:fs/promises';
import * as path from 'node:path';

const ROOT = path.resolve(new URL('../..', import.meta.url).pathname);
const FIXTURES_DIR = path.join(
  ROOT,
  'packages/schema/fixtures/protocol-conformance'
);

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

  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) {
    digits.push(0);
  }

  return digits
    .reverse()
    .map((d) => BASE58_ALPHABET[d])
    .join('');
}

function base64UrlEncode(bytes) {
  return Buffer.from(bytes)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

async function sha256B64uUtf8(s) {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(s)
  );
  return base64UrlEncode(new Uint8Array(digest));
}

async function computeHash(payload) {
  return sha256B64uUtf8(JSON.stringify(payload));
}

async function makeDidKeyFromSeed(seed) {
  if (!(seed instanceof Uint8Array) || seed.length !== 32) {
    throw new Error('seed must be Uint8Array(32)');
  }

  // Ed25519 PKCS#8: 16-byte header + 32-byte seed
  // (matches services/clawverify tests)
  const pkcs8Header = new Uint8Array([
    0x30, 0x2e,
    0x02, 0x01, 0x00,
    0x30, 0x05,
    0x06, 0x03, 0x2b, 0x65, 0x70,
    0x04, 0x22,
    0x04, 0x20,
  ]);

  const pkcs8Key = new Uint8Array(pkcs8Header.length + seed.length);
  pkcs8Key.set(pkcs8Header);
  pkcs8Key.set(seed, pkcs8Header.length);

  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    pkcs8Key,
    { name: 'Ed25519' },
    true,
    ['sign']
  );

  const jwk = await crypto.subtle.exportKey('jwk', privateKey);
  const publicKeyBytes = Buffer.from(String(jwk.x), 'base64url');

  const prefixed = new Uint8Array(2 + publicKeyBytes.length);
  prefixed[0] = 0xed;
  prefixed[1] = 0x01;
  prefixed.set(publicKeyBytes, 2);

  const did = `did:key:z${base58Encode(prefixed)}`;

  return { did, privateKey };
}

function mutateB64u(value) {
  if (typeof value !== 'string' || value.length === 0) return value;
  const first = value[0] === 'A' ? 'B' : 'A';
  return `${first}${value.slice(1)}`;
}

async function signEnvelope({ envelopeType, payload, signer, issuedAt }) {
  const payloadHash = await computeHash(payload);
  const sigBytes = new Uint8Array(
    await crypto.subtle.sign(
      'Ed25519',
      signer.privateKey,
      new TextEncoder().encode(payloadHash)
    )
  );

  return {
    envelope_version: '1',
    envelope_type: envelopeType,
    payload,
    payload_hash_b64u: payloadHash,
    hash_algorithm: 'SHA-256',
    signature_b64u: base64UrlEncode(sigBytes),
    algorithm: 'Ed25519',
    signer_did: signer.did,
    issued_at: issuedAt,
  };
}

async function main() {
  await fs.mkdir(FIXTURES_DIR, { recursive: true });

  const agentSeed = new Uint8Array(32);
  const gatewaySeed = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    agentSeed[i] = i + 1;
    gatewaySeed[i] = 100 + i;
  }

  const agent = await makeDidKeyFromSeed(agentSeed);
  const gatewaySigner = await makeDidKeyFromSeed(gatewaySeed);

  const runId = 'run_conformance_001';

  // Event chain (1 event)
  const e1PayloadHash = await computeHash({ type: 'llm_call' });
  const e1Header = {
    event_id: 'evt_conformance_001',
    run_id: runId,
    event_type: 'llm_call',
    timestamp: '2026-02-12T00:00:00.000Z',
    payload_hash_b64u: e1PayloadHash,
    prev_hash_b64u: null,
  };
  const e1Hash = await computeHash(e1Header);

  const receiptPayload = {
    receipt_version: '1',
    receipt_id: 'rcpt_conformance_001',
    gateway_id: 'gw_conformance',
    provider: 'anthropic',
    model: 'claude-test',
    request_hash_b64u: await computeHash({ req: 1 }),
    response_hash_b64u: await computeHash({ res: 1 }),
    tokens_input: 10,
    tokens_output: 20,
    latency_ms: 123,
    timestamp: '2026-02-12T00:00:00.000Z',
    binding: {
      run_id: runId,
      event_hash_b64u: e1Hash,
      nonce: 'nonce_conformance_001',
    },
  };

  const receiptEnvelope = await signEnvelope({
    envelopeType: 'gateway_receipt',
    payload: receiptPayload,
    signer: gatewaySigner,
    issuedAt: '2026-02-12T00:00:01.000Z',
  });

  const bundlePayload = {
    bundle_version: '1',
    bundle_id: 'bundle_conformance_001',
    agent_did: agent.did,
    event_chain: [{ ...e1Header, event_hash_b64u: e1Hash }],
    receipts: [receiptEnvelope],
  };

  const proofBundlePass = await signEnvelope({
    envelopeType: 'proof_bundle',
    payload: bundlePayload,
    signer: agent,
    issuedAt: '2026-02-12T00:00:02.000Z',
  });

  const proofBundleInvalidSig = {
    ...proofBundlePass,
    signature_b64u: mutateB64u(proofBundlePass.signature_b64u),
  };

  // Receipt binding mismatch (signatures remain valid)
  const mismatchedReceiptPayload = {
    ...receiptPayload,
    binding: {
      ...receiptPayload.binding,
      run_id: 'run_conformance_other',
    },
  };

  const mismatchedReceiptEnvelope = await signEnvelope({
    envelopeType: 'gateway_receipt',
    payload: mismatchedReceiptPayload,
    signer: gatewaySigner,
    issuedAt: '2026-02-12T00:00:01.000Z',
  });

  const mismatchedBundlePayload = {
    ...bundlePayload,
    receipts: [mismatchedReceiptEnvelope],
  };

  const proofBundleReceiptBindingMismatch = await signEnvelope({
    envelopeType: 'proof_bundle',
    payload: mismatchedBundlePayload,
    signer: agent,
    issuedAt: '2026-02-12T00:00:02.000Z',
  });

  const proofBundleUnknownVersion = {
    ...proofBundlePass,
    envelope_version: '2',
  };

  const writeJson = async (name, value) => {
    await fs.writeFile(
      path.join(FIXTURES_DIR, name),
      `${JSON.stringify(value, null, 2)}\n`,
      'utf8'
    );
  };

  await writeJson('proof_bundle_pass.v1.json', proofBundlePass);
  await writeJson('proof_bundle_fail_invalid_signature.v1.json', proofBundleInvalidSig);
  await writeJson(
    'proof_bundle_fail_receipt_binding_mismatch.v1.json',
    proofBundleReceiptBindingMismatch
  );
  await writeJson('proof_bundle_fail_unknown_envelope_version.v1.json', proofBundleUnknownVersion);

  // Output allowlist DIDs for convenience.
  await writeJson('allowlists.v1.json', {
    vector_version: '1',
    gateway_receipt_signer_dids: [gatewaySigner.did],
    agent_did: agent.did,
  });

  process.stdout.write(
    `Wrote fixtures to ${FIXTURES_DIR}\n` +
      `gateway receipt signer DID: ${gatewaySigner.did}\n` +
      `agent DID: ${agent.did}\n`
  );
}

main().catch((err) => {
  process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
  process.exitCode = 1;
});
