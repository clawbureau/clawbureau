#!/usr/bin/env node

/**
 * Smoke test for /v1/verify/commit-proof.
 *
 * This generates a fresh Ed25519 did:key, creates a commit_proof envelope,
 * and verifies it against clawverify.
 *
 * Usage:
 *   node scripts/poh/smoke-commit-proof.mjs --env staging
 *   node scripts/poh/smoke-commit-proof.mjs --env prod
 */

import process from 'node:process';

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

const args = parseArgs(process.argv.slice(2));
const envName = (args.get('env') || 'staging').toLowerCase();

const baseUrl =
  envName === 'prod' || envName === 'production'
    ? 'https://clawverify.com'
    : 'https://staging.clawverify.com';

const repoClaimId = args.get('repo-claim-id') || 'repo:github:clawbureau/clawbureau';
const repository = args.get('repository') || 'github.com/clawbureau/clawbureau';

const commitSha = args.get('commit-sha') || '261271e';
const branch = args.get('branch') || 'main';

const HASH_ALGO = 'SHA-256';
const SIG_ALGO = 'Ed25519';

function base64UrlEncode(bytes) {
  const base64 = Buffer.from(bytes).toString('base64');
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Encode(bytes) {
  let leadingZeros = 0;
  for (const b of bytes) {
    if (b !== 0) break;
    leadingZeros++;
  }

  const digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i++) {
      carry += digits[i] << 8;
      digits[i] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }

  let result = '';
  for (let i = 0; i < leadingZeros; i++) result += '1';
  for (let i = digits.length - 1; i >= 0; i--) result += BASE58_ALPHABET[digits[i]];
  return result;
}

async function sha256B64u(data) {
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return base64UrlEncode(new Uint8Array(hashBuffer));
}

async function hashJsonB64u(value) {
  const data = new TextEncoder().encode(JSON.stringify(value));
  return sha256B64u(data);
}

async function didFromPublicKey(publicKey) {
  const raw = await crypto.subtle.exportKey('raw', publicKey);
  const pubBytes = new Uint8Array(raw);
  const multicodec = new Uint8Array(2 + pubBytes.length);
  multicodec[0] = 0xed;
  multicodec[1] = 0x01;
  multicodec.set(pubBytes, 2);
  return `did:key:z${base58Encode(multicodec)}`;
}

async function signEd25519(privateKey, messageBytes) {
  const sigBuffer = await crypto.subtle.sign('Ed25519', privateKey, messageBytes);
  return base64UrlEncode(new Uint8Array(sigBuffer));
}

async function main() {
  const kp = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  const signerDid = await didFromPublicKey(kp.publicKey);

  const payload = {
    proof_version: '1',
    repo_claim_id: repoClaimId,
    commit_sha: commitSha,
    repository,
    branch,
  };

  const payloadHash = await hashJsonB64u(payload);
  const signature = await signEd25519(kp.privateKey, new TextEncoder().encode(payloadHash));

  const envelope = {
    envelope_version: '1',
    envelope_type: 'commit_proof',
    payload,
    payload_hash_b64u: payloadHash,
    hash_algorithm: HASH_ALGO,
    signature_b64u: signature,
    algorithm: SIG_ALGO,
    signer_did: signerDid,
    issued_at: new Date().toISOString(),
  };

  const res = await fetch(`${baseUrl}/v1/verify/commit-proof`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ envelope }),
  });

  const json = await res.json().catch(() => null);

  // Keep output compact and stable for copy/paste.
  console.log(JSON.stringify({
    env: envName,
    url: `${baseUrl}/v1/verify/commit-proof`,
    http_status: res.status,
    result_status: json?.result?.status,
    result_reason: json?.result?.reason,
    repo_claim_id: json?.repo_claim_id,
    repository: json?.repository,
    commit_sha: json?.commit_sha,
    error: json?.error || null,
  }, null, 2));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
