import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { concatBytes } from '@noble/hashes/utils';
import { createWalletClient, createPublicClient, http, getAddress } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

ed.etc.sha512Sync = (...m) => sha512(concatBytes(...m));

interface Env {
  DB: D1Database;
  LEDGER_SIGNING_PRIVATE_KEY: string;
  LEDGER_SIGNING_PUBLIC_KEY: string;
  LEDGER_SIGNING_DID: string;
  ANCHOR_ADMIN_KEY: string;
  ANCHOR_PRIVATE_KEY: string;
  ANCHOR_CONTRACT_ADDRESS: string;
  ANCHOR_CHAIN_ID: string;
  ANCHOR_RPC_URL: string;
}

const BUCKETS = new Set(['A', 'H', 'F']);
const SIGN_ALG = 'ed25519-sha256';

const ANCHOR_ABI = [
  {
    type: 'function',
    name: 'anchorRoot',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'root', type: 'bytes32' },
      { name: 'fromTs', type: 'uint64' },
      { name: 'toTs', type: 'uint64' },
      { name: 'count', type: 'uint32' }
    ],
    outputs: []
  }
] as const;

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}

function badRequest(message: string, details?: unknown): Response {
  return json({ success: false, error: message, details }, 400);
}

function unauthorized(): Response {
  return json({ success: false, error: 'Unauthorized' }, 401);
}

function assertEnv(env: Env, key: keyof Env): string {
  const value = env[key];
  if (!value) throw new Error(`Missing env: ${String(key)}`);
  return value as string;
}

function parseAmount(amountMinor: string): bigint {
  if (!/^[0-9-]+$/.test(amountMinor)) throw new Error('amount_minor must be integer string');
  return BigInt(amountMinor);
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) throw new Error('Invalid hex string');
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    bytes[i / 2] = parseInt(clean.slice(i, i + 2), 16);
  }
  return bytes;
}

function bytesToBase64(bytes: Uint8Array): string {
  // Avoid `String.fromCharCode(...bytes)` which can overflow the stack on large inputs.
  // (ed25519 signatures are 64 bytes today, but keep this safe for future changes.)
  return btoa(Array.from(bytes).map(b => String.fromCharCode(b)).join(''));
}

async function sha256Bytes(data: Uint8Array): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(digest);
}

async function sha256Hex(data: Uint8Array): Promise<string> {
  return bytesToHex(await sha256Bytes(data));
}

function canonicalEventPayload(event: Record<string, unknown>): string {
  // NOTE: This relies on ES2015+ stable object property enumeration order for
  // deterministic signing (all keys here are non-integer and are inserted in this literal order).
  // If we ever need cross-language canonicalization, switch to a formal JSON canonicalization scheme.
  return JSON.stringify({
    event_id: event.event_id,
    idempotency_key: event.idempotency_key,
    type: event.type,
    from_did: event.from_did ?? null,
    to_did: event.to_did ?? null,
    amount_minor: event.amount_minor,
    currency: event.currency,
    from_bucket: event.from_bucket ?? null,
    to_bucket: event.to_bucket ?? null,
    metadata_json: event.metadata_json ?? null,
    created_at: event.created_at
  });
}

async function signEvent(env: Env, event: Record<string, unknown>) {
  const payload = canonicalEventPayload(event);
  const payloadBytes = new TextEncoder().encode(payload);
  const eventHash = await sha256Hex(payloadBytes);
  const signatureBytes = await ed.sign(hexToBytes(eventHash), hexToBytes(assertEnv(env, 'LEDGER_SIGNING_PRIVATE_KEY')));

  return {
    event_hash: eventHash,
    event_sig: bytesToBase64(signatureBytes),
    event_sig_alg: SIGN_ALG,
    event_sig_did: assertEnv(env, 'LEDGER_SIGNING_DID'),
    event_sig_pubkey: assertEnv(env, 'LEDGER_SIGNING_PUBLIC_KEY')
  };
}

function receiptFromRow(row: Record<string, any>) {
  if (!row.event_hash || !row.event_sig) return null;
  return {
    event_hash: row.event_hash,
    signature: row.event_sig,
    alg: row.event_sig_alg ?? SIGN_ALG,
    did: row.event_sig_did ?? null,
    public_key: row.event_sig_pubkey ?? null
  };
}

function requireAnchorAuth(request: Request, env: Env): boolean {
  const header = request.headers.get('Authorization') ?? '';
  const expected = `Bearer ${assertEnv(env, 'ANCHOR_ADMIN_KEY')}`;
  return header === expected;
}

async function computeMerkleRootHex(hashes: string[]): Promise<string> {
  if (!hashes.length) throw new Error('No hashes to anchor');
  let level = hashes.map(hex => hexToBytes(hex));

  while (level.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      // If the level has an odd number of nodes, duplicate the last node (common Merkle convention).
      const right = level[i + 1] ?? level[i];
      const combined = new Uint8Array(left.length + right.length);
      combined.set(left, 0);
      combined.set(right, left.length);
      next.push(await sha256Bytes(combined));
    }
    level = next;
  }

  return bytesToHex(level[0]);
}

function toUnixSeconds(iso: string): bigint {
  return BigInt(Math.floor(new Date(iso).getTime() / 1000));
}

async function getBalance(env: Env, did: string, bucket: string): Promise<bigint> {
  const row = await env.DB.prepare(
    `SELECT amount_minor FROM balances WHERE did = ? AND bucket = ?`
  ).bind(did, bucket).first();
  if (!row) return 0n;
  return parseAmount(String(row.amount_minor));
}

async function setBalance(env: Env, did: string, bucket: string, amount: bigint): Promise<void> {
  await env.DB.prepare(
    `INSERT INTO balances (did, bucket, amount_minor) VALUES (?, ?, ?)
     ON CONFLICT(did, bucket) DO UPDATE SET amount_minor = excluded.amount_minor`
  ).bind(did, bucket, amount.toString()).run();
}

async function ensureAccount(env: Env, did: string): Promise<void> {
  await env.DB.prepare(
    `INSERT INTO accounts (did, created_at) VALUES (?, ?)
     ON CONFLICT(did) DO NOTHING`
  ).bind(did, new Date().toISOString()).run();
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === '/health') {
      return json({ status: 'ok' });
    }

    if (request.method === 'GET' && url.pathname === '/v1/balances') {
      const did = url.searchParams.get('did');
      if (!did) return badRequest('Missing did');

      await ensureAccount(env, did);

      const [a, h, f] = await Promise.all([
        getBalance(env, did, 'A'),
        getBalance(env, did, 'H'),
        getBalance(env, did, 'F')
      ]);

      return json({
        did,
        balances: {
          A: a.toString(),
          H: h.toString(),
          F: f.toString()
        }
      });
    }

    if (request.method === 'GET' && url.pathname.startsWith('/v1/events/')) {
      const eventId = url.pathname.split('/')[3];
      if (!eventId) return badRequest('Missing event_id');

      const row = await env.DB.prepare(`SELECT * FROM events WHERE event_id = ?`).bind(eventId).first();
      if (!row) return badRequest('Unknown event_id');

      return json({ success: true, event: row, receipt: receiptFromRow(row) });
    }

    if (request.method === 'GET' && url.pathname === '/v1/anchors') {
      const rows = await env.DB.prepare(
        `SELECT * FROM anchors ORDER BY created_at DESC LIMIT 50`
      ).all();
      return json({ success: true, anchors: rows.results ?? [] });
    }

    if (request.method === 'POST' && url.pathname === '/v1/anchors') {
      if (!requireAnchorAuth(request, env)) return unauthorized();

      const last = await env.DB.prepare(
        `SELECT * FROM anchors ORDER BY created_at DESC LIMIT 1`
      ).first();
      const since = last?.to_created_at ?? '1970-01-01T00:00:00.000Z';

      const events = await env.DB.prepare(
        `SELECT * FROM events WHERE created_at > ? ORDER BY created_at ASC, event_id ASC`
      ).bind(since).all();

      const rows = events.results ?? [];
      if (!rows.length) return badRequest('No new events to anchor');

      const hashes: string[] = [];

      // Sign any unsigned events before anchoring.
      // Use a DB transaction so we don't end up with a partially-signed range if the request fails mid-way.
      await env.DB.exec('BEGIN');
      try {
        for (const row of rows) {
          if (!row.event_hash || !row.event_sig) {
            const receipt = await signEvent(env, row);
            await env.DB.prepare(
              `UPDATE events SET event_hash = ?, event_sig = ?, event_sig_alg = ?, event_sig_did = ?, event_sig_pubkey = ? WHERE event_id = ?`
            ).bind(
              receipt.event_hash,
              receipt.event_sig,
              receipt.event_sig_alg,
              receipt.event_sig_did,
              receipt.event_sig_pubkey,
              row.event_id
            ).run();
            row.event_hash = receipt.event_hash;
            row.event_sig = receipt.event_sig;
            row.event_sig_alg = receipt.event_sig_alg;
            row.event_sig_did = receipt.event_sig_did;
            row.event_sig_pubkey = receipt.event_sig_pubkey;
          }
          hashes.push(row.event_hash);
        }
        await env.DB.exec('COMMIT');
      } catch (err) {
        await env.DB.exec('ROLLBACK');
        throw err;
      }

      const rootHex = await computeMerkleRootHex(hashes);
      const fromCreatedAt = rows[0].created_at;
      const toCreatedAt = rows[rows.length - 1].created_at;

      const rawPrivateKey = assertEnv(env, 'ANCHOR_PRIVATE_KEY');
      const privateKey = (rawPrivateKey.startsWith('0x') ? rawPrivateKey : `0x${rawPrivateKey}`) as `0x${string}`;
      const account = privateKeyToAccount(privateKey);
      const chainId = Number(assertEnv(env, 'ANCHOR_CHAIN_ID'));
      const rpcUrl = assertEnv(env, 'ANCHOR_RPC_URL');

      const chain = {
        id: chainId,
        name: 'Base Sepolia',
        nativeCurrency: { name: 'Sepolia ETH', symbol: 'ETH', decimals: 18 },
        rpcUrls: { default: { http: [rpcUrl] } }
      } as const;

      const walletClient = createWalletClient({
        account,
        chain,
        transport: http(rpcUrl)
      });

      const publicClient = createPublicClient({
        chain,
        transport: http(rpcUrl)
      });

      const txHash = await walletClient.writeContract({
        address: getAddress(assertEnv(env, 'ANCHOR_CONTRACT_ADDRESS')),
        abi: ANCHOR_ABI,
        functionName: 'anchorRoot',
        args: [
          `0x${rootHex}`,
          toUnixSeconds(fromCreatedAt),
          toUnixSeconds(toCreatedAt),
          rows.length
        ]
      });

      // Ensure the tx succeeded before persisting the anchor record.
      await publicClient.waitForTransactionReceipt({ hash: txHash });

      const anchorId = crypto.randomUUID();
      await env.DB.prepare(
        `INSERT INTO anchors (anchor_id, root_hash, from_created_at, to_created_at, event_count, tx_hash, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      ).bind(
        anchorId,
        rootHex,
        fromCreatedAt,
        toCreatedAt,
        rows.length,
        txHash,
        new Date().toISOString()
      ).run();

      return json({
        success: true,
        anchor: {
          anchor_id: anchorId,
          root_hash: rootHex,
          from_created_at: fromCreatedAt,
          to_created_at: toCreatedAt,
          event_count: rows.length,
          tx_hash: txHash
        }
      });
    }

    if (request.method === 'POST' && url.pathname === '/v1/transfers') {
      const body = await request.json().catch(() => null) as any;
      if (!body) return badRequest('Invalid JSON');

      const required = ['from_did', 'to_did', 'amount_minor', 'currency', 'from_bucket', 'to_bucket', 'idempotency_key'];
      for (const key of required) {
        if (!body[key]) return badRequest(`Missing ${key}`);
      }

      if (body.currency !== 'USD') return badRequest('Only USD supported');
      if (!BUCKETS.has(body.from_bucket) || !BUCKETS.has(body.to_bucket)) {
        return badRequest('Invalid bucket; allowed A, H, F');
      }

      const idempotencyKey = String(body.idempotency_key);
      const existing = await env.DB.prepare(
        `SELECT * FROM events WHERE idempotency_key = ?`
      ).bind(idempotencyKey).first();

      if (existing) {
        return json({ success: true, event: existing, idempotent: true, receipt: receiptFromRow(existing) });
      }

      const amount = parseAmount(String(body.amount_minor));
      if (amount <= 0n) return badRequest('amount_minor must be > 0');

      const fromDid = String(body.from_did);
      const toDid = String(body.to_did);
      const fromBucket = String(body.from_bucket);
      const toBucket = String(body.to_bucket);

      await ensureAccount(env, fromDid);
      await ensureAccount(env, toDid);

      const fromBalance = await getBalance(env, fromDid, fromBucket);
      const toBalance = await getBalance(env, toDid, toBucket);

      const isClearing = fromDid.startsWith('clearing:');
      if (!isClearing && fromBalance < amount) {
        return badRequest('Insufficient funds');
      }

      const newFrom = fromBalance - amount;
      const newTo = toBalance + amount;

      await setBalance(env, fromDid, fromBucket, newFrom);
      await setBalance(env, toDid, toBucket, newTo);

      const eventId = crypto.randomUUID();
      const event = {
        event_id: eventId,
        idempotency_key: idempotencyKey,
        type: 'transfer',
        from_did: fromDid,
        to_did: toDid,
        amount_minor: amount.toString(),
        currency: 'USD',
        from_bucket: fromBucket,
        to_bucket: toBucket,
        metadata_json: body.metadata ? JSON.stringify(body.metadata) : null,
        created_at: new Date().toISOString()
      } as Record<string, unknown>;

      const receipt = await signEvent(env, event);

      await env.DB.prepare(
        `INSERT INTO events (event_id, idempotency_key, type, from_did, to_did, amount_minor, currency, from_bucket, to_bucket, metadata_json, event_hash, event_sig, event_sig_alg, event_sig_did, event_sig_pubkey, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(
        event.event_id,
        event.idempotency_key,
        event.type,
        event.from_did,
        event.to_did,
        event.amount_minor,
        event.currency,
        event.from_bucket,
        event.to_bucket,
        event.metadata_json,
        receipt.event_hash,
        receipt.event_sig,
        receipt.event_sig_alg,
        receipt.event_sig_did,
        receipt.event_sig_pubkey,
        event.created_at
      ).run();

      return json({ success: true, event, receipt });
    }

    return new Response('Not found', { status: 404 });
  }
};
