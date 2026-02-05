interface Env {
  DB: D1Database;
}

const BUCKETS = new Set(['A', 'H', 'F']);

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}

function badRequest(message: string, details?: unknown): Response {
  return json({ success: false, error: message, details }, 400);
}

function parseAmount(amountMinor: string): bigint {
  if (!/^[0-9-]+$/.test(amountMinor)) throw new Error('amount_minor must be integer string');
  return BigInt(amountMinor);
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
        return json({ success: true, event: existing, idempotent: true });
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
      };

      await env.DB.prepare(
        `INSERT INTO events (event_id, idempotency_key, type, from_did, to_did, amount_minor, currency, from_bucket, to_bucket, metadata_json, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
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
        event.created_at
      ).run();

      return json({ success: true, event });
    }

    return new Response('Not found', { status: 404 });
  }
};
