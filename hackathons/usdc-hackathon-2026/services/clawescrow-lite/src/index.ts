interface Env {
  DB: D1Database;
  LEDGER_URL: string;
  FEE_DID: string;
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}

function badRequest(message: string, details?: unknown): Response {
  return json({ success: false, error: message, details }, 400);
}

function assertEnv(env: Env, key: keyof Env): string {
  const value = env[key];
  if (!value) throw new Error(`Missing env: ${String(key)}`);
  return value as string;
}

function parseAmount(amountMinor: string): bigint {
  if (!/^[0-9]+$/.test(amountMinor)) throw new Error('amount_minor must be non-negative integer string');
  return BigInt(amountMinor);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === '/health') {
      return json({ status: 'ok' });
    }

    if (request.method === 'POST' && url.pathname === '/v1/escrows') {
      const body = await request.json().catch(() => null) as any;
      if (!body?.buyer_did || !body?.amount_minor || !body?.currency || !body?.idempotency_key) {
        return badRequest('Missing buyer_did, amount_minor, currency, or idempotency_key');
      }
      if (body.currency !== 'USD') return badRequest('Only USD supported');

      const amountMinor = String(body.amount_minor);
      const feeMinor = String(body.fee_minor ?? '0');
      const amount = parseAmount(amountMinor);
      const fee = parseAmount(feeMinor);
      if (fee > amount) return badRequest('fee_minor cannot exceed amount_minor');

      const existing = await env.DB.prepare(
        `SELECT * FROM escrows WHERE idempotency_key = ?`
      ).bind(String(body.idempotency_key)).first();

      if (existing) return json({ success: true, escrow: existing, idempotent: true });

      const escrowId = crypto.randomUUID();
      const now = new Date().toISOString();

      // hold funds: buyer A -> buyer H
      const ledgerUrl = assertEnv(env, 'LEDGER_URL');
      const holdRes = await fetch(`${ledgerUrl}/v1/transfers`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          from_did: body.buyer_did,
          to_did: body.buyer_did,
          amount_minor: amountMinor,
          currency: 'USD',
          from_bucket: 'A',
          to_bucket: 'H',
          idempotency_key: `escrow:${escrowId}:hold`
        })
      });

      if (!holdRes.ok) {
        const errText = await holdRes.text();
        return badRequest('Ledger hold failed', errText);
      }

      await env.DB.prepare(
        `INSERT INTO escrows (escrow_id, buyer_did, amount_minor, fee_minor, currency, status, idempotency_key, created_at)
         VALUES (?, ?, ?, ?, ?, 'held', ?, ?)`
      ).bind(
        escrowId,
        body.buyer_did,
        amountMinor,
        feeMinor,
        'USD',
        String(body.idempotency_key),
        now
      ).run();

      return json({ success: true, escrow_id: escrowId, status: 'held' });
    }

    if (request.method === 'POST' && url.pathname.startsWith('/v1/escrows/') && url.pathname.endsWith('/assign')) {
      const escrowId = url.pathname.split('/')[3];
      const body = await request.json().catch(() => null) as any;
      if (!body?.worker_did) return badRequest('Missing worker_did');

      const escrow = await env.DB.prepare(`SELECT * FROM escrows WHERE escrow_id = ?`).bind(escrowId).first();
      if (!escrow) return badRequest('Unknown escrow');
      if (escrow.status !== 'held') return badRequest('Escrow not in held state');

      await env.DB.prepare(
        `UPDATE escrows SET worker_did = ?, status = 'assigned', assigned_at = ? WHERE escrow_id = ?`
      ).bind(body.worker_did, new Date().toISOString(), escrowId).run();

      return json({ success: true, escrow_id: escrowId, status: 'assigned' });
    }

    if (request.method === 'POST' && url.pathname.startsWith('/v1/escrows/') && url.pathname.endsWith('/release')) {
      const escrowId = url.pathname.split('/')[3];
      const escrow = await env.DB.prepare(`SELECT * FROM escrows WHERE escrow_id = ?`).bind(escrowId).first();
      if (!escrow) return badRequest('Unknown escrow');
      if (escrow.status !== 'assigned') return badRequest('Escrow not assigned');
      if (!escrow.worker_did) return badRequest('Missing worker_did');

      const amount = parseAmount(String(escrow.amount_minor));
      const fee = parseAmount(String(escrow.fee_minor));
      const workerAmount = amount - fee;

      const ledgerUrl = assertEnv(env, 'LEDGER_URL');

      // release to worker A
      const workerRes = await fetch(`${ledgerUrl}/v1/transfers`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          from_did: escrow.buyer_did,
          to_did: escrow.worker_did,
          amount_minor: workerAmount.toString(),
          currency: 'USD',
          from_bucket: 'H',
          to_bucket: 'A',
          idempotency_key: `escrow:${escrowId}:release:worker`
        })
      });

      if (!workerRes.ok) {
        const errText = await workerRes.text();
        return badRequest('Worker release failed', errText);
      }

      // release fee to fee pool
      if (fee > 0n) {
        const feeRes = await fetch(`${ledgerUrl}/v1/transfers`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            from_did: escrow.buyer_did,
            to_did: assertEnv(env, 'FEE_DID'),
            amount_minor: fee.toString(),
            currency: 'USD',
            from_bucket: 'H',
            to_bucket: 'F',
            idempotency_key: `escrow:${escrowId}:release:fee`
          })
        });

        if (!feeRes.ok) {
          const errText = await feeRes.text();
          return badRequest('Fee release failed', errText);
        }
      }

      await env.DB.prepare(
        `UPDATE escrows SET status = 'released', released_at = ? WHERE escrow_id = ?`
      ).bind(new Date().toISOString(), escrowId).run();

      return json({ success: true, escrow_id: escrowId, status: 'released' });
    }

    return new Response('Not found', { status: 404 });
  }
};
