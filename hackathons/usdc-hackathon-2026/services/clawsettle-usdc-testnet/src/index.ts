import { createPublicClient, createWalletClient, http, erc20Abi, parseEventLogs, getAddress } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

interface Env {
  DB: D1Database;
  CHAIN_ID: string;
  USDC_TOKEN_ADDRESS: string;
  DEPOSIT_ADDRESS: string;
  RPC_URL: string;
  LEDGER_URL: string;
  PLATFORM_PRIVATE_KEY: string;
}

const USDC_DECIMALS = 6n;
const CENTS_TO_USDC_BASE = 10_000n; // $0.01 = 0.01 USDC = 10,000 base units

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}

function badRequest(message: string, details?: unknown): Response {
  return json({ success: false, error: message, details }, 400);
}

function serverError(message: string, details?: unknown): Response {
  return json({ success: false, error: message, details }, 500);
}

function assertEnv(env: Env, key: keyof Env): string {
  const value = env[key];
  if (!value) throw new Error(`Missing env: ${String(key)}`);
  return value as string;
}

function parseMinor(amountMinor: string): bigint {
  if (!/^[0-9]+$/.test(amountMinor)) throw new Error('amount_minor must be a non-negative integer string');
  return BigInt(amountMinor);
}

function toUsdcBase(amountMinor: string): bigint {
  return parseMinor(amountMinor) * CENTS_TO_USDC_BASE;
}

async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function randomHex(bytes = 32): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function verifyUsdcTransfer(params: {
  publicClient: ReturnType<typeof createPublicClient>;
  txHash: `0x${string}`;
  usdcAddress: `0x${string}`;
  depositAddress: `0x${string}`;
  amountUsdcBase: bigint;
}): Promise<boolean> {
  const receipt = await params.publicClient.getTransactionReceipt({ hash: params.txHash });
  if (receipt.status !== 'success') return false;

  const logs = parseEventLogs({
    abi: erc20Abi,
    logs: receipt.logs,
    eventName: 'Transfer',
    strict: false
  });

  const usdcLower = params.usdcAddress.toLowerCase();
  const depositLower = params.depositAddress.toLowerCase();

  return logs.some(log => {
    const addressMatch = log.address.toLowerCase() === usdcLower;
    const toMatch = String(log.args?.to ?? '').toLowerCase() === depositLower;
    const valueMatch = BigInt(log.args?.value ?? 0n) === params.amountUsdcBase;
    return addressMatch && toMatch && valueMatch;
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      const url = new URL(request.url);

      if (url.pathname === '/health') {
        return json({ status: 'ok' });
      }

      if (request.method === 'POST' && url.pathname === '/v1/usdc/deposit-intents') {
        const body = await request.json().catch(() => null) as any;
        if (!body?.buyer_did || !body?.amount_minor || !body?.currency) {
          return badRequest('Missing buyer_did, amount_minor, or currency');
        }
        if (body.currency !== 'USD') return badRequest('Only USD supported');

        const amountMinor = String(body.amount_minor);
        const amountUsdcBase = toUsdcBase(amountMinor);

        const intentId = crypto.randomUUID();
        const claimSecret = randomHex(32);
        const claimHash = await sha256Hex(claimSecret);
        const now = new Date();
        const expiresAt = new Date(now.getTime() + 60 * 60 * 1000).toISOString();

        await env.DB.prepare(
          `INSERT INTO deposit_intents (intent_id, buyer_did, amount_minor, amount_usdc_base, deposit_address, claim_secret_hash, status, expires_at, created_at)
           VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)`
        ).bind(
          intentId,
          body.buyer_did,
          amountMinor,
          amountUsdcBase.toString(),
          env.DEPOSIT_ADDRESS,
          claimHash,
          expiresAt,
          now.toISOString()
        ).run();

        return json({
          intent_id: intentId,
          deposit_address: env.DEPOSIT_ADDRESS,
          amount_usdc_base: amountUsdcBase.toString(),
          expires_at: expiresAt,
          claim_secret: claimSecret
        });
      }

      if (request.method === 'POST' && url.pathname === '/v1/usdc/deposits/claim') {
        const body = await request.json().catch(() => null) as any;
        if (!body?.intent_id || !body?.claim_secret || !body?.tx_hash) {
          return badRequest('Missing intent_id, claim_secret, or tx_hash');
        }

        const intent = await env.DB.prepare(
          `SELECT * FROM deposit_intents WHERE intent_id = ?`
        ).bind(body.intent_id).first();

        if (!intent) return badRequest('Unknown intent_id');
        if (intent.status !== 'pending') return badRequest('Intent already claimed or closed');

        const now = new Date();
        if (new Date(intent.expires_at) < now) return badRequest('Intent expired');

        const claimHash = await sha256Hex(String(body.claim_secret));
        if (claimHash !== intent.claim_secret_hash) return badRequest('Invalid claim secret');

        const txHash = String(body.tx_hash) as `0x${string}`;

        // verify on-chain transfer
        const publicClient = createPublicClient({ transport: http(assertEnv(env, 'RPC_URL')) });
        const isValid = await verifyUsdcTransfer({
          publicClient,
          txHash,
          usdcAddress: getAddress(assertEnv(env, 'USDC_TOKEN_ADDRESS')),
          depositAddress: getAddress(assertEnv(env, 'DEPOSIT_ADDRESS')),
          amountUsdcBase: BigInt(intent.amount_usdc_base)
        });

        if (!isValid) return badRequest('Transfer not found or invalid');

        // mark intent claimed
        await env.DB.prepare(
          `UPDATE deposit_intents SET status = 'claimed', tx_hash = ? WHERE intent_id = ?`
        ).bind(txHash, body.intent_id).run();

        // mint ledger credits via ledger service
        const ledgerUrl = assertEnv(env, 'LEDGER_URL');
        const ledgerRes = await fetch(`${ledgerUrl}/v1/transfers`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            from_did: 'clearing:clawsettle',
            to_did: intent.buyer_did,
            amount_minor: intent.amount_minor,
            currency: 'USD',
            from_bucket: 'A',
            to_bucket: 'A',
            idempotency_key: `usdc:tx:${txHash}`
          })
        });

        if (!ledgerRes.ok) {
          const errText = await ledgerRes.text();
          return serverError('Ledger mint failed', errText);
        }

        const ledgerJson = await ledgerRes.json();
        return json({ success: true, ledger: ledgerJson });
      }

      if (request.method === 'POST' && url.pathname === '/v1/usdc/payouts') {
        const body = await request.json().catch(() => null) as any;
        if (!body?.worker_did || !body?.amount_minor || !body?.destination_address || !body?.idempotency_key) {
          return badRequest('Missing worker_did, amount_minor, destination_address, or idempotency_key');
        }

        const idempotencyKey = String(body.idempotency_key);
        const existing = await env.DB.prepare(
          `SELECT * FROM payouts WHERE idempotency_key = ?`
        ).bind(idempotencyKey).first();

        if (existing) {
          return json({ success: true, payout: existing });
        }

        const amountMinor = String(body.amount_minor);
        const amountUsdcBase = toUsdcBase(amountMinor);

        // lock funds in ledger (worker A -> clearing H)
        const ledgerUrl = assertEnv(env, 'LEDGER_URL');
        const lockRes = await fetch(`${ledgerUrl}/v1/transfers`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            from_did: body.worker_did,
            to_did: 'clearing:clawsettle',
            amount_minor: amountMinor,
            currency: 'USD',
            from_bucket: 'A',
            to_bucket: 'H',
            idempotency_key: `payout:lock:${idempotencyKey}`
          })
        });

        if (!lockRes.ok) {
          const errText = await lockRes.text();
          return serverError('Ledger lock failed', errText);
        }

        // send USDC on-chain
        const privateKey = assertEnv(env, 'PLATFORM_PRIVATE_KEY') as `0x${string}`;
        const account = privateKeyToAccount(privateKey);
        const chainId = Number(assertEnv(env, 'CHAIN_ID'));
        const walletClient = createWalletClient({
          account,
          chain: {
            id: chainId,
            name: 'Base Sepolia',
            nativeCurrency: { name: 'Sepolia ETH', symbol: 'ETH', decimals: 18 },
            rpcUrls: { default: { http: [assertEnv(env, 'RPC_URL')] } }
          },
          transport: http(assertEnv(env, 'RPC_URL'))
        });

        const txHash = await walletClient.writeContract({
          address: getAddress(assertEnv(env, 'USDC_TOKEN_ADDRESS')),
          abi: erc20Abi,
          functionName: 'transfer',
          args: [getAddress(body.destination_address), amountUsdcBase]
        });

        const payoutId = crypto.randomUUID();
        await env.DB.prepare(
          `INSERT INTO payouts (payout_id, worker_did, amount_minor, destination_address, idempotency_key, tx_hash, status, created_at)
           VALUES (?, ?, ?, ?, ?, ?, 'submitted', ?)`
        ).bind(
          payoutId,
          body.worker_did,
          amountMinor,
          body.destination_address,
          idempotencyKey,
          txHash,
          new Date().toISOString()
        ).run();

        return json({ success: true, tx_hash: txHash, status: 'submitted' });
      }

      return new Response('Not found', { status: 404 });
    } catch (err: any) {
      return serverError('Unhandled error', err?.message ?? String(err));
    }
  }
};
