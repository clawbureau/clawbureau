import { sha256B64uUtf8 } from './crypto';

export interface Env {
  CUTS_VERSION: string;
}

type FeePayer = 'buyer' | 'worker';

interface FeeItem {
  kind: 'platform';
  payer: FeePayer;
  amount_minor: string;
  rate_bps: number;
  min_fee_minor: string;
  floor_applied: boolean;
}

interface PolicyInfo {
  id: string;
  version: string;
  hash_b64u: string;
}

interface FeeQuote {
  principal_minor: string;
  buyer_total_minor: string;
  worker_net_minor: string;
  fees: FeeItem[];
}

interface FeeSimulateRequest {
  product: string;
  policy_id: string;
  amount_minor: string;
  currency: string;
  params?: Record<string, unknown>;
}

interface FeeSimulateResponse {
  policy: PolicyInfo;
  quote: FeeQuote;
}

interface BountiesV2Params {
  closure_type: 'test' | 'requester' | 'quorum' | string;
  is_code_bounty: boolean;
}

type CodeSelector = 'true' | 'false' | '*';
type ClosureSelector = 'test' | 'requester' | 'quorum' | '*';

interface FeeRule {
  is_code_bounty: CodeSelector;
  closure_type: ClosureSelector;
  buyer_fee_bps: number;
  worker_fee_bps: number;
  min_fee_minor: string;
}

interface FeePolicy {
  product: string;
  policy_id: string;
  version: string;
  rules: FeeRule[];
}

const POLICY_CACHE = new Map<string, Promise<{ policy: FeePolicy; hash_b64u: string }>>();

function jsonResponse(body: unknown, status = 200, extraHeaders?: HeadersInit): Response {
  const headers = new Headers(extraHeaders);
  headers.set('content-type', 'application/json; charset=utf-8');
  return new Response(JSON.stringify(body, null, 2), { status, headers });
}

function textResponse(body: string, contentType: string, status = 200, version?: string): Response {
  const headers = new Headers({ 'content-type': contentType });
  if (version) headers.set('X-Cuts-Version', version);
  return new Response(body, { status, headers });
}

function errorResponse(code: string, message: string, status = 400): Response {
  return jsonResponse({ error: code, message }, status);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function parseMoneyMinor(input: unknown): bigint | null {
  if (typeof input !== 'string') return null;
  const s = input.trim();
  if (!/^[0-9]+$/.test(s)) return null;
  try {
    const n = BigInt(s);
    if (n <= 0n) return null;
    return n;
  } catch {
    return null;
  }
}

function ceilDiv(n: bigint, d: bigint): bigint {
  if (d <= 0n) throw new Error('Invalid divisor');
  return (n + d - 1n) / d;
}

function stableStringify(value: unknown): string {
  if (value === null) return 'null';

  if (Array.isArray(value)) {
    return `[${value.map((v) => stableStringify(v)).join(',')}]`;
  }

  switch (typeof value) {
    case 'string':
      return JSON.stringify(value);
    case 'number': {
      if (!Number.isFinite(value)) throw new Error('Non-finite number');
      return JSON.stringify(value);
    }
    case 'boolean':
      return value ? 'true' : 'false';
    case 'bigint':
      return JSON.stringify(value.toString());
    case 'object': {
      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj).sort();
      return `{${keys
        .map((k) => {
          const v = obj[k];
          return `${JSON.stringify(k)}:${stableStringify(v)}`;
        })
        .join(',')}}`;
    }
    default:
      return 'null';
  }
}

function policyCacheKey(product: string, policy_id: string): string {
  return `${product}:${policy_id}`;
}

function getBuiltInPolicy(product: string, policy_id: string): FeePolicy | null {
  if (product === 'clawbounties' && policy_id === 'bounties_v1') {
    const rules: FeeRule[] = [
      { is_code_bounty: 'true', closure_type: 'test', buyer_fee_bps: 500, worker_fee_bps: 0, min_fee_minor: '0' },
      { is_code_bounty: '*', closure_type: 'requester', buyer_fee_bps: 750, worker_fee_bps: 0, min_fee_minor: '25' },
      { is_code_bounty: '*', closure_type: 'quorum', buyer_fee_bps: 750, worker_fee_bps: 0, min_fee_minor: '25' },
    ];

    return {
      product,
      policy_id,
      version: '1',
      rules,
    };
  }

  if (product === 'clawtips' && policy_id === 'tips_v1') {
    const rules: FeeRule[] = [
      { is_code_bounty: '*', closure_type: '*', buyer_fee_bps: 0, worker_fee_bps: 0, min_fee_minor: '0' },
    ];

    return {
      product,
      policy_id,
      version: '1',
      rules,
    };
  }

  return null;
}

async function getPolicyWithHash(product: string, policy_id: string): Promise<{ policy: FeePolicy; hash_b64u: string }> {
  const key = policyCacheKey(product, policy_id);
  const existing = POLICY_CACHE.get(key);
  if (existing) return existing;

  const promise = (async () => {
    const policy = getBuiltInPolicy(product, policy_id);
    if (!policy) {
      throw new Error('POLICY_NOT_FOUND');
    }

    // Deterministic policy hash over a stable JSON representation.
    const canonical = stableStringify({
      schema: 'clawcuts.policy.v2',
      product: policy.product,
      policy_id: policy.policy_id,
      version: policy.version,
      rules: policy.rules,
    });
    const hash_b64u = await sha256B64uUtf8(canonical);
    return { policy, hash_b64u };
  })();

  POLICY_CACHE.set(key, promise);
  try {
    return await promise;
  } catch (err) {
    POLICY_CACHE.delete(key);
    throw err;
  }
}

function selectBountiesRule(params: BountiesV2Params, policy: FeePolicy): FeeRule | null {
  // Fail-closed rule selection. Only support closure types defined by the spec.
  const closure = params.closure_type;
  const code: CodeSelector = params.is_code_bounty ? 'true' : 'false';

  const exact = policy.rules.find((r) => r.closure_type === closure && r.is_code_bounty === code) ?? null;
  if (exact) return exact;

  const wildcard = policy.rules.find((r) => r.closure_type === closure && r.is_code_bounty === '*') ?? null;
  if (wildcard) return wildcard;

  return null;
}

function computeFee(principalMinor: bigint, rateBps: number, minFeeMinor: bigint): { feeMinor: bigint; floorApplied: boolean } {
  if (rateBps < 0 || rateBps > 10_000) {
    throw new Error('INVALID_RATE_BPS');
  }

  const numerator = principalMinor * BigInt(rateBps);
  const computed = rateBps === 0 ? 0n : ceilDiv(numerator, 10_000n);
  const floorApplied = computed < minFeeMinor;
  const feeMinor = floorApplied ? minFeeMinor : computed;

  return { feeMinor, floorApplied };
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === 'GET' && url.pathname === '/health') {
      return jsonResponse({ status: 'ok', service: 'clawcuts', version: env.CUTS_VERSION });
    }

    if (request.method === 'GET' && url.pathname === '/skill.md') {
      const metadata = {
        name: 'clawcuts',
        version: '1',
        description: 'Fee policy + simulation engine (bounties + tips).',
        endpoints: [
          { method: 'GET', path: '/health' },
          { method: 'POST', path: '/v1/fees/simulate' },
        ],
      };

      const md = `---\nmetadata: '${JSON.stringify(metadata)}'\n---\n\n# clawcuts\n\nEndpoints:\n- GET /health\n- POST /v1/fees/simulate\n\nExample (bounties):\n\n\`\`\`bash\ncurl -sS \\\n  -X POST "${url.origin}/v1/fees/simulate" \\\n  -H 'content-type: application/json' \\\n  -d '{"product":"clawbounties","policy_id":"bounties_v1","amount_minor":"5000","currency":"USD","params":{"is_code_bounty":true,"closure_type":"test"}}'\n\`\`\`\n\n`;

      return textResponse(md, 'text/markdown; charset=utf-8', 200, env.CUTS_VERSION);
    }

    // CCU-US-005 — Fee simulation
    if (request.method === 'POST' && url.pathname === '/v1/fees/simulate') {
      let body: unknown;
      try {
        body = await request.json();
      } catch {
        return errorResponse('INVALID_JSON', 'Request body must be valid JSON', 400);
      }

      if (!isRecord(body)) {
        return errorResponse('INVALID_REQUEST', 'Request body must be a JSON object', 400);
      }

      const product = body.product;
      const policy_id = body.policy_id;
      const currency = body.currency;
      const amount_minor = body.amount_minor;

      if (!isNonEmptyString(product)) {
        return errorResponse('INVALID_REQUEST', 'product is required', 400);
      }
      if (!isNonEmptyString(policy_id)) {
        return errorResponse('INVALID_REQUEST', 'policy_id is required', 400);
      }
      if (!isNonEmptyString(currency)) {
        return errorResponse('INVALID_REQUEST', 'currency is required', 400);
      }

      if (currency.trim().toUpperCase() !== 'USD') {
        return errorResponse('UNSUPPORTED_CURRENCY', 'Only USD is supported (amount_minor in cents)', 400);
      }

      const principalMinor = parseMoneyMinor(amount_minor);
      if (principalMinor === null) {
        return errorResponse('INVALID_REQUEST', 'amount_minor must be a positive integer string', 400);
      }

      let policyWithHash: { policy: FeePolicy; hash_b64u: string };
      try {
        policyWithHash = await getPolicyWithHash(product.trim(), policy_id.trim());
      } catch (err) {
        if (err instanceof Error && err.message === 'POLICY_NOT_FOUND') {
          return errorResponse('POLICY_NOT_FOUND', 'Unknown policy for product', 404);
        }
        return errorResponse('POLICY_LOAD_FAILED', 'Failed to load policy', 500);
      }

      const { policy, hash_b64u } = policyWithHash;

      let rule: FeeRule | null = null;
      if (policy.product === 'clawbounties' && policy.policy_id === 'bounties_v1') {
        const paramsRaw = body.params;
        if (!isRecord(paramsRaw)) {
          return errorResponse('INVALID_REQUEST', 'params must be an object for bounties_v1', 400);
        }

        const closure_type = paramsRaw.closure_type;
        if (!isNonEmptyString(closure_type)) {
          return errorResponse('INVALID_REQUEST', 'params.closure_type is required for bounties_v1', 400);
        }

        const closure = closure_type.trim();
        const allowedClosures = new Set(['test', 'requester', 'quorum']);
        if (!allowedClosures.has(closure)) {
          return errorResponse('INVALID_REQUEST', 'params.closure_type must be one of test|requester|quorum for bounties_v1', 400);
        }

        const is_code_bounty_raw = paramsRaw.is_code_bounty;
        let is_code_bounty = false;
        if (is_code_bounty_raw !== undefined) {
          if (typeof is_code_bounty_raw !== 'boolean') {
            return errorResponse('INVALID_REQUEST', 'params.is_code_bounty must be a boolean when provided', 400);
          }
          is_code_bounty = is_code_bounty_raw;
        }

        if (closure === 'test' && !is_code_bounty) {
          return errorResponse('INVALID_REQUEST', 'closure_type=test requires params.is_code_bounty=true', 400);
        }

        rule = selectBountiesRule({ closure_type: closure, is_code_bounty }, policy);

        if (!rule) {
          return errorResponse('RULE_NOT_FOUND', 'No fee rule matches the provided params', 400);
        }
      } else if (policy.product === 'clawtips' && policy.policy_id === 'tips_v1') {
        rule = policy.rules[0] ?? null;
      } else {
        return errorResponse('POLICY_NOT_FOUND', 'Unknown policy for product', 404);
      }

      if (!rule) {
        return errorResponse('RULE_NOT_FOUND', 'No fee rule matches the provided params', 400);
      }

      const minFeeMinor = BigInt(rule.min_fee_minor);
      const buyerFee = computeFee(principalMinor, rule.buyer_fee_bps, minFeeMinor);
      const workerFee = computeFee(principalMinor, rule.worker_fee_bps, 0n);

      const fees: FeeItem[] = [];

      if (rule.buyer_fee_bps !== 0 || minFeeMinor !== 0n) {
        fees.push({
          kind: 'platform',
          payer: 'buyer',
          amount_minor: buyerFee.feeMinor.toString(),
          rate_bps: rule.buyer_fee_bps,
          min_fee_minor: rule.min_fee_minor,
          floor_applied: buyerFee.floorApplied,
        });
      } else {
        // Tips policy: still emit an explicit 0-fee item for clarity.
        fees.push({
          kind: 'platform',
          payer: 'buyer',
          amount_minor: '0',
          rate_bps: 0,
          min_fee_minor: '0',
          floor_applied: false,
        });
      }

      const buyerTotalMinor = principalMinor + buyerFee.feeMinor;
      const workerNetMinor = principalMinor - workerFee.feeMinor;

      const response: FeeSimulateResponse = {
        policy: {
          id: policy.policy_id,
          version: policy.version,
          hash_b64u,
        },
        quote: {
          principal_minor: principalMinor.toString(),
          buyer_total_minor: buyerTotalMinor.toString(),
          worker_net_minor: workerNetMinor.toString(),
          fees,
        },
      };

      return jsonResponse(response);
    }

    return errorResponse('NOT_FOUND', 'Not found', 404);
  },
};
