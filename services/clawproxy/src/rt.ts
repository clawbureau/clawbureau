/**
 * Receipt Transparency (RT) — submit receipt hashes to clawlogs Merkle tree.
 *
 * When RT_ENABLED=true, every gateway receipt envelope's payload_hash_b64u is
 * POSTed to the clawlogs /v1/rt/submit endpoint. The returned
 * log_inclusion_proof is attached to the receipt envelope metadata.
 *
 * If the RT submission fails for any reason the receipt is still emitted
 * without the inclusion proof (graceful degradation, never blocks inference).
 */

import type { Env } from './types';

/** Shape returned by clawlogs POST /v1/rt/submit */
export interface RtSubmitResponse {
  ok: boolean;
  log_inclusion_proof?: LogInclusionProof;
  error?: { code: string; message: string };
}

/** Matches log_inclusion_proof.v1.json schema */
export interface LogInclusionProof {
  proof_version: '1';
  log_id: string;
  tree_size: number;
  leaf_hash_b64u: string;
  root_hash_b64u: string;
  audit_path: string[];
  root_published_at: string;
  root_signature: {
    signer_did: string;
    sig_b64u: string;
  };
  metadata?: Record<string, unknown>;
}

/** Check whether RT is enabled for this worker. */
export function isRtEnabled(env: Env): boolean {
  return env.RT_ENABLED?.trim().toLowerCase() === 'true';
}

/** Resolve the clawlogs RT base URL. */
function rtBaseUrl(env: Env): string {
  const url = env.CLAWLOGS_RT_URL?.trim();
  if (url && url.length > 0) return url.replace(/\/+$/, '');
  return 'https://clawlogs.com';
}

/**
 * Submit a receipt hash to the RT log and return the inclusion proof.
 *
 * Returns null on any failure (network, auth, timeout) — caller must
 * treat null as "no proof available" and continue without blocking.
 */
export async function submitReceiptToRt(
  env: Env,
  receiptHashB64u: string,
): Promise<LogInclusionProof | null> {
  if (!isRtEnabled(env)) return null;

  const adminToken = env.CLAWLOGS_RT_ADMIN_TOKEN?.trim();
  if (!adminToken) {
    console.error('[RT] CLAWLOGS_RT_ADMIN_TOKEN not configured; skipping RT submission');
    return null;
  }

  const base = rtBaseUrl(env);
  const url = `${base}/v1/rt/submit`;

  try {
    const resp = await fetch(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${adminToken}`,
      },
      body: JSON.stringify({ receipt_hash_b64u: receiptHashB64u }),
      signal: AbortSignal.timeout(5_000),
    });

    const body = (await resp.json()) as RtSubmitResponse;

    if (body.ok && body.log_inclusion_proof) {
      return body.log_inclusion_proof;
    }

    // 409 = duplicate (already in log). Fetch existing proof instead.
    if (resp.status === 409) {
      return fetchExistingRtProof(env, receiptHashB64u);
    }

    console.error(`[RT] submit failed: ${resp.status} ${JSON.stringify(body.error ?? {})}`);
    return null;
  } catch (err) {
    console.error('[RT] submit error:', err instanceof Error ? err.message : err);
    return null;
  }
}

/**
 * Fetch an existing RT proof for a receipt hash that was already submitted.
 */
async function fetchExistingRtProof(
  env: Env,
  receiptHashB64u: string,
): Promise<LogInclusionProof | null> {
  const base = rtBaseUrl(env);
  const url = `${base}/v1/rt/proof/${encodeURIComponent(receiptHashB64u)}`;

  try {
    const resp = await fetch(url, {
      signal: AbortSignal.timeout(5_000),
    });

    if (!resp.ok) return null;

    const body = (await resp.json()) as Record<string, unknown>;

    // The GET /v1/rt/proof endpoint returns the proof at the top level
    if (body.proof_version === '1' && typeof body.log_id === 'string') {
      return body as unknown as LogInclusionProof;
    }

    return null;
  } catch {
    return null;
  }
}
