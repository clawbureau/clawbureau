/**
 * Marketplace CST response helpers.
 *
 * Used by the CLI to auto-fetch a job-scoped CST from clawbounties.
 */

export type ParsedMarketplaceCst =
  | { kind: 'cwc'; cst: string; policy_hash_b64u?: string; mission_id?: string }
  | { kind: 'job'; cst: string; policy_hash_b64u?: string; mission_id?: string };

function isRecord(x: unknown): x is Record<string, unknown> {
  return typeof x === 'object' && x !== null && !Array.isArray(x);
}

function isNonEmptyString(x: unknown): x is string {
  return typeof x === 'string' && x.trim().length > 0;
}

export function parseMarketplaceCstResponse(json: unknown): ParsedMarketplaceCst {
  if (!isRecord(json)) {
    throw new Error('clawbounties /cst returned an invalid response (expected a JSON object)');
  }

  const cwc = json.cwc_auth;
  if (isRecord(cwc)) {
    const cst = cwc.cst;
    if (isNonEmptyString(cst)) {
      return {
        kind: 'cwc',
        cst: cst.trim(),
        policy_hash_b64u: isNonEmptyString(cwc.policy_hash_b64u) ? cwc.policy_hash_b64u.trim() : undefined,
        mission_id: isNonEmptyString(cwc.mission_id) ? cwc.mission_id.trim() : undefined,
      };
    }
  }

  const job = json.job_auth;
  if (isRecord(job)) {
    const cst = job.cst;
    if (isNonEmptyString(cst)) {
      return {
        kind: 'job',
        cst: cst.trim(),
        policy_hash_b64u: isNonEmptyString(job.policy_hash_b64u) ? job.policy_hash_b64u.trim() : undefined,
        mission_id: isNonEmptyString(job.mission_id) ? job.mission_id.trim() : undefined,
      };
    }
  }

  throw new Error('clawbounties /cst returned an invalid response (missing cwc_auth.cst or job_auth.cst)');
}
