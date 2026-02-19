import type { Env, LedgerIngestMessage } from './types';
import { computeHash } from './utils';

interface RunStateRow {
  run_id: string;
  rt_leaf_index: number | null;
}

function d1Changes(result: unknown): number {
  const maybeMeta = (result as { meta?: { changes?: number | string } } | null | undefined)?.meta;
  const raw = maybeMeta?.changes;

  if (typeof raw === 'number' && Number.isFinite(raw)) return raw;
  if (typeof raw === 'string') {
    const parsed = Number(raw);
    if (Number.isFinite(parsed)) return parsed;
  }

  return 0;
}

async function findRunState(env: Env, runId: string): Promise<RunStateRow | null> {
  const row = await env.LEDGER_DB.prepare(
    'SELECT run_id, rt_leaf_index FROM runs WHERE run_id = ? LIMIT 1'
  ).bind(runId).first<RunStateRow>();

  return row ?? null;
}

async function ensureRunAndAgentCounters(m: LedgerIngestMessage, env: Env): Promise<void> {
  const insertResult = await env.LEDGER_DB.prepare(
    `INSERT OR IGNORE INTO runs (
      run_id, bundle_hash_b64u, agent_did, proof_tier, status,
      reason_code, failure_class, verification_source, auth_mode,
      wpc_hash_b64u, models_json
    ) VALUES (?,?,?,?,?,?,?,?,?,?,?)`
  ).bind(
    m.run_id,
    m.bundle_hash_b64u,
    m.agent_did,
    m.proof_tier,
    m.status,
    m.reason_code,
    m.failure_class,
    m.verification_source,
    m.auth_mode,
    m.wpc_hash_b64u ?? null,
    m.models_json ?? null,
  ).run();

  const inserted = d1Changes(insertResult) > 0;
  if (!inserted) {
    return;
  }

  const gw = ['gateway', 'sandbox', 'tee', 'witnessed_web'].includes(m.proof_tier) ? 1 : 0;
  const viol = m.status !== 'PASS' ? 1 : 0;

  await env.LEDGER_DB.prepare(
    `INSERT INTO agents (did, verified_runs, gateway_tier_runs, policy_violations)
     VALUES (?,1,?,?)
     ON CONFLICT(did) DO UPDATE SET
       verified_runs = verified_runs + 1,
       gateway_tier_runs = gateway_tier_runs + ?,
       policy_violations = policy_violations + ?`
  ).bind(m.agent_did, gw, viol, gw, viol).run();
}

export async function handleQueue(batch: MessageBatch<LedgerIngestMessage>, env: Env): Promise<void> {
  for (const msg of batch.messages) {
    try {
      await processMessage(msg.body, env);
      msg.ack();
    } catch (err) {
      console.error(`[ledger-ingest] ${msg.body.run_id}:`, err instanceof Error ? err.message : String(err));
      msg.retry();
    }
  }
}

async function processMessage(m: LedgerIngestMessage, env: Env): Promise<void> {
  const existing = await findRunState(env, m.run_id);
  if (!existing) {
    await ensureRunAndAgentCounters(m, env);
  }

  await env.BUNDLES.put(`bundles/${m.run_id}.json`, m.bundle_json, {
    httpMetadata: { contentType: 'application/json' },
    customMetadata: {
      agent_did: m.agent_did,
      proof_tier: m.proof_tier,
      status: m.status,
      bundle_hash_b64u: m.bundle_hash_b64u,
    },
  });

  const stateAfterPersistence = await findRunState(env, m.run_id);
  if (stateAfterPersistence?.rt_leaf_index != null) {
    return;
  }

  let rtIdx: number | null = null;
  if (env.CLAWLOGS_RT_URL && env.CLAWLOGS_ADMIN_TOKEN) {
    try {
      const hash = await computeHash(m.bundle_hash_b64u);
      const res = await fetch(`${env.CLAWLOGS_RT_URL}/v1/rt/submit`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${env.CLAWLOGS_ADMIN_TOKEN}`,
        },
        body: JSON.stringify({ receipt_hash_b64u: hash }),
      });
      if (res.ok) {
        const body = (await res.json()) as {
          ok?: boolean;
          log_inclusion_proof?: { metadata?: { leaf_index?: number } };
        };
        if (body.ok && body.log_inclusion_proof?.metadata?.leaf_index != null) {
          rtIdx = body.log_inclusion_proof.metadata.leaf_index;
        }
      }
    } catch (err) {
      console.warn(`[ledger-ingest] RT failed ${m.run_id}:`, err instanceof Error ? err.message : String(err));
    }
  }

  if (rtIdx != null) {
    await env.LEDGER_DB.prepare(
      'UPDATE runs SET rt_leaf_index = COALESCE(rt_leaf_index, ?) WHERE run_id = ?'
    ).bind(rtIdx, m.run_id).run();
  }
}
