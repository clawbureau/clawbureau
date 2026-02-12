import type { Env, LedgerIngestMessage } from './types';
import { computeHash } from './utils';

export async function handleQueue(batch: MessageBatch<LedgerIngestMessage>, env: Env): Promise<void> {
  for (const msg of batch.messages) {
    try { await processMessage(msg.body, env); msg.ack(); }
    catch (err) { console.error(`[ledger-ingest] ${msg.body.run_id}:`, err instanceof Error ? err.message : String(err)); msg.retry(); }
  }
}

async function processMessage(m: LedgerIngestMessage, env: Env): Promise<void> {
  await env.BUNDLES.put(`bundles/${m.run_id}.json`, m.bundle_json, {
    httpMetadata: { contentType: 'application/json' },
    customMetadata: { agent_did: m.agent_did, proof_tier: m.proof_tier, status: m.status, bundle_hash_b64u: m.bundle_hash_b64u },
  });

  await env.LEDGER_DB.prepare(
    'INSERT OR IGNORE INTO runs (run_id, bundle_hash_b64u, agent_did, proof_tier, status, wpc_hash_b64u, models_json) VALUES (?,?,?,?,?,?,?)',
  ).bind(m.run_id, m.bundle_hash_b64u, m.agent_did, m.proof_tier, m.status, m.wpc_hash_b64u ?? null, m.models_json ?? null).run();

  const gw = ['gateway', 'sandbox', 'tee', 'witnessed_web'].includes(m.proof_tier) ? 1 : 0;
  const viol = m.status !== 'PASS' ? 1 : 0;
  await env.LEDGER_DB.prepare(
    `INSERT INTO agents (did, verified_runs, gateway_tier_runs, policy_violations) VALUES (?,1,?,?)
     ON CONFLICT(did) DO UPDATE SET verified_runs=verified_runs+1, gateway_tier_runs=gateway_tier_runs+?, policy_violations=policy_violations+?`,
  ).bind(m.agent_did, gw, viol, gw, viol).run();

  let rtIdx: number | null = null;
  if (env.CLAWLOGS_RT_URL && env.CLAWLOGS_ADMIN_TOKEN) {
    try {
      const hash = await computeHash(m.bundle_hash_b64u, 'SHA-256');
      const res = await fetch(`${env.CLAWLOGS_RT_URL}/v1/rt/submit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${env.CLAWLOGS_ADMIN_TOKEN}` },
        body: JSON.stringify({ receipt_hash_b64u: hash }),
      });
      if (res.ok) {
        const body = (await res.json()) as { ok?: boolean; log_inclusion_proof?: { metadata?: { leaf_index?: number } } };
        if (body.ok && body.log_inclusion_proof?.metadata?.leaf_index != null) rtIdx = body.log_inclusion_proof.metadata.leaf_index;
      }
    } catch (err) { console.warn(`[ledger-ingest] RT failed ${m.run_id}:`, err instanceof Error ? err.message : String(err)); }
  }

  if (rtIdx != null) await env.LEDGER_DB.prepare('UPDATE runs SET rt_leaf_index=? WHERE run_id=?').bind(rtIdx, m.run_id).run();
}
