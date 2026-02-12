import { compileSemanticTrace } from '@clawbureau/clawverify-core';
import type { ProofBundlePayload } from '@clawbureau/clawverify-core';
import { embedTrace } from './evaluator.js';
import type { Env, IngestMessage, TrajectoryMetadata } from './types.js';

export async function handleIngestBatch(
  batch: MessageBatch<IngestMessage>,
  env: Env,
): Promise<void> {
  const vectors: VectorizeVector[] = [];

  for (const message of batch.messages) {
    const msg = message.body;
    try {
      const bundle = msg.proof_bundle as unknown as ProofBundlePayload;
      const traceString = compileSemanticTrace(bundle);
      const values = await embedTrace(traceString, env.AI);
      const metadata: TrajectoryMetadata = {
        run_id: msg.run_id, agent_did: msg.agent_did, status: msg.status,
        proof_tier: msg.proof_tier ?? 'unknown', created_at: msg.created_at ?? new Date().toISOString(),
      };
      vectors.push({
        id: msg.run_id, values,
        metadata: metadata as unknown as Record<string, VectorizeVectorMetadata>,
      });
      message.ack();
    } catch (err) {
      console.error(`[sentinel-ingest] Failed run_id=${msg.run_id}:`, err instanceof Error ? err.message : String(err));
      message.retry();
    }
  }

  if (vectors.length > 0) {
    try {
      await env.SENTINEL_DB.upsert(vectors);
      console.log(`[sentinel-ingest] Upserted ${vectors.length} vectors`);
    } catch (err) {
      console.error('[sentinel-ingest] Vectorize upsert failed:', err instanceof Error ? err.message : String(err));
    }
  }
}
