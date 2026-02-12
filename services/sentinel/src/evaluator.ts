import type { Env, SentinelResult, TrajectoryMetadata } from './types.js';

const K = 5;
const ANOMALY_THRESHOLD = 0.85;
const ALIEN_DISTANCE_THRESHOLD = 0.85;
const VIOLATION_STATUSES = new Set(['INVALID', 'policy_violation', 'flagged']);

export async function embedTrace(traceString: string, ai: Ai): Promise<number[]> {
  const result = await ai.run('@cf/baai/bge-large-en-v1.5', { text: [traceString] });
  const output = result as { data?: number[][] };
  if (!output.data || !output.data[0]) {
    throw new Error('Workers AI embedding returned no data');
  }
  return output.data[0];
}

export async function evaluateBehavioralRisk(
  traceString: string,
  env: Env,
): Promise<SentinelResult> {
  const vector = await embedTrace(traceString, env.AI);
  const queryResult = await env.SENTINEL_DB.query(vector, { topK: K, returnMetadata: 'all' });
  const matches = queryResult.matches ?? [];

  if (matches.length === 0) {
    return { safe: true, threat_score: 0, anomaly_type: 'benign', nearest_run_ids: [], confidence: 0 };
  }

  let maliciousWeight = 0;
  let totalWeight = 0;
  let allFar = true;
  const nearestRunIds: string[] = [];

  for (const match of matches) {
    const similarity = match.score ?? 0;
    const distance = 1 - similarity;
    const metadata = (match.metadata ?? {}) as unknown as TrajectoryMetadata;
    if (metadata.run_id) nearestRunIds.push(metadata.run_id);
    totalWeight += similarity;
    if (VIOLATION_STATUSES.has(metadata.status)) maliciousWeight += similarity;
    if (distance < ALIEN_DISTANCE_THRESHOLD) allFar = false;
  }

  const anomalyScore = totalWeight > 0 ? maliciousWeight / totalWeight : 0;

  if (allFar && maliciousWeight === 0) {
    return {
      safe: false, threat_score: 50, anomaly_type: 'alien_trajectory',
      nearest_run_ids: nearestRunIds, confidence: Math.min(matches.length / K, 1),
    };
  }

  if (anomalyScore > ANOMALY_THRESHOLD) {
    const hasEffect = traceString.includes('[EFFECT:');
    return {
      safe: false,
      threat_score: Math.round(anomalyScore * 100),
      anomaly_type: hasEffect ? 'data_exfiltration_topology' : 'prompt_injection_suspected',
      nearest_run_ids: nearestRunIds,
      confidence: Math.min(matches.length / K, 1),
    };
  }

  return {
    safe: true, threat_score: Math.round(anomalyScore * 100), anomaly_type: 'benign',
    nearest_run_ids: nearestRunIds, confidence: Math.min(matches.length / K, 1),
  };
}
