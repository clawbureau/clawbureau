/**
 * KPOM -- Kinematic Proof of Model
 *
 * Passive timing collector for streaming LLM responses. Records per-chunk
 * timestamps and sizes to produce a hardware-level fingerprint without adding
 * any latency to the streaming path (never buffers, never awaits).
 *
 * The fingerprint is attached to the gateway receipt metadata after the
 * stream closes, making clawproxy an independent arbiter of model identity
 * that providers cannot manipulate.
 */

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/** Kinematic fingerprint matching kinematic_fingerprint.v1.json schema. */
export interface KinematicFingerprint {
  ttft_ms: number;
  itl_p50_ms: number;
  itl_p95_ms: number;
  itl_stddev_ms: number;
  chunk_count: number;
  burst_signature_b64u: string;
  hardware_inferred?: string;
  confidence_score?: number;
  total_tokens?: number;
  total_duration_ms?: number;
}

export interface TimingCollector {
  /** Record a single SSE chunk. Must be called synchronously on each chunk. */
  recordChunk(chunkSizeBytes: number): void;
  /** Compute the finalized fingerprint. Call once after the stream closes. */
  finalize(): Promise<KinematicFingerprint>;
}

// ---------------------------------------------------------------------------
// Internal helpers (pure, no side effects)
// ---------------------------------------------------------------------------

/** Quantize chunk sizes into `binCount` logarithmic buckets and return the distribution array. */
function quantizeChunkSizes(sizes: number[], binCount: number): number[] {
  if (sizes.length === 0) return new Array<number>(binCount).fill(0);

  let maxSize = 0;
  for (let i = 0; i < sizes.length; i++) {
    const s = sizes[i]!;
    if (s > maxSize) maxSize = s;
  }
  // Avoid log(0); treat zero-byte chunks as bin 0.
  const logMax = maxSize > 0 ? Math.log(maxSize + 1) : 1;

  const bins = new Array<number>(binCount).fill(0);
  for (let i = 0; i < sizes.length; i++) {
    const s = sizes[i]!;
    const logVal = s > 0 ? Math.log(s + 1) : 0;
    let idx = Math.floor((logVal / logMax) * binCount);
    if (idx >= binCount) idx = binCount - 1;
    bins[idx]!++;
  }
  return bins;
}

/** Percentile value from a **sorted** numeric array. */
function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const idx = (p / 100) * (sorted.length - 1);
  const lo = Math.floor(idx);
  const hi = Math.ceil(idx);
  const loVal = sorted[lo] ?? 0;
  const hiVal = sorted[hi] ?? 0;
  if (lo === hi) return loVal;
  return loVal + (hiVal - loVal) * (idx - lo);
}

/** Standard deviation (population). */
function stddev(values: number[]): number {
  const n = values.length;
  if (n === 0) return 0;
  let sum = 0;
  for (let i = 0; i < n; i++) sum += values[i]!;
  const mean = sum / n;
  let sqSum = 0;
  for (let i = 0; i < n; i++) sqSum += (values[i]! - mean) ** 2;
  return Math.sqrt(sqSum / n);
}

/** SHA-256 of a Uint8Array, returned as base64url (no padding). */
async function sha256B64u(data: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', data);
  const bytes = new Uint8Array(digest);

  // base64url encode (no padding)
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// ---------------------------------------------------------------------------
// Heuristic hardware classifier
// ---------------------------------------------------------------------------

type HardwareClass = 'cloud_optimized_cluster' | 'cloud_standard' | 'local_consumer_gpu' | 'unknown';

function classifyHardware(
  ttftMs: number,
  itlP50Ms: number,
  itlStddevMs: number
): { hardware: HardwareClass; confidence: number } {
  // Cloud optimized: fast first token, very low ITL, low jitter
  if (ttftMs < 100 && itlP50Ms < 20 && itlStddevMs < 10) {
    return { hardware: 'cloud_optimized_cluster', confidence: 0.7 };
  }

  // Local consumer GPU: slow start, high ITL, noisy
  if (ttftMs > 500 && itlP50Ms > 80 && itlStddevMs > 30) {
    return { hardware: 'local_consumer_gpu', confidence: 0.6 };
  }

  // Cloud standard: reasonable first token, moderate ITL
  if (ttftMs < 200 && itlP50Ms >= 20 && itlP50Ms <= 50) {
    return { hardware: 'cloud_standard', confidence: 0.5 };
  }

  return { hardware: 'unknown', confidence: 0.1 };
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

const BURST_BIN_COUNT = 8;

/**
 * Create a new timing collector. Call this when the streaming request starts.
 *
 * Zero-overhead on the hot path: `recordChunk` is a synchronous push into
 * pre-allocated arrays. All computation happens in `finalize()`.
 */
export function createTimingCollector(): TimingCollector {
  const createdAt = performance.now();
  const timestamps: number[] = [];
  const chunkSizes: number[] = [];

  return {
    recordChunk(chunkSizeBytes: number): void {
      timestamps.push(performance.now());
      chunkSizes.push(chunkSizeBytes);
    },

    async finalize(): Promise<KinematicFingerprint> {
      const chunkCount = timestamps.length;
      const lastTs = chunkCount > 0 ? timestamps[chunkCount - 1]! : createdAt;
      const firstTs = chunkCount > 0 ? timestamps[0]! : createdAt;
      const totalDuration = lastTs - createdAt;
      const ttft = firstTs - createdAt;

      // Compute inter-token latencies (ITL) from consecutive chunk timestamps
      const itl: number[] = [];
      for (let i = 1; i < chunkCount; i++) {
        itl.push(timestamps[i]! - timestamps[i - 1]!);
      }

      // Sort ITL for percentile computation
      const sortedItl = [...itl].sort((a, b) => a - b);
      const itlP50 = percentile(sortedItl, 50);
      const itlP95 = percentile(sortedItl, 95);
      const itlStddev = stddev(itl);

      // Burst signature: SHA-256 of quantized chunk-size distribution
      const distribution = quantizeChunkSizes(chunkSizes, BURST_BIN_COUNT);
      const distBytes = new TextEncoder().encode(JSON.stringify(distribution));
      const burstSignature = await sha256B64u(distBytes);

      // Hardware heuristic
      const { hardware, confidence: baseConfidence } = classifyHardware(ttft, itlP50, itlStddev);

      // Confidence scaling: need at least 20 chunks for >0.5 confidence
      let confidence = baseConfidence;
      if (chunkCount < 5) {
        confidence = Math.min(confidence, 0.1);
      } else if (chunkCount < 20) {
        confidence = Math.min(confidence, 0.3 + (chunkCount / 20) * 0.2);
      }

      // Round to 2 decimal places for stable output
      const round2 = (n: number) => Math.round(n * 100) / 100;

      return {
        ttft_ms: round2(ttft),
        itl_p50_ms: round2(itlP50),
        itl_p95_ms: round2(itlP95),
        itl_stddev_ms: round2(itlStddev),
        chunk_count: chunkCount,
        burst_signature_b64u: burstSignature,
        hardware_inferred: hardware,
        confidence_score: round2(confidence),
        total_duration_ms: round2(totalDuration),
      };
    },
  };
}

/**
 * Create a minimal fingerprint for non-streaming responses.
 * Only records TTFT (request start to response received). ITL fields are zeroed.
 */
export async function createNonStreamingFingerprint(
  requestStartPerfNow: number,
  responseReceivedPerfNow: number
): Promise<KinematicFingerprint> {
  const ttft = responseReceivedPerfNow - requestStartPerfNow;
  const emptyDistribution = new Array<number>(BURST_BIN_COUNT).fill(0);
  const distBytes = new TextEncoder().encode(JSON.stringify(emptyDistribution));
  const burstSignature = await sha256B64u(distBytes);

  const round2 = (n: number) => Math.round(n * 100) / 100;

  return {
    ttft_ms: round2(ttft),
    itl_p50_ms: 0,
    itl_p95_ms: 0,
    itl_stddev_ms: 0,
    chunk_count: 1,
    burst_signature_b64u: burstSignature,
    hardware_inferred: 'unknown',
    confidence_score: 0.1,
    total_duration_ms: round2(ttft),
  };
}
