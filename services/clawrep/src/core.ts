export type ClosureType =
  | 'auto_approve'
  | 'quorum_approve'
  | 'manual_approve'
  | 'dispute_resolved';

export type ProofTier = 'unknown' | 'self' | 'gateway' | 'sandbox' | 'tee' | 'witnessed_web';

export type PenaltyType =
  | 'dispute_upheld_against_reviewer'
  | 'dispute_upheld_against_worker'
  | 'fraud_confirmed'
  | 'spam_review'
  | 'policy_violation';

export type RecoveryType = 'appeal_upheld_for_reviewer' | 'appeal_upheld_for_worker';

export type RepEventType = 'closure' | 'penalty' | 'decay' | 'recovery';

export interface ClosureEventInput {
  source_event_id: string;
  did: string;
  value_usd: number;
  closure_type: ClosureType;
  proof_tier: ProofTier;
  owner_verified: boolean;
  owner_attestation_ref?: string;
  occurred_at: string;
  metadata?: Record<string, unknown>;
}

export interface PenaltyEventInput {
  source_event_id: string;
  did: string;
  penalty_type: PenaltyType;
  severity: number;
  occurred_at: string;
  reason?: string;
  metadata?: Record<string, unknown>;
}

export interface RecoveryEventInput {
  source_event_id: string;
  did: string;
  recovery_type: RecoveryType;
  severity: number;
  occurred_at: string;
  reason?: string;
  metadata?: Record<string, unknown>;
}

export interface RepProfile {
  did: string;
  reputation_score: number;
  events_count: number;
  penalties_count: number;
  dispute_penalties_count: number;
  is_owner_verified: boolean;
  owner_attestation_ref?: string;
  last_event_at?: string;
  last_decay_at?: string;
  updated_at: string;
  created_at: string;
}

export interface RepEvent {
  source_event_id: string;
  did: string;
  event_type: RepEventType;
  score_delta: number;
  status: 'pending' | 'processed';
  closure_type?: ClosureType;
  proof_tier?: ProofTier;
  owner_verified?: boolean;
  owner_attestation_ref?: string;
  value_usd?: number;
  concave_value?: number;
  weight_closure?: number;
  weight_proof?: number;
  weight_owner?: number;
  penalty_type?: PenaltyType;
  recovery_type?: RecoveryType;
  severity?: number;
  occurred_at: string;
  processed_at?: string;
  metadata?: Record<string, unknown>;
}

export interface ReviewerInfo {
  reviewer_did: string;
  reputation_score: number;
  is_owner_verified: boolean;
  owner_attestation_ref?: string;
}

export interface SelectReviewersRequest {
  bounty_id: string;
  difficulty_scalar: number;
  quorum_size: number;
  min_reputation_score?: number;
  require_owner_verified?: boolean;
  exclude_dids?: string[];
  submission_proof_tier?: ProofTier;
  requester_did?: string;
  worker_did?: string;
}

export interface ReviewerSelectionSignals {
  requester_did?: string;
  worker_did?: string;
  recent_selection_counts?: Record<string, number>;
  pair_selection_counts?: Record<string, number>;
  cooldown_blocked?: Set<string>;
  cooldown_hours?: number;
  history_window_days?: number;
}

export interface ReviewerSelectionReason {
  reviewer_did: string;
  base_score: number;
  owner_bonus: number;
  recency_count: number;
  recency_penalty: number;
  pair_penalty: number;
  attestation_penalty: number;
  final_score: number;
}

export interface ReviewerSelectionMetadata {
  request_hash_seed: string;
  candidate_pool_size: number;
  eligible_candidate_count: number;
  exclusion_buckets: Record<string, number>;
  anti_collusion: {
    cooldown_hours: number;
    history_window_days: number;
  };
  selected_reasoning: ReviewerSelectionReason[];
}

export interface ReviewerSelectionResult {
  reviewers: ReviewerInfo[];
  metadata: ReviewerSelectionMetadata;
}

export interface TierResult {
  tier: 0 | 1 | 2 | 3;
  tier_label: 'new' | 'emerging' | 'trusted' | 'elite';
  capped_by_dispute_rate: boolean;
  dispute_rate: number;
}

const CLOSURE_WEIGHTS: Record<ClosureType, number> = {
  auto_approve: 0.85,
  quorum_approve: 1,
  manual_approve: 0.95,
  dispute_resolved: 0.7,
};

const PROOF_WEIGHTS: Record<ProofTier, number> = {
  unknown: 0.5,
  self: 0.7,
  gateway: 1,
  sandbox: 1.2,
  tee: 1.35,
  witnessed_web: 1.1,
};

const PENALTY_BASE: Record<PenaltyType, number> = {
  dispute_upheld_against_reviewer: 12,
  dispute_upheld_against_worker: 9,
  fraud_confirmed: 30,
  spam_review: 15,
  policy_violation: 8,
};

const RECOVERY_BASE: Record<RecoveryType, number> = {
  appeal_upheld_for_reviewer: 7,
  appeal_upheld_for_worker: 6,
};

const DISPUTE_PENALTIES = new Set<PenaltyType>([
  'dispute_upheld_against_reviewer',
  'dispute_upheld_against_worker',
]);

const SCORE_MULTIPLIER = 10;

function round(value: number, precision = 6): number {
  const factor = 10 ** precision;
  return Math.round(value * factor) / factor;
}

export function isDidString(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const trimmed = value.trim();
  if (!trimmed.startsWith('did:')) return false;
  return trimmed.length >= 16;
}

export function normalizeSourceEventId(value: string): string {
  return value.trim();
}

export function computeConcaveValue(valueUsd: number): number {
  const bounded = Math.min(Math.max(valueUsd, 0), 1_000_000);
  return round(Math.sqrt(bounded));
}

export function computeOwnerWeight(ownerVerified: boolean): number {
  return ownerVerified ? 1.15 : 1;
}

export function computeClosureWeight(closureType: ClosureType): number {
  return CLOSURE_WEIGHTS[closureType];
}

export function computeProofWeight(proofTier: ProofTier): number {
  return PROOF_WEIGHTS[proofTier];
}

export function computeClosureScoreDelta(input: {
  value_usd: number;
  closure_type: ClosureType;
  proof_tier: ProofTier;
  owner_verified: boolean;
}): {
  score_delta: number;
  concave_value: number;
  weight_closure: number;
  weight_proof: number;
  weight_owner: number;
} {
  const concaveValue = computeConcaveValue(input.value_usd);
  const weightClosure = computeClosureWeight(input.closure_type);
  const weightProof = computeProofWeight(input.proof_tier);
  const weightOwner = computeOwnerWeight(input.owner_verified);
  const scoreDelta = round(concaveValue * weightClosure * weightProof * weightOwner * SCORE_MULTIPLIER);

  return {
    score_delta: scoreDelta,
    concave_value: concaveValue,
    weight_closure: weightClosure,
    weight_proof: weightProof,
    weight_owner: weightOwner,
  };
}

export function computePenaltyScoreDelta(penaltyType: PenaltyType, severity: number): number {
  const boundedSeverity = Math.min(5, Math.max(1, Math.floor(severity)));
  const multiplier = 1 + (boundedSeverity - 1) * 0.5;
  return round(-PENALTY_BASE[penaltyType] * multiplier);
}

export function computeRecoveryScoreDelta(recoveryType: RecoveryType, severity: number): number {
  const boundedSeverity = Math.min(5, Math.max(1, Math.floor(severity)));
  const multiplier = 1 + (boundedSeverity - 1) * 0.4;
  return round(RECOVERY_BASE[recoveryType] * multiplier);
}

export function isDisputePenalty(penaltyType: PenaltyType): boolean {
  return DISPUTE_PENALTIES.has(penaltyType);
}

export function deriveTier(profile: Pick<RepProfile, 'reputation_score' | 'events_count' | 'dispute_penalties_count'>): TierResult {
  const score = Math.max(0, profile.reputation_score);
  let tier: 0 | 1 | 2 | 3;
  let tierLabel: 'new' | 'emerging' | 'trusted' | 'elite';

  if (score >= 250) {
    tier = 3;
    tierLabel = 'elite';
  } else if (score >= 100) {
    tier = 2;
    tierLabel = 'trusted';
  } else if (score >= 25) {
    tier = 1;
    tierLabel = 'emerging';
  } else {
    tier = 0;
    tierLabel = 'new';
  }

  const disputeRate = profile.events_count <= 0 ? 0 : profile.dispute_penalties_count / profile.events_count;

  let cappedByDisputeRate = false;
  if (disputeRate >= 0.25 && tier > 1) {
    tier = 1;
    tierLabel = 'emerging';
    cappedByDisputeRate = true;
  } else if (disputeRate >= 0.1 && tier > 2) {
    tier = 2;
    tierLabel = 'trusted';
    cappedByDisputeRate = true;
  }

  return {
    tier,
    tier_label: tierLabel,
    capped_by_dispute_rate: cappedByDisputeRate,
    dispute_rate: round(disputeRate, 6),
  };
}

function deterministicJitter(seed: string): number {
  let hash = 2166136261;
  for (let i = 0; i < seed.length; i += 1) {
    hash ^= seed.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0) / 0xffffffff;
}

function pairKey(a: string, b: string): string {
  return a <= b ? `${a}::${b}` : `${b}::${a}`;
}

export function selectReviewersDeterministicWithSignals(
  request: SelectReviewersRequest,
  candidates: ReviewerInfo[],
  signals: ReviewerSelectionSignals = {}
): ReviewerSelectionResult {
  const requesterDid = (signals.requester_did ?? request.requester_did)?.trim() || null;
  const workerDid = (signals.worker_did ?? request.worker_did)?.trim() || null;

  const excludes = new Set((request.exclude_dids ?? []).map((did) => did.trim()));
  if (requesterDid) excludes.add(requesterDid);
  if (workerDid) excludes.add(workerDid);

  const cooldownBlocked = signals.cooldown_blocked ?? new Set<string>();
  const recentSelectionCounts = signals.recent_selection_counts ?? {};
  const pairSelectionCounts = signals.pair_selection_counts ?? {};

  const minRep = request.min_reputation_score ?? 0;
  const effectiveMinRep = minRep + Math.max(0, request.difficulty_scalar - 1) * 5;

  const exclusionBuckets: {
    excluded_did: number;
    owner_verification_required: number;
    below_min_reputation: number;
    cooldown_blocked: number;
  } = {
    excluded_did: 0,
    owner_verification_required: 0,
    below_min_reputation: 0,
    cooldown_blocked: 0,
  };

  const eligible: ReviewerInfo[] = [];
  for (const candidate of candidates) {
    const did = candidate.reviewer_did.trim();

    if (excludes.has(did)) {
      exclusionBuckets.excluded_did += 1;
      continue;
    }

    if (request.require_owner_verified && !candidate.is_owner_verified) {
      exclusionBuckets.owner_verification_required += 1;
      continue;
    }

    if (candidate.reputation_score < effectiveMinRep) {
      exclusionBuckets.below_min_reputation += 1;
      continue;
    }

    if (cooldownBlocked.has(did)) {
      exclusionBuckets.cooldown_blocked += 1;
      continue;
    }

    eligible.push(candidate);
  }

  const selected: ReviewerInfo[] = [];
  const selectedReasoning: ReviewerSelectionReason[] = [];
  const remaining = [...eligible];

  while (selected.length < request.quorum_size && remaining.length > 0) {
    let bestIndex = 0;
    let bestScore = Number.NEGATIVE_INFINITY;
    let bestReason: ReviewerSelectionReason | null = null;

    for (let i = 0; i < remaining.length; i += 1) {
      const candidate = remaining[i];
      if (!candidate) continue;

      const difficultyBoost = 1 + Math.max(0, request.difficulty_scalar - 1) * 0.05;
      const ownerBonus = candidate.is_owner_verified ? 2 : 0;
      const baseScore = candidate.reputation_score * difficultyBoost;
      const recencyCount = Math.max(0, Math.floor(recentSelectionCounts[candidate.reviewer_did] ?? 0));
      const recencyPenalty = recencyCount * 1.25;

      let pairPenalty = 0;
      for (const prior of selected) {
        const count = Math.max(0, Math.floor(pairSelectionCounts[pairKey(candidate.reviewer_did, prior.reviewer_did)] ?? 0));
        if (count > 0) {
          pairPenalty += count * 2;
        }
      }

      const attestationPenalty = selected.some(
        (prior) =>
          candidate.owner_attestation_ref &&
          prior.owner_attestation_ref &&
          candidate.owner_attestation_ref === prior.owner_attestation_ref
      )
        ? 1.5
        : 0;

      const jitter = deterministicJitter(`${request.bounty_id}:${candidate.reviewer_did}`) * 1e-6;
      const finalScore = baseScore + ownerBonus - recencyPenalty - pairPenalty - attestationPenalty + jitter;

      const reason: ReviewerSelectionReason = {
        reviewer_did: candidate.reviewer_did,
        base_score: round(baseScore),
        owner_bonus: ownerBonus,
        recency_count: recencyCount,
        recency_penalty: round(recencyPenalty),
        pair_penalty: round(pairPenalty),
        attestation_penalty: round(attestationPenalty),
        final_score: round(finalScore),
      };

      if (
        finalScore > bestScore ||
        (finalScore === bestScore && candidate.reviewer_did.localeCompare(remaining[bestIndex]?.reviewer_did ?? '') < 0)
      ) {
        bestScore = finalScore;
        bestIndex = i;
        bestReason = reason;
      }
    }

    const [winner] = remaining.splice(bestIndex, 1);
    if (!winner) {
      break;
    }

    selected.push(winner);
    if (bestReason) {
      selectedReasoning.push(bestReason);
    }
  }

  const metadata: ReviewerSelectionMetadata = {
    request_hash_seed: `${request.bounty_id}:${request.difficulty_scalar}:${request.quorum_size}`,
    candidate_pool_size: candidates.length,
    eligible_candidate_count: eligible.length,
    exclusion_buckets: exclusionBuckets,
    anti_collusion: {
      cooldown_hours: signals.cooldown_hours ?? 12,
      history_window_days: signals.history_window_days ?? 30,
    },
    selected_reasoning: selectedReasoning,
  };

  return {
    reviewers: selected,
    metadata,
  };
}

export function selectReviewersDeterministic(
  request: SelectReviewersRequest,
  candidates: ReviewerInfo[]
): ReviewerInfo[] {
  return selectReviewersDeterministicWithSignals(request, candidates).reviewers;
}

export class InMemoryRepEngine {
  private readonly events = new Map<string, RepEvent>();
  private readonly profiles = new Map<string, RepProfile>();
  private readonly decayRuns = new Set<string>();

  ingestClosure(input: ClosureEventInput): { duplicate: boolean; event: RepEvent } {
    const sourceId = normalizeSourceEventId(input.source_event_id);
    const existing = this.events.get(sourceId);
    if (existing) {
      return { duplicate: true, event: existing };
    }

    const scoring = computeClosureScoreDelta(input);
    const event: RepEvent = {
      source_event_id: sourceId,
      did: input.did,
      event_type: 'closure',
      score_delta: scoring.score_delta,
      status: 'pending',
      closure_type: input.closure_type,
      proof_tier: input.proof_tier,
      owner_verified: input.owner_verified,
      owner_attestation_ref: input.owner_attestation_ref,
      value_usd: input.value_usd,
      concave_value: scoring.concave_value,
      weight_closure: scoring.weight_closure,
      weight_proof: scoring.weight_proof,
      weight_owner: scoring.weight_owner,
      occurred_at: input.occurred_at,
      metadata: input.metadata,
    };

    this.events.set(sourceId, event);
    return { duplicate: false, event };
  }

  ingestPenalty(input: PenaltyEventInput): { duplicate: boolean; event: RepEvent } {
    const sourceId = normalizeSourceEventId(input.source_event_id);
    const existing = this.events.get(sourceId);
    if (existing) {
      return { duplicate: true, event: existing };
    }

    const event: RepEvent = {
      source_event_id: sourceId,
      did: input.did,
      event_type: 'penalty',
      score_delta: computePenaltyScoreDelta(input.penalty_type, input.severity),
      status: 'pending',
      penalty_type: input.penalty_type,
      severity: Math.min(5, Math.max(1, Math.floor(input.severity))),
      occurred_at: input.occurred_at,
      metadata: {
        ...(input.metadata ?? {}),
        ...(input.reason ? { reason: input.reason } : {}),
      },
    };

    this.events.set(sourceId, event);
    return { duplicate: false, event };
  }

  ingestRecovery(input: RecoveryEventInput): { duplicate: boolean; event: RepEvent } {
    const sourceId = normalizeSourceEventId(input.source_event_id);
    const existing = this.events.get(sourceId);
    if (existing) {
      return { duplicate: true, event: existing };
    }

    const event: RepEvent = {
      source_event_id: sourceId,
      did: input.did,
      event_type: 'recovery',
      score_delta: computeRecoveryScoreDelta(input.recovery_type, input.severity),
      status: 'pending',
      recovery_type: input.recovery_type,
      severity: Math.min(5, Math.max(1, Math.floor(input.severity))),
      occurred_at: input.occurred_at,
      metadata: {
        ...(input.metadata ?? {}),
        ...(input.reason ? { reason: input.reason } : {}),
      },
    };

    this.events.set(sourceId, event);
    return { duplicate: false, event };
  }

  processPending(sourceEventId?: string): number {
    const entries = sourceEventId
      ? Array.from(this.events.entries()).filter(([key, value]) => key === sourceEventId && value.status === 'pending')
      : Array.from(this.events.entries()).filter(([, value]) => value.status === 'pending');

    let processed = 0;

    for (const [, event] of entries) {
      const now = new Date().toISOString();
      const existing = this.profiles.get(event.did);
      if (!existing) {
        this.profiles.set(event.did, {
          did: event.did,
          reputation_score: Math.max(0, event.score_delta),
          events_count: 1,
          penalties_count: event.event_type === 'penalty' ? 1 : 0,
          dispute_penalties_count: event.penalty_type && isDisputePenalty(event.penalty_type) ? 1 : 0,
          is_owner_verified: !!event.owner_verified,
          owner_attestation_ref: event.owner_attestation_ref,
          last_event_at: event.occurred_at,
          last_decay_at: event.event_type === 'decay' ? now : undefined,
          updated_at: now,
          created_at: now,
        });
      } else {
        existing.reputation_score = Math.max(0, round(existing.reputation_score + event.score_delta));
        existing.events_count += 1;
        if (event.event_type === 'penalty') {
          existing.penalties_count += 1;
        }
        if (event.penalty_type && isDisputePenalty(event.penalty_type)) {
          existing.dispute_penalties_count += 1;
        }
        existing.is_owner_verified = existing.is_owner_verified || !!event.owner_verified;
        if (event.owner_attestation_ref) {
          existing.owner_attestation_ref = event.owner_attestation_ref;
        }
        existing.last_event_at = event.occurred_at;
        if (event.event_type === 'decay') {
          existing.last_decay_at = now;
        }
        existing.updated_at = now;
      }

      event.status = 'processed';
      event.processed_at = now;
      processed += 1;
    }

    return processed;
  }

  runDailyDecay(runDay: string, decayRate: number): { already_applied: boolean; affected: number; total_delta: number } {
    if (this.decayRuns.has(runDay)) {
      return { already_applied: true, affected: 0, total_delta: 0 };
    }

    this.decayRuns.add(runDay);

    let affected = 0;
    let totalDelta = 0;

    for (const profile of this.profiles.values()) {
      if (profile.reputation_score <= 0) continue;
      const decayAmount = round(profile.reputation_score * decayRate);
      if (decayAmount <= 0) continue;

      const sourceId = `decay:${runDay}:${profile.did}`;
      if (this.events.has(sourceId)) continue;

      const event: RepEvent = {
        source_event_id: sourceId,
        did: profile.did,
        event_type: 'decay',
        score_delta: -decayAmount,
        status: 'pending',
        occurred_at: `${runDay}T00:00:00.000Z`,
      };
      this.events.set(sourceId, event);
      affected += 1;
      totalDelta += decayAmount;
    }

    this.processPending();

    return {
      already_applied: false,
      affected,
      total_delta: round(totalDelta),
    };
  }

  getProfile(did: string): RepProfile | null {
    const profile = this.profiles.get(did);
    if (!profile) return null;
    return { ...profile };
  }

  getReviewerInfo(did: string): ReviewerInfo | null {
    const profile = this.profiles.get(did);
    if (!profile) return null;
    return {
      reviewer_did: did,
      reputation_score: profile.reputation_score,
      is_owner_verified: profile.is_owner_verified,
      owner_attestation_ref: profile.owner_attestation_ref,
    };
  }

  getAllReviewers(): ReviewerInfo[] {
    return Array.from(this.profiles.values()).map((profile) => ({
      reviewer_did: profile.did,
      reputation_score: profile.reputation_score,
      is_owner_verified: profile.is_owner_verified,
      owner_attestation_ref: profile.owner_attestation_ref,
    }));
  }
}
