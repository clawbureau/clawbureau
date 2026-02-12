import { describe, expect, it } from 'vitest';
import {
  InMemoryRepEngine,
  computeClosureScoreDelta,
  computeConcaveValue,
  computePenaltyScoreDelta,
  deriveTier,
  selectReviewersDeterministic,
} from '../src/core';

describe('clawrep core scoring', () => {
  it('applies concave contribution (diminishing returns)', () => {
    const low = computeConcaveValue(100);
    const high = computeConcaveValue(10_000);

    const linearRatio = 10_000 / 100;
    const concaveRatio = high / low;

    expect(concaveRatio).toBeLessThan(linearRatio);
  });

  it('computes deterministic closure score deltas', () => {
    const first = computeClosureScoreDelta({
      value_usd: 120,
      closure_type: 'quorum_approve',
      proof_tier: 'gateway',
      owner_verified: true,
    });

    const second = computeClosureScoreDelta({
      value_usd: 120,
      closure_type: 'quorum_approve',
      proof_tier: 'gateway',
      owner_verified: true,
    });

    expect(first).toEqual(second);
    expect(first.score_delta).toBeGreaterThan(0);
  });

  it('computes deterministic dispute penalties', () => {
    const severityOne = computePenaltyScoreDelta('dispute_upheld_against_reviewer', 1);
    const severityThree = computePenaltyScoreDelta('dispute_upheld_against_reviewer', 3);

    expect(severityOne).toBeLessThan(0);
    expect(severityThree).toBeLessThan(severityOne);
    expect(severityThree).toBe(-24);
  });
});

describe('clawrep in-memory idempotency and decay', () => {
  it('keeps ingest idempotent by source_event_id', () => {
    const engine = new InMemoryRepEngine();
    const now = new Date().toISOString();

    const first = engine.ingestClosure({
      source_event_id: 'evt_rep_001',
      did: 'did:key:z6MkiRepA1111111111111111111111111111111',
      value_usd: 100,
      closure_type: 'quorum_approve',
      proof_tier: 'gateway',
      owner_verified: true,
      occurred_at: now,
    });
    engine.processPending();

    const second = engine.ingestClosure({
      source_event_id: 'evt_rep_001',
      did: 'did:key:z6MkiRepA1111111111111111111111111111111',
      value_usd: 999,
      closure_type: 'dispute_resolved',
      proof_tier: 'self',
      owner_verified: false,
      occurred_at: now,
    });
    engine.processPending();

    const profile = engine.getProfile('did:key:z6MkiRepA1111111111111111111111111111111');

    expect(first.duplicate).toBe(false);
    expect(second.duplicate).toBe(true);
    expect(profile?.events_count).toBe(1);
  });

  it('applies daily decay exactly once per run day', () => {
    const engine = new InMemoryRepEngine();
    const did = 'did:key:z6MkiRepDecay1111111111111111111111111111';
    const now = new Date().toISOString();

    engine.ingestClosure({
      source_event_id: 'evt_rep_decay_seed',
      did,
      value_usd: 400,
      closure_type: 'quorum_approve',
      proof_tier: 'sandbox',
      owner_verified: true,
      occurred_at: now,
    });
    engine.processPending();

    const before = engine.getProfile(did)!;
    const run1 = engine.runDailyDecay('2026-02-12', 0.02);
    const after1 = engine.getProfile(did)!;
    const run2 = engine.runDailyDecay('2026-02-12', 0.02);
    const after2 = engine.getProfile(did)!;

    expect(run1.already_applied).toBe(false);
    expect(run1.affected).toBeGreaterThan(0);
    expect(after1.reputation_score).toBeLessThan(before.reputation_score);

    expect(run2.already_applied).toBe(true);
    expect(after2.reputation_score).toBe(after1.reputation_score);
  });
});

describe('clawrep tiering and reviewer selection', () => {
  it('caps tier deterministically on high dispute rate', () => {
    const tier = deriveTier({
      reputation_score: 400,
      events_count: 10,
      dispute_penalties_count: 3,
    });

    expect(tier.tier).toBe(1);
    expect(tier.capped_by_dispute_rate).toBe(true);
  });

  it('selects reviewers deterministically for identical input', () => {
    const req = {
      bounty_id: 'bnty_123',
      difficulty_scalar: 2,
      quorum_size: 2,
      min_reputation_score: 10,
      require_owner_verified: false,
      exclude_dids: ['did:key:z6MkiExclude1111111111111111111111111111'],
      submission_proof_tier: 'gateway' as const,
    };

    const candidates = [
      {
        reviewer_did: 'did:key:z6MkiReviewerA1111111111111111111111111111',
        reputation_score: 44,
        is_owner_verified: true,
      },
      {
        reviewer_did: 'did:key:z6MkiReviewerB1111111111111111111111111111',
        reputation_score: 41,
        is_owner_verified: false,
      },
      {
        reviewer_did: 'did:key:z6MkiReviewerC1111111111111111111111111111',
        reputation_score: 39,
        is_owner_verified: true,
      },
      {
        reviewer_did: 'did:key:z6MkiExclude1111111111111111111111111111',
        reputation_score: 100,
        is_owner_verified: true,
      },
    ];

    const first = selectReviewersDeterministic(req, candidates);
    const second = selectReviewersDeterministic(req, candidates);

    expect(first).toEqual(second);
    expect(first).toHaveLength(2);
    expect(first.some((r) => r.reviewer_did.includes('Exclude'))).toBe(false);
  });
});
