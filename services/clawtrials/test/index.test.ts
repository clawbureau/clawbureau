import { describe, expect, it } from 'vitest';
import { __internals } from '../src/index';

describe('clawtrials internals', () => {
  it('parses judge pool deterministically', () => {
    const judges = __internals.parseJudgePool('did:key:zJudgeA, did:key:zJudgeB, did:key:zJudgeA');
    expect(judges).toEqual(['did:key:zJudgeA', 'did:key:zJudgeB']);
  });

  it('cursor encoding roundtrips', () => {
    const openedAt = '2026-02-12T00:00:00.000Z';
    const caseId = 'trc_123e4567-e89b-12d3-a456-426614174000';
    const encoded = __internals.encodeCursor(openedAt, caseId);
    const decoded = __internals.decodeCursor(encoded);

    expect(decoded).toEqual({
      opened_at: openedAt,
      case_id: caseId,
    });
  });

  it('invalid cursor returns null', () => {
    expect(__internals.decodeCursor('bad-cursor')).toBeNull();
  });

  it('normalizes evidence and enforces required refs', () => {
    const evidence = __internals.normalizeEvidence({
      proof_bundle_hash_b64u: 'hash_abc',
      receipt_refs: ['receipt:1'],
      artifact_refs: ['artifact:1'],
    });

    expect(evidence).toEqual({
      proof_bundle_hash_b64u: 'hash_abc',
      receipt_refs: ['receipt:1'],
      artifact_refs: ['artifact:1'],
    });

    expect(() =>
      __internals.normalizeEvidence({
        proof_bundle_hash_b64u: 'hash_abc',
        receipt_refs: [],
        artifact_refs: ['artifact:1'],
      })
    ).toThrowError(/receipt_refs/);
  });

  it('deterministic judge index is stable for same seed', async () => {
    const first = await __internals.deterministicJudgeIndex('seed:abc', 5);
    const second = await __internals.deterministicJudgeIndex('seed:abc', 5);

    expect(first.index).toBe(second.index);
    expect(first.hash_b64u).toBe(second.hash_b64u);
  });

  it('parses decision outcomes strictly', () => {
    expect(__internals.parseDecisionOutcome('worker_award')).toBe('worker_award');
    expect(__internals.parseDecisionOutcome('requester_refund')).toBe('requester_refund');
    expect(__internals.parseDecisionOutcome('other')).toBeNull();
  });
});
