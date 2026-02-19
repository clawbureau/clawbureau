import { describe, expect, it } from 'vitest';

import {
  validateArenaManagerReviewV1,
  validateArenaProofPackV3,
  validateArenaReportV1,
} from '../src/schema-validation';

const HASH_A = '9fUlg6xBkfyyjv4FIKR2Rjm3M2fW2Y8zW0y0kJ3Qn3A';
const HASH_B = '9fUlg6xBkfyyjv4FIKR2Rjm3M2fW2Y8zW0y0kJ3Qn3B';

function makeProofPackV3() {
  return {
    schema_version: 'proof_pack.v3',
    arena_id: 'arena_contract_001',
    generated_at: '2026-02-19T14:00:00.000Z',
    claim_binding: {
      bounty_id: 'bty_contract_001',
      contract_id: 'contract_001',
      contract_hash_b64u: HASH_A,
      claim_hash_b64u: HASH_B,
      task_fingerprint: 'typescript:api:bugfix',
      objective_profile: 'balanced',
    },
    contender: {
      contender_id: 'contender_alpha',
      label: 'Alpha contender',
      config: {
        model: 'gpt-5.2-codex',
        harness: 'pi',
        tools: ['bash', 'read'],
        skills: ['cloudflare'],
        plugins: ['did-work'],
        prompt_hash_b64u: HASH_A,
      },
    },
    compliance: {
      mandatory_passed: 2,
      mandatory_failed: 0,
      checks: [
        {
          criterion_id: 'ac_1',
          required: true,
          status: 'PASS',
          reason_code: 'CHECK_OK',
        },
      ],
    },
    metrics: {
      quality_score: 82,
      risk_score: 24,
      efficiency_score: 79,
      latency_ms: 9012,
      cost_usd: 0.42,
      autonomy_score: 76,
    },
    score_explain: {
      formula: {
        summary: 'final_score = quality*Wq + speed*Ws + cost*Wc + safety*Wsafe - optional_penalty',
        components: ['quality from ci', 'risk from retries', 'cost from usd'],
      },
      raw_inputs: {
        ci: {
          typecheck_passed: true,
          lint_passed: true,
          tests_passed: 45,
          tests_failed: 5,
          tests_total: 50,
        },
        git: {
          files_changed: 11,
          lines_added: 230,
          lines_deleted: 75,
          churn_hotspots: ['src/index.ts'],
        },
        execution: {
          latency_ms: 9012,
          tool_calls: 24,
          retries: 1,
          manual_interventions: 0,
        },
        cost: {
          usd: 0.42,
        },
      },
      weights: {
        objective: {
          quality: 0.35,
          speed: 0.25,
          cost: 0.2,
          safety: 0.2,
        },
      },
      derived: {
        quality_score: 82,
        risk_score: 24,
        efficiency_score: 79,
        autonomy_score: 76,
        speed_score: 92.49,
        cost_score: 91.6,
        safety_score: 76,
        weighted_pre_penalty: 85.454,
        optional_penalty: 0,
        final_score: 85.454,
      },
      reason_codes: ['ARENA_SCORE_EVIDENCE_GROUNDED'],
      evidence_links: [
        {
          label: 'CI',
          url: 'https://github.com/clawbureau/clawbureau/actions/runs/22186834424/job/64162890956',
          source: 'ci',
        },
        {
          label: 'Diff',
          url: 'https://github.com/clawbureau/clawbureau/pull/366/files',
          source: 'git',
        },
        {
          label: 'Trace',
          url: 'https://github.com/clawbureau/clawbureau/actions/runs/22186834313/job/64162891224',
          source: 'execution',
        },
      ],
    },
    evidence: {
      delivery_summary: 'Implements contract checks and test coverage.',
      delivery_hash_b64u: HASH_A,
      links: [
        {
          label: 'PR',
          url: 'https://github.com/clawbureau/clawbureau/pull/366',
        },
      ],
    },
    insights: {
      bottlenecks: ['integration test runtime'],
      contract_improvements: ['clarify failure budget threshold'],
      next_delegation_hints: ['reuse contender for API bugfix class'],
    },
  };
}

describe('arena schema validators', () => {
  it('accepts valid proof_pack.v3 payload', () => {
    const out = validateArenaProofPackV3(makeProofPackV3());
    expect(out.valid).toBe(true);
  });

  it('rejects proof_pack.v3 payload with invalid schema_version', () => {
    const payload = makeProofPackV3();
    payload.schema_version = 'proof_pack.v2';

    const out = validateArenaProofPackV3(payload);
    expect(out.valid).toBe(false);
    if (!out.valid) {
      expect(out.message).toContain('arena.proof_pack.v3');
    }
  });

  it('accepts valid manager_review.v1 payload', () => {
    const payload = {
      schema_version: 'manager_review.v1',
      arena_id: 'arena_contract_001',
      contender_id: 'contender_alpha',
      decision: 'promote',
      confidence: 0.88,
      reason_codes: ['ARENA_READY_TO_PROMOTE'],
      failed_checks: [],
      metrics: {
        quality_score: 82,
        risk_score: 24,
        efficiency_score: 79,
        latency_ms: 9012,
        cost_usd: 0.42,
        autonomy_score: 76,
      },
      recommended_next_action: 'Promote as default contender for this task fingerprint.',
    };

    const out = validateArenaManagerReviewV1(payload);
    expect(out.valid).toBe(true);
  });

  it('accepts valid arena_report.v1 payload', () => {
    const payload = {
      schema_version: 'arena_report.v1',
      arena_id: 'arena_contract_001',
      generated_at: '2026-02-19T14:05:00.000Z',
      contract: {
        bounty_id: 'bty_contract_001',
        contract_id: 'contract_001',
        contract_hash_b64u: HASH_A,
        task_fingerprint: 'typescript:api:bugfix',
      },
      objective_profile: {
        name: 'balanced',
        weights: {
          quality: 0.35,
          speed: 0.25,
          cost: 0.2,
          safety: 0.2,
        },
        tie_breakers: ['mandatory_pass_rate', 'quality_score'],
      },
      score_explain: {
        formula: {
          summary: 'final_score = quality*Wq + speed*Ws + cost*Wc + safety*Wsafe - optional_penalty',
          components: ['quality/risk/efficiency from CI+git+trace'],
        },
        weights: {
          quality: 0.35,
          speed: 0.25,
          cost: 0.2,
          safety: 0.2,
        },
        contender_breakdown: [
          {
            contender_id: 'contender_alpha',
            final_score: 84.44,
            reason_codes: ['ARENA_SCORE_EVIDENCE_GROUNDED'],
            evidence_links: [
              {
                label: 'CI',
                url: 'https://github.com/clawbureau/clawbureau/actions/runs/22186834424/job/64162890956',
                source: 'ci',
              },
            ],
          },
        ],
      },
      contenders: [
        {
          contender_id: 'contender_alpha',
          label: 'Alpha contender',
          hard_gate_pass: true,
          mandatory_failed: 0,
          score: 84.44,
          metrics: {
            quality_score: 82,
            risk_score: 24,
            efficiency_score: 79,
            latency_ms: 9012,
            cost_usd: 0.42,
            autonomy_score: 76,
          },
          score_explain: {
            formula: {
              summary: 'final_score = quality*Wq + speed*Ws + cost*Wc + safety*Wsafe - optional_penalty',
              components: ['quality from ci', 'risk from retries', 'cost from usd'],
            },
            raw_inputs: {
              ci: {
                typecheck_passed: true,
                lint_passed: true,
                tests_passed: 45,
                tests_failed: 5,
                tests_total: 50,
              },
              git: {
                files_changed: 11,
                lines_added: 230,
                lines_deleted: 75,
                churn_hotspots: ['src/index.ts'],
              },
              execution: {
                latency_ms: 9012,
                tool_calls: 24,
                retries: 1,
                manual_interventions: 0,
              },
              cost: {
                usd: 0.42,
              },
            },
            weights: {
              objective: {
                quality: 0.35,
                speed: 0.25,
                cost: 0.2,
                safety: 0.2,
              },
            },
            derived: {
              quality_score: 82,
              risk_score: 24,
              efficiency_score: 79,
              autonomy_score: 76,
              speed_score: 92.49,
              cost_score: 91.6,
              safety_score: 76,
              weighted_pre_penalty: 85.454,
              optional_penalty: 0,
              final_score: 85.454,
            },
            reason_codes: ['ARENA_SCORE_EVIDENCE_GROUNDED'],
            evidence_links: [
              {
                label: 'CI',
                url: 'https://github.com/clawbureau/clawbureau/actions/runs/22186834424/job/64162890956',
                source: 'ci',
              },
              {
                label: 'Diff',
                url: 'https://github.com/clawbureau/clawbureau/pull/366/files',
                source: 'git',
              },
              {
                label: 'Trace',
                url: 'https://github.com/clawbureau/clawbureau/actions/runs/22186834313/job/64162891224',
                source: 'execution',
              },
            ],
          },
          proof_pack_path: 'artifacts/arena/arena_contract_001/contenders/contender_alpha/proof-pack.v3.json',
          manager_review_path: 'artifacts/arena/arena_contract_001/contenders/contender_alpha/manager-review.json',
          review_paste_path: 'artifacts/arena/arena_contract_001/contenders/contender_alpha/review-paste.md',
        },
      ],
      rankings: [
        {
          rank: 1,
          contender_id: 'contender_alpha',
          score: 84.44,
          hard_gate_pass: true,
        },
      ],
      winner: {
        contender_id: 'contender_alpha',
        reason: 'Best weighted score with no mandatory check failures.',
      },
      tradeoffs: ['Slightly higher cost than low-latency contender.'],
      reason_codes: ['ARENA_WINNER_SELECTED'],
    };

    const out = validateArenaReportV1(payload);
    expect(out.valid).toBe(true);
  });
});
