import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import {
  buildProofPackV3,
  stableJson,
  writeProofPackArtifacts,
} from './proof-pack-v3.mjs';

function sha256b64u(input) {
  return createHash('sha256').update(input).digest('base64url');
}

function stableValue(value) {
  if (Array.isArray(value)) return value.map((item) => stableValue(item));
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value)
        .sort((a, b) => a[0].localeCompare(b[0]))
        .map(([key, item]) => [key, stableValue(item)])
    );
  }
  return value;
}

function stableHash(value) {
  return sha256b64u(JSON.stringify(stableValue(value)));
}

function clampScore(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return 0;
  if (n < 0) return 0;
  if (n > 100) return 100;
  return Number(n.toFixed(2));
}

function toNonNegativeInt(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) return null;
  return Math.round(n);
}

function toNonNegativeNumber(value, precision = 4) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) return null;
  return Number(n.toFixed(precision));
}

function normalizeStringArray(values) {
  const out = [];
  const seen = new Set();
  for (const raw of Array.isArray(values) ? values : []) {
    if (typeof raw !== 'string') continue;
    const value = raw.trim();
    if (!value || seen.has(value)) continue;
    seen.add(value);
    out.push(value);
  }
  out.sort((a, b) => a.localeCompare(b));
  return out;
}

function normalizeStringArrayInOrder(values) {
  const out = [];
  const seen = new Set();
  for (const raw of Array.isArray(values) ? values : []) {
    if (typeof raw !== 'string') continue;
    const value = raw.trim();
    if (!value || seen.has(value)) continue;
    seen.add(value);
    out.push(value);
  }
  return out;
}

function normalizeLinks(values) {
  const rows = [];
  const seen = new Set();

  for (const raw of Array.isArray(values) ? values : []) {
    if (!raw || typeof raw !== 'object') continue;

    const label = typeof raw.label === 'string' ? raw.label.trim() : '';
    const url = typeof raw.url === 'string' ? raw.url.trim() : '';
    const source = typeof raw.source === 'string' ? raw.source.trim() : '';

    if (!label || !url) continue;

    const key = `${label}::${url}::${source}`;
    if (seen.has(key)) continue;
    seen.add(key);

    rows.push(source ? { label, url, source } : { label, url });
  }

  rows.sort((a, b) => {
    const byLabel = a.label.localeCompare(b.label);
    if (byLabel !== 0) return byLabel;
    const byUrl = a.url.localeCompare(b.url);
    if (byUrl !== 0) return byUrl;
    return (a.source ?? '').localeCompare(b.source ?? '');
  });

  return rows;
}

function normalizeObjectiveProfile(input) {
  const profile = input ?? {};
  const name = typeof profile.name === 'string' && profile.name.trim() ? profile.name.trim() : 'balanced';

  const weightsRaw = profile.weights ?? {};
  const weights = {
    quality: Number.isFinite(Number(weightsRaw.quality)) ? Number(weightsRaw.quality) : 0.35,
    speed: Number.isFinite(Number(weightsRaw.speed)) ? Number(weightsRaw.speed) : 0.25,
    cost: Number.isFinite(Number(weightsRaw.cost)) ? Number(weightsRaw.cost) : 0.2,
    safety: Number.isFinite(Number(weightsRaw.safety)) ? Number(weightsRaw.safety) : 0.2,
  };

  const weightTotal = weights.quality + weights.speed + weights.cost + weights.safety;
  const normalizedWeights = weightTotal > 0
    ? {
      quality: Number((weights.quality / weightTotal).toFixed(4)),
      speed: Number((weights.speed / weightTotal).toFixed(4)),
      cost: Number((weights.cost / weightTotal).toFixed(4)),
      safety: Number((weights.safety / weightTotal).toFixed(4)),
    }
    : { quality: 0.35, speed: 0.25, cost: 0.2, safety: 0.2 };

  const tieBreakers = normalizeStringArrayInOrder(profile.tie_breakers);

  return {
    name,
    weights: normalizedWeights,
    tie_breakers: tieBreakers.length > 0
      ? tieBreakers
      : ['mandatory_passed', 'quality_score', 'risk_score_low', 'cost_low', 'latency_low', 'contender_id'],
  };
}

function evaluateCriterion(criterion, contender) {
  const id = typeof criterion?.id === 'string' ? criterion.id.trim() : '';
  const required = criterion?.required !== false;
  const description = typeof criterion?.description === 'string' ? criterion.description.trim() : '';

  if (!id) {
    return {
      criterion_id: 'unknown_criterion',
      required,
      passed: false,
      reason_code: 'ARENA_CONTRACT_INVALID_CRITERION',
      notes: 'criterion.id missing',
    };
  }

  const rule = criterion?.rule ?? {};
  const field = typeof rule.field === 'string' ? rule.field.trim() : 'delivery_summary';
  const fieldValue = typeof contender?.[field] === 'string' ? contender[field] : '';
  const type = typeof rule.type === 'string' ? rule.type.trim() : 'contains';

  if (type === 'contains') {
    const needle = typeof rule.needle === 'string' ? rule.needle.trim() : '';
    const passed = needle.length > 0 && fieldValue.toLowerCase().includes(needle.toLowerCase());
    return {
      criterion_id: id,
      required,
      passed,
      reason_code: passed
        ? 'CHECK_OK'
        : (required ? 'ARENA_ACCEPTANCE_CRITERION_FAILED' : 'ARENA_OPTIONAL_CRITERION_MISS'),
      notes: description || `Expected field ${field} to contain "${needle}"`,
    };
  }

  if (type === 'regex') {
    const pattern = typeof rule.pattern === 'string' ? rule.pattern : '';
    let passed = false;

    try {
      const re = new RegExp(pattern, 'i');
      passed = re.test(fieldValue);
    } catch {
      return {
        criterion_id: id,
        required,
        passed: false,
        reason_code: 'ARENA_CONTRACT_INVALID_REGEX',
        notes: description || 'Invalid regex rule in contract',
      };
    }

    return {
      criterion_id: id,
      required,
      passed,
      reason_code: passed
        ? 'CHECK_OK'
        : (required ? 'ARENA_ACCEPTANCE_CRITERION_FAILED' : 'ARENA_OPTIONAL_CRITERION_MISS'),
      notes: description || `Expected field ${field} to match /${pattern}/i`,
    };
  }

  return {
    criterion_id: id,
    required,
    passed: false,
    reason_code: 'ARENA_CONTRACT_INVALID_RULE_TYPE',
    notes: description || `Unsupported rule type: ${type}`,
  };
}

function requireObject(value, pathLabel) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`Missing required evidence object: ${pathLabel}`);
  }
  return value;
}

function requireBoolean(value, pathLabel) {
  if (typeof value !== 'boolean') {
    throw new Error(`Missing required boolean evidence field: ${pathLabel}`);
  }
  return value;
}

function requireNonNegativeInt(value, pathLabel) {
  const n = toNonNegativeInt(value);
  if (n === null) {
    throw new Error(`Missing required non-negative integer evidence field: ${pathLabel}`);
  }
  return n;
}

function requireNonNegativeNumber(value, pathLabel, precision = 4) {
  const n = toNonNegativeNumber(value, precision);
  if (n === null) {
    throw new Error(`Missing required non-negative numeric evidence field: ${pathLabel}`);
  }
  return n;
}

function requireLink(value, pathLabel, source) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`Missing required evidence link object: ${pathLabel}`);
  }

  const label = typeof value.label === 'string' ? value.label.trim() : '';
  const url = typeof value.url === 'string' ? value.url.trim() : '';

  if (!label || !url) {
    throw new Error(`Missing required evidence link fields (label/url): ${pathLabel}`);
  }

  return { label, url, source };
}

function extractEvidenceSignals(contenderInput) {
  const evidence = requireObject(contenderInput?.evidence_signals, 'evidence_signals');
  const ci = requireObject(evidence.ci, 'evidence_signals.ci');
  const git = requireObject(evidence.git, 'evidence_signals.git');
  const execution = requireObject(evidence.execution, 'evidence_signals.execution');
  const cost = requireObject(evidence.cost, 'evidence_signals.cost');

  const ciArtifacts = normalizeLinks(ci.artifacts);
  if (ciArtifacts.length === 0) {
    throw new Error('Missing required evidence links: evidence_signals.ci.artifacts');
  }

  const diffLink = requireLink(git.diff_artifact, 'evidence_signals.git.diff_artifact', 'git');
  const traceLink = requireLink(execution.trace_artifact, 'evidence_signals.execution.trace_artifact', 'execution');
  const costLink = requireLink(cost.cost_artifact, 'evidence_signals.cost.cost_artifact', 'cost');

  const normalized = {
    ci: {
      typecheck_passed: requireBoolean(ci.typecheck_passed, 'evidence_signals.ci.typecheck_passed'),
      lint_passed: requireBoolean(ci.lint_passed, 'evidence_signals.ci.lint_passed'),
      tests_passed: requireNonNegativeInt(ci.tests_passed, 'evidence_signals.ci.tests_passed'),
      tests_failed: requireNonNegativeInt(ci.tests_failed, 'evidence_signals.ci.tests_failed'),
      artifacts: ciArtifacts.map((row) => ({ ...row, source: 'ci' })),
    },
    git: {
      files_changed: requireNonNegativeInt(git.files_changed, 'evidence_signals.git.files_changed'),
      lines_added: requireNonNegativeInt(git.lines_added, 'evidence_signals.git.lines_added'),
      lines_deleted: requireNonNegativeInt(git.lines_deleted, 'evidence_signals.git.lines_deleted'),
      churn_hotspots: normalizeStringArray(git.churn_hotspots),
      diff_artifact: diffLink,
    },
    execution: {
      latency_ms: requireNonNegativeInt(execution.latency_ms, 'evidence_signals.execution.latency_ms'),
      tool_calls: requireNonNegativeInt(execution.tool_calls, 'evidence_signals.execution.tool_calls'),
      retries: requireNonNegativeInt(execution.retries, 'evidence_signals.execution.retries'),
      manual_interventions: requireNonNegativeInt(execution.manual_interventions ?? 0, 'evidence_signals.execution.manual_interventions'),
      trace_artifact: traceLink,
    },
    cost: {
      usd: requireNonNegativeNumber(cost.usd, 'evidence_signals.cost.usd', 4),
      cost_artifact: costLink,
    },
  };

  return normalized;
}

function deriveMetricsFromEvidence(evidence) {
  const testTotal = evidence.ci.tests_passed + evidence.ci.tests_failed;
  const testPassRate = testTotal > 0 ? evidence.ci.tests_passed / testTotal : 0;

  let qualityScore = 100 * testPassRate;
  if (!evidence.ci.typecheck_passed) qualityScore -= 22;
  if (!evidence.ci.lint_passed) qualityScore -= 12;
  qualityScore -= Math.min(8, evidence.execution.manual_interventions * 4);

  const churnMagnitude = evidence.git.lines_added + evidence.git.lines_deleted;
  const churnPerFile = churnMagnitude / Math.max(1, evidence.git.files_changed);

  let riskScore = 8;
  if (!evidence.ci.typecheck_passed) riskScore += 35;
  if (!evidence.ci.lint_passed) riskScore += 16;
  riskScore += Math.min(18, evidence.execution.retries * 4.5);
  riskScore += Math.min(14, evidence.execution.manual_interventions * 6);
  riskScore += Math.min(18, (churnPerFile / 450) * 18);
  riskScore += Math.min(10, evidence.git.churn_hotspots.length * 2);

  let efficiencyScore = 100;
  efficiencyScore -= Math.min(24, evidence.execution.retries * 6.5);
  efficiencyScore -= Math.min(16, (evidence.execution.tool_calls / 40) * 16);
  efficiencyScore -= Math.min(24, (evidence.execution.latency_ms / 120000) * 24);
  efficiencyScore -= Math.min(16, (evidence.git.files_changed / 80) * 16);
  efficiencyScore -= Math.min(14, evidence.execution.manual_interventions * 6.5);

  let autonomyScore = 100;
  autonomyScore -= Math.min(34, evidence.execution.manual_interventions * 15);
  autonomyScore -= Math.min(26, evidence.execution.retries * 5.5);
  if (!evidence.ci.typecheck_passed || !evidence.ci.lint_passed) autonomyScore -= 10;

  return {
    quality_score: clampScore(qualityScore),
    risk_score: clampScore(riskScore),
    efficiency_score: clampScore(efficiencyScore),
    latency_ms: evidence.execution.latency_ms,
    cost_usd: Number(evidence.cost.usd.toFixed(4)),
    autonomy_score: clampScore(autonomyScore),
  };
}

function derivedSpeedScore(metrics) {
  const latencyCapMs = 120000;
  const normalized = 100 - Math.min(100, (metrics.latency_ms / latencyCapMs) * 100);
  return Number(normalized.toFixed(2));
}

function derivedCostScore(metrics) {
  const costCapUsd = 5;
  const normalized = 100 - Math.min(100, (metrics.cost_usd / costCapUsd) * 100);
  return Number(normalized.toFixed(2));
}

function derivedSafetyScore(metrics) {
  return Number((100 - metrics.risk_score).toFixed(2));
}

function buildScoreReasonCodes({ evidence, metrics, mandatoryFailed, optionalFailed }) {
  const reasonCodes = ['ARENA_SCORE_EVIDENCE_GROUNDED'];

  if (!evidence.ci.typecheck_passed) reasonCodes.push('ARENA_EVIDENCE_TYPECHECK_FAILED');
  if (!evidence.ci.lint_passed) reasonCodes.push('ARENA_EVIDENCE_LINT_FAILED');
  if (evidence.execution.retries > 2) reasonCodes.push('ARENA_EVIDENCE_RETRY_HEAVY');
  if (evidence.execution.manual_interventions > 0) reasonCodes.push('ARENA_EVIDENCE_MANUAL_INTERVENTION');

  const churnMagnitude = evidence.git.lines_added + evidence.git.lines_deleted;
  if (churnMagnitude > 1500) reasonCodes.push('ARENA_EVIDENCE_HIGH_CHURN');
  if (metrics.latency_ms > 60000) reasonCodes.push('ARENA_EVIDENCE_HIGH_LATENCY');
  if (metrics.cost_usd > 1.5) reasonCodes.push('ARENA_EVIDENCE_HIGH_COST');

  if (mandatoryFailed > 0) reasonCodes.push('ARENA_MANDATORY_CHECK_FAILED');
  if (optionalFailed > 0) reasonCodes.push('ARENA_OPTIONAL_CHECK_FAILED');

  return reasonCodes;
}

function computeScoreExplain({ evidence, metrics, objective, optionalFailures, mandatoryFailed }) {
  const speedScore = derivedSpeedScore(metrics);
  const costScore = derivedCostScore(metrics);
  const safetyScore = derivedSafetyScore(metrics);

  const weightedPrePenalty =
    (metrics.quality_score * objective.weights.quality) +
    (speedScore * objective.weights.speed) +
    (costScore * objective.weights.cost) +
    (safetyScore * objective.weights.safety);

  const optionalPenalty = optionalFailures > 0 ? optionalFailures * 1.5 : 0;
  const finalScore = Number(Math.max(0, weightedPrePenalty - optionalPenalty).toFixed(4));

  const reasonCodes = buildScoreReasonCodes({
    evidence,
    metrics,
    mandatoryFailed,
    optionalFailed: optionalFailures,
  });

  const evidenceLinks = normalizeLinks([
    ...evidence.ci.artifacts,
    evidence.git.diff_artifact,
    evidence.execution.trace_artifact,
    evidence.cost.cost_artifact,
  ]);

  return {
    score: finalScore,
    score_explain: {
      formula: {
        summary: 'final_score = quality*Wq + speed*Ws + cost*Wc + safety*Wsafe - optional_penalty',
        components: [
          'quality = f(ci.typecheck, ci.lint, test pass rate, manual interventions)',
          'risk = f(ci failures, retries, manual interventions, git churn)',
          'efficiency = f(retries, tool_calls, latency, files_changed)',
          'speed = 100 - min(100, latency_ms/120000*100)',
          'cost = 100 - min(100, cost_usd/5*100)',
          'safety = 100 - risk_score',
          'optional_penalty = optional_failed * 1.5',
        ],
      },
      raw_inputs: {
        ci: {
          typecheck_passed: evidence.ci.typecheck_passed,
          lint_passed: evidence.ci.lint_passed,
          tests_passed: evidence.ci.tests_passed,
          tests_failed: evidence.ci.tests_failed,
          tests_total: evidence.ci.tests_passed + evidence.ci.tests_failed,
        },
        git: {
          files_changed: evidence.git.files_changed,
          lines_added: evidence.git.lines_added,
          lines_deleted: evidence.git.lines_deleted,
          churn_hotspots: evidence.git.churn_hotspots,
        },
        execution: {
          latency_ms: evidence.execution.latency_ms,
          tool_calls: evidence.execution.tool_calls,
          retries: evidence.execution.retries,
          manual_interventions: evidence.execution.manual_interventions,
        },
        cost: {
          usd: evidence.cost.usd,
        },
      },
      weights: {
        objective: objective.weights,
      },
      derived: {
        quality_score: metrics.quality_score,
        risk_score: metrics.risk_score,
        efficiency_score: metrics.efficiency_score,
        autonomy_score: metrics.autonomy_score,
        speed_score: speedScore,
        cost_score: costScore,
        safety_score: safetyScore,
        weighted_pre_penalty: Number(weightedPrePenalty.toFixed(4)),
        optional_penalty: Number(optionalPenalty.toFixed(4)),
        final_score: finalScore,
      },
      reason_codes: reasonCodes,
      evidence_links: evidenceLinks,
    },
  };
}

function compareWithTieBreakers(a, b, objective) {
  if (a.hard_gate_pass !== b.hard_gate_pass) {
    return a.hard_gate_pass ? -1 : 1;
  }

  if (a.score !== b.score) {
    return b.score - a.score;
  }

  for (const tieBreaker of objective.tie_breakers) {
    if (tieBreaker === 'mandatory_passed') {
      if (a.mandatory_passed !== b.mandatory_passed) {
        return b.mandatory_passed - a.mandatory_passed;
      }
      continue;
    }
    if (tieBreaker === 'quality_score') {
      if (a.metrics.quality_score !== b.metrics.quality_score) {
        return b.metrics.quality_score - a.metrics.quality_score;
      }
      continue;
    }
    if (tieBreaker === 'risk_score_low') {
      if (a.metrics.risk_score !== b.metrics.risk_score) {
        return a.metrics.risk_score - b.metrics.risk_score;
      }
      continue;
    }
    if (tieBreaker === 'cost_low') {
      if (a.metrics.cost_usd !== b.metrics.cost_usd) {
        return a.metrics.cost_usd - b.metrics.cost_usd;
      }
      continue;
    }
    if (tieBreaker === 'latency_low') {
      if (a.metrics.latency_ms !== b.metrics.latency_ms) {
        return a.metrics.latency_ms - b.metrics.latency_ms;
      }
      continue;
    }
    if (tieBreaker === 'contender_id') {
      const byId = a.contender_id.localeCompare(b.contender_id);
      if (byId !== 0) return byId;
      continue;
    }
  }

  return a.contender_id.localeCompare(b.contender_id);
}

function tradeoffSummary(sortedContenders, winner) {
  const lines = [];
  const runnerUp = sortedContenders[1];

  if (!runnerUp) {
    return ['Single contender in arena; no direct tradeoff comparison available.'];
  }

  if (winner.metrics.cost_usd > runnerUp.metrics.cost_usd) {
    lines.push(`${winner.contender_id} wins quality/safety but costs more than ${runnerUp.contender_id}.`);
  }

  if (winner.metrics.latency_ms > runnerUp.metrics.latency_ms) {
    lines.push(`${winner.contender_id} trades latency for stronger compliance confidence.`);
  }

  if (winner.metrics.risk_score > runnerUp.metrics.risk_score) {
    lines.push(`${winner.contender_id} has higher risk score than ${runnerUp.contender_id}; monitor in staged rollout.`);
  }

  if (lines.length === 0) {
    lines.push(`${winner.contender_id} dominates runner-up ${runnerUp.contender_id} on score and tie-breakers.`);
  }

  return lines;
}

function renderArenaReportMarkdown(report) {
  const rows = report.rankings
    .map((row) => `| ${row.rank} | ${row.contender_id} | ${row.hard_gate_pass ? 'PASS' : 'FAIL'} | ${row.score.toFixed(4)} |`)
    .join('\n');

  return [
    '# Bounty Arena Report',
    '',
    `- arena_id: ${report.arena_id}`,
    `- bounty_id: ${report.contract.bounty_id}`,
    `- contract_id: ${report.contract.contract_id}`,
    `- objective_profile: ${report.objective_profile.name}`,
    `- winner: ${report.winner.contender_id}`,
    '',
    '## Winner rationale',
    '',
    report.winner.reason,
    '',
    '## Rankings',
    '',
    '| Rank | Contender | Hard Gate | Score |',
    '| --- | --- | --- | ---: |',
    rows,
    '',
    '## Tradeoffs',
    '',
    ...report.tradeoffs.map((line) => `- ${line}`),
    '',
    '## Reason codes',
    '',
    ...report.reason_codes.map((code) => `- ${code}`),
  ].join('\n');
}

function buildReportScoreExplain(sortedContenders, objective) {
  return {
    formula: {
      summary: 'final_score = quality*Wq + speed*Ws + cost*Wc + safety*Wsafe - optional_penalty',
      components: [
        'quality/risk/efficiency are derived from CI + git + execution traces',
        'speed is normalized from latency_ms',
        'cost is normalized from cost_usd',
        'safety is normalized from risk_score',
      ],
    },
    weights: objective.weights,
    contender_breakdown: sortedContenders.map((contender) => ({
      contender_id: contender.contender_id,
      final_score: contender.score,
      reason_codes: contender.score_explain.reason_codes,
      evidence_links: contender.score_explain.evidence_links,
    })),
  };
}

export function runArena({ contract, contenders, outputDir, generatedAt, arenaIdOverride }) {
  if (!Array.isArray(contenders) || contenders.length < 3) {
    throw new Error('Arena runner requires at least 3 contenders');
  }

  const objective = normalizeObjectiveProfile(contract.objective_profile);
  const generated_at = generatedAt || new Date().toISOString();

  const contractCanonical = {
    bounty_id: String(contract.bounty_id ?? '').trim(),
    contract_id: String(contract.contract_id ?? '').trim(),
    task_fingerprint: String(contract.task_fingerprint ?? '').trim(),
    acceptance_criteria: Array.isArray(contract.acceptance_criteria) ? contract.acceptance_criteria : [],
  };

  if (!contractCanonical.bounty_id || !contractCanonical.contract_id || !contractCanonical.task_fingerprint) {
    throw new Error('contract must include bounty_id, contract_id, and task_fingerprint');
  }

  const contract_hash_b64u = stableHash(contractCanonical);
  const arena_id = arenaIdOverride || `arena_${contract_hash_b64u.slice(0, 16)}`;

  const contenderResults = [];

  for (const contenderInput of contenders) {
    const contender_id = String(contenderInput?.contender_id ?? '').trim();
    if (!contender_id) {
      throw new Error('contender_id is required for every contender');
    }

    const complianceChecks = contractCanonical.acceptance_criteria.map((criterion) =>
      evaluateCriterion(criterion, contenderInput)
    );

    const mandatory_failed = complianceChecks.filter((row) => row.required && !row.passed).length;
    const mandatory_passed = complianceChecks.filter((row) => row.required && row.passed).length;
    const optional_failed = complianceChecks.filter((row) => !row.required && !row.passed).length;

    const evidenceSignals = extractEvidenceSignals(contenderInput);
    const metrics = deriveMetricsFromEvidence(evidenceSignals);
    const { score, score_explain } = computeScoreExplain({
      evidence: evidenceSignals,
      metrics,
      objective,
      optionalFailures: optional_failed,
      mandatoryFailed: mandatory_failed,
    });

    const hard_gate_pass = mandatory_failed === 0 && metrics.risk_score < 95;

    const claim_hash_b64u = sha256b64u(`${contract_hash_b64u}:${contender_id}:${contenderInput.delivery_summary ?? ''}`);

    const explicitEvidenceLinks = Array.isArray(contenderInput?.evidence_links)
      ? contenderInput.evidence_links
      : [];

    const proofPack = buildProofPackV3({
      arena_id,
      generated_at,
      claim_binding: {
        bounty_id: contractCanonical.bounty_id,
        contract_id: contractCanonical.contract_id,
        contract_hash_b64u,
        claim_hash_b64u,
        task_fingerprint: contractCanonical.task_fingerprint,
        objective_profile: objective.name,
      },
      contender: {
        contender_id,
        label: String(contenderInput?.label ?? contender_id).trim(),
        model: String(contenderInput?.model ?? 'unknown-model').trim(),
        harness: String(contenderInput?.harness ?? 'unknown-harness').trim(),
        tools: normalizeStringArray(contenderInput?.tools),
        skills: normalizeStringArray(contenderInput?.skills),
        plugins: normalizeStringArray(contenderInput?.plugins),
        prompt: typeof contenderInput?.prompt === 'string' ? contenderInput.prompt : '',
      },
      compliance_checks: complianceChecks,
      metrics,
      score_explain,
      delivery_summary: String(contenderInput?.delivery_summary ?? '').trim(),
      evidence_links: normalizeLinks([...explicitEvidenceLinks, ...score_explain.evidence_links]),
      insights: {
        bottlenecks: Array.isArray(contenderInput?.bottlenecks) ? contenderInput.bottlenecks : [],
        contract_improvements: Array.isArray(contenderInput?.contract_improvements) ? contenderInput.contract_improvements : [],
        next_delegation_hints: Array.isArray(contenderInput?.next_delegation_hints) ? contenderInput.next_delegation_hints : [],
      },
    });

    const contenderDir = path.join(outputDir, 'contenders', contender_id);
    const artifactPaths = writeProofPackArtifacts(contenderDir, proofPack);

    contenderResults.push({
      contender_id,
      label: proofPack.contender.label,
      hard_gate_pass,
      mandatory_failed,
      mandatory_passed,
      optional_failed,
      score,
      metrics,
      score_explain,
      proof_pack_path: artifactPaths.proof_pack_path,
      manager_review_path: artifactPaths.manager_review_path,
      review_paste_path: artifactPaths.review_paste_path,
    });
  }

  const sorted = [...contenderResults].sort((a, b) => compareWithTieBreakers(a, b, objective));

  const winner = sorted.find((row) => row.hard_gate_pass) ?? sorted[0];
  const winnerReason = winner.hard_gate_pass
    ? `Winner ${winner.contender_id} passed all mandatory checks and achieved top weighted score (${winner.score.toFixed(4)}).`
    : `No contender passed hard gates; ${winner.contender_id} selected as best fallback with deterministic tie-breakers.`;

  const reason_codes = winner.hard_gate_pass
    ? ['ARENA_WINNER_SELECTED', 'ARENA_HARD_GATES_PASSED']
    : ['ARENA_NO_HARD_GATE_PASS', 'ARENA_FALLBACK_SELECTION'];

  const rankings = sorted.map((row, index) => ({
    rank: index + 1,
    contender_id: row.contender_id,
    score: row.score,
    hard_gate_pass: row.hard_gate_pass,
  }));

  const report = {
    schema_version: 'arena_report.v1',
    arena_id,
    generated_at,
    contract: {
      bounty_id: contractCanonical.bounty_id,
      contract_id: contractCanonical.contract_id,
      contract_hash_b64u,
      task_fingerprint: contractCanonical.task_fingerprint,
    },
    objective_profile: objective,
    score_explain: buildReportScoreExplain(sorted, objective),
    contenders: sorted.map((row) => ({
      contender_id: row.contender_id,
      label: row.label,
      hard_gate_pass: row.hard_gate_pass,
      mandatory_failed: row.mandatory_failed,
      score: row.score,
      metrics: row.metrics,
      score_explain: row.score_explain,
      proof_pack_path: row.proof_pack_path,
      manager_review_path: row.manager_review_path,
      review_paste_path: row.review_paste_path,
    })),
    rankings,
    winner: {
      contender_id: winner.contender_id,
      reason: winnerReason,
    },
    tradeoffs: tradeoffSummary(sorted, winner),
    reason_codes,
  };

  mkdirSync(outputDir, { recursive: true });
  writeFileSync(path.join(outputDir, 'arena-report.json'), `${stableJson(report)}\n`);
  writeFileSync(path.join(outputDir, 'arena-report.md'), `${renderArenaReportMarkdown(report)}\n`);

  return report;
}
