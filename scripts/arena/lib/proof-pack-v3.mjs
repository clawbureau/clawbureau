import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';

function sha256b64u(input) {
  return createHash('sha256').update(input).digest('base64url');
}

function normalizeStringArray(values) {
  if (!Array.isArray(values)) return [];
  const out = [];
  const seen = new Set();
  for (const raw of values) {
    if (typeof raw !== 'string') continue;
    const value = raw.trim();
    if (!value || seen.has(value)) continue;
    seen.add(value);
    out.push(value);
  }
  out.sort((a, b) => a.localeCompare(b));
  return out;
}

function stableSortLinks(links) {
  if (!Array.isArray(links)) return [];
  const normalized = links
    .map((row) => ({
      label: typeof row?.label === 'string' ? row.label.trim() : '',
      url: typeof row?.url === 'string' ? row.url.trim() : '',
    }))
    .filter((row) => row.label && row.url);

  normalized.sort((a, b) => {
    const byLabel = a.label.localeCompare(b.label);
    if (byLabel !== 0) return byLabel;
    return a.url.localeCompare(b.url);
  });

  return normalized;
}

function normalizeComplianceChecks(rawChecks) {
  const checks = Array.isArray(rawChecks) ? rawChecks : [];
  const normalized = checks
    .map((check) => {
      const criterionId = typeof check?.criterion_id === 'string' ? check.criterion_id.trim() : '';
      if (!criterionId) return null;

      const required = check?.required === true;
      const passed = check?.passed === true;
      const status = passed ? 'PASS' : 'FAIL';
      const reasonCodeRaw = typeof check?.reason_code === 'string' ? check.reason_code.trim() : '';
      const reasonCode = reasonCodeRaw || (passed ? 'CHECK_OK' : 'CHECK_FAILED');
      const notes = typeof check?.notes === 'string' ? check.notes.trim() : '';

      return {
        criterion_id: criterionId,
        required,
        status,
        reason_code: reasonCode,
        ...(notes ? { notes } : {}),
      };
    })
    .filter(Boolean);

  normalized.sort((a, b) => a.criterion_id.localeCompare(b.criterion_id));
  return normalized;
}

function clampScore(value) {
  if (typeof value !== 'number' || !Number.isFinite(value)) return 0;
  if (value < 0) return 0;
  if (value > 100) return 100;
  return Number(value.toFixed(2));
}

function normalizeMetrics(metrics) {
  const source = metrics ?? {};

  const latencyMsRaw = Number(source.latency_ms);
  const latencyMs = Number.isFinite(latencyMsRaw) && latencyMsRaw > 0
    ? Math.round(latencyMsRaw)
    : 0;

  const costUsdRaw = Number(source.cost_usd);
  const costUsd = Number.isFinite(costUsdRaw) && costUsdRaw >= 0
    ? Number(costUsdRaw.toFixed(4))
    : 0;

  return {
    quality_score: clampScore(Number(source.quality_score)),
    risk_score: clampScore(Number(source.risk_score)),
    efficiency_score: clampScore(Number(source.efficiency_score)),
    latency_ms: latencyMs,
    cost_usd: costUsd,
    autonomy_score: clampScore(Number(source.autonomy_score)),
  };
}

function normalizeInsights(insights) {
  const source = insights ?? {};
  return {
    bottlenecks: normalizeStringArray(source.bottlenecks),
    contract_improvements: normalizeStringArray(source.contract_improvements),
    next_delegation_hints: normalizeStringArray(source.next_delegation_hints),
  };
}

export function buildProofPackV3(input) {
  const now = typeof input?.generated_at === 'string' && input.generated_at.trim()
    ? input.generated_at.trim()
    : new Date().toISOString();

  const claimBinding = {
    bounty_id: String(input?.claim_binding?.bounty_id ?? '').trim(),
    contract_id: String(input?.claim_binding?.contract_id ?? '').trim(),
    contract_hash_b64u: String(input?.claim_binding?.contract_hash_b64u ?? '').trim(),
    claim_hash_b64u: String(input?.claim_binding?.claim_hash_b64u ?? '').trim(),
    task_fingerprint: String(input?.claim_binding?.task_fingerprint ?? '').trim(),
    ...(typeof input?.claim_binding?.objective_profile === 'string' && input.claim_binding.objective_profile.trim()
      ? { objective_profile: input.claim_binding.objective_profile.trim() }
      : {}),
  };

  const promptText = typeof input?.contender?.prompt === 'string' ? input.contender.prompt : '';

  const contender = {
    contender_id: String(input?.contender?.contender_id ?? '').trim(),
    label: String(input?.contender?.label ?? '').trim(),
    config: {
      model: String(input?.contender?.model ?? '').trim(),
      harness: String(input?.contender?.harness ?? '').trim(),
      tools: normalizeStringArray(input?.contender?.tools),
      skills: normalizeStringArray(input?.contender?.skills),
      plugins: normalizeStringArray(input?.contender?.plugins),
      prompt_hash_b64u: sha256b64u(promptText),
    },
  };

  const checks = normalizeComplianceChecks(input?.compliance_checks);
  const mandatoryPassed = checks.filter((row) => row.required && row.status === 'PASS').length;
  const mandatoryFailed = checks.filter((row) => row.required && row.status === 'FAIL').length;

  const deliverySummary = typeof input?.delivery_summary === 'string'
    ? input.delivery_summary.trim()
    : '';

  const proofPack = {
    schema_version: 'proof_pack.v3',
    arena_id: String(input?.arena_id ?? '').trim(),
    generated_at: now,
    claim_binding: claimBinding,
    contender,
    compliance: {
      mandatory_passed: mandatoryPassed,
      mandatory_failed: mandatoryFailed,
      checks,
    },
    metrics: normalizeMetrics(input?.metrics),
    evidence: {
      delivery_summary: deliverySummary,
      delivery_hash_b64u: sha256b64u(deliverySummary),
      links: stableSortLinks(input?.evidence_links),
    },
    insights: normalizeInsights(input?.insights),
  };

  return proofPack;
}

export function buildReviewPaste(proofPack) {
  const complianceStatus = proofPack.compliance.mandatory_failed === 0 ? 'PASS' : 'FAIL';
  const decision = complianceStatus === 'PASS' && proofPack.metrics.risk_score < 70 ? 'Promote contender' : 'Manual review required';

  const lines = [
    `Decision Summary: ${decision}`,
    `Contract Compliance: ${complianceStatus} (${proofPack.compliance.mandatory_passed} mandatory passed, ${proofPack.compliance.mandatory_failed} mandatory failed)`,
    `Delivery/Risk: quality=${proofPack.metrics.quality_score.toFixed(2)}, risk=${proofPack.metrics.risk_score.toFixed(2)}, efficiency=${proofPack.metrics.efficiency_score.toFixed(2)}, cost=$${proofPack.metrics.cost_usd.toFixed(4)}, latency=${proofPack.metrics.latency_ms}ms`,
    `Evidence: ${proofPack.evidence.links.map((row) => `${row.label}: ${row.url}`).join(' | ') || 'none'}`,
    `Recommendation: ${proofPack.insights.next_delegation_hints[0] ?? 'No additional recommendation available.'}`,
  ];

  return lines.join('\n');
}

export function buildManagerReview(proofPack) {
  const failedChecks = proofPack.compliance.checks
    .filter((row) => row.status === 'FAIL')
    .map((row) => ({
      criterion_id: row.criterion_id,
      reason_code: row.reason_code,
      required: row.required,
    }));

  let decision = 'promote';
  if (proofPack.compliance.mandatory_failed > 0) decision = 'reject';
  else if (proofPack.metrics.risk_score >= 60 || failedChecks.length > 0) decision = 'conditional';

  const confidenceRaw = (
    (proofPack.metrics.quality_score * 0.35) +
    (proofPack.metrics.efficiency_score * 0.25) +
    ((100 - proofPack.metrics.risk_score) * 0.25) +
    (proofPack.metrics.autonomy_score * 0.15)
  ) / 100;

  const confidencePenalty = proofPack.compliance.mandatory_failed > 0
    ? 0.35
    : (failedChecks.length > 0 ? 0.15 : 0);

  const confidence = Math.max(0, Math.min(1, Number((confidenceRaw - confidencePenalty).toFixed(4))));

  const reasonCodes = [];
  if (proofPack.compliance.mandatory_failed > 0) reasonCodes.push('ARENA_MANDATORY_CHECK_FAILED');
  if (proofPack.metrics.risk_score >= 60) reasonCodes.push('ARENA_RISK_ABOVE_THRESHOLD');
  if (reasonCodes.length === 0) reasonCodes.push('ARENA_READY_TO_PROMOTE');

  const nextAction = decision === 'promote'
    ? 'Promote as default contender for this task fingerprint.'
    : decision === 'conditional'
      ? 'Run targeted retry with tightened contract language before promotion.'
      : 'Reject contender and request contract/evidence correction.';

  return {
    schema_version: 'manager_review.v1',
    arena_id: proofPack.arena_id,
    contender_id: proofPack.contender.contender_id,
    decision,
    confidence,
    reason_codes: reasonCodes,
    failed_checks: failedChecks,
    metrics: proofPack.metrics,
    recommended_next_action: nextAction,
  };
}

export function validateProofPackV3Shape(proofPack) {
  const errors = [];

  if (!proofPack || typeof proofPack !== 'object') {
    return { valid: false, errors: ['proof_pack must be an object'] };
  }

  if (proofPack.schema_version !== 'proof_pack.v3') {
    errors.push('schema_version must equal proof_pack.v3');
  }

  const requiredStringPaths = [
    ['arena_id'],
    ['claim_binding', 'bounty_id'],
    ['claim_binding', 'contract_id'],
    ['claim_binding', 'contract_hash_b64u'],
    ['claim_binding', 'claim_hash_b64u'],
    ['claim_binding', 'task_fingerprint'],
    ['contender', 'contender_id'],
    ['contender', 'label'],
    ['contender', 'config', 'model'],
    ['contender', 'config', 'harness'],
    ['contender', 'config', 'prompt_hash_b64u'],
    ['evidence', 'delivery_summary'],
    ['evidence', 'delivery_hash_b64u'],
  ];

  for (const pathParts of requiredStringPaths) {
    let cursor = proofPack;
    for (const segment of pathParts) {
      cursor = cursor?.[segment];
    }
    if (typeof cursor !== 'string' || cursor.trim().length === 0) {
      errors.push(`${pathParts.join('.')} must be a non-empty string`);
    }
  }

  if (!Array.isArray(proofPack?.compliance?.checks)) {
    errors.push('compliance.checks must be an array');
  }

  const scoreFields = ['quality_score', 'risk_score', 'efficiency_score', 'autonomy_score'];
  for (const scoreField of scoreFields) {
    const value = Number(proofPack?.metrics?.[scoreField]);
    if (!Number.isFinite(value) || value < 0 || value > 100) {
      errors.push(`metrics.${scoreField} must be a number between 0 and 100`);
    }
  }

  const latency = Number(proofPack?.metrics?.latency_ms);
  if (!Number.isFinite(latency) || latency < 0) {
    errors.push('metrics.latency_ms must be a non-negative number');
  }

  const cost = Number(proofPack?.metrics?.cost_usd);
  if (!Number.isFinite(cost) || cost < 0) {
    errors.push('metrics.cost_usd must be a non-negative number');
  }

  return { valid: errors.length === 0, errors };
}

function stableValue(value) {
  if (Array.isArray(value)) {
    return value.map((item) => stableValue(item));
  }
  if (value && typeof value === 'object') {
    const entries = Object.entries(value)
      .map(([key, item]) => [key, stableValue(item)])
      .sort((a, b) => a[0].localeCompare(b[0]));
    return Object.fromEntries(entries);
  }
  return value;
}

export function stableJson(value) {
  return JSON.stringify(stableValue(value), null, 2);
}

export function writeProofPackArtifacts(outputDir, proofPack) {
  const validation = validateProofPackV3Shape(proofPack);
  if (!validation.valid) {
    throw new Error(`Invalid proof pack v3: ${validation.errors.join('; ')}`);
  }

  mkdirSync(outputDir, { recursive: true });

  const reviewPaste = buildReviewPaste(proofPack);
  const managerReview = buildManagerReview(proofPack);

  writeFileSync(path.join(outputDir, 'proof-pack.v3.json'), `${stableJson(proofPack)}\n`);
  writeFileSync(path.join(outputDir, 'review-paste.md'), `${reviewPaste}\n`);
  writeFileSync(path.join(outputDir, 'manager-review.json'), `${stableJson(managerReview)}\n`);

  return {
    proof_pack_path: path.join(outputDir, 'proof-pack.v3.json'),
    review_paste_path: path.join(outputDir, 'review-paste.md'),
    manager_review_path: path.join(outputDir, 'manager-review.json'),
  };
}
