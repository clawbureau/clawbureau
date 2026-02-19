import path from 'node:path';

export function mapManagerDecisionToRecommendation(decision) {
  const normalized = String(decision ?? '').trim().toLowerCase();
  if (normalized === 'promote') return 'APPROVE';
  if (normalized === 'conditional' || normalized === 'iterate') return 'REQUEST_CHANGES';
  return 'REJECT';
}

function urlJoin(base, suffix) {
  const trimmedBase = String(base ?? '').trim().replace(/\/$/, '');
  const trimmedSuffix = String(suffix ?? '').trim().replace(/^\//, '');
  if (!trimmedBase) return '';
  return `${trimmedBase}/${trimmedSuffix}`;
}

function toArtifactLink(filePath, artifactsBaseUrl) {
  if (!artifactsBaseUrl) {
    return filePath;
  }

  const rel = path.relative(process.cwd(), filePath).replace(/\\/g, '/');
  return urlJoin(artifactsBaseUrl, rel);
}

function buildArenaLink(arenaBaseUrl, arenaId, contenderId, anchor = '') {
  if (!arenaBaseUrl) return '';
  const root = String(arenaBaseUrl).trim().replace(/\/$/, '');

  if (root.includes('/arena/')) {
    const base = root.replace(/\/$/, '');
    const contenderQuery = contenderId ? `?contender=${encodeURIComponent(contenderId)}` : '';
    return `${base}${contenderQuery}${anchor}`;
  }

  const contenderQuery = contenderId ? `?contender=${encodeURIComponent(contenderId)}` : '';
  return `${root}/arena/${encodeURIComponent(arenaId)}${contenderQuery}${anchor}`;
}

export function buildDecisionPastePayload({
  arenaReport,
  contender,
  managerReview,
  reviewPaste,
  arenaBaseUrl,
  artifactsBaseUrl,
}) {
  const recommendation = mapManagerDecisionToRecommendation(managerReview.decision);
  const confidence = Number(managerReview.confidence ?? 0);
  const confidencePct = Number.isFinite(confidence) ? `${(confidence * 100).toFixed(1)}%` : '0.0%';

  const arenaId = String(arenaReport.arena_id);
  const contenderId = String(contender.contender_id);

  const arenaComparisonLink = buildArenaLink(arenaBaseUrl, arenaId, null);
  const proofCardLink = buildArenaLink(arenaBaseUrl, arenaId, contenderId, '#proof-card');
  const managerReviewLink = toArtifactLink(contender.manager_review_path, artifactsBaseUrl);

  const links = [
    { label: 'Proof card', url: proofCardLink || managerReviewLink },
    { label: 'Arena comparison', url: arenaComparisonLink || managerReviewLink },
    { label: 'Manager review JSON', url: managerReviewLink },
  ].filter((entry) => Boolean(entry.url));

  const reasonCodes = Array.isArray(managerReview.reason_codes)
    ? managerReview.reason_codes.filter((item) => typeof item === 'string' && item.trim().length > 0)
    : [];

  const nextAction = typeof managerReview.recommended_next_action === 'string'
    ? managerReview.recommended_next_action.trim()
    : '';

  const managerDecision = typeof managerReview.decision === 'string'
    ? managerReview.decision.trim()
    : '';

  const metrics = managerReview && typeof managerReview.metrics === 'object' && managerReview.metrics !== null
    ? managerReview.metrics
    : null;

  const failedChecks = Array.isArray(managerReview.failed_checks)
    ? managerReview.failed_checks
      .filter((item) => item && typeof item === 'object')
      .map((item) => ({
        criterion_id: typeof item.criterion_id === 'string' ? item.criterion_id.trim() : '',
        reason_code: typeof item.reason_code === 'string' ? item.reason_code.trim() : '',
      }))
      .filter((item) => item.criterion_id && item.reason_code)
    : [];

  const evidenceLinks = Array.isArray(contender?.score_explain?.evidence_links)
    ? contender.score_explain.evidence_links
      .filter((item) => item && typeof item === 'object')
      .map((item) => ({
        label: typeof item.label === 'string' ? item.label.trim() : '',
        url: typeof item.url === 'string' ? item.url.trim() : '',
      }))
      .filter((item) => item.label && item.url)
      .slice(0, 8)
    : [];

  const header = [
    `## Arena Decision — ${contender.label} (${contenderId})`,
    '',
    `Recommendation: **${recommendation}**`,
    `Confidence: **${confidencePct}**`,
    '',
    '### One-click links',
    ...links.map((entry) => `- [${entry.label}](${entry.url})`),
    '',
    '### Manager summary',
    managerDecision ? `- decision: \`${managerDecision}\`` : '- decision: `unknown`',
  ];

  if (metrics) {
    const quality = Number(metrics.quality_score ?? 0);
    const risk = Number(metrics.risk_score ?? 0);
    const efficiency = Number(metrics.efficiency_score ?? 0);
    const latency = Number(metrics.latency_ms ?? 0);
    const cost = Number(metrics.cost_usd ?? 0);

    header.push(
      `- metrics: quality=${quality.toFixed(2)}, risk=${risk.toFixed(2)}, efficiency=${efficiency.toFixed(2)}, latency=${Math.round(latency)}ms, cost=$${cost.toFixed(4)}`,
    );
  }

  if (failedChecks.length > 0) {
    header.push('- failed checks:', ...failedChecks.map((item) => `  - \`${item.criterion_id}\` -> \`${item.reason_code}\``));
  }

  if (reasonCodes.length > 0) {
    header.push('', '### Reason codes', ...reasonCodes.map((code) => `- \`${code}\``));
  }

  if (evidenceLinks.length > 0) {
    header.push('', '### Evidence links', ...evidenceLinks.map((entry) => `- [${entry.label}](${entry.url})`));
  }

  if (nextAction) {
    header.push('', `Next action: ${nextAction}`);
  }

  const bodyMarkdown = `${header.join('\n')}\n\n---\n\n${String(reviewPaste ?? '').trim()}\n`;

  return {
    recommendation,
    confidence: Number.isFinite(confidence) ? confidence : 0,
    bodyMarkdown,
    links,
    reasonCodes,
    nextAction,
    managerDecision,
    evidenceLinks,
  };
}
