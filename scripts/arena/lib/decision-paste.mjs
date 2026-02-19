import path from 'node:path';

export function mapManagerDecisionToRecommendation(decision) {
  const normalized = String(decision ?? '').trim().toLowerCase();
  if (normalized === 'promote') return 'APPROVE';
  if (normalized === 'iterate') return 'REQUEST_CHANGES';
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

  const header = [
    `## Arena Decision — ${contender.label} (${contenderId})`,
    '',
    `Recommendation: **${recommendation}**`,
    `Confidence: **${confidencePct}**`,
    '',
    '### One-click links',
    ...links.map((entry) => `- [${entry.label}](${entry.url})`),
  ];

  if (reasonCodes.length > 0) {
    header.push('', '### Reason codes', ...reasonCodes.map((code) => `- \`${code}\``));
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
  };
}
