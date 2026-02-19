#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { runArena } from './lib/arena-runner.mjs';
import { buildDecisionPastePayload } from './lib/decision-paste.mjs';
import { stableJson } from './lib/proof-pack-v3.mjs';

const DEFAULT_BOUNTIES_BASE = 'https://staging.clawbounties.com';
const DEFAULT_OUTPUT_ROOT = 'artifacts/arena';

function parseArgs(argv) {
  const args = {
    bountyId: null,
    contractPath: null,
    contendersPath: null,
    outputRoot: DEFAULT_OUTPUT_ROOT,
    arenaId: null,
    generatedAt: null,
    bountiesBase: DEFAULT_BOUNTIES_BASE,
    adminKey: process.env.BOUNTIES_ADMIN_KEY ?? '',
    startIdempotencyKey: null,
    resultIdempotencyKey: null,
    dryRun: false,
    prNumber: null,
    postBountyThread: true,
    arenaBaseUrl: '',
    artifactsBaseUrl: '',
    decisionSource: 'arena-launcher',
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];

    if (arg === '--bounty-id') {
      args.bountyId = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--contract') {
      args.contractPath = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--contenders') {
      args.contendersPath = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--output-root') {
      args.outputRoot = argv[i + 1] ?? DEFAULT_OUTPUT_ROOT;
      i += 1;
      continue;
    }
    if (arg === '--arena-id') {
      args.arenaId = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--generated-at') {
      args.generatedAt = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--bounties-base') {
      args.bountiesBase = argv[i + 1] ?? DEFAULT_BOUNTIES_BASE;
      i += 1;
      continue;
    }
    if (arg === '--admin-key') {
      args.adminKey = argv[i + 1] ?? '';
      i += 1;
      continue;
    }
    if (arg === '--start-idempotency-key') {
      args.startIdempotencyKey = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--result-idempotency-key') {
      args.resultIdempotencyKey = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--dry-run') {
      args.dryRun = true;
      continue;
    }
    if (arg === '--pr-number' || arg === '--post-pr-number') {
      args.prNumber = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--post-bounty-thread') {
      args.postBountyThread = true;
      continue;
    }
    if (arg === '--no-post-bounty-thread' || arg === '--skip-bounty-thread') {
      args.postBountyThread = false;
      continue;
    }
    if (arg === '--arena-base-url') {
      args.arenaBaseUrl = argv[i + 1] ?? '';
      i += 1;
      continue;
    }
    if (arg === '--artifacts-base-url') {
      args.artifactsBaseUrl = argv[i + 1] ?? '';
      i += 1;
      continue;
    }
    if (arg === '--decision-source') {
      args.decisionSource = argv[i + 1] ?? 'arena-launcher';
      i += 1;
      continue;
    }
  }

  if (!args.bountyId || !args.contractPath || !args.contendersPath) {
    throw new Error('Usage: node scripts/arena/run-real-bounty-arena.mjs --bounty-id <bty_...> --contract <json> --contenders <json> [--output-root <dir>] [--arena-id <id>] [--generated-at <iso>] [--bounties-base <url>] [--admin-key <key>] [--start-idempotency-key <key>] [--result-idempotency-key <key>] [--pr-number <num>] [--no-post-bounty-thread] [--arena-base-url <url>] [--artifacts-base-url <url>] [--decision-source <name>] [--dry-run]');
  }

  return args;
}

function nowLabel() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

function sha256b64u(input) {
  return createHash('sha256').update(input).digest('base64url');
}

function buildDefaultIdempotencyKey(prefix, parts) {
  const digest = sha256b64u(parts.join('|'));
  return `${prefix}:${digest}`;
}

function loadJson(filePath) {
  return JSON.parse(readFileSync(filePath, 'utf8'));
}

async function requestJson(url, { method = 'GET', adminKey, body } = {}) {
  const headers = {
    Accept: 'application/json',
  };

  if (adminKey) {
    headers['x-admin-key'] = adminKey;
  }

  const init = {
    method,
    headers,
  };

  if (body !== undefined) {
    headers['content-type'] = 'application/json';
    init.body = JSON.stringify(body);
  }

  const response = await fetch(url, init);
  const text = await response.text();

  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = { raw: text };
  }

  if (!response.ok) {
    const error = new Error(`${method} ${url} failed with ${response.status}`);
    error.response = parsed;
    error.status = response.status;
    throw error;
  }

  return parsed;
}

function readContenderArtifacts(report) {
  const artifacts = [];

  for (const contender of report.contenders) {
    const proofPack = loadJson(contender.proof_pack_path);
    const managerReview = loadJson(contender.manager_review_path);
    const reviewPaste = readFileSync(contender.review_paste_path, 'utf8').trim();

    artifacts.push({
      contender_id: contender.contender_id,
      proof_pack: proofPack,
      manager_review: managerReview,
      review_paste: reviewPaste,
    });
  }

  return artifacts;
}

function buildDecisionPaste(report, winnerContenderId, arenaBaseUrl, artifactsBaseUrl) {
  const contender = report.contenders.find((item) => item.contender_id === winnerContenderId);
  if (!contender) {
    return null;
  }

  const managerReview = loadJson(contender.manager_review_path);
  const reviewPaste = readFileSync(contender.review_paste_path, 'utf8');

  const decision = buildDecisionPastePayload({
    arenaReport: report,
    contender,
    managerReview,
    reviewPaste,
    arenaBaseUrl,
    artifactsBaseUrl,
  });

  return {
    contender,
    managerReview,
    markdown: decision.bodyMarkdown,
    recommendation: decision.recommendation,
    confidence: decision.confidence,
    links: decision.links,
    reasonCodes: decision.reasonCodes,
  };
}

function normalizePrNumber(value) {
  if (value === null || value === undefined) return null;
  const parsed = Number.parseInt(String(value).trim(), 10);
  if (!Number.isFinite(parsed) || parsed <= 0) return null;
  return parsed;
}

function resolvePrNumber(args, contract, report) {
  const explicit = normalizePrNumber(args.prNumber);
  if (explicit) return explicit;

  const contractMeta = contract && typeof contract === 'object' && contract !== null
    ? contract.metadata
    : null;

  const reportContract = report && typeof report === 'object' && report !== null
    ? report.contract
    : null;

  return (
    normalizePrNumber(contract?.pr_number)
    || normalizePrNumber(contractMeta?.pr_number)
    || normalizePrNumber(reportContract?.pr_number)
    || normalizePrNumber(process.env.ARENA_PR_NUMBER)
  );
}

function hasAutoPostedWinnerThread(resultResponse, contenderId) {
  if (!resultResponse || !Array.isArray(resultResponse.review_thread)) return false;
  return resultResponse.review_thread.some((entry) => {
    if (!entry || typeof entry !== 'object') return false;
    return entry.contender_id === contenderId && entry.source === 'arena-result-autopost';
  });
}

function postPrComment(prNumber, markdownPath) {
  const proc = spawnSync('gh', ['pr', 'comment', String(prNumber), '--body-file', markdownPath], {
    encoding: 'utf8',
  });

  if (proc.status !== 0) {
    throw new Error(`gh pr comment failed: ${proc.stderr || proc.stdout}`);
  }

  return (proc.stdout || '').trim();
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (!args.dryRun && (!args.adminKey || !args.adminKey.trim())) {
    throw new Error('admin key is required unless --dry-run is set (provide --admin-key or BOUNTIES_ADMIN_KEY env)');
  }

  const contract = loadJson(args.contractPath);
  const contenders = loadJson(args.contendersPath);

  if (String(contract.bounty_id ?? '').trim() !== args.bountyId.trim()) {
    throw new Error(`Contract bounty_id (${contract.bounty_id}) does not match --bounty-id (${args.bountyId})`);
  }

  const arenaId = args.arenaId ?? `arena_${args.bountyId}_${nowLabel()}`;
  const outputDir = path.join(args.outputRoot, arenaId);
  mkdirSync(outputDir, { recursive: true });

  const report = runArena({
    contract,
    contenders,
    outputDir,
    generatedAt: args.generatedAt ?? undefined,
    arenaIdOverride: arenaId,
  });

  const startIdempotencyKey = args.startIdempotencyKey
    ?? buildDefaultIdempotencyKey('arena-start', [report.arena_id, report.contract.bounty_id, report.contract.contract_hash_b64u]);

  const resultIdempotencyKey = args.resultIdempotencyKey
    ?? buildDefaultIdempotencyKey('arena-result', [report.arena_id, report.winner.contender_id, String(report.generated_at)]);

  const decision = buildDecisionPaste(
    report,
    report.winner.contender_id,
    args.arenaBaseUrl,
    args.artifactsBaseUrl,
  );
  const resolvedPrNumber = resolvePrNumber(args, contract, report);

  const decisionOutputPath = path.join(outputDir, 'decision-paste.md');
  if (decision) {
    writeFileSync(decisionOutputPath, `${decision.markdown.trim()}\n`);
  }

  const summary = {
    ok: true,
    generated_at: new Date().toISOString(),
    mode: args.dryRun ? 'dry-run' : 'live',
    bounties_base: args.bountiesBase,
    bounty_id: args.bountyId,
    arena_id: report.arena_id,
    output_dir: outputDir,
    winner: report.winner,
    start_idempotency_key: startIdempotencyKey,
    result_idempotency_key: resultIdempotencyKey,
    decision_paste: decision
      ? {
          output_path: decisionOutputPath,
          contender_id: decision.contender.contender_id,
          recommendation: decision.recommendation,
          confidence: decision.confidence,
          links: decision.links,
          target_pr_number: resolvedPrNumber,
          posted: {
            pr_comment: null,
            bounty_thread: null,
          },
        }
      : null,
  };

  if (args.dryRun) {
    writeFileSync(path.join(outputDir, 'real-bounty-launch.summary.json'), `${stableJson(summary)}\n`);
    console.log(JSON.stringify(summary, null, 2));
    return;
  }

  const adminKey = args.adminKey.trim();

  const bountyRead = await requestJson(
    `${args.bountiesBase.replace(/\/$/, '')}/v1/bounties/${encodeURIComponent(args.bountyId)}`,
    {
      method: 'GET',
      adminKey,
    },
  );

  const startPayload = {
    idempotency_key: startIdempotencyKey,
    arena_id: report.arena_id,
    contract: report.contract,
    objective_profile: report.objective_profile,
  };

  const startResponse = await requestJson(
    `${args.bountiesBase.replace(/\/$/, '')}/v1/bounties/${encodeURIComponent(args.bountyId)}/arena/start`,
    {
      method: 'POST',
      adminKey,
      body: startPayload,
    },
  );

  const contenderArtifacts = readContenderArtifacts(report);

  const resultPayload = {
    idempotency_key: resultIdempotencyKey,
    arena_report: report,
    contender_artifacts: contenderArtifacts,
  };

  const resultResponse = await requestJson(
    `${args.bountiesBase.replace(/\/$/, '')}/v1/bounties/${encodeURIComponent(args.bountyId)}/arena/result`,
    {
      method: 'POST',
      adminKey,
      body: resultPayload,
    },
  );

  const arenaRead = await requestJson(
    `${args.bountiesBase.replace(/\/$/, '')}/v1/bounties/${encodeURIComponent(args.bountyId)}/arena`,
    {
      method: 'GET',
      adminKey,
    },
  );

  if (decision && resolvedPrNumber) {
    const output = postPrComment(resolvedPrNumber, decisionOutputPath);
    if (summary.decision_paste) {
      summary.decision_paste.posted.pr_comment = {
        pr_number: resolvedPrNumber,
        output,
      };
    }
  }

  if (decision && args.postBountyThread) {
    const alreadyAutoPosted = hasAutoPostedWinnerThread(resultResponse, decision.contender.contender_id);

    if (alreadyAutoPosted) {
      if (summary.decision_paste) {
        summary.decision_paste.posted.bounty_thread = {
          skipped: true,
          reason: 'arena-result-autopost-present',
        };
      }
    } else {
      const threadIdempotencyKey = buildDefaultIdempotencyKey('arena-thread', [
        report.arena_id,
        decision.contender.contender_id,
        decision.recommendation,
        String(decision.confidence),
        sha256b64u(decision.markdown),
      ]);

      const threadPayload = {
        idempotency_key: threadIdempotencyKey,
        arena_id: report.arena_id,
        contender_id: decision.contender.contender_id,
        recommendation: decision.recommendation,
        confidence: decision.confidence,
        body_markdown: decision.markdown,
        links: decision.links,
        source: args.decisionSource,
        metadata: {
          manager_decision: decision.managerReview.decision,
          reason_codes: decision.reasonCodes,
          evidence_links: decision.evidenceLinks ?? [],
          auto_posted: true,
        },
      };

      const threadResponse = await requestJson(
        `${args.bountiesBase.replace(/\/$/, '')}/v1/bounties/${encodeURIComponent(args.bountyId)}/arena/review-thread`,
        {
          method: 'POST',
          adminKey,
          body: threadPayload,
        },
      );

      if (summary.decision_paste) {
        summary.decision_paste.posted.bounty_thread = threadResponse;
      }
    }
  }

  const fullSummary = {
    ...summary,
    bounty_status: bountyRead.status ?? null,
    start_response: startResponse,
    result_response: resultResponse,
    arena_response: arenaRead,
  };

  writeFileSync(path.join(outputDir, 'real-bounty-launch.summary.json'), `${stableJson(fullSummary)}\n`);
  console.log(JSON.stringify(fullSummary, null, 2));
}

main().catch((err) => {
  const out = {
    ok: false,
    error: err instanceof Error ? err.message : String(err),
    details: err && typeof err === 'object' && 'response' in err ? err.response : undefined,
    status: err && typeof err === 'object' && 'status' in err ? err.status : undefined,
  };
  console.error(JSON.stringify(out, null, 2));
  process.exit(1);
});
