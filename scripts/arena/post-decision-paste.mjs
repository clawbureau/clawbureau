#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { buildDecisionPastePayload } from './lib/decision-paste.mjs';
import { stableJson } from './lib/proof-pack-v3.mjs';

const DEFAULT_BOUNTIES_BASE = 'https://staging.clawbounties.com';

function parseArgs(argv) {
  const args = {
    arenaReportPath: null,
    contenderId: null,
    arenaBaseUrl: '',
    artifactsBaseUrl: '',
    outputPath: null,
    prNumber: null,
    bountyId: null,
    bountiesBase: DEFAULT_BOUNTIES_BASE,
    adminKey: process.env.BOUNTIES_ADMIN_KEY ?? '',
    postBountyThread: false,
    threadIdempotencyKey: null,
    source: 'arena-decision-paste',
    dryRun: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];

    if (arg === '--arena-report') {
      args.arenaReportPath = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--contender-id') {
      args.contenderId = argv[i + 1] ?? null;
      i += 1;
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
    if (arg === '--output') {
      args.outputPath = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--pr-number') {
      args.prNumber = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--bounty-id') {
      args.bountyId = argv[i + 1] ?? null;
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
    if (arg === '--post-bounty-thread') {
      args.postBountyThread = true;
      continue;
    }
    if (arg === '--thread-idempotency-key') {
      args.threadIdempotencyKey = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--source') {
      args.source = argv[i + 1] ?? 'arena-decision-paste';
      i += 1;
      continue;
    }
    if (arg === '--dry-run') {
      args.dryRun = true;
      continue;
    }
  }

  if (!args.arenaReportPath) {
    throw new Error('Usage: node scripts/arena/post-decision-paste.mjs --arena-report <arena-report.json> [--contender-id <id>] [--arena-base-url <url>] [--artifacts-base-url <url>] [--output <path>] [--pr-number <num>] [--post-bounty-thread --bounty-id <id> --admin-key <key>] [--dry-run]');
  }

  return args;
}

function loadJson(filePath) {
  return JSON.parse(readFileSync(filePath, 'utf8'));
}

function sha256b64u(input) {
  return createHash('sha256').update(input).digest('base64url');
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
    const err = new Error(`${method} ${url} failed with ${response.status}`);
    err.status = response.status;
    err.response = parsed;
    throw err;
  }

  return parsed;
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
  const report = loadJson(args.arenaReportPath);

  const contenderId = args.contenderId
    ? String(args.contenderId)
    : String(report?.winner?.contender_id ?? '');

  if (!contenderId) {
    throw new Error('Could not determine contender id (provide --contender-id)');
  }

  const contender = Array.isArray(report.contenders)
    ? report.contenders.find((item) => item && item.contender_id === contenderId)
    : null;

  if (!contender) {
    throw new Error(`contender ${contenderId} not found in arena report`);
  }

  const managerReview = loadJson(contender.manager_review_path);
  const reviewPaste = readFileSync(contender.review_paste_path, 'utf8');

  const decision = buildDecisionPastePayload({
    arenaReport: report,
    contender,
    managerReview,
    reviewPaste,
    arenaBaseUrl: args.arenaBaseUrl,
    artifactsBaseUrl: args.artifactsBaseUrl,
  });

  const outputPath = args.outputPath
    ? path.resolve(args.outputPath)
    : path.join(path.dirname(contender.review_paste_path), 'decision-paste.md');

  writeFileSync(outputPath, `${decision.bodyMarkdown.trim()}\n`);

  const summary = {
    ok: true,
    generated_at: new Date().toISOString(),
    arena_id: report.arena_id,
    bounty_id: args.bountyId ?? report?.contract?.bounty_id ?? null,
    contender_id: contenderId,
    recommendation: decision.recommendation,
    confidence: decision.confidence,
    output_path: outputPath,
    links: decision.links,
    posted: {
      pr_comment: null,
      bounty_thread: null,
    },
  };

  if (args.prNumber && !args.dryRun) {
    const output = postPrComment(args.prNumber, outputPath);
    summary.posted.pr_comment = {
      pr_number: args.prNumber,
      output,
    };
  }

  if (args.postBountyThread) {
    const bountyId = args.bountyId ?? report?.contract?.bounty_id;
    if (!bountyId) {
      throw new Error('--post-bounty-thread requires --bounty-id or report.contract.bounty_id');
    }

    if (!args.dryRun && !args.adminKey.trim()) {
      throw new Error('--post-bounty-thread requires --admin-key (or BOUNTIES_ADMIN_KEY env) unless --dry-run');
    }

    const idempotencyKey = args.threadIdempotencyKey
      ?? `arena-thread:${sha256b64u([report.arena_id, contenderId, decision.recommendation, String(decision.confidence), decision.bodyMarkdown].join('|'))}`;

    const payload = {
      idempotency_key: idempotencyKey,
      arena_id: report.arena_id,
      contender_id: contenderId,
      recommendation: decision.recommendation,
      confidence: decision.confidence,
      body_markdown: decision.bodyMarkdown,
      links: decision.links,
      source: args.source,
      metadata: {
        manager_decision: managerReview.decision,
        reason_codes: decision.reasonCodes,
      },
    };

    if (args.dryRun) {
      summary.posted.bounty_thread = {
        dry_run: true,
        endpoint: `${args.bountiesBase.replace(/\/$/, '')}/v1/bounties/${encodeURIComponent(bountyId)}/arena/review-thread`,
        payload,
      };
    } else {
      const response = await requestJson(
        `${args.bountiesBase.replace(/\/$/, '')}/v1/bounties/${encodeURIComponent(bountyId)}/arena/review-thread`,
        {
          method: 'POST',
          adminKey: args.adminKey.trim(),
          body: payload,
        },
      );

      summary.posted.bounty_thread = response;
    }
  }

  writeFileSync(path.join(path.dirname(outputPath), 'decision-paste.summary.json'), `${stableJson(summary)}\n`);
  console.log(JSON.stringify(summary, null, 2));
}

main().catch((err) => {
  const out = {
    ok: false,
    error: err instanceof Error ? err.message : String(err),
    status: err && typeof err === 'object' && 'status' in err ? err.status : undefined,
    details: err && typeof err === 'object' && 'response' in err ? err.response : undefined,
  };
  console.error(JSON.stringify(out, null, 2));
  process.exit(1);
});
