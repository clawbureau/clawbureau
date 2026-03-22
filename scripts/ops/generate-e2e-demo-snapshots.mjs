#!/usr/bin/env node
import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

const execFileAsync = promisify(execFile);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..', '..');

const CANONICAL_SOURCES = {
  commit_proof: 'proofs/feat/clawsig/human-readable-proofs/commit.sig.json',
  proof_bundle: 'artifacts/simulations/marketplace-e2e-settlement/2026-02-18T15-27-47-754Z-prod/proof-bundle.json',
  arena_summary: 'artifacts/arena/arena_bty_arena_001/summary.json',
  autopilot_summary: 'artifacts/ops/arena-productization/2026-02-20T02-18-40Z-agp-us-060-execution-submission-autopilot/summary.json',
};

const SNAPSHOT_ROOT = 'artifacts/ops/e2e-demo/public';
const TRACE_OUTPUT = 'artifacts/ops/e2e-demo/traces/settlement-prod.trace.json';

function resolveRepoPath(target) {
  return path.join(REPO_ROOT, target);
}

async function readJson(target) {
  const raw = await fs.readFile(resolveRepoPath(target), 'utf8');
  return JSON.parse(raw);
}

async function statIso(target) {
  const stat = await fs.stat(resolveRepoPath(target));
  return stat.mtime.toISOString();
}

async function writeJson(target, value) {
  const fullPath = resolveRepoPath(target);
  await fs.mkdir(path.dirname(fullPath), { recursive: true });
  await fs.writeFile(fullPath, JSON.stringify(value, null, 2) + '\n', 'utf8');
}

async function generateTraceSnapshot() {
  await execFileAsync(process.execPath, [
    'scripts/poh/trace-artifacts.mjs',
    '--bundle',
    CANONICAL_SOURCES.proof_bundle,
    '--out',
    TRACE_OUTPUT,
  ], {
    cwd: REPO_ROOT,
  });

  return readJson(TRACE_OUTPUT);
}

function toMetricCount(items, key) {
  if (!Array.isArray(items) || items.length === 0) return '0';
  const first = items[0];
  if (!first || typeof first !== 'object') return String(items.length);
  const value = first[key];
  return typeof value === 'string' ? value : String(items.length);
}

function buildCommitProofSnapshot(commitProof, sourceMtime, generatedAt) {
  return {
    snapshot_version: '1',
    workflow_id: 'pr-proof',
    generated_at: generatedAt,
    source_path: CANONICAL_SOURCES.commit_proof,
    source_mtime: sourceMtime,
    did: commitProof.did ?? null,
    message: commitProof.message ?? null,
    created_at: commitProof.createdAt ?? null,
    algorithm: commitProof.algo ?? null,
    signature_type: commitProof.type ?? null,
  };
}

function buildBundleReviewSnapshot(trace, sourceMtime, generatedAt) {
  const bundle = trace?.trace?.bundle ?? {};
  const verification = Array.isArray(trace?.trace?.verification_results) ? trace.trace.verification_results[0] ?? null : null;
  const toolSummary = bundle?.tool_summary ?? {};
  const byToolName = Array.isArray(toolSummary.by_tool_name) ? toolSummary.by_tool_name : [];
  const byResultStatus = Array.isArray(toolSummary.by_result_status) ? toolSummary.by_result_status : [];

  return {
    snapshot_version: '1',
    workflow_id: 'bundle-review',
    generated_at: generatedAt,
    source_path: CANONICAL_SOURCES.proof_bundle,
    source_mtime: sourceMtime,
    trace_path: TRACE_OUTPUT,
    run_id: trace?.trace?.run_id ?? null,
    bundle_id: bundle.bundle_id ?? null,
    agent_did: bundle.agent_did ?? null,
    issued_at: bundle.issued_at ?? null,
    event_count: Number(bundle?.array_counts?.event_chain ?? 0),
    tool_receipt_count: Number(bundle?.array_counts?.tool_receipts ?? 0),
    dominant_tool: byToolName[0]?.tool_name ?? null,
    dominant_tool_count: Number(byToolName[0]?.count ?? 0),
    primary_result_status: byResultStatus[0]?.result_status ?? null,
    primary_result_status_count: Number(byResultStatus[0]?.count ?? 0),
    verification_status: verification?.status ?? null,
    verification_code: verification?.code ?? null,
    verification_reason: verification?.reason ?? null,
  };
}

function buildArenaDecisionSnapshot(arenaSummary, autopilotSummary, arenaMtime, autopilotMtime, generatedAt) {
  return {
    snapshot_version: '1',
    workflow_id: 'arena-decision',
    generated_at: generatedAt,
    arena_summary_path: CANONICAL_SOURCES.arena_summary,
    arena_summary_mtime: arenaMtime,
    autopilot_summary_path: CANONICAL_SOURCES.autopilot_summary,
    autopilot_summary_mtime: autopilotMtime,
    arena_id: arenaSummary?.arena_id ?? null,
    contender_count: Number(arenaSummary?.contenders_count ?? 0),
    winner_contender_id: arenaSummary?.winner?.contender_id ?? null,
    winner_reason: arenaSummary?.winner?.reason ?? null,
    staging_valid_pending_review: Number(autopilotSummary?.done_criteria?.staging_pending_review_valid ?? 0),
    production_valid_pending_review: Number(autopilotSummary?.done_criteria?.production_pending_review_valid ?? 0),
  };
}

function buildManifest(generatedAt) {
  return {
    snapshot_version: '1',
    generated_at: generatedAt,
    canonical_sources: {
      ...CANONICAL_SOURCES,
      bundle_trace: TRACE_OUTPUT,
    },
    snapshot_outputs: {
      commit_proof: `${SNAPSHOT_ROOT}/commit-proof.snapshot.json`,
      bundle_review: `${SNAPSHOT_ROOT}/bundle-review.snapshot.json`,
      arena_decision: `${SNAPSHOT_ROOT}/arena-decision.snapshot.json`,
    },
    notes: [
      'Wave 3 converts the demo surfaces to staging-safe, repo-contained snapshot inputs.',
      'The bundle-review snapshot is derived by tracing a repo-contained marketplace E2E proof bundle.',
      'The refresh workflow can regenerate these snapshots in CI without relying on local /tmp state.',
    ],
  };
}

async function main() {
  const generatedAt = new Date().toISOString();

  const [commitProof, arenaSummary, autopilotSummary, commitMtime, bundleMtime, arenaMtime, autopilotMtime, trace] = await Promise.all([
    readJson(CANONICAL_SOURCES.commit_proof),
    readJson(CANONICAL_SOURCES.arena_summary),
    readJson(CANONICAL_SOURCES.autopilot_summary),
    statIso(CANONICAL_SOURCES.commit_proof),
    statIso(CANONICAL_SOURCES.proof_bundle),
    statIso(CANONICAL_SOURCES.arena_summary),
    statIso(CANONICAL_SOURCES.autopilot_summary),
    generateTraceSnapshot(),
  ]);

  const commitSnapshot = buildCommitProofSnapshot(commitProof, commitMtime, generatedAt);
  const bundleSnapshot = buildBundleReviewSnapshot(trace, bundleMtime, generatedAt);
  const arenaSnapshot = buildArenaDecisionSnapshot(arenaSummary, autopilotSummary, arenaMtime, autopilotMtime, generatedAt);
  const manifest = buildManifest(generatedAt);

  await Promise.all([
    writeJson(`${SNAPSHOT_ROOT}/commit-proof.snapshot.json`, commitSnapshot),
    writeJson(`${SNAPSHOT_ROOT}/bundle-review.snapshot.json`, bundleSnapshot),
    writeJson(`${SNAPSHOT_ROOT}/arena-decision.snapshot.json`, arenaSnapshot),
    writeJson(`${SNAPSHOT_ROOT}/manifest.json`, manifest),
  ]);

  process.stdout.write(`Wrote ${SNAPSHOT_ROOT}/commit-proof.snapshot.json\n`);
  process.stdout.write(`Wrote ${SNAPSHOT_ROOT}/bundle-review.snapshot.json\n`);
  process.stdout.write(`Wrote ${SNAPSHOT_ROOT}/arena-decision.snapshot.json\n`);
  process.stdout.write(`Wrote ${SNAPSHOT_ROOT}/manifest.json\n`);
  process.stdout.write(`Wrote ${TRACE_OUTPUT}\n`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
