#!/usr/bin/env node
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..', '..');

const SNAPSHOT_PATHS = {
  manifest: 'artifacts/ops/e2e-demo/public/manifest.json',
  commit_proof: 'artifacts/ops/e2e-demo/public/commit-proof.snapshot.json',
  bundle_review: 'artifacts/ops/e2e-demo/public/bundle-review.snapshot.json',
  arena_decision: 'artifacts/ops/e2e-demo/public/arena-decision.snapshot.json',
};

const OUTPUTS = [
  'services/clawea-www/src/generated/e2e-demo-registry.json',
  'services/clawsig-explorer/src/generated/e2e-demo-registry.json',
];

function resolveMaybeAbsolute(target) {
  return path.isAbsolute(target) ? target : path.join(REPO_ROOT, target);
}

async function readJson(target) {
  const fullPath = resolveMaybeAbsolute(target);
  const raw = await fs.readFile(fullPath, 'utf8');
  return JSON.parse(raw);
}

function relDisplay(target) {
  return path.isAbsolute(target) ? target : target.replace(/\\/g, '/');
}

function formatInt(value) {
  return new Intl.NumberFormat('en-US').format(value);
}

function workflowRegistry(manifest, commitProof, bundleReview, arenaDecision) {
  return {
    generated_at: new Date().toISOString(),
    source_artifacts: {
      manifest: relDisplay(SNAPSHOT_PATHS.manifest),
      commit_proof_snapshot: relDisplay(SNAPSHOT_PATHS.commit_proof),
      bundle_review_snapshot: relDisplay(SNAPSHOT_PATHS.bundle_review),
      arena_decision_snapshot: relDisplay(SNAPSHOT_PATHS.arena_decision),
    },
    canonical_sources: manifest?.canonical_sources ?? {},
    workflows: [
      {
        id: 'pr-proof',
        eyebrow: 'Workflow 01',
        title: 'GitHub PR proof workflow',
        summary:
          'The change itself, the commit proof, and the verification step stay in one review surface instead of being split across screenshots and side channels.',
        evidence: `Real artifact anchor: ${commitProof.source_path} · DID ${commitProof.did} · ${commitProof.message}.`,
        references: {
          commit_proof_path: commitProof.source_path ?? null,
          signer_did: commitProof.did ?? null,
          commit_message: commitProof.message ?? null,
        },
        metrics: [
          {
            label: 'Proof primitive',
            value: String(commitProof.algorithm ?? 'unknown').toUpperCase(),
            note: 'commit-bound and offline-verifiable',
          },
          {
            label: 'Artifact type',
            value: String(commitProof.signature_type ?? 'commit proof'),
            note: 'checked into the repo beside the change',
          },
          {
            label: 'Failure mode',
            value: 'Fail closed',
            note: 'wrong SHA or malformed envelope breaks trust immediately',
          },
        ],
        steps: [
          'Agent commits code in a normal branch.',
          'The commit SHA is signed into commit.sig.json.',
          'The PR pipeline validates the signature before merge.',
        ],
      },
      {
        id: 'bundle-review',
        eyebrow: 'Workflow 02',
        title: 'Proof bundle review workflow',
        summary:
          'Reviewers need a compact, repo-contained evidence view they can regenerate in CI. This bundle-review lane now comes from a traced marketplace E2E artifact instead of a local /tmp-only run.',
        evidence: `Real artifact anchor: ${bundleReview.trace_path} · proof bundle ${bundleReview.source_path} · run ${bundleReview.run_id ?? 'unknown'} · bundle ${bundleReview.bundle_id ?? 'unknown'}.`,
        references: {
          run_id: bundleReview.run_id ?? null,
          bundle_id: bundleReview.bundle_id ?? null,
          proof_bundle_path: bundleReview.source_path ?? null,
          trace_path: bundleReview.trace_path ?? null,
        },
        metrics: [
          {
            label: 'Smoke verdict',
            value: String(bundleReview.verification_status ?? 'unknown'),
            note: String(bundleReview.verification_reason ?? 'no verification summary available'),
          },
          {
            label: 'Event chain',
            value: `${formatInt(Number(bundleReview.event_count ?? 0))} events`,
            note: 'hash-linked timeline from the traced proof bundle',
          },
          {
            label: 'Tool receipts',
            value: `${formatInt(Number(bundleReview.tool_receipt_count ?? 0))} ${bundleReview.dominant_tool ?? 'receipts'}`,
            note: 'captured in a real marketplace settlement E2E artifact',
          },
        ],
        steps: [
          'A repo-contained proof bundle is traced into a stable review snapshot.',
          'The trace preserves run identity, event counts, tool activity, and smoke verdict.',
          'Inspect and explorer views let reviewers move from summary into structure and drill-down context.',
        ],
      },
      {
        id: 'arena-decision',
        eyebrow: 'Workflow 03',
        title: 'Arena decision workflow',
        summary:
          'Once a marketplace workflow fans out into multiple contenders, the UI has to show who won, why they won, and whether autopilot thresholds were actually met.',
        evidence: `Real artifact anchor: ${arenaDecision.arena_summary_path} + ${arenaDecision.autopilot_summary_path}.`,
        references: {
          arena_id: arenaDecision.arena_id ?? null,
          arena_summary_path: arenaDecision.arena_summary_path ?? null,
          autopilot_summary_path: arenaDecision.autopilot_summary_path ?? null,
        },
        metrics: [
          {
            label: 'Contenders compared',
            value: String(arenaDecision.contender_count ?? 0),
            note: `${arenaDecision.arena_id ?? 'arena'} compare set`,
          },
          {
            label: 'Winner',
            value: String(arenaDecision.winner_contender_id ?? 'unknown'),
            note: String(arenaDecision.winner_reason ?? 'winner explanation unavailable'),
          },
          {
            label: 'Autopilot proof',
            value: `${arenaDecision.staging_valid_pending_review ?? 0} staging / ${arenaDecision.production_valid_pending_review ?? 0} production`,
            note: 'valid pending_review thresholds met in AGP-US-060 evidence',
          },
        ],
        steps: [
          'The arena compares contenders against one bounty decision surface.',
          'Reason codes explain why the winner cleared policy and scoring gates.',
          'Autopilot evidence proves live readiness instead of implying it.',
        ],
      },
    ],
  };
}

async function main() {
  const [manifest, commitProof, bundleReview, arenaDecision] = await Promise.all([
    readJson(SNAPSHOT_PATHS.manifest),
    readJson(SNAPSHOT_PATHS.commit_proof),
    readJson(SNAPSHOT_PATHS.bundle_review),
    readJson(SNAPSHOT_PATHS.arena_decision),
  ]);

  const registry = workflowRegistry(manifest, commitProof, bundleReview, arenaDecision);
  const payload = JSON.stringify(registry, null, 2) + '\n';

  for (const output of OUTPUTS) {
    const fullPath = path.join(REPO_ROOT, output);
    await fs.mkdir(path.dirname(fullPath), { recursive: true });
    await fs.writeFile(fullPath, payload, 'utf8');
    process.stdout.write(`Wrote ${output}\n`);
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
