#!/usr/bin/env node
/**
 * Artifact tracer for Claw Bureau / Clawsig evidence packs.
 *
 * Scans known artifact roots, classifies JSON artifacts, and builds a
 * run-centric trace graph (proof bundle -> URM -> trust pulse -> verification outputs).
 *
 * Usage:
 *   node scripts/poh/trace-artifacts.mjs
 *   node scripts/poh/trace-artifacts.mjs --run-id run_123
 *   node scripts/poh/trace-artifacts.mjs --bundle .clawsig/proof_bundle.json
 *   node scripts/poh/trace-artifacts.mjs --json
 */

import * as fs from 'node:fs/promises';
import { existsSync } from 'node:fs';
import * as path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..', '..');

const SKIP_DIRS = new Set([
  '.git',
  'node_modules',
  '.wrangler',
  '.next',
  'dist',
  'coverage',
  '.turbo',
  '.cache',
]);

const MAX_JSON_BYTES_DEFAULT = 3 * 1024 * 1024;

function isoStamp() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

function normalizePath(p) {
  return p.replace(/\\/g, '/');
}

function isRecord(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function parseArgs(argv) {
  const options = {
    root: REPO_ROOT,
    artifactsDir: 'artifacts',
    proofsDir: 'proofs',
    runId: undefined,
    bundlePath: undefined,
    outPath: undefined,
    json: false,
    maxJsonBytes: MAX_JSON_BYTES_DEFAULT,
    maxFiles: 20000,
    help: false,
  };

  for (let i = 2; i < argv.length; i++) {
    const arg = argv[i];
    const next = argv[i + 1];

    if (arg === '--root' && next) {
      options.root = path.resolve(next);
      i++;
      continue;
    }
    if (arg === '--artifacts-dir' && next) {
      options.artifactsDir = next;
      i++;
      continue;
    }
    if (arg === '--proofs-dir' && next) {
      options.proofsDir = next;
      i++;
      continue;
    }
    if (arg === '--run-id' && next) {
      options.runId = next;
      i++;
      continue;
    }
    if (arg === '--bundle' && next) {
      options.bundlePath = next;
      i++;
      continue;
    }
    if (arg === '--out' && next) {
      options.outPath = next;
      i++;
      continue;
    }
    if (arg === '--max-json-bytes' && next) {
      const parsed = Number.parseInt(next, 10);
      if (Number.isFinite(parsed) && parsed > 0) options.maxJsonBytes = parsed;
      i++;
      continue;
    }
    if (arg === '--max-files' && next) {
      const parsed = Number.parseInt(next, 10);
      if (Number.isFinite(parsed) && parsed > 0) options.maxFiles = parsed;
      i++;
      continue;
    }
    if (arg === '--json') {
      options.json = true;
      continue;
    }
    if (arg === '--help' || arg === '-h') {
      options.help = true;
      continue;
    }

    throw new Error(`Unknown argument: ${arg}`);
  }

  if (typeof options.bundlePath === 'string') {
    options.bundlePath = path.resolve(options.root, options.bundlePath);
  }

  if (typeof options.outPath === 'string') {
    options.outPath = path.resolve(options.root, options.outPath);
  }

  return options;
}

function printHelp() {
  process.stdout.write(
    [
      'Artifact tracer (Claw Bureau)',
      '',
      'Usage:',
      '  node scripts/poh/trace-artifacts.mjs [options]',
      '',
      'Options:',
      '  --root <path>             Repository root (default: current repo)',
      '  --artifacts-dir <path>    Artifact dir relative to root (default: artifacts)',
      '  --proofs-dir <path>       Proof dir relative to root (default: proofs)',
      '  --run-id <run_id>         Trace a specific run_id',
      '  --bundle <path>           Trace starting from a proof bundle path',
      '  --out <path>              Output JSON path (default: artifacts/ops/artifact-trace/<ts>/summary.json)',
      '  --max-json-bytes <n>      Skip files larger than n bytes (default: 3145728)',
      '  --max-files <n>           Max JSON files scanned (default: 20000)',
      '  --json                    Print full report JSON to stdout',
      '  -h, --help                Show help',
      '',
      'Examples:',
      '  node scripts/poh/trace-artifacts.mjs',
      '  node scripts/poh/trace-artifacts.mjs --run-id run_abc123',
      '  node scripts/poh/trace-artifacts.mjs --bundle .clawsig/proof_bundle.json --json',
      '',
    ].join('\n')
  );
}

async function walkJsonFiles(rootDir, maxFiles) {
  const out = [];
  if (!existsSync(rootDir)) return out;

  const stack = [rootDir];

  while (stack.length > 0) {
    const current = stack.pop();
    if (!current) break;

    let entries;
    try {
      entries = await fs.readdir(current, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      const full = path.join(current, entry.name);

      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        stack.push(full);
        continue;
      }

      if (!entry.isFile()) continue;
      if (!entry.name.endsWith('.json')) continue;

      out.push(full);
      if (out.length >= maxFiles) return out;
    }
  }

  return out;
}

function collectKeyStrings(value, targetKey, maxValues = 64, maxDepth = 14) {
  const results = new Set();
  const stack = [{ value, depth: 0 }];

  while (stack.length > 0) {
    const node = stack.pop();
    if (!node) break;
    const { value: current, depth } = node;

    if (depth > maxDepth) continue;

    if (Array.isArray(current)) {
      for (const item of current) {
        stack.push({ value: item, depth: depth + 1 });
      }
      continue;
    }

    if (!isRecord(current)) continue;

    for (const [key, val] of Object.entries(current)) {
      if (key === targetKey && typeof val === 'string' && val.length > 0) {
        results.add(val);
        if (results.size >= maxValues) {
          return [...results];
        }
      }

      if (isRecord(val) || Array.isArray(val)) {
        stack.push({ value: val, depth: depth + 1 });
      }
    }
  }

  return [...results];
}

function sha256B64uFromJson(value) {
  const digest = createHash('sha256').update(JSON.stringify(value)).digest('base64');
  return digest.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function classifyArtifact(doc, relPath) {
  const rp = normalizePath(relPath);

  if (rp.endsWith('/commit.sig.json')) {
    return 'commit_signature';
  }

  if (!isRecord(doc)) {
    if (rp.endsWith('/summary.json')) return 'summary_json';
    if (rp.endsWith('/smoke.json') || rp.endsWith('/result.json')) return 'smoke_result';
    return 'json';
  }

  if (doc.envelope_type === 'proof_bundle' && isRecord(doc.payload)) {
    return 'proof_bundle_envelope';
  }
  if (doc.envelope_type === 'aggregate_bundle' && isRecord(doc.payload)) {
    return 'aggregate_bundle_envelope';
  }
  if (doc.urm_version === '1' && typeof doc.urm_id === 'string') {
    return 'urm_document';
  }
  if (doc.trust_pulse_version === '1' && typeof doc.run_id === 'string') {
    return 'trust_pulse';
  }
  if (doc.export_version === '1' && Array.isArray(doc.manifest)) {
    return 'export_bundle';
  }
  if (doc.type === 'message_signature' && typeof doc.message === 'string') {
    return 'commit_signature';
  }
  if (
    (isRecord(doc.result) && typeof doc.result.status === 'string') ||
    (typeof doc.status === 'string' && typeof doc.reason_code === 'string') ||
    (isRecord(doc.verification) && isRecord(doc.verification.result) && typeof doc.verification.result.status === 'string')
  ) {
    return 'verification_result';
  }
  if (isRecord(doc.results) && Array.isArray(doc.vectors) && isRecord(doc.manifest)) {
    return 'conformance_summary';
  }
  if (doc.manifest_version === '1' && Array.isArray(doc.vectors)) {
    return 'conformance_manifest';
  }
  if (rp.includes('/artifacts/ops/') && rp.endsWith('/summary.json')) {
    return 'ops_summary';
  }
  if (rp.endsWith('/smoke.json') || rp.endsWith('/result.json')) {
    return 'smoke_result';
  }
  if (rp.endsWith('/summary.json')) {
    return 'summary_json';
  }

  return 'json';
}

function normalizeClddMetrics(value) {
  if (!isRecord(value)) return null;
  const unmediated = value.unmediated_connections;
  const unmonitored = value.unmonitored_spawns;
  const escapes = value.escapes_suspected;

  if (
    typeof unmediated !== 'number' ||
    !Number.isInteger(unmediated) ||
    unmediated < 0 ||
    typeof unmonitored !== 'number' ||
    !Number.isInteger(unmonitored) ||
    unmonitored < 0 ||
    typeof escapes !== 'boolean'
  ) {
    return null;
  }

  return {
    unmediated_connections: unmediated,
    unmonitored_spawns: unmonitored,
    escapes_suspected: escapes,
  };
}

function aggregateCoverageClddFromPayload(payload) {
  const coverage = Array.isArray(payload.coverage_attestations)
    ? payload.coverage_attestations
    : [];

  let aggregate = null;

  for (const envelope of coverage) {
    if (!isRecord(envelope) || !isRecord(envelope.payload)) continue;
    const metrics = envelope.payload.metrics;
    if (!isRecord(metrics)) continue;

    const lineage = isRecord(metrics.lineage) ? metrics.lineage : null;
    const egress = isRecord(metrics.egress) ? metrics.egress : null;
    if (!lineage || !egress) continue;

    const next = normalizeClddMetrics({
      unmediated_connections: egress.unmediated_connections,
      unmonitored_spawns: lineage.unmonitored_spawns,
      escapes_suspected: lineage.escapes_suspected,
    });

    if (!next) continue;

    if (!aggregate) {
      aggregate = { ...next };
      continue;
    }

    aggregate = {
      unmediated_connections: Math.max(
        aggregate.unmediated_connections,
        next.unmediated_connections
      ),
      unmonitored_spawns: Math.max(
        aggregate.unmonitored_spawns,
        next.unmonitored_spawns
      ),
      escapes_suspected: aggregate.escapes_suspected || next.escapes_suspected,
    };
  }

  return aggregate;
}

function summarizeClddDiscrepancy(claimed, attested) {
  if (!claimed || !attested) {
    return {
      claimed,
      attested,
      mismatch_fields: [],
      discrepancy: false,
    };
  }

  const mismatchFields = [];

  if (claimed.unmediated_connections !== attested.unmediated_connections) {
    mismatchFields.push('unmediated_connections');
  }
  if (claimed.unmonitored_spawns !== attested.unmonitored_spawns) {
    mismatchFields.push('unmonitored_spawns');
  }
  if (claimed.escapes_suspected !== attested.escapes_suspected) {
    mismatchFields.push('escapes_suspected');
  }

  return {
    claimed,
    attested,
    mismatch_fields: mismatchFields,
    discrepancy: mismatchFields.length > 0,
  };
}

function collectCausalConfidenceEntries(payload) {
  const entries = [];

  const readBinding = (source, index, binding, extra = {}) => {
    if (!isRecord(binding)) return;
    if (typeof binding.attribution_confidence !== 'number') return;

    entries.push({
      source,
      index,
      confidence: binding.attribution_confidence,
      phase: typeof binding.phase === 'string' ? binding.phase : null,
      ...extra,
    });
  };

  const receipts = Array.isArray(payload.receipts) ? payload.receipts : [];
  for (let i = 0; i < receipts.length; i++) {
    const item = receipts[i];
    if (!isRecord(item) || !isRecord(item.payload)) continue;
    readBinding('receipts', i, item.payload.binding);
  }

  const webReceipts = Array.isArray(payload.web_receipts) ? payload.web_receipts : [];
  for (let i = 0; i < webReceipts.length; i++) {
    const item = webReceipts[i];
    if (!isRecord(item) || !isRecord(item.payload)) continue;
    readBinding('web_receipts', i, item.payload.binding);
  }

  const virReceipts = Array.isArray(payload.vir_receipts) ? payload.vir_receipts : [];
  for (let i = 0; i < virReceipts.length; i++) {
    const item = virReceipts[i];
    if (!isRecord(item)) continue;

    const maybePayload = isRecord(item.payload) ? item.payload : item;
    readBinding('vir_receipts', i, maybePayload.binding);
  }

  const sideEffects = Array.isArray(payload.side_effect_receipts)
    ? payload.side_effect_receipts
    : [];

  for (let i = 0; i < sideEffects.length; i++) {
    const item = sideEffects[i];
    if (!isRecord(item)) continue;

    const hashFirst =
      typeof item.target_digest === 'string' && item.target_digest.length > 0
        ? item.target_digest
        : typeof item.request_digest === 'string' && item.request_digest.length > 0
          ? item.request_digest
          : typeof item.response_digest === 'string' && item.response_digest.length > 0
            ? item.response_digest
            : typeof item.receipt_id === 'string'
              ? item.receipt_id
              : null;

    readBinding('side_effect_receipts', i, item.binding, {
      receipt_id: typeof item.receipt_id === 'string' ? item.receipt_id : null,
      effect_class: typeof item.effect_class === 'string' ? item.effect_class : null,
      hash_first: hashFirst,
    });
  }

  const approvals = Array.isArray(payload.human_approval_receipts)
    ? payload.human_approval_receipts
    : [];

  for (let i = 0; i < approvals.length; i++) {
    const item = approvals[i];
    if (!isRecord(item)) continue;
    readBinding('human_approval_receipts', i, item.binding, {
      receipt_id: typeof item.receipt_id === 'string' ? item.receipt_id : null,
    });
  }

  return entries;
}

function summarizeConfidenceDistribution(entries) {
  const summary = {
    total: entries.length,
    authoritative: 0,
    inferred: 0,
    low: 0,
    unattributed: 0,
    histogram: {},
  };

  for (const entry of entries) {
    const confidence = entry.confidence;

    if (!Number.isFinite(confidence)) continue;

    if (confidence === 0) {
      summary.unattributed += 1;
    } else if (confidence >= 0.99) {
      summary.authoritative += 1;
    } else if (confidence >= 0.5) {
      summary.inferred += 1;
    } else {
      summary.low += 1;
    }

    const bucket = confidence.toFixed(3);
    summary.histogram[bucket] = (summary.histogram[bucket] ?? 0) + 1;
  }

  return summary;
}

function summarizeLowConfidenceSideEffects(entries) {
  return entries
    .filter(
      (entry) =>
        entry.source === 'side_effect_receipts' &&
        Number.isFinite(entry.confidence) &&
        entry.confidence <= 0.5
    )
    .sort((a, b) => {
      if (a.confidence !== b.confidence) return a.confidence - b.confidence;
      const ah = typeof a.hash_first === 'string' ? a.hash_first : '';
      const bh = typeof b.hash_first === 'string' ? b.hash_first : '';
      return ah.localeCompare(bh);
    })
    .map((entry) => ({
      hash_first: entry.hash_first ?? 'n/a',
      confidence: entry.confidence,
      receipt_id: entry.receipt_id ?? null,
      effect_class: entry.effect_class ?? null,
      phase: entry.phase,
    }));
}

function summarizeProofBundle(doc) {
  if (!isRecord(doc) || !isRecord(doc.payload)) return null;

  const payload = doc.payload;
  const arrayCounts = {};
  for (const [key, value] of Object.entries(payload)) {
    if (Array.isArray(value)) arrayCounts[key] = value.length;
  }

  const runIds = new Set(collectKeyStrings(payload, 'run_id'));

  const eventChain = Array.isArray(payload.event_chain) ? payload.event_chain : [];
  const eventTimeline = eventChain
    .filter((e) => isRecord(e))
    .map((e) => ({
      timestamp: typeof e.timestamp === 'string' ? e.timestamp : undefined,
      event_type: typeof e.event_type === 'string' ? e.event_type : undefined,
      event_id: typeof e.event_id === 'string' ? e.event_id : undefined,
      run_id: typeof e.run_id === 'string' ? e.run_id : undefined,
    }))
    .slice(0, 200);

  const toolReceipts = Array.isArray(payload.tool_receipts) ? payload.tool_receipts : [];
  const toolCountByName = new Map();
  const toolStatusByResult = new Map();
  for (const tr of toolReceipts) {
    if (!isRecord(tr)) continue;
    const toolName = typeof tr.tool_name === 'string' ? tr.tool_name : 'unknown';
    const status = typeof tr.result_status === 'string' ? tr.result_status : 'unknown';
    toolCountByName.set(toolName, (toolCountByName.get(toolName) ?? 0) + 1);
    toolStatusByResult.set(status, (toolStatusByResult.get(status) ?? 0) + 1);
  }

  const gatewayReceipts = Array.isArray(payload.receipts) ? payload.receipts : [];
  const gatewayProviderModel = new Map();
  for (const r of gatewayReceipts) {
    if (!isRecord(r) || !isRecord(r.payload)) continue;
    const provider = typeof r.payload.provider === 'string' ? r.payload.provider : 'unknown';
    const model = typeof r.payload.model === 'string' ? r.payload.model : 'unknown';
    const key = `${provider}/${model}`;
    gatewayProviderModel.set(key, (gatewayProviderModel.get(key) ?? 0) + 1);
  }

  const metadata = isRecord(payload.metadata) ? payload.metadata : null;
  const sentinels = metadata && isRecord(metadata.sentinels) ? metadata.sentinels : null;

  const interposeState = sentinels && isRecord(sentinels.interpose_state)
    ? sentinels.interpose_state
    : null;

  const claimedCldd = interposeState
    ? normalizeClddMetrics(interposeState.cldd)
    : null;
  const attestedCldd = aggregateCoverageClddFromPayload(payload);
  const clddDiscrepancy = summarizeClddDiscrepancy(claimedCldd, attestedCldd);

  const confidenceEntries = collectCausalConfidenceEntries(payload);
  const confidenceDistribution = summarizeConfidenceDistribution(confidenceEntries);
  const lowConfidenceSideEffects = summarizeLowConfidenceSideEffects(confidenceEntries);

  return {
    bundle_id: typeof payload.bundle_id === 'string' ? payload.bundle_id : undefined,
    agent_did: typeof payload.agent_did === 'string' ? payload.agent_did : undefined,
    signer_did: typeof doc.signer_did === 'string' ? doc.signer_did : undefined,
    issued_at: typeof doc.issued_at === 'string' ? doc.issued_at : undefined,
    run_ids: [...runIds],
    array_counts: arrayCounts,
    event_timeline: eventTimeline,
    event_types: eventTimeline.reduce((acc, ev) => {
      const k = ev.event_type ?? 'unknown';
      acc[k] = (acc[k] ?? 0) + 1;
      return acc;
    }, {}),
    tool_summary: {
      by_tool_name: [...toolCountByName.entries()].map(([tool_name, count]) => ({ tool_name, count })),
      by_result_status: [...toolStatusByResult.entries()].map(([result_status, count]) => ({ result_status, count })),
    },
    gateway_receipt_summary: {
      total: gatewayReceipts.length,
      by_provider_model: [...gatewayProviderModel.entries()].map(([provider_model, count]) => ({ provider_model, count })),
    },
    causal_confidence_distribution: confidenceDistribution,
    low_confidence_side_effects: lowConfidenceSideEffects,
    cldd_discrepancy: clddDiscrepancy,
    sentinels,
    urm_ref: isRecord(payload.urm)
      ? {
          urm_id: typeof payload.urm.urm_id === 'string' ? payload.urm.urm_id : undefined,
          resource_hash_b64u:
            typeof payload.urm.resource_hash_b64u === 'string'
              ? payload.urm.resource_hash_b64u
              : undefined,
        }
      : null,
  };
}

function summarizeUrm(doc) {
  if (!isRecord(doc)) return null;
  const metadata = isRecord(doc.metadata) ? doc.metadata : null;
  const trustPulseRef = metadata && isRecord(metadata.trust_pulse)
    ? {
        schema: typeof metadata.trust_pulse.schema === 'string' ? metadata.trust_pulse.schema : undefined,
        artifact_hash_b64u:
          typeof metadata.trust_pulse.artifact_hash_b64u === 'string'
            ? metadata.trust_pulse.artifact_hash_b64u
            : undefined,
        evidence_class:
          typeof metadata.trust_pulse.evidence_class === 'string'
            ? metadata.trust_pulse.evidence_class
            : undefined,
        tier_uplift:
          typeof metadata.trust_pulse.tier_uplift === 'boolean'
            ? metadata.trust_pulse.tier_uplift
            : undefined,
      }
    : null;

  return {
    urm_id: typeof doc.urm_id === 'string' ? doc.urm_id : undefined,
    run_id: typeof doc.run_id === 'string' ? doc.run_id : undefined,
    agent_did: typeof doc.agent_did === 'string' ? doc.agent_did : undefined,
    issued_at: typeof doc.issued_at === 'string' ? doc.issued_at : undefined,
    trust_pulse_ref: trustPulseRef,
    hash_b64u: sha256B64uFromJson(doc),
  };
}

function summarizeTrustPulse(doc) {
  if (!isRecord(doc)) return null;
  return {
    trust_pulse_id:
      typeof doc.trust_pulse_id === 'string' ? doc.trust_pulse_id : undefined,
    run_id: typeof doc.run_id === 'string' ? doc.run_id : undefined,
    agent_did: typeof doc.agent_did === 'string' ? doc.agent_did : undefined,
    issued_at: typeof doc.issued_at === 'string' ? doc.issued_at : undefined,
    tools_count: Array.isArray(doc.tools) ? doc.tools.length : 0,
    files_count: Array.isArray(doc.files) ? doc.files.length : 0,
    evidence_class:
      typeof doc.evidence_class === 'string' ? doc.evidence_class : undefined,
    tier_uplift:
      typeof doc.tier_uplift === 'boolean' ? doc.tier_uplift : undefined,
    hash_b64u: sha256B64uFromJson(doc),
  };
}

function summarizeVerificationResult(doc) {
  if (!isRecord(doc)) return null;
  const result = isRecord(doc.result)
    ? doc.result
    : isRecord(doc.verification) && isRecord(doc.verification.result)
      ? doc.verification.result
      : null;
  const error = isRecord(doc.error) ? doc.error : null;
  const componentResults =
    result && isRecord(result.component_results)
      ? result.component_results
      : isRecord(doc.component_results)
        ? doc.component_results
        : null;

  const riskFlags = Array.isArray(result?.risk_flags)
    ? result.risk_flags.filter((f) => typeof f === 'string')
    : Array.isArray(doc.risk_flags)
      ? doc.risk_flags.filter((f) => typeof f === 'string')
      : [];

  const mismatchFields = Array.isArray(componentResults?.coverage_cldd_mismatch_fields)
    ? componentResults.coverage_cldd_mismatch_fields.filter(
      (f) => typeof f === 'string'
    )
    : [];

  return {
    status:
      typeof doc.status === 'string'
        ? doc.status
        : typeof result?.status === 'string'
          ? result.status
          : undefined,
    reason:
      typeof doc.reason === 'string'
        ? doc.reason
        : typeof result?.reason === 'string'
          ? result.reason
          : undefined,
    envelope_type:
      typeof result?.envelope_type === 'string'
        ? result.envelope_type
        : typeof doc.kind === 'string'
          ? doc.kind
          : undefined,
    code:
      typeof doc.reason_code === 'string'
        ? doc.reason_code
        : typeof error?.code === 'string'
          ? error.code
          : undefined,
    verified_at:
      typeof doc.verified_at === 'string'
        ? doc.verified_at
        : typeof result?.verified_at === 'string'
          ? result.verified_at
          : undefined,
    risk_flags: riskFlags,
    cldd_discrepancy: componentResults?.coverage_cldd_discrepancy === true,
    cldd_mismatch_fields: mismatchFields,
    cldd_claimed_metrics: normalizeClddMetrics(
      componentResults?.coverage_cldd_claimed_metrics
    ),
    cldd_attested_metrics: normalizeClddMetrics(
      componentResults?.coverage_cldd_attested_metrics
    ),
  };
}

async function parseArtifact(filePath, root, maxJsonBytes) {
  const relPath = normalizePath(path.relative(root, filePath));

  const stat = await fs.stat(filePath);
  const base = {
    path: filePath,
    rel_path: relPath,
    size_bytes: stat.size,
    mtime: new Date(stat.mtimeMs).toISOString(),
  };

  if (stat.size > maxJsonBytes) {
    return {
      ...base,
      kind: 'json_too_large',
      parse_error: `File exceeds max-json-bytes (${maxJsonBytes})`,
      run_ids: [],
      bundle_ids: [],
      urm_ids: [],
    };
  }

  let doc;
  try {
    const raw = await fs.readFile(filePath, 'utf8');
    doc = JSON.parse(raw);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      ...base,
      kind: 'json_parse_error',
      parse_error: message,
      run_ids: [],
      bundle_ids: [],
      urm_ids: [],
    };
  }

  const kind = classifyArtifact(doc, relPath);
  const runIds = collectKeyStrings(doc, 'run_id');
  const bundleIds = collectKeyStrings(doc, 'bundle_id');
  const urmIds = collectKeyStrings(doc, 'urm_id');

  let summary = null;
  if (kind === 'proof_bundle_envelope') summary = summarizeProofBundle(doc);
  else if (kind === 'urm_document') summary = summarizeUrm(doc);
  else if (kind === 'trust_pulse') summary = summarizeTrustPulse(doc);
  else if (kind === 'verification_result') summary = summarizeVerificationResult(doc);
  else if (kind === 'commit_signature' && isRecord(doc)) {
    summary = {
      did: typeof doc.did === 'string' ? doc.did : undefined,
      message: typeof doc.message === 'string' ? doc.message : undefined,
      created_at: typeof doc.createdAt === 'string' ? doc.createdAt : undefined,
    };
  }

  return {
    ...base,
    kind,
    run_ids: runIds,
    bundle_ids: bundleIds,
    urm_ids: urmIds,
    summary,
  };
}

function newestFirst(a, b) {
  return Date.parse(b.mtime) - Date.parse(a.mtime);
}

function bundlePreferenceScore(relPath) {
  const rp = normalizePath(relPath);
  if (rp.startsWith('artifacts/poh/')) return 40;
  if (rp.startsWith('artifacts/')) return 30;
  if (rp === '.clawsig/proof_bundle.json') return 20;
  if (rp.startsWith('.clawsig/')) return 10;
  return 0;
}

function chooseBestBundle(candidates) {
  if (candidates.length === 0) return null;
  return [...candidates].sort((a, b) => {
    const scoreDelta = bundlePreferenceScore(b.rel_path) - bundlePreferenceScore(a.rel_path);
    if (scoreDelta !== 0) return scoreDelta;
    return newestFirst(a, b);
  })[0] ?? null;
}

function chooseTargetBundle(records, options) {
  const bundles = records.filter((r) => r.kind === 'proof_bundle_envelope');

  if (options.bundlePath) {
    const normalizedBundlePath = normalizePath(path.resolve(options.bundlePath));
    const exact = bundles.find((r) => normalizePath(path.resolve(r.path)) === normalizedBundlePath);
    return exact ?? null;
  }

  if (options.runId) {
    const byRun = bundles.filter((r) => r.run_ids.includes(options.runId));
    const chosenByRun = chooseBestBundle(byRun);
    if (chosenByRun) return chosenByRun;
  }

  return chooseBestBundle(bundles);
}

function makeKindCounts(records) {
  const map = new Map();
  for (const r of records) {
    map.set(r.kind, (map.get(r.kind) ?? 0) + 1);
  }
  return [...map.entries()]
    .map(([kind, count]) => ({ kind, count }))
    .sort((a, b) => b.count - a.count || a.kind.localeCompare(b.kind));
}

function artifactCatalog() {
  return [
    {
      kind: 'proof_bundle_envelope',
      description:
        'Agent-signed run envelope (event chain + receipts + attestations + metadata).',
      typical_paths: ['.clawsig/proof_bundle.json', 'artifacts/poh/**-bundle.json', '*/proof-bundle.json'],
    },
    {
      kind: 'urm_document',
      description:
        'Universal Run Manifest that binds run identity, inputs/outputs, harness metadata, and roots.',
      typical_paths: ['*/*-urm.json', '*/urm.json'],
    },
    {
      kind: 'trust_pulse',
      description:
        'Self-reported UX summary (tools/files); explicitly non-tier-uplifting evidence.',
      typical_paths: ['*/*-trust-pulse.json', '*/trust-pulse.json'],
    },
    {
      kind: 'verification_result',
      description:
        'Offline/online verifier response with deterministic status + reason/code.',
      typical_paths: ['*/*-verify.json', '*/verify.json'],
    },
    {
      kind: 'conformance_summary',
      description:
        'Executable vector run summary for protocol/firewall/regression conformance suites.',
      typical_paths: ['artifacts/conformance/**/summary.json'],
    },
    {
      kind: 'smoke_result',
      description:
        'Scenario/e2e smoke evidence (simulation and service behavior snapshots).',
      typical_paths: ['artifacts/smoke/**/result.json', 'artifacts/simulations/**/smoke.json'],
    },
    {
      kind: 'ops_summary',
      description:
        'Operational gate/watch/deploy summaries produced by protocol and service ops runners.',
      typical_paths: ['artifacts/ops/**/summary.json'],
    },
    {
      kind: 'commit_signature',
      description:
        'DID-signed commit proof envelope used for lane provenance.',
      typical_paths: ['proofs/**/commit.sig.json'],
    },
    {
      kind: 'aggregate_bundle_envelope',
      description:
        'Fleet-level signed bundle-of-bundles envelope for aggregate verification.',
      typical_paths: ['*aggregate*.json', 'artifacts/**/aggregate*.json'],
    },
    {
      kind: 'export_bundle',
      description:
        'Content-addressed export manifest with attached artifacts for offline audit packages.',
      typical_paths: ['*export*.json'],
    },
  ];
}

function buildTrace(records, targetBundle, explicitRunId) {
  if (!targetBundle && !explicitRunId) {
    return {
      run_id: null,
      bundle: null,
      related_artifacts: [],
      notes: ['No proof bundle found. Provide --bundle or --run-id, or generate a bundle first.'],
    };
  }

  const bundleSummary = targetBundle?.summary && isRecord(targetBundle.summary)
    ? targetBundle.summary
    : null;

  const bundleRunId = bundleSummary?.run_ids?.[0] ?? targetBundle?.run_ids?.[0] ?? null;
  const runId = explicitRunId ?? bundleRunId;
  const bundleId = bundleSummary?.bundle_id ?? targetBundle?.bundle_ids?.[0] ?? null;
  const urmRefId = bundleSummary?.urm_ref?.urm_id ?? null;

  const related = records
    .filter((r) => {
      if (runId && r.run_ids.includes(runId)) return true;
      if (bundleId && r.bundle_ids.includes(bundleId)) return true;
      if (urmRefId && r.urm_ids.includes(urmRefId)) return true;
      if (targetBundle && path.dirname(r.path) === path.dirname(targetBundle.path)) return true;
      return false;
    })
    .sort(newestFirst);

  const urmCandidates = related.filter((r) => r.kind === 'urm_document');
  const trustPulseCandidates = related.filter((r) => r.kind === 'trust_pulse');
  const verificationCandidates = related.filter((r) => r.kind === 'verification_result');

  let selectedUrm = null;
  if (urmRefId) {
    selectedUrm = urmCandidates.find((r) => r.summary?.urm_id === urmRefId) ?? null;
  }
  if (!selectedUrm && runId) {
    selectedUrm = urmCandidates.find((r) => r.summary?.run_id === runId) ?? null;
  }
  if (!selectedUrm) selectedUrm = urmCandidates[0] ?? null;

  const hashCheck = {
    expected: bundleSummary?.urm_ref?.resource_hash_b64u ?? null,
    actual: selectedUrm?.summary?.hash_b64u ?? null,
    match:
      typeof bundleSummary?.urm_ref?.resource_hash_b64u === 'string' &&
      typeof selectedUrm?.summary?.hash_b64u === 'string'
        ? bundleSummary.urm_ref.resource_hash_b64u === selectedUrm.summary.hash_b64u
        : null,
  };

  let selectedTrustPulse = null;
  const trustPulseRef = selectedUrm?.summary?.trust_pulse_ref ?? null;

  if (trustPulseRef?.artifact_hash_b64u) {
    selectedTrustPulse =
      trustPulseCandidates.find((r) => r.summary?.hash_b64u === trustPulseRef.artifact_hash_b64u) ??
      null;
  }
  if (!selectedTrustPulse && runId) {
    selectedTrustPulse =
      trustPulseCandidates.find((r) => r.summary?.run_id === runId) ??
      null;
  }
  if (!selectedTrustPulse) selectedTrustPulse = trustPulseCandidates[0] ?? null;

  const trustPulseHashCheck = {
    expected: trustPulseRef?.artifact_hash_b64u ?? null,
    actual: selectedTrustPulse?.summary?.hash_b64u ?? null,
    match:
      typeof trustPulseRef?.artifact_hash_b64u === 'string' &&
      typeof selectedTrustPulse?.summary?.hash_b64u === 'string'
        ? trustPulseRef.artifact_hash_b64u === selectedTrustPulse.summary.hash_b64u
        : null,
  };

  const notes = [];
  if (targetBundle && !bundleSummary?.urm_ref) {
    notes.push('Selected proof bundle has no payload.urm reference.');
  }
  if (bundleSummary?.urm_ref && !selectedUrm) {
    notes.push('Bundle references a URM but no matching URM document was found in scanned roots.');
  }
  if (trustPulseRef && !selectedTrustPulse) {
    notes.push('URM references trust_pulse metadata but no matching trust pulse artifact was found.');
  }

  const verificationResults = verificationCandidates.map((r) => ({
    path: r.rel_path,
    mtime: r.mtime,
    ...r.summary,
  }));

  const clddEnforcementFindings = [];
  const clddInformationalFindings = [];

  for (const vr of verificationResults) {
    const status = typeof vr.status === 'string' ? vr.status.toUpperCase() : '';
    const isFailure = status === 'FAIL' || status === 'INVALID';
    const hasClddSignal =
      vr.cldd_discrepancy === true ||
      (Array.isArray(vr.risk_flags) && vr.risk_flags.includes('COVERAGE_CLDD_DISCREPANCY'));

    if (!hasClddSignal && vr.code !== 'COVERAGE_CLDD_DISCREPANCY_ENFORCED') {
      continue;
    }

    const finding = {
      path: vr.path,
      status: vr.status ?? 'n/a',
      code: vr.code ?? 'n/a',
      reason: vr.reason ?? 'n/a',
    };

    if (vr.code === 'COVERAGE_CLDD_DISCREPANCY_ENFORCED' || (isFailure && hasClddSignal)) {
      clddEnforcementFindings.push(finding);
    } else {
      clddInformationalFindings.push(finding);
    }
  }

  if (
    bundleSummary?.cldd_discrepancy?.discrepancy === true &&
    clddEnforcementFindings.length === 0 &&
    clddInformationalFindings.length === 0
  ) {
    clddInformationalFindings.push({
      path: targetBundle?.rel_path ?? 'bundle',
      status: 'n/a',
      code: 'COVERAGE_CLDD_DISCREPANCY',
      reason: 'Bundle telemetry and coverage-attestation CLDD metrics differ',
    });
  }

  return {
    run_id: runId,
    bundle: targetBundle
      ? {
          path: targetBundle.rel_path,
          mtime: targetBundle.mtime,
          ...bundleSummary,
        }
      : null,
    urm: selectedUrm
      ? {
          path: selectedUrm.rel_path,
          mtime: selectedUrm.mtime,
          ...selectedUrm.summary,
          hash_check_against_bundle_ref: hashCheck,
        }
      : null,
    trust_pulse: selectedTrustPulse
      ? {
          path: selectedTrustPulse.rel_path,
          mtime: selectedTrustPulse.mtime,
          ...selectedTrustPulse.summary,
          hash_check_against_urm_ref: trustPulseHashCheck,
        }
      : null,
    delivery: {
      confidence_distribution: bundleSummary?.causal_confidence_distribution ?? null,
      low_confidence_side_effects: bundleSummary?.low_confidence_side_effects ?? [],
      cldd_discrepancy: {
        ...(bundleSummary?.cldd_discrepancy ?? {
          claimed: null,
          attested: null,
          mismatch_fields: [],
          discrepancy: false,
        }),
        enforcement_findings: clddEnforcementFindings,
        informational_findings: clddInformationalFindings,
      },
    },
    verification_results: verificationResults,
    related_artifacts: related.map((r) => ({
      kind: r.kind,
      path: r.rel_path,
      mtime: r.mtime,
      run_ids: r.run_ids,
      bundle_ids: r.bundle_ids,
      urm_ids: r.urm_ids,
    })),
    notes,
  };
}

function renderMarkdownReport(report) {
  const lines = [];

  lines.push('# Artifact Trace Report');
  lines.push('');
  lines.push(`- generated_at: ${report.generated_at}`);
  lines.push(`- root: ${report.root}`);
  lines.push(`- scanned_files: ${report.scan.files_seen}`);
  lines.push(`- parsed_files: ${report.scan.files_parsed}`);
  lines.push(`- parse_errors: ${report.scan.parse_errors}`);
  lines.push('');

  lines.push('## Artifact inventory (by kind)');
  lines.push('');
  for (const item of report.inventory.kind_counts) {
    lines.push(`- ${item.kind}: ${item.count}`);
  }
  lines.push('');

  lines.push('## Trace target');
  lines.push('');
  lines.push(`- run_id: ${report.trace.run_id ?? 'n/a'}`);
  lines.push(`- bundle: ${report.trace.bundle?.path ?? 'n/a'}`);
  lines.push(`- URM: ${report.trace.urm?.path ?? 'n/a'}`);
  lines.push(`- trust pulse: ${report.trace.trust_pulse?.path ?? 'n/a'}`);
  lines.push('');

  if (report.trace.bundle?.array_counts) {
    lines.push('### Bundle component counts');
    lines.push('');
    for (const [key, value] of Object.entries(report.trace.bundle.array_counts)) {
      lines.push(`- ${key}: ${value}`);
    }
    lines.push('');
  }

  if (report.trace.bundle?.event_types && Object.keys(report.trace.bundle.event_types).length > 0) {
    lines.push('### Event types');
    lines.push('');
    for (const [key, value] of Object.entries(report.trace.bundle.event_types)) {
      lines.push(`- ${key}: ${value}`);
    }
    lines.push('');
  }

  if (Array.isArray(report.trace.bundle?.event_timeline) && report.trace.bundle.event_timeline.length > 0) {
    lines.push('### Event timeline (first 20)');
    lines.push('');
    for (const ev of report.trace.bundle.event_timeline.slice(0, 20)) {
      lines.push(`- ${ev.timestamp ?? 'n/a'} · ${ev.event_type ?? 'unknown'} · ${ev.event_id ?? 'n/a'}`);
    }
    lines.push('');
  }

  if (Array.isArray(report.trace.bundle?.tool_summary?.by_tool_name) && report.trace.bundle.tool_summary.by_tool_name.length > 0) {
    lines.push('### Tool receipts by tool name');
    lines.push('');
    for (const item of report.trace.bundle.tool_summary.by_tool_name) {
      lines.push(`- ${item.tool_name}: ${item.count}`);
    }
    lines.push('');
  }

  if (Array.isArray(report.trace.bundle?.gateway_receipt_summary?.by_provider_model) && report.trace.bundle.gateway_receipt_summary.by_provider_model.length > 0) {
    lines.push('### Gateway receipts by provider/model');
    lines.push('');
    for (const item of report.trace.bundle.gateway_receipt_summary.by_provider_model) {
      lines.push(`- ${item.provider_model}: ${item.count}`);
    }
    lines.push('');
  }

  if (report.trace.delivery?.confidence_distribution) {
    const cd = report.trace.delivery.confidence_distribution;
    lines.push('### Causal confidence distribution');
    lines.push('');
    lines.push(`- total: ${cd.total ?? 0}`);
    lines.push(`- authoritative (>=0.99): ${cd.authoritative ?? 0}`);
    lines.push(`- inferred (>=0.5,<0.99): ${cd.inferred ?? 0}`);
    lines.push(`- low (>0,<0.5): ${cd.low ?? 0}`);
    lines.push(`- unattributed (0.0): ${cd.unattributed ?? 0}`);

    const histogram = cd.histogram && typeof cd.histogram === 'object'
      ? Object.entries(cd.histogram).sort((a, b) => a[0].localeCompare(b[0]))
      : [];
    if (histogram.length > 0) {
      lines.push('- histogram:');
      for (const [bucket, count] of histogram) {
        lines.push(`  - ${bucket}: ${count}`);
      }
    }
    lines.push('');
  }

  if (Array.isArray(report.trace.delivery?.low_confidence_side_effects) && report.trace.delivery.low_confidence_side_effects.length > 0) {
    lines.push('### Low-confidence side effects (hash-first)');
    lines.push('');
    for (const entry of report.trace.delivery.low_confidence_side_effects.slice(0, 50)) {
      lines.push(
        `- ${entry.hash_first}: confidence=${entry.confidence} effect=${entry.effect_class ?? 'n/a'} receipt=${entry.receipt_id ?? 'n/a'} phase=${entry.phase ?? 'n/a'}`
      );
    }
    if (report.trace.delivery.low_confidence_side_effects.length > 50) {
      lines.push(`- ... ${report.trace.delivery.low_confidence_side_effects.length - 50} additional low-confidence side effects omitted`);
    }
    lines.push('');
  }

  if (report.trace.delivery?.cldd_discrepancy) {
    const cldd = report.trace.delivery.cldd_discrepancy;
    lines.push('### CLDD discrepancy');
    lines.push('');
    lines.push(`- discrepancy: ${cldd.discrepancy === true ? 'true' : 'false'}`);
    if (cldd.claimed) {
      lines.push(`- claimed: unmediated=${cldd.claimed.unmediated_connections}, unmonitored=${cldd.claimed.unmonitored_spawns}, escapes=${cldd.claimed.escapes_suspected}`);
    } else {
      lines.push('- claimed: n/a');
    }
    if (cldd.attested) {
      lines.push(`- attested: unmediated=${cldd.attested.unmediated_connections}, unmonitored=${cldd.attested.unmonitored_spawns}, escapes=${cldd.attested.escapes_suspected}`);
    } else {
      lines.push('- attested: n/a');
    }
    lines.push(`- mismatch_fields: ${Array.isArray(cldd.mismatch_fields) && cldd.mismatch_fields.length > 0 ? cldd.mismatch_fields.join(', ') : 'none'}`);

    if (Array.isArray(cldd.enforcement_findings) && cldd.enforcement_findings.length > 0) {
      lines.push('- enforcement_findings:');
      for (const finding of cldd.enforcement_findings) {
        lines.push(`  - ${finding.path}: status=${finding.status} code=${finding.code}`);
      }
    }

    if (Array.isArray(cldd.informational_findings) && cldd.informational_findings.length > 0) {
      lines.push('- informational_findings:');
      for (const finding of cldd.informational_findings) {
        lines.push(`  - ${finding.path}: status=${finding.status} code=${finding.code}`);
      }
    }

    lines.push('');
  }

  if (report.trace.urm?.hash_check_against_bundle_ref) {
    const check = report.trace.urm.hash_check_against_bundle_ref;
    lines.push('### URM integrity check');
    lines.push('');
    lines.push(`- expected: ${check.expected ?? 'n/a'}`);
    lines.push(`- actual: ${check.actual ?? 'n/a'}`);
    lines.push(`- match: ${check.match === null ? 'n/a' : String(check.match)}`);
    lines.push('');
  }

  if (Array.isArray(report.trace.verification_results) && report.trace.verification_results.length > 0) {
    lines.push('### Verification results');
    lines.push('');
    for (const v of report.trace.verification_results) {
      lines.push(`- ${v.path}: status=${v.status ?? 'n/a'} code=${v.code ?? 'n/a'} at=${v.verified_at ?? 'n/a'}`);
    }
    lines.push('');
  }

  if (Array.isArray(report.trace.notes) && report.trace.notes.length > 0) {
    lines.push('### Notes');
    lines.push('');
    for (const note of report.trace.notes) {
      lines.push(`- ${note}`);
    }
    lines.push('');
  }

  lines.push('## Related artifacts');
  lines.push('');
  for (const item of report.trace.related_artifacts.slice(0, 120)) {
    lines.push(`- [${item.kind}] ${item.path}`);
  }
  if (report.trace.related_artifacts.length > 120) {
    lines.push(`- ... ${report.trace.related_artifacts.length - 120} additional artifacts omitted`);
  }
  lines.push('');

  return `${lines.join('\n')}\n`;
}

async function ensureParentDir(filePath) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
}

async function main() {
  const options = parseArgs(process.argv);

  if (options.help) {
    printHelp();
    return;
  }

  const root = path.resolve(options.root);
  const artifactsRoot = path.resolve(root, options.artifactsDir);
  const proofsRoot = path.resolve(root, options.proofsDir);
  const localClawsigRoot = path.resolve(root, '.clawsig');

  const scanRoots = [artifactsRoot, proofsRoot, localClawsigRoot]
    .filter((p, idx, arr) => arr.indexOf(p) === idx)
    .filter((p) => existsSync(p));

  const discoveredFiles = [];
  for (const scanRoot of scanRoots) {
    const files = await walkJsonFiles(scanRoot, options.maxFiles);
    discoveredFiles.push(...files);
    if (discoveredFiles.length >= options.maxFiles) break;
  }

  let parseErrors = 0;
  let filesParsed = 0;
  const records = [];

  const limitedFiles = discoveredFiles.slice(0, options.maxFiles);
  for (const filePath of limitedFiles) {
    const record = await parseArtifact(filePath, root, options.maxJsonBytes);
    if (record.kind === 'json_parse_error' || record.kind === 'json_too_large') {
      parseErrors += 1;
    } else {
      filesParsed += 1;
    }
    records.push(record);
  }

  records.sort(newestFirst);

  let targetBundle = chooseTargetBundle(records, options);

  if (options.bundlePath && !targetBundle) {
    if (!existsSync(options.bundlePath)) {
      throw new Error(`Bundle path not found: ${options.bundlePath}`);
    }
    targetBundle = await parseArtifact(options.bundlePath, root, options.maxJsonBytes);
  }

  const trace = buildTrace(records, targetBundle, options.runId);

  const report = {
    generated_at: new Date().toISOString(),
    root,
    scan: {
      scan_roots: scanRoots.map((p) => normalizePath(path.relative(root, p) || '.')),
      files_seen: limitedFiles.length,
      files_parsed: filesParsed,
      parse_errors: parseErrors,
      max_json_bytes: options.maxJsonBytes,
      max_files: options.maxFiles,
    },
    inventory: {
      kind_counts: makeKindCounts(records),
      catalog: artifactCatalog(),
    },
    trace,
  };

  const outPath = options.outPath
    ? path.resolve(options.outPath)
    : path.join(root, 'artifacts', 'ops', 'artifact-trace', isoStamp(), 'summary.json');

  await ensureParentDir(outPath);
  await fs.writeFile(outPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');

  const markdownPath = outPath.endsWith('.json')
    ? `${outPath.slice(0, -5)}.md`
    : `${outPath}.md`;
  await fs.writeFile(markdownPath, renderMarkdownReport(report), 'utf8');

  if (options.json) {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } else {
    process.stdout.write(
      `${JSON.stringify(
        {
          ok: true,
          out_path: outPath,
          markdown_path: markdownPath,
          traced_run_id: report.trace.run_id,
          traced_bundle: report.trace.bundle?.path ?? null,
          related_artifact_count: report.trace.related_artifacts.length,
        },
        null,
        2
      )}\n`
    );
  }
}

main().catch((err) => {
  process.stderr.write(`${err instanceof Error ? err.stack : String(err)}\n`);
  process.exitCode = 1;
});
