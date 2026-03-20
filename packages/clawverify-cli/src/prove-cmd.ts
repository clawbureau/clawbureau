import { access, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';

import { decryptBundle, extractPublicLayer, InspectError } from './inspect-cmd.js';

import type { ClawsigIdentity } from './identity.js';

export interface ProveOptions {
  inputPath: string;
  htmlPath?: string;
  decrypt: boolean;
  json: boolean;
  runSummaryPath?: string;
}

export interface ProofGatewaySummary {
  signed_count: number;
  signer_dids: string[];
  provider: string | null;
  model: string | null;
  gateway_id: string | null;
  latency_ms: number | null;
  timestamp: string | null;
}

export type ProofReviewBucketTone = 'good' | 'caution' | 'info' | 'action';

export interface ProofReviewBucket {
  key: 'gateway_proof' | 'execution_hygiene' | 'background_noise' | 'reviewer_action_needed';
  label: string;
  tone: ProofReviewBucketTone;
  summary: string;
  items: string[];
}

export interface ProofReport {
  input_path: string;
  run_summary_path: string | null;
  generated_at: string;
  public_layer: ReturnType<typeof extractPublicLayer>;
  harness: {
    status: string | null;
    tier: string | null;
    duration_seconds: number | null;
    timestamp: string | null;
    did: string | null;
  };
  evidence: {
    event_chain_count: number;
    receipt_count: number;
    execution_receipt_count: number;
    network_receipt_count: number;
    tool_receipt_count: number;
    files_modified_count: number | null;
    tools_used_count: number | null;
  };
  gateway: ProofGatewaySummary;
  sentinels: {
    shell_events: number;
    fs_events: number;
    net_events: number;
    net_suspicious: number;
    preload_llm_events: number;
    interpose_active: boolean;
    unmediated_connections: number;
    unmonitored_spawns: number;
    escapes_suspected: boolean;
  };
  network: {
    classification_counts: Record<string, number>;
    top_processes: Array<{ process_name: string; count: number }>;
  };
  review_buckets: ProofReviewBucket[];
  warnings: string[];
  next_steps: string[];
  verify_command: string;
  html_path?: string;
  decrypted_payload_keys?: string[];
}

type ProofReportBase = Omit<
  ProofReport,
  'input_path' | 'run_summary_path' | 'generated_at' | 'review_buckets' | 'warnings' | 'next_steps' | 'verify_command' | 'html_path'
>;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function asString(value: unknown): string | null {
  return typeof value === 'string' && value.trim().length > 0 ? value.trim() : null;
}

function asNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function pluralize(count: number, singular: string, plural = `${singular}s`): string {
  return count === 1 ? singular : plural;
}

function formatTopProcesses(processes: Array<{ process_name: string; count: number }>): string {
  if (processes.length === 0) return 'no dominant processes recorded';
  if (processes.length === 1) return `${processes[0]!.process_name} (${processes[0]!.count})`;
  if (processes.length === 2) {
    return `${processes[0]!.process_name} (${processes[0]!.count}) and ${processes[1]!.process_name} (${processes[1]!.count})`;
  }
  return `${processes[0]!.process_name} (${processes[0]!.count}), ${processes[1]!.process_name} (${processes[1]!.count}), and ${processes.length - 2} more`;
}

async function readJsonObject(path: string): Promise<Record<string, unknown>> {
  const raw = await readFile(path, 'utf-8');
  const parsed = JSON.parse(raw);
  if (!isRecord(parsed)) {
    throw new Error(`Expected JSON object in ${path}`);
  }
  return parsed;
}

async function maybeReadJsonObject(path: string): Promise<Record<string, unknown> | null> {
  try {
    await access(path);
  } catch {
    return null;
  }

  return readJsonObject(path);
}

function inferRunSummaryPath(inputPath: string): string {
  return resolve(dirname(inputPath), 'run_summary.json');
}

function summarizeGateway(payload: Record<string, unknown>): ProofGatewaySummary {
  const receipts = asArray(payload.receipts);
  const signed = receipts.filter((entry) => {
    if (!isRecord(entry)) return false;
    const inner = isRecord(entry.payload) ? entry.payload : null;
    return (
      entry.envelope_type === 'gateway_receipt' &&
      typeof entry.envelope_version === 'string' &&
      typeof entry.signer_did === 'string' &&
      !!inner &&
      typeof inner.provider === 'string'
    );
  }) as Array<Record<string, unknown>>;

  const first = signed[0];
  const firstPayload = first && isRecord(first.payload) ? first.payload : null;

  return {
    signed_count: signed.length,
    signer_dids: [...new Set(signed.map((entry) => asString(entry.signer_did)).filter(Boolean) as string[])],
    provider: asString(firstPayload?.provider),
    model: asString(firstPayload?.model),
    gateway_id: asString(firstPayload?.gateway_id),
    latency_ms: asNumber(firstPayload?.latency_ms),
    timestamp: asString(firstPayload?.timestamp),
  };
}

function summarizeNetwork(payload: Record<string, unknown>): ProofReport['network'] {
  const receipts = asArray(payload.network_receipts);
  const classificationCounts: Record<string, number> = {};
  const processCounts = new Map<string, number>();

  for (const entry of receipts) {
    if (!isRecord(entry)) continue;
    const classification = asString(entry.classification) ?? 'unknown';
    classificationCounts[classification] = (classificationCounts[classification] ?? 0) + 1;

    const processName = asString(entry.process_name) ?? 'unknown';
    processCounts.set(processName, (processCounts.get(processName) ?? 0) + 1);
  }

  const topProcesses = [...processCounts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, 5)
    .map(([process_name, count]) => ({ process_name, count }));

  return {
    classification_counts: classificationCounts,
    top_processes: topProcesses,
  };
}

function summarizeSentinels(payload: Record<string, unknown>): ProofReport['sentinels'] {
  const metadata = isRecord(payload.metadata) ? payload.metadata : null;
  const sentinels = metadata && isRecord(metadata.sentinels) ? metadata.sentinels : null;
  const interposeState = sentinels && isRecord(sentinels.interpose_state) ? sentinels.interpose_state : null;
  const cldd = interposeState && isRecord(interposeState.cldd) ? interposeState.cldd : null;

  return {
    shell_events: asNumber(sentinels?.shell_events) ?? 0,
    fs_events: asNumber(sentinels?.fs_events) ?? 0,
    net_events: asNumber(sentinels?.net_events) ?? 0,
    net_suspicious: asNumber(sentinels?.net_suspicious) ?? 0,
    preload_llm_events: asNumber(sentinels?.preload_llm_events) ?? 0,
    interpose_active: Boolean(sentinels?.interpose_active),
    unmediated_connections: asNumber(cldd?.unmediated_connections) ?? 0,
    unmonitored_spawns: asNumber(cldd?.unmonitored_spawns) ?? 0,
    escapes_suspected: Boolean(cldd?.escapes_suspected),
  };
}

function deriveReviewBuckets(report: ProofReportBase): ProofReviewBucket[] {
  const gatewayItems = report.gateway.signed_count > 0
    ? [
        `Signed gateway receipt count: ${report.gateway.signed_count}.`,
        report.gateway.signer_dids[0] ? `Gateway signer DID: ${report.gateway.signer_dids[0]}.` : null,
        report.gateway.gateway_id ? `Gateway identity: ${report.gateway.gateway_id}.` : null,
        report.gateway.provider && report.gateway.model
          ? `Provider/model: ${report.gateway.provider} / ${report.gateway.model}.`
          : null,
      ].filter(Boolean) as string[]
    : ['No signed gateway receipt is present in the bundle yet.'];

  const gatewayBucket: ProofReviewBucket = {
    key: 'gateway_proof',
    label: 'Gateway proof',
    tone: report.gateway.signed_count > 0 ? 'good' : 'action',
    summary:
      report.gateway.signed_count > 0
        ? `${report.gateway.signed_count} signed gateway ${pluralize(report.gateway.signed_count, 'receipt')} ${report.gateway.provider && report.gateway.model ? `${report.gateway.signed_count === 1 ? 'covers' : 'cover'} ${report.gateway.provider} / ${report.gateway.model}` : 'present'}${report.gateway.gateway_id ? ` via ${report.gateway.gateway_id}` : ''}.`
        : 'Gateway-tier proof is not complete yet because no signed gateway receipt was found.',
    items: gatewayItems,
  };

  const executionItems: string[] = [];
  if (report.sentinels.interpose_active) {
    executionItems.push('Interpose monitoring was active during the run.');
  } else {
    executionItems.push('Interpose monitoring was not active for this run.');
  }
  if (report.sentinels.unmediated_connections > 0) {
    executionItems.push(`CLDD observed ${report.sentinels.unmediated_connections} unmediated ${pluralize(report.sentinels.unmediated_connections, 'connection')}.`);
  }
  if (report.sentinels.unmonitored_spawns > 0) {
    executionItems.push(`CLDD observed ${report.sentinels.unmonitored_spawns} unmonitored ${pluralize(report.sentinels.unmonitored_spawns, 'spawn')}.`);
  }
  if (report.sentinels.escapes_suspected) {
    executionItems.push('CLDD flagged the run as escape-suspected.');
  }
  if (executionItems.length === 1 && report.sentinels.interpose_active) {
    executionItems.push('No unmonitored spawns or escape flags were recorded.');
  }

  const executionTone: ProofReviewBucketTone = report.sentinels.escapes_suspected || report.sentinels.unmonitored_spawns > 0
    ? 'action'
    : report.sentinels.unmediated_connections > 0 || !report.sentinels.interpose_active
      ? 'caution'
      : 'good';

  const executionBucket: ProofReviewBucket = {
    key: 'execution_hygiene',
    label: 'Execution hygiene',
    tone: executionTone,
    summary:
      executionTone === 'good'
        ? 'Execution telemetry looks clean for reviewer-facing proof presentation.'
        : executionTone === 'caution'
          ? 'Execution telemetry captured the run, but there are environment-level signals worth noting.'
          : 'Execution telemetry recorded signals that should be explained before treating the run as clean external evidence.',
    items: executionItems,
  };

  const infraCount = report.network.classification_counts.infrastructure ?? 0;
  const expectedCount = report.network.classification_counts.expected ?? 0;
  const otherBackgroundCount = Object.entries(report.network.classification_counts)
    .filter(([key]) => key !== 'suspicious')
    .reduce((sum, [, count]) => sum + count, 0);
  const backgroundBucket: ProofReviewBucket = {
    key: 'background_noise',
    label: 'Background noise / ignorable infra',
    tone: otherBackgroundCount > 0 ? 'info' : 'good',
    summary:
      otherBackgroundCount > 0
        ? `${otherBackgroundCount} network ${pluralize(otherBackgroundCount, 'receipt')} look like environment/background traffic, led by ${formatTopProcesses(report.network.top_processes)}.`
        : 'No notable background or infrastructure traffic was recorded.',
    items: [
      infraCount > 0 ? `${infraCount} ${pluralize(infraCount, 'receipt')} were classified as infrastructure traffic.` : null,
      expectedCount > 0 ? `${expectedCount} ${pluralize(expectedCount, 'receipt')} were classified as expected traffic.` : null,
      report.network.top_processes.length > 0 ? `Top observed processes: ${formatTopProcesses(report.network.top_processes)}.` : null,
    ].filter(Boolean) as string[],
  };

  const reviewerActionItems: string[] = [];
  if (report.gateway.signed_count === 0) {
    reviewerActionItems.push('Do not present this run as gateway-tier proof until a signed gateway receipt is present.');
  }
  if (report.sentinels.net_suspicious > 0) {
    reviewerActionItems.push(`Review ${report.sentinels.net_suspicious} suspicious network ${pluralize(report.sentinels.net_suspicious, 'receipt')} in the raw bundle before external sharing.`);
  }
  if (report.sentinels.unmediated_connections > 0) {
    reviewerActionItems.push('Decide whether the CLDD unmediated-connection signal is expected for this runtime or should be suppressed/tuned for cleaner reports.');
  }
  if (report.sentinels.unmonitored_spawns > 0) {
    reviewerActionItems.push(`Confirm ${report.sentinels.unmonitored_spawns} unmonitored ${pluralize(report.sentinels.unmonitored_spawns, 'spawn')} are expected for this environment.`);
  }
  if (report.sentinels.escapes_suspected) {
    reviewerActionItems.push('Resolve or explain the CLDD escape-suspected signal before using this as buyer-facing proof.');
  }

  const reviewerActionBucket: ProofReviewBucket = {
    key: 'reviewer_action_needed',
    label: 'Reviewer action needed',
    tone: reviewerActionItems.length > 0 ? 'action' : 'good',
    summary:
      reviewerActionItems.length > 0
        ? `${reviewerActionItems.length} reviewer ${pluralize(reviewerActionItems.length, 'follow-up')} remain before this report reads as clean external evidence.`
        : 'No extra reviewer follow-up is needed beyond standard verifier checks.',
    items: reviewerActionItems.length > 0 ? reviewerActionItems : ['No extra reviewer action is required.'],
  };

  return [gatewayBucket, executionBucket, backgroundBucket, reviewerActionBucket];
}

function deriveWarnings(report: ProofReportBase): string[] {
  const warnings: string[] = [];

  if (report.gateway.signed_count === 0) {
    warnings.push('No signed gateway receipt found in the bundle.');
  }
  if (report.sentinels.net_suspicious > 0) {
    warnings.push(`${report.sentinels.net_suspicious} suspicious network events were recorded.`);
  }
  if (report.sentinels.unmediated_connections > 0) {
    warnings.push(`${report.sentinels.unmediated_connections} unmediated connections were observed by CLDD.`);
  }
  if (report.sentinels.unmonitored_spawns > 0) {
    warnings.push(`${report.sentinels.unmonitored_spawns} unmonitored spawns were detected.`);
  }
  if (report.sentinels.escapes_suspected) {
    warnings.push('CLDD marked the run as escape-suspected.');
  }

  return warnings;
}

function deriveNextSteps(report: Pick<ProofReport, 'gateway' | 'warnings' | 'verify_command'>): string[] {
  const steps: string[] = [];
  if (report.gateway.signed_count > 0) {
    steps.push('Signed gateway evidence is present; attach this report to PRs, submissions, or reviews.');
  } else {
    steps.push('Re-run under clawproxy mode until a signed gateway receipt is present.');
  }
  steps.push(`Canonical offline verifier command: ${report.verify_command}`);
  if (report.warnings.length > 0) {
    steps.push('Review the bucketed warning/action cards before treating the run as clean reviewer-facing evidence.');
  }
  return steps;
}

export function buildProofReport(args: {
  inputPath: string;
  bundle: Record<string, unknown>;
  runSummary: Record<string, unknown> | null;
  decryptedPayload?: Record<string, unknown>;
}): ProofReport {
  const { inputPath, bundle, runSummary, decryptedPayload } = args;
  const publicLayer = extractPublicLayer(bundle);
  const payload = isRecord(bundle.payload) ? bundle.payload : {};
  const gateway = summarizeGateway(payload);
  const sentinels = summarizeSentinels(payload);
  const network = summarizeNetwork(payload);

  const base: ProofReportBase = {
    public_layer: publicLayer,
    harness: {
      status: asString(runSummary?.status),
      tier: asString(runSummary?.tier),
      duration_seconds: asNumber(runSummary?.duration_seconds),
      timestamp: asString(runSummary?.timestamp),
      did: asString(runSummary?.did),
    },
    evidence: {
      event_chain_count: asArray(payload.event_chain).length,
      receipt_count: asArray(payload.receipts).length,
      execution_receipt_count: asArray(payload.execution_receipts).length,
      network_receipt_count: asArray(payload.network_receipts).length,
      tool_receipt_count: asArray(payload.tool_receipts).length,
      files_modified_count: Array.isArray(runSummary?.files_modified) ? runSummary.files_modified.length : null,
      tools_used_count: Array.isArray(runSummary?.tools_used) ? runSummary.tools_used.length : null,
    },
    gateway,
    sentinels,
    network,
    decrypted_payload_keys: decryptedPayload ? Object.keys(decryptedPayload) : undefined,
  };

  const reviewBuckets = deriveReviewBuckets(base);
  const warnings = deriveWarnings(base);
  const verifyCommand = `clawverify verify proof-bundle --input ${inputPath}`;

  return {
    input_path: inputPath,
    run_summary_path: runSummary ? inferRunSummaryPath(inputPath) : null,
    generated_at: new Date().toISOString(),
    ...base,
    review_buckets: reviewBuckets,
    warnings,
    next_steps: deriveNextSteps({ gateway, warnings, verify_command: verifyCommand }),
    verify_command: verifyCommand,
  };
}

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function renderList(items: string[]): string {
  if (items.length === 0) return '<li>None</li>';
  return items.map((item) => `<li>${escapeHtml(item)}</li>`).join('');
}

function renderKeyValueRows(rows: Array<[string, string | number | null | undefined]>): string {
  return rows
    .map(([label, value]) => `<div class="row"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value == null ? '—' : String(value))}</strong></div>`)
    .join('');
}

function toneToPillClass(tone: ProofReviewBucketTone): string {
  switch (tone) {
    case 'good':
      return 'ok';
    case 'caution':
      return 'warn';
    case 'action':
      return 'danger';
    default:
      return 'info';
  }
}

function renderReviewBucket(bucket: ProofReviewBucket): string {
  return `<article class="card">
    <div class="bucket-header">
      <h2>${escapeHtml(bucket.label)}</h2>
      <span class="pill ${toneToPillClass(bucket.tone)}">${escapeHtml(bucket.tone.toUpperCase())}</span>
    </div>
    <p class="bucket-summary">${escapeHtml(bucket.summary)}</p>
    <ul>${renderList(bucket.items)}</ul>
  </article>`;
}

export function renderProofReportHtml(report: ProofReport): string {
  const reviewerActionBucket = report.review_buckets.find((bucket) => bucket.key === 'reviewer_action_needed');
  const warningsClass = (reviewerActionBucket?.tone === 'action' || report.warnings.length > 0) ? 'warn' : 'ok';
  const reviewerActionCount = reviewerActionBucket?.items.length ?? 0;
  const rawJson = escapeHtml(JSON.stringify(report, null, 2));

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Clawsig proof report</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #07111f;
      --panel: rgba(12, 23, 40, 0.88);
      --line: rgba(148, 163, 184, 0.18);
      --text: #e6eef8;
      --muted: #95a7bf;
      --accent: #76e4c3;
      --warn: #f6c177;
      --danger: #f38ba8;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, sans-serif;
      background: radial-gradient(circle at top, #0d2340 0%, var(--bg) 58%);
      color: var(--text);
      line-height: 1.5;
    }
    main { max-width: 1100px; margin: 0 auto; padding: 32px 20px 72px; }
    .hero, .card {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 20px;
      box-shadow: 0 20px 80px rgba(0,0,0,0.28);
    }
    .hero { padding: 28px; margin-bottom: 20px; }
    h1, h2, h3, p { margin: 0; }
    .eyebrow { color: var(--accent); text-transform: uppercase; letter-spacing: .12em; font-size: 12px; margin-bottom: 10px; }
    .subtitle { color: var(--muted); margin-top: 10px; max-width: 760px; }
    .grid { display: grid; gap: 16px; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); }
    .card { padding: 20px; }
    .card h2 { font-size: 16px; margin-bottom: 14px; }
    .row { display: flex; justify-content: space-between; gap: 16px; padding: 8px 0; border-bottom: 1px solid rgba(148, 163, 184, 0.08); }
    .row:last-child { border-bottom: 0; }
    .row span { color: var(--muted); }
    .pill {
      display: inline-flex; align-items: center; gap: 8px;
      border-radius: 999px; padding: 8px 12px; font-size: 13px; margin: 6px 8px 0 0;
      border: 1px solid var(--line);
      color: var(--text);
    }
    .pill.ok { background: rgba(118, 228, 195, 0.12); border-color: rgba(118, 228, 195, 0.35); }
    .pill.warn { background: rgba(246, 193, 119, 0.14); border-color: rgba(246, 193, 119, 0.35); }
    .pill.danger { background: rgba(243, 139, 168, 0.14); border-color: rgba(243, 139, 168, 0.35); }
    .pill.info { background: rgba(147, 197, 253, 0.12); border-color: rgba(147, 197, 253, 0.35); }
    .bucket-header { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
    .bucket-summary { margin-top: 10px; color: var(--text); }
    ul { margin: 10px 0 0 18px; color: var(--muted); }
    li + li { margin-top: 8px; }
    code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
    pre {
      margin: 0; white-space: pre-wrap; word-break: break-word;
      padding: 16px; border-radius: 16px; background: rgba(2, 6, 23, 0.58); border: 1px solid rgba(148,163,184,0.12);
      color: #d7e3f4; font-size: 12px;
    }
    details { margin-top: 16px; }
    summary { cursor: pointer; color: var(--accent); }
    .footer-note { color: var(--muted); font-size: 13px; margin-top: 18px; }
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <div class="eyebrow">Clawsig proof report</div>
      <h1>Human-readable proof bundle view</h1>
      <p class="subtitle">This report renders the proof bundle into reviewer-facing evidence. Canonical verification still comes from the bundle itself and the offline verifier/service verifier.</p>
      <div>
        <span class="pill ok">Harness status: ${escapeHtml(report.harness.status ?? 'unknown')}</span>
        <span class="pill ok">Claimed tier: ${escapeHtml(report.harness.tier ?? 'unknown')}</span>
        <span class="pill ${warningsClass}">Reviewer actions: ${reviewerActionCount}</span>
        <span class="pill ok">Signed gateway receipts: ${report.gateway.signed_count}</span>
      </div>
    </section>

    <section class="grid" style="margin-bottom:16px;">
      ${report.review_buckets.map(renderReviewBucket).join('')}
    </section>

    <section class="grid">
      <article class="card">
        <h2>Identity & bundle</h2>
        ${renderKeyValueRows([
          ['Bundle ID', report.public_layer.bundle_id],
          ['Agent DID', report.public_layer.agent_did],
          ['Signer DID', report.public_layer.signer_did],
          ['Visibility', report.public_layer.visibility ?? 'public'],
          ['Encrypted payload', report.public_layer.has_encrypted_payload ? 'yes' : 'no'],
          ['Generated at', report.generated_at],
        ])}
      </article>

      <article class="card">
        <h2>Gateway proof</h2>
        ${renderKeyValueRows([
          ['Provider', report.gateway.provider],
          ['Model', report.gateway.model],
          ['Gateway', report.gateway.gateway_id],
          ['Signer DID', report.gateway.signer_dids[0] ?? null],
          ['Latency (ms)', report.gateway.latency_ms],
          ['Receipt timestamp', report.gateway.timestamp],
        ])}
      </article>

      <article class="card">
        <h2>Evidence counts</h2>
        ${renderKeyValueRows([
          ['Event chain entries', report.evidence.event_chain_count],
          ['Gateway receipts', report.evidence.receipt_count],
          ['Execution receipts', report.evidence.execution_receipt_count],
          ['Network receipts', report.evidence.network_receipt_count],
          ['Tool receipts', report.evidence.tool_receipt_count],
          ['Files modified', report.evidence.files_modified_count],
          ['Tools used', report.evidence.tools_used_count],
        ])}
      </article>

      <article class="card">
        <h2>Sentinel telemetry</h2>
        ${renderKeyValueRows([
          ['Shell events', report.sentinels.shell_events],
          ['FS events', report.sentinels.fs_events],
          ['Net events', report.sentinels.net_events],
          ['Suspicious net events', report.sentinels.net_suspicious],
          ['Preload LLM events', report.sentinels.preload_llm_events],
          ['Interpose active', report.sentinels.interpose_active ? 'yes' : 'no'],
          ['Unmediated connections', report.sentinels.unmediated_connections],
          ['Unmonitored spawns', report.sentinels.unmonitored_spawns],
          ['Escapes suspected', report.sentinels.escapes_suspected ? 'yes' : 'no'],
        ])}
      </article>

      <article class="card">
        <h2>Raw warning strings (debug)</h2>
        <ul>${renderList(report.warnings)}</ul>
      </article>

      <article class="card">
        <h2>Next steps</h2>
        <ul>${renderList(report.next_steps)}</ul>
        <p class="footer-note">Verifier command: <code>${escapeHtml(report.verify_command)}</code></p>
      </article>
    </section>

    <section class="grid" style="margin-top:16px;">
      <article class="card">
        <h2>Top network processes</h2>
        <ul>${renderList(report.network.top_processes.map((entry) => `${entry.process_name} — ${entry.count}`))}</ul>
      </article>
      <article class="card">
        <h2>Network classifications</h2>
        <ul>${renderList(Object.entries(report.network.classification_counts).map(([k, v]) => `${k} — ${v}`))}</ul>
      </article>
    </section>

    <section class="card" style="margin-top:16px;">
      <h2>Raw report JSON</h2>
      <details>
        <summary>Expand canonical human-readable report payload</summary>
        <pre>${rawJson}</pre>
      </details>
    </section>
  </main>
</body>
</html>`;
}

function printHumanReadable(report: ProofReport): void {
  process.stdout.write('\n=== Clawsig proof report ===\n\n');
  process.stdout.write(`Bundle ID        : ${report.public_layer.bundle_id ?? '—'}\n`);
  process.stdout.write(`Agent DID        : ${report.public_layer.agent_did ?? '—'}\n`);
  process.stdout.write(`Harness status   : ${report.harness.status ?? 'unknown'}\n`);
  process.stdout.write(`Claimed tier     : ${report.harness.tier ?? 'unknown'}\n`);
  process.stdout.write(`Gateway proof    : ${report.gateway.signed_count > 0 ? 'SIGNED' : 'MISSING'}\n`);
  process.stdout.write(`Gateway signer   : ${report.gateway.signer_dids[0] ?? '—'}\n`);
  process.stdout.write(`Provider/model   : ${(report.gateway.provider ?? '—')} / ${(report.gateway.model ?? '—')}\n`);
  process.stdout.write(`Evidence counts  : event_chain=${report.evidence.event_chain_count}, receipts=${report.evidence.receipt_count}, network=${report.evidence.network_receipt_count}, execution=${report.evidence.execution_receipt_count}\n`);
  process.stdout.write('\nReview buckets:\n');
  for (const bucket of report.review_buckets) {
    process.stdout.write(`  ${bucket.label.padEnd(31)} [${bucket.tone.toUpperCase()}] ${bucket.summary}\n`);
    for (const item of bucket.items) {
      process.stdout.write(`    - ${item}\n`);
    }
  }
  process.stdout.write('\nNext steps:\n');
  for (const step of report.next_steps) {
    process.stdout.write(`  - ${step}\n`);
  }
  if (report.html_path) {
    process.stdout.write(`\nHTML report      : ${report.html_path}\n`);
  }
  process.stdout.write('\n');
}

export async function runProveReport(options: ProveOptions): Promise<ProofReport> {
  const bundle = await readJsonObject(options.inputPath);
  let decryptedPayload: Record<string, unknown> | undefined;

  if (options.decrypt) {
    const { loadIdentity } = await import('./identity.js');
    const identity = await loadIdentity();
    if (!identity) {
      throw new InspectError(
        'INSPECT_NO_IDENTITY',
        'No persistent identity found. Run `clawsig init` before using --decrypt.',
      );
    }
    decryptedPayload = decryptBundle(bundle, identity as ClawsigIdentity);
  }

  const runSummaryPath = options.runSummaryPath
    ? resolve(options.runSummaryPath)
    : inferRunSummaryPath(options.inputPath);
  const runSummary = await maybeReadJsonObject(runSummaryPath);

  const report = buildProofReport({
    inputPath: resolve(options.inputPath),
    bundle,
    runSummary,
    decryptedPayload,
  });

  if (options.htmlPath) {
    const htmlPath = resolve(options.htmlPath);
    await writeFile(htmlPath, renderProofReportHtml(report), 'utf-8');
    report.html_path = htmlPath;
  }

  if (options.json) {
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  } else {
    printHumanReadable(report);
  }

  return report;
}
