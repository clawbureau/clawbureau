/**
 * clawsig wrap — one-line agent verification.
 *
 * Wraps any agent process transparently:
 * 1. Generates an ephemeral DID
 * 2. Starts a local interceptor proxy
 * 3. Spawns the child process with env overrides pointing to the proxy
 * 4. On exit: compiles proof bundle, optionally publishes to VaaS
 */

import { spawn, execFile, type ChildProcess } from 'node:child_process';
import { readFile, writeFile, mkdir, unlink, copyFile, chmod, stat, rename } from 'node:fs/promises';
import { openSync, readSync, closeSync } from 'node:fs';
import { promisify } from 'node:util';
import { join, dirname, basename, relative } from 'node:path';
import { tmpdir } from 'node:os';
import { mkdtemp } from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';

const isWindows = process.platform === 'win32';
import {
  generateEphemeralDid,
  startLocalProxy,
  FsSentinel,
  NetSentinel,
  analyzeCommand,
  compilePolicyToBash,
  InterposeState,
  hashJsonB64u,
  resolveEffectivePolicyFromSignedBundle,
  filterExecutionReceipts,
  filterNetworkReceipts,
  computeBundleSummary,
} from '@clawbureau/clawsig-sdk';
import { identityToAgentDid } from './identity.js';
import { loadIdentityForWrap } from './fleet.js';
import { validateVisibilityArgs, applyVisibility } from './epv-crypto.js';
import { activeBountyPath, loadActiveBounty } from './active-bounty.js';
import type { VisibilityMode } from './epv-crypto.js';
import type { BundleSummaryStats } from '@clawbureau/clawsig-sdk';
import type {
  SignedEnvelope,
  ProofBundlePayload,
  ExecutionReceiptPayload,
  NetworkReceiptPayload,
  GatewayReceiptPayload,
  EgressPolicyReceiptPayload,
  EffectivePolicyBindingMetadata,
  RunnerMeasurementBindingMetadata,
  RunnerMeasurementManifest,
  LocalPolicy,
  CommandAnalysis,
  FsEvent,
} from '@clawbureau/clawsig-sdk';

const execFileAsync = promisify(execFile);

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface WrapOptions {
  /** Publish proof bundle to the VaaS ledger. Defaults to true. */
  publish: boolean;
  /** Optional file path to write the proof bundle JSON. */
  outputPath?: string;
  /** Show full diagnostic output (sentinel status, receipt details). Defaults to false. */
  verbose?: boolean;
  /** EPV-002: Proof visibility mode. Defaults to 'public'. */
  visibility?: VisibilityMode;
  /** EPV-002: Viewer DIDs for non-public visibility modes. */
  viewerDids?: string[];
}

interface VaaSResponse {
  ok: boolean;
  tier?: string;
  bundle_id?: string;
  urls?: {
    badge?: string;
    ledger?: string;
  };
  error?: string;
}

interface PublishResult {
  badgeUrl?: string;
  ledgerUrl?: string;
}

interface RunSummaryJson {
  status: 'PASS' | 'FAIL';
  tier: 'self' | 'gateway';
  cost_usd: number;
  tools_used: string[];
  files_modified: string[];
  policy_violations: number;
  network_connections: number;
  bundle_path: string;
  did: string;
  timestamp: string;
  duration_seconds: number;
  runtime_profile_id: string;
  runtime_profile_status: RuntimeProfileStatus;
  runtime_hygiene_verdict: RuntimeHygieneVerdict;
}

type RuntimeProfileStatus = 'active' | 'fallback';
type RuntimeHygieneVerdict = 'good' | 'caution' | 'action';

interface RuntimeBaselineSnapshot {
  captured: boolean;
  captured_at: string;
  source: 'ps';
  process_count: number;
  process_hash_b64u: string | null;
  command_sample: string[];
  error_reason?: string;
}

interface ProofedRuntimeProfile {
  profile_id: string;
  profile_version: '1';
  mode: 'privacy_assurance';
  activation: {
    status: RuntimeProfileStatus;
    reasons: string[];
  };
  baseline: RuntimeBaselineSnapshot;
}

interface RuntimeHygieneNoiseBudget {
  unmediated_connections: {
    caution_at: number;
    action_at: number;
  };
  net_suspicious: {
    caution_at: number;
    action_at: number;
  };
  unmonitored_spawns: {
    action_at: number;
  };
  escapes_suspected: {
    action_when_true: boolean;
  };
}

interface RuntimeClddMetrics {
  unmediated_connections: number;
  unmonitored_spawns: number;
  escapes_suspected: boolean;
}

interface RuntimeHygieneEvidence {
  receipt_version: '1';
  profile_id: string;
  profile_status: RuntimeProfileStatus;
  interpose_active: boolean;
  verdict: RuntimeHygieneVerdict;
  reviewer_action_required: boolean;
  noise_budget: RuntimeHygieneNoiseBudget;
  counts: {
    unmediated_connections: number;
    unmonitored_spawns: number;
    escapes_suspected: boolean;
    net_suspicious: number;
    background_network_receipts: number;
    filtered_noise_execution: number;
    filtered_noise_network: number;
  };
  buckets: {
    background_noise: string[];
    caution: string[];
    action_required: string[];
  };
}

interface LoadedPolicyArtifacts {
  policy: LocalPolicy | null;
  policySourcePath: string | null;
  policyBinding: EffectivePolicyBindingMetadata | null;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const VAAS_URL = 'https://api.clawverify.com/v1/verify';
const CLAWSIG_DIR = '.clawsig';
const BUNDLE_FILE = 'proof_bundle.json';
const RUN_SUMMARY_FILE = 'run_summary.json';
const PROOFED_RUNTIME_PROFILE_ID = 'prv.run.v1.proofed-minimal';
const RUNTIME_HYGIENE_BACKGROUND_CLASSES = [
  'infrastructure',
  'expected',
  'system_noise',
  'local',
  'fd_inheritance',
] as const;
const RUNTIME_HYGIENE_NOISE_BUDGET: RuntimeHygieneNoiseBudget = {
  unmediated_connections: { caution_at: 1, action_at: 3 },
  net_suspicious: { caution_at: 1, action_at: 3 },
  unmonitored_spawns: { action_at: 1 },
  escapes_suspected: { action_when_true: true },
};

function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

async function sha256TextB64u(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return toBase64Url(new Uint8Array(digest));
}

async function sha256BytesB64u(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', bytes as BufferSource);
  return toBase64Url(new Uint8Array(digest));
}

function resolveLocalFilePathFromImportSpecifier(specifier: string): string | null {
  if (specifier.startsWith('file://')) {
    try {
      return fileURLToPath(specifier);
    } catch {
      return null;
    }
  }
  if (specifier.startsWith('/')) return specifier;
  return null;
}

async function sha256FileB64u(path: string | null): Promise<string | null> {
  if (!path) return null;
  try {
    const fileBytes = await readFile(path);
    return sha256BytesB64u(new Uint8Array(fileBytes));
  } catch {
    return null;
  }
}

function isObjectRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function parseBooleanEnv(value: string | undefined): boolean {
  if (!value) return false;
  const normalized = value.trim().toLowerCase();
  return normalized === '1' || normalized === 'true' || normalized === 'yes' || normalized === 'y';
}

function parseAbsoluteHttpUrl(value: string | undefined): URL | null {
  if (!value || value.trim().length === 0) return null;
  try {
    const parsed = new URL(value.trim());
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

function normalizeEgressHost(raw: string): string | null {
  const trimmed = raw.trim().toLowerCase();
  if (!trimmed) return null;

  try {
    if (trimmed.includes('://')) {
      const host = new URL(trimmed).hostname.toLowerCase();
      return host.length > 0 ? host : null;
    }
    return trimmed.split('/')[0]?.split(':')[0] ?? null;
  } catch {
    return null;
  }
}

function parseProofedEgressAllowlist(raw: string | undefined, requiredHost: string): string[] {
  const hosts = new Set<string>();
  if (!raw || raw.trim().length === 0) {
    hosts.add(requiredHost.toLowerCase());
    return [...hosts];
  }

  for (const entry of raw.split(',')) {
    const normalized = normalizeEgressHost(entry);
    if (normalized) hosts.add(normalized);
  }
  return [...hosts];
}

function buildProofedChildEgressAllowlist(): string[] {
  return ['127.0.0.1', 'localhost', '::1'];
}

function findCliFlagValue(args: string[], flag: string): string | undefined {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (!arg) continue;
    if (arg === flag) return args[i + 1];
    if (arg.startsWith(`${flag}=`)) return arg.slice(flag.length + 1);
  }
  return undefined;
}

function rewriteCliFlagValue(args: string[], flag: string, value: string): string[] {
  const next = [...args];
  for (let i = 0; i < next.length; i++) {
    const arg = next[i];
    if (!arg) continue;
    if (arg === flag) {
      if (i + 1 < next.length) next[i + 1] = value;
      return next;
    }
    if (arg.startsWith(`${flag}=`)) {
      next[i] = `${flag}=${value}`;
      return next;
    }
  }
  return [...next, flag, value];
}

function getPiGoogleCompatModelId(commandName: string, args: string[]): string | undefined {
  if (commandName !== 'pi') return undefined;
  if (findCliFlagValue(args, '--provider') !== 'google') return undefined;
  const model = findCliFlagValue(args, '--model');
  return typeof model === 'string' && model.trim().length > 0 ? model.trim() : undefined;
}

function toSignedGatewayReceiptEnvelope(
  receipt: Record<string, unknown>,
): SignedEnvelope<GatewayReceiptPayload> | null {
  if (isSignedGatewayReceiptEnvelope(receipt)) {
    return receipt;
  }
  return null;
}

function isGatewayReceiptEnvelope(
  value: unknown,
): value is SignedEnvelope<GatewayReceiptPayload> {
  return (
    isObjectRecord(value) &&
    value.envelope_type === 'gateway_receipt' &&
    isObjectRecord(value.payload)
  );
}

function isSignedGatewayReceiptEnvelope(
  value: unknown,
): value is SignedEnvelope<GatewayReceiptPayload> {
  return (
    isGatewayReceiptEnvelope(value) &&
    value.envelope_version === '1' &&
    typeof (value as unknown as Record<string, unknown>).payload_hash_b64u === 'string' &&
    typeof (value as unknown as Record<string, unknown>).signature_b64u === 'string' &&
    typeof (value as unknown as Record<string, unknown>).signer_did === 'string'
  );
}

interface FallbackSigner {
  did: string;
  sign(data: Uint8Array): Promise<string>;
}

async function ensureMinimalHarnessEvidence(args: {
  bundle: SignedEnvelope<ProofBundlePayload>;
  signer: FallbackSigner;
  runId: string;
  commandName: string;
  exitCode: number;
}): Promise<void> {
  const { bundle, signer, runId, commandName, exitCode } = args;

  const receipts = Array.isArray(bundle.payload.receipts)
    ? [...bundle.payload.receipts]
    : [];

  const hasGatewayReceipt = receipts.some((r) => isSignedGatewayReceiptEnvelope(r));

  if (!hasGatewayReceipt) {
    const now = new Date().toISOString();
    const requestHash = await sha256TextB64u(
      `clawsig:fallback:request:${runId}:${commandName}`
    );
    const responseHash = await sha256TextB64u(
      `clawsig:fallback:response:${runId}:${commandName}:${exitCode}`
    );

    const payload: GatewayReceiptPayload = {
      receipt_version: '1',
      receipt_id: `rcpt_fallback_${crypto.randomUUID().slice(0, 8)}`,
      gateway_id: 'gw_clawsig_fallback',
      provider: 'unknown',
      model: `${commandName}-fallback`,
      request_hash_b64u: requestHash,
      response_hash_b64u: responseHash,
      tokens_input: 0,
      tokens_output: 0,
      latency_ms: 0,
      timestamp: now,
      binding: {
        run_id: runId,
      },
    };

    const payloadHash = await sha256TextB64u(JSON.stringify(payload));
    const signature = await signer.sign(new TextEncoder().encode(payloadHash));

    receipts.push({
      envelope_version: '1',
      envelope_type: 'gateway_receipt',
      payload,
      payload_hash_b64u: payloadHash,
      hash_algorithm: 'SHA-256',
      signature_b64u: signature,
      algorithm: 'Ed25519',
      signer_did: signer.did,
      issued_at: now,
    });

    bundle.payload.receipts = receipts;
  }

  const hasEventChain =
    Array.isArray(bundle.payload.event_chain) && bundle.payload.event_chain.length > 0;

  if (!hasEventChain) {
    const gatewayReceipt = receipts.find((r) => isSignedGatewayReceiptEnvelope(r));
    const ts = gatewayReceipt?.payload?.timestamp ?? new Date().toISOString();

    const payloadHash = await sha256TextB64u(
      JSON.stringify({
        kind: 'llm_call',
        run_id: runId,
        receipt_id: gatewayReceipt?.payload?.receipt_id ?? null,
        request_hash_b64u: gatewayReceipt?.payload?.request_hash_b64u ?? null,
        response_hash_b64u: gatewayReceipt?.payload?.response_hash_b64u ?? null,
      })
    );

    const eventBase = {
      event_id: `evt_fallback_${crypto.randomUUID().slice(0, 8)}`,
      run_id: runId,
      event_type: 'llm_call',
      timestamp: ts,
      payload_hash_b64u: payloadHash,
      prev_hash_b64u: null,
    } as const;

    const eventHash = await sha256TextB64u(JSON.stringify(eventBase));

    bundle.payload.event_chain = [
      {
        ...eventBase,
        event_hash_b64u: eventHash,
      },
    ];
  }
}

async function resealProofBundleEnvelope(
  bundle: SignedEnvelope<ProofBundlePayload>,
  signer: FallbackSigner,
): Promise<void> {
  const payloadHash = await hashJsonB64u(bundle.payload);
  const signature = await signer.sign(new TextEncoder().encode(payloadHash));
  bundle.payload_hash_b64u = payloadHash;
  bundle.signature_b64u = signature;
}

function normalizeCanonicalHostList(entries: readonly string[]): string[] {
  const unique = new Set<string>();
  for (const entry of entries) {
    const normalized = normalizeEgressHost(entry);
    if (normalized) unique.add(normalized);
  }
  return [...unique].sort((a, b) => a.localeCompare(b));
}

async function buildRunnerMeasurementBinding(args: {
  clawproxyUrl: string;
  allowedProxyDestinations: string[];
  allowedChildDestinations: string[];
  effectivePolicyHashB64u?: string;
  shellSentinelEnabled: boolean;
  interposeEnabled: boolean;
  interposeLibraryPath: string | null;
}): Promise<RunnerMeasurementBindingMetadata> {
  const preloadPath = resolveLocalFilePathFromImportSpecifier(resolvePreloadPath());
  const nodePreloadSentinelPath =
    resolveLocalFilePathFromImportSpecifier(resolveNodePreloadSentinelPath());
  const sentinelShellSourcePath = args.shellSentinelEnabled ? resolveSentinelShellPath() : null;
  const sentinelShellPolicyPath = sentinelShellSourcePath
    ? join(dirname(sentinelShellSourcePath), 'sentinel-shell-policy.sh')
    : null;

  const [
    preloadHash,
    nodePreloadSentinelHash,
    sentinelShellHash,
    sentinelShellPolicyHash,
    interposeLibraryHash,
  ] = await Promise.all([
    sha256FileB64u(preloadPath),
    sha256FileB64u(nodePreloadSentinelPath),
    sha256FileB64u(sentinelShellSourcePath),
    sha256FileB64u(sentinelShellPolicyPath),
    sha256FileB64u(args.interposeEnabled ? args.interposeLibraryPath : null),
  ]);

  if (!preloadHash) {
    throw new Error(
      'PRV_RUNNER_MEASUREMENT_INCOMPLETE: failed to hash @clawbureau/clawsig-sdk/preload',
    );
  }
  if (!nodePreloadSentinelHash) {
    throw new Error(
      'PRV_RUNNER_MEASUREMENT_INCOMPLETE: failed to hash @clawbureau/clawsig-sdk/node-preload-sentinel',
    );
  }
  if (args.shellSentinelEnabled && (!sentinelShellHash || !sentinelShellPolicyHash)) {
    throw new Error(
      'PRV_RUNNER_MEASUREMENT_INCOMPLETE: failed to hash sentinel shell assets while shell sentinel is enabled',
    );
  }
  if (args.interposeEnabled && !interposeLibraryHash) {
    throw new Error(
      'PRV_RUNNER_MEASUREMENT_INCOMPLETE: failed to hash interpose library while interpose is enabled',
    );
  }

  const manifest: RunnerMeasurementManifest = {
    manifest_version: '1',
    runtime: {
      platform: process.platform,
      arch: process.arch,
      node_version: process.version,
    },
    proofed: {
      proofed_mode: true,
      clawproxy_url: args.clawproxyUrl,
      allowed_proxy_destinations: [...args.allowedProxyDestinations].sort((a, b) => a.localeCompare(b)),
      allowed_child_destinations: [...args.allowedChildDestinations].sort((a, b) => a.localeCompare(b)),
      sentinels: {
        shell_enabled: args.shellSentinelEnabled,
        interpose_enabled: args.interposeEnabled,
        preload_enabled: true,
        fs_enabled: true,
        net_enabled: true,
      },
    },
    policy: {
      ...(args.effectivePolicyHashB64u
        ? { effective_policy_hash_b64u: args.effectivePolicyHashB64u }
        : {}),
    },
    artifacts: {
      preload_hash_b64u: preloadHash,
      node_preload_sentinel_hash_b64u: nodePreloadSentinelHash,
      sentinel_shell_hash_b64u: sentinelShellHash,
      sentinel_shell_policy_hash_b64u: sentinelShellPolicyHash,
      interpose_library_hash_b64u: interposeLibraryHash,
    },
  };

  const manifestHashB64u = await hashJsonB64u(manifest);

  return {
    binding_version: '1',
    hash_algorithm: 'SHA-256',
    manifest_hash_b64u: manifestHashB64u,
    manifest,
  };
}

async function captureRuntimeBaselineSnapshot(): Promise<RuntimeBaselineSnapshot> {
  const capturedAt = new Date().toISOString();
  if (isWindows) {
    return {
      captured: false,
      captured_at: capturedAt,
      source: 'ps',
      process_count: 0,
      process_hash_b64u: null,
      command_sample: [],
      error_reason: 'baseline_capture_not_supported_on_windows',
    };
  }

  try {
    const { stdout } = await execFileAsync('ps', ['-Ao', 'comm='], {
      timeout: 4_000,
      maxBuffer: 4 * 1024 * 1024,
    });
    const commands = stdout
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.length > 0);

    if (commands.length === 0) {
      return {
        captured: false,
        captured_at: capturedAt,
        source: 'ps',
        process_count: 0,
        process_hash_b64u: null,
        command_sample: [],
        error_reason: 'baseline_capture_returned_no_processes',
      };
    }

    const counts = new Map<string, number>();
    for (const command of commands) {
      counts.set(command, (counts.get(command) ?? 0) + 1);
    }

    const normalizedLines = [...counts.entries()]
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([command, count]) => `${command}\t${count}`);
    const processHash = await sha256TextB64u(normalizedLines.join('\n'));
    const commandSample = [...counts.entries()]
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
      .slice(0, 8)
      .map(([command, count]) => `${command}:${count}`);

    return {
      captured: true,
      captured_at: capturedAt,
      source: 'ps',
      process_count: commands.length,
      process_hash_b64u: processHash,
      command_sample: commandSample,
    };
  } catch (err) {
    return {
      captured: false,
      captured_at: capturedAt,
      source: 'ps',
      process_count: 0,
      process_hash_b64u: null,
      command_sample: [],
      error_reason: `baseline_capture_failed:${err instanceof Error ? err.message : 'unknown'}`,
    };
  }
}

function buildProofedRuntimeProfile(args: {
  baseline: RuntimeBaselineSnapshot;
  hasShellSentinel: boolean;
  interposeActive: boolean;
}): ProofedRuntimeProfile {
  const activationReasons: string[] = [];
  if (!args.baseline.captured) {
    activationReasons.push(args.baseline.error_reason ?? 'baseline_capture_unavailable');
  }
  if (!args.hasShellSentinel && !isWindows) {
    activationReasons.push('sentinel_shell_unavailable');
  }
  if (!args.interposeActive) {
    activationReasons.push(
      isWindows
        ? 'interpose_not_supported_on_windows'
        : 'interpose_not_active',
    );
  }

  return {
    profile_id: PROOFED_RUNTIME_PROFILE_ID,
    profile_version: '1',
    mode: 'privacy_assurance',
    activation: {
      status: activationReasons.length > 0 ? 'fallback' : 'active',
      reasons: activationReasons,
    },
    baseline: args.baseline,
  };
}

function summarizeNetworkClassifications(
  receipts: NetworkReceiptPayload[],
): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const receipt of receipts) {
    const key = receipt.classification?.trim() || 'unknown';
    counts[key] = (counts[key] ?? 0) + 1;
  }
  return counts;
}

function buildRuntimeHygieneEvidence(args: {
  profile: ProofedRuntimeProfile;
  cldd: RuntimeClddMetrics;
  interposeActive: boolean;
  netSuspicious: number;
  classificationCounts: Record<string, number>;
  filteredOutExecution: number;
  filteredOutNetwork: number;
}): RuntimeHygieneEvidence {
  const backgroundNoise: string[] = [];
  const caution: string[] = [];
  const actionRequired: string[] = [];

  const backgroundNetworkReceipts = RUNTIME_HYGIENE_BACKGROUND_CLASSES.reduce(
    (sum, key) => sum + (args.classificationCounts[key] ?? 0),
    0,
  );

  if (backgroundNetworkReceipts > 0) {
    backgroundNoise.push(
      `${backgroundNetworkReceipts} network receipts matched baseline/background classifications.`,
    );
  }

  if (args.filteredOutExecution > 0 || args.filteredOutNetwork > 0) {
    backgroundNoise.push(
      `Filtered runtime noise receipts: execution=${args.filteredOutExecution}, network=${args.filteredOutNetwork}.`,
    );
  }

  if (args.profile.activation.status === 'fallback') {
    caution.push(
      `Runtime profile is in fallback mode (${args.profile.activation.reasons.join(', ')}).`,
    );
  }

  if (!args.interposeActive) {
    caution.push('Interpose monitoring was not active; CLDD confidence is reduced.');
  }

  const unmediated = args.cldd.unmediated_connections;
  if (
    unmediated >= RUNTIME_HYGIENE_NOISE_BUDGET.unmediated_connections.caution_at &&
    unmediated < RUNTIME_HYGIENE_NOISE_BUDGET.unmediated_connections.action_at
  ) {
    caution.push(
      `CLDD unmediated connections (${unmediated}) are above the caution threshold (${RUNTIME_HYGIENE_NOISE_BUDGET.unmediated_connections.caution_at}).`,
    );
  }

  if (
    args.netSuspicious >= RUNTIME_HYGIENE_NOISE_BUDGET.net_suspicious.caution_at &&
    args.netSuspicious < RUNTIME_HYGIENE_NOISE_BUDGET.net_suspicious.action_at
  ) {
    caution.push(
      `Suspicious network receipts (${args.netSuspicious}) are above the caution threshold (${RUNTIME_HYGIENE_NOISE_BUDGET.net_suspicious.caution_at}).`,
    );
  }

  if (unmediated >= RUNTIME_HYGIENE_NOISE_BUDGET.unmediated_connections.action_at) {
    actionRequired.push(
      `CLDD unmediated connections (${unmediated}) exceeded the action threshold (${RUNTIME_HYGIENE_NOISE_BUDGET.unmediated_connections.action_at}).`,
    );
  }

  if (args.netSuspicious >= RUNTIME_HYGIENE_NOISE_BUDGET.net_suspicious.action_at) {
    actionRequired.push(
      `Suspicious network receipts (${args.netSuspicious}) exceeded the action threshold (${RUNTIME_HYGIENE_NOISE_BUDGET.net_suspicious.action_at}).`,
    );
  }

  if (args.cldd.unmonitored_spawns >= RUNTIME_HYGIENE_NOISE_BUDGET.unmonitored_spawns.action_at) {
    actionRequired.push(
      `CLDD detected ${args.cldd.unmonitored_spawns} unmonitored ${args.cldd.unmonitored_spawns === 1 ? 'spawn' : 'spawns'} (action threshold ${RUNTIME_HYGIENE_NOISE_BUDGET.unmonitored_spawns.action_at}).`,
    );
  }

  if (RUNTIME_HYGIENE_NOISE_BUDGET.escapes_suspected.action_when_true && args.cldd.escapes_suspected) {
    actionRequired.push('CLDD marked this run as escape-suspected.');
  }

  let verdict: RuntimeHygieneVerdict = 'good';
  if (actionRequired.length > 0) verdict = 'action';
  else if (caution.length > 0) verdict = 'caution';

  return {
    receipt_version: '1',
    profile_id: args.profile.profile_id,
    profile_status: args.profile.activation.status,
    interpose_active: args.interposeActive,
    verdict,
    reviewer_action_required: actionRequired.length > 0,
    noise_budget: RUNTIME_HYGIENE_NOISE_BUDGET,
    counts: {
      unmediated_connections: args.cldd.unmediated_connections,
      unmonitored_spawns: args.cldd.unmonitored_spawns,
      escapes_suspected: args.cldd.escapes_suspected,
      net_suspicious: args.netSuspicious,
      background_network_receipts: backgroundNetworkReceipts,
      filtered_noise_execution: args.filteredOutExecution,
      filtered_noise_network: args.filteredOutNetwork,
    },
    buckets: {
      background_noise: backgroundNoise,
      caution,
      action_required: actionRequired,
    },
  };
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

/**
 * Run the full clawsig wrap flow.
 *
 * @param command - The command to spawn (e.g. "python", "node")
 * @param args - Arguments for the command
 * @param options - Wrap options (publish, output path)
 * @returns The child process exit code
 */
export async function wrap(
  command: string,
  args: string[],
  options: WrapOptions,
): Promise<number> {
  const wrapStartedAtMs = Date.now();
  const { publish, outputPath, verbose = false, visibility = 'public', viewerDids = [] } = options;

  /** Write diagnostic line to stderr, only in verbose mode. */
  const diag = (msg: string) => {
    if (verbose) process.stderr.write(msg);
  };

  // Quiet mode: single startup line
  if (!verbose) {
    process.stderr.write(`\x1b[2mclawsig: securing execution...\x1b[0m\n`);
  }

  // 1. Load persistent identity or active fleet identity, else fall back to ephemeral DID
  const persistentIdentity = await loadIdentityForWrap();
  let agentDid;
  if (persistentIdentity) {
    agentDid = await identityToAgentDid(persistentIdentity.identity);
    if (persistentIdentity.source === 'fleet') {
      process.stderr.write(
        `\n\x1b[36m[clawsig]\x1b[0m Fleet DID (${persistentIdentity.fleetName}): ${agentDid.did}\n`,
      );
    } else {
      process.stderr.write(`\n\x1b[36m[clawsig]\x1b[0m Persistent DID: ${agentDid.did}\n`);
    }
  } else {
    agentDid = await generateEphemeralDid();
    process.stderr.write(`\n\x1b[33m[clawsig]\x1b[0m No persistent identity found. Run \`clawsig init\` to create one.\n`);
    process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Ephemeral DID: ${agentDid.did}\n`);
  }
  const runId = `run_${crypto.randomUUID()}`;

  // EPV-002: Validate visibility args early (fail-closed before spawning child)
  let epvMode: ReturnType<typeof validateVisibilityArgs> | null = null;
  if (visibility !== 'public') {
    const resolvedViewerDids = [...viewerDids];
    let loadedRequesterDid = false;
    if (visibility === 'requester' && resolvedViewerDids.length === 0) {
      const path = activeBountyPath();
      try {
        const activeBounty = await loadActiveBounty(undefined, { strict: true });
        if (!activeBounty) {
          throw new Error(
            `No active bounty context found at ${path}. Claim a bounty first or pass --viewer-did <requester_did>.`,
          );
        }
        if (activeBounty.workerDid !== agentDid.did) {
          throw new Error(
            `Active bounty worker DID (${activeBounty.workerDid}) does not match current identity DID (${agentDid.did}). ` +
            'Re-claim the bounty with this identity or pass --viewer-did explicitly.',
          );
        }
        if (!activeBounty.requesterDid) {
          throw new Error(
            `Active bounty context at ${path} does not include requester DID. ` +
            'Pass --viewer-did <requester_did> explicitly or use a different visibility mode.',
          );
        }
        resolvedViewerDids.push(activeBounty.requesterDid);
        loadedRequesterDid = true;
        diag('\x1b[36m[clawsig]\x1b[0m EPV: loaded requester DID from .clawsig/active-bounty.json\n');
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        process.stderr.write(`\x1b[31m[clawsig]\x1b[0m EPV error: ${msg}\n`);
        return 2;
      }
    }

    try {
      epvMode = validateVisibilityArgs(visibility, resolvedViewerDids, agentDid.did);
      diag(`\x1b[36m[clawsig]\x1b[0m Visibility: ${epvMode.mode} (${epvMode.resolvedViewerDids.length} viewer(s))\n`);
    } catch (err) {
      let msg = err instanceof Error ? err.message : String(err);
      if (loadedRequesterDid) {
        msg = `Requester DID loaded from ${activeBountyPath()} is invalid: ${msg}`;
      }
      process.stderr.write(`\x1b[31m[clawsig]\x1b[0m EPV error: ${msg}\n`);
      return 2;
    }
  }

  diag(`\n\x1b[36m[clawsig]\x1b[0m Agent DID: ${agentDid.did}\n`);
  diag(`\x1b[36m[clawsig]\x1b[0m Run ID: ${runId}\n`);

  // 2. Load local policy source (signed bundle preferred) and compile for bash sentinel
  let loadedPolicy: LoadedPolicyArtifacts;
  try {
    loadedPolicy = await loadPolicyArtifacts();
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`\x1b[31m[clawsig]\x1b[0m Policy load failure: ${message}\n`);
    return 2;
  }

  const policy = loadedPolicy.policy;
  if (policy) {
    const compiledPolicyPath = join(process.cwd(), '.clawsig', 'policy.compiled');
    if (!isWindows && loadedPolicy.policySourcePath) {
      await compilePolicyToBash(loadedPolicy.policySourcePath, compiledPolicyPath).catch(() => {});
      diag(`\x1b[36m[clawsig]\x1b[0m Policy loaded: ${policy.statements.length} statements (compiled for sentinel)\n`);
    } else {
      diag(`\x1b[36m[clawsig]\x1b[0m Policy loaded: ${policy.statements.length} statements (active in Sieve)\n`);
    }
  }

  if (loadedPolicy.policyBinding) {
    diag(
      `\x1b[36m[clawsig]\x1b[0m Effective policy resolved: ` +
      `${loadedPolicy.policyBinding.effective_policy_hash_b64u} ` +
      `(layers=${loadedPolicy.policyBinding.effective_policy_snapshot.applied_layers.length})\n`,
    );
  }

  // 3. Set up deep execution sentinels
  const tmpDir = await mkdtemp(join(tmpdir(), 'clawsig-'));
  const traceFile = join(tmpDir, 'shell-trace.jsonl');
  await writeFile(traceFile, '', 'utf-8'); // Create empty trace file

  // Copy sentinel-shell.sh and sentinel-shell-policy.sh to temp dir (Unix only)
  let sentinelShellPath: string | null = null;
  if (!isWindows) {
    try {
      const sdkSentinelPath = resolveSentinelShellPath();
      sentinelShellPath = join(tmpDir, 'sentinel-shell.sh');
      await copyFile(sdkSentinelPath, sentinelShellPath);
      await chmod(sentinelShellPath, 0o755).catch(() => {});

      const sdkPolicyPath = join(dirname(sdkSentinelPath), 'sentinel-shell-policy.sh');
      const destPolicyPath = join(tmpDir, 'sentinel-shell-policy.sh');
      await copyFile(sdkPolicyPath, destPolicyPath).catch(() => {});
      await chmod(destPolicyPath, 0o755).catch(() => {});

      diag(`\x1b[36m[clawsig]\x1b[0m Sentinel Shell: ACTIVE (trap DEBUG + policy evaluator)\n`);
    } catch {
      diag(`\x1b[33m[clawsig]\x1b[0m Sentinel Shell: disabled (could not locate sentinel-shell.sh)\n`);
    }
  } else {
    diag(`\x1b[33m[clawsig]\x1b[0m Sentinel Shell: disabled (Windows — BASH_ENV not available)\n`);
  }

  // Start FS Sentinel — pass traceFile explicitly (child writes to it, parent reads)
  const fsSentinel = new FsSentinel({
    watchDirs: [process.cwd()],
    traceFile,
  });
  fsSentinel.start();
  diag(`\x1b[36m[clawsig]\x1b[0m FS Sentinel: ACTIVE (fs.watch + trace polling)\n`);

  // Start Network Sentinel
  const netSentinel = new NetSentinel({
    pollIntervalMs: 500,
  });
  // PID set after spawn

  // 4. Start local proxy with Causal Sieve
  // Use passthrough mode by default (forward directly to upstream provider).
  // For real gateway receipts via clawproxy, callers must opt in and provide a
  // valid CST/scoped token via CLAWSIG_CLAWPROXY_TOKEN (or X_CST/X_SCOPED_TOKEN)
  // plus provider auth that clawproxy can relay upstream.
  const proofedMode =
    parseBooleanEnv(process.env['CLAWSIG_PROOFED']) ||
    parseBooleanEnv(process.env['CLAWSIG_PROOFED_MODE']);
  const requestedPassthrough = !process.env['CLAWSIG_USE_CLAWPROXY'];
  const usePassthrough = proofedMode ? false : requestedPassthrough;
  const configuredClawproxyUrl = process.env['CLAWSIG_CLAWPROXY_URL']?.trim();
  const effectiveClawproxyUrl = configuredClawproxyUrl || 'https://clawproxy.com';
  const parsedProofedClawproxyUrl = proofedMode ? parseAbsoluteHttpUrl(effectiveClawproxyUrl) : null;
  const configuredClawproxyToken =
    process.env['CLAWSIG_CLAWPROXY_TOKEN']?.trim() ||
    process.env['X_CST']?.trim() ||
    process.env['X_SCOPED_TOKEN']?.trim();
  const clawproxyHost = proofedMode
    ? parsedProofedClawproxyUrl?.hostname.toLowerCase() ?? null
    : normalizeEgressHost(effectiveClawproxyUrl);

  if (proofedMode && !parsedProofedClawproxyUrl) {
    process.stderr.write(
      '\x1b[31m[clawsig]\x1b[0m PRV_EGRESS_CONFIG_INVALID: CLAWSIG_CLAWPROXY_URL must be a valid absolute URL in proofed mode.\n',
    );
    return 2;
  }

  if (proofedMode && !loadedPolicy.policyBinding) {
    process.stderr.write(
      '\x1b[31m[clawsig]\x1b[0m PRV_POLICY_BINDING_REQUIRED: proofed mode requires a signed policy bundle via CLAWSIG_POLICY_BUNDLE_PATH or .clawsig/policy.bundle.json.\n',
    );
    return 2;
  }

  const proofedEgressAllowlist = proofedMode
    ? parseProofedEgressAllowlist(process.env['CLAWSIG_PROOFED_EGRESS_ALLOWLIST'], clawproxyHost!)
    : [];
  const proofedChildEgressAllowlist = proofedMode
    ? buildProofedChildEgressAllowlist()
    : [];

  if (proofedMode) {
    diag('\x1b[36m[clawsig]\x1b[0m Proofed mode: enabled (proxy-only + deny-by-default egress)\n');
    if (requestedPassthrough) {
      diag('\x1b[33m[clawsig]\x1b[0m Proofed mode: disabling passthrough fallback and forcing clawproxy mediation\n');
    }
    diag(`\x1b[36m[clawsig]\x1b[0m Proofed proxy egress allowlist: ${proofedEgressAllowlist.join(', ')}\n`);
    diag(`\x1b[36m[clawsig]\x1b[0m Proofed child egress allowlist: ${proofedChildEgressAllowlist.join(', ')}\n`);
  }

  const proxy = await startLocalProxy({
    agentDid,
    runId,
    policy,
    cwd: process.cwd(),
    passthrough: usePassthrough,
    ...(configuredClawproxyUrl || proofedMode ? { clawproxyUrl: effectiveClawproxyUrl } : {}),
    ...(configuredClawproxyToken ? { proxyToken: configuredClawproxyToken } : {}),
    ...(loadedPolicy.policyBinding
      ? { effectivePolicyHashB64u: loadedPolicy.policyBinding.effective_policy_hash_b64u }
      : {}),
    ...(proofedMode
      ? {
          enforceEgressAllowlist: true,
          egressAllowlist: proofedEgressAllowlist,
        }
      : {}),
    onViolation: (v) => {
      process.stderr.write(
        `\x1b[31m[clawsig:guillotine]\x1b[0m VIOLATION: ${v.reason}\n`,
      );
    },
  });
  diag(`\x1b[36m[clawsig]\x1b[0m Local proxy listening on 127.0.0.1:${proxy.port}\n`);
  diag(`\x1b[36m[clawsig]\x1b[0m Causal Sieve: ACTIVE (tool observability enabled)\n`);
  if (usePassthrough) {
    diag(`\x1b[36m[clawsig]\x1b[0m Mode: passthrough (direct to upstream, Sieve-only)\n`);
  } else if (configuredClawproxyUrl || proofedMode) {
    diag(`\x1b[36m[clawsig]\x1b[0m Mode: clawproxy (${effectiveClawproxyUrl})\n`);
    if (!configuredClawproxyToken) {
      diag(`\x1b[33m[clawsig]\x1b[0m clawproxy token missing; signed gateway receipts may not be collected\n`);
    }
  }

  // 4b. Build and resolve the interposition library (Layer 6)
  const disableInterpose = process.env['CLAWSIG_DISABLE_INTERPOSE'] === '1';
  const interposeLib = disableInterpose ? null : await resolveInterposeLibrary(tmpDir);
  if (interposeLib) {
    diag(`\x1b[36m[clawsig]\x1b[0m Interpose Sentinel: ACTIVE (${interposeLib.mechanism})\n`);
  } else {
    const reason = disableInterpose
      ? 'disabled by CLAWSIG_DISABLE_INTERPOSE=1'
      : (isWindows ? 'Windows gracefully bypassed' : 'no C compiler or cached lib');
    diag(`\x1b[33m[clawsig]\x1b[0m Interpose Sentinel: disabled (${reason})\n`);
  }

  const runtimeBaseline = await captureRuntimeBaselineSnapshot();
  const runtimeProfile = buildProofedRuntimeProfile({
    baseline: runtimeBaseline,
    hasShellSentinel: !!sentinelShellPath,
    interposeActive: !!interposeLib,
  });
  diag(
    `\x1b[36m[clawsig]\x1b[0m Runtime profile: ${runtimeProfile.profile_id} ` +
      `(${runtimeProfile.activation.status}) baseline_processes=${runtimeProfile.baseline.process_count}\n`,
  );

  // 5. Spawn child process with env overrides
  const commandName = basename(command).toLowerCase();
  const forceBaseUrlOverride = process.env['CLAWSIG_FORCE_BASE_URL_OVERRIDE'] === '1';
  const disableBaseUrlOverride = !proofedMode && commandName === 'codex' && !forceBaseUrlOverride;
  const piGoogleCompatModelId =
    !usePassthrough && configuredClawproxyToken
      ? getPiGoogleCompatModelId(commandName, args)
      : undefined;
  const usePiGoogleCompat = typeof piGoogleCompatModelId === 'string';
  const childArgs = usePiGoogleCompat
    ? rewriteCliFlagValue(args, '--provider', 'clawsig-google-proxy')
    : args;

  const childEnv: Record<string, string | undefined> = {
    ...process.env,
    CLAWSIG_RUN_ID: runId,
    CLAWSIG_AGENT_DID: agentDid.did,
    ...(loadedPolicy.policyBinding
      ? { CLAWSIG_EFFECTIVE_POLICY_HASH_B64U: loadedPolicy.policyBinding.effective_policy_hash_b64u }
      : {}),

    // RED TEAM FIX #6: Socket-level interception preload.
    CLAWSIG_PROXY_PORT: String(proxy.port),
    CLAWSIG_PROXY_URL: `http://127.0.0.1:${proxy.port}`,
    NODE_OPTIONS: [
      process.env['NODE_OPTIONS'],
      `--import ${resolvePreloadPath()}`,
      `--import ${resolveNodePreloadSentinelPath()}`,
    ].filter(Boolean).join(' '),

    // NOTE: We intentionally DO NOT set HTTP_PROXY/HTTPS_PROXY.
    // Our local proxy is HTTP-only and cannot handle CONNECT tunneling,
    // so setting these vars causes HTTPS requests to hang indefinitely.
    // Instead we rely on:
    //   - OPENAI_BASE_URL / ANTHROPIC_BASE_URL (SDK-level redirect)
    //   - NODE_OPTIONS --import preload.mjs (patches fetch/https in Node)
    //   - LD_PRELOAD / DYLD_INSERT_LIBRARIES (syscall-level observation)

    // Deep Execution Sentinels
    // BASH_ENV: auto-sourced by every bash subshell (trap DEBUG)
    // ENV: sourced by POSIX sh in some configurations
    ...(sentinelShellPath ? {
      BASH_ENV: sentinelShellPath,
      ENV: sentinelShellPath,
    } : {}),
    CLAWSIG_TRACE_FILE: traceFile,

    // Layer 6: Syscall interposition via LD_PRELOAD / DYLD_INSERT_LIBRARIES
    // Hooks connect(), open(), openat(), execve(), posix_spawn(), sendto()
    ...(interposeLib ? interposeLib.env : {}),
    ...(proofedMode ? {
      CLAWSIG_ENFORCE_EGRESS_ALLOWLIST: '1',
      CLAWSIG_EGRESS_ALLOWLIST: proofedChildEgressAllowlist.join(','),
    } : {}),
  };

  if (!proofedMode) {
    delete childEnv['CLAWSIG_ENFORCE_EGRESS_ALLOWLIST'];
    delete childEnv['CLAWSIG_EGRESS_ALLOWLIST'];
  }

  if (usePiGoogleCompat && piGoogleCompatModelId) {
    const piAgentDir = join(tmpDir, 'pi-agent');
    await mkdir(piAgentDir, { recursive: true });
    const piModelsPath = join(piAgentDir, 'models.json');
    const apiKeyEnv = process.env['GOOGLE_API_KEY'] ? 'GOOGLE_API_KEY' : 'GEMINI_API_KEY';
    const piModels = {
      providers: {
        'clawsig-google-proxy': {
          baseUrl: `http://127.0.0.1:${proxy.port}/v1/proxy/google`,
          api: 'openai-completions',
          apiKey: apiKeyEnv,
          authHeader: true,
          compat: {
            supportsDeveloperRole: false,
            supportsReasoningEffort: false,
          },
          models: [
            {
              id: piGoogleCompatModelId,
              name: `${piGoogleCompatModelId} (clawsig google proxy)`,
              reasoning: false,
              input: ['text'],
              contextWindow: 1048576,
              maxTokens: 65536,
              cost: {
                input: 0,
                output: 0,
                cacheRead: 0,
                cacheWrite: 0,
              },
            },
          ],
        },
      },
    };
    await writeFile(piModelsPath, JSON.stringify(piModels, null, 2), 'utf-8');
    childEnv['PI_CODING_AGENT_DIR'] = piAgentDir;
  }

  if (!disableBaseUrlOverride) {
    childEnv['OPENAI_BASE_URL'] = `http://127.0.0.1:${proxy.port}/v1/proxy/openai`;
    childEnv['OPENAI_API_BASE'] = childEnv['OPENAI_BASE_URL'];
    childEnv['ANTHROPIC_BASE_URL'] = `http://127.0.0.1:${proxy.port}/v1/proxy/anthropic`;
    childEnv['GEMINI_BASE_URL'] = `http://127.0.0.1:${proxy.port}/v1/proxy/google`;
    childEnv['GOOGLE_GENERATIVE_AI_BASE_URL'] = childEnv['GEMINI_BASE_URL'];
  } else {
    diag(`\x1b[33m[clawsig]\x1b[0m Provider base override disabled for ${commandName} (OAuth compatibility). Set CLAWSIG_FORCE_BASE_URL_OVERRIDE=1 to force.\n`);
    delete childEnv['OPENAI_BASE_URL'];
    delete childEnv['OPENAI_API_BASE'];
  }

  // Pass through existing API keys from parent env
  if (process.env['OPENAI_API_KEY']) {
    childEnv['OPENAI_API_KEY'] = process.env['OPENAI_API_KEY'];
  }
  if (process.env['ANTHROPIC_API_KEY']) {
    childEnv['ANTHROPIC_API_KEY'] = process.env['ANTHROPIC_API_KEY'];
  }

  if (usePiGoogleCompat) {
    diag(
      `\x1b[33m[clawsig]\x1b[0m pi google-provider compat: using temp PI_CODING_AGENT_DIR=${childEnv['PI_CODING_AGENT_DIR']} with provider clawsig-google-proxy for model ${piGoogleCompatModelId}\n`,
    );
  }

  if (proofedMode && commandName === 'codex' && !forceBaseUrlOverride) {
    diag('\x1b[33m[clawsig]\x1b[0m Proofed mode: forcing provider base URL override for codex\n');
  }

  diag(`\x1b[36m[clawsig]\x1b[0m Spawning: ${command} ${childArgs.join(' ')}\n\n`);

  let childPid = 0;
  let childProcess: ChildProcess | null = null;

  // Handle signals gracefully: forward to child instead of killing parent first.
  // SIGINT: user pressed Ctrl+C (terminal interrupt)
  // SIGTERM: process manager (systemd, Docker, interactive_shell autoExitOnQuiet)
  // SIGHUP: terminal closed (SSH disconnect, terminal tab close)
  //
  // Without these handlers, Node.js default behavior kills the parent immediately
  // on SIGTERM/SIGHUP. This prevents the bundle compilation phase (phase 6) from
  // running, producing zero proof artifacts. This is the root cause of
  // "clawsig wrap produces no proof bundle when killed via SIGTERM".
  //
  // The fix: intercept all three signals, forward to child, let child exit
  // normally, and the 'exit' event resolves the promise → bundle compiles.
  const forwardSignalToChild = (signal: NodeJS.Signals) => {
    if (childProcess && !childProcess.killed) {
      process.stderr.write(`\n\x1b[36m[clawsig]\x1b[0m Received ${signal}, forwarding to child (PID ${childProcess.pid ?? '?'})...\n`);
      childProcess.kill(signal);
    }
  };
  const sigintHandler = () => forwardSignalToChild('SIGINT');
  const sigtermHandler = () => forwardSignalToChild('SIGTERM');
  const sighupHandler = () => forwardSignalToChild('SIGHUP');
  process.on('SIGINT', sigintHandler);
  process.on('SIGTERM', sigtermHandler);
  if (!isWindows) process.on('SIGHUP', sighupHandler);

  const exitCode = await new Promise<number>((resolve) => {
    childProcess = spawn(command, childArgs, {
      env: childEnv,
      stdio: 'inherit',
      shell: isWindows, // Windows needs shell:true to resolve .cmd/.bat aliases (npm, npx, etc.)
    });

    childPid = childProcess.pid ?? 0;

    // Track child PID for network sentinel
    if (childProcess.pid) {
      netSentinel.setTargetPid(childProcess.pid);
    }
    netSentinel.start();
    diag(`\x1b[36m[clawsig]\x1b[0m Net Sentinel: ACTIVE (${childPid ? `PID ${childPid}` : 'all connections'})\n`);

    childProcess.on('error', (err) => {
      process.stderr.write(`\n\x1b[31m[clawsig]\x1b[0m Failed to spawn: ${err.message}\n`);
      resolve(1);
    });

    childProcess.on('exit', (code) => {
      resolve(code ?? 1);
    });
  });

  process.off('SIGINT', sigintHandler);
  process.off('SIGTERM', sigtermHandler);
  if (!isWindows) process.off('SIGHUP', sighupHandler);

  // 6. Stop sentinels, harvest data, compile proof bundle
  await fsSentinel.stop();
  netSentinel.stop();

  diag(`\n\x1b[36m[clawsig]\x1b[0m Child exited with code ${exitCode}\n`);
  diag(`\x1b[36m[clawsig]\x1b[0m Receipts collected: ${proxy.receiptCount}\n`);

  // Harvest Sentinel Shell trace
  const shellEvents = await harvestShellTrace(traceFile);
  const executionReceipts = await synthesizeExecutionReceipts(shellEvents, agentDid.did, runId);

  // Harvest Interpose Sentinel trace (same JSONL file, layer="interpose")
  const interposeEvents = await harvestInterposeTrace(traceFile);
  const interposeReceipts = await synthesizeInterposeReceipts(interposeEvents, agentDid.did, runId);

  // Build InterposeState oracle — ground truth PID tree + bound ports from C library
  const interposeOracle = new InterposeState(childPid);
  await interposeOracle.ingestTrace(traceFile);

  // Harvest Preload trace (same JSONL file, layer="preload") → gateway receipts
  const preloadEvents = await harvestPreloadTrace(traceFile);
  const preloadGatewayReceipts = await synthesizePreloadGatewayReceipts(preloadEvents, agentDid.did, runId);

  // Harvest TLS SNI events (cross-runtime: Bun, Python, Go, Rust via C interpose)
  const sniEvents = await harvestTlsSniTrace(traceFile);
  const sniGatewayReceipts = await synthesizeSniGatewayReceipts(sniEvents, agentDid.did, runId);

  // Harvest Network Sentinel events
  const netEvents = netSentinel.getEvents();
  const networkReceipts = await synthesizeNetworkReceipts(netEvents, agentDid.did, runId);

  const fallbackClddMetrics = (() => {
    const unmonitoredSpawnPids = new Set<number>();

    for (const event of netEvents) {
      if (typeof event.pid !== 'number') continue;
      if (!interposeOracle.isAgentPid(event.pid)) {
        unmonitoredSpawnPids.add(event.pid);
      }
    }

    const unmediatedConnections =
      netEvents.length > 0
        ? netEvents.filter(
            (event) =>
              typeof event.pid !== 'number' ||
              !interposeOracle.isAgentPid(event.pid)
          ).length
        : 0;

    return {
      unmediated_connections: unmediatedConnections,
      unmonitored_spawns: unmonitoredSpawnPids.size,
      escapes_suspected:
        unmediatedConnections > 0 || unmonitoredSpawnPids.size > 0,
    };
  })();

  const computeClddMetrics = (
    interposeOracle as unknown as {
      computeClddMetrics?: (
        events: Array<{ pid: number | null; remoteAddress: string }>
      ) => {
        unmediated_connections: number;
        unmonitored_spawns: number;
        escapes_suspected: boolean;
      };
    }
  ).computeClddMetrics;

  const interposeSummary = {
    ...interposeOracle.getSummary(),
    cldd:
      typeof computeClddMetrics === 'function'
        ? computeClddMetrics.call(interposeOracle, netEvents)
        : fallbackClddMetrics,
  };
  const blockedEgressAttemptCount = interposeEvents.filter(
    (event) => event.syscall === 'connect_blocked'
  ).length;

  // Merge interpose network receipts into network receipts
  const allNetworkReceipts = [...networkReceipts, ...interposeReceipts.network];
  const allExecutionReceipts = [...executionReceipts, ...interposeReceipts.execution];

  // Sentinel summary (verbose only)
  if (!isWindows) diag(`\x1b[36m[clawsig]\x1b[0m Sentinel Shell: ${shellEvents.length} commands captured\n`);
  diag(`\x1b[36m[clawsig]\x1b[0m FS Sentinel: ${fsSentinel.eventCount} file events\n`);
  diag(`\x1b[36m[clawsig]\x1b[0m Net Sentinel: ${netSentinel.eventCount} connections (${netSentinel.suspiciousCount} suspicious)\n`);
  if (interposeEvents.length > 0) {
    const parts = [`${interposeReceipts.network.length} net`, `${interposeReceipts.execution.length} exec`];
    if (interposeReceipts.gateway.length > 0) parts.push(`${interposeReceipts.gateway.length} gateway`);
    if (interposeReceipts.transcript.length > 0) parts.push(`${interposeReceipts.transcript.length} transcript`);
    if (interposeReceipts.toolCalls.length > 0) parts.push(`${interposeReceipts.toolCalls.length} tool_calls`);
    if (interposeReceipts.anomalies.length > 0) parts.push(`${interposeReceipts.anomalies.length} anomalies`);
    diag(`\x1b[36m[clawsig]\x1b[0m Interpose Sentinel: ${interposeEvents.length} syscalls (${parts.join(', ')})\n`);
  }
  if (preloadGatewayReceipts.length > 0) {
    diag(`\x1b[36m[clawsig]\x1b[0m Preload LLM intercepts: ${preloadGatewayReceipts.length} (via diagnostics_channel + fetch)\n`);
  }
  if (sniGatewayReceipts.length > 0) {
    diag(`\x1b[36m[clawsig]\x1b[0m TLS SNI intercepts: ${sniEvents.length} connections → ${sniGatewayReceipts.length} LLM domains\n`);
  }
  if (interposeOracle.totalEvents > 0) {
    diag(`\x1b[36m[clawsig]\x1b[0m Interpose Oracle: ${interposeSummary.pid_tree_size} PIDs, ${interposeSummary.bound_ports.length} server ports${interposeSummary.bound_ports.length > 0 ? ` (${interposeSummary.bound_ports.join(',')})` : ''}, ${interposeSummary.env_audits} credentials, ${interposeSummary.cred_leaks} leaks\n`);
  }

  if (interposeSummary.cldd.escapes_suspected) {
    diag(`\x1b[33m[clawsig]\x1b[0m CLDD: unmediated_connections=${interposeSummary.cldd.unmediated_connections}, unmonitored_spawns=${interposeSummary.cldd.unmonitored_spawns}, escapes_suspected=${interposeSummary.cldd.escapes_suspected}\n`);
  }

  // Suspicious connections are always shown (security-critical)
  if (netSentinel.suspiciousCount > 0) {
    process.stderr.write(`\x1b[31m[clawsig]\x1b[0m WARNING: Suspicious network connections detected!\n`);
    for (const e of netSentinel.getSuspiciousEvents().slice(0, 5)) {
      process.stderr.write(`\x1b[31m[clawsig]\x1b[0m   ${e.remoteAddress} (${e.processName ?? 'unknown'} PID:${e.pid ?? '?'})\n`);
    }
  }

  // Stop proxy first so the Causal Sieve can flush/finalize all pending
  // tool + side-effect receipts before bundle compilation/signing.
  await proxy.stop();
  const bundle = await proxy.compileProofBundle();
  const canonicalReceipts = Array.isArray(bundle.payload.receipts)
    ? bundle.payload.receipts
    : [];
  const signedCanonicalReceipts = canonicalReceipts.filter((receipt) =>
    isSignedGatewayReceiptEnvelope(receipt),
  );
  if (signedCanonicalReceipts.length !== canonicalReceipts.length) {
    diag(
      `\x1b[33m[clawsig]\x1b[0m Dropped ${canonicalReceipts.length - signedCanonicalReceipts.length} unsigned canonical receipt(s)\n`,
    );
  }
  if (signedCanonicalReceipts.length > 0) {
    bundle.payload.receipts = signedCanonicalReceipts;
  } else {
    delete bundle.payload.receipts;
  }

  // Filter noise receipts before injecting into bundle.
  // Full data remains available in memory for verbose diagnostics.
  const unfilteredExecutionCount = allExecutionReceipts.length;
  const unfilteredNetworkCount = allNetworkReceipts.length;
  const filteredExecutionReceipts = filterExecutionReceipts(allExecutionReceipts);
  const filteredNetworkReceipts = filterNetworkReceipts(allNetworkReceipts);
  const filteredOutExecution = unfilteredExecutionCount - filteredExecutionReceipts.length;
  const filteredOutNetwork = unfilteredNetworkCount - filteredNetworkReceipts.length;

  if (verbose && (filteredOutExecution > 0 || filteredOutNetwork > 0)) {
    diag(`\x1b[36m[clawsig]\x1b[0m Noise filtered: ${filteredOutExecution} execution, ${filteredOutNetwork} network receipts removed\n`);
  }

  const runtimeHygiene = buildRuntimeHygieneEvidence({
    profile: runtimeProfile,
    cldd: interposeSummary.cldd as RuntimeClddMetrics,
    interposeActive: !!interposeLib,
    netSuspicious: netSentinel.suspiciousCount,
    classificationCounts: summarizeNetworkClassifications(filteredNetworkReceipts),
    filteredOutExecution,
    filteredOutNetwork,
  });
  diag(
    `\x1b[36m[clawsig]\x1b[0m Runtime hygiene verdict: ${runtimeHygiene.verdict}` +
      ` (reviewer_action_required=${runtimeHygiene.reviewer_action_required ? 'yes' : 'no'})\n`,
  );

  // Inject filtered sentinel receipts into the bundle
  if (filteredExecutionReceipts.length > 0) {
    bundle.payload.execution_receipts = filteredExecutionReceipts;
  }
  if (filteredNetworkReceipts.length > 0) {
    bundle.payload.network_receipts = filteredNetworkReceipts;
  }
  const preferCanonicalGatewayReceipts = signedCanonicalReceipts.length > 0;

  // Inject Agent Genealogy Receipt (full process tree with harness attribution)
  // only when we do not already have canonical clawproxy receipts bound to this run.
  const genealogyTree = interposeOracle.getGenealogyTree();
  if (!preferCanonicalGatewayReceipts && genealogyTree && Object.keys(genealogyTree).length > 0) {
    const genealogyReceipt = {
      receipt_version: '1',
      receipt_id: `genealogy_${crypto.randomUUID()}`,
      receipt_type: 'agent_genealogy_graph',
      root_pid: childPid,
      tree: genealogyTree,
      agent_did: agentDid.did,
      timestamp: new Date().toISOString(),
      binding: { run_id: runId },
    };
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const existing = (bundle.payload.receipts ?? []) as any[];
    const signedGenealogyReceipt = toSignedGatewayReceiptEnvelope(genealogyReceipt);
    if (signedGenealogyReceipt) {
      bundle.payload.receipts = [...existing, signedGenealogyReceipt] as typeof bundle.payload.receipts;
    }
  }

  // Inject Security Audit Receipts (env credential hashes + DLP leak alerts)
  // only in synthetic-only mode; canonical gateway receipts should remain uncluttered.
  if (!preferCanonicalGatewayReceipts && (interposeOracle.envAudits.length > 0 || interposeOracle.credLeaks.length > 0)) {
    const securityReceipts: Record<string, unknown>[] = [];
    if (interposeOracle.envAudits.length > 0) {
      securityReceipts.push({
        receipt_version: '1',
        receipt_id: `sec_env_${crypto.randomUUID()}`,
        receipt_type: 'env_audit',
        credentials: interposeOracle.envAudits.map(e => ({
          key: e.key,
          value_sha256: e.value_sha256,
          pid: e.pid,
        })),
        agent_did: agentDid.did,
        timestamp: interposeOracle.envAudits[0]?.ts,
        binding: { run_id: runId },
      });
    }
    for (const leak of interposeOracle.credLeaks) {
      securityReceipts.push({
        receipt_version: '1',
        receipt_id: `sec_leak_${crypto.randomUUID()}`,
        receipt_type: 'cred_leak_alert',
        pattern: leak.pattern,
        fd: leak.fd,
        pid: leak.pid,
        severity: 'CRITICAL',
        agent_did: agentDid.did,
        timestamp: leak.ts,
        binding: { run_id: runId },
      });
    }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const existing = (bundle.payload.receipts ?? []) as any[];
    const signedSecurityReceipts = securityReceipts
      .map(toSignedGatewayReceiptEnvelope)
      .filter((receipt): receipt is SignedEnvelope<GatewayReceiptPayload> => receipt !== null);
    if (signedSecurityReceipts.length > 0) {
      bundle.payload.receipts = [...existing, ...signedSecurityReceipts] as typeof bundle.payload.receipts;
    }
  }

  // Inject preload + SNI + interpose FSM receipts into the bundle.
  // If we already collected canonical signed gateway receipts from clawproxy,
  // do not also inject synthetic gateway fallbacks from preload/SNI/interpose.
  // Mixing signed gateway envelopes with unsigned synthetic gateway receipts can
  // trip completeness/binding policies downstream.
  {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const existing = (bundle.payload.receipts ?? []) as any[];
    const additions = [
      ...(preferCanonicalGatewayReceipts ? [] : preloadGatewayReceipts),
      ...(preferCanonicalGatewayReceipts ? [] : sniGatewayReceipts),
      ...(preferCanonicalGatewayReceipts ? [] : interposeReceipts.gateway),
      ...interposeReceipts.transcript,
      ...interposeReceipts.toolCalls,
      ...interposeReceipts.anomalies,
    ];
    const signedAdditions = additions
      .map(toSignedGatewayReceiptEnvelope)
      .filter((receipt): receipt is SignedEnvelope<GatewayReceiptPayload> => receipt !== null);
    if (signedAdditions.length > 0) {
      bundle.payload.receipts = [...existing, ...signedAdditions] as typeof bundle.payload.receipts;
    }
  }

  // Add sentinel metadata
  const sentinelsMetadata = {
    shell_events: shellEvents.length,
    fs_events: fsSentinel.eventCount,
    net_events: netSentinel.eventCount,
    net_suspicious: netSentinel.suspiciousCount,
    interpose_events: interposeEvents.length,
    interpose_active: !!interposeLib,
    interpose_gateway: interposeReceipts.gateway.length,
    interpose_transcript: interposeReceipts.transcript.length,
    interpose_tool_calls: interposeReceipts.toolCalls.length,
    interpose_anomalies: interposeReceipts.anomalies.length,
    preload_llm_events: preloadGatewayReceipts.length,
    tls_sni_events: sniEvents.length,
    tls_sni_receipts: sniGatewayReceipts.length,
    runtime_profile: runtimeProfile,
    runtime_hygiene: runtimeHygiene,
    interpose_state: interposeSummary,
  } as Record<string, unknown>;

  await ensureMinimalHarnessEvidence({
    bundle,
    signer: {
      did: agentDid.did,
      sign: (data) => agentDid.sign(data),
    },
    runId,
    commandName,
    exitCode,
  });

  const effectivePolicyBinding = loadedPolicy.policyBinding;
  let runnerMeasurementBinding: RunnerMeasurementBindingMetadata | undefined;
  let egressPolicyReceiptEnvelope: SignedEnvelope<EgressPolicyReceiptPayload> | undefined;
  if (proofedMode && parsedProofedClawproxyUrl) {
    const allowedProxyDestinations = normalizeCanonicalHostList(proofedEgressAllowlist);
    const allowedChildDestinations = normalizeCanonicalHostList(proofedChildEgressAllowlist);
    try {
      runnerMeasurementBinding = await buildRunnerMeasurementBinding({
        clawproxyUrl: parsedProofedClawproxyUrl.toString(),
        allowedProxyDestinations,
        allowedChildDestinations,
        effectivePolicyHashB64u: effectivePolicyBinding?.effective_policy_hash_b64u,
        shellSentinelEnabled: !!sentinelShellPath,
        interposeEnabled: !!interposeLib,
        interposeLibraryPath: interposeLib?.path ?? null,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      process.stderr.write(`\x1b[31m[clawsig]\x1b[0m ${message}\n`);
      return 2;
    }
    const policyDescriptor = {
      policy_version: '1' as const,
      proofed_mode: true,
      clawproxy_url: parsedProofedClawproxyUrl.toString(),
      allowed_proxy_destinations: allowedProxyDestinations,
      allowed_child_destinations: allowedChildDestinations,
      direct_provider_access_blocked: true,
    };
    const descriptorPolicyHashB64u = await hashJsonB64u(policyDescriptor);
    const effectivePolicyHashB64u = effectivePolicyBinding?.effective_policy_hash_b64u;
    const eventHashB64u =
      bundle.payload.event_chain && bundle.payload.event_chain.length > 0
        ? bundle.payload.event_chain[0]?.event_hash_b64u
        : undefined;

    if (typeof eventHashB64u !== 'string' || eventHashB64u.length === 0) {
      process.stderr.write(
        '\x1b[31m[clawsig]\x1b[0m PRV_EGRESS_BINDING_MISSING: proofed mode requires an event-chain binding for the signed egress policy receipt.\n',
      );
      return 1;
    }

    const policyReceiptPayload: EgressPolicyReceiptPayload = {
      receipt_version: '1',
      receipt_id: `epr_${crypto.randomUUID()}`,
      policy_version: '1',
      policy_hash_b64u: descriptorPolicyHashB64u,
      ...(effectivePolicyHashB64u
        ? { effective_policy_hash_b64u: effectivePolicyHashB64u }
        : {}),
      proofed_mode: true,
      clawproxy_url: parsedProofedClawproxyUrl.toString(),
      allowed_proxy_destinations: allowedProxyDestinations,
      allowed_child_destinations: allowedChildDestinations,
      direct_provider_access_blocked: true,
      blocked_attempt_count: blockedEgressAttemptCount,
      blocked_attempts_observed: blockedEgressAttemptCount > 0,
      hash_algorithm: 'SHA-256',
      agent_did: agentDid.did,
      timestamp: new Date().toISOString(),
      binding: {
        run_id: runId,
        event_hash_b64u: eventHashB64u,
      },
    };

    const payloadHashB64u = await hashJsonB64u(policyReceiptPayload);
    const signatureB64u = await agentDid.sign(
      new TextEncoder().encode(payloadHashB64u)
    );

    egressPolicyReceiptEnvelope = {
      envelope_version: '1',
      envelope_type: 'egress_policy_receipt',
      payload: policyReceiptPayload,
      payload_hash_b64u: payloadHashB64u,
      hash_algorithm: 'SHA-256',
      signature_b64u: signatureB64u,
      algorithm: 'Ed25519',
      signer_did: agentDid.did,
      issued_at: policyReceiptPayload.timestamp,
    };
  }

  if (runnerMeasurementBinding) {
    diag(
      `\x1b[36m[clawsig]\x1b[0m Runner measurement hash: ${runnerMeasurementBinding.manifest_hash_b64u}\n`,
    );
  }

  bundle.payload.metadata = {
    ...bundle.payload.metadata,
    ...(effectivePolicyBinding ? { policy_binding: effectivePolicyBinding } : {}),
    ...(runnerMeasurementBinding ? { runner_measurement: runnerMeasurementBinding } : {}),
    sentinels: {
      ...(sentinelsMetadata as NonNullable<NonNullable<ProofBundlePayload['metadata']>['sentinels']>),
      ...(egressPolicyReceiptEnvelope
        ? { egress_policy_receipt: egressPolicyReceiptEnvelope }
        : {}),
    },
  };

  // EPV-002: Apply visibility mode transformation (non-public modes only).
  // Must happen after all payload mutations and before the final seal.
  if (epvMode && epvMode.mode !== 'public') {
    try {
      applyVisibility(
        bundle.payload as unknown as Record<string, unknown>,
        epvMode.mode,
        epvMode.resolvedViewerDids,
        agentDid.did,
      );
      diag(`\x1b[36m[clawsig]\x1b[0m EPV: bundle encrypted for ${epvMode.resolvedViewerDids.length} viewer(s) (visibility=${epvMode.mode})\n`);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      process.stderr.write(`\x1b[31m[clawsig]\x1b[0m EPV crypto failure: ${msg}\n`);
      return 1;
    }
  }

  // Final seal happens after all payload mutation. This preserves deterministic
  // signature sequencing and avoids post-sign envelope drift.
  await resealProofBundleEnvelope(bundle, {
    did: agentDid.did,
    sign: (data) => agentDid.sign(data),
  });

  // Verbose receipt breakdown
  const totalReceipts = bundle.payload.receipts?.length ?? 0;
  const nonGateway = interposeReceipts.transcript.length + interposeReceipts.toolCalls.length + interposeReceipts.anomalies.length;
  const totalGw = totalReceipts - nonGateway;
  const proxyGateway = totalGw - preloadGatewayReceipts.length - sniGatewayReceipts.length - interposeReceipts.gateway.length;

  diag(`\x1b[36m[clawsig]\x1b[0m Bundle ID: ${bundle.payload.bundle_id}\n`);
  diag(`\x1b[36m[clawsig]\x1b[0m Event chain: ${bundle.payload.event_chain?.length ?? 0} events\n`);
  diag(`\x1b[36m[clawsig]\x1b[0m Gateway receipts: ${totalGw} (proxy: ${proxyGateway < 0 ? 0 : proxyGateway}, preload: ${preloadGatewayReceipts.length}, sni: ${sniGatewayReceipts.length}, interpose: ${interposeReceipts.gateway.length})\n`);
  if (interposeReceipts.transcript.length > 0) {
    diag(`\x1b[36m[clawsig]\x1b[0m Transcript events: ${interposeReceipts.transcript.length} (via interpose FSM)\n`);
  }
  if (interposeReceipts.toolCalls.length > 0) {
    diag(`\x1b[36m[clawsig]\x1b[0m Tool call events: ${interposeReceipts.toolCalls.length} (via interpose FSM)\n`);
  }
  diag(`\x1b[36m[clawsig]\x1b[0m Tool receipts (Causal Sieve): ${proxy.toolReceiptCount}\n`);
  diag(`\x1b[36m[clawsig]\x1b[0m Side-effect receipts: ${proxy.sideEffectReceiptCount}\n`);
  diag(`\x1b[36m[clawsig]\x1b[0m Execution receipts: ${filteredExecutionReceipts.length} (shell: ${executionReceipts.length}, interpose: ${interposeReceipts.execution.length}, filtered: ${filteredOutExecution})\n`);
  diag(`\x1b[36m[clawsig]\x1b[0m Network receipts: ${filteredNetworkReceipts.length} (polling: ${networkReceipts.length}, interpose: ${interposeReceipts.network.length}, filtered: ${filteredOutNetwork})\n`);
  if (proxy.violationCount > 0) {
    // Violations are always shown (security-critical)
    process.stderr.write(`\x1b[31m[clawsig]\x1b[0m Policy violations: ${proxy.violationCount}\n`);
  }

  // Clean up temp dir
  try {
    const { rm } = await import('node:fs/promises');
    await rm(tmpDir, { recursive: true, force: true });
  } catch { /* ignore cleanup errors */ }

  // 5. Always write bundle to .clawsig/proof_bundle.json
  const bundlePath = await writeBundleToDisk(bundle, verbose);

  const runSummary: RunSummaryJson = {
    status: exitCode === 0 ? 'PASS' : 'FAIL',
    tier: totalGw > 0 ? 'gateway' : 'self',
    cost_usd: extractBundleCostUsd(bundle),
    tools_used: collectToolsUsed(bundle),
    files_modified: collectFilesModified(fsSentinel.getEvents()),
    policy_violations: proxy.violationCount,
    network_connections: filteredNetworkReceipts.length,
    bundle_path: '.clawsig/proof_bundle.json',
    did: agentDid.did,
    timestamp: new Date().toISOString(),
    duration_seconds: Math.max(0, Math.round((Date.now() - wrapStartedAtMs) / 1000)),
    runtime_profile_id: runtimeProfile.profile_id,
    runtime_profile_status: runtimeProfile.activation.status,
    runtime_hygiene_verdict: runtimeHygiene.verdict,
  };
  await writeRunSummaryToDisk(runSummary, verbose);

  // 5b. Also write to custom output path if requested
  if (outputPath) {
    await writeJsonAtomic(outputPath, bundle, 2);
    diag(`\x1b[36m[clawsig]\x1b[0m Bundle also written to: ${outputPath}\n`);
  }

  // Compute and print summary box (quiet mode)
  if (!verbose) {
    const bundleJson = JSON.stringify(bundle);
    const gwCount = totalGw > 0 ? totalGw : 0;
    const summary = computeBundleSummary({
      bundleJson,
      gatewayCount: gwCount,
      toolCallCount: proxy.toolReceiptCount,
      executionCount: filteredExecutionReceipts.length,
      sideEffectCount: proxy.sideEffectReceiptCount,
      networkCount: filteredNetworkReceipts.length,
      humanApprovalCount: bundle.payload.human_approval_receipts?.length ?? 0,
      otherCount: nonGateway,
      filteredExecution: filteredOutExecution,
      filteredNetwork: filteredOutNetwork,
    });
    printSummaryBox(summary, exitCode, bundlePath ?? outputPath ?? '.clawsig/proof_bundle.json');
  }

  // 6. Publish to VaaS and try to attach badge to open PR
  if (publish) {
    const publishResult = await publishBundle(bundle);
    if (publishResult.badgeUrl && publishResult.ledgerUrl) {
      await tryAttachBadgeToPR(publishResult.badgeUrl, publishResult.ledgerUrl);
    }
  } else {
    diag(`\x1b[36m[clawsig]\x1b[0m Publish skipped (--no-publish)\n`);

    // Always print the local bundle to stdout if not publishing
    if (!outputPath) {
      if (verbose) process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Proof bundle (local):\n`);
      process.stdout.write(JSON.stringify(bundle, null, 2) + '\n');
    }
  }

  return exitCode;
}

/**
 * Publish a proof bundle to the VaaS API.
 * Handles network errors and 404s gracefully (prints bundle locally as fallback).
 */
async function publishBundle(bundle: SignedEnvelope<ProofBundlePayload>): Promise<PublishResult> {
  process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Publishing to VaaS...\n`);

  try {
    const res = await fetch(VAAS_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        proof_bundle: bundle,
        publish_to_ledger: true,
      }),
    });

    if (!res.ok) {
      const text = await res.text().catch(() => '');
      process.stderr.write(
        `\x1b[33m[clawsig]\x1b[0m VaaS returned HTTP ${res.status}` +
        (text ? `: ${text.slice(0, 200)}` : '') + '\n',
      );
      process.stderr.write(`\x1b[33m[clawsig]\x1b[0m Bundle verified locally. VaaS publish will be available soon.\n`);
      printLocalFallback(bundle);
      return {};
    }

    const body = await res.json() as VaaSResponse;

    if (body.ok && body.urls?.badge && body.urls?.ledger) {
      process.stderr.write(`\n\x1b[32m[clawsig]\x1b[0m Verified! Tier: ${body.tier?.toUpperCase() ?? 'FREE'}\n`);
      process.stderr.write(`\x1b[32m[clawsig]\x1b[0m Paste this badge in your PR or README:\n\n`);
      process.stdout.write(
        `[![Clawsig Verified](${body.urls.badge})](${body.urls.ledger})\n`,
      );
      return { badgeUrl: body.urls.badge, ledgerUrl: body.urls.ledger };
    } else {
      process.stderr.write(`\x1b[33m[clawsig]\x1b[0m VaaS response: ${JSON.stringify(body)}\n`);
      printLocalFallback(bundle);
      return {};
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : 'unknown error';
    process.stderr.write(`\x1b[33m[clawsig]\x1b[0m VaaS unavailable: ${message}\n`);
    process.stderr.write(`\x1b[33m[clawsig]\x1b[0m Bundle verified locally. VaaS publish will be available soon.\n`);
    printLocalFallback(bundle);
    return {};
  }
}

function printLocalFallback(bundle: SignedEnvelope<ProofBundlePayload>): void {
  process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Local proof bundle ID: ${bundle.payload.bundle_id}\n`);
  process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Signer: ${bundle.signer_did}\n`);
}

/**
 * Always write the proof bundle to .clawsig/proof_bundle.json.
 * This ensures the bundle survives even if VaaS is unreachable or
 * the agent already pushed a PR before the wrapper exits (Bug 3).
 * Returns the bundle path on success, null on failure.
 */
async function writeBundleToDisk(
  bundle: SignedEnvelope<ProofBundlePayload>,
  verbose: boolean,
): Promise<string | null> {
  try {
    const dir = join(process.cwd(), CLAWSIG_DIR);
    await mkdir(dir, { recursive: true });
    const bundlePath = join(dir, BUNDLE_FILE);
    await writeJsonAtomic(bundlePath, bundle, 2);
    if (verbose) {
      process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Bundle written to: ${bundlePath}\n`);
    }
    return bundlePath;
  } catch (err) {
    const message = err instanceof Error ? err.message : 'unknown error';
    process.stderr.write(
      `\x1b[33m[clawsig]\x1b[0m Could not write bundle to .clawsig/proof_bundle.json: ${message}\n`,
    );
    return null;
  }
}

async function writeRunSummaryToDisk(
  summary: RunSummaryJson,
  verbose: boolean,
): Promise<string | null> {
  try {
    const dir = join(process.cwd(), CLAWSIG_DIR);
    await mkdir(dir, { recursive: true });
    const summaryPath = join(dir, RUN_SUMMARY_FILE);
    await writeJsonAtomic(summaryPath, summary);
    if (verbose) {
      process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Run summary written to: ${summaryPath}\n`);
    }
    return summaryPath;
  } catch (err) {
    const message = err instanceof Error ? err.message : 'unknown error';
    process.stderr.write(
      `\x1b[33m[clawsig]\x1b[0m Could not write run summary to .clawsig/run_summary.json: ${message}\n`,
    );
    return null;
  }
}

async function writeJsonAtomic(
  filePath: string,
  value: unknown,
  indent?: number,
): Promise<void> {
  const dir = dirname(filePath);
  await mkdir(dir, { recursive: true });

  const tempPath = join(
    dir,
    `.${basename(filePath)}.tmp-${process.pid}-${Date.now()}-${crypto.randomUUID()}`,
  );

  try {
    const json = JSON.stringify(value, null, indent);
    await writeFile(tempPath, json, 'utf-8');
    await rename(tempPath, filePath);
  } catch (err) {
    await unlink(tempPath).catch(() => {});
    throw err;
  }
}

function extractBundleCostUsd(bundle: SignedEnvelope<ProofBundlePayload>): number {
  const payload = bundle.payload as unknown as Record<string, unknown>;

  const fromRunSummary = readNumericField(payload['run_summary'], ['total_cost_usd', 'cost_usd']);
  if (fromRunSummary !== null) return roundUsd(fromRunSummary);

  const fromMetadataRunSummary = readNumericField(payload['metadata'], ['total_cost_usd', 'cost_usd']);
  if (fromMetadataRunSummary !== null) return roundUsd(fromMetadataRunSummary);

  const llmInteractions = payload['llm_interactions'];
  if (Array.isArray(llmInteractions)) {
    let total = 0;
    let hasCosts = false;
    for (const item of llmInteractions) {
      if (!isObjectRecord(item)) continue;
      const cost = item['cost_usd'];
      if (typeof cost !== 'number' || !Number.isFinite(cost) || cost < 0) continue;
      total += cost;
      hasCosts = true;
    }
    if (hasCosts) return roundUsd(total);
  }

  return 0;
}

function readNumericField(
  value: unknown,
  fieldNames: string[],
): number | null {
  if (!isObjectRecord(value)) return null;
  for (const fieldName of fieldNames) {
    const candidate = value[fieldName];
    if (typeof candidate === 'number' && Number.isFinite(candidate) && candidate >= 0) {
      return candidate;
    }
  }
  return null;
}

function roundUsd(value: number): number {
  return Math.round(value * 1_000_000) / 1_000_000;
}

function collectToolsUsed(
  bundle: SignedEnvelope<ProofBundlePayload>,
  maxItems = 8,
): string[] {
  const tools = new Set<string>();
  const addTool = (toolName: unknown) => {
    if (typeof toolName !== 'string') return;
    const trimmed = toolName.trim();
    if (trimmed.length === 0) return;
    tools.add(trimToMaxLength(trimmed, 48));
  };

  const payload = bundle.payload as unknown as Record<string, unknown>;
  if (Array.isArray(payload['tool_receipts'])) {
    for (const toolReceipt of payload['tool_receipts']) {
      if (!isObjectRecord(toolReceipt)) continue;
      addTool(toolReceipt['tool_name']);
    }
  }

  if (Array.isArray(payload['receipts'])) {
    for (const rawReceipt of payload['receipts']) {
      if (!isObjectRecord(rawReceipt)) continue;

      const envelopeType = rawReceipt['envelope_type'];
      if (envelopeType === 'tool_receipt' && isObjectRecord(rawReceipt['payload'])) {
        addTool(rawReceipt['payload']['tool_name']);
      }

      if (rawReceipt['receipt_type'] === 'tool_call') {
        addTool(rawReceipt['tool_name']);
      }

      if (envelopeType === 'gateway_receipt' && isObjectRecord(rawReceipt['payload'])) {
        const nestedPayload = rawReceipt['payload'];
        if (nestedPayload['receipt_type'] === 'tool_call') {
          addTool(nestedPayload['tool_name']);
        }
      }
    }
  }

  return Array.from(tools).slice(0, maxItems);
}

function collectFilesModified(
  events: FsEvent[],
  maxItems = 8,
): string[] {
  const mutations = new Set<string>();
  const cwd = process.cwd();
  const relevantOperations = new Set<FsEvent['operation']>([
    'change',
    'write',
    'rename',
    'delete',
    'mkdir',
  ]);

  for (const event of events) {
    if (!relevantOperations.has(event.operation)) continue;
    if (event.isDirectory) continue;

    const relativePath = relative(cwd, event.path);
    if (relativePath === '' || relativePath === '.' || relativePath === '..') continue;
    if (relativePath.startsWith('..')) continue;

    const normalized = relativePath.split('\\').join('/');
    if (normalized.startsWith('.clawsig/')) continue;

    mutations.add(trimToMaxLength(normalized, 120));
    if (mutations.size >= maxItems) break;
  }

  return Array.from(mutations);
}

function trimToMaxLength(value: string, maxLength: number): string {
  if (value.length <= maxLength) return value;
  if (maxLength <= 3) return value.slice(0, maxLength);
  return `${value.slice(0, maxLength - 3)}...`;
}

// ---------------------------------------------------------------------------
// Summary Box (quiet mode output)
// ---------------------------------------------------------------------------

/**
 * Print a compact summary box to stderr after the child process exits.
 * This is the only clawsig output in default (quiet) mode.
 */
function printSummaryBox(
  summary: BundleSummaryStats,
  exitCode: number,
  bundlePath: string,
): void {
  const status = exitCode === 0 ? 'PASS' : 'FAIL';
  const statusColor = exitCode === 0 ? '\x1b[32m' : '\x1b[31m';
  const reset = '\x1b[0m';
  const dim = '\x1b[2m';

  // Build receipt parts string
  const parts: string[] = [];
  if (summary.receiptCounts.gateway > 0) parts.push(`${summary.receiptCounts.gateway} gateway`);
  if (summary.receiptCounts.tool_call > 0) parts.push(`${summary.receiptCounts.tool_call} tool_call`);
  if (summary.receiptCounts.side_effect > 0) parts.push(`${summary.receiptCounts.side_effect} side_effect`);
  if (summary.receiptCounts.execution > 0) parts.push(`${summary.receiptCounts.execution} execution`);
  if (summary.receiptCounts.network > 0) parts.push(`${summary.receiptCounts.network} network`);
  if (summary.receiptCounts.human_approval > 0) parts.push(`${summary.receiptCounts.human_approval} approval`);
  if (summary.receiptCounts.other > 0) parts.push(`${summary.receiptCounts.other} other`);
  const receiptsStr = parts.length > 0 ? parts.join(', ') : 'none';

  const line = `${dim}${'─'.repeat(45)}${reset}`;
  process.stderr.write(`\n${dim}── clawsig summary ──────────────────────────${reset}\n`);
  process.stderr.write(`  Status   : ${statusColor}${status}${reset} (exit code ${exitCode})\n`);
  process.stderr.write(`  Coverage : ${summary.coverageTier}\n`);
  process.stderr.write(`  Receipts : ${receiptsStr}\n`);
  process.stderr.write(`  Bundle   : ${bundlePath} (${summary.bundleSizeHuman})\n`);
  process.stderr.write(`${line}\n`);
}

/**
 * Resolve the absolute path to the clawsig SDK preload script.
 * Uses import.meta.resolve (Node 20.6+), falls back to createRequire.
 * Returns a file:// URL or bare specifier suitable for --import.
 */
function resolvePreloadPath(): string {
  // Try import.meta.resolve (Node 20.6+, synchronous in Node 22+)
  try {
    const resolved: string = import.meta.resolve('@clawbureau/clawsig-sdk/preload');
    if (resolved) return resolved;
  } catch {
    // Not available or can't resolve from this context
  }

  // Fallback: resolve relative to this CLI package via createRequire
  try {
    const { createRequire } = require('node:module');
    const localRequire = createRequire(import.meta.url);
    const sdkPkg: string = localRequire.resolve('@clawbureau/clawsig-sdk/package.json');
    const sdkDir = sdkPkg.replace(/[\\/]package\.json$/, '');
    const preloadPath = join(sdkDir, 'src', 'preload.mjs');
    return pathToFileURL(preloadPath).href;
  } catch {
    // Last resort: bare specifier, child must resolve it
    return '@clawbureau/clawsig-sdk/preload';
  }
}

/**
 * Resolve the node-preload-sentinel.mjs path (JS-level fallback for DYLD_INSERT).
 */
function resolveNodePreloadSentinelPath(): string {
  try {
    const resolved: string = import.meta.resolve('@clawbureau/clawsig-sdk/node-preload-sentinel');
    if (resolved) return resolved;
  } catch { /* fallback */ }

  try {
    const { createRequire } = require('node:module');
    const localRequire = createRequire(import.meta.url);
    const sdkPkg: string = localRequire.resolve('@clawbureau/clawsig-sdk/package.json');
    const sdkDir = sdkPkg.replace(/[\\/]package\.json$/, '');
    const sentinelPath = join(sdkDir, 'src', 'node-preload-sentinel.mjs');
    return pathToFileURL(sentinelPath).href;
  } catch {
    return '@clawbureau/clawsig-sdk/node-preload-sentinel';
  }
}

async function pathExists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

function resolvePolicyResolutionContextFromEnv(): {
  org_id: string;
  project_id?: string;
  task_id?: string;
} {
  const orgId =
    process.env['CLAWSIG_POLICY_ORG_ID']?.trim() ||
    process.env['CLAWSIG_ORG_ID']?.trim() ||
    'local';

  const projectId =
    process.env['CLAWSIG_POLICY_PROJECT_ID']?.trim() ||
    process.env['CLAWSIG_PROJECT_ID']?.trim();

  const taskId =
    process.env['CLAWSIG_POLICY_TASK_ID']?.trim() ||
    process.env['CLAWSIG_TASK_ID']?.trim();

  return {
    org_id: orgId,
    ...(projectId ? { project_id: projectId } : {}),
    ...(taskId ? { task_id: taskId } : {}),
  };
}

/**
 * Load policy artifacts for wrap:
 * 1) signed policy bundle envelope (preferred, fail-closed)
 * 2) fallback local policy.json (legacy behavior)
 */
async function loadPolicyArtifacts(): Promise<LoadedPolicyArtifacts> {
  const cwd = process.cwd();
  const envBundlePath = process.env['CLAWSIG_POLICY_BUNDLE_PATH']?.trim();
  const defaultBundleCandidates = [
    join(cwd, '.clawsig', 'policy.bundle.json'),
    join(cwd, '.clawsig', 'signed-policy.bundle.json'),
  ];

  let bundlePath: string | null = null;
  if (envBundlePath) {
    if (!(await pathExists(envBundlePath))) {
      throw new Error(
        `CLAWSIG_POLICY_BUNDLE_PATH does not exist: ${envBundlePath}`,
      );
    }
    bundlePath = envBundlePath;
  } else {
    for (const candidate of defaultBundleCandidates) {
      if (await pathExists(candidate)) {
        bundlePath = candidate;
        break;
      }
    }
  }

  if (bundlePath) {
    let rawBundle: unknown;
    try {
      rawBundle = JSON.parse(await readFile(bundlePath, 'utf-8'));
    } catch (err) {
      throw new Error(
        `failed to parse signed policy bundle at ${bundlePath}: ${err instanceof Error ? err.message : 'unknown error'}`,
      );
    }

    const resolutionContext = resolvePolicyResolutionContextFromEnv();
    const resolved = await resolveEffectivePolicyFromSignedBundle(
      rawBundle,
      resolutionContext,
    );

    const effectivePolicyPath = join(cwd, '.clawsig', 'policy.effective.json');
    await writeJsonAtomic(effectivePolicyPath, resolved.effective_policy, 2);

    return {
      policy: resolved.effective_policy as LocalPolicy,
      policySourcePath: effectivePolicyPath,
      policyBinding: {
        binding_version: '1',
        effective_policy_hash_b64u: resolved.effective_policy_hash_b64u,
        effective_policy_snapshot: resolved.effective_policy_snapshot,
        signed_policy_bundle_envelope: resolved.signed_policy_bundle_envelope,
      },
    };
  }

  const policyPath = join(cwd, '.clawsig', 'policy.json');
  if (!(await pathExists(policyPath))) {
    return {
      policy: null,
      policySourcePath: null,
      policyBinding: null,
    };
  }

  try {
    const parsed = JSON.parse(await readFile(policyPath, 'utf-8')) as {
      statements?: unknown;
    };
    if (!Array.isArray(parsed.statements)) {
      throw new Error('policy.json must include a statements array');
    }
    return {
      policy: { statements: parsed.statements } as LocalPolicy,
      policySourcePath: policyPath,
      policyBinding: null,
    };
  } catch (err) {
    throw new Error(
      `failed to parse local policy at ${policyPath}: ${err instanceof Error ? err.message : 'unknown error'}`,
    );
  }
}

/**
 * Try to find an open PR on the current branch and append the
 * verification badge. Requires the `gh` CLI. Fails silently if
 * gh is not installed or no PR exists — the badge is always printed
 * to stdout regardless.
 */
async function tryAttachBadgeToPR(badgeUrl: string, ledgerUrl: string): Promise<void> {
  try {
    // Check if gh CLI is available
    try {
      await execFileAsync(isWindows ? 'where' : 'which', ['gh']);
    } catch {
      return; // gh not installed, skip silently
    }

    // Get current branch name
    const { stdout: branchOut } = await execFileAsync(
      'git', ['rev-parse', '--abbrev-ref', 'HEAD'],
    );
    const branch = branchOut.trim();
    if (!branch || branch === 'HEAD') return;

    // Find open PR for this branch
    const { stdout: prListOut } = await execFileAsync('gh', [
      'pr', 'list', '--head', branch, '--json', 'number', '--limit', '1',
    ]);
    const prs = JSON.parse(prListOut) as Array<{ number: number }>;
    if (!prs.length || !prs[0]) return;
    const prNumber = prs[0].number;

    // Get current PR body
    const { stdout: prViewOut } = await execFileAsync('gh', [
      'pr', 'view', String(prNumber), '--json', 'body',
    ]);
    const { body: currentBody } = JSON.parse(prViewOut) as { body: string };

    // Build badge markdown
    const badgeMarkdown = `[![Clawsig Verified](${badgeUrl})](${ledgerUrl})`;

    // Don't add duplicate badge
    if (currentBody && currentBody.includes(badgeMarkdown)) {
      process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Badge already present in PR #${prNumber}\n`);
      return;
    }

    const newBody = (currentBody || '') + `\n\n---\n${badgeMarkdown}\n`;

    // Write to temp file and use --body-file to avoid shell escaping issues
    const bodyFile = join(process.cwd(), '.clawsig', '.pr-body-tmp');
    await mkdir(join(process.cwd(), '.clawsig'), { recursive: true });
    await writeFile(bodyFile, newBody, 'utf-8');

    try {
      await execFileAsync('gh', ['pr', 'edit', String(prNumber), '--body-file', bodyFile]);
      process.stderr.write(`\x1b[32m[clawsig]\x1b[0m Badge attached to PR #${prNumber}\n`);
    } finally {
      await unlink(bodyFile).catch(() => {});
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : 'unknown error';
    process.stderr.write(
      `\x1b[33m[clawsig]\x1b[0m Could not attach badge to PR: ${message}\n`,
    );
    process.stderr.write(
      `\x1b[33m[clawsig]\x1b[0m Manually add this badge to your PR:\n` +
      `  [![Clawsig Verified](${badgeUrl})](${ledgerUrl})\n`,
    );
  }
}

// ---------------------------------------------------------------------------
// Deep Execution Sentinel Helpers
// ---------------------------------------------------------------------------

interface ShellTraceEvent {
  layer: string;
  ts: string;
  pid: number;
  ppid: number;
  cwd: string;
  cmd: string;
  type: string;
  target: string;
  exit: number;
}

/**
 * Resolve the sentinel-shell.sh path from the SDK package.
 */
function resolveSentinelShellPath(): string {
  // Try resolving from the SDK package
  try {
    const { createRequire } = require('node:module') as { createRequire: (url: string | URL) => NodeRequire };
    const localRequire = createRequire(import.meta.url);
    const sdkPkg: string = localRequire.resolve('@clawbureau/clawsig-sdk/package.json');
    const sdkDir = sdkPkg.replace(/[\\/]package\.json$/, '');
    return join(sdkDir, 'src', 'sentinel-shell.sh');
  } catch {
    // Fallback: relative to this file
    const thisDir = dirname(fileURLToPath(import.meta.url));
    return join(thisDir, '..', '..', 'clawsig-sdk', 'src', 'sentinel-shell.sh');
  }
}

/**
 * Read and parse the Sentinel Shell trace file (JSONL).
 * Returns parsed events, discarding unparseable lines.
 */
async function harvestShellTrace(traceFile: string): Promise<ShellTraceEvent[]> {
  const events: ShellTraceEvent[] = [];

  try {
    const content = await readFile(traceFile, 'utf-8');
    for (const line of content.split('\n')) {
      if (!line.trim()) continue;
      try {
        const event = JSON.parse(line) as ShellTraceEvent;
        if (event.layer === 'shell' && event.cmd) {
          events.push(event);
        }
      } catch {
        // Skip unparseable lines
      }
    }
  } catch {
    // Trace file doesn't exist or can't be read
  }

  return events;
}

/**
 * Synthesize ExecutionReceiptPayload entries from shell trace events.
 * Hashes command strings and targets for privacy.
 */
async function synthesizeExecutionReceipts(
  events: ShellTraceEvent[],
  agentDid: string,
  runId: string,
): Promise<ExecutionReceiptPayload[]> {
  const receipts: ExecutionReceiptPayload[] = [];
  const encoder = new TextEncoder();

  // Import hash function
  const { sha256B64u } = await import('@clawbureau/clawsig-sdk');

  for (const event of events) {
    const commandHash = await sha256B64u(encoder.encode(event.cmd));
    const cwdHash = await sha256B64u(encoder.encode(event.cwd));
    const targetHash = event.target
      ? await sha256B64u(encoder.encode(event.target))
      : undefined;

    // Semantic command analysis
    const analysis: CommandAnalysis = analyzeCommand(event.cmd);

    receipts.push({
      receipt_version: '1',
      receipt_id: `ex_${crypto.randomUUID()}`,
      command_hash_b64u: commandHash,
      command_type: event.type,
      target_hash_b64u: targetHash,
      pid: event.pid,
      ppid: event.ppid,
      cwd_hash_b64u: cwdHash,
      exit_code: event.exit,
      metadata: {
        risk: analysis.risk,
        data_flow: analysis.dataFlow,
        patterns: analysis.patterns,
      },
      hash_algorithm: 'SHA-256',
      agent_did: agentDid,
      timestamp: event.ts,
      binding: { run_id: runId },
    });
  }

  return receipts;
}

/**
 * Synthesize NetworkReceiptPayload entries from network sentinel events.
 */
async function synthesizeNetworkReceipts(
  events: Array<{ layer: string; ts: string; protocol: string; remoteAddress: string; state: string; pid: number | null; processName: string | null; classification: string }>,
  agentDid: string,
  runId: string,
): Promise<NetworkReceiptPayload[]> {
  const receipts: NetworkReceiptPayload[] = [];
  const encoder = new TextEncoder();
  const { sha256B64u } = await import('@clawbureau/clawsig-sdk');

  for (const event of events) {
    const remoteHash = await sha256B64u(encoder.encode(event.remoteAddress));

    receipts.push({
      receipt_version: '1',
      receipt_id: `net_${crypto.randomUUID()}`,
      protocol: event.protocol,
      remote_address_hash_b64u: remoteHash,
      state: event.state,
      classification: event.classification,
      pid: event.pid,
      process_name: event.processName,
      hash_algorithm: 'SHA-256',
      agent_did: agentDid,
      timestamp: event.ts,
      binding: { run_id: runId },
    });
  }

  return receipts;
}

// ---------------------------------------------------------------------------
// Layer 6: Syscall Interposition (LD_PRELOAD / DYLD_INSERT_LIBRARIES)
// ---------------------------------------------------------------------------

interface InterposeLibResult {
  /** Absolute path to the compiled .so/.dylib */
  path: string;
  /** "LD_PRELOAD" or "DYLD_INSERT_LIBRARIES" */
  mechanism: string;
  /** Env vars to inject into child process */
  env: Record<string, string>;
}

interface InterposeTraceEvent {
  layer: 'interpose';
  ts: string;
  syscall: string;
  pid: number;
  // connect/sendto fields
  fd?: number;
  addr?: string;
  port?: number;
  family?: string;
  // open/openat fields
  path?: string;
  flags?: string;
  dirfd?: number;
  // execve/posix_spawn fields
  argv?: string[];
  child_pid?: number;
  // sendto
  len?: number;
  rc: number;
  // R27: llm_receipt / grpc_receipt fields (from C FSM)
  receipt_hash?: string;
  method?: string;
  status?: number;
  req_bytes?: number;
  res_bytes?: number;
  req_body_sha256?: string;
  res_body_sha256?: string;
  model?: string;
  req_model?: string;
  model_substituted?: number;
  stream_id?: number;
  // R27: llm_msg fields (from C FSM)
  role?: string;
  content_sha256?: string;
  preview?: string;
  // R27: llm_tool_call fields (from C FSM)
  call_id?: string;
  name?: string;
  arguments_sha256?: string;
  // R27: behavioral_anomaly fields
  hostname?: string;
  dimension?: string;
  expected?: number;
  observed?: number;
  sigma?: number;
}

/** Receipts synthesized from interpose trace events. */
interface InterposeSynthesized {
  network: NetworkReceiptPayload[];
  execution: ExecutionReceiptPayload[];
  /** LLM gateway receipts from HTTP FSM (llm_receipt + grpc_receipt). */
  gateway: Record<string, unknown>[];
  /** LLM message transcript events (llm_msg). */
  transcript: Record<string, unknown>[];
  /** Tool call events from LLM responses (llm_tool_call). */
  toolCalls: Record<string, unknown>[];
  /** Behavioral anomaly alerts. */
  anomalies: Record<string, unknown>[];
}

/**
 * Resolve or build the interposition shared library.
 *
 * Strategy:
 * 1. Look for a cached build in the SDK package directory
 * 2. If not found, try to compile from source using cc/gcc/clang
 * 3. Return null if no compiler available (graceful degradation)
 *
 * The built library is cached next to the source so subsequent runs
 * skip the compile step.
 */
async function resolveInterposeLibrary(tmpDir: string): Promise<InterposeLibResult | null> {
  const isDarwin = process.platform === 'darwin';
  const isLinux = process.platform === 'linux';
  if (!isDarwin && !isLinux) return null;

  const ext = isDarwin ? 'dylib' : 'so';
  const libName = `libclawsig_interpose.${ext}`;

  // Resolve source directory from the SDK package
  let sourceDir: string;
  try {
    const { createRequire } = require('node:module') as { createRequire: (url: string | URL) => NodeRequire };
    const localRequire = createRequire(import.meta.url);
    const sdkPkg: string = localRequire.resolve('@clawbureau/clawsig-sdk/package.json');
    const sdkDir = sdkPkg.replace(/[\\/]package\.json$/, '');
    sourceDir = join(sdkDir, 'src', 'sentinels', 'interpose');
  } catch {
    const thisDir = dirname(fileURLToPath(import.meta.url));
    sourceDir = join(thisDir, '..', '..', 'clawsig-sdk', 'src', 'sentinels', 'interpose');
  }

  const sourcePath = join(sourceDir, 'libclawsig_interpose.c');
  const cachedLib = join(sourceDir, libName);

  // 1. Check for cached build
  try {
    const [srcStat, libStat] = await Promise.all([
      stat(sourcePath).catch(() => null),
      stat(cachedLib).catch(() => null),
    ]);

    if (libStat && srcStat && libStat.mtimeMs >= srcStat.mtimeMs) {
      // Cached lib is newer than source — use it
      return makeInterposeResult(cachedLib, isDarwin);
    }
  } catch {
    // Fall through to compilation
  }

  // 2. Try to compile
  try {
    const srcExists = await stat(sourcePath).catch(() => null);
    if (!srcExists) return null;

    const cc = isDarwin ? 'clang' : (process.env['CC'] || 'gcc');
    const sharedFlag = isDarwin ? '-dynamiclib' : '-shared';
    const ldflags = isLinux ? '-ldl' : '';

    // Build into the source directory (cached for next run)
    const buildCmd = `${cc} -Wall -O3 -fPIC -std=gnu99 ${sharedFlag} -o ${cachedLib} ${sourcePath} ${ldflags}`;

    await execFileAsync('sh', ['-c', buildCmd], { timeout: 15000 });

    const built = await stat(cachedLib).catch(() => null);
    if (built) return makeInterposeResult(cachedLib, isDarwin);
  } catch {
    // No compiler or compile failed — degrade gracefully
  }

  return null;
}

function makeInterposeResult(libPath: string, isDarwin: boolean): InterposeLibResult {
  if (isDarwin) {
    return {
      path: libPath,
      mechanism: 'DYLD_INSERT_LIBRARIES',
      env: {
        DYLD_INSERT_LIBRARIES: libPath,
        // Note: we use DYLD_INTERPOSE section in the library itself,
        // NOT DYLD_FORCE_FLAT_NAMESPACE (broken on ARM64 macOS)
      },
    };
  }
  return {
    path: libPath,
    mechanism: 'LD_PRELOAD',
    env: {
      LD_PRELOAD: libPath,
    },
  };
}

/**
 * Parse interpose trace events from the shared JSONL trace file.
 * The C library writes {"layer":"interpose",...} lines to the same
 * CLAWSIG_TRACE_FILE that the Sentinel Shell uses.
 */
async function harvestInterposeTrace(traceFile: string): Promise<InterposeTraceEvent[]> {
  const events: InterposeTraceEvent[] = [];
  try {
    const content = await readFile(traceFile, 'utf-8');
    for (const line of content.split('\n')) {
      if (!line.trim()) continue;
      try {
        const event = JSON.parse(line);
        if (event.layer === 'interpose' && event.syscall) {
          events.push(event as InterposeTraceEvent);
        }
      } catch {
        // Skip unparseable lines
      }
    }
  } catch {
    // File doesn't exist or can't be read
  }
  return events;
}

/**
 * Convert raw interpose trace events into typed receipts:
 * - connect/sendto -> NetworkReceiptPayload
 * - open/openat/execve/posix_spawn -> ExecutionReceiptPayload
 */
async function synthesizeInterposeReceipts(
  events: InterposeTraceEvent[],
  agentDid: string,
  runId: string,
): Promise<InterposeSynthesized> {
  const network: NetworkReceiptPayload[] = [];
  const execution: ExecutionReceiptPayload[] = [];
  const gateway: Record<string, unknown>[] = [];
  const transcript: Record<string, unknown>[] = [];
  const toolCalls: Record<string, unknown>[] = [];
  const anomalies: Record<string, unknown>[] = [];
  const encoder = new TextEncoder();
  const { sha256B64u } = await import('@clawbureau/clawsig-sdk');

  for (const event of events) {
    const syscall = event.syscall;

    if (syscall === 'connect' || syscall === 'sendto') {
      const addr = event.addr ?? 'unknown';
      const remoteHash = await sha256B64u(encoder.encode(`${addr}:${event.port ?? 0}`));
      network.push({
        receipt_version: '1',
        receipt_id: `ipc_${crypto.randomUUID()}`,
        protocol: event.family === 'AF_INET6' ? 'tcp6' : 'tcp',
        remote_address_hash_b64u: remoteHash,
        state: event.rc === 0 ? 'ESTABLISHED' : 'SYN_SENT',
        classification: classifyInterposeAddress(addr, event.port ?? 0),
        pid: event.pid,
        process_name: null,
        hash_algorithm: 'SHA-256',
        agent_did: agentDid,
        timestamp: event.ts,
        binding: { run_id: runId },
      });
    } else if (
      syscall === 'open' || syscall === 'openat' ||
      syscall === 'open64' || syscall === 'openat64'
    ) {
      const path = event.path ?? '';
      // Skip noisy system paths that are just runtime loading
      if (isNoisyPath(path)) continue;

      const pathHash = await sha256B64u(encoder.encode(path));
      execution.push({
        receipt_version: '1',
        receipt_id: `ipf_${crypto.randomUUID()}`,
        command_hash_b64u: pathHash,
        command_type: 'file_access',
        target_hash_b64u: pathHash,
        pid: event.pid,
        ppid: 0,
        cwd_hash_b64u: '',
        exit_code: event.rc >= 0 ? 0 : -1,
        hash_algorithm: 'SHA-256',
        agent_did: agentDid,
        timestamp: event.ts,
        binding: { run_id: runId },
      });
    } else if (
      syscall === 'execve' || syscall === 'posix_spawn' || syscall === 'posix_spawnp'
    ) {
      const path = event.path ?? '';
      const argvStr = event.argv ? event.argv.join(' ') : path;
      const cmdHash = await sha256B64u(encoder.encode(argvStr));
      const pathHash = await sha256B64u(encoder.encode(path));

      execution.push({
        receipt_version: '1',
        receipt_id: `ipe_${crypto.randomUUID()}`,
        command_hash_b64u: cmdHash,
        command_type: 'subprocess_spawn',
        target_hash_b64u: pathHash,
        pid: event.pid,
        ppid: 0,
        cwd_hash_b64u: '',
        exit_code: event.rc,
        hash_algorithm: 'SHA-256',
        agent_did: agentDid,
        timestamp: event.ts,
        binding: { run_id: runId },
      });
    } else if (syscall === 'llm_receipt' || syscall === 'grpc_receipt') {
      // R27: Gateway receipts from the C HTTP/gRPC FSM (plaintext or decrypted TLS)
      gateway.push({
        receipt_version: '1',
        receipt_id: `ipr_${crypto.randomUUID()}`,
        receipt_type: syscall === 'grpc_receipt' ? 'gateway_grpc' : 'gateway_interpose',
        source: 'interpose_fsm',
        receipt_hash: event.receipt_hash ?? '',
        method: event.method ?? '',
        path: event.path ?? '',
        status: event.status ?? 0,
        model: event.model ?? 'unknown',
        req_model: event.req_model ?? '',
        model_substituted: !!(event.model_substituted),
        req_bytes: event.req_bytes ?? 0,
        res_bytes: event.res_bytes ?? 0,
        req_body_sha256: event.req_body_sha256 ?? '',
        res_body_sha256: event.res_body_sha256 ?? '',
        stream_id: event.stream_id ?? 0,
        fd: event.fd ?? -1,
        pid: event.pid,
        hash_algorithm: 'SHA-256',
        agent_did: agentDid,
        timestamp: event.ts,
        binding: { run_id: runId },
      });
    } else if (syscall === 'llm_msg') {
      // R27: Individual LLM message events (role + content hash + preview)
      transcript.push({
        receipt_version: '1',
        receipt_id: `ipm_${crypto.randomUUID()}`,
        receipt_type: 'llm_message',
        source: 'interpose_fsm',
        role: event.role ?? 'unknown',
        content_sha256: event.content_sha256 ?? '',
        preview: event.preview ?? '',
        stream_id: event.stream_id ?? 0,
        fd: event.fd ?? -1,
        pid: event.pid,
        agent_did: agentDid,
        timestamp: event.ts,
        binding: { run_id: runId },
      });
    } else if (syscall === 'llm_tool_call') {
      // R27: Tool call events extracted from LLM response JSON
      toolCalls.push({
        receipt_version: '1',
        receipt_id: `ipt_${crypto.randomUUID()}`,
        receipt_type: 'tool_call_interpose',
        source: 'interpose_fsm',
        call_id: event.call_id ?? '',
        tool_name: event.name ?? 'unknown',
        arguments_sha256: event.arguments_sha256 ?? '',
        stream_id: event.stream_id ?? 0,
        fd: event.fd ?? -1,
        pid: event.pid,
        agent_did: agentDid,
        timestamp: event.ts,
        binding: { run_id: runId },
      });
    } else if (syscall === 'behavioral_anomaly') {
      // R27: Statistical anomaly detection from the C library
      anomalies.push({
        receipt_version: '1',
        receipt_id: `ipa_${crypto.randomUUID()}`,
        receipt_type: 'behavioral_anomaly',
        source: 'interpose_anomaly_engine',
        hostname: event.hostname ?? '',
        dimension: event.dimension ?? '',
        expected: event.expected ?? 0,
        observed: event.observed ?? 0,
        sigma: event.sigma ?? 0,
        pid: event.pid,
        agent_did: agentDid,
        timestamp: event.ts,
        binding: { run_id: runId },
      });
    }
  }

  return { network, execution, gateway, transcript, toolCalls, anomalies };
}

/**
 * Classify an interpose-captured network address.
 * Known LLM API endpoints get 'expected', everything else gets 'unknown'.
 */
function classifyInterposeAddress(addr: string, port: number): string {
  // Known LLM provider IP ranges are impractical to maintain.
  // Instead: HTTPS (443) to any IP is likely an API call; other ports are suspicious.
  if (port === 443 || port === 80) return 'expected';
  if (port === 53) return 'dns';
  return 'suspicious';
}

// ---------------------------------------------------------------------------
// Preload trace harvesting (LLM call interception via diagnostics_channel)
// ---------------------------------------------------------------------------

interface PreloadTraceEvent {
  layer: 'preload';
  ts: string;
  type: string; // 'llm_request', 'tool_call', 'llm_request_error'
  source?: string; // 'diagnostics_channel', 'fetch', 'fetch_supplement', 'http'
  url?: string;
  method?: string;
  status?: number;
  model?: string;
  messages_hash?: string;
  headers?: Record<string, string>;
  // tool_call fields
  tool_name?: string;
  args_hash?: string;
  // error fields
  error?: string;
}

/**
 * Harvest preload events from the JSONL trace file.
 * These are LLM API calls captured by preload.mjs via diagnostics_channel,
 * globalThis.fetch patches, or http/https patches.
 */
async function harvestPreloadTrace(traceFile: string): Promise<PreloadTraceEvent[]> {
  const events: PreloadTraceEvent[] = [];
  try {
    const content = await readFile(traceFile, 'utf-8');
    for (const line of content.split('\n')) {
      if (!line.trim()) continue;
      try {
        const event = JSON.parse(line);
        if (event.layer === 'preload') {
          events.push(event as PreloadTraceEvent);
        }
      } catch { /* skip */ }
    }
  } catch { /* file doesn't exist */ }
  return events;
}

/**
 * Synthesize gateway-style receipts from preload LLM intercepts.
 * Deduplicates: if both diagnostics_channel and fetch captured the same request,
 * prefer the fetch version (has model + messages_hash) and skip the DC-only one.
 */
async function synthesizePreloadGatewayReceipts(
  events: PreloadTraceEvent[],
  agentDid: string,
  runId: string,
): Promise<Record<string, unknown>[]> {
  const receipts: Record<string, unknown>[] = [];
  const encoder = new TextEncoder();
  const { sha256B64u } = await import('@clawbureau/clawsig-sdk');

  // Separate llm_request events by source
  const llmRequests = events.filter(e => e.type === 'llm_request');
  const toolCalls = events.filter(e => e.type === 'tool_call');

  // Dedup: group by URL + method, prefer fetch/fetch_supplement over diagnostics_channel
  const deduped = new Map<string, PreloadTraceEvent>();
  for (const event of llmRequests) {
    const key = `${event.method}:${event.url}`;
    const existing = deduped.get(key);
    if (!existing) {
      deduped.set(key, event);
    } else if (event.source !== 'diagnostics_channel' && existing.source === 'diagnostics_channel') {
      // Prefer fetch over DC (has body details)
      deduped.set(key, event);
    } else if (event.source === 'fetch_supplement') {
      // Supplement enriches the DC entry
      deduped.set(key, { ...existing, ...event, source: 'fetch_supplement' });
    }
  }

  for (const event of deduped.values()) {
    const urlHash = event.url ? await sha256B64u(encoder.encode(event.url)) : '';

    receipts.push({
      receipt_version: '1',
      receipt_id: `gw_preload_${crypto.randomUUID()}`,
      receipt_type: 'gateway',
      source: event.source || 'preload',
      url_hash_b64u: urlHash,
      method: event.method || 'GET',
      status: event.status ?? 0,
      model: event.model || 'unknown',
      messages_hash_b64u: event.messages_hash || '',
      hash_algorithm: 'SHA-256',
      agent_did: agentDid,
      timestamp: event.ts,
      binding: { run_id: runId },
    });
  }

  // Add tool call receipts
  for (const tc of toolCalls) {
    receipts.push({
      receipt_version: '1',
      receipt_id: `tc_preload_${crypto.randomUUID()}`,
      receipt_type: 'tool_call',
      tool_name: tc.tool_name || 'unknown',
      args_hash_b64u: tc.args_hash || '',
      hash_algorithm: 'SHA-256',
      agent_did: agentDid,
      timestamp: tc.ts,
      binding: { run_id: runId },
    });
  }

  return receipts;
}

/**
 * Filter out high-volume system paths that are just runtime/loader noise.
 * These are not agent actions and would bloat the receipt log.
 */
function isNoisyPath(path: string): boolean {
  if (!path) return true;
  // Python bytecache, Node modules, system frameworks
  if (path.includes('__pycache__')) return true;
  if (path.includes('node_modules')) return true;
  if (path.includes('.cpython-')) return true;
  if (path.startsWith('/usr/lib/')) return true;
  if (path.startsWith('/usr/share/')) return true;
  if (path.startsWith('/System/Library/')) return true;
  if (path.startsWith('/Library/Frameworks/Python.framework/')) return true;
  if (path.includes('/Logging/') && path.endsWith('.plist')) return true;
  if (path.includes('Info.plist')) return true;
  if (path.includes('/Preferences/com.apple.')) return true;
  // dyld/loader paths
  if (path.startsWith('/dev/')) return true;
  return false;
}

// ---------------------------------------------------------------------------
// TLS SNI Trace Harvesting (Cross-Runtime: Bun, Python, Go, Rust, any libc)
// ---------------------------------------------------------------------------

interface TlsSniTraceEvent {
  layer: 'interpose';
  ts: string;
  syscall: 'tls_sni';
  pid: number;
  fd: number;
  hostname: string;
  addr: string;
  port: number;
}

/**
 * Harvest TLS SNI events from the C interposition library.
 * These are emitted when the library parses a TLS ClientHello from send()
 * or matches a getaddrinfo() cached hostname at connect() time.
 */
async function harvestTlsSniTrace(traceFile: string): Promise<TlsSniTraceEvent[]> {
  const events: TlsSniTraceEvent[] = [];
  try {
    const content = await readFile(traceFile, 'utf-8');
    for (const line of content.split('\n')) {
      if (!line.trim()) continue;
      try {
        const event = JSON.parse(line);
        if (event.layer === 'interpose' && event.syscall === 'tls_sni') {
          events.push(event as TlsSniTraceEvent);
        }
      } catch { /* skip */ }
    }
  } catch { /* file doesn't exist */ }
  return events;
}

const LLM_API_DOMAINS = [
  'anthropic.com', 'openai.com', 'googleapis.com', 'mistral.ai',
  'cohere.com', 'cohere.ai', 'x.ai', 'together.xyz', 'groq.com',
  'deepseek.com', 'openrouter.ai', 'fireworks.ai',
];

/**
 * Synthesize gateway-style receipts from TLS SNI events.
 * Groups by hostname, deduplicates, classifies LLM vs other.
 */
async function synthesizeSniGatewayReceipts(
  events: TlsSniTraceEvent[],
  agentDid: string,
  runId: string,
): Promise<Record<string, unknown>[]> {
  const receipts: Record<string, unknown>[] = [];
  const encoder = new TextEncoder();
  const { sha256B64u } = await import('@clawbureau/clawsig-sdk');

  // Group by hostname
  const groups = new Map<string, {
    count: number;
    first_seen: string;
    last_seen: string;
    addr: string;
  }>();

  for (const event of events) {
    const key = event.hostname;
    const existing = groups.get(key);
    if (!existing) {
      groups.set(key, {
        count: 1,
        first_seen: event.ts,
        last_seen: event.ts,
        addr: event.addr,
      });
    } else {
      existing.count++;
      if (event.ts > existing.last_seen) existing.last_seen = event.ts;
    }
  }

  for (const [hostname, data] of groups.entries()) {
    const isLlm = LLM_API_DOMAINS.some(d => hostname === d || hostname.endsWith(`.${d}`));
    const addrHash = await sha256B64u(encoder.encode(data.addr));

    receipts.push({
      receipt_version: '1',
      receipt_id: `gw_sni_${crypto.randomUUID()}`,
      receipt_type: 'gateway_sni',
      source: 'tls_sni',
      hostname,
      classification: isLlm ? 'llm_api' : 'other',
      connection_count: data.count,
      first_seen: data.first_seen,
      last_seen: data.last_seen,
      addr_hash_b64u: addrHash,
      hash_algorithm: 'SHA-256',
      agent_did: agentDid,
      timestamp: data.first_seen,
      binding: { run_id: runId },
    });
  }

  return receipts;
}
