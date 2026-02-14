/**
 * clawsig wrap — one-line agent verification.
 *
 * Wraps any agent process transparently:
 * 1. Generates an ephemeral DID
 * 2. Starts a local interceptor proxy
 * 3. Spawns the child process with env overrides pointing to the proxy
 * 4. On exit: compiles proof bundle, optionally publishes to VaaS
 */

import { spawn, execFile } from 'node:child_process';
import { readFile, writeFile, mkdir, unlink, copyFile, chmod, stat } from 'node:fs/promises';
import { openSync, readSync, closeSync } from 'node:fs';
import { promisify } from 'node:util';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { mkdtemp } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import {
  generateEphemeralDid,
  startLocalProxy,
  FsSentinel,
  NetSentinel,
} from '@clawbureau/clawsig-sdk';
import type {
  SignedEnvelope,
  ProofBundlePayload,
  ExecutionReceiptPayload,
  NetworkReceiptPayload,
  LocalPolicy,
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

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const VAAS_URL = 'https://api.clawverify.com/v1/verify';

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
  const { publish, outputPath } = options;

  // 1. Generate ephemeral DID
  const agentDid = await generateEphemeralDid();
  const runId = `run_${crypto.randomUUID()}`;

  process.stderr.write(`\n\x1b[36m[clawsig]\x1b[0m Ephemeral DID: ${agentDid.did}\n`);
  process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Run ID: ${runId}\n`);

  // 2. Load local WPC policy (if present)
  const policy = await loadLocalPolicy();
  if (policy) {
    process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Policy loaded: ${policy.statements.length} statements\n`);
  }

  // 3. Set up deep execution sentinels
  const tmpDir = await mkdtemp(join(tmpdir(), 'clawsig-'));
  const traceFile = join(tmpDir, 'shell-trace.jsonl');
  await writeFile(traceFile, '', 'utf-8'); // Create empty trace file

  // Copy sentinel-shell.sh to temp dir
  let sentinelShellPath: string | null = null;
  try {
    // Resolve from the SDK package
    const sdkSentinelPath = resolveSentinelShellPath();
    sentinelShellPath = join(tmpDir, 'sentinel-shell.sh');
    await copyFile(sdkSentinelPath, sentinelShellPath);
    await chmod(sentinelShellPath, 0o755);
    process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Sentinel Shell: ACTIVE (trap DEBUG)\n`);
  } catch {
    process.stderr.write(`\x1b[33m[clawsig]\x1b[0m Sentinel Shell: disabled (could not locate sentinel-shell.sh)\n`);
  }

  // Start FS Sentinel
  const fsSentinel = new FsSentinel({
    watchDirs: [process.cwd()],
  });
  fsSentinel.start();
  process.stderr.write(`\x1b[36m[clawsig]\x1b[0m FS Sentinel: ACTIVE (fs.watch recursive)\n`);

  // Start Network Sentinel
  const netSentinel = new NetSentinel({
    pollIntervalMs: 500,
  });
  // PID set after spawn

  // 4. Start local proxy with Causal Sieve
  // Use passthrough mode by default (forward directly to upstream provider).
  // This preserves the agent's native auth (OAuth, API keys) without requiring
  // clawproxy CST tokens. Gateway receipts are only available when an explicit
  // provider API key is configured for clawproxy routing.
  const usePassthrough = !process.env['CLAWSIG_USE_CLAWPROXY'];
  const proxy = await startLocalProxy({
    agentDid,
    runId,
    policy,
    cwd: process.cwd(),
    passthrough: usePassthrough,
    onViolation: (v) => {
      process.stderr.write(
        `\x1b[31m[clawsig:guillotine]\x1b[0m VIOLATION: ${v.reason}\n`,
      );
    },
  });
  process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Local proxy listening on 127.0.0.1:${proxy.port}\n`);
  process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Causal Sieve: ACTIVE (tool observability enabled)\n`);
  if (usePassthrough) {
    process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Mode: passthrough (direct to upstream, Sieve-only)\n`);
  }

  // 4b. Build and resolve the interposition library (Layer 6)
  const interposeLib = await resolveInterposeLibrary(tmpDir);
  if (interposeLib) {
    process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Interpose Sentinel: ACTIVE (${interposeLib.mechanism})\n`);
  } else {
    process.stderr.write(`\x1b[33m[clawsig]\x1b[0m Interpose Sentinel: disabled (no C compiler or cached lib)\n`);
  }

  // 5. Spawn child process with env overrides
  const childEnv: Record<string, string | undefined> = {
    ...process.env,
    OPENAI_BASE_URL: `http://127.0.0.1:${proxy.port}/v1/proxy/openai`,
    ANTHROPIC_BASE_URL: `http://127.0.0.1:${proxy.port}/v1/proxy/anthropic`,
    CLAWSIG_RUN_ID: runId,
    CLAWSIG_AGENT_DID: agentDid.did,

    // RED TEAM FIX #6: Socket-level interception preload.
    CLAWSIG_PROXY_PORT: String(proxy.port),
    CLAWSIG_PROXY_URL: `http://127.0.0.1:${proxy.port}`,
    NODE_OPTIONS: [
      process.env['NODE_OPTIONS'],
      `--import ${resolvePreloadPath()}`,
    ].filter(Boolean).join(' '),

    // Polyglot proxy env vars
    HTTP_PROXY: `http://127.0.0.1:${proxy.port}`,
    HTTPS_PROXY: `http://127.0.0.1:${proxy.port}`,
    http_proxy: `http://127.0.0.1:${proxy.port}`,
    https_proxy: `http://127.0.0.1:${proxy.port}`,
    NO_PROXY: 'localhost,127.0.0.1',
    no_proxy: 'localhost,127.0.0.1',

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
  };

  // Pass through existing API keys from parent env
  if (process.env['OPENAI_API_KEY']) {
    childEnv['OPENAI_API_KEY'] = process.env['OPENAI_API_KEY'];
  }
  if (process.env['ANTHROPIC_API_KEY']) {
    childEnv['ANTHROPIC_API_KEY'] = process.env['ANTHROPIC_API_KEY'];
  }

  process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Spawning: ${command} ${args.join(' ')}\n`);
  process.stderr.write(`\n`);

  const exitCode = await new Promise<number>((resolve) => {
    const child = spawn(command, args, {
      env: childEnv,
      stdio: 'inherit',
      shell: false,
    });

    // Track child PID for network sentinel
    if (child.pid) {
      netSentinel.setTargetPid(child.pid);
    }
    netSentinel.start();
    process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Net Sentinel: ACTIVE (${child.pid ? `PID ${child.pid}` : 'all connections'})\n`);

    child.on('error', (err) => {
      process.stderr.write(`\n\x1b[31m[clawsig]\x1b[0m Failed to spawn: ${err.message}\n`);
      resolve(1);
    });

    child.on('exit', (code) => {
      resolve(code ?? 1);
    });
  });

  // 6. Stop sentinels, harvest data, compile proof bundle
  fsSentinel.stop();
  netSentinel.stop();

  process.stderr.write(`\n\x1b[36m[clawsig]\x1b[0m Child exited with code ${exitCode}\n`);
  process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Receipts collected: ${proxy.receiptCount}\n`);

  // Harvest Sentinel Shell trace
  const shellEvents = await harvestShellTrace(traceFile);
  const executionReceipts = await synthesizeExecutionReceipts(shellEvents, agentDid.did, runId);

  // Harvest Interpose Sentinel trace (same JSONL file, layer="interpose")
  const interposeEvents = await harvestInterposeTrace(traceFile);
  const interposeReceipts = await synthesizeInterposeReceipts(interposeEvents, agentDid.did, runId);

  // Harvest Network Sentinel events
  const netEvents = netSentinel.getEvents();
  const networkReceipts = await synthesizeNetworkReceipts(netEvents, agentDid.did, runId);

  // Merge interpose network receipts into network receipts
  const allNetworkReceipts = [...networkReceipts, ...interposeReceipts.network];
  const allExecutionReceipts = [...executionReceipts, ...interposeReceipts.execution];

  // Sentinel summary
  process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Sentinel Shell: ${shellEvents.length} commands captured\n`);
  process.stderr.write(`\x1b[36m[clawsig]\x1b[0m FS Sentinel: ${fsSentinel.eventCount} file events\n`);
  process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Net Sentinel: ${netSentinel.eventCount} connections (${netSentinel.suspiciousCount} suspicious)\n`);
  if (interposeEvents.length > 0) {
    process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Interpose Sentinel: ${interposeEvents.length} syscalls (${interposeReceipts.network.length} net, ${interposeReceipts.execution.length} exec)\n`);
  }

  if (netSentinel.suspiciousCount > 0) {
    process.stderr.write(`\x1b[31m[clawsig]\x1b[0m WARNING: Suspicious network connections detected!\n`);
    for (const e of netSentinel.getSuspiciousEvents().slice(0, 5)) {
      process.stderr.write(`\x1b[31m[clawsig]\x1b[0m   ${e.remoteAddress} (${e.processName ?? 'unknown'} PID:${e.pid ?? '?'})\n`);
    }
  }

  const bundle = await proxy.compileProofBundle();
  await proxy.stop();

  // Inject sentinel receipts into the bundle
  if (allExecutionReceipts.length > 0) {
    bundle.payload.execution_receipts = allExecutionReceipts;
  }
  if (allNetworkReceipts.length > 0) {
    bundle.payload.network_receipts = allNetworkReceipts;
  }
  // Add sentinel metadata
  bundle.payload.metadata = {
    ...bundle.payload.metadata,
    sentinels: {
      shell_events: shellEvents.length,
      fs_events: fsSentinel.eventCount,
      net_events: netSentinel.eventCount,
      net_suspicious: netSentinel.suspiciousCount,
      interpose_events: interposeEvents.length,
      interpose_active: !!interposeLib,
    },
  };

  // Print summary
  process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Bundle ID: ${bundle.payload.bundle_id}\n`);
  process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Event chain: ${bundle.payload.event_chain?.length ?? 0} events\n`);
  process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Gateway receipts: ${bundle.payload.receipts?.length ?? 0}\n`);
  process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Tool receipts (Causal Sieve): ${proxy.toolReceiptCount}\n`);
  process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Side-effect receipts: ${proxy.sideEffectReceiptCount}\n`);
  process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Execution receipts: ${allExecutionReceipts.length} (shell: ${executionReceipts.length}, interpose: ${interposeReceipts.execution.length})\n`);
  process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Network receipts: ${allNetworkReceipts.length} (polling: ${networkReceipts.length}, interpose: ${interposeReceipts.network.length})\n`);
  if (proxy.violationCount > 0) {
    process.stderr.write(`\x1b[31m[clawsig]\x1b[0m Policy violations: ${proxy.violationCount}\n`);
  }

  // Clean up temp dir
  try {
    const { rm } = await import('node:fs/promises');
    await rm(tmpDir, { recursive: true, force: true });
  } catch { /* ignore cleanup errors */ }

  // 5. Always write bundle to .clawsig/proof_bundle.json
  await writeBundleToDisk(bundle);

  // 5b. Also write to custom output path if requested
  if (outputPath) {
    await writeFile(outputPath, JSON.stringify(bundle, null, 2), 'utf-8');
    process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Bundle also written to: ${outputPath}\n`);
  }

  // 6. Publish to VaaS and try to attach badge to open PR
  if (publish) {
    const publishResult = await publishBundle(bundle);
    if (publishResult.badgeUrl && publishResult.ledgerUrl) {
      await tryAttachBadgeToPR(publishResult.badgeUrl, publishResult.ledgerUrl);
    }
  } else {
    process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Publish skipped (--no-publish)\n`);

    // Always print the local bundle to stdout if not publishing
    if (!outputPath) {
      process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Proof bundle (local):\n`);
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
 */
async function writeBundleToDisk(bundle: SignedEnvelope<ProofBundlePayload>): Promise<void> {
  try {
    const dir = join(process.cwd(), '.clawsig');
    await mkdir(dir, { recursive: true });
    const bundlePath = join(dir, 'proof_bundle.json');
    await writeFile(bundlePath, JSON.stringify(bundle, null, 2), 'utf-8');
    process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Bundle written to: ${bundlePath}\n`);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'unknown error';
    process.stderr.write(
      `\x1b[33m[clawsig]\x1b[0m Could not write bundle to .clawsig/proof_bundle.json: ${message}\n`,
    );
  }
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
    const sdkDir = sdkPkg.replace(/\/package\.json$/, '');
    const preloadPath = join(sdkDir, 'src', 'preload.mjs');
    return `file://${preloadPath}`;
  } catch {
    // Last resort: bare specifier, child must resolve it
    return '@clawbureau/clawsig-sdk/preload';
  }
}

/**
 * Load local WPC policy from .clawsig/policy.json (if present).
 * Returns null if no policy file exists.
 */
async function loadLocalPolicy(): Promise<LocalPolicy | null> {
  try {
    const policyPath = join(process.cwd(), '.clawsig', 'policy.json');
    const raw = await readFile(policyPath, 'utf-8');
    const parsed = JSON.parse(raw);
    if (parsed?.statements && Array.isArray(parsed.statements)) {
      return { statements: parsed.statements };
    }
    return null;
  } catch {
    return null;
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
      await execFileAsync('which', ['gh']);
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
    const sdkDir = sdkPkg.replace(/\/package\.json$/, '');
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
}

interface InterposeSynthesized {
  network: NetworkReceiptPayload[];
  execution: ExecutionReceiptPayload[];
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
    const sdkDir = sdkPkg.replace(/\/package\.json$/, '');
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
    }
  }

  return { network, execution };
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

