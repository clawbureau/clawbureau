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
import { readFile, writeFile, mkdir, unlink, copyFile, chmod, stat } from 'node:fs/promises';
import { openSync, readSync, closeSync } from 'node:fs';
import { promisify } from 'node:util';
import { join, dirname, basename } from 'node:path';
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
  sha256B64u,
} from '@clawbureau/clawsig-sdk';
import type {
  SignedEnvelope,
  ProofBundlePayload,
  ExecutionReceiptPayload,
  NetworkReceiptPayload,
  LocalPolicy,
  CommandAnalysis,
  VirSource,
  VirReceiptPayload,
  VirReceiptEnvelope,
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

  // 2. Load local WPC policy (if present) and compile for bash sentinel
  const policy = await loadLocalPolicy();
  if (policy) {
    const policyJsonPath = join(process.cwd(), '.clawsig', 'policy.json');
    const compiledPolicyPath = join(process.cwd(), '.clawsig', 'policy.compiled');
    if (!isWindows) {
      await compilePolicyToBash(policyJsonPath, compiledPolicyPath).catch(() => {});
      process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Policy loaded: ${policy.statements.length} statements (compiled for sentinel)\n`);
    } else {
      process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Policy loaded: ${policy.statements.length} statements (active in Sieve)\n`);
    }
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

      process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Sentinel Shell: ACTIVE (trap DEBUG + policy evaluator)\n`);
    } catch {
      process.stderr.write(`\x1b[33m[clawsig]\x1b[0m Sentinel Shell: disabled (could not locate sentinel-shell.sh)\n`);
    }
  } else {
    process.stderr.write(`\x1b[33m[clawsig]\x1b[0m Sentinel Shell: disabled (Windows — BASH_ENV not available)\n`);
  }

  // Start FS Sentinel — pass traceFile explicitly (child writes to it, parent reads)
  const fsSentinel = new FsSentinel({
    watchDirs: [process.cwd()],
    traceFile,
  });
  fsSentinel.start();
  process.stderr.write(`\x1b[36m[clawsig]\x1b[0m FS Sentinel: ACTIVE (fs.watch + trace polling)\n`);

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
  const configuredClawproxyUrl = process.env['CLAWSIG_CLAWPROXY_URL']?.trim();

  const proxy = await startLocalProxy({
    agentDid,
    runId,
    policy,
    cwd: process.cwd(),
    passthrough: usePassthrough,
    ...(configuredClawproxyUrl ? { clawproxyUrl: configuredClawproxyUrl } : {}),
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
  } else if (configuredClawproxyUrl) {
    process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Mode: clawproxy (${configuredClawproxyUrl})\n`);
  }

  // 4b. Build and resolve the interposition library (Layer 6)
  const disableInterpose = process.env['CLAWSIG_DISABLE_INTERPOSE'] === '1';
  const interposeLib = disableInterpose ? null : await resolveInterposeLibrary(tmpDir);
  if (interposeLib) {
    process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Interpose Sentinel: ACTIVE (${interposeLib.mechanism})\n`);
  } else {
    const reason = disableInterpose
      ? 'disabled by CLAWSIG_DISABLE_INTERPOSE=1'
      : (isWindows ? 'Windows gracefully bypassed' : 'no C compiler or cached lib');
    process.stderr.write(`\x1b[33m[clawsig]\x1b[0m Interpose Sentinel: disabled (${reason})\n`);
  }

  // 5. Spawn child process with env overrides
  const commandName = basename(command).toLowerCase();
  const forceBaseUrlOverride = process.env['CLAWSIG_FORCE_BASE_URL_OVERRIDE'] === '1';
  const disableBaseUrlOverride = commandName === 'codex' && !forceBaseUrlOverride;

  const bountyNonce = process.env['CLAWSIG_BOUNTY_NONCE'];
  const childEnv: Record<string, string | undefined> = {
    ...process.env,
    CLAWSIG_RUN_ID: runId,
    CLAWSIG_AGENT_DID: agentDid.did,
    ...(bountyNonce ? { CLAWSIG_BOUNTY_NONCE: bountyNonce } : {}),

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
  };

  if (!disableBaseUrlOverride) {
    childEnv['OPENAI_BASE_URL'] = `http://127.0.0.1:${proxy.port}/v1/proxy/openai`;
    childEnv['ANTHROPIC_BASE_URL'] = `http://127.0.0.1:${proxy.port}/v1/proxy/anthropic`;
  } else {
    process.stderr.write(`\x1b[33m[clawsig]\x1b[0m Provider base override disabled for ${commandName} (OAuth compatibility). Set CLAWSIG_FORCE_BASE_URL_OVERRIDE=1 to force.\n`);
  }

  // Pass through existing API keys from parent env
  if (process.env['OPENAI_API_KEY']) {
    childEnv['OPENAI_API_KEY'] = process.env['OPENAI_API_KEY'];
  }
  if (process.env['ANTHROPIC_API_KEY']) {
    childEnv['ANTHROPIC_API_KEY'] = process.env['ANTHROPIC_API_KEY'];
  }

  process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Spawning: ${command} ${args.join(' ')}\n\n`);

  let childPid = 0;
  let childProcess: ChildProcess | null = null;

  // Handle Ctrl+C gracefully: forward to child instead of killing parent first.
  // Without this, Ctrl+C may orphan the child process (especially on Windows).
  const sigintHandler = () => {
    if (childProcess && !childProcess.killed) childProcess.kill('SIGINT');
  };
  process.on('SIGINT', sigintHandler);

  const exitCode = await new Promise<number>((resolve) => {
    childProcess = spawn(command, args, {
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
    process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Net Sentinel: ACTIVE (${childPid ? `PID ${childPid}` : 'all connections'})\n`);

    childProcess.on('error', (err) => {
      process.stderr.write(`\n\x1b[31m[clawsig]\x1b[0m Failed to spawn: ${err.message}\n`);
      resolve(1);
    });

    childProcess.on('exit', (code) => {
      resolve(code ?? 1);
    });
  });

  process.off('SIGINT', sigintHandler);

  // 6. Stop sentinels, harvest data, compile proof bundle
  await fsSentinel.stop();
  netSentinel.stop();

  process.stderr.write(`\n\x1b[36m[clawsig]\x1b[0m Child exited with code ${exitCode}\n`);
  process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Receipts collected: ${proxy.receiptCount}\n`);

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

  // R39: Offline TLS decryption — decrypt ciphertext spool + keylog to extract
  // actual model names, request/response hashes, and token counts from encrypted traffic.
  // This is the "Oracle Arbitrage" countermeasure: proves which model was ACTUALLY called.
  let tlsDecryptReceipts: Record<string, unknown>[] = [];
  const keylogFile = `${traceFile}.keys`;
  const cipherFile = `${traceFile}.clawcipher`;
  let keylogPresent = false;
  let cipherSpoolPresent = false;
  try {
    const { access: fsAccess } = await import('node:fs/promises');
    await fsAccess(keylogFile);
    keylogPresent = true;
  } catch {
    // optional artifact
  }
  try {
    const { access: fsAccess } = await import('node:fs/promises');
    await fsAccess(cipherFile);
    cipherSpoolPresent = true;
    const { decryptTraffic } = await import('@clawbureau/clawsig-sdk');
    const decryptResult = await decryptTraffic(traceFile, keylogFile, cipherFile);
    if (decryptResult.receipts.length > 0) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      tlsDecryptReceipts = decryptResult.receipts.map((r: any) => ({
        ...r,
        receipt_type: 'tls_decrypted_gateway',
        agent_did: agentDid.did,
        binding: { run_id: runId },
      }));
      process.stderr.write(`\x1b[36m[clawsig]\x1b[0m TLS Decrypt: ${decryptResult.receipts.length} requests decrypted from ${decryptResult.connections.length} connections\n`);
      if (decryptResult.errors.length > 0) {
        process.stderr.write(`\x1b[33m[clawsig]\x1b[0m TLS Decrypt warnings: ${decryptResult.errors.slice(0, 3).join('; ')}\n`);
      }
    }
  } catch {
    // No cipher spool or decrypt unavailable — non-fatal
  }

  // Harvest Network Sentinel events
  const netEvents = netSentinel.getEvents();
  const networkReceipts = await synthesizeNetworkReceipts(netEvents, agentDid.did, runId);

  // Merge interpose network receipts into network receipts
  const allNetworkReceipts = [...networkReceipts, ...interposeReceipts.network];
  const allExecutionReceipts = [...executionReceipts, ...interposeReceipts.execution];

  // Sentinel summary
  if (!isWindows) process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Sentinel Shell: ${shellEvents.length} commands captured\n`);
  process.stderr.write(`\x1b[36m[clawsig]\x1b[0m FS Sentinel: ${fsSentinel.eventCount} file events\n`);
  process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Net Sentinel: ${netSentinel.eventCount} connections (${netSentinel.suspiciousCount} suspicious)\n`);
  if (interposeEvents.length > 0) {
    const parts = [`${interposeReceipts.network.length} net`, `${interposeReceipts.execution.length} exec`];
    if (interposeReceipts.gateway.length > 0) parts.push(`${interposeReceipts.gateway.length} gateway`);
    if (interposeReceipts.transcript.length > 0) parts.push(`${interposeReceipts.transcript.length} transcript`);
    if (interposeReceipts.toolCalls.length > 0) parts.push(`${interposeReceipts.toolCalls.length} tool_calls`);
    if (interposeReceipts.anomalies.length > 0) parts.push(`${interposeReceipts.anomalies.length} anomalies`);
    process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Interpose Sentinel: ${interposeEvents.length} syscalls (${parts.join(', ')})\n`);
  }
  if (preloadGatewayReceipts.length > 0) {
    process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Preload LLM intercepts: ${preloadGatewayReceipts.length} (via diagnostics_channel + fetch)\n`);
  }
  if (sniGatewayReceipts.length > 0) {
    process.stderr.write(`\x1b[36m[clawsig]\x1b[0m TLS SNI intercepts: ${sniEvents.length} connections → ${sniGatewayReceipts.length} LLM domains\n`);
  }
  if (interposeOracle.totalEvents > 0) {
    const oState = interposeOracle.getSummary();
    process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Interpose Oracle: ${oState.pid_tree_size} PIDs, ${oState.bound_ports.length} server ports${oState.bound_ports.length > 0 ? ` (${oState.bound_ports.join(',')})` : ''}, ${oState.env_audits} credentials, ${oState.cred_leaks} leaks\n`);
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
  // Inject Agent Genealogy Receipt (full process tree with harness attribution)
  const genealogyTree = interposeOracle.getGenealogyTree();
  if (genealogyTree && Object.keys(genealogyTree).length > 0) {
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
    bundle.payload.receipts = [...existing, genealogyReceipt] as typeof bundle.payload.receipts;
  }

  // Inject Security Audit Receipts (env credential hashes + DLP leak alerts)
  if (interposeOracle.envAudits.length > 0 || interposeOracle.credLeaks.length > 0) {
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
    bundle.payload.receipts = [...existing, ...securityReceipts] as typeof bundle.payload.receipts;
  }

  // R43: Synthesize VIR (Verified Inference Receipt) v0.1 from multi-source evidence
  let merkleDisclosure: { chain_hash: string; event_count: number } | undefined;
  for (const event of interposeEvents) {
    if (event.syscall === 'merkle_final') {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const raw = event as any;
      const eventCount = typeof raw.count === 'number' ? raw.count : Number(raw.count);
      const chainHash = typeof raw.hash === 'string' ? raw.hash : undefined;
      if (chainHash && Number.isFinite(eventCount)) {
        merkleDisclosure = {
          chain_hash: chainHash,
          event_count: Math.max(0, eventCount),
        };
      }
    }
  }

  const sourceWeight: Record<VirSource, number> = {
    tls_decrypt: 5,
    gateway: 4,
    interpose: 3,
    preload: 2,
    sni: 1,
  };

  type VirCandidate = {
    source: VirSource;
    weight: number;
    ts: number;
    data: Record<string, unknown>;
  };

  const toRecord = (value: unknown): Record<string, unknown> | null => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
    return value as Record<string, unknown>;
  };

  const pickString = (...values: unknown[]): string | undefined => {
    for (const value of values) {
      if (typeof value === 'string' && value.trim().length > 0) return value;
    }
    return undefined;
  };

  const pickNumber = (...values: unknown[]): number | undefined => {
    for (const value of values) {
      if (typeof value === 'number' && Number.isFinite(value)) return value;
      if (typeof value === 'string' && value.trim().length > 0) {
        const parsed = Number(value);
        if (Number.isFinite(parsed)) return parsed;
      }
    }
    return undefined;
  };

  const parseBoolean = (value: unknown): boolean | undefined => {
    if (typeof value === 'boolean') return value;
    if (value === 'true') return true;
    if (value === 'false') return false;
    return undefined;
  };

  const safeTs = (value: unknown): number => {
    const ms = new Date(typeof value === 'string' || typeof value === 'number' ? value : 0).getTime();
    return Number.isFinite(ms) ? ms : 0;
  };

  const tryExtractGatewayPayload = (entry: unknown): Record<string, unknown> | null => {
    const obj = toRecord(entry);
    if (!obj) return null;
    if (obj.envelope_type !== 'gateway_receipt') return null;
    return toRecord(obj.payload);
  };

  const virCandidates: VirCandidate[] = [];

  const pushCandidate = (source: VirSource, raw: unknown, tsValue: unknown): void => {
    const data = toRecord(raw);
    if (!data) return;
    virCandidates.push({
      source,
      weight: sourceWeight[source],
      ts: safeTs(tsValue),
      data,
    });
  };

  for (const receipt of bundle.payload.receipts || []) {
    const payload = tryExtractGatewayPayload(receipt);
    if (!payload) continue;
    pushCandidate(
      'gateway',
      payload,
      payload.timestamp ?? payload.issued_at,
    );
  }

  for (const receipt of tlsDecryptReceipts) {
    const r = toRecord(receipt);
    if (!r) continue;
    pushCandidate('tls_decrypt', r, r.timestamp);
  }

  for (const receipt of interposeReceipts.gateway) {
    const r = toRecord(receipt);
    if (!r) continue;
    pushCandidate('interpose', r, r.timestamp);
  }

  for (const receipt of preloadGatewayReceipts) {
    const r = toRecord(receipt);
    if (!r) continue;
    const receiptType = pickString(r.receipt_type);
    if (receiptType && receiptType !== 'gateway') continue;
    pushCandidate('preload', r, r.timestamp);
  }

  for (const receipt of sniGatewayReceipts) {
    const r = toRecord(receipt);
    if (!r) continue;
    pushCandidate('sni', r, r.timestamp);
  }

  // Sort chronologically then collapse into 2s windows, keeping highest-precedence source.
  virCandidates.sort((a, b) => a.ts - b.ts);

  const groupedVir: VirCandidate[] = [];
  for (const candidate of virCandidates) {
    let matched = false;
    for (const group of groupedVir) {
      if (Math.abs(candidate.ts - group.ts) < 2000) {
        if (candidate.weight > group.weight) {
          group.weight = candidate.weight;
          group.source = candidate.source;
          group.data = candidate.data;
          group.ts = candidate.ts;
        }
        matched = true;
        break;
      }
    }
    if (!matched) groupedVir.push({ ...candidate });
  }

  const harnessAttestation = interposeEvents.find((event) => event.syscall === 'harness_attestation');
  const harnessRecheck = interposeEvents.find((event) => event.syscall === 'harness_recheck');
  const harnessAttestationRecord = toRecord(harnessAttestation);
  const harnessRecheckRecord = toRecord(harnessRecheck);
  const eventChainLen = bundle.payload.event_chain?.length ?? (shellEvents.length + interposeEvents.length);
  const encoder = new TextEncoder();

  const virReceipts: VirReceiptEnvelope[] = [];

  for (const grouped of groupedVir) {
    const data = grouped.data;

    const provider = pickString(data.provider, data.hostname, data.authority) ?? 'unknown';
    const modelClaimed = pickString(data.req_model, data.model_claimed, data.model, data.model_name) ?? 'unknown';
    const modelObserved = pickString(data.model, data.model_observed, data.res_model) ?? modelClaimed;

    const requestHash =
      pickString(
        data.request_hash_b64u,
        data.messages_hash_b64u,
        data.requestBodyHash,
        data.req_body_sha256,
        data.url_hash_b64u,
        data.addr_hash_b64u,
      ) ??
      await sha256B64u(encoder.encode(`vir:req:${runId}:${crypto.randomUUID()}`));

    const responseHash =
      pickString(
        data.response_hash_b64u,
        data.responseBodyHash,
        data.res_body_sha256,
      ) ??
      await sha256B64u(encoder.encode(`vir:res:${runId}:${crypto.randomUUID()}`));

    const tokensInput = Math.max(0, Math.floor(pickNumber(data.tokens_input, data.tokensInput, data.req_bytes) ?? 0));
    const tokensOutput = Math.max(0, Math.floor(pickNumber(data.tokens_output, data.tokensOutput, data.res_bytes) ?? 0));
    const latencyMs = Math.max(0, Math.floor(pickNumber(data.latency_ms, data.latencyMs) ?? 0));

    const tsMs = grouped.ts > 0 ? grouped.ts : Date.now();
    const timestamp = pickString(data.timestamp, data.issued_at) ?? new Date(tsMs).toISOString();

    const bindingRecord = toRecord(data.binding);
    const boundEventHash = pickString(bindingRecord?.event_hash_b64u, data.event_hash_b64u);

    const disclosedLeaves: Record<string, string> = {
      request_hash: await sha256B64u(encoder.encode(`request_hash:${requestHash}`)),
      response_hash: await sha256B64u(encoder.encode(`response_hash:${responseHash}`)),
      source: await sha256B64u(encoder.encode(`source:${grouped.source}`)),
      provider: await sha256B64u(encoder.encode(`provider:${provider}`)),
      model: await sha256B64u(encoder.encode(`model:${modelObserved}`)),
      token_counts: await sha256B64u(encoder.encode(`tokens:${tokensInput}:${tokensOutput}`)),
      latency: await sha256B64u(encoder.encode(`latency:${latencyMs}`)),
    };
    if (boundEventHash) {
      disclosedLeaves.event_hash = await sha256B64u(encoder.encode(`event_hash:${boundEventHash}`));
    }

    const sortedLeafKeys = Object.keys(disclosedLeaves).sort();
    const leafHashes = sortedLeafKeys.map((key) => disclosedLeaves[key]!);
    const merkleRoot = await sha256B64u(encoder.encode(leafHashes.join('|')));

    const harnessRecheckMatch = parseBoolean(harnessRecheckRecord?.text_hash_match) ?? false;
    const harnessAttestationHash = pickString(
      harnessAttestationRecord?.dylib_text_hash,
      harnessAttestationRecord?.text_hash,
    );

    const virPayload: VirReceiptPayload = {
      receipt_version: '1',
      receipt_id: `vir_${crypto.randomUUID()}`,
      source: grouped.source,
      provider,
      model: modelObserved,
      model_claimed: modelClaimed,
      model_observed: modelObserved,
      request_hash_b64u: requestHash,
      response_hash_b64u: responseHash,
      tokens_input: tokensInput,
      tokens_output: tokensOutput,
      latency_ms: latencyMs,
      agent_did: agentDid.did,
      timestamp,
      binding: {
        run_id: runId,
        ...(boundEventHash ? { event_hash_b64u: boundEventHash } : {}),
        ...(bountyNonce ? { nonce: bountyNonce } : {}),
      },
      transport_attestation: {
        source: grouped.source,
        keylog_present: keylogPresent,
        cipher_spool_present: cipherSpoolPresent,
        decrypted_match: grouped.source === 'tls_decrypt' ? modelClaimed === modelObserved : null,
      },
      process_attestation: {
        harness_attestation_hash: harnessAttestationHash ?? null,
        harness_recheck_match: harnessRecheckMatch,
        interpose_active: !!interposeLib,
      },
      semantic_attestation: {
        tool_calls_count: interposeReceipts.toolCalls.length,
        side_effect_receipts_count: proxy.sideEffectReceiptCount,
        event_chain_len: eventChainLen,
      },
      selective_disclosure: {
        merkle_root_b64u: merkleRoot,
        leaf_hashes_b64u: leafHashes,
        disclosed_leaves: disclosedLeaves,
        redacted_fields: ['tool_transcript', 'policy_evidence'],
      },
      ...(merkleDisclosure ? { merkle_disclosure: merkleDisclosure } : {}),
    };

    const payloadHashB64u = await sha256B64u(encoder.encode(JSON.stringify(virPayload)));
    const signatureB64u = await agentDid.sign(encoder.encode(payloadHashB64u));

    virReceipts.push({
      envelope_version: '1',
      envelope_type: 'vir_receipt',
      payload: virPayload,
      payload_hash_b64u: payloadHashB64u,
      hash_algorithm: 'SHA-256',
      signature_b64u: signatureB64u,
      algorithm: 'Ed25519',
      signer_did: agentDid.did,
      issued_at: timestamp,
    });
  }

  if (virReceipts.length > 0) {
    bundle.payload.vir_receipts = virReceipts;
  }

  // Inject preload + SNI + interpose FSM receipts into the bundle
  {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const existing = (bundle.payload.receipts ?? []) as any[];
    const additions = [
      ...preloadGatewayReceipts,
      ...sniGatewayReceipts,
      ...interposeReceipts.gateway,
      ...interposeReceipts.transcript,
      ...interposeReceipts.toolCalls,
      ...interposeReceipts.anomalies,
      ...tlsDecryptReceipts,
    ];
    if (additions.length > 0) {
      bundle.payload.receipts = [...existing, ...additions] as typeof bundle.payload.receipts;
    }
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
      interpose_gateway: interposeReceipts.gateway.length,
      interpose_transcript: interposeReceipts.transcript.length,
      interpose_tool_calls: interposeReceipts.toolCalls.length,
      interpose_anomalies: interposeReceipts.anomalies.length,
      preload_llm_events: preloadGatewayReceipts.length,
      tls_sni_events: sniEvents.length,
      tls_sni_receipts: sniGatewayReceipts.length,
      tls_decrypt_receipts: tlsDecryptReceipts.length,
      vir_receipts: virReceipts.length,
      interpose_state: interposeOracle.getSummary(),
    },
  };

  // Print summary
  process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Bundle ID: ${bundle.payload.bundle_id}\n`);
  process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Event chain: ${bundle.payload.event_chain?.length ?? 0} events\n`);
  const totalReceipts = bundle.payload.receipts?.length ?? 0;
  const nonGateway = interposeReceipts.transcript.length + interposeReceipts.toolCalls.length + interposeReceipts.anomalies.length;
  const totalGw = totalReceipts - nonGateway;
  const proxyGateway = totalGw - preloadGatewayReceipts.length - sniGatewayReceipts.length - interposeReceipts.gateway.length - tlsDecryptReceipts.length;
  process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Gateway receipts: ${totalGw} (proxy: ${proxyGateway < 0 ? 0 : proxyGateway}, preload: ${preloadGatewayReceipts.length}, sni: ${sniGatewayReceipts.length}, interpose: ${interposeReceipts.gateway.length}, tls_decrypt: ${tlsDecryptReceipts.length})\n`);
  if (virReceipts.length > 0) {
    process.stderr.write(`\x1b[36m[clawsig]\x1b[0m VIR v0.1 receipts synthesized: ${virReceipts.length}\n`);
  }
  if (interposeReceipts.transcript.length > 0) {
    process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Transcript events: ${interposeReceipts.transcript.length} (via interpose FSM)\n`);
  }
  if (interposeReceipts.toolCalls.length > 0) {
    process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Tool call events: ${interposeReceipts.toolCalls.length} (via interpose FSM)\n`);
  }
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

