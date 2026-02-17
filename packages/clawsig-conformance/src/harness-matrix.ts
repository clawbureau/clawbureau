/**
 * Harness matrix runner for clawsig wrap E2E tests.
 *
 * Matrix dimensions:
 * - Agents: claude, pi, openclaw, codex, opencode, gemini
 * - Modes: mock (default), live (optional via CLAWSIG_E2E_LIVE=1)
 * - Layers: proxy-only, proxy+interpose (macOS only)
 */

import { spawn } from 'node:child_process';
import { access, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { startMockProxy, type MockProxyHandle } from './mock-proxy.js';

export type HarnessAgent = 'claude' | 'pi' | 'openclaw' | 'codex' | 'opencode' | 'gemini';
export type HarnessMode = 'mock' | 'live';
export type HarnessLayer = 'proxy' | 'interpose';
export type HarnessCaseStatus = 'PASS' | 'FAIL' | 'SKIP';

export interface HarnessCaseMetrics {
  bundle: 0 | 1;
  receipts: number;
  events: number;
  interpose_events?: number;
}

export interface HarnessCaseResult {
  id: string;
  agent: HarnessAgent | string;
  mode: HarnessMode;
  layer: HarnessLayer;
  status: HarnessCaseStatus;
  reason?: string;
  errors: string[];
  metrics: HarnessCaseMetrics;
  duration_ms: number;
  exit_code: number | null;
  timed_out: boolean;
  cli_path?: string;
  bundle_path?: string;
  expected_model?: string;
  stdout_tail?: string;
  stderr_tail?: string;
}

export interface HarnessMatrixSummary {
  passed: number;
  failed: number;
  skipped: number;
  executed: number;
  detected_agents: number;
  requested_agents: number;
}

export interface HarnessMatrixRun {
  started_at: string;
  finished_at: string;
  root_dir: string;
  results_path: string;
  live_enabled: boolean;
  interpose_supported: boolean;
  timeout_ms: number;
  prompt: string;
  results: HarnessCaseResult[];
  summary: HarnessMatrixSummary;
}

export interface HarnessMatrixOptions {
  rootDir?: string;
  timeoutMs?: number;
  prompt?: string;
  includeLive?: boolean;
  agents?: HarnessAgent[];
  resultsPath?: string;
  /** Optional explicit layer list override (e.g. ['proxy'] for Linux lanes). */
  layers?: HarnessLayer[];
}

interface AgentSpec {
  id: HarnessAgent;
  cli: string;
  commandArgs: (prompt: string) => string[];
  mockEnv: (mockProxyUrl: string) => Record<string, string>;
  expectedModelEnv?: string;
  expectedModelDefault?: string;
}

interface GatewayReceiptEnvelope {
  envelope_type: 'gateway_receipt';
  payload: {
    model?: string;
    tokens_input?: number;
    tokens_output?: number;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

const DEFAULT_TIMEOUT_MS = 60_000;
const DEFAULT_PROMPT = 'Say exactly: hello world';
const DEFAULT_RESULTS_PATH = '.clawsig/e2e-results.json';
const DEFAULT_AGENTS: HarnessAgent[] = ['claude', 'pi', 'openclaw', 'codex', 'opencode', 'gemini'];

const AGENTS: Record<HarnessAgent, AgentSpec> = {
  claude: {
    id: 'claude',
    cli: 'claude',
    commandArgs: (prompt) => ['--print', '--dangerously-skip-permissions', prompt],
    mockEnv: (mockProxyUrl) => ({
      ANTHROPIC_BASE_URL: mockProxyUrl,
    }),
    expectedModelEnv: 'CLAWSIG_E2E_EXPECTED_MODEL_CLAUDE',
  },
  pi: {
    id: 'pi',
    cli: 'pi',
    commandArgs: (prompt) => ['--provider', 'anthropic', '-p', prompt],
    mockEnv: (mockProxyUrl) => ({
      ANTHROPIC_BASE_URL: mockProxyUrl,
      OPENAI_BASE_URL: mockProxyUrl,
    }),
    expectedModelEnv: 'CLAWSIG_E2E_EXPECTED_MODEL_PI',
  },
  openclaw: {
    id: 'openclaw',
    cli: 'openclaw',
    commandArgs: (prompt) => ['agent', '--local', '--json', '--session-id', 'clawsig-e2e', '--message', prompt],
    mockEnv: (mockProxyUrl) => ({
      OPENAI_BASE_URL: mockProxyUrl,
      ANTHROPIC_BASE_URL: mockProxyUrl,
    }),
    expectedModelEnv: 'CLAWSIG_E2E_EXPECTED_MODEL_OPENCLAW',
  },
  codex: {
    id: 'codex',
    cli: 'codex',
    commandArgs: (prompt) => [
      'exec',
      '--json',
      '--skip-git-repo-check',
      '--dangerously-bypass-approvals-and-sandbox',
      '-c',
      'model_provider=openai',
      '-c',
      'model="gpt-4-conformance-mock"',
      prompt,
    ],
    mockEnv: (mockProxyUrl) => {
      // Codex default: do not override base URL unless explicitly forced.
      const env: Record<string, string> = {};
      if (process.env['CLAWSIG_FORCE_BASE_URL_OVERRIDE'] === '1') {
        env['OPENAI_BASE_URL'] = mockProxyUrl;
        env['OPENAI_API_BASE'] = mockProxyUrl;
      }
      return env;
    },
    expectedModelEnv: 'CLAWSIG_E2E_EXPECTED_MODEL_CODEX',
  },
  opencode: {
    id: 'opencode',
    cli: 'opencode',
    commandArgs: (prompt) => ['run', '--format', 'json', '--model', 'openai/gpt-4-conformance-mock', prompt],
    mockEnv: (mockProxyUrl) => ({
      OPENAI_BASE_URL: mockProxyUrl,
      OPENAI_API_BASE: mockProxyUrl,
    }),
    expectedModelEnv: 'CLAWSIG_E2E_EXPECTED_MODEL_OPENCODE',
  },
  gemini: {
    id: 'gemini',
    cli: 'gemini',
    commandArgs: (prompt) => ['-p', prompt],
    mockEnv: (mockProxyUrl) => ({
      GOOGLE_GENERATIVE_AI_BASE_URL: mockProxyUrl,
      GEMINI_BASE_URL: mockProxyUrl,
      OPENAI_BASE_URL: mockProxyUrl,
    }),
    expectedModelEnv: 'CLAWSIG_E2E_EXPECTED_MODEL_GEMINI',
  },
};

function nowIso(): string {
  return new Date().toISOString();
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function toNumber(value: unknown): number {
  if (typeof value === 'number') return value;
  if (typeof value === 'string') {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : 0;
  }
  return 0;
}

function truncateTail(value: string, maxChars = 2000): string {
  if (!value) return '';
  if (value.length <= maxChars) return value;
  return value.slice(-maxChars);
}

async function findBinary(name: string): Promise<string | null> {
  const locator = process.platform === 'win32' ? 'where' : 'which';
  return new Promise((resolvePath) => {
    const child = spawn(locator, [name], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    child.stdout.on('data', (d: Buffer) => { stdout += d.toString('utf-8'); });
    child.on('error', () => resolvePath(null));
    child.on('close', (code) => {
      if (code !== 0) {
        resolvePath(null);
        return;
      }
      const first = stdout.split(/\r?\n/).find(Boolean)?.trim();
      resolvePath(first || null);
    });
  });
}

async function spawnWithTimeout(
  command: string,
  args: string[],
  env: NodeJS.ProcessEnv,
  cwd: string,
  timeoutMs: number,
): Promise<{ code: number | null; timedOut: boolean; stdout: string; stderr: string }> {
  return new Promise((resolveRun) => {
    const child = spawn(command, args, {
      cwd,
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';
    let timedOut = false;

    child.stdout.on('data', (d: Buffer) => { stdout += d.toString('utf-8'); });
    child.stderr.on('data', (d: Buffer) => { stderr += d.toString('utf-8'); });

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGTERM');
      setTimeout(() => child.kill('SIGKILL'), 5000);
    }, timeoutMs);

    child.on('error', (err) => {
      clearTimeout(timer);
      resolveRun({ code: null, timedOut: false, stdout, stderr: `${stderr}\nspawn error: ${err.message}`.trim() });
    });

    child.on('close', (code) => {
      clearTimeout(timer);
      resolveRun({ code, timedOut, stdout, stderr });
    });
  });
}

function extractGatewayReceipts(receipts: unknown[]): GatewayReceiptEnvelope[] {
  const out: GatewayReceiptEnvelope[] = [];
  for (const receipt of receipts) {
    if (!isRecord(receipt)) continue;
    if (receipt['envelope_type'] !== 'gateway_receipt') continue;
    const payload = receipt['payload'];
    if (!isRecord(payload)) continue;
    out.push(receipt as GatewayReceiptEnvelope);
  }
  return out;
}

function extractTlsDecryptReceipts(receipts: unknown[]): Array<Record<string, unknown>> {
  const out: Array<Record<string, unknown>> = [];
  for (const receipt of receipts) {
    if (!isRecord(receipt)) continue;
    const t = receipt['receipt_type'];
    if (typeof t !== 'string') continue;
    if (!t.includes('tls_decrypted')) continue;
    out.push(receipt);
  }
  return out;
}

function resolveExpectedModel(spec: AgentSpec): string | undefined {
  const envName = spec.expectedModelEnv;
  if (envName) {
    const value = process.env[envName];
    if (value && value.trim().length > 0) return value.trim();
  }
  if (spec.expectedModelDefault && spec.expectedModelDefault.trim().length > 0) {
    return spec.expectedModelDefault.trim();
  }
  return undefined;
}

async function runHarnessCase(params: {
  rootDir: string;
  timeoutMs: number;
  prompt: string;
  mode: HarnessMode;
  layer: HarnessLayer;
  agent: AgentSpec;
  cliPath: string;
  clawsigCliPath: string;
}): Promise<HarnessCaseResult> {
  const { rootDir, timeoutMs, prompt, mode, layer, agent, cliPath, clawsigCliPath } = params;

  const id = `${agent.id}:${mode}:${layer}`;
  const started = Date.now();
  const errors: string[] = [];

  const testDir = join(rootDir, '.clawsig', 'e2e-workdir', `${agent.id}-${mode}-${layer}`);
  const bundlePath = join(testDir, '.clawsig', 'proof_bundle.json');

  let mockProxy: MockProxyHandle | undefined;

  try {
    await rm(testDir, { recursive: true, force: true });
    await mkdir(testDir, { recursive: true });

    const env: NodeJS.ProcessEnv = { ...process.env };

    if (mode === 'mock') {
      mockProxy = await startMockProxy(0);
      Object.assign(env, agent.mockEnv(mockProxy.baseUrl));

      if (env['OPENAI_BASE_URL'] && !env['OPENAI_API_BASE']) {
        env['OPENAI_API_BASE'] = env['OPENAI_BASE_URL'];
      }

      env['CLAWSIG_USE_CLAWPROXY'] = '1';
      env['CLAWSIG_CLAWPROXY_URL'] = mockProxy.baseUrl;

      if (!env['OPENAI_API_KEY']) env['OPENAI_API_KEY'] = 'sk-clawsig-mock';
      if (!env['ANTHROPIC_API_KEY']) env['ANTHROPIC_API_KEY'] = 'sk-ant-clawsig-mock';
    } else {
      // Live mode still routes through clawproxy so gateway receipts are emitted.
      env['CLAWSIG_USE_CLAWPROXY'] = '1';
    }

    // Layer control:
    // - proxy: force-disable interpose
    // - interpose: allow normal interpose activation
    if (layer === 'proxy') {
      env['CLAWSIG_DISABLE_INTERPOSE'] = '1';
    } else {
      delete env['CLAWSIG_DISABLE_INTERPOSE'];
    }

    const wrappedCommandArgs = [
      clawsigCliPath,
      'wrap',
      '--no-publish',
      '--',
      agent.cli,
      ...agent.commandArgs(prompt),
    ];

    const run = await spawnWithTimeout(
      process.execPath,
      wrappedCommandArgs,
      env,
      testDir,
      timeoutMs,
    );

    if (run.timedOut) {
      errors.push(`Timed out after ${timeoutMs}ms`);
    }

    // Non-zero wrapped command exit is recorded in result metadata but is not,
    // by itself, a conformance failure. The strict gate is evidence-first:
    // require deterministic bundle artifacts/counters for required lanes.

    let bundle: unknown;
    try {
      await access(bundlePath);
    } catch {
      errors.push(`Missing proof bundle: ${bundlePath}`);
    }

    if (errors.length === 0) {
      try {
        bundle = JSON.parse(await readFile(bundlePath, 'utf-8'));
      } catch (err) {
        errors.push(`Failed to parse proof bundle JSON: ${(err as Error).message}`);
      }
    }

    let eventChainLength = 0;
    let gatewayReceiptCount = 0;
    let interposeEvents = 0;
    let interposeActive = false;

    const allReceipts: unknown[] = [];

    if (errors.length === 0 && isRecord(bundle)) {
      const payload = bundle['payload'];
      if (!isRecord(payload)) {
        errors.push('Proof bundle missing payload object');
      } else {
        const eventChain = payload['event_chain'];
        if (Array.isArray(eventChain)) eventChainLength = eventChain.length;

        const receipts = payload['receipts'];
        if (Array.isArray(receipts)) {
          allReceipts.push(...receipts);
        }

        const gatewayReceipts = extractGatewayReceipts(allReceipts);
        gatewayReceiptCount = gatewayReceipts.length;

        const metadata = payload['metadata'];
        const sentinels = isRecord(metadata) && isRecord(metadata['sentinels'])
          ? metadata['sentinels']
          : null;

        interposeEvents = sentinels ? toNumber(sentinels['interpose_events']) : 0;
        interposeActive = sentinels ? sentinels['interpose_active'] === true : false;

        if (eventChainLength <= 0) {
          errors.push('bundle.payload.event_chain.length must be > 0');
        }

        if (gatewayReceiptCount <= 0) {
          errors.push('bundle.payload.receipts must contain at least 1 gateway receipt');
        }

        if (layer === 'interpose') {
          if (!interposeActive) {
            errors.push('bundle.payload.metadata.sentinels.interpose_active must be true in interpose mode');
          }
          if (interposeEvents <= 0) {
            errors.push('bundle.payload.metadata.sentinels.interpose_events must be > 0 in interpose mode');
          }
        }

        if (mode === 'live') {
          const expectedModel = resolveExpectedModel(agent);
          if (expectedModel) {
            const modelMatch = gatewayReceipts.some((r) => r.payload.model === expectedModel);
            if (!modelMatch) {
              errors.push(`Expected at least one gateway receipt model=${expectedModel}`);
            }
          } else {
            const hasModel = gatewayReceipts.some((r) => typeof r.payload.model === 'string' && r.payload.model.length > 0);
            if (!hasModel) {
              errors.push('Live mode requires gateway receipt model to be present');
            }
          }

          const hasInputTokens = gatewayReceipts.some((r) => toNumber(r.payload.tokens_input) > 0);
          const hasOutputTokens = gatewayReceipts.some((r) => toNumber(r.payload.tokens_output) > 0);

          if (!hasInputTokens) {
            errors.push('Live mode requires gateway receipt tokens_input > 0');
          }
          if (!hasOutputTokens) {
            errors.push('Live mode requires gateway receipt tokens_output > 0');
          }

          const tlsDecryptReceipts = extractTlsDecryptReceipts(allReceipts);
          if (tlsDecryptReceipts.length > 0) {
            const invalidTlsType = tlsDecryptReceipts.some((r) => r['receipt_type'] !== 'tls_decrypted_gateway');
            if (invalidTlsType) {
              errors.push('TLS decrypt receipts must use receipt_type="tls_decrypted_gateway"');
            }
          }
        }
      }
    }

    const status: HarnessCaseStatus = errors.length === 0 ? 'PASS' : 'FAIL';
    return {
      id,
      agent: agent.id,
      mode,
      layer,
      status,
      reason: status === 'FAIL' ? errors[0] : undefined,
      errors,
      metrics: {
        bundle: errors.some(e => e.startsWith('Missing proof bundle')) ? 0 : 1,
        receipts: gatewayReceiptCount,
        events: eventChainLength,
        ...(layer === 'interpose' ? { interpose_events: interposeEvents } : {}),
      },
      duration_ms: Date.now() - started,
      exit_code: run.code,
      timed_out: run.timedOut,
      cli_path: cliPath,
      bundle_path: bundlePath,
      expected_model: mode === 'live' ? resolveExpectedModel(agent) : undefined,
      stdout_tail: truncateTail(run.stdout),
      stderr_tail: truncateTail(run.stderr),
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      id,
      agent: agent.id,
      mode,
      layer,
      status: 'FAIL',
      reason: message,
      errors: [message],
      metrics: { bundle: 0, receipts: 0, events: 0 },
      duration_ms: Date.now() - started,
      exit_code: null,
      timed_out: false,
      cli_path: cliPath,
      bundle_path: bundlePath,
    };
  } finally {
    if (mockProxy) {
      try {
        await mockProxy.shutdown();
      } catch {
        // best effort
      }
    }
  }
}

function makeUnavailableHarnessCase(params: {
  agent: HarnessAgent | string;
  mode: HarnessMode;
  layer: HarnessLayer;
  reason: string;
}): HarnessCaseResult {
  return {
    id: `${params.agent}:${params.mode}:${params.layer}`,
    agent: params.agent,
    mode: params.mode,
    layer: params.layer,
    status: 'SKIP',
    reason: `AGENT_UNAVAILABLE: ${params.reason}`,
    errors: [],
    metrics: {
      bundle: 0,
      receipts: 0,
      events: 0,
      ...(params.layer === 'interpose' ? { interpose_events: 0 } : {}),
    },
    duration_ms: 0,
    exit_code: null,
    timed_out: false,
  };
}

export async function runHarnessMatrix(options: HarnessMatrixOptions = {}): Promise<HarnessMatrixRun> {
  const rootDir = resolve(options.rootDir ?? process.cwd());
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const prompt = options.prompt ?? DEFAULT_PROMPT;
  const includeLive = options.includeLive ?? process.env['CLAWSIG_E2E_LIVE'] === '1';
  const hostInterposeSupported = process.platform === 'darwin';
  const requestedAgents = options.agents ?? DEFAULT_AGENTS;
  const resultsPath = resolve(rootDir, options.resultsPath ?? DEFAULT_RESULTS_PATH);

  const clawsigCliPath = resolve(rootDir, 'packages/clawverify-cli/dist/cli.js');

  const started_at = nowIso();
  const results: HarnessCaseResult[] = [];

  const modes: HarnessMode[] = includeLive ? ['mock', 'live'] : ['mock'];
  const defaultLayers: HarnessLayer[] = hostInterposeSupported ? ['proxy', 'interpose'] : ['proxy'];
  const layers: HarnessLayer[] =
    options.layers && options.layers.length > 0 ? options.layers : defaultLayers;

  const installed: Array<{ spec: AgentSpec; path: string }> = [];

  for (const agentId of requestedAgents) {
    const spec = AGENTS[agentId as HarnessAgent];
    if (!spec) {
      for (const mode of modes) {
        for (const layer of layers) {
          results.push(
            makeUnavailableHarnessCase({
              agent: String(agentId),
              mode,
              layer,
              reason: `unknown agent '${String(agentId)}'`,
            }),
          );
        }
      }
      continue;
    }

    const cliPath = await findBinary(spec.cli);
    if (!cliPath) {
      for (const mode of modes) {
        for (const layer of layers) {
          results.push(
            makeUnavailableHarnessCase({
              agent: spec.id,
              mode,
              layer,
              reason: `${spec.cli} is not installed`,
            }),
          );
        }
      }
      continue;
    }

    installed.push({ spec, path: cliPath });
  }

  for (const { spec, path } of installed) {
    for (const mode of modes) {
      for (const layer of layers) {
        const result = await runHarnessCase({
          rootDir,
          timeoutMs,
          prompt,
          mode,
          layer,
          agent: spec,
          cliPath: path,
          clawsigCliPath,
        });
        results.push(result);
      }
    }
  }

  const passed = results.filter(r => r.status === 'PASS').length;
  const failed = results.filter(r => r.status === 'FAIL').length;
  const skipped = results.filter(r => r.status === 'SKIP').length;

  const run: HarnessMatrixRun = {
    started_at,
    finished_at: nowIso(),
    root_dir: rootDir,
    results_path: resultsPath,
    live_enabled: includeLive,
    interpose_supported: layers.includes('interpose'),
    timeout_ms: timeoutMs,
    prompt,
    results,
    summary: {
      passed,
      failed,
      skipped,
      executed: passed + failed,
      detected_agents: installed.length,
      requested_agents: requestedAgents.length,
    },
  };

  await mkdir(dirname(resultsPath), { recursive: true });
  await writeFile(resultsPath, `${JSON.stringify(run, null, 2)}\n`, 'utf-8');

  return run;
}

export function formatHarnessCaseLine(result: HarnessCaseResult): string {
  const layerLabel = result.layer === 'proxy' ? 'proxy' : 'interpose';
  const modeLayer = `(${result.mode}, ${layerLabel})`;

  if (result.status === 'SKIP') {
    return `${result.agent.padEnd(8)} ${modeLayer.padEnd(24)} SKIP  (${result.reason ?? 'skipped'})`;
  }

  if (result.status === 'FAIL') {
    const reason = result.reason ?? result.errors[0] ?? 'failed';
    return `${result.agent.padEnd(8)} ${modeLayer.padEnd(24)} FAIL  ${reason}`;
  }

  const detail = [
    `bundle=${result.metrics.bundle}`,
    `receipts=${result.metrics.receipts}`,
    `events=${result.metrics.events}`,
  ];

  if (result.layer === 'interpose') {
    detail.push(`interpose=${result.metrics.interpose_events ?? 0}`);
  }

  return `${result.agent.padEnd(8)} ${modeLayer.padEnd(24)} PASS  ${detail.join(' ')}`;
}

export function formatHarnessMatrixReport(run: HarnessMatrixRun): string {
  const lines: string[] = [];
  lines.push('clawsig E2E Test Suite');
  lines.push('=======================');

  for (const result of run.results) {
    lines.push(formatHarnessCaseLine(result));
  }

  lines.push('');
  lines.push(`${run.summary.passed}/${run.summary.executed} passed, ${run.summary.failed} failed, ${run.summary.skipped} skipped`);

  return lines.join('\n');
}
