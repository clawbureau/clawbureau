/**
 * Clawsig Conformance Test Runner
 *
 * Orchestrates: mock proxy -> spawn agent -> find bundle -> verify -> return result
 */

import { spawn } from 'node:child_process';
import { readFile, access, mkdir } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { verifyProofBundle } from '@clawbureau/clawverify-core';
import { startMockProxy } from './mock-proxy.js';
import { PROOF_TIERS, type ConformanceConfig, type ConformanceResult, type ProofTier } from './types.js';

const DEFAULT_OUTPUT_PATH = '.clawsig/proof_bundle.json';
const DEFAULT_TIMEOUT_S = 60;
const DEFAULT_EXPECTED_TIER: ProofTier = 'self';

function tierMeetsExpected(actual: string, expected: string): boolean {
  const actualIdx = PROOF_TIERS.indexOf(actual as ProofTier);
  const expectedIdx = PROOF_TIERS.indexOf(expected as ProofTier);
  if (actualIdx === -1 || expectedIdx === -1) return false;
  return actualIdx >= expectedIdx;
}

function spawnWithTimeout(
  command: string, env: NodeJS.ProcessEnv, cwd: string, timeoutMs: number,
): Promise<{ code: number | null; stdout: string; stderr: string; timedOut: boolean }> {
  return new Promise((resolveP) => {
    const stdout: string[] = [];
    const stderr: string[] = [];
    let timedOut = false;
    const child = spawn(command, [], { shell: true, env, cwd, stdio: ['ignore', 'pipe', 'pipe'] });
    child.stdout.on('data', (d: Buffer) => stdout.push(d.toString()));
    child.stderr.on('data', (d: Buffer) => stderr.push(d.toString()));
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGTERM');
      setTimeout(() => child.kill('SIGKILL'), 5000);
    }, timeoutMs);
    child.on('close', (code) => { clearTimeout(timer); resolveP({ code, stdout: stdout.join(''), stderr: stderr.join(''), timedOut }); });
    child.on('error', (err) => { clearTimeout(timer); resolveP({ code: null, stdout: stdout.join(''), stderr: `spawn error: ${err.message}`, timedOut: false }); });
  });
}

/**
 * Run a conformance test against an agent command.
 */
export async function runConformanceTest(config: ConformanceConfig): Promise<ConformanceResult> {
  const {
    agentCommand, expectedTier = DEFAULT_EXPECTED_TIER, timeout = DEFAULT_TIMEOUT_S,
    outputPath = DEFAULT_OUTPUT_PATH, mockProxyPort = 0, cwd = process.cwd(),
  } = config;

  const errors: string[] = [];
  const result: ConformanceResult = {
    passed: false, bundle_found: false, bundle_valid: false, tier: null,
    tier_meets_expected: false, event_chain_length: 0, receipt_count: 0, errors,
  };

  let proxy;
  try { proxy = await startMockProxy(mockProxyPort); }
  catch (err) { errors.push(`Failed to start mock proxy: ${(err as Error).message}`); return result; }

  try {
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      OPENAI_BASE_URL: `${proxy.baseUrl}/v1/proxy/openai`,
      OPENAI_API_BASE: `${proxy.baseUrl}/v1/proxy/openai`,
      ANTHROPIC_BASE_URL: `${proxy.baseUrl}/v1/proxy/anthropic`,
      CLAWSIG_CONFORMANCE_TEST: '1',
      CLAWSIG_MOCK_PROXY_URL: proxy.baseUrl,
      CLAWSIG_MOCK_PROXY_PORT: String(proxy.port),
    };

    const fullOutputPath = resolve(cwd, outputPath);
    try { await mkdir(dirname(fullOutputPath), { recursive: true }); } catch { /* ok */ }

    const { code, stderr: agentStderr, timedOut } = await spawnWithTimeout(agentCommand, env, cwd, timeout * 1000);
    if (timedOut) errors.push(`Agent process timed out after ${timeout}s`);
    if (code !== null && code !== 0 && !timedOut) {
      errors.push(`Agent process exited with code ${code}`);
      if (agentStderr.trim()) errors.push(`Agent stderr: ${agentStderr.trim().slice(0, 500)}`);
    }

    try { await access(fullOutputPath); } catch { errors.push(`Proof bundle not found at: ${outputPath}`); return result; }
    result.bundle_found = true;

    let bundle: unknown;
    try { bundle = JSON.parse(await readFile(fullOutputPath, 'utf-8')); }
    catch (err) { errors.push(`Failed to read/parse proof bundle: ${(err as Error).message}`); return result; }

    const verification = await verifyProofBundle(bundle);
    if (verification.result.status === 'VALID') result.bundle_valid = true;
    else {
      errors.push(`Bundle verification failed: ${verification.result.reason}`);
      if (verification.error) errors.push(`Verification error: ${verification.error.code} - ${verification.error.message}`);
    }

    result.tier = verification.result.proof_tier ?? verification.result.trust_tier ?? null;

    const c = verification.result.component_results;
    if (c) result.receipt_count = (c.receipts_count ?? 0) + (c.tool_receipts_count ?? 0) + (c.side_effect_receipts_count ?? 0) + (c.human_approval_receipts_count ?? 0);

    if (bundle && typeof bundle === 'object' && 'payload' in bundle) {
      const payload = (bundle as Record<string, unknown>).payload as Record<string, unknown>;
      if (payload && Array.isArray(payload.event_chain)) result.event_chain_length = payload.event_chain.length;
    }

    if (result.tier) {
      result.tier_meets_expected = tierMeetsExpected(result.tier, expectedTier);
      if (!result.tier_meets_expected) errors.push(`Proof tier "${result.tier}" does not meet expected tier "${expectedTier}"`);
    }

    result.passed = result.bundle_found && result.bundle_valid && result.tier_meets_expected;
  } finally {
    try { await proxy.shutdown(); } catch { /* best-effort */ }
  }
  return result;
}
