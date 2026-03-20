import { describe, it, expect } from 'vitest';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import {
  isNoiseExecutionReceipt,
  isNoiseNetworkReceipt,
  filterExecutionReceipts,
  filterNetworkReceipts,
} from '../../clawsig-sdk/dist/receipt-filter.js';

const execFileAsync = promisify(execFile);

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const CLI_PATH = resolve(__dirname, '../dist/cli.js');

/**
 * Run clawsig wrap with the given extra CLI flags, capturing stderr.
 * Returns { stderr, exitCode, bundlePath }.
 */
async function runWrap(
  workdir: string,
  extraFlags: string[] = [],
): Promise<{
  stderr: string;
  stdout: string;
  exitCode: number;
  bundlePath: string;
  summaryPath: string;
}> {
  const args = [
    CLI_PATH,
    'wrap',
    '--no-publish',
    ...extraFlags,
    '--',
    process.execPath,
    '-e',
    "console.log('hello from child')",
  ];

  const { stdout, stderr } = await execFileAsync(process.execPath, args, {
    cwd: workdir,
    env: {
      ...process.env,
      CLAWSIG_DISABLE_INTERPOSE: '1',
    },
    timeout: 60_000,
  });

  return {
    stderr,
    stdout,
    exitCode: 0,
    bundlePath: join(workdir, '.clawsig', 'proof_bundle.json'),
    summaryPath: join(workdir, '.clawsig', 'run_summary.json'),
  };
}

async function runWrapRaw(
  workdir: string,
  opts: {
    extraFlags?: string[];
    childArgs?: string[];
    extraEnv?: Record<string, string>;
  } = {},
): Promise<{
  stderr: string;
  stdout: string;
  exitCode: number;
  bundlePath: string;
  summaryPath: string;
}> {
  const args = [
    CLI_PATH,
    'wrap',
    '--no-publish',
    ...(opts.extraFlags ?? []),
    '--',
    ...(opts.childArgs ?? [process.execPath, '-e', "console.log('hello from child')"]),
  ];

  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, args, {
      cwd: workdir,
      env: {
        ...process.env,
        CLAWSIG_DISABLE_INTERPOSE: '1',
        ...(opts.extraEnv ?? {}),
      },
      timeout: 60_000,
    });

    return {
      stderr,
      stdout,
      exitCode: 0,
      bundlePath: join(workdir, '.clawsig', 'proof_bundle.json'),
      summaryPath: join(workdir, '.clawsig', 'run_summary.json'),
    };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string; status?: number; code?: number };
    return {
      stderr: e.stderr ?? '',
      stdout: e.stdout ?? '',
      exitCode: e.status ?? e.code ?? 1,
      bundlePath: join(workdir, '.clawsig', 'proof_bundle.json'),
      summaryPath: join(workdir, '.clawsig', 'run_summary.json'),
    };
  }
}

describe('clawsig wrap quiet mode (SKL-003)', () => {
  // -----------------------------------------------------------------------
  // 1. Default output is clean summary (no sentinel diagnostics)
  // -----------------------------------------------------------------------

  it('default output shows summary box, not diagnostic lines', async () => {
    const workdir = await mkdtemp(join(tmpdir(), 'clawsig-quiet-'));

    try {
      const { stderr } = await runWrap(workdir);

      // Should contain the startup line
      expect(stderr).toMatch(/clawsig: securing execution/);

      // Should contain the summary box
      expect(stderr).toMatch(/clawsig summary/);
      expect(stderr).toMatch(/Status\s+:/);
      expect(stderr).toMatch(/Coverage\s+:/);
      expect(stderr).toMatch(/Receipts\s+:/);
      expect(stderr).toMatch(/Bundle\s+:/);

      // Should NOT contain verbose sentinel diagnostics
      expect(stderr).not.toContain('[clawsig] FS Sentinel:');
      expect(stderr).not.toContain('[clawsig] Net Sentinel:');
      expect(stderr).not.toContain('[clawsig] Ephemeral DID:');
      expect(stderr).not.toContain('[clawsig] Run ID:');
      expect(stderr).not.toContain('[clawsig] Local proxy listening');
      expect(stderr).not.toContain('[clawsig] Causal Sieve:');
      expect(stderr).not.toContain('[clawsig] Spawning:');
      expect(stderr).not.toContain('[clawsig] Bundle ID:');
    } finally {
      await rm(workdir, { recursive: true, force: true });
    }
  });

  it('default output is under 10 lines (excluding child output)', async () => {
    const workdir = await mkdtemp(join(tmpdir(), 'clawsig-quiet-'));

    try {
      const { stderr } = await runWrap(workdir);

      // Count non-empty lines, excluding any child output that leaked to stderr
      const clawsigLines = stderr
        .split('\n')
        .filter((line) => line.trim().length > 0)
        // Filter out any lines that are clearly child process output
        .filter((line) => !line.includes('hello from child'));

      expect(clawsigLines.length).toBeLessThan(10);
    } finally {
      await rm(workdir, { recursive: true, force: true });
    }
  });

  it('child process stdout is passed through unchanged', async () => {
    const workdir = await mkdtemp(join(tmpdir(), 'clawsig-quiet-'));

    try {
      const { stdout } = await runWrap(workdir);

      // Child prints 'hello from child' to stdout
      expect(stdout).toMatch(/hello from child/);
    } finally {
      await rm(workdir, { recursive: true, force: true });
    }
  });

  // -----------------------------------------------------------------------
  // 2. --verbose restores diagnostic output
  // -----------------------------------------------------------------------

  it('--verbose flag restores full diagnostic output', async () => {
    const workdir = await mkdtemp(join(tmpdir(), 'clawsig-verbose-'));

    try {
      const { stderr } = await runWrap(workdir, ['--verbose']);

      // Should contain verbose diagnostics
      expect(stderr).toMatch(/\[clawsig\].*Ephemeral DID:/);
      expect(stderr).toMatch(/\[clawsig\].*Run ID:/);
      expect(stderr).toMatch(/\[clawsig\].*FS Sentinel:/);
      expect(stderr).toMatch(/\[clawsig\].*Spawning:/);
      expect(stderr).toMatch(/\[clawsig\].*Bundle ID:/);

      // Should NOT contain the quiet startup line
      expect(stderr).not.toContain('clawsig: securing execution');
    } finally {
      await rm(workdir, { recursive: true, force: true });
    }
  });

  it('-v short flag also enables verbose mode', async () => {
    const workdir = await mkdtemp(join(tmpdir(), 'clawsig-verbose-'));

    try {
      const { stderr } = await runWrap(workdir, ['-v']);

      expect(stderr).toMatch(/\[clawsig\].*Ephemeral DID:/);
    } finally {
      await rm(workdir, { recursive: true, force: true });
    }
  });

  // -----------------------------------------------------------------------
  // 3. Bundle is valid (filtered bundle passes basic checks)
  // -----------------------------------------------------------------------

  it('bundle is written and contains expected structure', async () => {
    const workdir = await mkdtemp(join(tmpdir(), 'clawsig-bundle-'));

    try {
      await runWrap(workdir);

      const bundlePath = join(workdir, '.clawsig', 'proof_bundle.json');
      const raw = await readFile(bundlePath, 'utf-8');
      const bundle = JSON.parse(raw) as {
        envelope_type: string;
        payload: {
          bundle_version: string;
          bundle_id: string;
          agent_did: string;
          receipts?: unknown[];
          execution_receipts?: unknown[];
          network_receipts?: unknown[];
        };
        payload_hash_b64u: string;
        signature_b64u: string;
      };

      expect(bundle.envelope_type).toBe('proof_bundle');
      expect(bundle.payload.bundle_version).toBe('1');
      expect(bundle.payload.bundle_id).toMatch(/^bundle_/);
      expect(bundle.payload.agent_did).toMatch(/^did:key:/);
      expect(bundle.payload_hash_b64u).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(bundle.signature_b64u).toMatch(/^[A-Za-z0-9_-]+$/);
    } finally {
      await rm(workdir, { recursive: true, force: true });
    }
  });

  it('run_summary.json is generated with required fields and compact size', async () => {
    const workdir = await mkdtemp(join(tmpdir(), 'clawsig-summary-'));

    try {
      const { summaryPath } = await runWrap(workdir);
      const raw = await readFile(summaryPath, 'utf-8');
      const summary = JSON.parse(raw) as Record<string, unknown>;

      expect(summary['status']).toMatch(/^(PASS|FAIL)$/);
      expect(typeof summary['tier']).toBe('string');
      expect(typeof summary['cost_usd']).toBe('number');
      expect(Array.isArray(summary['tools_used'])).toBe(true);
      expect(Array.isArray(summary['files_modified'])).toBe(true);
      expect(typeof summary['policy_violations']).toBe('number');
      expect(typeof summary['network_connections']).toBe('number');
      expect(summary['bundle_path']).toBe('.clawsig/proof_bundle.json');
      expect(typeof summary['did']).toBe('string');
      expect(typeof summary['timestamp']).toBe('string');
      expect(typeof summary['duration_seconds']).toBe('number');

      // Lightweight distillation target.
      expect(Buffer.byteLength(raw, 'utf-8')).toBeLessThan(500);
    } finally {
      await rm(workdir, { recursive: true, force: true });
    }
  });
});

describe('proofed mode privacy egress controls (PRV-EGR-001/002)', () => {
  it('proofed mode rejects non-absolute clawproxy URLs before spawning', async () => {
    const workdir = await mkdtemp(join(tmpdir(), 'clawsig-proofed-config-'));

    try {
      const result = await runWrapRaw(workdir, {
        extraEnv: {
          CLAWSIG_PROOFED: '1',
          CLAWSIG_CLAWPROXY_URL: 'clawproxy.com',
        },
      });

      expect(result.exitCode).toBe(2);
      expect(result.stderr).toContain('PRV_EGRESS_CONFIG_INVALID');
    } finally {
      await rm(workdir, { recursive: true, force: true });
    }
  });

  it('proofed mode blocks non-allowlisted outbound destinations with explicit reason code', async () => {
    const workdir = await mkdtemp(join(tmpdir(), 'clawsig-proofed-egress-'));

    try {
      const childScript =
        "(async()=>{" +
        "const port=process.env.CLAWSIG_PROXY_PORT;" +
        "if(!port){throw new Error('missing CLAWSIG_PROXY_PORT');}" +
        "const res=await fetch(`http://127.0.0.1:${port}/v1/proxy/openai`,{" +
        "method:'POST'," +
        "headers:{'content-type':'application/json','authorization':'Bearer sk-test'}," +
        "body:JSON.stringify({model:'gpt-4o-mini',messages:[{role:'user',content:'ping'}]})" +
        "});" +
        "const body=await res.json().catch(()=>({}));" +
        "if(res.status===403&&body.error==='PRV_EGRESS_DENIED'&&body.reason_code==='PRV_EGRESS_DENIED'){process.exit(0);}" +
        "console.error(JSON.stringify({status:res.status,body}));" +
        "process.exit(1);" +
        "})().catch((err)=>{console.error(err);process.exit(1);});";

      const result = await runWrapRaw(workdir, {
        childArgs: [process.execPath, '-e', childScript],
        extraEnv: {
          CLAWSIG_PROOFED: '1',
          CLAWSIG_CLAWPROXY_URL: 'https://clawproxy.com',
          CLAWSIG_PROOFED_EGRESS_ALLOWLIST: 'localhost,127.0.0.1',
        },
      });

      expect(result.exitCode).toBe(0);
    } finally {
      await rm(workdir, { recursive: true, force: true });
    }
  });

  it('proofed mode blocks direct child egress outside the local proxy path', async () => {
    const workdir = await mkdtemp(join(tmpdir(), 'clawsig-proofed-direct-'));

    try {
      const childScript =
        "(async()=>{" +
        "try{" +
        "await fetch('https://api.openai.com/v1/models');" +
        "console.error('expected PRV_EGRESS_DENIED');" +
        "process.exit(1);" +
        "}catch(err){" +
        "if(err&&err.code==='PRV_EGRESS_DENIED'&&String(err.message||'').includes('api.openai.com')){process.exit(0);}" +
        "console.error(err);" +
        "process.exit(1);" +
        "}" +
        "})();";

      const result = await runWrapRaw(workdir, {
        childArgs: [process.execPath, '-e', childScript],
        extraEnv: {
          CLAWSIG_PROOFED: '1',
        },
      });

      expect(result.exitCode).toBe(0);
    } finally {
      await rm(workdir, { recursive: true, force: true });
    }
  });

  it('proofed mode forces clawproxy path (no passthrough fallback)', async () => {
    const workdir = await mkdtemp(join(tmpdir(), 'clawsig-proofed-proxy-'));

    try {
      const result = await runWrapRaw(workdir, {
        extraFlags: ['--verbose'],
        extraEnv: {
          CLAWSIG_PROOFED: '1',
        },
      });

      expect(result.exitCode).toBe(0);
      expect(result.stderr).toContain('Proofed mode: enabled');
      expect(result.stderr).toContain('Mode: clawproxy');
      expect(result.stderr).not.toContain('Mode: passthrough');
    } finally {
      await rm(workdir, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// Receipt filtering unit tests (SDK layer)
// ---------------------------------------------------------------------------

describe('receipt noise filtering (SKL-003)', () => {
  it('isNoiseExecutionReceipt returns true for null-field execution receipts', () => {
    const noisy = {
      receipt_version: '1' as const,
      receipt_id: 'ex_test',
      command_hash_b64u: '',
      command_type: 'execution',
      target_hash_b64u: undefined,
      pid: 123,
      ppid: 1,
      cwd_hash_b64u: '',
      exit_code: 0,
      hash_algorithm: 'SHA-256' as const,
      agent_did: 'did:key:test',
      timestamp: new Date().toISOString(),
    };
    expect(isNoiseExecutionReceipt(noisy)).toBe(true);
  });

  it('isNoiseExecutionReceipt returns false for receipts with command hash', () => {
    const real = {
      receipt_version: '1' as const,
      receipt_id: 'ex_test',
      command_hash_b64u: 'abc123',
      command_type: 'execution',
      pid: 123,
      ppid: 1,
      cwd_hash_b64u: 'def456',
      exit_code: 0,
      hash_algorithm: 'SHA-256' as const,
      agent_did: 'did:key:test',
      timestamp: new Date().toISOString(),
    };
    expect(isNoiseExecutionReceipt(real)).toBe(false);
  });

  it('isNoiseExecutionReceipt returns false for non-execution types', () => {
    const fileAccess = {
      receipt_version: '1' as const,
      receipt_id: 'ex_test',
      command_hash_b64u: '',
      command_type: 'file_access',
      target_hash_b64u: undefined,
      pid: 123,
      ppid: 1,
      cwd_hash_b64u: '',
      exit_code: 0,
      hash_algorithm: 'SHA-256' as const,
      agent_did: 'did:key:test',
      timestamp: new Date().toISOString(),
    };
    expect(isNoiseExecutionReceipt(fileAccess)).toBe(false);
  });

  it('isNoiseNetworkReceipt returns true for fully null network receipts', () => {
    const noisy = {
      receipt_version: '1' as const,
      receipt_id: 'net_test',
      protocol: 'tcp',
      remote_address_hash_b64u: '',
      state: 'ESTABLISHED',
      classification: 'unknown',
      pid: null,
      process_name: null,
      hash_algorithm: 'SHA-256' as const,
      agent_did: 'did:key:test',
      timestamp: new Date().toISOString(),
    };
    expect(isNoiseNetworkReceipt(noisy)).toBe(true);
  });

  it('isNoiseNetworkReceipt returns false for receipts with remote address', () => {
    const real = {
      receipt_version: '1' as const,
      receipt_id: 'net_test',
      protocol: 'tcp',
      remote_address_hash_b64u: 'abc123',
      state: 'ESTABLISHED',
      classification: 'expected',
      pid: 456,
      process_name: 'node',
      hash_algorithm: 'SHA-256' as const,
      agent_did: 'did:key:test',
      timestamp: new Date().toISOString(),
    };
    expect(isNoiseNetworkReceipt(real)).toBe(false);
  });

  it('filterExecutionReceipts: 100 noise + 5 real -> only 5 remain', () => {
    const noiseReceipts = Array.from({ length: 100 }, (_, i) => ({
      receipt_version: '1' as const,
      receipt_id: `ex_noise_${i}`,
      command_hash_b64u: '',
      command_type: 'execution',
      target_hash_b64u: undefined,
      pid: i,
      ppid: 1,
      cwd_hash_b64u: '',
      exit_code: 0,
      hash_algorithm: 'SHA-256' as const,
      agent_did: 'did:key:test',
      timestamp: new Date().toISOString(),
    }));

    const realReceipts = Array.from({ length: 5 }, (_, i) => ({
      receipt_version: '1' as const,
      receipt_id: `ex_real_${i}`,
      command_hash_b64u: `hash_${i}`,
      command_type: 'subprocess_spawn',
      target_hash_b64u: `target_${i}`,
      pid: 1000 + i,
      ppid: 1,
      cwd_hash_b64u: `cwd_${i}`,
      exit_code: 0,
      hash_algorithm: 'SHA-256' as const,
      agent_did: 'did:key:test',
      timestamp: new Date().toISOString(),
    }));

    const all = [...noiseReceipts, ...realReceipts];
    const filtered = filterExecutionReceipts(all);

    expect(filtered).toHaveLength(5);
    for (const r of filtered) {
      expect(r.receipt_id).toMatch(/^ex_real_/);
    }
  });

  it('filterNetworkReceipts: removes null-field entries', () => {
    const noiseReceipts = Array.from({ length: 50 }, (_, i) => ({
      receipt_version: '1' as const,
      receipt_id: `net_noise_${i}`,
      protocol: 'tcp',
      remote_address_hash_b64u: '',
      state: 'ESTABLISHED',
      classification: 'unknown',
      pid: null,
      process_name: null,
      hash_algorithm: 'SHA-256' as const,
      agent_did: 'did:key:test',
      timestamp: new Date().toISOString(),
    }));

    const realReceipts = Array.from({ length: 3 }, (_, i) => ({
      receipt_version: '1' as const,
      receipt_id: `net_real_${i}`,
      protocol: 'tcp',
      remote_address_hash_b64u: `addr_${i}`,
      state: 'ESTABLISHED',
      classification: 'expected',
      pid: 100 + i,
      process_name: 'node',
      hash_algorithm: 'SHA-256' as const,
      agent_did: 'did:key:test',
      timestamp: new Date().toISOString(),
    }));

    const all = [...noiseReceipts, ...realReceipts];
    const filtered = filterNetworkReceipts(all);

    expect(filtered).toHaveLength(3);
  });
});
