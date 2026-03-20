import { describe, it, expect } from 'vitest';
import { execFile } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import {
  computeSignedPolicyBundlePayloadHashB64u,
  computeSignedPolicyLayerHashB64u,
} from '../../clawsig-sdk/src/policy-resolution.js';
import {
  didFromPublicKey,
  generateKeyPair,
  signEd25519,
} from '../../clawsig-sdk/src/crypto.js';
import {
  isNoiseExecutionReceipt,
  isNoiseNetworkReceipt,
  filterExecutionReceipts,
  filterNetworkReceipts,
} from '../../clawsig-sdk/dist/receipt-filter.js';

const execFileAsync = promisify(execFile);

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const CLI_PATH = resolve(__dirname, '../dist/cli.js');

async function ensureSignedPolicyBundleForProofedMode(
  workdir: string,
  env: Record<string, string | undefined>,
): Promise<void> {
  const proofed = env['CLAWSIG_PROOFED'] === '1' || env['CLAWSIG_PROOFED_MODE'] === '1';
  if (!proofed || env['CLAWSIG_POLICY_BUNDLE_PATH']) return;

  const clawsigDir = join(workdir, '.clawsig');
  const bundlePath = join(clawsigDir, 'policy.bundle.json');

  try {
    await readFile(bundlePath, 'utf-8');
    return;
  } catch {
    // create below
  }

  await mkdir(clawsigDir, { recursive: true });

  const keyPair = await generateKeyPair();
  const issuerDid = await didFromPublicKey(keyPair.publicKey);
  const orgId = env['CLAWSIG_POLICY_ORG_ID']?.trim() || env['CLAWSIG_ORG_ID']?.trim() || 'local';

  const payload = {
    policy_bundle_version: '1' as const,
    bundle_id: `bundle_test_${Date.now()}`,
    issuer_did: issuerDid,
    issued_at: '2026-03-20T00:00:00.000Z',
    hash_algorithm: 'SHA-256' as const,
    layers: [
      {
        layer_id: 'org',
        scope: { scope_type: 'org' as const, org_id: orgId },
        apply_mode: 'merge' as const,
        policy: {
          statements: [
            {
              sid: 'org.allow',
              effect: 'Allow' as const,
              actions: ['model:invoke', 'side_effect:network_egress', 'tool:execute'],
              resources: ['*'],
            },
          ],
        },
        policy_hash_b64u: '',
      },
    ],
  };

  payload.layers[0]!.policy_hash_b64u = await computeSignedPolicyLayerHashB64u(payload.layers[0]!.policy);
  const payloadHash = await computeSignedPolicyBundlePayloadHashB64u(payload);
  const signature = await signEd25519(
    keyPair.privateKey,
    new TextEncoder().encode(payloadHash),
  );

  await writeFile(
    bundlePath,
    JSON.stringify(
      {
        envelope_version: '1',
        envelope_type: 'policy_bundle',
        payload,
        payload_hash_b64u: payloadHash,
        hash_algorithm: 'SHA-256',
        signature_b64u: signature,
        algorithm: 'Ed25519',
        signer_did: issuerDid,
        issued_at: payload.issued_at,
      },
      null,
      2,
    ),
    'utf-8',
  );
}

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

  const env = {
    ...process.env,
    CLAWSIG_DISABLE_INTERPOSE: '1',
    ...(opts.extraEnv ?? {}),
  };

  await ensureSignedPolicyBundleForProofedMode(workdir, env);

  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, args, {
      cwd: workdir,
      env,
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

interface MockClawproxyRequest {
  method: string;
  url: string;
  body: string;
  headers: Record<string, string | string[] | undefined>;
}

async function readBody(req: IncomingMessage): Promise<string> {
  return await new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
    req.on('error', reject);
  });
}

async function startMockClawproxy(): Promise<{
  url: string;
  requests: MockClawproxyRequest[];
  stop: () => Promise<void>;
}> {
  const requests: MockClawproxyRequest[] = [];
  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    if (req.method === 'POST' && req.url?.startsWith('/v1/proxy/')) {
      const body = await readBody(req);
      requests.push({
        method: req.method ?? 'POST',
        url: req.url ?? '',
        body,
        headers: req.headers,
      });
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ id: 'mock-ok', object: 'chat.completion', choices: [] }));
      return;
    }

    res.writeHead(404, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'NOT_FOUND' }));
  });

  await new Promise<void>((resolve, reject) => {
    server.listen(0, '127.0.0.1', () => resolve());
    server.on('error', reject);
  });
  const address = server.address();
  if (!address || typeof address !== 'object') {
    throw new Error('Failed to start mock clawproxy server');
  }

  return {
    url: `http://127.0.0.1:${address.port}`,
    requests,
    stop: async () =>
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}

function extractDataHandlingActions(bundle: {
  payload?: {
    metadata?: {
      data_handling?: {
        receipts?: Array<{
          payload?: {
            action?: string;
            reason_code?: string;
          };
        }>;
      };
    };
  };
}): Array<{ action: string; reason_code: string }> {
  const receipts = bundle.payload?.metadata?.data_handling?.receipts ?? [];
  return receipts
    .map((receipt) => ({
      action: receipt.payload?.action ?? '',
      reason_code: receipt.payload?.reason_code ?? '',
    }))
    .filter((entry) => entry.action.length > 0 && entry.reason_code.length > 0);
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
      expect(summary['runtime_profile_id']).toBe('prv.run.v1.proofed-minimal');
      expect(summary['runtime_profile_status']).toMatch(/^(active|fallback)$/);
      expect(summary['runtime_hygiene_verdict']).toMatch(/^(good|caution|action)$/);

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

  it('proofed mode emits signed egress policy receipt with blocked-attempt telemetry', async () => {
    const workdir = await mkdtemp(join(tmpdir(), 'clawsig-proofed-egress-receipt-'));

    try {
      const childScript =
        "(async()=>{" +
        "try{" +
        "await fetch('https://api.openai.com/v1/models');" +
        "console.error('expected PRV_EGRESS_DENIED');" +
        "process.exit(1);" +
        "}catch(err){" +
        "if(err&&err.code==='PRV_EGRESS_DENIED'){process.exit(0);}" +
        "console.error(err);" +
        "process.exit(1);" +
        "}" +
        "})();";

      const result = await runWrapRaw(workdir, {
        childArgs: [process.execPath, '-e', childScript],
        extraEnv: {
          CLAWSIG_PROOFED: '1',
          CLAWSIG_CLAWPROXY_URL: 'https://clawproxy.com',
        },
      });

      expect(result.exitCode).toBe(0);

      const raw = await readFile(result.bundlePath, 'utf-8');
      const bundle = JSON.parse(raw) as {
        payload: {
          agent_did: string;
          metadata?: {
            sentinels?: {
              egress_policy_receipt?: {
                envelope_type?: string;
                signer_did?: string;
                payload?: {
                  proofed_mode?: boolean;
                  direct_provider_access_blocked?: boolean;
                  blocked_attempt_count?: number;
                  blocked_attempts_observed?: boolean;
                  allowed_proxy_destinations?: string[];
                  allowed_child_destinations?: string[];
                };
              };
            };
          };
        };
      };

      const receipt = bundle.payload.metadata?.sentinels?.egress_policy_receipt;
      expect(receipt).toBeDefined();
      expect(receipt?.envelope_type).toBe('egress_policy_receipt');
      expect(receipt?.signer_did).toBe(bundle.payload.agent_did);
      expect(receipt?.payload?.proofed_mode).toBe(true);
      expect(receipt?.payload?.direct_provider_access_blocked).toBe(true);
      expect(typeof receipt?.payload?.blocked_attempt_count).toBe('number');
      expect(receipt?.payload?.blocked_attempt_count).toBeGreaterThanOrEqual(0);
      expect(receipt?.payload?.blocked_attempts_observed).toBe(
        (receipt?.payload?.blocked_attempt_count ?? 0) > 0
      );
      expect(receipt?.payload?.allowed_proxy_destinations).toContain('clawproxy.com');
      expect(receipt?.payload?.allowed_child_destinations).toContain('127.0.0.1');
      expect(receipt?.payload?.allowed_child_destinations).toContain('localhost');
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

  it('proofed mode enforces processor provider allowlist', async () => {
    const workdir = await mkdtemp(join(tmpdir(), 'clawsig-proofed-processor-provider-'));

    try {
      const childScript =
        "(async()=>{" +
        "const port=process.env.CLAWSIG_PROXY_PORT;" +
        "const res=await fetch(`http://127.0.0.1:${port}/v1/proxy/openai`,{" +
        "method:'POST'," +
        "headers:{'content-type':'application/json','authorization':'Bearer sk-test'}," +
        "body:JSON.stringify({model:'claude-3-5-sonnet'})" +
        "});" +
        "const body=await res.json().catch(()=>({}));" +
        "if(res.status===403&&body.reason_code==='PRV_PROCESSOR_PROVIDER_DENIED'){process.exit(0);}" +
        "console.error(JSON.stringify({status:res.status,body}));" +
        "process.exit(1);" +
        "})().catch((err)=>{console.error(err);process.exit(1);});";

      const result = await runWrapRaw(workdir, {
        childArgs: [process.execPath, '-e', childScript],
        extraEnv: {
          CLAWSIG_PROOFED: '1',
          CLAWSIG_CLAWPROXY_URL: 'http://127.0.0.1:9',
          CLAWSIG_PROCESSOR_ALLOWED_PROVIDERS: 'anthropic',
        },
      });

      expect(result.exitCode).toBe(0);
    } finally {
      await rm(workdir, { recursive: true, force: true });
    }
  });

  it('proofed mode enforces processor model allowlist', async () => {
    const workdir = await mkdtemp(join(tmpdir(), 'clawsig-proofed-processor-model-'));

    try {
      const childScript =
        "(async()=>{" +
        "const port=process.env.CLAWSIG_PROXY_PORT;" +
        "const res=await fetch(`http://127.0.0.1:${port}/v1/proxy/openai`,{" +
        "method:'POST'," +
        "headers:{'content-type':'application/json','authorization':'Bearer sk-test'}," +
        "body:JSON.stringify({model:'gpt-4o-mini'})" +
        "});" +
        "const body=await res.json().catch(()=>({}));" +
        "if(res.status===403&&body.reason_code==='PRV_PROCESSOR_MODEL_DENIED'){process.exit(0);}" +
        "console.error(JSON.stringify({status:res.status,body}));" +
        "process.exit(1);" +
        "})().catch((err)=>{console.error(err);process.exit(1);});";

      const result = await runWrapRaw(workdir, {
        childArgs: [process.execPath, '-e', childScript],
        extraEnv: {
          CLAWSIG_PROOFED: '1',
          CLAWSIG_CLAWPROXY_URL: 'http://127.0.0.1:9',
          CLAWSIG_PROCESSOR_ALLOWED_PROVIDERS: 'openai',
          CLAWSIG_PROCESSOR_ALLOWED_MODELS: 'gpt-5-mini',
        },
      });

      expect(result.exitCode).toBe(0);
    } finally {
      await rm(workdir, { recursive: true, force: true });
    }
  });

  it('proofed mode enforces processor region and retention constraints', async () => {
    const workdir = await mkdtemp(join(tmpdir(), 'clawsig-proofed-processor-region-retention-'));

    try {
      const regionScript =
        "(async()=>{" +
        "const port=process.env.CLAWSIG_PROXY_PORT;" +
        "const res=await fetch(`http://127.0.0.1:${port}/v1/proxy/openai`,{" +
        "method:'POST'," +
        "headers:{'content-type':'application/json','authorization':'Bearer sk-test','x-clawsig-region':'us','x-clawsig-retention-profile':'no_store'}," +
        "body:JSON.stringify({model:'gpt-5-mini'})" +
        "});" +
        "const body=await res.json().catch(()=>({}));" +
        "if(res.status===403&&body.reason_code==='PRV_PROCESSOR_REGION_DENIED'){process.exit(0);}" +
        "console.error(JSON.stringify({status:res.status,body}));" +
        "process.exit(1);" +
        "})().catch((err)=>{console.error(err);process.exit(1);});";

      const regionResult = await runWrapRaw(workdir, {
        childArgs: [process.execPath, '-e', regionScript],
        extraEnv: {
          CLAWSIG_PROOFED: '1',
          CLAWSIG_CLAWPROXY_URL: 'http://127.0.0.1:9',
          CLAWSIG_PROCESSOR_ALLOWED_PROVIDERS: 'openai',
          CLAWSIG_PROCESSOR_ALLOWED_MODELS: 'gpt-5-mini',
          CLAWSIG_PROCESSOR_ALLOWED_REGIONS: 'eu',
          CLAWSIG_PROCESSOR_ALLOWED_RETENTION_PROFILES: 'no_store',
        },
      });
      expect(regionResult.exitCode).toBe(0);

      const retentionScript =
        "(async()=>{" +
        "const port=process.env.CLAWSIG_PROXY_PORT;" +
        "const res=await fetch(`http://127.0.0.1:${port}/v1/proxy/openai`,{" +
        "method:'POST'," +
        "headers:{'content-type':'application/json','authorization':'Bearer sk-test','x-clawsig-region':'eu','x-clawsig-retention-profile':'provider_default'}," +
        "body:JSON.stringify({model:'gpt-5-mini'})" +
        "});" +
        "const body=await res.json().catch(()=>({}));" +
        "if(res.status===403&&body.reason_code==='PRV_PROCESSOR_RETENTION_DENIED'){process.exit(0);}" +
        "console.error(JSON.stringify({status:res.status,body}));" +
        "process.exit(1);" +
        "})().catch((err)=>{console.error(err);process.exit(1);});";

      const retentionResult = await runWrapRaw(workdir, {
        childArgs: [process.execPath, '-e', retentionScript],
        extraEnv: {
          CLAWSIG_PROOFED: '1',
          CLAWSIG_CLAWPROXY_URL: 'http://127.0.0.1:9',
          CLAWSIG_PROCESSOR_ALLOWED_PROVIDERS: 'openai',
          CLAWSIG_PROCESSOR_ALLOWED_MODELS: 'gpt-5-mini',
          CLAWSIG_PROCESSOR_ALLOWED_REGIONS: 'eu',
          CLAWSIG_PROCESSOR_ALLOWED_RETENTION_PROFILES: 'no_store',
        },
      });
      expect(retentionResult.exitCode).toBe(0);
    } finally {
      await rm(workdir, { recursive: true, force: true });
    }
  });

  it('proofed mode emits signed processor-policy evidence in the proof bundle metadata', async () => {
    const workdir = await mkdtemp(join(tmpdir(), 'clawsig-proofed-processor-evidence-'));

    try {
      const childScript =
        "(async()=>{" +
        "const port=process.env.CLAWSIG_PROXY_PORT;" +
        "const res=await fetch(`http://127.0.0.1:${port}/v1/proxy/openai`,{" +
        "method:'POST'," +
        "headers:{'content-type':'application/json','authorization':'Bearer sk-test','x-clawsig-region':'eu','x-clawsig-retention-profile':'no_store'}," +
        "body:JSON.stringify({model:'gpt-5-mini'})" +
        "});" +
        "if(res.status===502){process.exit(0);}" +
        "const body=await res.json().catch(()=>({}));" +
        "console.error(JSON.stringify({status:res.status,body}));" +
        "process.exit(1);" +
        "})().catch((err)=>{console.error(err);process.exit(1);});";

      const result = await runWrapRaw(workdir, {
        childArgs: [process.execPath, '-e', childScript],
        extraEnv: {
          CLAWSIG_PROOFED: '1',
          CLAWSIG_CLAWPROXY_URL: 'http://127.0.0.1:9',
          CLAWSIG_PROCESSOR_POLICY_PROFILE: 'prv.pol.test-profile',
          CLAWSIG_PROCESSOR_ALLOWED_PROVIDERS: 'openai',
          CLAWSIG_PROCESSOR_ALLOWED_MODELS: 'gpt-5-mini',
          CLAWSIG_PROCESSOR_ALLOWED_REGIONS: 'eu',
          CLAWSIG_PROCESSOR_ALLOWED_RETENTION_PROFILES: 'no_store',
        },
      });
      expect(result.exitCode).toBe(0);

      const raw = await readFile(result.bundlePath, 'utf-8');
      const bundle = JSON.parse(raw) as {
        payload: {
          event_chain?: Array<{
            run_id: string;
            event_hash_b64u: string;
          }>;
          metadata?: {
            processor_policy?: {
              receipt_version: string;
              receipt_type: string;
              profile_id: string;
              policy_hash_b64u: string;
              binding?: {
                run_id?: string;
                event_chain_root_hash_b64u?: string;
              };
              constraints?: {
                allowed_providers?: string[];
                allowed_models?: string[];
                allowed_regions?: string[];
                allowed_retention_profiles?: string[];
                default_region?: string;
                default_retention_profile?: string;
              };
              counters?: {
                allowed_routes?: number;
                denied_routes?: number;
              };
              used_processors?: Array<{
                provider: string;
                model: string;
                region: string;
                retention_profile: string;
                count: number;
              }>;
            };
          };
        };
      };

      const evidence = bundle.payload.metadata?.processor_policy;
      expect(evidence?.receipt_version).toBe('1');
      expect(evidence?.receipt_type).toBe('processor_policy');
      expect(evidence?.profile_id).toBe('prv.pol.test-profile');
      expect(evidence?.policy_hash_b64u).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(evidence?.binding?.run_id).toMatch(/^run_/);
      expect(evidence?.binding?.event_chain_root_hash_b64u).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(bundle.payload.event_chain?.[0]?.run_id).toBe(evidence?.binding?.run_id);
      expect(bundle.payload.event_chain?.[0]?.event_hash_b64u).toBe(
        evidence?.binding?.event_chain_root_hash_b64u,
      );
      expect(evidence?.constraints).toEqual({
        allowed_providers: ['openai'],
        allowed_models: ['gpt-5-mini'],
        allowed_regions: ['eu'],
        allowed_retention_profiles: ['no_store'],
        default_region: 'unspecified',
        default_retention_profile: 'unspecified',
      });
      expect(evidence?.counters?.allowed_routes).toBe(1);
      expect(evidence?.counters?.denied_routes).toBe(0);
      expect(evidence?.used_processors).toEqual([
        {
          provider: 'openai',
          model: 'gpt-5-mini',
          region: 'eu',
          retention_profile: 'no_store',
          count: 1,
        },
      ]);
    } finally {
      await rm(workdir, { recursive: true, force: true });
    }
  });
});

describe('proofed mode data handling controls (PRV-DLP-001/002)', () => {
  it('redacts matched secrets before upstream egress and emits signed handling evidence', async () => {
    const workdir = await mkdtemp(join(tmpdir(), 'clawsig-proofed-dlp-redact-'));
    const mock = await startMockClawproxy();
    const rawSecret = 'sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    try {
      const childScript =
        "(async()=>{" +
        "const port=process.env.CLAWSIG_PROXY_PORT;" +
        "const res=await fetch(`http://127.0.0.1:${port}/v1/proxy/openai`,{" +
        "method:'POST'," +
        "headers:{'content-type':'application/json','authorization':'Bearer sk-test'}," +
        `body:JSON.stringify({model:'gpt-4o-mini',messages:[{role:'user',content:'secret ${rawSecret}'}]})` +
        "});" +
        "if(res.status!==200){const body=await res.text();console.error(body);process.exit(1);}"+
        "process.exit(0);" +
        "})().catch((err)=>{console.error(err);process.exit(1);});";

      const result = await runWrapRaw(workdir, {
        childArgs: [process.execPath, '-e', childScript],
        extraEnv: {
          CLAWSIG_PROOFED: '1',
          CLAWSIG_CLAWPROXY_URL: mock.url,
        },
      });

      expect(result.exitCode).toBe(0);
      expect(mock.requests.length).toBeGreaterThan(0);
      const forwardedBody = mock.requests[0]!.body;
      expect(forwardedBody).not.toContain(rawSecret);
      expect(forwardedBody).toContain('[REDACTED_SECRET]');

      const bundleRaw = await readFile(result.bundlePath, 'utf-8');
      const bundle = JSON.parse(bundleRaw) as {
        payload?: {
          metadata?: {
            data_handling?: unknown;
          };
        };
      };
      const actions = extractDataHandlingActions(bundle);
      expect(actions.some((entry) => entry.action === 'redact' && entry.reason_code === 'PRV_DLP_REDACTED')).toBe(true);
    } finally {
      await mock.stop();
      await rm(workdir, { recursive: true, force: true });
    }
  });

  it('blocks customer-restricted payloads before upstream egress', async () => {
    const workdir = await mkdtemp(join(tmpdir(), 'clawsig-proofed-dlp-block-'));
    const mock = await startMockClawproxy();

    try {
      const childScript =
        "(async()=>{" +
        "const port=process.env.CLAWSIG_PROXY_PORT;" +
        "const res=await fetch(`http://127.0.0.1:${port}/v1/proxy/openai`,{" +
        "method:'POST'," +
        "headers:{'content-type':'application/json','authorization':'Bearer sk-test'}," +
        "body:JSON.stringify({model:'gpt-4o-mini',messages:[{role:'user',content:'customer_restricted export dump'}]})" +
        "});" +
        "const body=await res.json().catch(()=>({}));" +
        "if(res.status===403&&body.reason_code==='PRV_DLP_BLOCKED'){process.exit(0);}"+
        "console.error(JSON.stringify({status:res.status,body}));process.exit(1);" +
        "})().catch((err)=>{console.error(err);process.exit(1);});";

      const result = await runWrapRaw(workdir, {
        childArgs: [process.execPath, '-e', childScript],
        extraEnv: {
          CLAWSIG_PROOFED: '1',
          CLAWSIG_CLAWPROXY_URL: mock.url,
        },
      });

      expect(result.exitCode).toBe(0);
      expect(mock.requests).toHaveLength(0);

      const bundleRaw = await readFile(result.bundlePath, 'utf-8');
      const bundle = JSON.parse(bundleRaw) as {
        payload?: {
          metadata?: {
            data_handling?: unknown;
          };
        };
      };
      const actions = extractDataHandlingActions(bundle);
      expect(actions.some((entry) => entry.action === 'block' && entry.reason_code === 'PRV_DLP_BLOCKED')).toBe(true);
    } finally {
      await mock.stop();
      await rm(workdir, { recursive: true, force: true });
    }
  });

  it('requires approval for credential matches and fails closed without approval token', async () => {
    const workdir = await mkdtemp(join(tmpdir(), 'clawsig-proofed-dlp-approval-'));
    const mock = await startMockClawproxy();

    try {
      const childScript =
        "(async()=>{" +
        "const port=process.env.CLAWSIG_PROXY_PORT;" +
        "const res=await fetch(`http://127.0.0.1:${port}/v1/proxy/openai`,{" +
        "method:'POST'," +
        "headers:{'content-type':'application/json','authorization':'Bearer sk-test'}," +
        "body:JSON.stringify({model:'gpt-4o-mini',password:'dont-send-this'})" +
        "});" +
        "const body=await res.json().catch(()=>({}));" +
        "if(res.status===403&&body.reason_code==='PRV_DLP_APPROVAL_REQUIRED'){process.exit(0);}"+
        "console.error(JSON.stringify({status:res.status,body}));process.exit(1);" +
        "})().catch((err)=>{console.error(err);process.exit(1);});";

      const result = await runWrapRaw(workdir, {
        childArgs: [process.execPath, '-e', childScript],
        extraEnv: {
          CLAWSIG_PROOFED: '1',
          CLAWSIG_CLAWPROXY_URL: mock.url,
          CLAWSIG_DLP_APPROVAL_TOKEN: 'expected-approval-token',
        },
      });

      expect(result.exitCode).toBe(0);
      expect(mock.requests).toHaveLength(0);

      const bundleRaw = await readFile(result.bundlePath, 'utf-8');
      const bundle = JSON.parse(bundleRaw) as {
        payload?: {
          metadata?: {
            data_handling?: unknown;
          };
        };
      };
      const actions = extractDataHandlingActions(bundle);
      expect(actions.some((entry) => entry.action === 'require_approval' && entry.reason_code === 'PRV_DLP_APPROVAL_REQUIRED')).toBe(true);
    } finally {
      await mock.stop();
      await rm(workdir, { recursive: true, force: true });
    }
  });

  it('forwards approved credential payloads without leaking the approval header upstream', async () => {
    const workdir = await mkdtemp(join(tmpdir(), 'clawsig-proofed-dlp-approved-'));
    const mock = await startMockClawproxy();

    try {
      const childScript =
        "(async()=>{" +
        "const port=process.env.CLAWSIG_PROXY_PORT;" +
        "const res=await fetch(`http://127.0.0.1:${port}/v1/proxy/openai`,{" +
        "method:'POST'," +
        "headers:{" +
        "'content-type':'application/json'," +
        "'authorization':'Bearer sk-test'," +
        "'x-clawsig-approval-token':'expected-approval-token'" +
        "}," +
        "body:JSON.stringify({model:'gpt-4o-mini',password:'approved-send'})" +
        "});" +
        "if(res.status===200){process.exit(0);}"+
        "console.error(await res.text());process.exit(1);" +
        "})().catch((err)=>{console.error(err);process.exit(1);});";

      const result = await runWrapRaw(workdir, {
        childArgs: [process.execPath, '-e', childScript],
        extraEnv: {
          CLAWSIG_PROOFED: '1',
          CLAWSIG_CLAWPROXY_URL: mock.url,
          CLAWSIG_DLP_APPROVAL_TOKEN: 'expected-approval-token',
        },
      });

      expect(result.exitCode).toBe(0);
      expect(mock.requests).toHaveLength(1);
      expect(mock.requests[0]?.body).toContain('"password":"approved-send"');
      expect(mock.requests[0]?.headers['x-clawsig-approval-token']).toBeUndefined();

      const bundleRaw = await readFile(result.bundlePath, 'utf-8');
      const bundle = JSON.parse(bundleRaw) as {
        payload?: {
          metadata?: {
            data_handling?: unknown;
          };
        };
      };
      const actions = extractDataHandlingActions(bundle);
      expect(actions.some((entry) => entry.action === 'allow' && entry.reason_code === 'PRV_DLP_APPROVAL_GRANTED')).toBe(true);
    } finally {
      await mock.stop();
      await rm(workdir, { recursive: true, force: true });
    }
  });

  it('fails closed on encoded payloads the classifier cannot inspect before upstream egress', async () => {
    const workdir = await mkdtemp(join(tmpdir(), 'clawsig-proofed-dlp-encoding-'));
    const mock = await startMockClawproxy();

    try {
      const childScript =
        "(async()=>{" +
        "const { gzipSync } = await import('node:zlib');" +
        "const port=process.env.CLAWSIG_PROXY_PORT;" +
        "const body=gzipSync(Buffer.from(JSON.stringify({model:'gpt-4o-mini',messages:[{role:'user',content:'secret sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'}]})));" +
        "const res=await fetch(`http://127.0.0.1:${port}/v1/proxy/openai`,{" +
        "method:'POST'," +
        "headers:{" +
        "'content-type':'application/json'," +
        "'content-encoding':'gzip'," +
        "'authorization':'Bearer sk-test'" +
        "}," +
        "body:body" +
        "});" +
        "const payload=await res.json().catch(()=>({}));" +
        "if(res.status===403&&payload.reason_code==='PRV_DLP_CLASSIFIER_ERROR'){process.exit(0);}"+
        "console.error(JSON.stringify({status:res.status,payload}));process.exit(1);" +
        "})().catch((err)=>{console.error(err);process.exit(1);});";

      const result = await runWrapRaw(workdir, {
        childArgs: [process.execPath, '-e', childScript],
        extraEnv: {
          CLAWSIG_PROOFED: '1',
          CLAWSIG_CLAWPROXY_URL: mock.url,
        },
      });

      expect(result.exitCode).toBe(0);
      expect(mock.requests).toHaveLength(0);

      const bundleRaw = await readFile(result.bundlePath, 'utf-8');
      const bundle = JSON.parse(bundleRaw) as {
        payload?: {
          metadata?: {
            data_handling?: unknown;
          };
        };
      };
      const actions = extractDataHandlingActions(bundle);
      expect(actions.some((entry) => entry.action === 'require_approval' && entry.reason_code === 'PRV_DLP_CLASSIFIER_ERROR')).toBe(true);
    } finally {
      await mock.stop();
      await rm(workdir, { recursive: true, force: true });
    }
  });

  it('allows clean payloads in proofed mode and records allow action', async () => {
    const workdir = await mkdtemp(join(tmpdir(), 'clawsig-proofed-dlp-allow-'));
    const mock = await startMockClawproxy();

    try {
      const childScript =
        "(async()=>{" +
        "const port=process.env.CLAWSIG_PROXY_PORT;" +
        "const res=await fetch(`http://127.0.0.1:${port}/v1/proxy/openai`,{" +
        "method:'POST'," +
        "headers:{'content-type':'application/json','authorization':'Bearer sk-test'}," +
        "body:JSON.stringify({model:'gpt-4o-mini',messages:[{role:'user',content:'hello world'}]})" +
        "});" +
        "if(res.status===200){process.exit(0);}"+
        "console.error(await res.text());process.exit(1);" +
        "})().catch((err)=>{console.error(err);process.exit(1);});";

      const result = await runWrapRaw(workdir, {
        childArgs: [process.execPath, '-e', childScript],
        extraEnv: {
          CLAWSIG_PROOFED: '1',
          CLAWSIG_CLAWPROXY_URL: mock.url,
        },
      });

      expect(result.exitCode).toBe(0);
      expect(mock.requests.length).toBeGreaterThan(0);

      const bundleRaw = await readFile(result.bundlePath, 'utf-8');
      const bundle = JSON.parse(bundleRaw) as {
        payload?: {
          metadata?: {
            data_handling?: unknown;
          };
        };
      };
      const actions = extractDataHandlingActions(bundle);
      expect(actions.some((entry) => entry.action === 'allow' && entry.reason_code === 'PRV_DLP_ALLOW')).toBe(true);
    } finally {
      await mock.stop();
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
