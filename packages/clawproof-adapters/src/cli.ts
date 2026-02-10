/**
 * CLI runner for clawproof-wrap.
 *
 * Orchestrates the full adapter lifecycle:
 *   1. Load/generate agent key pair
 *   2. Resolve adapter by harness ID
 *   3. Set proxy env vars
 *   4. Spawn the harness subprocess
 *   5. Parse output for tool events
 *   6. Record events + finalize proof bundle
 *   7. Write proof bundle + URM to output directory
 *
 * Usage:
 *   node cli.js <harness-id> -- <harness-command> [args...]
 *
 * Environment:
 *   CLAWPROOF_PROXY_URL   — clawproxy base URL (required)
 *   CLAWPROOF_PROXY_TOKEN — bearer token for proxy auth (optional)
 *   CLAWPROOF_KEY_FILE    — path to JWK key file (default: .clawproof-key.json)
 *   CLAWPROOF_OUTPUT_DIR  — output directory for proof artifacts (default: .clawproof/)
 */

import { spawn } from 'node:child_process';
import { readFile, writeFile, mkdir, chmod } from 'node:fs/promises';
import { join } from 'node:path';
import { createSession } from './session';
import { startShim } from './shim';
import { getAdapter, listAdapters } from './adapters/index';
import {
  generateKeyPair,
  didFromPublicKey,
  exportKeyPairJWK,
  importKeyPairJWK,
  hashJsonB64u,
} from './crypto';
import { ENV } from './types';
import type { HarnessId, Ed25519KeyPair } from './types';

// ---------------------------------------------------------------------------
// Key management
// ---------------------------------------------------------------------------

async function loadOrGenerateKeyPair(keyFile: string): Promise<Ed25519KeyPair> {
  try {
    const raw = await readFile(keyFile, 'utf-8');
    const jwk = JSON.parse(raw) as { publicKey: JsonWebKey; privateKey: JsonWebKey };
    return importKeyPairJWK(jwk);
  } catch {
    // Key file doesn't exist — generate a new key pair
    const kp = await generateKeyPair();
    const jwk = await exportKeyPairJWK(kp);
    await writeFile(keyFile, JSON.stringify(jwk, null, 2), {
      encoding: 'utf-8',
      mode: 0o600,
    });

    // Best-effort hardening in case the platform ignores the mode option
    try {
      await chmod(keyFile, 0o600);
    } catch {
      // ignore
    }
    const did = await didFromPublicKey(kp.publicKey);
    process.stderr.write(`clawproof: generated new key pair → ${did}\n`);
    process.stderr.write(`clawproof: saved to ${keyFile}\n`);
    return kp;
  }
}

// ---------------------------------------------------------------------------
// Marketplace CST auto-fetch (POH-US-021)
// ---------------------------------------------------------------------------

type BountyCstResponse = {
  cwc_auth?: {
    cst: string;
    token_scope_hash_b64u: string;
    policy_hash_b64u?: string;
    mission_id?: string;
  };
};

async function fetchJobCstFromBounties(params: {
  baseUrl: string;
  bountyId: string;
  workerToken: string;
}): Promise<string> {
  const baseUrl = params.baseUrl.replace(/\/$/, '');
  const url = `${baseUrl}/v1/bounties/${encodeURIComponent(params.bountyId)}/cst`;

  const res = await fetch(url, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${params.workerToken.trim()}`,
      'content-type': 'application/json; charset=utf-8',
    },
    body: '{}',
  });

  const text = await res.text();
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }

  if (!res.ok) {
    throw new Error(`clawbounties /cst failed: HTTP ${res.status}: ${text}`);
  }

  const parsed = json as Partial<BountyCstResponse>;
  const cst = parsed?.cwc_auth?.cst;
  if (typeof cst !== 'string' || cst.trim().length === 0) {
    throw new Error('clawbounties /cst returned an invalid response (missing cwc_auth.cst)');
  }

  return cst.trim();
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

export async function main(argv: string[]): Promise<void> {
  // Parse args: <harness-id> -- <command> [args...]
  const dashDash = argv.indexOf('--');
  if (dashDash === -1 || dashDash === 0) {
    process.stderr.write(
      `Usage: clawproof-wrap <harness-id> -- <command> [args...]\n\n` +
      `Supported harnesses: ${listAdapters().join(', ')}\n\n` +
      `Environment:\n` +
      `  ${ENV.CLAWPROXY_BASE_URL}   — clawproxy base URL (required)\n` +
      `  ${ENV.CLAWPROXY_TOKEN} — CST token for proxy auth (optional)\n` +
      `\n` +
      `  # Optional: marketplace job CST auto-fetch (POH-US-021)\n` +
      `  ${ENV.CLAWBOUNTIES_BASE_URL} — clawbounties base URL (optional)\n` +
      `  ${ENV.CLAWBOUNTIES_BOUNTY_ID} — bounty id (bty_...)\n` +
      `  ${ENV.CLAWBOUNTIES_WORKER_TOKEN} — worker auth token (Bearer ...)\n` +
      `\n` +
      `  ${ENV.AGENT_KEY_FILE}    — JWK key file (default: .clawproof-key.json)\n` +
      `  ${ENV.OUTPUT_DIR}  — output dir (default: .clawproof/)\n`,
    );
    process.exit(1);
    return;
  }

  const harnessId = argv[dashDash - 1] as HarnessId;
  const command = argv.slice(dashDash + 1);

  if (command.length === 0) {
    process.stderr.write('clawproof: no command specified after --\n');
    process.exit(1);
    return;
  }

  // Resolve adapter
  const adapter = getAdapter(harnessId);
  if (!adapter) {
    process.stderr.write(
      `clawproof: unknown harness "${harnessId}"\n` +
      `Supported: ${listAdapters().join(', ')}\n`,
    );
    process.exit(1);
    return;
  }

  // Read env vars
  const proxyUrl = process.env[ENV.CLAWPROXY_BASE_URL];
  if (!proxyUrl) {
    process.stderr.write(`clawproof: ${ENV.CLAWPROXY_BASE_URL} is required\n`);
    process.exit(1);
    return;
  }

  let proxyToken = process.env[ENV.CLAWPROXY_TOKEN];

  const bountiesBaseUrl = process.env[ENV.CLAWBOUNTIES_BASE_URL];
  const bountiesBountyId = process.env[ENV.CLAWBOUNTIES_BOUNTY_ID];
  const bountiesWorkerToken = process.env[ENV.CLAWBOUNTIES_WORKER_TOKEN];

  // POH-US-021: If no proxy token was provided, optionally fetch a job-scoped CST from clawbounties.
  if (!proxyToken && (bountiesBaseUrl || bountiesBountyId || bountiesWorkerToken)) {
    if (!bountiesBaseUrl || !bountiesBountyId || !bountiesWorkerToken) {
      process.stderr.write(
        `clawproof: marketplace CST auto-fetch requested but missing env vars. Need ${ENV.CLAWBOUNTIES_BASE_URL}, ${ENV.CLAWBOUNTIES_BOUNTY_ID}, ${ENV.CLAWBOUNTIES_WORKER_TOKEN}.\n`,
      );
      process.exit(1);
      return;
    }

    process.stderr.write(
      `clawproof: fetching job CST from clawbounties (${bountiesBaseUrl}, bounty=${bountiesBountyId})\n`,
    );

    try {
      proxyToken = await fetchJobCstFromBounties({
        baseUrl: bountiesBaseUrl,
        bountyId: bountiesBountyId,
        workerToken: bountiesWorkerToken,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      process.stderr.write(`clawproof: failed to fetch job CST: ${message}\n`);
      process.exit(1);
      return;
    }
  }

  const keyFile = process.env[ENV.AGENT_KEY_FILE] ?? '.clawproof-key.json';
  const outputDir = process.env[ENV.OUTPUT_DIR] ?? '.clawproof';

  // Load or generate key pair
  const keyPair = await loadOrGenerateKeyPair(keyFile);
  const agentDid = await didFromPublicKey(keyPair.publicKey);

  // Create session
  const session = await createSession({
    proxyBaseUrl: proxyUrl,
    proxyToken,
    keyPair,
    agentDid,
    harness: adapter.HARNESS,
    outputDir,
  });

  process.stderr.write(`clawproof: session started (run=${session.runId}, did=${agentDid})\n`);
  process.stderr.write(`clawproof: harness=${adapter.HARNESS.id} v${adapter.HARNESS.version}\n`);

  // Record run_start event
  await session.recordEvent({
    eventType: 'run_start',
    payload: {
      harness: adapter.HARNESS,
      command: command.join(' '),
      timestamp: new Date().toISOString(),
    },
  });

  // Start a local shim server for provider-compatible base URL overrides.
  // The shim forwards requests to clawproxy via session.proxyLLMCall(), which:
  //   - records llm_call events into the event chain
  //   - injects PoH binding headers
  //   - extracts and stores canonical gateway receipt envelopes
  const shim = await startShim({
    session,
    log: (msg) => process.stderr.write(`clawproof: ${msg}\n`),
  });

  let exitCode: number;
  try {
    // Compute proxy env vars (point the harness at the local shim)
    const proxyEnv = adapter.getProxyEnv(shim.baseUrl, proxyToken);

    // Spawn the harness subprocess with shim env vars injected
    const childEnv = { ...process.env, ...proxyEnv };

    exitCode = await new Promise<number>((resolve) => {
      let stdout = '';
      const child = spawn(command[0], command.slice(1), {
        env: childEnv,
        stdio: ['inherit', 'pipe', 'inherit'],
      });

      child.stdout.on('data', (data: Buffer) => {
        const chunk = data.toString();
        stdout += chunk;
        process.stdout.write(chunk);
      });

      child.on('close', async (code: number | null) => {
        // Parse tool events from output
        const toolEvents = adapter.parseToolEvents(stdout);
        for (const te of toolEvents) {
          await session.recordEvent({
            eventType: 'tool_call',
            payload: te,
          });
        }

        resolve(code ?? 1);
      });

      child.on('error', (err: Error) => {
        process.stderr.write(`clawproof: failed to spawn "${command[0]}": ${err.message}\n`);
        resolve(127);
      });
    });
  } finally {
    try {
      await shim.close();
    } catch {
      // ignore
    }
  }

  // Record run_end event
  await session.recordEvent({
    eventType: 'run_end',
    payload: {
      exitCode,
      timestamp: new Date().toISOString(),
    },
  });

  // Hash the command string as a minimal input descriptor
  const commandHash = await hashJsonB64u(command.join(' '));

  // Finalize and produce proof bundle
  const result = await session.finalize({
    inputs: [
      {
        type: 'command',
        hashB64u: commandHash,
        metadata: { command: command.join(' ') },
      },
    ],
    outputs: [
      {
        type: 'exit_code',
        hashB64u: await hashJsonB64u(exitCode),
        metadata: { exitCode },
      },
    ],
  });

  // Write artifacts to output directory
  await mkdir(outputDir, { recursive: true });

  const bundlePath = join(outputDir, `${session.runId}-bundle.json`);
  const urmPath = join(outputDir, `${session.runId}-urm.json`);
  const trustPulsePath = join(outputDir, `${session.runId}-trust-pulse.json`);

  await writeFile(bundlePath, JSON.stringify(result.envelope, null, 2), 'utf-8');
  await writeFile(urmPath, JSON.stringify(result.urm, null, 2), 'utf-8');

  // Write the trust pulse in a canonical JSON form (no whitespace) so the hash is stable.
  await writeFile(trustPulsePath, JSON.stringify(result.trustPulse), 'utf-8');

  process.stderr.write(`\nclawproof: proof bundle → ${bundlePath}\n`);
  process.stderr.write(`clawproof: URM          → ${urmPath}\n`);
  process.stderr.write(`clawproof: trust pulse  → ${trustPulsePath}\n`);
  process.stderr.write(
    `clawproof: run=${session.runId} events=${result.envelope.payload.event_chain?.length ?? 0} receipts=${result.envelope.payload.receipts?.length ?? 0}\n`,
  );

  process.exit(exitCode);
}

// Direct invocation
const args = process.argv.slice(2);
if (args.length > 0) {
  main(args).catch((err) => {
    process.stderr.write(`clawproof: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
    return;
  });
}
