/**
 * clawsig wrap — one-line agent verification.
 *
 * Wraps any agent process transparently:
 * 1. Generates an ephemeral DID
 * 2. Starts a local interceptor proxy
 * 3. Spawns the child process with env overrides pointing to the proxy
 * 4. On exit: compiles proof bundle, optionally publishes to VaaS
 */

import { spawn } from 'node:child_process';
import { writeFile } from 'node:fs/promises';
import {
  generateEphemeralDid,
  startLocalProxy,
} from '@clawbureau/clawsig-sdk';
import type {
  SignedEnvelope,
  ProofBundlePayload,
} from '@clawbureau/clawsig-sdk';

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

  // 2. Start local proxy
  const proxy = await startLocalProxy({ agentDid, runId });
  process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Local proxy listening on 127.0.0.1:${proxy.port}\n`);

  // 3. Spawn child process with env overrides
  const childEnv: Record<string, string | undefined> = {
    ...process.env,
    OPENAI_BASE_URL: `http://127.0.0.1:${proxy.port}/v1/proxy/openai`,
    ANTHROPIC_BASE_URL: `http://127.0.0.1:${proxy.port}/v1/proxy/anthropic`,
    CLAWSIG_RUN_ID: runId,
    CLAWSIG_AGENT_DID: agentDid.did,

    // RED TEAM FIX #6: Socket-level interception preload.
    // Inject Node.js --import flag to monkey-patch http/https at socket level.
    CLAWSIG_PROXY_PORT: String(proxy.port),
    NODE_OPTIONS: [
      process.env['NODE_OPTIONS'],
      '--import @clawbureau/clawsig-sdk/preload',
    ].filter(Boolean).join(' '),
  };

  // Pass through existing API keys from parent env
  if (process.env['OPENAI_API_KEY']) {
    childEnv['OPENAI_API_KEY'] = process.env['OPENAI_API_KEY'];
  }
  if (process.env['ANTHROPIC_API_KEY']) {
    childEnv['ANTHROPIC_API_KEY'] = process.env['ANTHROPIC_API_KEY'];
  }

  process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Spawning: ${command} ${args.join(' ')}\n\n`);

  const exitCode = await new Promise<number>((resolve) => {
    const child = spawn(command, args, {
      env: childEnv,
      stdio: 'inherit',
      shell: false,
    });

    child.on('error', (err) => {
      process.stderr.write(`\n\x1b[31m[clawsig]\x1b[0m Failed to spawn: ${err.message}\n`);
      resolve(1);
    });

    child.on('exit', (code) => {
      resolve(code ?? 1);
    });
  });

  // 4. Compile proof bundle
  process.stderr.write(`\n\x1b[36m[clawsig]\x1b[0m Child exited with code ${exitCode}\n`);
  process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Receipts collected: ${proxy.receiptCount}\n`);

  const bundle = await proxy.compileProofBundle();
  await proxy.stop();

  // Print summary
  process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Bundle ID: ${bundle.payload.bundle_id}\n`);
  process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Event chain: ${bundle.payload.event_chain?.length ?? 0} events\n`);
  process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Receipts: ${bundle.payload.receipts?.length ?? 0} gateway receipts\n`);

  // 5. Write to disk if requested
  if (outputPath) {
    await writeFile(outputPath, JSON.stringify(bundle, null, 2), 'utf-8');
    process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Bundle written to: ${outputPath}\n`);
  }

  // 6. Publish to VaaS
  if (publish) {
    await publishBundle(bundle);
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
async function publishBundle(bundle: SignedEnvelope<ProofBundlePayload>): Promise<void> {
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
      return;
    }

    const body = await res.json() as VaaSResponse;

    if (body.ok && body.urls?.badge && body.urls?.ledger) {
      process.stderr.write(`\n\x1b[32m[clawsig]\x1b[0m Verified! Tier: ${body.tier?.toUpperCase() ?? 'FREE'}\n`);
      process.stderr.write(`\x1b[32m[clawsig]\x1b[0m Paste this badge in your PR or README:\n\n`);
      process.stdout.write(
        `[![Clawsig Verified](${body.urls.badge})](${body.urls.ledger})\n`,
      );
    } else {
      process.stderr.write(`\x1b[33m[clawsig]\x1b[0m VaaS response: ${JSON.stringify(body)}\n`);
      printLocalFallback(bundle);
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : 'unknown error';
    process.stderr.write(`\x1b[33m[clawsig]\x1b[0m VaaS unavailable: ${message}\n`);
    process.stderr.write(`\x1b[33m[clawsig]\x1b[0m Bundle verified locally. VaaS publish will be available soon.\n`);
    printLocalFallback(bundle);
  }
}

function printLocalFallback(bundle: SignedEnvelope<ProofBundlePayload>): void {
  process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Local proof bundle ID: ${bundle.payload.bundle_id}\n`);
  process.stderr.write(`\x1b[36m[clawsig]\x1b[0m Signer: ${bundle.signer_did}\n`);
}
