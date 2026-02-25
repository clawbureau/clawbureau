/**
 * `clawsig work init` — Bootstrap work-loop configuration.
 *
 * Creates .clawsig/work.json with marketplace URL and worker DID.
 * Optionally registers the worker DID with the clawbounties marketplace.
 *
 * Requires a persistent identity to already exist (via `clawsig init`).
 */

import { loadIdentity } from './identity.js';
import {
  type WorkConfig,
  DEFAULT_MARKETPLACE_URL,
  loadWorkConfig,
  saveWorkConfig,
  workConfigPath,
} from './work-config.js';
import { registerWorker } from './work-api.js';
import { printJson, printJsonError } from './json-output.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface WorkInitOptions {
  /** Marketplace base URL. */
  marketplace?: string;
  /** Whether to register with the marketplace. */
  register?: boolean;
  /** JSON output mode. */
  json?: boolean;
  /** Project directory (defaults to cwd). */
  projectDir?: string;
}

export interface WorkInitResult {
  status: 'ok' | 'error';
  workerDid: string;
  configPath: string;
  config: WorkConfig;
  registered: boolean;
  /** Present only on error. */
  error?: { code: string; message: string };
}

// ---------------------------------------------------------------------------
// Command implementation
// ---------------------------------------------------------------------------

export async function runWorkInit(options: WorkInitOptions = {}): Promise<WorkInitResult> {
  const jsonMode = !!options.json;
  const marketplaceUrl = options.marketplace ?? DEFAULT_MARKETPLACE_URL;
  const projectDir = options.projectDir;

  // 1. Ensure persistent identity exists.
  const identity = await loadIdentity(projectDir);
  if (!identity) {
    const code = 'IDENTITY_MISSING';
    const message = 'No persistent identity found. Run `clawsig init` first to generate one.';
    const nextActions = ['clawsig init', 'clawsig init --global'];

    if (jsonMode) {
      process.exitCode = 2;
      printJsonError({
        code,
        message,
        details: { next_actions: nextActions },
      });
    } else {
      process.exitCode = 2;
      process.stderr.write(`Error: ${message}\n`);
      process.stderr.write('\nNext actions:\n');
      for (const action of nextActions) {
        process.stderr.write(`  ${action}\n`);
      }
    }

    // Return a result object for programmatic callers.
    return {
      status: 'error',
      workerDid: '',
      configPath: '',
      config: undefined as unknown as WorkConfig,
      registered: false,
      error: { code, message },
    };
  }

  // 2. Build work config.
  const now = new Date().toISOString();
  let config: WorkConfig = {
    configVersion: '1',
    workerDid: identity.did,
    marketplaceUrl,
    createdAt: now,
  };

  // Preserve existing registration if re-initializing without --register.
  const existing = await loadWorkConfig(projectDir);
  if (existing?.registration && !options.register) {
    config.registration = existing.registration;
  }

  // 3. Optional marketplace registration.
  let registered = false;
  if (options.register) {
    const result = await registerWorker(marketplaceUrl, { workerDid: identity.did });

    if (!result.ok) {
      if (jsonMode) {
        process.exitCode = 1;
        printJson({
          status: 'error',
          worker_did: identity.did,
          marketplace_url: marketplaceUrl,
          registered: false,
          error: { code: result.code, message: result.message },
          next_actions: ['Retry with: clawsig work init --register'],
          config_path: workConfigPath(projectDir),
        });
      } else {
        process.exitCode = 1;
        process.stderr.write(`Registration failed: ${result.message}\n`);
        process.stderr.write('Work config was still saved (offline mode).\n');
        process.stderr.write('Retry registration with: clawsig work init --register\n');
      }

      // Save config without registration (offline fallback).
      const configPath = await saveWorkConfig(config, projectDir);

      return {
        status: 'error',
        workerDid: identity.did,
        configPath,
        config,
        registered: false,
        error: { code: result.code, message: result.message },
      };
    }

    config.registration = result.registration;
    registered = true;
  }

  // 4. Write config to disk.
  const configPath = await saveWorkConfig(config, projectDir);

  // 5. Output.
  if (jsonMode) {
    printJson({
      status: 'ok',
      worker_did: identity.did,
      marketplace_url: marketplaceUrl,
      registered,
      config_path: configPath,
      created_at: now,
      ...(config.registration ? { registration: config.registration } : {}),
    });
  } else {
    process.stdout.write(`Work config initialized at ${configPath}\n`);
    process.stdout.write(`  Worker DID: ${identity.did}\n`);
    process.stdout.write(`  Marketplace: ${marketplaceUrl}\n`);
    if (registered) {
      process.stdout.write(`  Registered: yes (worker_id: ${config.registration?.workerId})\n`);
    } else {
      process.stdout.write('  Registered: no (use --register to register with marketplace)\n');
    }
  }

  return {
    status: 'ok',
    workerDid: identity.did,
    configPath,
    config,
    registered,
  };
}
