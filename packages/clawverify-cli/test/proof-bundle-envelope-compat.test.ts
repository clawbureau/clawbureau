import { describe, expect, it } from 'vitest';

import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';

import { resolveVerifierConfig } from '../src/config.js';
import { verifyProofBundleFromFile } from '../src/verify.js';
import { wrap } from '../src/wrap.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..', '..', '..');

const CONFIG_PATH = path.join(
  ROOT,
  'packages/schema/fixtures/protocol-conformance/clawverify.config.conformance.v1.json'
);
const PROOF_PASS_PATH = path.join(
  ROOT,
  'packages/schema/fixtures/protocol-conformance/proof_bundle_pass.v1.json'
);
const PROOF_FAIL_SIG_PATH = path.join(
  ROOT,
  'packages/schema/fixtures/protocol-conformance/proof_bundle_fail_invalid_signature.v1.json'
);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

async function readJson(pathname: string): Promise<unknown> {
  const raw = await readFile(pathname, 'utf8');
  return JSON.parse(raw) as unknown;
}

describe('proof bundle input compatibility', () => {
  it('accepts legacy flat proof bundle payload format', async () => {
    const config = await resolveVerifierConfig({ configPath: CONFIG_PATH });
    const fixture = await readJson(PROOF_PASS_PATH);
    if (!isRecord(fixture) || !isRecord(fixture.payload)) {
      throw new Error('proof_bundle_pass fixture must be an envelope with payload');
    }

    const workdir = await mkdtemp(path.join(tmpdir(), 'clawverify-flat-proof-bundle-'));
    const flatPath = path.join(workdir, 'proof_bundle_flat.json');

    try {
      await writeFile(flatPath, JSON.stringify(fixture.payload, null, 2), 'utf8');

      const result = await verifyProofBundleFromFile({
        inputPath: flatPath,
        configPath: CONFIG_PATH,
        config,
      });

      expect(result.status).toBe('PASS');
      expect(result.reason_code).toBe('OK');
    } finally {
      await rm(workdir, { recursive: true, force: true });
    }
  });

  it('returns clear reason code for invalid envelope signature', async () => {
    const config = await resolveVerifierConfig({ configPath: CONFIG_PATH });

    const result = await verifyProofBundleFromFile({
      inputPath: PROOF_FAIL_SIG_PATH,
      configPath: CONFIG_PATH,
      config,
    });

    expect(result.status).toBe('FAIL');
    expect(result.reason_code).toBe('SIGNATURE_INVALID');
  });

  it('verifies clawsig wrap output end-to-end', async () => {
    const config = await resolveVerifierConfig({ configPath: CONFIG_PATH });
    const workdir = await mkdtemp(path.join(tmpdir(), 'clawsig-wrap-verify-'));
    const outputPath = path.join(workdir, 'bundle.json');
    const defaultBundleDir = path.join(process.cwd(), '.clawsig');

    const previousInterposeFlag = process.env.CLAWSIG_DISABLE_INTERPOSE;

    try {
      process.env.CLAWSIG_DISABLE_INTERPOSE = '1';

      const exitCode = await wrap(
        process.execPath,
        ['-e', "console.log('hello')"],
        { publish: false, outputPath }
      );
      expect(exitCode).toBe(0);

      const wrappedBundle = await readJson(outputPath);
      const receiptSignerDids =
        isRecord(wrappedBundle) &&
        isRecord(wrappedBundle.payload) &&
        Array.isArray(wrappedBundle.payload.receipts)
          ? wrappedBundle.payload.receipts
              .map((r) => (isRecord(r) ? r.signer_did : undefined))
              .filter((v): v is string => typeof v === 'string' && v.length > 0)
          : [];

      const result = await verifyProofBundleFromFile({
        inputPath: outputPath,
        configPath: CONFIG_PATH,
        config: {
          ...config,
          gatewayReceiptSignerDids: receiptSignerDids,
        },
      });

      expect(result.status).toBe('PASS');
      expect(result.reason_code).toBe('OK');
    } finally {
      if (previousInterposeFlag === undefined) {
        delete process.env.CLAWSIG_DISABLE_INTERPOSE;
      } else {
        process.env.CLAWSIG_DISABLE_INTERPOSE = previousInterposeFlag;
      }
      await rm(defaultBundleDir, { recursive: true, force: true });
      await rm(workdir, { recursive: true, force: true });
    }
  }, 120_000);
});
