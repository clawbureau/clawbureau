import { describe, expect, it } from 'vitest';

import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import { resolveVerifierConfig } from '../src/config.js';
import { verifyExportBundleFromFile, verifyProofBundleFromFile } from '../src/verify.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..', '..', '..');

const CONFIG_PATH = path.join(
  ROOT,
  'packages/schema/fixtures/protocol-conformance/clawverify.config.conformance.v1.json'
);

describe('clawverify-cli: protocol conformance smoke (offline)', () => {
  it('verifies PASS/FAIL vectors deterministically', async () => {
    const config = await resolveVerifierConfig({ configPath: CONFIG_PATH });

    const proofPass = await verifyProofBundleFromFile({
      inputPath: path.join(
        ROOT,
        'packages/schema/fixtures/protocol-conformance/proof_bundle_pass.v1.json'
      ),
      configPath: CONFIG_PATH,
      config,
    });

    expect(proofPass.status).toBe('PASS');
    expect(proofPass.reason_code).toBe('OK');

    const proofFail = await verifyProofBundleFromFile({
      inputPath: path.join(
        ROOT,
        'packages/schema/fixtures/protocol-conformance/proof_bundle_fail_receipt_binding_mismatch.v1.json'
      ),
      configPath: CONFIG_PATH,
      config,
    });

    expect(proofFail.status).toBe('FAIL');
    expect(proofFail.reason_code).toBe('RECEIPT_BINDING_MISMATCH');

    const exportPass = await verifyExportBundleFromFile({
      inputPath: path.join(ROOT, 'packages/schema/fixtures/export_bundle_golden.v1.json'),
      configPath: CONFIG_PATH,
      config,
    });

    expect(exportPass.status).toBe('PASS');
    expect(exportPass.reason_code).toBe('OK');

    const exportFail = await verifyExportBundleFromFile({
      inputPath: path.join(
        ROOT,
        'packages/schema/fixtures/protocol-conformance/export_bundle_fail_manifest_hash_mismatch.v1.json'
      ),
      configPath: CONFIG_PATH,
      config,
    });

    expect(exportFail.status).toBe('FAIL');
    expect(exportFail.reason_code).toBe('HASH_MISMATCH');
  });
});
