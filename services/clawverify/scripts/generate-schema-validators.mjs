#!/usr/bin/env node

/**
 * Generate standalone Ajv validators for Cloudflare Workers.
 *
 * Why?
 * - Ajv normally compiles schemas using `new Function(...)`, which is disallowed in Workers.
 * - Ajv standalone mode generates plain JS validation functions that do not require runtime
 *   code generation.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import standaloneCode from 'ajv/dist/standalone/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '../../..');

function readJson(relPath) {
  const abs = path.resolve(repoRoot, relPath);
  return JSON.parse(fs.readFileSync(abs, 'utf8'));
}

const receiptBinding = readJson('packages/schema/poh/receipt_binding.v1.json');
const gatewayReceipt = readJson('packages/schema/poh/gateway_receipt.v1.json');
const gatewayReceiptEnvelope = readJson('packages/schema/poh/gateway_receipt_envelope.v1.json');
const proofBundle = readJson('packages/schema/poh/proof_bundle.v1.json');
const proofBundleEnvelope = readJson('packages/schema/poh/proof_bundle_envelope.v1.json');
const urm = readJson('packages/schema/poh/urm.v1.json');

const ajv = new Ajv2020({
  allErrors: true,
  // This is about schema correctness warnings, not validation strictness.
  // Some of our schemas use anyOf+required patterns that trip strictRequired.
  strict: false,
  code: {
    source: true,
    esm: true,
  },
});

addFormats(ajv);

// Add referenced schemas first.
ajv.addSchema(receiptBinding);

// Add payload + envelope schemas.
ajv.addSchema(gatewayReceipt);
ajv.addSchema(gatewayReceiptEnvelope);
ajv.addSchema(proofBundle);
ajv.addSchema(proofBundleEnvelope);

// PoH artifact schemas (URM materialization)
ajv.addSchema(urm);

const code = standaloneCode(ajv, {
  validateProofBundleEnvelopeV1: proofBundleEnvelope.$id,
  validateGatewayReceiptEnvelopeV1: gatewayReceiptEnvelope.$id,
  validateUrmV1: urm.$id,
});

const header = `/* eslint-disable */\n// @ts-nocheck\n\n// AUTO-GENERATED FILE. DO NOT EDIT.\n// Regenerate via:\n//   node services/clawverify/scripts/generate-schema-validators.mjs\n\n`;

const outPath = path.resolve(repoRoot, 'services/clawverify/src/schema-validators.generated.ts');
fs.writeFileSync(outPath, `${header}${code}\n`, 'utf8');

console.log(`Wrote ${path.relative(repoRoot, outPath)}`);
