#!/usr/bin/env node

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
const modelIdentity = readJson('packages/schema/poh/model_identity.v1.json');
const logInclusionProof = readJson('packages/schema/poh/log_inclusion_proof.v1.json');
const kinematicFingerprint = readJson('packages/schema/poh/kinematic_fingerprint.v1.json');
const sentinelAnomalyReport = readJson('packages/schema/poh/sentinel_anomaly_report.v1.json');

const toolReceiptV1 = readJson('packages/schema/poh/tool_receipt.v1.json');
const toolReceiptEnvelopeV1 = readJson('packages/schema/poh/tool_receipt_envelope.v1.json');
const selectiveDisclosureV1 = readJson('packages/schema/poh/selective_disclosure.v1.json');
const coSignatureV1 = readJson('packages/schema/poh/co_signature.v1.json');
const toolReceiptV2 = readJson('packages/schema/poh/tool_receipt.v2.json');
const toolReceiptEnvelopeV2 = readJson('packages/schema/poh/tool_receipt_envelope.v2.json');
const aggregateBundleV1 = readJson('packages/schema/poh/aggregate_bundle.v1.json');
const aggregateBundleEnvelopeV1 = readJson('packages/schema/poh/aggregate_bundle_envelope.v1.json');

const derivationAttestation = readJson('packages/schema/poh/derivation_attestation.v1.json');
const derivationAttestationEnvelope = readJson('packages/schema/poh/derivation_attestation_envelope.v1.json');
const auditResultAttestation = readJson('packages/schema/poh/audit_result_attestation.v1.json');
const auditResultAttestationEnvelope = readJson('packages/schema/poh/audit_result_attestation_envelope.v1.json');
const executionAttestation = readJson('packages/schema/poh/execution_attestation.v1.json');
const executionAttestationEnvelope = readJson('packages/schema/poh/execution_attestation_envelope.v1.json');

const exportBundleManifest = readJson('packages/schema/poh/export_bundle_manifest.v1.json');
const exportBundle = readJson('packages/schema/poh/export_bundle.v1.json');

const gatewayReceipt = readJson('packages/schema/poh/gateway_receipt.v1.json');
const gatewayReceiptEnvelope = readJson('packages/schema/poh/gateway_receipt_envelope.v1.json');
const webReceipt = readJson('packages/schema/poh/web_receipt.v1.json');
const webReceiptEnvelope = readJson('packages/schema/poh/web_receipt_envelope.v1.json');
const vir = readJson('packages/schema/poh/vir.v1.json');
const virV2 = readJson('packages/schema/poh/vir.v2.json');
const virEnvelope = readJson('packages/schema/poh/vir_envelope.v1.json');
const virEnvelopeV2 = readJson('packages/schema/poh/vir_envelope.v2.json');
const coverageAttestation = readJson('packages/schema/poh/coverage_attestation.v1.json');
const coverageAttestationEnvelope = readJson('packages/schema/poh/coverage_attestation_envelope.v1.json');
const binarySemanticEvidence = readJson('packages/schema/poh/binary_semantic_evidence.v1.json');
const binarySemanticEvidenceEnvelope = readJson('packages/schema/poh/binary_semantic_evidence_envelope.v1.json');
const proofBundle = readJson('packages/schema/poh/proof_bundle.v1.json');
const proofBundleEnvelope = readJson('packages/schema/poh/proof_bundle_envelope.v1.json');
const urm = readJson('packages/schema/poh/urm.v1.json');

const promptPack = readJson('packages/schema/poh/prompt_pack.v1.json');
const systemPromptReport = readJson('packages/schema/poh/system_prompt_report.v1.json');

const ajv = new Ajv2020({
  allErrors: true,
  strict: false,
  code: {
    source: true,
    esm: true,
  },
});
addFormats(ajv);

ajv.addSchema(receiptBinding);
ajv.addSchema(modelIdentity);
ajv.addSchema(logInclusionProof);
ajv.addSchema(kinematicFingerprint);
ajv.addSchema(sentinelAnomalyReport);
ajv.addSchema(toolReceiptV1);
ajv.addSchema(toolReceiptEnvelopeV1);
ajv.addSchema(selectiveDisclosureV1);
ajv.addSchema(coSignatureV1);
ajv.addSchema(toolReceiptV2);
ajv.addSchema(toolReceiptEnvelopeV2);
ajv.addSchema(aggregateBundleV1);
ajv.addSchema(aggregateBundleEnvelopeV1);

ajv.addSchema(gatewayReceipt);
ajv.addSchema(gatewayReceiptEnvelope);
ajv.addSchema(webReceipt);
ajv.addSchema(webReceiptEnvelope);
ajv.addSchema(vir);
ajv.addSchema(virV2);
ajv.addSchema(virEnvelope);
ajv.addSchema(virEnvelopeV2);
ajv.addSchema(coverageAttestation);
ajv.addSchema(coverageAttestationEnvelope);
ajv.addSchema(binarySemanticEvidence);
ajv.addSchema(binarySemanticEvidenceEnvelope);
ajv.addSchema(proofBundle);
ajv.addSchema(proofBundleEnvelope);

ajv.addSchema(derivationAttestation);
ajv.addSchema(derivationAttestationEnvelope);
ajv.addSchema(auditResultAttestation);
ajv.addSchema(auditResultAttestationEnvelope);
ajv.addSchema(executionAttestation);
ajv.addSchema(executionAttestationEnvelope);

ajv.addSchema(exportBundleManifest);
ajv.addSchema(exportBundle);
ajv.addSchema(urm);
ajv.addSchema(promptPack);
ajv.addSchema(systemPromptReport);

const code = standaloneCode(ajv, {
  validateProofBundleEnvelopeV1: proofBundleEnvelope.$id,
  validateGatewayReceiptEnvelopeV1: gatewayReceiptEnvelope.$id,
  validateWebReceiptEnvelopeV1: webReceiptEnvelope.$id,
  validateToolReceiptV1: toolReceiptV1.$id,
  validateToolReceiptEnvelopeV1: toolReceiptEnvelopeV1.$id,
  validateSelectiveDisclosureV1: selectiveDisclosureV1.$id,
  validateCoSignatureV1: coSignatureV1.$id,
  validateToolReceiptV2: toolReceiptV2.$id,
  validateToolReceiptEnvelopeV2: toolReceiptEnvelopeV2.$id,
  validateAggregateBundleV1: aggregateBundleV1.$id,
  validateAggregateBundleEnvelopeV1: aggregateBundleEnvelopeV1.$id,
  validateVirV1: vir.$id,
  validateVirV2: virV2.$id,
  validateVirEnvelopeV1: virEnvelope.$id,
  validateVirEnvelopeV2: virEnvelopeV2.$id,
  validateCoverageAttestationV1: coverageAttestation.$id,
  validateCoverageAttestationEnvelopeV1: coverageAttestationEnvelope.$id,
  validateBinarySemanticEvidenceEnvelopeV1: binarySemanticEvidenceEnvelope.$id,
  validateExecutionAttestationEnvelopeV1: executionAttestationEnvelope.$id,
  validateDerivationAttestationEnvelopeV1: derivationAttestationEnvelope.$id,
  validateAuditResultAttestationEnvelopeV1: auditResultAttestationEnvelope.$id,
  validateLogInclusionProofV1: logInclusionProof.$id,
  validateExportBundleV1: exportBundle.$id,
  validateModelIdentityV1: modelIdentity.$id,
  validateUrmV1: urm.$id,
  validatePromptPackV1: promptPack.$id,
  validateSystemPromptReportV1: systemPromptReport.$id,
});

const header = `/* eslint-disable */\n// @ts-nocheck\n\n// AUTO-GENERATED\nimport { createRequire } from 'node:module';\nconst require = createRequire(import.meta.url);\n\n// AUTO-GENERATED FILE. DO NOT EDIT.\n// Regenerate via:\n//   node packages/clawverify-core/scripts/generate-schema-validators.mjs\n\n`;

const outPath = path.resolve(repoRoot, 'packages/clawverify-core/src/schema-validators.generated.ts');
fs.writeFileSync(outPath, `${header}${code}\n`, 'utf8');
console.log(`Wrote ${path.relative(repoRoot, outPath)}`);
