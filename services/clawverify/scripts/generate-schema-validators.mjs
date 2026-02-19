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

// POH-US-017: prompt commitment schemas
const promptPack = readJson('packages/schema/poh/prompt_pack.v1.json');
const systemPromptReport = readJson('packages/schema/poh/system_prompt_report.v1.json');

// WPC v2 policy schema
const workPolicyContractV2 = readJson('packages/schema/policy/work_policy_contract.v2.json');

// Arena product schemas
const arenaProofPackV3 = readJson('packages/schema/arena/proof_pack.v3.json');
const arenaManagerReviewV1 = readJson('packages/schema/arena/manager_review.v1.json');
const arenaReportV1 = readJson('packages/schema/arena/arena_report.v1.json');

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

// Add payload + envelope schemas.
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

// Attestation payload + envelope schemas
ajv.addSchema(derivationAttestation);
ajv.addSchema(derivationAttestationEnvelope);
ajv.addSchema(auditResultAttestation);
ajv.addSchema(auditResultAttestationEnvelope);
ajv.addSchema(executionAttestation);
ajv.addSchema(executionAttestationEnvelope);

// Export bundle schemas
ajv.addSchema(exportBundleManifest);
ajv.addSchema(exportBundle);

// PoH artifact schemas (URM materialization)
ajv.addSchema(urm);

// Prompt commitment schemas
ajv.addSchema(promptPack);
ajv.addSchema(systemPromptReport);

// Policy schemas
ajv.addSchema(workPolicyContractV2);

// Arena product schemas
ajv.addSchema(arenaProofPackV3);
ajv.addSchema(arenaManagerReviewV1);
ajv.addSchema(arenaReportV1);

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
  validateWorkPolicyContractV2: workPolicyContractV2.$id,
  validateArenaProofPackV3: arenaProofPackV3.$id,
  validateArenaManagerReviewV1: arenaManagerReviewV1.$id,
  validateArenaReportV1: arenaReportV1.$id,
});

const header = `/* eslint-disable */\n// @ts-nocheck\n\n// AUTO-GENERATED FILE. DO NOT EDIT.\n// Regenerate via:\n//   node services/clawverify/scripts/generate-schema-validators.mjs\n\n`;

const outPath = path.resolve(repoRoot, 'services/clawverify/src/schema-validators.generated.ts');
fs.writeFileSync(outPath, `${header}${code}\n`, 'utf8');

console.log(`Wrote ${path.relative(repoRoot, outPath)}`);
