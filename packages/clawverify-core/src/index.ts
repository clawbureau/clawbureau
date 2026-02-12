/**
 * @clawbureau/clawverify-core
 *
 * Pure, offline-capable verification primitives shared by:
 * - packages/clawverify-cli (offline verifier)
 * - (optional) hosted verifiers / services
 *
 * Hard constraints:
 * - fail-closed for unknown schema/version/algorithm
 * - deterministic error codes
 * - no network fetches
 */

export * from './types.js';

export { verifyProofBundle } from './verify-proof-bundle.js';
export type { ProofBundleVerifierOptions } from './verify-proof-bundle.js';

export { verifyExportBundle } from './verify-export-bundle.js';
export type { VerifyExportBundleOptions } from './verify-export-bundle.js';

export { verifyReceipt } from './verify-receipt.js';
export type { ReceiptVerifierOptions } from './verify-receipt.js';

export { verifyWebReceipt } from './verify-web-receipt.js';

export { verifyExecutionAttestation } from './verify-execution-attestation.js';
export { verifyDerivationAttestation } from './verify-derivation-attestation.js';
export { verifyAuditResultAttestation } from './verify-audit-result-attestation.js';
export { verifyLogInclusionProof } from './verify-log-inclusion-proof.js';

export {
  base64UrlDecode,
  base64UrlEncode,
  computeHash,
  extractPublicKeyFromDidKey,
  verifySignature,
} from './crypto.js';

export { jcsCanonicalize } from './jcs.js';

export {
  mapToSOC2,
  mapToISO27001,
  mapToEUAIAct,
  generateComplianceReport,
} from './compliance.js';
export type {
  ComplianceFramework,
  ControlStatus,
  EvidenceType,
  ControlResult,
  ComplianceGap,
  ComplianceReport,
  ComplianceBundleInput,
  CompliancePolicyInput,
} from './compliance.js';

export {
  evaluatePolicy,
  evaluatePolicyBatch,
  convertV1toV2,
} from './policy-evaluator.js';
export type {
  WPCv1,
  WPCv2,
  WPC,
  PolicyStatement,
  PolicyConditions,
  ConditionMap,
  PolicyContext,
  PolicyDecision,
  PolicyDecisionEffect,
  PolicyResolver,
} from './policy-evaluator.js';

// Red Team Fix #8: Hashcash PoW for VaaS DoS protection
export {
  generatePoW,
  verifyPoW,
  buildChallenge,
  getDateHourUTC,
  DEFAULT_POW_DIFFICULTY,
} from './hashcash.js';

// Red Team Fix #9: Heartbeat Badge status computation
export { computeBadgeStatus } from './badge-health.js';
export type {
  BadgeColor,
  BadgeStats,
  BadgeStatus,
} from './badge-health.js';

// Sentinel trace compiler
export { compileSemanticTrace } from './trace-compiler.js';
