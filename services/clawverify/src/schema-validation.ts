/**
 * Strict JSON Schema validation (Ajv) — Workers-safe
 * CVF-US-024
 *
 * Cloudflare Workers disallow runtime code generation (new Function/eval).
 * Ajv normally compiles schemas using generated functions, so we use Ajv
 * "standalone" output generated ahead-of-time:
 *   services/clawverify/src/schema-validators.generated.ts
 */

import type { ErrorObject } from 'ajv';
import {
  validateGatewayReceiptEnvelopeV1 as validateGatewayReceiptEnvelopeV1Generated,
  validateProofBundleEnvelopeV1 as validateProofBundleEnvelopeV1Generated,
  validateWebReceiptEnvelopeV1 as validateWebReceiptEnvelopeV1Generated,
  validateDerivationAttestationEnvelopeV1 as validateDerivationAttestationEnvelopeV1Generated,
  validateAuditResultAttestationEnvelopeV1 as validateAuditResultAttestationEnvelopeV1Generated,
  validateLogInclusionProofV1 as validateLogInclusionProofV1Generated,
  validateExportBundleV1 as validateExportBundleV1Generated,
  validateModelIdentityV1 as validateModelIdentityV1Generated,
  validateUrmV1 as validateUrmV1Generated,
  validatePromptPackV1 as validatePromptPackV1Generated,
  validateSystemPromptReportV1 as validateSystemPromptReportV1Generated,
} from './schema-validators.generated';

export interface SchemaValidationFailure {
  valid: false;
  message: string;
  field?: string;
  /** Raw Ajv errors (for debugging). */
  errors?: ErrorObject[] | null;
}

export type SchemaValidationResult =
  | { valid: true }
  | SchemaValidationFailure;

type StandaloneValidateFunction = ((data: unknown) => boolean) & {
  errors?: ErrorObject[] | null;
};

const validateProofBundleEnvelopeV1Fn =
  validateProofBundleEnvelopeV1Generated as StandaloneValidateFunction;

const validateGatewayReceiptEnvelopeV1Fn =
  validateGatewayReceiptEnvelopeV1Generated as StandaloneValidateFunction;

const validateWebReceiptEnvelopeV1Fn =
  validateWebReceiptEnvelopeV1Generated as StandaloneValidateFunction;

const validateDerivationAttestationEnvelopeV1Fn =
  validateDerivationAttestationEnvelopeV1Generated as StandaloneValidateFunction;

const validateAuditResultAttestationEnvelopeV1Fn =
  validateAuditResultAttestationEnvelopeV1Generated as StandaloneValidateFunction;

const validateLogInclusionProofV1Fn =
  validateLogInclusionProofV1Generated as StandaloneValidateFunction;

const validateExportBundleV1Fn =
  validateExportBundleV1Generated as StandaloneValidateFunction;

const validateModelIdentityV1Fn =
  validateModelIdentityV1Generated as StandaloneValidateFunction;

const validateUrmV1Fn = validateUrmV1Generated as StandaloneValidateFunction;

const validatePromptPackV1Fn =
  validatePromptPackV1Generated as StandaloneValidateFunction;

const validateSystemPromptReportV1Fn =
  validateSystemPromptReportV1Generated as StandaloneValidateFunction;

export function getSchemaValidationInitError(): string | null {
  // Standalone validators are generated at build/commit time.
  return null;
}

export function isSchemaValidationReady(): boolean {
  return true;
}

const IDENTIFIER_RE = /^[A-Za-z_$][A-Za-z0-9_$]*$/;

function decodeJsonPointerSegment(seg: string): string {
  // RFC 6901: ~1 -> '/', ~0 -> '~'
  return seg.replace(/~1/g, '/').replace(/~0/g, '~');
}

function appendInstancePathSegment(base: string, seg: string): string {
  // Ajv uses JSON Pointer in instancePath; for arrays the segment is the index.
  if (/^\d+$/.test(seg)) {
    return `${base}[${seg}]`;
  }

  if (IDENTIFIER_RE.test(seg)) {
    return base.length === 0 ? seg : `${base}.${seg}`;
  }

  const q = JSON.stringify(seg);
  return base.length === 0 ? `[${q}]` : `${base}[${q}]`;
}

function appendPropertySegment(base: string, prop: string): string {
  // missingProperty/additionalProperty are object property names (not array indices).
  if (IDENTIFIER_RE.test(prop)) {
    return base.length === 0 ? prop : `${base}.${prop}`;
  }

  const q = JSON.stringify(prop);
  return base.length === 0 ? `[${q}]` : `${base}[${q}]`;
}

function instancePathToField(instancePath: string): string {
  if (!instancePath) return '';
  const parts = instancePath
    .split('/')
    .filter(Boolean)
    .map(decodeJsonPointerSegment);

  let out = '';
  for (const part of parts) {
    out = appendInstancePathSegment(out, part);
  }
  return out;
}

function additionalPropertyFromParams(
  params: ErrorObject['params']
): string | undefined {
  if (!params || typeof params !== 'object') return undefined;
  const p = params as Record<string, unknown>;
  const ap = p.additionalProperty;
  return typeof ap === 'string' ? ap : undefined;
}

function missingPropertyFromParams(
  params: ErrorObject['params']
): string | undefined {
  if (!params || typeof params !== 'object') return undefined;
  const p = params as Record<string, unknown>;
  const mp = p.missingProperty;
  return typeof mp === 'string' ? mp : undefined;
}

function fieldFromAjvError(err: ErrorObject): string | undefined {
  const base = instancePathToField(err.instancePath);

  if (err.keyword === 'additionalProperties') {
    const ap = additionalPropertyFromParams(err.params);
    if (ap) return appendPropertySegment(base, ap);
  }

  if (err.keyword === 'required') {
    const mp = missingPropertyFromParams(err.params);
    if (mp) return appendPropertySegment(base, mp);
  }

  return base.length > 0 ? base : undefined;
}

function messageFromAjvError(err: ErrorObject): string {
  const keyword = err.keyword ? `[${err.keyword}] ` : '';
  const msg = err.message ?? 'schema validation error';

  if (err.keyword === 'additionalProperties') {
    const ap = additionalPropertyFromParams(err.params);
    if (ap) return `${keyword}${msg}: ${ap}`;
  }

  return `${keyword}${msg}`;
}

function validateWith(
  fn: StandaloneValidateFunction,
  value: unknown,
  label: string
): SchemaValidationResult {
  const ok = fn(value);
  if (ok) return { valid: true };

  const errors = fn.errors ?? null;
  const first = errors && errors.length > 0 ? errors[0] : null;

  return {
    valid: false,
    message: first
      ? `${label}: ${messageFromAjvError(first)}`
      : `${label}: schema validation failed`,
    field: first ? fieldFromAjvError(first) : undefined,
    errors,
  };
}

export function validateProofBundleEnvelopeV1(
  envelope: unknown
): SchemaValidationResult {
  return validateWith(
    validateProofBundleEnvelopeV1Fn,
    envelope,
    'proof_bundle_envelope.v1'
  );
}

export function validateGatewayReceiptEnvelopeV1(
  envelope: unknown
): SchemaValidationResult {
  return validateWith(
    validateGatewayReceiptEnvelopeV1Fn,
    envelope,
    'gateway_receipt_envelope.v1'
  );
}

export function validateWebReceiptEnvelopeV1(
  envelope: unknown
): SchemaValidationResult {
  return validateWith(
    validateWebReceiptEnvelopeV1Fn,
    envelope,
    'web_receipt_envelope.v1'
  );
}

export function validateDerivationAttestationEnvelopeV1(
  envelope: unknown
): SchemaValidationResult {
  return validateWith(
    validateDerivationAttestationEnvelopeV1Fn,
    envelope,
    'derivation_attestation_envelope.v1'
  );
}

export function validateAuditResultAttestationEnvelopeV1(
  envelope: unknown
): SchemaValidationResult {
  return validateWith(
    validateAuditResultAttestationEnvelopeV1Fn,
    envelope,
    'audit_result_attestation_envelope.v1'
  );
}

export function validateLogInclusionProofV1(value: unknown): SchemaValidationResult {
  return validateWith(validateLogInclusionProofV1Fn, value, 'log_inclusion_proof.v1');
}

export function validateExportBundleV1(value: unknown): SchemaValidationResult {
  return validateWith(validateExportBundleV1Fn, value, 'export_bundle.v1');
}

export function validateModelIdentityV1(value: unknown): SchemaValidationResult {
  return validateWith(validateModelIdentityV1Fn, value, 'model_identity.v1');
}

export function validateUrmV1(urm: unknown): SchemaValidationResult {
  return validateWith(validateUrmV1Fn, urm, 'urm.v1');
}

export function validatePromptPackV1(value: unknown): SchemaValidationResult {
  return validateWith(validatePromptPackV1Fn, value, 'prompt_pack.v1');
}

export function validateSystemPromptReportV1(value: unknown): SchemaValidationResult {
  return validateWith(validateSystemPromptReportV1Fn, value, 'system_prompt_report.v1');
}
