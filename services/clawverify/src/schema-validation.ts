/**
 * Strict JSON Schema validation (Ajv)
 * CVF-US-024
 *
 * Notes:
 * - Schemas live in packages/schema and are draft 2020-12.
 * - We fail closed on any schema validation error (including additionalProperties:false).
 */

import Ajv2020, { type ErrorObject, type ValidateFunction } from 'ajv/dist/2020';
import addFormats from 'ajv-formats';

// PoH schemas
import receiptBindingSchema from '../../../packages/schema/poh/receipt_binding.v1.json';
import gatewayReceiptPayloadSchema from '../../../packages/schema/poh/gateway_receipt.v1.json';
import gatewayReceiptEnvelopeSchema from '../../../packages/schema/poh/gateway_receipt_envelope.v1.json';
import proofBundlePayloadSchema from '../../../packages/schema/poh/proof_bundle.v1.json';
import proofBundleEnvelopeSchema from '../../../packages/schema/poh/proof_bundle_envelope.v1.json';

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

let initError: string | null = null;
let validateProofBundleEnvelopeV1Fn: ValidateFunction | null = null;
let validateGatewayReceiptEnvelopeV1Fn: ValidateFunction | null = null;

try {
  const ajv = new Ajv2020({
    allErrors: true,
    strict: true,
    // Our schemas use `anyOf: [{required:["..."]}]` patterns which are valid JSON Schema
    // but trip Ajv's strictRequired heuristic. Disable strictRequired while keeping strict mode.
    strictRequired: false,
    allowUnionTypes: true,
  });

  addFormats(ajv);

  // Add referenced schemas first.
  ajv.addSchema(receiptBindingSchema);

  // Add PoH payload/envelope schemas.
  ajv.addSchema(gatewayReceiptPayloadSchema);
  ajv.addSchema(gatewayReceiptEnvelopeSchema);
  ajv.addSchema(proofBundlePayloadSchema);
  ajv.addSchema(proofBundleEnvelopeSchema);

  validateProofBundleEnvelopeV1Fn =
    (ajv.getSchema(
      'https://schemas.clawbureau.org/claw.poh.proof_bundle_envelope.v1.json'
    ) as ValidateFunction | undefined) ?? null;

  validateGatewayReceiptEnvelopeV1Fn =
    (ajv.getSchema(
      'https://schemas.clawbureau.org/claw.poh.gateway_receipt_envelope.v1.json'
    ) as ValidateFunction | undefined) ?? null;

  if (!validateProofBundleEnvelopeV1Fn) {
    validateProofBundleEnvelopeV1Fn = ajv.compile(proofBundleEnvelopeSchema);
  }

  if (!validateGatewayReceiptEnvelopeV1Fn) {
    validateGatewayReceiptEnvelopeV1Fn = ajv.compile(gatewayReceiptEnvelopeSchema);
  }
} catch (err) {
  initError = err instanceof Error ? err.message : 'unknown schema init error';
}

export function getSchemaValidationInitError(): string | null {
  return initError;
}

export function isSchemaValidationReady(): boolean {
  return (
    initError === null &&
    validateProofBundleEnvelopeV1Fn !== null &&
    validateGatewayReceiptEnvelopeV1Fn !== null
  );
}

function instancePathToField(instancePath: string): string {
  if (!instancePath) return '';
  const parts = instancePath.split('/').filter(Boolean);
  let out = '';
  for (const part of parts) {
    if (/^\d+$/.test(part)) {
      out += `[${part}]`;
    } else {
      out += out.length === 0 ? part : `.${part}`;
    }
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

function fieldFromAjvError(err: ErrorObject): string | undefined {
  const base = instancePathToField(err.instancePath);

  if (err.keyword === 'additionalProperties') {
    const ap = additionalPropertyFromParams(err.params);
    if (ap) return base ? `${base}.${ap}` : ap;
  }

  return base.length > 0 ? base : undefined;
}

function messageFromAjvError(err: ErrorObject): string {
  // Example: "must have required property 'foo'" / "must NOT have additional properties"
  const keyword = err.keyword ? `[${err.keyword}] ` : '';
  const msg = err.message ?? 'schema validation error';

  if (err.keyword === 'additionalProperties') {
    const ap = additionalPropertyFromParams(err.params);
    if (ap) return `${keyword}${msg}: ${ap}`;
  }

  return `${keyword}${msg}`;
}

function validateWith(
  fn: ValidateFunction | null,
  value: unknown,
  label: string
): SchemaValidationResult {
  if (!fn) {
    return {
      valid: false,
      message: `Schema validator unavailable for ${label}`,
    };
  }

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

export function validateProofBundleEnvelopeV1(envelope: unknown): SchemaValidationResult {
  if (initError) {
    return {
      valid: false,
      message: `Schema validation not initialized: ${initError}`,
    };
  }

  return validateWith(
    validateProofBundleEnvelopeV1Fn,
    envelope,
    'proof_bundle_envelope.v1'
  );
}

export function validateGatewayReceiptEnvelopeV1(envelope: unknown): SchemaValidationResult {
  if (initError) {
    return {
      valid: false,
      message: `Schema validation not initialized: ${initError}`,
    };
  }

  return validateWith(
    validateGatewayReceiptEnvelopeV1Fn,
    envelope,
    'gateway_receipt_envelope.v1'
  );
}
