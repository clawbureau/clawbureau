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

export function getSchemaValidationInitError(): string | null {
  // Standalone validators are generated at build/commit time.
  return null;
}

export function isSchemaValidationReady(): boolean {
  return true;
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
