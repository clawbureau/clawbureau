import type {
  GatewayReceiptMetadata,
  GatewayReceiptPayload,
  X402BindingReasonCode,
} from './types';
import { isValidBase64Url } from './schema-registry';

function isObjectRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function extractMetadata(payload: unknown): GatewayReceiptMetadata | null {
  if (!isObjectRecord(payload)) return null;
  const metadata = payload.metadata;
  if (!isObjectRecord(metadata)) return null;
  return metadata as GatewayReceiptMetadata;
}

export interface X402ClaimInspection {
  claimed: boolean;
  payment_auth_hash_b64u?: string;
}

export interface X402BindingValidationResult extends X402ClaimInspection {
  valid: boolean;
  reason_code: X402BindingReasonCode;
  field?: string;
}

function hasAnyX402Field(metadata: GatewayReceiptMetadata): boolean {
  return (
    metadata.x402_payment_ref !== undefined ||
    metadata.x402_amount_minor !== undefined ||
    metadata.x402_currency !== undefined ||
    metadata.x402_network !== undefined ||
    metadata.x402_payment_auth_hash_b64u !== undefined
  );
}

export function inspectX402Claim(payload: unknown): X402ClaimInspection {
  const metadata = extractMetadata(payload);
  if (!metadata || !hasAnyX402Field(metadata)) {
    return { claimed: false };
  }

  const paymentAuthHash =
    typeof metadata.x402_payment_auth_hash_b64u === 'string' &&
    metadata.x402_payment_auth_hash_b64u.trim().length > 0
      ? metadata.x402_payment_auth_hash_b64u.trim()
      : undefined;

  return {
    claimed: true,
    payment_auth_hash_b64u: paymentAuthHash,
  };
}

export function mapX402SchemaFieldToReasonCode(
  field: string | undefined,
): X402BindingReasonCode | undefined {
  switch (field) {
    case 'payload.metadata.x402_payment_auth_hash_b64u':
      return 'X402_PAYMENT_AUTH_HASH_INVALID';
    case 'payload.metadata.x402_payment_ref':
    case 'payload.metadata.x402_amount_minor':
    case 'payload.metadata.x402_currency':
    case 'payload.metadata.x402_network':
      return 'X402_METADATA_PARTIAL';
    case 'payload.binding':
      return 'X402_BINDING_MISSING';
    case 'payload.binding.run_id':
      return 'X402_BINDING_RUN_ID_MISSING';
    case 'payload.binding.event_hash_b64u':
      return 'X402_BINDING_EVENT_HASH_INVALID';
    default:
      return undefined;
  }
}

export function validateX402ReceiptBinding(
  payload: GatewayReceiptPayload,
): X402BindingValidationResult {
  const metadata = extractMetadata(payload);

  if (!metadata || !hasAnyX402Field(metadata)) {
    return {
      claimed: false,
      valid: true,
      reason_code: 'X402_NOT_CLAIMED',
    };
  }

  const x402PaymentRef =
    typeof metadata.x402_payment_ref === 'string'
      ? metadata.x402_payment_ref.trim()
      : '';

  if (x402PaymentRef.length === 0) {
    return {
      claimed: true,
      valid: false,
      reason_code: 'X402_METADATA_PARTIAL',
      field: 'payload.metadata.x402_payment_ref',
    };
  }

  if (
    typeof metadata.x402_amount_minor !== 'number' ||
    !Number.isInteger(metadata.x402_amount_minor) ||
    metadata.x402_amount_minor < 0
  ) {
    return {
      claimed: true,
      valid: false,
      reason_code: 'X402_METADATA_PARTIAL',
      field: 'payload.metadata.x402_amount_minor',
    };
  }

  const x402Currency =
    typeof metadata.x402_currency === 'string' ? metadata.x402_currency.trim() : '';
  if (x402Currency.length === 0) {
    return {
      claimed: true,
      valid: false,
      reason_code: 'X402_METADATA_PARTIAL',
      field: 'payload.metadata.x402_currency',
    };
  }

  const x402Network =
    typeof metadata.x402_network === 'string' ? metadata.x402_network.trim() : '';
  if (x402Network.length === 0) {
    return {
      claimed: true,
      valid: false,
      reason_code: 'X402_METADATA_PARTIAL',
      field: 'payload.metadata.x402_network',
    };
  }

  const paymentAuthHash =
    typeof metadata.x402_payment_auth_hash_b64u === 'string'
      ? metadata.x402_payment_auth_hash_b64u.trim()
      : '';

  if (
    paymentAuthHash.length < 8 ||
    !isValidBase64Url(paymentAuthHash)
  ) {
    return {
      claimed: true,
      valid: false,
      reason_code: 'X402_PAYMENT_AUTH_HASH_INVALID',
      field: 'payload.metadata.x402_payment_auth_hash_b64u',
      payment_auth_hash_b64u: paymentAuthHash.length > 0 ? paymentAuthHash : undefined,
    };
  }

  const binding = payload.binding;
  if (!binding || typeof binding !== 'object') {
    return {
      claimed: true,
      valid: false,
      reason_code: 'X402_BINDING_MISSING',
      field: 'payload.binding',
      payment_auth_hash_b64u: paymentAuthHash,
    };
  }

  const runId = typeof binding.run_id === 'string' ? binding.run_id.trim() : '';
  if (runId.length === 0) {
    return {
      claimed: true,
      valid: false,
      reason_code: 'X402_BINDING_RUN_ID_MISSING',
      field: 'payload.binding.run_id',
      payment_auth_hash_b64u: paymentAuthHash,
    };
  }

  const eventHash =
    typeof binding.event_hash_b64u === 'string' ? binding.event_hash_b64u.trim() : '';
  if (eventHash.length === 0) {
    return {
      claimed: true,
      valid: false,
      reason_code: 'X402_BINDING_EVENT_HASH_MISSING',
      field: 'payload.binding.event_hash_b64u',
      payment_auth_hash_b64u: paymentAuthHash,
    };
  }

  if (eventHash.length < 8 || !isValidBase64Url(eventHash)) {
    return {
      claimed: true,
      valid: false,
      reason_code: 'X402_BINDING_EVENT_HASH_INVALID',
      field: 'payload.binding.event_hash_b64u',
      payment_auth_hash_b64u: paymentAuthHash,
    };
  }

  return {
    claimed: true,
    valid: true,
    reason_code: 'X402_BOUND',
    payment_auth_hash_b64u: paymentAuthHash,
  };
}
