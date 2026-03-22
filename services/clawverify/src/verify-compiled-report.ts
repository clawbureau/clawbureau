import {
  base64UrlDecode,
  base64UrlEncode,
  extractPublicKeyFromDidKey,
  verifySignature,
} from './crypto';
import { jcsCanonicalize } from './jcs';
import type {
  CompileCompiledEvidenceReportResponse,
  CompiledEvidenceControlResult,
  CompiledEvidenceReportEnvelope,
  CompiledEvidenceReportPayload,
  VerifyCompiledEvidenceReportResponse,
  VerificationError,
  VerificationResult,
} from './types';

const STRICT_ISO_UTC_RE =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
const BASE64_URL_RE = /^[A-Za-z0-9_-]+$/;
const COMPILED_REPORT_ID_RE = /^cer_[A-Za-z0-9._:-]+$/;
const COMPILER_VERSION_WAVE2 = 'clawcompiler-runtime-v1-wave2';
const COMPILER_VERSION_WAVE3 = 'clawcompiler-runtime-v1-wave3';
const COMPILED_EVIDENCE_NARRATIVE_DISCLAIMER =
  'NON_NORMATIVE: This narrative is explanatory only and is not authoritative compliance evidence. Authoritative determinations are in compiled_evidence_report.control_results.';
const WAIVER_APPLIED_REASON_CODE = 'WAIVER_APPLIED_SIGNED';
const WAIVER_RESIDUAL_REASON_CODES = new Set([
  'RESIDUAL_COMPENSATING_CONTROL_RELIANCE',
  'RESIDUAL_HUMAN_EXCEPTION_APPLIED',
]);

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function isNonEmptyString(v: unknown): v is string {
  return typeof v === 'string' && v.trim().length > 0;
}

function isBase64UrlString(v: unknown, minLength: number = 1): v is string {
  return typeof v === 'string' && v.length >= minLength && BASE64_URL_RE.test(v);
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const source = bytes.buffer;
  if (source instanceof ArrayBuffer) {
    return source.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
  }

  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

async function sha256CanonicalB64u(value: unknown): Promise<string> {
  const canonical = jcsCanonicalize(value);
  const bytes = new TextEncoder().encode(canonical);
  const digest = await crypto.subtle.digest('SHA-256', toArrayBuffer(bytes));
  return base64UrlEncode(new Uint8Array(digest));
}

function normalizeControlResults(
  controls: CompiledEvidenceControlResult[],
): CompiledEvidenceControlResult[] {
  return [...controls]
    .map((control) => ({
      control_id: control.control_id,
      status: control.status,
      reason_codes: [...control.reason_codes],
      evidence_hashes_b64u: [...control.evidence_hashes_b64u],
      waiver_applied: control.waiver_applied,
    }))
    .sort((a, b) => a.control_id.localeCompare(b.control_id));
}

async function computeMatrixHash(
  controlResults: CompiledEvidenceControlResult[],
): Promise<string> {
  return sha256CanonicalB64u({
    matrix_version: '1',
    control_results: normalizeControlResults(controlResults),
  });
}

type AuthoritativeCompiledReportView = Omit<
  CompiledEvidenceReportPayload,
  'narrative'
>;

function authoritativeCompiledReportView(
  payload: CompiledEvidenceReportPayload,
): AuthoritativeCompiledReportView {
  const { narrative: _ignoredNarrative, ...authoritative } = payload;
  return authoritative;
}

async function computeAuthoritativeReportHash(
  payload: CompiledEvidenceReportPayload,
): Promise<string> {
  return sha256CanonicalB64u(authoritativeCompiledReportView(payload));
}

function summarizeOverallStatus(
  controls: CompiledEvidenceControlResult[],
): CompiledEvidenceReportPayload['overall_status'] {
  if (controls.some((control) => control.status === 'FAIL_CLOSED_INVALID_EVIDENCE')) {
    return 'FAIL_CLOSED_INVALID_EVIDENCE';
  }

  if (controls.some((control) => control.status === 'FAIL')) {
    return 'FAIL';
  }

  if (controls.some((control) => control.status === 'PARTIAL')) {
    return 'PARTIAL';
  }

  return 'PASS';
}

function countWaiverResidualReasonCodes(reasonCodes: string[]): number {
  return reasonCodes.filter((reasonCode) =>
    WAIVER_RESIDUAL_REASON_CODES.has(reasonCode),
  ).length;
}

function hasWaiverReasonMarkers(reasonCodes: string[]): boolean {
  return (
    reasonCodes.includes(WAIVER_APPLIED_REASON_CODE) ||
    countWaiverResidualReasonCodes(reasonCodes) > 0
  );
}

type PayloadValidationResult =
  | { ok: true; value: CompiledEvidenceReportPayload }
  | {
      ok: false;
      error: VerificationError;
      reason: string;
    };

function validatePayload(
  rawPayload: unknown,
  opts?: { matrixHashOptional?: boolean },
): PayloadValidationResult {
  const matrixHashOptional = opts?.matrixHashOptional === true;

  if (!isRecord(rawPayload)) {
    return {
      ok: false,
      reason: 'Compiled evidence report payload failed schema validation.',
      error: {
        code: 'SCHEMA_VALIDATION_FAILED',
        message: 'payload must be a JSON object.',
        field: 'payload',
      },
    };
  }

  if (rawPayload.report_version !== '1') {
    return {
      ok: false,
      reason: 'Compiled evidence report payload failed schema validation.',
      error: {
        code: 'SCHEMA_VALIDATION_FAILED',
        message: 'payload.report_version must equal "1".',
        field: 'payload.report_version',
      },
    };
  }

  if (!isNonEmptyString(rawPayload.report_id) || !COMPILED_REPORT_ID_RE.test(rawPayload.report_id)) {
    return {
      ok: false,
      reason: 'Compiled evidence report payload failed schema validation.',
      error: {
        code: 'SCHEMA_VALIDATION_FAILED',
        message: 'payload.report_id must match /^cer_[A-Za-z0-9._:-]+$/.',
        field: 'payload.report_id',
      },
    };
  }

  if (!isNonEmptyString(rawPayload.compiled_at) || !STRICT_ISO_UTC_RE.test(rawPayload.compiled_at)) {
    return {
      ok: false,
      reason: 'Compiled evidence report payload failed schema validation.',
      error: {
        code: 'SCHEMA_VALIDATION_FAILED',
        message: 'payload.compiled_at must be a strict UTC ISO-8601 timestamp.',
        field: 'payload.compiled_at',
      },
    };
  }

  if (
    rawPayload.compiler_version !== COMPILER_VERSION_WAVE2 &&
    rawPayload.compiler_version !== COMPILER_VERSION_WAVE3
  ) {
    return {
      ok: false,
      reason: 'Compiled evidence report payload failed schema validation.',
      error: {
        code: 'SCHEMA_VALIDATION_FAILED',
        message:
          `payload.compiler_version must equal "${COMPILER_VERSION_WAVE2}" or "${COMPILER_VERSION_WAVE3}".`,
        field: 'payload.compiler_version',
      },
    };
  }

  const isWave3CompiledPayload =
    rawPayload.compiler_version === COMPILER_VERSION_WAVE3;

  if (!isRecord(rawPayload.evidence_refs)) {
    return {
      ok: false,
      reason: 'Compiled evidence report payload is missing required evidence refs.',
      error: {
        code: 'MISSING_REQUIRED_FIELD',
        message: 'payload.evidence_refs is required.',
        field: 'payload.evidence_refs',
      },
    };
  }

  const refFields = [
    'proof_bundle_hash_b64u',
    'ontology_hash_b64u',
    'mapping_rules_hash_b64u',
    'verify_result_hash_b64u',
  ] as const;

  for (const field of refFields) {
    const value = rawPayload.evidence_refs[field];
    if (!isNonEmptyString(value)) {
      return {
        ok: false,
        reason: 'Compiled evidence report payload is missing required evidence refs.',
        error: {
          code: 'MISSING_REQUIRED_FIELD',
          message: `payload.evidence_refs.${field} is required.`,
          field: `payload.evidence_refs.${field}`,
        },
      };
    }

    if (!isBase64UrlString(value, 8)) {
      return {
        ok: false,
        reason: 'Compiled evidence report payload failed schema validation.',
        error: {
          code: 'SCHEMA_VALIDATION_FAILED',
          message: `payload.evidence_refs.${field} must be base64url (min length 8).`,
          field: `payload.evidence_refs.${field}`,
        },
      };
    }
  }

  if (
    rawPayload.overall_status !== 'PASS' &&
    rawPayload.overall_status !== 'FAIL' &&
    rawPayload.overall_status !== 'PARTIAL' &&
    rawPayload.overall_status !== 'FAIL_CLOSED_INVALID_EVIDENCE'
  ) {
    return {
      ok: false,
      reason: 'Compiled evidence report payload failed schema validation.',
      error: {
        code: 'SCHEMA_VALIDATION_FAILED',
        message:
          'payload.overall_status must be PASS, FAIL, PARTIAL, or FAIL_CLOSED_INVALID_EVIDENCE.',
        field: 'payload.overall_status',
      },
    };
  }

  if (!isWave3CompiledPayload && rawPayload.overall_status === 'PARTIAL') {
    return {
      ok: false,
      reason: 'Compiled evidence report payload failed schema validation.',
      error: {
        code: 'SCHEMA_VALIDATION_FAILED',
        message:
          'payload.overall_status=PARTIAL is only allowed for wave3 compiled reports.',
        field: 'payload.overall_status',
      },
    };
  }

  if (
    !matrixHashOptional &&
    !isBase64UrlString(rawPayload.matrix_hash_b64u, 8)
  ) {
    return {
      ok: false,
      reason: 'Compiled evidence report payload failed schema validation.',
      error: {
        code: 'SCHEMA_VALIDATION_FAILED',
        message: 'payload.matrix_hash_b64u must be base64url (min length 8).',
        field: 'payload.matrix_hash_b64u',
      },
    };
  }

  if (!Array.isArray(rawPayload.control_results) || rawPayload.control_results.length === 0) {
    return {
      ok: false,
      reason: 'Compiled evidence report payload failed schema validation.',
      error: {
        code: 'SCHEMA_VALIDATION_FAILED',
        message: 'payload.control_results must be a non-empty array.',
        field: 'payload.control_results',
      },
    };
  }

  for (let i = 0; i < rawPayload.control_results.length; i++) {
    const control = rawPayload.control_results[i];
    const prefix = `payload.control_results[${i}]`;

    if (!isRecord(control)) {
      return {
        ok: false,
        reason: 'Compiled evidence report payload failed schema validation.',
        error: {
          code: 'SCHEMA_VALIDATION_FAILED',
          message: `${prefix} must be an object.`,
          field: prefix,
        },
      };
    }

    if (!isNonEmptyString(control.control_id)) {
      return {
        ok: false,
        reason: 'Compiled evidence report payload failed schema validation.',
        error: {
          code: 'SCHEMA_VALIDATION_FAILED',
          message: `${prefix}.control_id must be a non-empty string.`,
          field: `${prefix}.control_id`,
        },
      };
    }

    if (
      control.status !== 'PASS' &&
      control.status !== 'FAIL' &&
      control.status !== 'PARTIAL' &&
      control.status !== 'INAPPLICABLE' &&
      control.status !== 'FAIL_CLOSED_INVALID_EVIDENCE'
    ) {
      return {
        ok: false,
        reason: 'Compiled evidence report payload failed schema validation.',
        error: {
          code: 'SCHEMA_VALIDATION_FAILED',
          message:
            `${prefix}.status must be PASS, FAIL, PARTIAL, INAPPLICABLE, or FAIL_CLOSED_INVALID_EVIDENCE.`,
          field: `${prefix}.status`,
        },
      };
    }

    if (!isWave3CompiledPayload && control.status === 'PARTIAL') {
      return {
        ok: false,
        reason: 'Compiled evidence report payload failed schema validation.',
        error: {
          code: 'SCHEMA_VALIDATION_FAILED',
          message: `${prefix}.status=PARTIAL is only allowed for wave3 compiled reports.`,
          field: `${prefix}.status`,
        },
      };
    }

    if (!Array.isArray(control.reason_codes) || control.reason_codes.length === 0) {
      return {
        ok: false,
        reason: 'Compiled evidence report payload failed schema validation.',
        error: {
          code: 'SCHEMA_VALIDATION_FAILED',
          message: `${prefix}.reason_codes must be a non-empty array.`,
          field: `${prefix}.reason_codes`,
        },
      };
    }

    const invalidReason = control.reason_codes.some(
      (reasonCode) =>
        !isNonEmptyString(reasonCode) || !/^[A-Z0-9_]{3,}$/.test(reasonCode),
    );
    if (invalidReason) {
      return {
        ok: false,
        reason: 'Compiled evidence report payload failed schema validation.',
        error: {
          code: 'SCHEMA_VALIDATION_FAILED',
          message: `${prefix}.reason_codes values must match /^[A-Z0-9_]{3,}$/.`,
          field: `${prefix}.reason_codes`,
        },
      };
    }

    if (
      !Array.isArray(control.evidence_hashes_b64u) ||
      control.evidence_hashes_b64u.length === 0
    ) {
      return {
        ok: false,
        reason: 'Compiled evidence report payload failed schema validation.',
        error: {
          code: 'SCHEMA_VALIDATION_FAILED',
          message: `${prefix}.evidence_hashes_b64u must be a non-empty array.`,
          field: `${prefix}.evidence_hashes_b64u`,
        },
      };
    }

    const invalidEvidenceHash = control.evidence_hashes_b64u.some(
      (hash) => !isBase64UrlString(hash, 8),
    );
    if (invalidEvidenceHash) {
      return {
        ok: false,
        reason: 'Compiled evidence report payload failed schema validation.',
        error: {
          code: 'SCHEMA_VALIDATION_FAILED',
          message: `${prefix}.evidence_hashes_b64u values must be base64url (min length 8).`,
          field: `${prefix}.evidence_hashes_b64u`,
        },
      };
    }

    if (typeof control.waiver_applied !== 'boolean') {
      return {
        ok: false,
        reason: 'Compiled evidence report payload failed schema validation.',
        error: {
          code: 'SCHEMA_VALIDATION_FAILED',
          message: `${prefix}.waiver_applied must be a boolean.`,
          field: `${prefix}.waiver_applied`,
        },
      };
    }

    if (!isWave3CompiledPayload && control.waiver_applied !== false) {
      return {
        ok: false,
        reason: 'Compiled evidence report payload failed schema validation.',
        error: {
          code: 'SCHEMA_VALIDATION_FAILED',
          message: `${prefix}.waiver_applied must be false for wave2 compiled reports.`,
          field: `${prefix}.waiver_applied`,
        },
      };
    }

    if (isWave3CompiledPayload && control.waiver_applied && control.status !== 'PARTIAL') {
      return {
        ok: false,
        reason: 'Compiled evidence report payload failed schema validation.',
        error: {
          code: 'SCHEMA_VALIDATION_FAILED',
          message: `${prefix}.waiver_applied=true requires status=PARTIAL.`,
          field: `${prefix}.status`,
        },
      };
    }

    if (isWave3CompiledPayload && control.status === 'PARTIAL' && control.waiver_applied !== true) {
      return {
        ok: false,
        reason: 'Compiled evidence report payload failed schema validation.',
        error: {
          code: 'SCHEMA_VALIDATION_FAILED',
          message: `${prefix}.status=PARTIAL requires waiver_applied=true.`,
          field: `${prefix}.waiver_applied`,
        },
      };
    }

    const residualReasonCount = countWaiverResidualReasonCodes(control.reason_codes);
    const hasWaiverAppliedReason = control.reason_codes.includes(
      WAIVER_APPLIED_REASON_CODE,
    );
    const hasBaseReasonCode = control.reason_codes.some(
      (reasonCode) =>
        reasonCode !== WAIVER_APPLIED_REASON_CODE &&
        !WAIVER_RESIDUAL_REASON_CODES.has(reasonCode),
    );

    if (control.waiver_applied) {
      if (!hasWaiverAppliedReason) {
        return {
          ok: false,
          reason: 'Compiled evidence report payload failed schema validation.',
          error: {
            code: 'SCHEMA_VALIDATION_FAILED',
            message:
              `${prefix}.waiver_applied=true requires reason_codes to include ${WAIVER_APPLIED_REASON_CODE}.`,
            field: `${prefix}.reason_codes`,
          },
        };
      }

      if (residualReasonCount !== 1) {
        return {
          ok: false,
          reason: 'Compiled evidence report payload failed schema validation.',
          error: {
            code: 'SCHEMA_VALIDATION_FAILED',
            message:
              `${prefix}.waiver_applied=true requires exactly one deterministic residual reason code.`,
            field: `${prefix}.reason_codes`,
          },
        };
      }

      if (!hasBaseReasonCode) {
        return {
          ok: false,
          reason: 'Compiled evidence report payload failed schema validation.',
          error: {
            code: 'SCHEMA_VALIDATION_FAILED',
            message:
              `${prefix}.waiver_applied=true requires the underlying control failure reason code to remain present.`,
            field: `${prefix}.reason_codes`,
          },
        };
      }
    } else if (hasWaiverReasonMarkers(control.reason_codes)) {
      return {
        ok: false,
        reason: 'Compiled evidence report payload failed schema validation.',
        error: {
          code: 'SCHEMA_VALIDATION_FAILED',
          message:
            `${prefix}.reason_codes may not contain waiver markers when waiver_applied=false.`,
          field: `${prefix}.reason_codes`,
        },
      };
    }
  }

  if (rawPayload.narrative !== undefined) {
    const narrative = rawPayload.narrative;

    if (!isRecord(narrative)) {
      return {
        ok: false,
        reason: 'Compiled evidence report payload failed schema validation.',
        error: {
          code: 'SCHEMA_VALIDATION_FAILED',
          message: 'payload.narrative must be a JSON object when present.',
          field: 'payload.narrative',
        },
      };
    }

    if (narrative.narrative_version !== '1') {
      return {
        ok: false,
        reason: 'Compiled evidence report payload failed schema validation.',
        error: {
          code: 'SCHEMA_VALIDATION_FAILED',
          message: 'payload.narrative.narrative_version must equal "1".',
          field: 'payload.narrative.narrative_version',
        },
      };
    }

    if (!isNonEmptyString(narrative.report_id)) {
      return {
        ok: false,
        reason: 'Compiled evidence report payload failed schema validation.',
        error: {
          code: 'SCHEMA_VALIDATION_FAILED',
          message: 'payload.narrative.report_id must be a non-empty string.',
          field: 'payload.narrative.report_id',
        },
      };
    }

    if (narrative.report_id !== rawPayload.report_id) {
      return {
        ok: false,
        reason: 'Compiled evidence report payload failed schema validation.',
        error: {
          code: 'SCHEMA_VALIDATION_FAILED',
          message: 'payload.narrative.report_id must match payload.report_id.',
          field: 'payload.narrative.report_id',
        },
      };
    }

    if (!isNonEmptyString(narrative.generated_at) || !STRICT_ISO_UTC_RE.test(narrative.generated_at)) {
      return {
        ok: false,
        reason: 'Compiled evidence report payload failed schema validation.',
        error: {
          code: 'SCHEMA_VALIDATION_FAILED',
          message:
            'payload.narrative.generated_at must be a strict UTC ISO-8601 timestamp.',
          field: 'payload.narrative.generated_at',
        },
      };
    }

    if (narrative.authoritative !== false) {
      return {
        ok: false,
        reason: 'Compiled evidence report payload failed schema validation.',
        error: {
          code: 'SCHEMA_VALIDATION_FAILED',
          message: 'payload.narrative.authoritative must equal false.',
          field: 'payload.narrative.authoritative',
        },
      };
    }

    if (narrative.disclaimer !== COMPILED_EVIDENCE_NARRATIVE_DISCLAIMER) {
      return {
        ok: false,
        reason: 'Compiled evidence report payload failed schema validation.',
        error: {
          code: 'SCHEMA_VALIDATION_FAILED',
          message:
            'payload.narrative.disclaimer must match the fixed non-authoritative disclaimer contract.',
          field: 'payload.narrative.disclaimer',
        },
      };
    }

    if (!isBase64UrlString(narrative.authoritative_matrix_hash_b64u, 8)) {
      return {
        ok: false,
        reason: 'Compiled evidence report payload failed schema validation.',
        error: {
          code: 'SCHEMA_VALIDATION_FAILED',
          message:
            'payload.narrative.authoritative_matrix_hash_b64u must be base64url (min length 8).',
          field: 'payload.narrative.authoritative_matrix_hash_b64u',
        },
      };
    }

    if (narrative.authoritative_matrix_hash_b64u !== rawPayload.matrix_hash_b64u) {
      return {
        ok: false,
        reason: 'Compiled evidence report payload failed schema validation.',
        error: {
          code: 'SCHEMA_VALIDATION_FAILED',
          message:
            'payload.narrative.authoritative_matrix_hash_b64u must match payload.matrix_hash_b64u.',
          field: 'payload.narrative.authoritative_matrix_hash_b64u',
        },
      };
    }

    if (!isBase64UrlString(narrative.authoritative_report_hash_b64u, 8)) {
      return {
        ok: false,
        reason: 'Compiled evidence report payload failed schema validation.',
        error: {
          code: 'SCHEMA_VALIDATION_FAILED',
          message:
            'payload.narrative.authoritative_report_hash_b64u must be base64url (min length 8).',
          field: 'payload.narrative.authoritative_report_hash_b64u',
        },
      };
    }

    if (!isNonEmptyString(narrative.text) || narrative.text.length > 20000) {
      return {
        ok: false,
        reason: 'Compiled evidence report payload failed schema validation.',
        error: {
          code: 'SCHEMA_VALIDATION_FAILED',
          message: 'payload.narrative.text must be 1..20000 characters.',
          field: 'payload.narrative.text',
        },
      };
    }

    if (
      narrative.generator_provider !== undefined &&
      !isNonEmptyString(narrative.generator_provider)
    ) {
      return {
        ok: false,
        reason: 'Compiled evidence report payload failed schema validation.',
        error: {
          code: 'SCHEMA_VALIDATION_FAILED',
          message:
            'payload.narrative.generator_provider, when present, must be a non-empty string.',
          field: 'payload.narrative.generator_provider',
        },
      };
    }

    if (
      narrative.generator_model !== undefined &&
      !isNonEmptyString(narrative.generator_model)
    ) {
      return {
        ok: false,
        reason: 'Compiled evidence report payload failed schema validation.',
        error: {
          code: 'SCHEMA_VALIDATION_FAILED',
          message:
            'payload.narrative.generator_model, when present, must be a non-empty string.',
          field: 'payload.narrative.generator_model',
        },
      };
    }
  }

  const computedOverallStatus = summarizeOverallStatus(
    rawPayload.control_results as unknown as CompiledEvidenceControlResult[],
  );
  if (computedOverallStatus !== rawPayload.overall_status) {
    return {
      ok: false,
      reason: 'Compiled evidence report payload failed schema validation.',
      error: {
        code: 'SCHEMA_VALIDATION_FAILED',
        message:
          `payload.overall_status must equal ${computedOverallStatus} for the provided control_results.`,
        field: 'payload.overall_status',
      },
    };
  }

  return {
    ok: true,
    value: rawPayload as unknown as CompiledEvidenceReportPayload,
  };
}

function invalidResponse(
  now: string,
  reason: string,
  error: VerificationError,
  extras: Partial<VerifyCompiledEvidenceReportResponse> = {},
): VerifyCompiledEvidenceReportResponse {
  const result: VerificationResult = {
    status: 'INVALID',
    reason,
    envelope_type: 'compiled_evidence_report',
    verified_at: now,
  };

  return {
    result,
    error,
    ...extras,
  };
}

export async function verifyCompiledEvidenceReport(
  envelopeInput: unknown,
): Promise<VerifyCompiledEvidenceReportResponse> {
  const now = new Date().toISOString();

  if (!isRecord(envelopeInput)) {
    return invalidResponse(now, 'Compiled evidence report envelope is malformed.', {
      code: 'SCHEMA_VALIDATION_FAILED',
      message: 'Envelope must be a JSON object.',
      field: 'envelope',
    });
  }

  if (envelopeInput.envelope_version !== '1') {
    return invalidResponse(
      now,
      'Compiled evidence report envelope failed schema validation.',
      {
        code: 'SCHEMA_VALIDATION_FAILED',
        message: 'envelope_version must equal "1".',
        field: 'envelope_version',
      },
    );
  }

  if (envelopeInput.envelope_type !== 'compiled_evidence_report') {
    return invalidResponse(
      now,
      'Compiled evidence report envelope failed schema validation.',
      {
        code: 'SCHEMA_VALIDATION_FAILED',
        message: 'envelope_type must equal "compiled_evidence_report".',
        field: 'envelope_type',
      },
    );
  }

  if (envelopeInput.hash_algorithm !== 'SHA-256') {
    return invalidResponse(
      now,
      'Compiled evidence report envelope hash algorithm is unsupported.',
      {
        code:
          envelopeInput.hash_algorithm === 'BLAKE3'
            ? 'UNKNOWN_HASH_ALGORITHM'
            : 'SCHEMA_VALIDATION_FAILED',
        message: 'hash_algorithm must equal "SHA-256".',
        field: 'hash_algorithm',
      },
    );
  }

  if (envelopeInput.algorithm !== 'Ed25519') {
    return invalidResponse(
      now,
      'Compiled evidence report envelope signature algorithm is unsupported.',
      {
        code: 'UNKNOWN_ALGORITHM',
        message: 'algorithm must equal "Ed25519".',
        field: 'algorithm',
      },
    );
  }

  if (!isBase64UrlString(envelopeInput.payload_hash_b64u, 8)) {
    return invalidResponse(
      now,
      'Compiled evidence report envelope failed schema validation.',
      {
        code: 'SCHEMA_VALIDATION_FAILED',
        message: 'payload_hash_b64u must be base64url (min length 8).',
        field: 'payload_hash_b64u',
      },
    );
  }

  if (!isBase64UrlString(envelopeInput.signature_b64u, 8)) {
    return invalidResponse(
      now,
      'Compiled evidence report envelope failed schema validation.',
      {
        code: 'SCHEMA_VALIDATION_FAILED',
        message: 'signature_b64u must be base64url (min length 8).',
        field: 'signature_b64u',
      },
    );
  }

  if (!isNonEmptyString(envelopeInput.signer_did)) {
    return invalidResponse(
      now,
      'Compiled evidence report envelope failed schema validation.',
      {
        code: 'SCHEMA_VALIDATION_FAILED',
        message: 'signer_did must be a non-empty string.',
        field: 'signer_did',
      },
    );
  }

  if (!envelopeInput.signer_did.startsWith('did:')) {
    return invalidResponse(
      now,
      'Compiled evidence report signer DID format is invalid.',
      {
        code: 'INVALID_DID_FORMAT',
        message: 'signer_did must start with "did:".',
        field: 'signer_did',
      },
    );
  }

  if (!isNonEmptyString(envelopeInput.issued_at) || !STRICT_ISO_UTC_RE.test(envelopeInput.issued_at)) {
    return invalidResponse(
      now,
      'Compiled evidence report envelope failed schema validation.',
      {
        code: 'SCHEMA_VALIDATION_FAILED',
        message: 'issued_at must be a strict UTC ISO-8601 timestamp.',
        field: 'issued_at',
      },
    );
  }

  const payloadValidation = validatePayload(envelopeInput.payload);
  if (!payloadValidation.ok) {
    return invalidResponse(now, payloadValidation.reason, payloadValidation.error);
  }

  const payload = payloadValidation.value;

  if (payload.narrative) {
    const expectedAuthoritativeReportHash =
      await computeAuthoritativeReportHash(payload);

    if (
      expectedAuthoritativeReportHash !==
      payload.narrative.authoritative_report_hash_b64u
    ) {
      return invalidResponse(
        now,
        'Compiled evidence narrative binding hash mismatch.',
        {
          code: 'HASH_MISMATCH',
          message:
            'payload.narrative.authoritative_report_hash_b64u does not match canonical authoritative report hash.',
          field: 'payload.narrative.authoritative_report_hash_b64u',
        },
        {
          report_id: payload.report_id,
          matrix_hash_b64u: payload.matrix_hash_b64u,
          payload_hash_b64u: envelopeInput.payload_hash_b64u,
        },
      );
    }
  }

  const expectedMatrixHash = await computeMatrixHash(payload.control_results);
  if (expectedMatrixHash !== payload.matrix_hash_b64u) {
    return invalidResponse(
      now,
      'Compiled evidence report matrix hash mismatch.',
      {
        code: 'HASH_MISMATCH',
        message: 'matrix_hash_b64u does not match canonical control_results hash.',
        field: 'payload.matrix_hash_b64u',
      },
      {
        report_id: payload.report_id,
        matrix_hash_b64u: payload.matrix_hash_b64u,
        payload_hash_b64u: envelopeInput.payload_hash_b64u,
      },
    );
  }

  const expectedPayloadHash = await sha256CanonicalB64u(payload);
  if (expectedPayloadHash !== envelopeInput.payload_hash_b64u) {
    return invalidResponse(
      now,
      'Compiled evidence report payload hash mismatch.',
      {
        code: 'HASH_MISMATCH',
        message: 'payload_hash_b64u does not match canonical payload hash.',
        field: 'payload_hash_b64u',
      },
      {
        report_id: payload.report_id,
        matrix_hash_b64u: payload.matrix_hash_b64u,
        payload_hash_b64u: envelopeInput.payload_hash_b64u,
      },
    );
  }

  const publicKeyBytes = extractPublicKeyFromDidKey(envelopeInput.signer_did);
  if (!publicKeyBytes) {
    return invalidResponse(
      now,
      'Compiled evidence report signer DID format is invalid.',
      {
        code: 'INVALID_DID_FORMAT',
        message: 'signer_did must be a did:key DID with Ed25519 multicodec key.',
        field: 'signer_did',
      },
      {
        report_id: payload.report_id,
        matrix_hash_b64u: payload.matrix_hash_b64u,
        payload_hash_b64u: envelopeInput.payload_hash_b64u,
      },
    );
  }

  let signatureBytes: Uint8Array;
  try {
    signatureBytes = base64UrlDecode(envelopeInput.signature_b64u);
  } catch {
    return invalidResponse(
      now,
      'Compiled evidence report envelope is malformed.',
      {
        code: 'MALFORMED_ENVELOPE',
        message: 'signature_b64u must be valid base64url.',
        field: 'signature_b64u',
      },
      {
        report_id: payload.report_id,
        matrix_hash_b64u: payload.matrix_hash_b64u,
        payload_hash_b64u: envelopeInput.payload_hash_b64u,
      },
    );
  }

  const signatureValid = await verifySignature(
    'Ed25519',
    publicKeyBytes,
    signatureBytes,
    new TextEncoder().encode(envelopeInput.payload_hash_b64u),
  );

  if (!signatureValid) {
    return invalidResponse(
      now,
      'Compiled evidence report signature verification failed.',
      {
        code: 'SIGNATURE_INVALID',
        message: 'signature_b64u does not verify payload_hash_b64u with signer_did key.',
        field: 'signature_b64u',
      },
      {
        report_id: payload.report_id,
        matrix_hash_b64u: payload.matrix_hash_b64u,
        payload_hash_b64u: envelopeInput.payload_hash_b64u,
      },
    );
  }

  return {
    result: {
      status: 'VALID',
      reason: 'Compiled evidence report envelope verified successfully.',
      envelope_type: 'compiled_evidence_report',
      signer_did: envelopeInput.signer_did,
      verified_at: now,
    },
    report_id: payload.report_id,
    matrix_hash_b64u: payload.matrix_hash_b64u,
    payload_hash_b64u: envelopeInput.payload_hash_b64u,
  };
}

function compileFailure(
  now: string,
  reason: string,
  error: VerificationError,
): CompileCompiledEvidenceReportResponse {
  return {
    result: {
      status: 'INVALID',
      reason,
      envelope_type: 'compiled_evidence_report',
      verified_at: now,
    },
    error,
  };
}

export async function compileAndSignCompiledEvidenceReport(
  body: unknown,
): Promise<CompileCompiledEvidenceReportResponse> {
  const now = new Date().toISOString();

  if (!isRecord(body)) {
    return compileFailure(now, 'Compile request is malformed.', {
      code: 'SCHEMA_VALIDATION_FAILED',
      message: 'Request body must be a JSON object.',
      field: 'body',
    });
  }

  const payloadValidation = validatePayload(body.payload, { matrixHashOptional: true });
  if (!payloadValidation.ok) {
    return compileFailure(now, payloadValidation.reason, payloadValidation.error);
  }

  if (!isRecord(body.signer)) {
    return compileFailure(now, 'Compile request is missing signer.', {
      code: 'MISSING_REQUIRED_FIELD',
      message: 'signer is required.',
      field: 'signer',
    });
  }

  if (!isNonEmptyString(body.signer.signer_did) || !body.signer.signer_did.startsWith('did:key:')) {
    return compileFailure(now, 'Compile request signer DID is invalid.', {
      code: 'INVALID_DID_FORMAT',
      message: 'signer.signer_did must be a did:key DID.',
      field: 'signer.signer_did',
    });
  }

  const signerPublicKey = extractPublicKeyFromDidKey(body.signer.signer_did);
  if (!signerPublicKey) {
    return compileFailure(now, 'Compile request signer DID is invalid.', {
      code: 'INVALID_DID_FORMAT',
      message: 'signer.signer_did must be a did:key DID with Ed25519 multicodec key.',
      field: 'signer.signer_did',
    });
  }

  if (!isNonEmptyString(body.signer.private_key_pkcs8_b64u)) {
    return compileFailure(now, 'Compile request signer private key is missing.', {
      code: 'MISSING_REQUIRED_FIELD',
      message: 'signer.private_key_pkcs8_b64u is required.',
      field: 'signer.private_key_pkcs8_b64u',
    });
  }

  if (
    body.signer.issued_at !== undefined &&
    (!isNonEmptyString(body.signer.issued_at) || !STRICT_ISO_UTC_RE.test(body.signer.issued_at))
  ) {
    return compileFailure(now, 'Compile request signer issued_at is invalid.', {
      code: 'SCHEMA_VALIDATION_FAILED',
      message: 'signer.issued_at must be a strict UTC ISO-8601 timestamp when provided.',
      field: 'signer.issued_at',
    });
  }

  const issuedAt = body.signer.issued_at ?? payloadValidation.value.compiled_at;

  const normalizedPayload: CompiledEvidenceReportPayload = {
    ...payloadValidation.value,
    matrix_hash_b64u: await computeMatrixHash(payloadValidation.value.control_results),
  };

  if (normalizedPayload.narrative) {
    if (
      normalizedPayload.narrative.authoritative_matrix_hash_b64u !==
      normalizedPayload.matrix_hash_b64u
    ) {
      return compileFailure(now, 'Compile request narrative matrix binding hash mismatch.', {
        code: 'HASH_MISMATCH',
        message:
          'payload.narrative.authoritative_matrix_hash_b64u must match canonical payload.matrix_hash_b64u.',
        field: 'payload.narrative.authoritative_matrix_hash_b64u',
      });
    }

    const expectedAuthoritativeReportHash =
      await computeAuthoritativeReportHash(normalizedPayload);

    if (
      expectedAuthoritativeReportHash !==
      normalizedPayload.narrative.authoritative_report_hash_b64u
    ) {
      return compileFailure(now, 'Compile request narrative binding hash mismatch.', {
        code: 'HASH_MISMATCH',
        message:
          'payload.narrative.authoritative_report_hash_b64u must match canonical authoritative report hash.',
        field: 'payload.narrative.authoritative_report_hash_b64u',
      });
    }
  }

  const payloadHash = await sha256CanonicalB64u(normalizedPayload);

  let privateKeyBytes: Uint8Array;
  try {
    privateKeyBytes = base64UrlDecode(body.signer.private_key_pkcs8_b64u);
  } catch {
    return compileFailure(now, 'Compile request signer private key is invalid.', {
      code: 'MALFORMED_ENVELOPE',
      message: 'signer.private_key_pkcs8_b64u must be valid base64url.',
      field: 'signer.private_key_pkcs8_b64u',
    });
  }

  let privateKey: CryptoKey;
  try {
    privateKey = await crypto.subtle.importKey(
      'pkcs8',
      toArrayBuffer(privateKeyBytes),
      { name: 'Ed25519' },
      false,
      ['sign'],
    );
  } catch {
    return compileFailure(now, 'Compile request signer private key import failed.', {
      code: 'MALFORMED_ENVELOPE',
      message: 'Could not import signer.private_key_pkcs8_b64u as PKCS#8 Ed25519 key.',
      field: 'signer.private_key_pkcs8_b64u',
    });
  }

  const payloadHashBytes = new TextEncoder().encode(payloadHash);

  let signatureBytes: Uint8Array;
  try {
    const signed = await crypto.subtle.sign(
      'Ed25519',
      privateKey,
      toArrayBuffer(payloadHashBytes),
    );
    signatureBytes = new Uint8Array(signed);
  } catch {
    return compileFailure(now, 'Compile request signing failed.', {
      code: 'SIGNATURE_INVALID',
      message: 'Failed to sign payload_hash_b64u with signer key.',
      field: 'signer.private_key_pkcs8_b64u',
    });
  }

  const signerMatchesDid = await verifySignature(
    'Ed25519',
    signerPublicKey,
    signatureBytes,
    payloadHashBytes,
  );

  if (!signerMatchesDid) {
    return compileFailure(now, 'Compile request signer key does not match signer DID.', {
      code: 'SIGNATURE_INVALID',
      message: 'signer.private_key_pkcs8_b64u does not match signer.signer_did.',
      field: 'signer.private_key_pkcs8_b64u',
    });
  }

  const envelope: CompiledEvidenceReportEnvelope = {
    envelope_version: '1',
    envelope_type: 'compiled_evidence_report',
    payload: normalizedPayload,
    payload_hash_b64u: payloadHash,
    hash_algorithm: 'SHA-256',
    signature_b64u: base64UrlEncode(signatureBytes),
    algorithm: 'Ed25519',
    signer_did: body.signer.signer_did,
    issued_at: issuedAt,
  };

  return {
    result: {
      status: 'VALID',
      reason: 'Compiled evidence report signed successfully.',
      envelope_type: 'compiled_evidence_report',
      signer_did: body.signer.signer_did,
      verified_at: now,
    },
    report_id: normalizedPayload.report_id,
    envelope,
  };
}
