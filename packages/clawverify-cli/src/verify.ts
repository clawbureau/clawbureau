import * as fs from 'node:fs/promises';

import {
  verifyExportBundle,
  verifyProofBundle,
  type ExportBundlePayload,
  type ProofBundlePayload,
  type SignedEnvelope,
  type VerifyBundleResponse,
  type VerifyExportBundleResponse,
} from '@clawbureau/clawverify-core';

import type { CliKind, CliVerifyOutput, ResolvedVerifierConfig } from './types.js';
import { CliUsageError } from './errors.js';

function nowIso(): string {
  return new Date().toISOString();
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

async function readJsonFile(path: string): Promise<unknown> {
  let raw: string;
  try {
    raw = await fs.readFile(path, 'utf8');
  } catch (err) {
    throw new CliUsageError(
      `Could not read input file at ${path}: ${err instanceof Error ? err.message : 'unknown error'}`
    );
  }

  try {
    return JSON.parse(raw) as unknown;
  } catch (err) {
    throw new CliUsageError(
      `Input file is not valid JSON: ${err instanceof Error ? err.message : 'unknown error'}`
    );
  }
}

function unwrapProofBundleInput(value: unknown): unknown {
  if (!isRecord(value)) return value;
  const envelope = value.envelope;
  if (envelope !== undefined) return envelope;
  return value;
}

function unwrapExportBundleInput(value: unknown): unknown {
  if (!isRecord(value)) return value;
  const bundle = value.bundle;
  if (bundle !== undefined) return bundle;
  return value;
}

function countReceiptsFromEnvelope(envelope: unknown): number {
  if (!isRecord(envelope)) return 0;
  const payload = envelope.payload;
  if (!isRecord(payload)) return 0;
  const receipts = payload.receipts;
  if (!Array.isArray(receipts)) return 0;
  return receipts.length;
}

function strictProofBundleReceiptVerdict(opts: {
  envelope: unknown;
  verification: VerifyBundleResponse;
  config: ResolvedVerifierConfig;
}): { ok: true } | { ok: false; reason_code: string; reason: string } {
  const receiptsCount = countReceiptsFromEnvelope(opts.envelope);
  if (receiptsCount === 0) return { ok: true };

  // Fail-closed: if receipts are present, a signer allowlist MUST be configured.
  if (opts.config.gatewayReceiptSignerDids.length === 0) {
    return {
      ok: false,
      reason_code: 'DEPENDENCY_NOT_CONFIGURED',
      reason: 'Gateway receipt signer allowlist not configured (required to verify receipts)',
    };
  }

  const cr = opts.verification.result.component_results;
  const verified = cr?.receipts_verified_count ?? 0;
  const sigVerified = cr?.receipts_signature_verified_count ?? 0;

  // Conformance mode: all receipts must verify and be bound.
  if (verified !== receiptsCount) {
    if (sigVerified === receiptsCount) {
      return {
        ok: false,
        reason_code: 'RECEIPT_BINDING_MISMATCH',
        reason: 'One or more receipts are not bound to the proof bundle event chain',
      };
    }

    return {
      ok: false,
      reason_code: 'RECEIPT_VERIFICATION_FAILED',
      reason: 'One or more receipts failed cryptographic verification',
    };
  }

  return { ok: true };
}

export async function verifyProofBundleFromFile(opts: {
  inputPath: string;
  /** Optional URM path. If not provided, clawverify will try to auto-load a sibling "-urm.json" file for "-bundle.json" inputs. */
  urmPath?: string;
  configPath?: string;
  config: ResolvedVerifierConfig;
}): Promise<CliVerifyOutput> {
  const verifiedAt = nowIso();

  const raw = await readJsonFile(opts.inputPath);
  const envelope = unwrapProofBundleInput(raw) as SignedEnvelope<ProofBundlePayload>;

  // Optional: load URM from an explicit flag, or auto-detect a sibling file for canonical PoH evidence packs.
  let resolvedUrmPath: string | undefined = opts.urmPath;

  if (!resolvedUrmPath && opts.inputPath.endsWith('-bundle.json')) {
    const candidate = opts.inputPath.replace(/-bundle\.json$/, '-urm.json');
    try {
      await fs.access(candidate);
      resolvedUrmPath = candidate;
    } catch {
      // ignore
    }
  }

  const urm = resolvedUrmPath ? await readJsonFile(resolvedUrmPath) : undefined;

  const input = {
    path: opts.inputPath,
    config_path: opts.configPath,
    urm_path: resolvedUrmPath,
  };

  const verification = await verifyProofBundle(envelope, {
    allowlistedReceiptSignerDids: opts.config.gatewayReceiptSignerDids,
    allowlistedAttesterDids: opts.config.attestationSignerDids,
    urm,
  });

  if (verification.result.status !== 'VALID') {
    return {
      kind: 'proof_bundle',
      status: 'FAIL',
      verified_at: verifiedAt,
      reason_code: verification.error?.code ?? 'INVALID',
      reason: verification.error?.message ?? verification.result.reason,
      input,
      verification,
    };
  }

  const strict = strictProofBundleReceiptVerdict({
    envelope,
    verification,
    config: opts.config,
  });

  if (!strict.ok) {
    return {
      kind: 'proof_bundle',
      status: 'FAIL',
      verified_at: verifiedAt,
      reason_code: strict.reason_code,
      reason: strict.reason,
      input,
      verification,
    };
  }

  return {
    kind: 'proof_bundle',
    status: 'PASS',
    verified_at: verifiedAt,
    reason_code: 'OK',
    reason: 'Proof bundle verified successfully',
    input,
    verification,
  };
}

export async function verifyExportBundleFromFile(opts: {
  inputPath: string;
  configPath?: string;
  config: ResolvedVerifierConfig;
}): Promise<CliVerifyOutput> {
  const verifiedAt = nowIso();

  const raw = await readJsonFile(opts.inputPath);
  const bundle = unwrapExportBundleInput(raw) as ExportBundlePayload;

  const verification: VerifyExportBundleResponse = await verifyExportBundle(bundle, {
    allowlistedReceiptSignerDids: opts.config.gatewayReceiptSignerDids,
    allowlistedAttesterDids: opts.config.attestationSignerDids,
    allowlistedExecutionAttestationSignerDids: opts.config.executionAttestationSignerDids,
    allowlistedDerivationAttestationSignerDids: opts.config.derivationAttestationSignerDids,
    allowlistedAuditResultAttestationSignerDids: opts.config.auditResultAttestationSignerDids,
  });

  if (verification.result.status !== 'VALID') {
    return {
      kind: 'export_bundle',
      status: 'FAIL',
      verified_at: verifiedAt,
      reason_code: verification.error?.code ?? 'INVALID',
      reason: verification.error?.message ?? verification.result.reason,
      input: {
        path: opts.inputPath,
        config_path: opts.configPath,
      },
      verification,
    };
  }

  // Optional strict receipt enforcement for nested proof bundle.
  const nestedProofEnvelope = (bundle as any)?.artifacts?.proof_bundle_envelope;
  if (nestedProofEnvelope !== undefined) {
    const proofOut = await verifyProofBundle(nestedProofEnvelope, {
      allowlistedReceiptSignerDids: opts.config.gatewayReceiptSignerDids,
      allowlistedAttesterDids: opts.config.attestationSignerDids,
    });

    if (proofOut.result.status !== 'VALID') {
      return {
        kind: 'export_bundle',
        status: 'FAIL',
        verified_at: verifiedAt,
        reason_code: proofOut.error?.code ?? 'INVALID',
        reason: `Nested proof bundle verification failed: ${proofOut.error?.message ?? proofOut.result.reason}`,
        input: {
          path: opts.inputPath,
          config_path: opts.configPath,
        },
        verification: {
          export_bundle: verification,
          proof_bundle: proofOut,
        },
      };
    }

    const strict = strictProofBundleReceiptVerdict({
      envelope: nestedProofEnvelope,
      verification: proofOut,
      config: opts.config,
    });

    if (!strict.ok) {
      return {
        kind: 'export_bundle',
        status: 'FAIL',
        verified_at: verifiedAt,
        reason_code: strict.reason_code,
        reason: strict.reason,
        input: {
          path: opts.inputPath,
          config_path: opts.configPath,
        },
        verification: {
          export_bundle: verification,
          proof_bundle: proofOut,
        },
      };
    }
  }

  return {
    kind: 'export_bundle',
    status: 'PASS',
    verified_at: verifiedAt,
    reason_code: 'OK',
    reason: 'Export bundle verified successfully',
    input: {
      path: opts.inputPath,
      config_path: opts.configPath,
    },
    verification,
  };
}

export function exitCodeForOutput(out: { status: string }): number {
  if (out.status === 'PASS') return 0;
  if (out.status === 'FAIL') return 1;
  return 2;
}

export function kindForSubcommand(cmd: string): CliKind | null {
  if (cmd === 'proof-bundle' || cmd === 'proof_bundle') return 'proof_bundle';
  if (cmd === 'export-bundle' || cmd === 'export_bundle') return 'export_bundle';
  return null;
}
