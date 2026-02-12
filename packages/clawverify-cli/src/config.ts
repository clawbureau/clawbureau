import * as fs from 'node:fs/promises';

import type { ClawverifyConfigV1, ResolvedVerifierConfig } from './types.js';

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((v) => typeof v === 'string') as string[];
}

function parseCommaSeparatedAllowlist(value: string | undefined): string[] {
  if (!value) return [];
  return value
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

export class CliConfigError extends Error {
  readonly code = 'CONFIG_ERROR';

  constructor(message: string) {
    super(message);
  }
}

export async function loadClawverifyConfigFile(
  path: string
): Promise<ClawverifyConfigV1> {
  let raw: string;
  try {
    raw = await fs.readFile(path, 'utf8');
  } catch (err) {
    throw new CliConfigError(
      `Could not read config file at ${path}: ${err instanceof Error ? err.message : 'unknown error'}`
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new CliConfigError(
      `Config file is not valid JSON: ${err instanceof Error ? err.message : 'unknown error'}`
    );
  }

  if (!isRecord(parsed) || parsed.config_version !== '1') {
    throw new CliConfigError(
      'Config must be an object with {"config_version":"1", ... }'
    );
  }

  const allowlists = isRecord(parsed.allowlists) ? parsed.allowlists : {};

  return {
    config_version: '1',
    allowlists: {
      gateway_receipt_signer_dids: asStringArray(
        (allowlists as Record<string, unknown>).gateway_receipt_signer_dids
      ),
      web_receipt_signer_dids: asStringArray(
        (allowlists as Record<string, unknown>).web_receipt_signer_dids
      ),
      attestation_signer_dids: asStringArray(
        (allowlists as Record<string, unknown>).attestation_signer_dids
      ),
      execution_attestation_signer_dids: asStringArray(
        (allowlists as Record<string, unknown>).execution_attestation_signer_dids
      ),
      derivation_attestation_signer_dids: asStringArray(
        (allowlists as Record<string, unknown>).derivation_attestation_signer_dids
      ),
      audit_result_attestation_signer_dids: asStringArray(
        (allowlists as Record<string, unknown>).audit_result_attestation_signer_dids
      ),
    },
  };
}

function mergeUnique(a: string[], b: string[]): string[] {
  const out = new Set<string>();
  for (const v of a) out.add(v);
  for (const v of b) out.add(v);
  return [...out];
}

export async function resolveVerifierConfig(opts: {
  configPath?: string;
}): Promise<ResolvedVerifierConfig> {
  const fileConfig: ClawverifyConfigV1 | null = opts.configPath
    ? await loadClawverifyConfigFile(opts.configPath)
    : null;

  const fileAllowlists = fileConfig?.allowlists ?? {};

  // Env var parity with hosted clawverify service.
  const envAllowlists = {
    gateway_receipt_signer_dids: parseCommaSeparatedAllowlist(
      process.env.GATEWAY_RECEIPT_SIGNER_DIDS
    ),
    web_receipt_signer_dids: parseCommaSeparatedAllowlist(
      process.env.WEB_RECEIPT_SIGNER_DIDS
    ),
    attestation_signer_dids: parseCommaSeparatedAllowlist(
      process.env.ATTESTATION_SIGNER_DIDS
    ),
    execution_attestation_signer_dids: parseCommaSeparatedAllowlist(
      process.env.EXECUTION_ATTESTATION_SIGNER_DIDS
    ),
    derivation_attestation_signer_dids: parseCommaSeparatedAllowlist(
      process.env.DERIVATION_ATTESTATION_SIGNER_DIDS
    ),
    audit_result_attestation_signer_dids: parseCommaSeparatedAllowlist(
      process.env.AUDIT_RESULT_ATTESTATION_SIGNER_DIDS
    ),
  };

  return {
    gatewayReceiptSignerDids: mergeUnique(
      fileAllowlists.gateway_receipt_signer_dids ?? [],
      envAllowlists.gateway_receipt_signer_dids
    ),
    webReceiptSignerDids: mergeUnique(
      fileAllowlists.web_receipt_signer_dids ?? [],
      envAllowlists.web_receipt_signer_dids
    ),
    attestationSignerDids: mergeUnique(
      fileAllowlists.attestation_signer_dids ?? [],
      envAllowlists.attestation_signer_dids
    ),
    executionAttestationSignerDids: mergeUnique(
      fileAllowlists.execution_attestation_signer_dids ?? [],
      envAllowlists.execution_attestation_signer_dids
    ),
    derivationAttestationSignerDids: mergeUnique(
      fileAllowlists.derivation_attestation_signer_dids ?? [],
      envAllowlists.derivation_attestation_signer_dids
    ),
    auditResultAttestationSignerDids: mergeUnique(
      fileAllowlists.audit_result_attestation_signer_dids ?? [],
      envAllowlists.audit_result_attestation_signer_dids
    ),
  };
}
