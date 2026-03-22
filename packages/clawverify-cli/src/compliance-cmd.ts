import * as fs from 'node:fs/promises';

import {
  compileAuthoritativeComplianceWave2,
  jcsCanonicalize,
  base64UrlEncode,
  type ComplianceFramework,
  type ComplianceBundleInput,
  type CompliancePolicyInput,
  type AuthoritativeVerificationFact,
} from '@clawbureau/clawverify-core';

import { CliUsageError } from './errors.js';

// ---------------------------------------------------------------------------
// Framework flag normalization
// ---------------------------------------------------------------------------

const FRAMEWORK_ALIASES: Record<string, ComplianceFramework> = {
  soc2: 'SOC2_Type2',
  'soc2-type2': 'SOC2_Type2',
  'soc2_type2': 'SOC2_Type2',
  iso27001: 'ISO27001',
  'iso-27001': 'ISO27001',
  'eu-ai-act': 'EU_AI_Act',
  'eu_ai_act': 'EU_AI_Act',
  'nist-ai-rmf': 'NIST_AI_RMF',
  'nist_ai_rmf': 'NIST_AI_RMF',
  'ai-execution-v1': 'CLAW_AI_EXECUTION_ASSURANCE_V1',
  'ai_execution_assurance_v1': 'CLAW_AI_EXECUTION_ASSURANCE_V1',
  'claw-ai-execution-v1': 'CLAW_AI_EXECUTION_ASSURANCE_V1',
  'claw_ai_execution_assurance_v1': 'CLAW_AI_EXECUTION_ASSURANCE_V1',
};

const DETERMINISTIC_EPOCH_ISO = '1970-01-01T00:00:00.000Z';

function resolveFramework(raw: string): ComplianceFramework {
  const normalized = raw.toLowerCase().trim();
  const framework = FRAMEWORK_ALIASES[normalized];
  if (!framework) {
    const validKeys = Object.keys(FRAMEWORK_ALIASES).join(', ');
    throw new CliUsageError(
      `Unknown compliance framework: "${raw}". Valid options: ${validKeys}`,
    );
  }
  return framework;
}

// ---------------------------------------------------------------------------
// Input extraction helpers
// ---------------------------------------------------------------------------

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function parseVerificationStatus(raw: unknown): 'VALID' | 'INVALID' | undefined {
  if (raw === 'VALID' || raw === 'PASS') return 'VALID';
  if (raw === 'INVALID' || raw === 'FAIL' || raw === 'ERROR') return 'INVALID';
  return undefined;
}

function tryExtractBundlePayload(raw: unknown): ComplianceBundleInput | undefined {
  if (!isRecord(raw)) return undefined;

  // Authoritative compiler envelope shape: { bundle: { ... } }
  if (isRecord(raw.bundle) && typeof raw.bundle.agent_did === 'string') {
    return raw.bundle as unknown as ComplianceBundleInput;
  }

  // Ledger/API request wrapper: { proof_bundle: ... }
  if (raw.proof_bundle !== undefined) {
    return tryExtractBundlePayload(raw.proof_bundle);
  }

  // Wrapped: { envelope: { payload: { ... } } }
  if (isRecord(raw.envelope) && isRecord(raw.envelope.payload)) {
    return raw.envelope.payload as unknown as ComplianceBundleInput;
  }

  // Signed envelope: { payload: { ... } }
  if (isRecord(raw.payload) && typeof raw.payload.agent_did === 'string') {
    return raw.payload as unknown as ComplianceBundleInput;
  }

  // Bare payload
  if (typeof raw.agent_did === 'string') {
    return raw as unknown as ComplianceBundleInput;
  }

  return undefined;
}

function extractPolicyInput(raw: unknown): CompliancePolicyInput | undefined {
  if (!isRecord(raw)) return undefined;

  if (isRecord(raw.policy)) {
    return raw.policy as CompliancePolicyInput;
  }

  if (isRecord(raw.wpc_policy_override)) {
    return raw.wpc_policy_override as CompliancePolicyInput;
  }

  return undefined;
}

function extractCompiledReportRefs(
  raw: unknown,
): Record<string, unknown> | undefined {
  if (!isRecord(raw)) return undefined;
  if (!isRecord(raw.compiled_report_refs)) return undefined;
  return raw.compiled_report_refs;
}

function extractCompiledReportSigner(
  raw: unknown,
): Record<string, unknown> | undefined {
  if (!isRecord(raw)) return undefined;
  if (!isRecord(raw.compiled_report_signer)) return undefined;
  return raw.compiled_report_signer;
}

function extractWaiversInput(raw: unknown): unknown[] | undefined {
  if (!isRecord(raw)) return undefined;
  if (!Array.isArray(raw.waivers)) return undefined;
  return raw.waivers;
}

function extractNarrativeRuntime(
  raw: unknown,
): Record<string, unknown> | undefined {
  if (!isRecord(raw)) return undefined;
  if (!isRecord(raw.narrative_runtime)) return undefined;
  return raw.narrative_runtime;
}

function buildFactFromLooseObject(
  raw: Record<string, unknown>,
): AuthoritativeVerificationFact | undefined {
  const status = parseVerificationStatus(raw.status);
  if (!status) return undefined;

  const reasonCode =
    typeof raw.reason_code === 'string' && raw.reason_code.trim().length > 0
      ? raw.reason_code
      : status === 'VALID'
        ? 'OK'
        : 'VERIFICATION_FAILED';

  const reason =
    typeof raw.reason === 'string' && raw.reason.trim().length > 0
      ? raw.reason
      : status === 'VALID'
        ? 'Proof bundle verified successfully'
        : 'Proof bundle verification failed';

  const verifiedAt =
    typeof raw.verified_at === 'string' && raw.verified_at.trim().length > 0
      ? raw.verified_at
      : DETERMINISTIC_EPOCH_ISO;

  return {
    fact_version: '1',
    status,
    reason_code: reasonCode,
    reason,
    verified_at: verifiedAt,
    verifier:
      typeof raw.verifier === 'string' && raw.verifier.trim().length > 0
        ? raw.verifier
        : 'clawverify-cli',
    proof_tier:
      typeof raw.proof_tier === 'string' && raw.proof_tier.trim().length > 0
        ? raw.proof_tier
        : undefined,
    agent_did:
      typeof raw.agent_did === 'string' && raw.agent_did.trim().length > 0
        ? raw.agent_did
        : undefined,
  };
}

function extractVerificationFact(raw: unknown): AuthoritativeVerificationFact | undefined {
  if (!isRecord(raw)) return undefined;

  // Explicit authoritative fact
  if (isRecord(raw.verification_fact)) {
    const explicit = buildFactFromLooseObject(raw.verification_fact);
    if (explicit) return explicit;
  }

  // Accept known verifier output shapes only; never trust ad-hoc top-level PASS/FAIL flags.
  if (isRecord(raw.verification)) {
    const verification = raw.verification;

    if (isRecord(verification.result)) {
      const candidate = buildFactFromLooseObject({
        status: verification.result.status,
        reason_code:
          isRecord(verification.error) && typeof verification.error.code === 'string'
            ? verification.error.code
            : raw.reason_code,
        reason:
          isRecord(verification.error) && typeof verification.error.message === 'string'
            ? verification.error.message
            : raw.reason,
        verified_at: raw.verified_at,
        verifier:
          typeof raw.kind === 'string' && raw.kind.trim().length > 0
            ? 'clawverify-cli'
            : 'clawverify-core',
        proof_tier: verification.result.proof_tier,
        agent_did: verification.result.agent_did,
      });

      if (candidate) return candidate;
    }
  }

  return undefined;
}

/**
 * Compute a stable SHA-256 hash of the bundle for the compiler contract.
 * Uses JCS canonicalization for determinism.
 */
async function hashBundlePayload(bundle: ComplianceBundleInput): Promise<string> {
  const canonical = jcsCanonicalize(bundle);
  const bytes = new TextEncoder().encode(canonical);
  const hashBuffer = await crypto.subtle.digest('SHA-256', bytes);
  return base64UrlEncode(new Uint8Array(hashBuffer));
}

async function buildCompilerInput(
  raw: unknown,
  framework: ComplianceFramework,
): Promise<Record<string, unknown>> {
  const bundle = tryExtractBundlePayload(raw);
  const verificationFact = extractVerificationFact(raw);
  const policy = extractPolicyInput(raw);
  const compiledReportRefs = extractCompiledReportRefs(raw);
  const compiledReportSigner = extractCompiledReportSigner(raw);
  const waivers = extractWaiversInput(raw);
  const narrativeRuntime = extractNarrativeRuntime(raw);

  const compilerInput: Record<string, unknown> = {
    compiler_input_version: '1',
    framework,
  };

  if (bundle) {
    compilerInput.bundle = bundle;
    compilerInput.bundle_hash_b64u = await hashBundlePayload(bundle);
  }

  if (policy) {
    compilerInput.policy = policy;
  }

  if (verificationFact) {
    compilerInput.verification_fact = verificationFact;
  }

  if (waivers) {
    compilerInput.waivers = waivers;
  }

  if (compiledReportRefs) {
    compilerInput.compiled_report_refs = compiledReportRefs;
  }

  if (compiledReportSigner) {
    compilerInput.compiled_report_signer = compiledReportSigner;
  }

  if (narrativeRuntime) {
    compilerInput.narrative_runtime = narrativeRuntime;
  }

  return compilerInput;
}

// ---------------------------------------------------------------------------
// CLI entry
// ---------------------------------------------------------------------------

export async function runComplianceReport(
  inputPath: string,
  frameworkFlag: string,
  outputPath?: string,
): Promise<void> {
  const framework = resolveFramework(frameworkFlag);

  let rawText: string;
  try {
    rawText = await fs.readFile(inputPath, 'utf8');
  } catch (err) {
    throw new CliUsageError(
      `Could not read input file at ${inputPath}: ${err instanceof Error ? err.message : 'unknown error'}`,
    );
  }

  let raw: unknown;
  try {
    raw = JSON.parse(rawText);
  } catch (err) {
    throw new CliUsageError(
      `Input file is not valid JSON: ${err instanceof Error ? err.message : 'unknown error'}`,
    );
  }

  const compilerInput = await buildCompilerInput(raw, framework);
  const compilation = await compileAuthoritativeComplianceWave2(compilerInput);

  const json = JSON.stringify(compilation, null, 2) + '\n';

  if (outputPath) {
    await fs.writeFile(outputPath, json, 'utf8');
    process.stderr.write(`Compliance report written to ${outputPath}\n`);
  } else {
    process.stdout.write(json);
  }
}
