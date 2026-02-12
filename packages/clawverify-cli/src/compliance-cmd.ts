import * as fs from 'node:fs/promises';

import {
  generateComplianceReport,
  computeHash,
  jcsCanonicalize,
  base64UrlEncode,
  type ComplianceFramework,
  type ComplianceBundleInput,
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
};

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
// Bundle loading
// ---------------------------------------------------------------------------

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * Extracts the proof bundle payload from various input shapes:
 * - Bare proof_bundle payload (has bundle_version + agent_did)
 * - Signed envelope (has payload.bundle_version + payload.agent_did)
 * - Wrapped { envelope: ... } object
 */
function extractBundlePayload(raw: unknown): ComplianceBundleInput {
  if (!isRecord(raw)) {
    throw new CliUsageError('Input file must be a JSON object.');
  }

  // Wrapped: { envelope: { payload: { ... } } }
  if (isRecord(raw.envelope) && isRecord((raw.envelope as any).payload)) {
    return (raw.envelope as any).payload as ComplianceBundleInput;
  }

  // Signed envelope: { payload: { bundle_version, agent_did, ... } }
  if (isRecord(raw.payload) && typeof (raw.payload as Record<string, unknown>).agent_did === 'string') {
    return raw.payload as unknown as ComplianceBundleInput;
  }

  // Bare payload
  if (typeof raw.agent_did === 'string') {
    return raw as unknown as ComplianceBundleInput;
  }

  throw new CliUsageError(
    'Cannot extract proof bundle payload from input. Expected a proof_bundle payload, signed envelope, or { envelope: ... } wrapper.',
  );
}

/**
 * Compute a stable SHA-256 hash of the bundle for the report.
 * Uses JCS canonicalization for determinism.
 */
async function hashBundlePayload(bundle: ComplianceBundleInput): Promise<string> {
  const canonical = jcsCanonicalize(bundle);
  const bytes = new TextEncoder().encode(canonical);
  const hashBuffer = await crypto.subtle.digest('SHA-256', bytes);
  return base64UrlEncode(new Uint8Array(hashBuffer));
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

  // Read input
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

  const bundle = extractBundlePayload(raw);
  const bundleHash = await hashBundlePayload(bundle);

  const report = generateComplianceReport(framework, bundle, undefined, {
    bundleHash,
  });

  const json = JSON.stringify(report, null, 2) + '\n';

  if (outputPath) {
    await fs.writeFile(outputPath, json, 'utf8');
    process.stderr.write(`Compliance report written to ${outputPath}\n`);
  } else {
    process.stdout.write(json);
  }
}
