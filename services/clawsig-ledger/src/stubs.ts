import {
  compileAuthoritativeComplianceWave1,
  type ComplianceFramework as CoreComplianceFramework,
  type ComplianceBundleInput as CoreComplianceBundleInput,
  type CompliancePolicyInput as CoreCompliancePolicyInput,
} from '@clawbureau/clawverify-core';

export type ComplianceFramework =
  | 'soc2'
  | 'iso27001'
  | 'eu-ai-act'
  | 'nist-ai-rmf';

export type ComplianceBundleInput = CoreComplianceBundleInput;
export type CompliancePolicyInput = CoreCompliancePolicyInput;

export interface ComplianceCompileContext {
  bundle_hash_b64u?: string;
  verification_fact?: {
    status: 'VALID' | 'INVALID';
    reason_code: string;
    reason?: string;
    verified_at?: string;
    verifier?: string;
    proof_tier?: string;
    agent_did?: string;
  };
}

const DETERMINISTIC_EPOCH_ISO = '1970-01-01T00:00:00.000Z';

function normalizeFramework(
  framework: ComplianceFramework,
): CoreComplianceFramework | undefined {
  switch (framework) {
    case 'soc2':
      return 'SOC2_Type2';
    case 'iso27001':
      return 'ISO27001';
    case 'eu-ai-act':
      return 'EU_AI_Act';
    case 'nist-ai-rmf':
      return 'NIST_AI_RMF';
    default:
      return undefined;
  }
}

export function generateComplianceReport(
  framework: ComplianceFramework,
  bundle: ComplianceBundleInput,
  policy?: CompliancePolicyInput,
  context?: ComplianceCompileContext,
): Record<string, unknown> {
  const normalizedFramework = normalizeFramework(framework);

  const compilerInput: Record<string, unknown> = {
    compiler_input_version: '1',
    framework: normalizedFramework ?? 'SOC2_Type2',
    bundle,
    policy,
  };

  if (typeof context?.bundle_hash_b64u === 'string') {
    compilerInput.bundle_hash_b64u = context.bundle_hash_b64u;
  }

  if (context?.verification_fact) {
    compilerInput.verification_fact = {
      fact_version: '1',
      status: context.verification_fact.status,
      reason_code: context.verification_fact.reason_code,
      reason:
        context.verification_fact.reason ??
        (context.verification_fact.status === 'VALID'
          ? 'Proof bundle verified successfully'
          : 'Proof bundle verification failed'),
      verified_at:
        context.verification_fact.verified_at ?? DETERMINISTIC_EPOCH_ISO,
      verifier: context.verification_fact.verifier ?? 'clawsig-ledger',
      proof_tier: context.verification_fact.proof_tier,
      agent_did: context.verification_fact.agent_did,
    };
  }

  if (!normalizedFramework) {
    return {
      runtime: {
        runtime_version: '1',
        engine: 'clawcompiler-runtime-v1-wave1',
        deterministic: true,
        state: 'INPUT_REJECTED',
        generated_at: DETERMINISTIC_EPOCH_ISO,
        global_status: 'FAIL',
        global_reason_code: 'COMPILER_INPUT_UNKNOWN_FRAMEWORK',
      },
      failure: {
        reason_code: 'COMPILER_INPUT_UNKNOWN_FRAMEWORK',
        reason: `Unknown compliance framework: ${framework}`,
      },
    };
  }

  return compileAuthoritativeComplianceWave1(compilerInput) as unknown as Record<string, unknown>;
}
