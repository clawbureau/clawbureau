/**
 * One-call agent verification
 * CVF-US-012
 *
 * Provides a single endpoint that can return:
 * - DID validity
 * - owner status (from owner attestation)
 * - PoH tier (from proof bundle trust tier)
 * - policy compliance (optional, if policy_hash present)
 */

import type {
  OwnerAttestationStatus,
  PolicyComplianceResult,
  ProofBundlePayload,
  SignedEnvelope,
  TrustTier,
  VerifyAgentRequest,
  VerifyAgentResponse,
} from './types';
import { isValidDidFormat } from './schema-registry';
import { verifyOwnerAttestation } from './verify-owner-attestation';
import { verifyProofBundle } from './verify-proof-bundle';

function trustTierToPoHTier(trustTier: TrustTier): number {
  switch (trustTier) {
    case 'unknown':
      return 0;
    case 'basic':
      return 1;
    case 'verified':
      return 2;
    case 'attested':
      return 3;
    case 'full':
      return 4;
  }
}

function getPolicyHashFromMetadata(metadata: unknown): string | null {
  if (!metadata || typeof metadata !== 'object') return null;
  const m = metadata as Record<string, unknown>;

  const candidates = [m.policy_hash, m.policyHash, m.wpc_policy_hash, m.policy];
  for (const c of candidates) {
    if (typeof c === 'string' && c.trim().length > 0) return c;
  }

  return null;
}

function computePolicyCompliance(
  policyHash: string,
  bundleEnvelope: SignedEnvelope<ProofBundlePayload>
): PolicyComplianceResult {
  const receipts = bundleEnvelope.payload.receipts;

  if (!Array.isArray(receipts) || receipts.length === 0) {
    return {
      policy_hash: policyHash,
      compliant: false,
      reason: 'policy_hash provided but proof bundle contains no receipts to evaluate',
    };
  }

  const observed: string[] = [];

  for (const receipt of receipts) {
    const receiptPolicy = getPolicyHashFromMetadata(receipt.payload?.metadata);
    if (!receiptPolicy) {
      return {
        policy_hash: policyHash,
        compliant: false,
        reason: 'At least one receipt is missing metadata.policy_hash (required when policy_hash is provided)',
      };
    }
    observed.push(receiptPolicy);
    if (receiptPolicy !== policyHash) {
      return {
        policy_hash: policyHash,
        compliant: false,
        reason: `Receipt policy_hash mismatch (expected ${policyHash}, got ${receiptPolicy})`,
      };
    }
  }

  return {
    policy_hash: policyHash,
    compliant: true,
    reason: `All ${observed.length} receipts match policy_hash`,
  };
}

export async function verifyAgent(body: unknown): Promise<VerifyAgentResponse> {
  const now = new Date().toISOString();

  // Basic request validation
  if (!body || typeof body !== 'object') {
    return {
      result: {
        status: 'INVALID',
        reason: 'Request must be an object',
        verified_at: now,
      },
      agent_did: '',
      did_valid: false,
      owner_status: 'unknown',
      trust_tier: 'unknown',
      poh_tier: 0,
      error: {
        code: 'PARSE_ERROR',
        message: 'Request must be an object',
      },
    };
  }

  const req = body as Partial<VerifyAgentRequest>;

  if (typeof req.agent_did !== 'string' || req.agent_did.trim().length === 0) {
    return {
      result: {
        status: 'INVALID',
        reason: 'agent_did is required',
        verified_at: now,
      },
      agent_did: '',
      did_valid: false,
      owner_status: 'unknown',
      trust_tier: 'unknown',
      poh_tier: 0,
      error: {
        code: 'MISSING_REQUIRED_FIELD',
        message: 'agent_did is required and must be a non-empty string',
        field: 'agent_did',
      },
    };
  }

  const agentDid = req.agent_did;
  const didValid = isValidDidFormat(agentDid);

  const riskFlags: string[] = [];
  if (!didValid) {
    riskFlags.push('INVALID_DID');
  }

  // Default semantic values
  let ownerStatus: OwnerAttestationStatus = 'unknown';
  let trustTier: TrustTier = 'unknown';
  let policyCompliance: PolicyComplianceResult | undefined;

  const components: VerifyAgentResponse['components'] = {};

  // Verify owner attestation if provided
  if (req.owner_attestation_envelope !== undefined) {
    const ownerVerification = await verifyOwnerAttestation(req.owner_attestation_envelope);
    components.owner_attestation = {
      result: ownerVerification.result,
      owner_status: ownerVerification.owner_status,
      error: ownerVerification.error,
    };

    ownerStatus = ownerVerification.owner_status ?? 'unknown';

    // Ensure the owner attestation is for the requested agent DID
    if (
      ownerVerification.subject_did &&
      ownerVerification.subject_did !== agentDid
    ) {
      return {
        result: {
          status: 'INVALID',
          reason: 'Owner attestation subject_did does not match agent_did',
          verified_at: now,
        },
        agent_did: agentDid,
        did_valid: didValid,
        owner_status: ownerStatus,
        trust_tier: trustTier,
        poh_tier: trustTierToPoHTier(trustTier),
        components,
        risk_flags: [...riskFlags, 'OWNER_ATTESTATION_SUBJECT_MISMATCH'],
        error: {
          code: 'INVALID_DID_FORMAT',
          message: 'owner_attestation.subject_did does not match requested agent_did',
          field: 'owner_attestation_envelope.payload.subject_did',
        },
      };
    }

    if (ownerVerification.result.status !== 'VALID') {
      // Fail closed: if caller provided an attestation, it must verify
      riskFlags.push('OWNER_ATTESTATION_INVALID');
      if (ownerStatus === 'expired') riskFlags.push('OWNER_ATTESTATION_EXPIRED');

      return {
        result: {
          status: 'INVALID',
          reason: 'Owner attestation verification failed',
          verified_at: now,
        },
        agent_did: agentDid,
        did_valid: didValid,
        owner_status: ownerStatus,
        trust_tier: trustTier,
        poh_tier: trustTierToPoHTier(trustTier),
        components,
        risk_flags: riskFlags,
        error: ownerVerification.error,
      };
    }

    if (ownerStatus !== 'verified') {
      riskFlags.push('OWNER_NOT_VERIFIED');
    }
  } else {
    riskFlags.push('MISSING_OWNER_ATTESTATION');
  }

  // Verify proof bundle if provided
  let proofBundleEnvelope: SignedEnvelope<ProofBundlePayload> | undefined;

  if (req.proof_bundle_envelope !== undefined) {
    const bundleVerification = await verifyProofBundle(req.proof_bundle_envelope);

    components.proof_bundle = {
      status: bundleVerification.result.status,
      reason: bundleVerification.result.reason,
      trust_tier: bundleVerification.result.trust_tier,
      error: bundleVerification.error,
    };

    trustTier = bundleVerification.result.trust_tier ?? 'unknown';

    // Fail closed: if caller provided a bundle, it must verify
    if (bundleVerification.result.status !== 'VALID') {
      riskFlags.push('PROOF_BUNDLE_INVALID');
      return {
        result: {
          status: 'INVALID',
          reason: 'Proof bundle verification failed',
          verified_at: now,
        },
        agent_did: agentDid,
        did_valid: didValid,
        owner_status: ownerStatus,
        trust_tier: trustTier,
        poh_tier: trustTierToPoHTier(trustTier),
        components,
        risk_flags: riskFlags,
        error: bundleVerification.error,
      };
    }

    // Subject binding: bundle must be for the requested agent
    proofBundleEnvelope = req.proof_bundle_envelope as SignedEnvelope<ProofBundlePayload>;
    if (proofBundleEnvelope?.payload?.agent_did && proofBundleEnvelope.payload.agent_did !== agentDid) {
      riskFlags.push('PROOF_BUNDLE_AGENT_MISMATCH');
      return {
        result: {
          status: 'INVALID',
          reason: 'Proof bundle agent_did does not match agent_did',
          verified_at: now,
        },
        agent_did: agentDid,
        did_valid: didValid,
        owner_status: ownerStatus,
        trust_tier: trustTier,
        poh_tier: trustTierToPoHTier(trustTier),
        components,
        risk_flags: riskFlags,
        error: {
          code: 'INVALID_DID_FORMAT',
          message: 'proof_bundle.agent_did does not match requested agent_did',
          field: 'proof_bundle_envelope.payload.agent_did',
        },
      };
    }
  } else {
    riskFlags.push('MISSING_PROOF_BUNDLE');
  }

  // Compute PoH tier
  const pohTier = trustTierToPoHTier(trustTier);
  if (pohTier < 2) {
    riskFlags.push('LOW_POH_TIER');
  }

  // Policy compliance (optional)
  if (typeof req.policy_hash === 'string' && req.policy_hash.trim().length > 0) {
    if (!proofBundleEnvelope) {
      policyCompliance = {
        policy_hash: req.policy_hash,
        compliant: false,
        reason: 'policy_hash provided but proof_bundle_envelope not provided',
      };

      return {
        result: {
          status: 'INVALID',
          reason: policyCompliance.reason,
          verified_at: now,
        },
        agent_did: agentDid,
        did_valid: didValid,
        owner_status: ownerStatus,
        trust_tier: trustTier,
        poh_tier: pohTier,
        policy_compliance: policyCompliance,
        components,
        risk_flags: [...riskFlags, 'POLICY_NONCOMPLIANT'],
        error: {
          code: 'MISSING_REQUIRED_FIELD',
          message: 'policy_hash was provided but proof_bundle_envelope is required to evaluate policy compliance',
          field: 'proof_bundle_envelope',
        },
      };
    }

    policyCompliance = computePolicyCompliance(req.policy_hash, proofBundleEnvelope);
    if (!policyCompliance.compliant) {
      return {
        result: {
          status: 'INVALID',
          reason: policyCompliance.reason,
          verified_at: now,
        },
        agent_did: agentDid,
        did_valid: didValid,
        owner_status: ownerStatus,
        trust_tier: trustTier,
        poh_tier: pohTier,
        policy_compliance: policyCompliance,
        components,
        risk_flags: [...riskFlags, 'POLICY_NONCOMPLIANT'],
        error: {
          code: 'SIGNATURE_INVALID',
          message: 'Policy compliance check failed',
        },
      };
    }
  }

  // DID validity is required for a valid response
  if (!didValid) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Invalid agent DID format',
        verified_at: now,
      },
      agent_did: agentDid,
      did_valid: didValid,
      owner_status: ownerStatus,
      trust_tier: trustTier,
      poh_tier: pohTier,
      policy_compliance: policyCompliance,
      components,
      risk_flags: riskFlags,
      error: {
        code: 'INVALID_DID_FORMAT',
        message: 'agent_did does not match expected format (did:key:... or did:web:...)',
        field: 'agent_did',
      },
    };
  }

  return {
    result: {
      status: 'VALID',
      reason: 'Agent verification completed',
      verified_at: now,
      signer_did: agentDid,
    },
    agent_did: agentDid,
    did_valid: didValid,
    owner_status: ownerStatus,
    trust_tier: trustTier,
    poh_tier: pohTier,
    policy_compliance: policyCompliance,
    components,
    risk_flags: riskFlags.length > 0 ? riskFlags : undefined,
  };
}
