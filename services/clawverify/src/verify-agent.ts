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
  ProofTier,
  ModelIdentityTier,
  VerifyAgentRequest,
  VerifyAgentResponse,
  DidRotationCertificate,
  ExecutionAttestationPayload,
} from './types';
import { isValidDidFormat } from './schema-registry';
import { verifyOwnerAttestation } from './verify-owner-attestation';
import { verifyProofBundle } from './verify-proof-bundle';
import { verifyExecutionAttestation } from './verify-execution-attestation';
import { verifyDidRotation } from './verify-did-rotation';

export interface VerifyAgentOptions {
  /** Allowlisted gateway receipt signer DIDs (did:key:...). */
  allowlistedReceiptSignerDids?: readonly string[];

  /** Allowlisted attester DIDs for proof bundle attestations. */
  allowlistedAttesterDids?: readonly string[];

  /** Allowlisted signer DIDs for execution attestations (CEA-US-010). */
  allowlistedExecutionAttesterDids?: readonly string[];
}

function proofTierToPoHTier(proofTier: ProofTier): number {
  switch (proofTier) {
    case 'unknown':
      return 0;
    case 'self':
      return 1;
    case 'gateway':
      return 2;
    case 'sandbox':
      return 3;
    case 'tee':
      return 4;
    case 'witnessed_web':
      return 5;
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

const DID_ROTATION_CERT_LIMIT = 20;

type DidRotationMap = Map<string, string>;

function buildDidRotationMapStrict(
  certs: readonly DidRotationCertificate[]
): { map: DidRotationMap; error?: string } {
  const map: DidRotationMap = new Map();
  const incoming = new Map<string, string>();

  // Fail-closed: disallow ambiguous/branching rotation sets.
  // - Each old_did may rotate to exactly one new_did.
  // - Each new_did may have at most one incoming edge.
  for (const cert of certs) {
    if (map.has(cert.old_did)) {
      return {
        map,
        error: `Ambiguous rotation: old_did appears more than once (${cert.old_did})`,
      };
    }

    if (incoming.has(cert.new_did)) {
      return {
        map,
        error: `Ambiguous rotation: new_did has multiple incoming edges (${cert.new_did})`,
      };
    }

    map.set(cert.old_did, cert.new_did);
    incoming.set(cert.new_did, cert.old_did);
  }

  // Fail-closed: disallow cycles (prevents "rotate backwards" sets like A→B and B→A).
  for (const start of map.keys()) {
    const visiting = new Set<string>();
    let current = start;
    while (map.has(current)) {
      if (visiting.has(current)) {
        return {
          map,
          error: 'Ambiguous rotation: rotation certificates contain a cycle',
        };
      }
      visiting.add(current);
      current = map.get(current)!;
    }
  }

  return { map };
}

function canRotateDidTo(
  fromDid: string,
  toDid: string,
  map: DidRotationMap | null
): boolean {
  if (fromDid === toDid) return true;
  if (!map) return false;

  // Functional graph: follow the chain from `fromDid` forward.
  const visited = new Set<string>();
  let current = fromDid;

  // Bound traversal by the max cert count to avoid pathological chains.
  for (let steps = 0; steps < DID_ROTATION_CERT_LIMIT + 1; steps++) {
    if (visited.has(current)) return false;
    visited.add(current);

    const next = map.get(current);
    if (!next) return false;
    if (next === toDid) return true;

    current = next;
  }

  return false;
}

export async function verifyAgent(
  body: unknown,
  options: VerifyAgentOptions = {}
): Promise<VerifyAgentResponse> {
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
      proof_tier: 'unknown',
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
      proof_tier: 'unknown',
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
  let proofTier: ProofTier = 'unknown';
  let modelIdentityTier: ModelIdentityTier | undefined;
  let policyCompliance: PolicyComplianceResult | undefined;

  const components: VerifyAgentResponse['components'] = {};

  // Optional DID rotation certificates (fail-closed if provided)
  let didRotationMap: DidRotationMap | null = null;

  if (req.did_rotation_certificates !== undefined) {
    if (!Array.isArray(req.did_rotation_certificates)) {
      return {
        result: {
          status: 'INVALID',
          reason: 'did_rotation_certificates must be an array when provided',
          verified_at: now,
        },
        agent_did: agentDid,
        did_valid: didValid,
        owner_status: ownerStatus,
        trust_tier: trustTier,
        proof_tier: proofTier,
        poh_tier: proofTierToPoHTier(proofTier),
        components,
        risk_flags: [...riskFlags, 'DID_ROTATION_CERTS_MALFORMED'],
        error: {
          code: 'MALFORMED_ENVELOPE',
          message: 'did_rotation_certificates must be an array',
          field: 'did_rotation_certificates',
        },
      };
    }

    if (req.did_rotation_certificates.length > DID_ROTATION_CERT_LIMIT) {
      return {
        result: {
          status: 'INVALID',
          reason: `Too many did_rotation_certificates (max ${DID_ROTATION_CERT_LIMIT})`,
          verified_at: now,
        },
        agent_did: agentDid,
        did_valid: didValid,
        owner_status: ownerStatus,
        trust_tier: trustTier,
        proof_tier: proofTier,
        poh_tier: proofTierToPoHTier(proofTier),
        components,
        risk_flags: [...riskFlags, 'DID_ROTATION_CERTS_TOO_MANY'],
        error: {
          code: 'MALFORMED_ENVELOPE',
          message: `did_rotation_certificates length exceeds limit (${DID_ROTATION_CERT_LIMIT})`,
          field: 'did_rotation_certificates',
        },
      };
    }

    for (let i = 0; i < req.did_rotation_certificates.length; i++) {
      const cert = req.did_rotation_certificates[i];
      const rotationVerification = await verifyDidRotation(cert);

      if (rotationVerification.result.status !== 'VALID') {
        return {
          result: {
            status: 'INVALID',
            reason: 'DID rotation certificate verification failed',
            verified_at: now,
          },
          agent_did: agentDid,
          did_valid: didValid,
          owner_status: ownerStatus,
          trust_tier: trustTier,
          proof_tier: proofTier,
          poh_tier: proofTierToPoHTier(proofTier),
          components,
          risk_flags: [...riskFlags, 'DID_ROTATION_CERT_INVALID'],
          error:
            rotationVerification.error ??
            ({
              code: 'SIGNATURE_INVALID',
              message: 'Rotation certificate verification failed',
              field: `did_rotation_certificates[${i}]`,
            } as const),
        };
      }
    }

    const built = buildDidRotationMapStrict(
      req.did_rotation_certificates as DidRotationCertificate[]
    );

    if (built.error) {
      return {
        result: {
          status: 'INVALID',
          reason: built.error,
          verified_at: now,
        },
        agent_did: agentDid,
        did_valid: didValid,
        owner_status: ownerStatus,
        trust_tier: trustTier,
        proof_tier: proofTier,
        poh_tier: proofTierToPoHTier(proofTier),
        components,
        risk_flags: [...riskFlags, 'DID_ROTATION_CERTS_AMBIGUOUS'],
        error: {
          code: 'MALFORMED_ENVELOPE',
          message: built.error,
          field: 'did_rotation_certificates',
        },
      };
    }

    didRotationMap = built.map;
  }

  // Verify owner attestation if provided
  if (req.owner_attestation_envelope !== undefined) {
    const ownerVerification = await verifyOwnerAttestation(req.owner_attestation_envelope);
    components.owner_attestation = {
      result: ownerVerification.result,
      owner_status: ownerVerification.owner_status,
      error: ownerVerification.error,
    };

    ownerStatus = ownerVerification.owner_status ?? 'unknown';

    // Ensure the owner attestation is for the requested agent DID (or rotates to it)
    if (
      ownerVerification.subject_did &&
      ownerVerification.subject_did !== agentDid
    ) {
      const canRotate = canRotateDidTo(
        ownerVerification.subject_did,
        agentDid,
        didRotationMap
      );

      if (!canRotate) {
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
          proof_tier: proofTier,
          poh_tier: proofTierToPoHTier(proofTier),
          components,
          risk_flags: [...riskFlags, 'OWNER_ATTESTATION_SUBJECT_MISMATCH'],
          error: {
            code: 'INVALID_DID_FORMAT',
            message: 'owner_attestation.subject_did does not match requested agent_did',
            field: 'owner_attestation_envelope.payload.subject_did',
          },
        };
      }

      riskFlags.push('OWNER_ATTESTATION_SUBJECT_ROTATED');
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
        proof_tier: proofTier,
        poh_tier: proofTierToPoHTier(proofTier),
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
    const bundleVerification = await verifyProofBundle(req.proof_bundle_envelope, {
      allowlistedReceiptSignerDids: options.allowlistedReceiptSignerDids,
      allowlistedAttesterDids: options.allowlistedAttesterDids,
      urm: req.urm,
    });

    components.proof_bundle = {
      status: bundleVerification.result.status,
      reason: bundleVerification.result.reason,
      trust_tier: bundleVerification.result.trust_tier,
      proof_tier: bundleVerification.result.proof_tier,
      model_identity_tier: bundleVerification.result.model_identity_tier,
      error: bundleVerification.error,
    };

    trustTier = bundleVerification.result.trust_tier ?? 'unknown';
    proofTier = bundleVerification.result.proof_tier ?? 'unknown';
    modelIdentityTier = bundleVerification.result.model_identity_tier;

    // Merge proof-bundle risk flags into the top-level risk vector.
    if (Array.isArray(bundleVerification.result.risk_flags)) {
      for (const f of bundleVerification.result.risk_flags) {
        if (typeof f === 'string' && f.length > 0 && !riskFlags.includes(f)) {
          riskFlags.push(f);
        }
      }
    }

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
        proof_tier: proofTier,
        poh_tier: proofTierToPoHTier(proofTier),
        components,
        risk_flags: riskFlags,
        error: bundleVerification.error,
      };
    }

    // Subject binding: bundle must be for the requested agent
    proofBundleEnvelope = req.proof_bundle_envelope as SignedEnvelope<ProofBundlePayload>;
    if (proofBundleEnvelope?.payload?.agent_did && proofBundleEnvelope.payload.agent_did !== agentDid) {
      const canRotate = canRotateDidTo(
        proofBundleEnvelope.payload.agent_did,
        agentDid,
        didRotationMap
      );

      if (!canRotate) {
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
          proof_tier: proofTier,
          poh_tier: proofTierToPoHTier(proofTier),
          components,
          risk_flags: riskFlags,
          error: {
            code: 'INVALID_DID_FORMAT',
            message: 'proof_bundle.agent_did does not match requested agent_did',
            field: 'proof_bundle_envelope.payload.agent_did',
          },
        };
      }

      riskFlags.push('PROOF_BUNDLE_AGENT_ROTATED');
    }
  } else {
    riskFlags.push('MISSING_PROOF_BUNDLE');
  }

  // Verify execution attestations if provided (CEA-US-010)
  if (req.execution_attestations !== undefined) {
    if (!Array.isArray(req.execution_attestations)) {
      components.execution_attestation = {
        status: 'INVALID',
        reason: 'execution_attestations must be an array when provided',
      };

      return {
        result: {
          status: 'INVALID',
          reason: 'execution_attestations must be an array when provided',
          verified_at: now,
        },
        agent_did: agentDid,
        did_valid: didValid,
        owner_status: ownerStatus,
        trust_tier: trustTier,
        proof_tier: proofTier,
        poh_tier: proofTierToPoHTier(proofTier),
        components,
        risk_flags: [...riskFlags, 'EXECUTION_ATTESTATIONS_MALFORMED'],
        error: {
          code: 'MALFORMED_ENVELOPE',
          message: 'execution_attestations must be an array',
          field: 'execution_attestations',
        },
      };
    }

    if (req.execution_attestations.length === 0) {
      components.execution_attestation = {
        status: 'INVALID',
        reason: 'execution_attestations must be non-empty when provided',
      };

      return {
        result: {
          status: 'INVALID',
          reason: 'execution_attestations must be non-empty when provided',
          verified_at: now,
        },
        agent_did: agentDid,
        did_valid: didValid,
        owner_status: ownerStatus,
        trust_tier: trustTier,
        proof_tier: proofTier,
        poh_tier: proofTierToPoHTier(proofTier),
        components,
        risk_flags: [...riskFlags, 'EXECUTION_ATTESTATIONS_EMPTY'],
        error: {
          code: 'MISSING_REQUIRED_FIELD',
          message: 'execution_attestations was provided but empty',
          field: 'execution_attestations',
        },
      };
    }

    if (!proofBundleEnvelope) {
      components.execution_attestation = {
        status: 'INVALID',
        reason: 'execution_attestations requires proof_bundle_envelope for binding',
      };

      return {
        result: {
          status: 'INVALID',
          reason: 'execution_attestations requires proof_bundle_envelope for binding',
          verified_at: now,
        },
        agent_did: agentDid,
        did_valid: didValid,
        owner_status: ownerStatus,
        trust_tier: trustTier,
        proof_tier: proofTier,
        poh_tier: proofTierToPoHTier(proofTier),
        components,
        risk_flags: [...riskFlags, 'EXECUTION_ATTESTATION_MISSING_BUNDLE'],
        error: {
          code: 'MISSING_REQUIRED_FIELD',
          message:
            'execution_attestations was provided but proof_bundle_envelope was not provided (required for binding)',
          field: 'proof_bundle_envelope',
        },
      };
    }

    const expectedBundleHash = proofBundleEnvelope.payload_hash_b64u;

    const expectedRunId =
      typeof req.urm?.run_id === 'string'
        ? req.urm.run_id
        : Array.isArray(proofBundleEnvelope.payload?.event_chain) &&
            proofBundleEnvelope.payload.event_chain.length > 0 &&
            typeof proofBundleEnvelope.payload.event_chain[0]?.run_id === 'string'
          ? proofBundleEnvelope.payload.event_chain[0].run_id
          : null;

    if (!expectedRunId) {
      components.execution_attestation = {
        status: 'INVALID',
        reason:
          'execution_attestations binding requires run_id (via urm.run_id or proof_bundle.event_chain[0].run_id)',
      };

      return {
        result: {
          status: 'INVALID',
          reason:
            'execution_attestations binding requires run_id (via urm.run_id or proof_bundle.event_chain[0].run_id)',
          verified_at: now,
        },
        agent_did: agentDid,
        did_valid: didValid,
        owner_status: ownerStatus,
        trust_tier: trustTier,
        proof_tier: proofTier,
        poh_tier: proofTierToPoHTier(proofTier),
        components,
        risk_flags: [...riskFlags, 'EXECUTION_ATTESTATION_MISSING_RUN_ID'],
        error: {
          code: 'MISSING_REQUIRED_FIELD',
          message:
            'run_id is required to bind execution attestations to the proof bundle',
        },
      };
    }

    let verifiedCount = 0;
    let bestTier: ProofTier = 'sandbox';

    for (let i = 0; i < req.execution_attestations.length; i++) {
      const attEnv = req.execution_attestations[i] as SignedEnvelope<ExecutionAttestationPayload>;
      const attV = await verifyExecutionAttestation(attEnv, {
        allowlistedSignerDids: options.allowlistedExecutionAttesterDids,
      });

      if (attV.result.status !== 'VALID') {
        components.execution_attestation = {
          status: 'INVALID',
          reason: `execution_attestation verification failed (index ${i})`,
          error: attV.error,
        };

        return {
          result: {
            status: 'INVALID',
            reason: 'Execution attestation verification failed',
            verified_at: now,
          },
          agent_did: agentDid,
          did_valid: didValid,
          owner_status: ownerStatus,
          trust_tier: trustTier,
          proof_tier: proofTier,
          poh_tier: proofTierToPoHTier(proofTier),
          components,
          risk_flags: [...riskFlags, 'EXECUTION_ATTESTATION_INVALID'],
          error:
            attV.error ??
            ({
              code: 'SIGNATURE_INVALID',
              message: 'Execution attestation verification failed',
              field: `execution_attestations[${i}]`,
            } as const),
        };
      }

      // Binding checks (fail-closed)
      if (attV.agent_did && attV.agent_did !== agentDid) {
        const canRotate = canRotateDidTo(attV.agent_did, agentDid, didRotationMap);
        if (!canRotate) {
          components.execution_attestation = {
            status: 'INVALID',
            reason: 'execution_attestation.agent_did does not match agent_did',
          };

          return {
            result: {
              status: 'INVALID',
              reason: 'execution_attestation.agent_did does not match agent_did',
              verified_at: now,
            },
            agent_did: agentDid,
            did_valid: didValid,
            owner_status: ownerStatus,
            trust_tier: trustTier,
            proof_tier: proofTier,
            poh_tier: proofTierToPoHTier(proofTier),
            components,
            risk_flags: [...riskFlags, 'EXECUTION_ATTESTATION_AGENT_MISMATCH'],
            error: {
              code: 'HASH_MISMATCH',
              message: 'execution_attestation.agent_did mismatch',
              field: `execution_attestations[${i}].payload.agent_did`,
            },
          };
        }

        riskFlags.push('EXECUTION_ATTESTATION_AGENT_ROTATED');
      }

      if (attV.run_id !== expectedRunId) {
        components.execution_attestation = {
          status: 'INVALID',
          reason: 'execution_attestation.run_id does not match proof bundle run_id',
        };

        return {
          result: {
            status: 'INVALID',
            reason: 'execution_attestation.run_id does not match proof bundle run_id',
            verified_at: now,
          },
          agent_did: agentDid,
          did_valid: didValid,
          owner_status: ownerStatus,
          trust_tier: trustTier,
          proof_tier: proofTier,
          poh_tier: proofTierToPoHTier(proofTier),
          components,
          risk_flags: [...riskFlags, 'EXECUTION_ATTESTATION_RUN_ID_MISMATCH'],
          error: {
            code: 'HASH_MISMATCH',
            message: 'execution_attestation.run_id mismatch',
            field: `execution_attestations[${i}].payload.run_id`,
          },
        };
      }

      if (attV.proof_bundle_hash_b64u !== expectedBundleHash) {
        components.execution_attestation = {
          status: 'INVALID',
          reason:
            'execution_attestation.proof_bundle_hash_b64u does not match proof bundle payload hash',
        };

        return {
          result: {
            status: 'INVALID',
            reason:
              'execution_attestation.proof_bundle_hash_b64u does not match proof bundle payload hash',
            verified_at: now,
          },
          agent_did: agentDid,
          did_valid: didValid,
          owner_status: ownerStatus,
          trust_tier: trustTier,
          proof_tier: proofTier,
          poh_tier: proofTierToPoHTier(proofTier),
          components,
          risk_flags: [...riskFlags, 'EXECUTION_ATTESTATION_BUNDLE_HASH_MISMATCH'],
          error: {
            code: 'HASH_MISMATCH',
            message: 'execution_attestation.proof_bundle_hash_b64u mismatch',
            field: `execution_attestations[${i}].payload.proof_bundle_hash_b64u`,
          },
        };
      }

      verifiedCount++;
      if (attV.execution_type === 'tee_execution') bestTier = 'tee';
    }

    const tierRank: Record<ProofTier, number> = {
      unknown: 0,
      self: 1,
      gateway: 2,
      sandbox: 3,
      tee: 4,
      witnessed_web: 5,
    };

    if (tierRank[bestTier] > (tierRank[proofTier] ?? 0)) {
      proofTier = bestTier;
    }

    components.execution_attestation = {
      status: 'VALID',
      reason: `Verified ${verifiedCount} execution attestations`,
      verified_count: verifiedCount,
      proof_tier: bestTier,
    };

    riskFlags.push('EXECUTION_ATTESTATION_VERIFIED');
  }

  // Compute PoH tier (canonical numeric mapping of proof_tier)
  const pohTier = proofTierToPoHTier(proofTier);
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
        proof_tier: proofTier,
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
        proof_tier: proofTier,
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
      proof_tier: proofTier,
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
    proof_tier: proofTier,
    poh_tier: pohTier,
    model_identity_tier: modelIdentityTier,
    policy_compliance: policyCompliance,
    components,
    risk_flags: riskFlags.length > 0 ? riskFlags : undefined,
  };
}
