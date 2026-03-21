/* eslint-disable */

// AUTO-GENERATED FILE. DO NOT EDIT.
// Source schema:
//   packages/schema/bounties/task_spec.v1.json

export type RequiredProofTier = 'self' | 'gateway' | 'sandbox';

export type TaskDeliverable = 'pr' | 'proof_bundle' | 'did_signature';

export type AssuranceRequiredLevel = 'none' | 'gateway' | 'sandbox';

export type AssurancePrivacyPosture = 'good' | 'caution' | 'action';

export type AssuranceApprovalPolicy = 'none' | 'human_approval_receipt';

export interface AssuranceRequirementsV1 {
  version: '1';
  required_assurance_level?: AssuranceRequiredLevel;
  required_privacy_posture?: AssurancePrivacyPosture;
  required_processors?: string[];
  approval_policy?: AssuranceApprovalPolicy;
}

export interface TaskSpecValidationV1 {
  commands: string[];
  timeout_seconds: number;
}

export interface TaskSpecConstraintsV1 {
  max_files_changed: number;
  forbidden_patterns: string[];
  required_proof_tier: RequiredProofTier;
  assurance_requirements?: AssuranceRequirementsV1;
}

export interface TaskSpecV1 {
  version: '1';
  objective: string;
  repo: string;
  base_ref: string;
  files_hint: string[];
  validation: TaskSpecValidationV1;
  constraints: TaskSpecConstraintsV1;
  deliverables: TaskDeliverable[];
}
