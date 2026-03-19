/* eslint-disable */

// AUTO-GENERATED FILE. DO NOT EDIT.
// Source schema:
//   packages/schema/bounties/task_spec.v1.json

export type RequiredProofTier = 'self' | 'gateway' | 'sandbox';

export type TaskDeliverable = 'pr' | 'proof_bundle' | 'did_signature';

export interface TaskSpecValidationV1 {
  commands: string[];
  timeout_seconds: number;
}

export interface TaskSpecConstraintsV1 {
  max_files_changed: number;
  forbidden_patterns: string[];
  required_proof_tier: RequiredProofTier;
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
