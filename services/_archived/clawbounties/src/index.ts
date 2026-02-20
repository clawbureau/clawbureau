/**
 * clawbounties.com worker
 *
 * - Public discovery endpoints (landing/docs/skill/health/robots/sitemap/security)
 * - Scoped requester-token + worker-token marketplace API (schema v2 aligned)
 */

import { bountyUiDuelPage } from './ui-duel-page.js';

export interface Env {
  ENVIRONMENT?: string;
  BOUNTIES_VERSION?: string;

  /** Admin key for /v1 endpoints. Set via `wrangler secret put`. */
  BOUNTIES_ADMIN_KEY?: string;

  /** Dedicated risk service key for loss-event intake endpoint. */
  BOUNTIES_RISK_KEY?: string;

  /** Escrow service key (ESCROW_ADMIN_KEY from clawescrow). Set via `wrangler secret put`. */
  ESCROW_SERVICE_KEY?: string;

  /** Base URL for clawcuts (defaults to https://clawcuts.com). */
  CUTS_BASE_URL?: string;

  /** Base URL for clawescrow (defaults to https://clawescrow.com). */
  ESCROW_BASE_URL?: string;

  /** Base URL for clawverify (defaults to https://clawverify.com). */
  VERIFY_BASE_URL?: string;

  /** Base URL for clawscope (defaults to https://clawscope.com). */
  SCOPE_BASE_URL?: string;

  /** Base URL for clawrep (defaults to https://clawrep.com). */
  CLAWREP_BASE_URL?: string;

  /** Ingest key for clawrep loop endpoint (set via `wrangler secret put`). */
  CLAWREP_INGEST_KEY?: string;

  /** Admin key for calling clawscope /v1/tokens/issue (set via `wrangler secret put`). */
  SCOPE_ADMIN_KEY?: string;

  /** Base URL for test harness service (required for closure_type=test auto-approval). */
  TEST_HARNESS_BASE_URL?: string;

  /** Base URL for dispute arbitration service. */
  TRIALS_BASE_URL?: string;

  /** Service token for clawtrials arbitration APIs. */
  TRIALS_SERVICE_KEY?: string;

  /** Test harness timeout override in milliseconds. */
  TEST_HARNESS_TIMEOUT_MS?: string;

  /** Worker auth token TTL in seconds for /v1/workers/register (defaults to 86400). */
  WORKER_TOKEN_TTL_SECONDS?: string;

  /** Compatibility path: allow admin + x-requester-did requester auth (disabled by default). */
  REQUESTER_AUTH_COMPAT_LEGACY?: string;

  /** Required audience for requester scoped tokens (defaults to clawbounties.com). */
  REQUESTER_AUTH_REQUIRED_AUDIENCE?: string;

  /** Timeout in ms for requester token introspection (defaults to 5000). */
  REQUESTER_AUTH_TIMEOUT_MS?: string;

  /** Compatibility path: allow local worker DB tokens (disabled by default). */
  WORKER_AUTH_COMPAT_LEGACY?: string;

  /** Required audience for worker scoped tokens (defaults to requester audience). */
  WORKER_AUTH_REQUIRED_AUDIENCE?: string;

  /** Timeout in ms for worker token introspection (defaults to requester timeout). */
  WORKER_AUTH_TIMEOUT_MS?: string;

  /** D1 database binding */
  BOUNTIES_DB: D1Database;

  /** Optional direct queue producer binding to clawrep events. */
  REP_EVENTS?: Queue;
}

type ClosureType = 'test' | 'requester' | 'quorum';
type BountyStatus = 'open' | 'accepted' | 'pending_review' | 'approved' | 'rejected' | 'disputed' | 'cancelled';
type BountyArenaStatus = 'idle' | 'started' | 'completed' | 'failed';
type ProofTier = 'self' | 'gateway' | 'sandbox';
type SubmissionStatus = 'pending_review' | 'invalid' | 'approved' | 'rejected';
type VerificationStatus = 'VALID' | 'INVALID';

type RequesterAuthAction = 'post_bounty' | 'approve_bounty' | 'reject_bounty' | 'read_submission';
type RequesterAuthMode = 'scoped_token' | 'legacy_admin_header';
type WorkerAuthAction =
  | 'worker_self'
  | 'accept_bounty'
  | 'submit_bounty'
  | 'issue_bounty_cst'
  | 'read_submission'
  | 'read_trust_pulse'
  | 'reregister_worker';

type ScopedTokenLane = 'legacy' | 'canonical';

interface RequesterAuthContext {
  requester_did: string;
  auth_mode: RequesterAuthMode;
  token_hash: string | null;
  scope: string[];
  aud: string[];
  token_scope_hash_b64u: string | null;
  token_lane: ScopedTokenLane | null;
  payment_account_did: string | null;
  delegation_id: string | null;
  delegator_did: string | null;
  delegate_did: string | null;
  iat: number | null;
  exp: number | null;
  bearer_token: string | null;
}

interface RequesterAuthOverrideOptions {
  authOverride?: RequesterAuthContext;
  controlPlaneCheckOverride?: Record<string, unknown> | null;
}

interface WorkerAuthContext {
  worker_did: string;
  auth_mode: WorkerAuthMode;
  token_hash: string | null;
  scope: string[];
  aud: string[];
  token_scope_hash_b64u: string | null;
  token_lane: ScopedTokenLane | null;
  payment_account_did: string | null;
  agent_did: string | null;
  iat: number | null;
  exp: number | null;
  bearer_token: string | null;
}

interface ScopeIntrospectionSuccess {
  active: true;
  token_hash?: unknown;
  sub?: unknown;
  aud?: unknown;
  scope?: unknown;
  owner_ref?: unknown;
  owner_did?: unknown;
  controller_did?: unknown;
  agent_did?: unknown;
  policy_hash_b64u?: unknown;
  control_plane_policy_hash_b64u?: unknown;
  token_scope_hash_b64u?: unknown;
  payment_account_did?: unknown;
  spend_cap?: unknown;
  mission_id?: unknown;
  delegation_id?: unknown;
  delegator_did?: unknown;
  delegate_did?: unknown;
  delegation_policy_hash_b64u?: unknown;
  delegation_spend_cap_minor?: unknown;
  delegation_expires_at?: unknown;
  token_lane?: unknown;
  iat?: unknown;
  exp?: unknown;
}

interface ScopeIntrospectionInactive {
  active: false;
  revoked?: unknown;
  token_hash?: unknown;
  sub?: unknown;
  aud?: unknown;
  scope?: unknown;
  owner_ref?: unknown;
  owner_did?: unknown;
  controller_did?: unknown;
  agent_did?: unknown;
  policy_hash_b64u?: unknown;
  control_plane_policy_hash_b64u?: unknown;
  token_scope_hash_b64u?: unknown;
  payment_account_did?: unknown;
  spend_cap?: unknown;
  mission_id?: unknown;
  delegation_id?: unknown;
  delegator_did?: unknown;
  delegate_did?: unknown;
  delegation_policy_hash_b64u?: unknown;
  delegation_spend_cap_minor?: unknown;
  delegation_expires_at?: unknown;
  token_lane?: unknown;
  iat?: unknown;
  exp?: unknown;
}

type ScopeIntrospectionResponse = ScopeIntrospectionSuccess | ScopeIntrospectionInactive;

const REQUESTER_AUTH_SCOPE_BY_ACTION: Record<RequesterAuthAction, string> = {
  post_bounty: 'clawbounties:bounty:create',
  approve_bounty: 'clawbounties:bounty:approve',
  reject_bounty: 'clawbounties:bounty:reject',
  read_submission: 'clawbounties:bounty:read',
};

const WORKER_AUTH_SCOPE_BY_ACTION: Record<WorkerAuthAction, string> = {
  worker_self: 'clawbounties:worker:self:read',
  accept_bounty: 'clawbounties:bounty:accept',
  submit_bounty: 'clawbounties:bounty:submit',
  issue_bounty_cst: 'clawbounties:bounty:cst:issue',
  read_submission: 'clawbounties:submission:read',
  read_trust_pulse: 'clawbounties:submission:trust-pulse:read',
  reregister_worker: 'clawbounties:worker:register',
};

type FeePayer = 'buyer' | 'worker';
type FeeSplitKind = 'platform' | 'referral';

interface FeeSplit {
  kind: FeeSplitKind;
  account: string;
  bucket: 'A' | 'F';
  amount_minor: string;
  referrer_did?: string;
  referral_code?: string;
}

interface FeeItem {
  kind: string;
  payer: FeePayer;
  amount_minor: string;
  rate_bps: number;
  min_fee_minor: string;
  floor_applied: boolean;
  base_amount_minor?: string;
  discount_bps_applied?: number;
  discount_minor?: string;
  splits?: FeeSplit[];
}

interface CutsPolicyInfo {
  id: string;
  version: string;
  hash_b64u: string;
}

interface CutsFeeQuote {
  principal_minor: string;
  buyer_total_minor: string;
  worker_net_minor: string;
  fees: FeeItem[];
}

interface CutsSimulateResponse {
  policy: CutsPolicyInfo;
  quote: CutsFeeQuote;
}

interface EscrowFeeQuoteSnapshot {
  policy_id: string;
  policy_version: string;
  policy_hash_b64u: string;
  buyer_total_minor: string;
  worker_net_minor: string;
  fees: FeeItem[];
}

interface RewardV2 {
  amount_minor: string;
  currency: 'USD';
}

interface AllInCostV2 {
  principal_minor: string;
  platform_fee_minor: string;
  total_minor: string;
  currency: 'USD';
}

interface PostBountyResponseV2 {
  schema_version: '2';
  bounty_id: string;
  escrow_id: string;
  status: 'open';
  all_in_cost: AllInCostV2;
  fee_policy_version: string;
  created_at: string;
}

interface BountyV2 {
  schema_version: '2';
  bounty_id: string;
  requester_did: string;
  title: string;
  description: string;
  reward: RewardV2;
  closure_type: ClosureType;
  difficulty_scalar: number;
  escrow_id: string;
  status: BountyStatus;
  created_at: string;

  // acceptance (worker)
  worker_did: string | null;
  accept_idempotency_key: string | null;
  accepted_at: string | null;

  /** Deterministic v1 job-scoped token_scope_hash_b64u for binding receipts to this bounty. */
  job_token_scope_hash_b64u: string | null;

  // Confidential Work Contract (CWC) — direct-hire confidential consulting
  cwc_hash_b64u: string | null;
  cwc_wpc_policy_hash_b64u: string | null;
  cwc_required_proof_tier: ProofTier | null;
  cwc_token_scope_hash_b64u: string | null;
  cwc_buyer_envelope: Record<string, unknown> | null;
  cwc_worker_envelope: Record<string, unknown> | null;

  // requester decision (approve/reject)
  approved_submission_id: string | null;
  approve_idempotency_key: string | null;
  approved_at: string | null;
  rejected_submission_id: string | null;
  reject_idempotency_key: string | null;
  rejected_at: string | null;
  trial_case_id: string | null;
  trial_opened_at: string | null;

  // arena lifecycle (AGP-US-043)
  arena_status: BountyArenaStatus;
  arena_id: string | null;
  arena_task_fingerprint: string | null;
  arena_winner_contender_id: string | null;
  arena_evidence_links: ArenaScoreExplainLink[];
  arena_updated_at: string | null;

  // recommended/common
  is_code_bounty: boolean;
  tags: string[];
  min_proof_tier: ProofTier;
  require_owner_verified_votes: boolean;
  test_harness_id: string | null;
  metadata: Record<string, unknown>;
  idempotency_key: string;

  fee_policy_version: string;
  all_in_cost: AllInCostV2;

  // internal
  fee_quote: CutsSimulateResponse;
  updated_at: string;
}

interface BountyRiskEventRecord {
  risk_event_id: string;
  idempotency_key: string;
  source_loss_event_id: string;
  source_service: string;
  source_event_id: string | null;
  bounty_id: string;
  account_did: string | null;
  amount_minor: string;
  currency: 'USD';
  reason_code: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  metadata_json: string | null;
  created_at: string;
  updated_at: string;
}

interface BountyRiskClearRecord {
  clear_id: string;
  idempotency_key: string;
  source_loss_event_id: string;
  bounty_id: string;
  reason: string | null;
  metadata_json: string | null;
  created_at: string;
  updated_at: string;
}

type ArenaRunStatus = 'started' | 'completed';

interface ArenaCheckResult {
  criterion_id: string;
  required: boolean;
  status: 'PASS' | 'FAIL';
  reason_code: string;
}

interface ArenaScoreExplainLink {
  label: string;
  url: string;
  source?: string;
}

interface ArenaThreadLink {
  label: string;
  url: string;
}

interface ArenaScoreExplain {
  final_score: number;
  reason_codes: string[];
  evidence_links: ArenaScoreExplainLink[];
}

interface ArenaContenderResult {
  contender_id: string;
  label: string;
  model: string;
  harness: string;
  tools: string[];
  skills: string[];
  plugins: string[];
  score: number;
  hard_gate_pass: boolean;
  mandatory_failed: number;
  metrics: {
    quality_score: number;
    risk_score: number;
    efficiency_score: number;
    latency_ms: number;
    cost_usd: number;
    autonomy_score: number;
  };
  check_results: ArenaCheckResult[];
  score_explain: ArenaScoreExplain;
  insights: {
    bottlenecks: string[];
    contract_improvements: string[];
    next_delegation_hints: string[];
  };
  version_pin: string | null;
  prompt_template: string | null;
  experiment_arm: string | null;
  proof_pack: Record<string, unknown> | null;
  manager_review: Record<string, unknown> | null;
  review_paste: string;
}

interface ArenaRunRecord {
  run_id: string;
  arena_id: string;
  bounty_id: string;
  status: ArenaRunStatus;
  contract_id: string;
  contract_hash_b64u: string;
  task_fingerprint: string;
  objective_profile_json: string;
  arena_report_json: string | null;
  winner_contender_id: string | null;
  winner_reason: string | null;
  reason_codes_json: string | null;
  tradeoffs_json: string | null;
  registry_version: string | null;
  experiment_id: string | null;
  experiment_arm: string | null;
  start_idempotency_key: string;
  result_idempotency_key: string | null;
  report_hash_b64u: string | null;
  started_at: string;
  completed_at: string | null;
  created_at: string;
  updated_at: string;
}

interface ArenaRegistrySelection {
  contender_id: string;
  version_pin: string | null;
}

interface ArenaRegistryContext {
  registry_version: string;
  objective_profile_name: string | null;
  selected_contenders: ArenaRegistrySelection[];
}

interface ArenaExperimentContext {
  experiment_id: string;
  arm: string | null;
}

interface ArenaContenderRecord {
  run_id: string;
  contender_id: string;
  label: string;
  model: string;
  harness: string;
  tools_json: string;
  skills_json: string;
  plugins_json: string;
  version_pin: string | null;
  prompt_template: string | null;
  experiment_arm: string | null;
  score: number;
  hard_gate_pass: boolean;
  mandatory_failed: number;
  metrics_json: string;
  check_results_json: string;
  proof_pack_json: string | null;
  manager_review_json: string | null;
  review_paste: string;
  created_at: string;
  updated_at: string;
}

interface ArenaReviewThreadEntry {
  thread_entry_id: string;
  idempotency_key: string;
  bounty_id: string;
  arena_id: string;
  contender_id: string;
  recommendation: 'APPROVE' | 'REQUEST_CHANGES' | 'REJECT';
  confidence: number;
  body_markdown: string;
  links_json: string;
  source: string;
  metadata_json: string | null;
  created_at: string;
  updated_at: string;
}

interface ArenaOutcomeRecord {
  outcome_id: string;
  idempotency_key: string;
  bounty_id: string;
  arena_id: string;
  contender_id: string;
  outcome_status: 'ACCEPTED' | 'OVERRIDDEN' | 'REWORK' | 'REJECTED' | 'DISPUTED';
  accepted: boolean;
  overridden: boolean;
  rework_required: boolean;
  disputed: boolean;
  review_time_minutes: number;
  time_to_accept_minutes: number | null;
  predicted_confidence: number;
  recommendation: 'APPROVE' | 'REQUEST_CHANGES' | 'REJECT';
  reviewer_decision: 'approve' | 'request_changes' | 'reject';
  reviewer_rationale: string | null;
  decision_taxonomy_json: string;
  override_reason_code: string | null;
  notes: string | null;
  source: string;
  metadata_json: string | null;
  created_at: string;
  updated_at: string;
}

interface ArenaContractLanguageSuggestionRecord {
  suggestion_id: string;
  task_fingerprint: string;
  scope: 'global' | 'contender';
  contender_id: string;
  reason_code: ArenaOverrideReasonCode;
  failures: number;
  overrides: number;
  share: number;
  priority_score: number;
  contract_rewrite: string;
  prompt_rewrite: string;
  contract_language_patch: string;
  prompt_language_patch: string;
  sample_notes_json: string;
  tags_json: string;
  computed_at: string;
  created_at: string;
  updated_at: string;
}

interface ArenaContractCopilotSuggestionRecord {
  suggestion_id: string;
  task_fingerprint: string;
  scope: 'global' | 'contender';
  contender_id: string;
  reason_code: ArenaOverrideReasonCode;
  before_text: string;
  after_text: string;
  rationale: string;
  confidence: number;
  expected_override_reduction: number;
  expected_rework_reduction: number;
  evidence_count: number;
  arena_count: number;
  outcome_count: number;
  source_evidence_json: string;
  computed_at: string;
  created_at: string;
  updated_at: string;
}

interface ArenaRoutePolicyOptimizerStateRecord {
  state_id: string;
  task_fingerprint: string;
  environment: string;
  objective_profile_name: string;
  experiment_id: string;
  experiment_arm: string;
  active_policy_json: string | null;
  shadow_policy_json: string;
  last_promotion_event_json: string | null;
  reason_codes_json: string;
  sample_count: number;
  confidence_score: number;
  min_samples: number;
  min_confidence: number;
  promotion_status: 'PROMOTED' | 'NOT_READY';
  created_at: string;
  updated_at: string;
}

type ArenaFleetCostTier = 'low' | 'medium' | 'high';
type ArenaFleetRiskTier = 'low' | 'medium' | 'high';
type ArenaFleetAvailabilityStatus = 'online' | 'offline' | 'paused';

interface ArenaHarnessFleetWorkerRecord {
  worker_did: string;
  harness: string;
  model: string;
  skills_json: string;
  tools_json: string;
  objective_profiles_json: string;
  cost_tier: ArenaFleetCostTier;
  risk_tier: ArenaFleetRiskTier;
  availability_status: ArenaFleetAvailabilityStatus;
  heartbeat_at: string | null;
  heartbeat_seq: number;
  metadata_json: string | null;
  created_at: string;
  updated_at: string;
}

interface ArenaAutoClaimLockRecord {
  bounty_id: string;
  lock_id: string;
  loop_id: string;
  claim_status: 'processing' | 'claimed' | 'skipped' | 'failed';
  worker_did: string | null;
  contender_id: string | null;
  reason_code: string;
  claim_idempotency_key: string;
  budget_minor_before: string;
  budget_minor_after: string;
  route_reason_codes_json: string;
  metadata_json: string | null;
  created_at: string;
  updated_at: string;
}

interface BountyListItemV2 {
  schema_version: '2';
  bounty_id: string;
  requester_did: string;
  title: string;
  reward: RewardV2;
  closure_type: ClosureType;
  difficulty_scalar: number;
  status: BountyStatus;
  created_at: string;
  escrow_id: string;
  is_code_bounty: boolean;
  tags: string[];
  min_proof_tier: ProofTier;
}

interface WorkerBountyListItemV2 {
  schema_version: '2';
  bounty_id: string;
  title: string;
  reward: RewardV2;
  closure_type: ClosureType;
  difficulty_scalar: number;
  status: BountyStatus;
  created_at: string;
  is_code_bounty: boolean;
  tags: string[];
  min_proof_tier: ProofTier;
}

interface VerifyBundleComponentResults {
  envelope_valid: boolean;
  receipts_valid?: boolean;
  attestations_valid?: boolean;

  /** Optional CEA-US-010 execution attestation evidence (passed out-of-band to /v1/verify/bundle). */
  execution_attestations_valid?: boolean;
  execution_attestations_count?: number;
  execution_attestations_verified_count?: number;
}

interface VerifyBundleResult {
  status: VerificationStatus;
  reason: string;
  verified_at: string;
  trust_tier?: string;
  /** Canonical marketplace-facing proof tier from clawverify (POH-US-013). */
  proof_tier?: string;
  component_results?: VerifyBundleComponentResults;
}

interface VerifyBundleResponse {
  result: VerifyBundleResult;
  trust_tier?: string;
  proof_tier?: string;
  error?: { code: string; message: string; field?: string };
}

interface VerifyCommitProofResult {
  status: VerificationStatus;
  reason: string;
  verified_at: string;
}

interface VerifyCommitProofResponse {
  result: VerifyCommitProofResult;
  repository?: string;
  commit_sha?: string;
  repo_claim_id?: string;
  error?: { code: string; message: string; field?: string };
}

interface VerifyReceiptResult {
  status: VerificationStatus;
  reason: string;
  verified_at: string;
  signer_did?: string;
}

interface VerifyReceiptResponse {
  result: VerifyReceiptResult;
  provider?: string;
  model?: string;
  gateway_id?: string;
  error?: { code: string; message: string; field?: string };
}

interface TestHarnessRunRequest {
  schema_version: '1';
  test_harness_id: string;
  submission_id: string;
  bounty_id: string;
  output: Record<string, unknown> | string;
  proof_bundle_hash: string;
  timeout_ms?: number;
}

interface TestHarnessRunResponse {
  schema_version: '1';
  test_harness_id: string;
  submission_id: string;
  passed: boolean;
  total_tests: number;
  passed_tests: number;
  failed_tests: number;
  test_results: unknown[];
  execution_time_ms: number;
  completed_at: string;
  error?: string;
}

interface TestResultRecord {
  test_result_id: string;
  submission_id: string;
  bounty_id: string;
  test_harness_id: string;
  passed: boolean;
  total_tests: number;
  passed_tests: number;
  failed_tests: number;
  execution_time_ms: number;
  completed_at: string;
  error: string | null;
  test_results: unknown[];
  created_at: string;
  updated_at: string;
}

interface DeterministicTestLaneFailure {
  code: string;
  message: string;
  status: number;
  details?: Record<string, unknown>;
}

interface TestAutoDecisionResult {
  applied: boolean;
  failure?: DeterministicTestLaneFailure;
}

interface ArenaStartActionTemplateView {
  endpoint: string;
  method: 'POST';
  payload_template: {
    idempotency_key: string;
    arena_id: string;
    contract: {
      bounty_id: string;
      contract_id: string;
      contract_hash_b64u: string;
      task_fingerprint: string;
    };
    objective_profile: Record<string, unknown>;
  };
}

interface ArenaInlineReviewSummaryView {
  arena_id: string;
  status: ArenaRunStatus;
  winner_contender_id: string | null;
  winner_reason: string | null;
  winner_confidence: number | null;
  tradeoffs: string[];
  review_links: {
    review_paste: string | null;
    manager_review: string | null;
  };
}

type ArenaOutcomeStatusView = 'ACCEPTED' | 'OVERRIDDEN' | 'REWORK' | 'REJECTED' | 'DISPUTED';
type ArenaRecommendationView = 'APPROVE' | 'REQUEST_CHANGES' | 'REJECT';
type ArenaReviewerDecisionView = 'approve' | 'request_changes' | 'reject';

interface ArenaDecisionCaptureActionTemplateView {
  endpoint: string;
  method: 'POST';
  payload_template: {
    idempotency_key: string;
    arena_id: string;
    contender_id: string | null;
    outcome_status: ArenaOutcomeStatusView;
    recommendation: ArenaRecommendationView;
    reviewer_decision: ArenaReviewerDecisionView;
    rework_required: boolean;
    reviewer_rationale: string;
    decision_taxonomy_tags: string[];
    predicted_confidence: number;
    review_time_minutes: number;
    time_to_accept_minutes: number | null;
    override_reason_code: ArenaOverrideReasonCode | null;
    notes: string;
    source: string;
    metadata: {
      decision_rationale: string;
      override_rationale: string;
      calibration_signal_tags: string[];
    };
  };
}

interface ArenaOutcomeStatusOptionView {
  value: ArenaOutcomeStatusView;
  requires_override_reason: boolean;
  calibration_impact: string;
}

interface ArenaReviewerDecisionOptionView {
  value: ArenaReviewerDecisionView;
  recommendation: ArenaRecommendationView;
  default_outcome_status: ArenaOutcomeStatusView;
  calibration_impact: string;
}

interface ArenaOverrideReasonOptionView {
  code: ArenaOverrideReasonCode;
  weight: number;
  contract_rewrite: string;
  prompt_rewrite: string;
}

interface ArenaDecisionCaptureView {
  outcome_endpoint: ArenaDecisionCaptureActionTemplateView;
  outcome_status_options: ArenaOutcomeStatusOptionView[];
  reviewer_decision_options: ArenaReviewerDecisionOptionView[];
  override_reason_options: ArenaOverrideReasonOptionView[];
  calibration_bindings: {
    notes_path: string;
    rationale_path: string;
    override_reason_path: string;
    reviewer_decision_path: string;
    reviewer_rationale_path: string;
    decision_taxonomy_tags_path: string;
  };
}

interface BountyReviewArenaFlowView {
  start_arena: ArenaStartActionTemplateView;
  latest_arena: ArenaInlineReviewSummaryView | null;
  decision_capture: ArenaDecisionCaptureView | null;
}

interface SubmissionSummaryView {
  submission_id: string;
  bounty_id: string;
  worker_did: string;
  status: SubmissionStatus;
  proof_verify_status: 'valid' | 'invalid';
  proof_tier: ProofTier | null;
  commit_proof_verify_status: 'valid' | 'invalid' | null;
  commit_sha: string | null;
  created_at: string;
  updated_at: string;
  latest_test_result: {
    test_result_id: string;
    test_harness_id: string;
    passed: boolean;
    completed_at: string;
    error: string | null;
  } | null;
  arena_review_flow: BountyReviewArenaFlowView;
}

interface SubmissionDetailView {
  submission_id: string;
  bounty_id: string;
  worker_did: string;
  status: SubmissionStatus;
  idempotency_key: string | null;
  verification: {
    proof_bundle: {
      status: 'valid' | 'invalid';
      reason: string | null;
      verified_at: string | null;
      proof_tier: ProofTier | null;
      proof_bundle_hash_b64u: string | null;
    };
    commit_proof: {
      status: 'valid' | 'invalid' | null;
      reason: string | null;
      verified_at: string | null;
      commit_proof_hash_b64u: string | null;
    };
  };
  source: {
    commit_sha: string | null;
    repo_url: string | null;
    repo_claim_id: string | null;
  };
  output: {
    result_summary: string | null;
    artifacts: unknown[] | null;
    agent_pack: Record<string, unknown> | null;
    execution_attestations: Record<string, unknown>[] | null;
  };
  latest_test_result: {
    test_result_id: string;
    test_harness_id: string;
    passed: boolean;
    total_tests: number;
    passed_tests: number;
    failed_tests: number;
    execution_time_ms: number;
    completed_at: string;
    error: string | null;
  } | null;
  arena_review_flow: BountyReviewArenaFlowView;
  arena?: Record<string, unknown> | null;
  created_at: string;
  updated_at: string;
}

type SubmissionViewerContext =
  | { kind: 'admin' }
  | { kind: 'worker'; worker: WorkerRecordV1 }
  | { kind: 'requester'; requester_did: string; auth: RequesterAuthContext };

interface SubmissionViewerContextResultOk {
  ok: true;
  context: SubmissionViewerContext;
}

interface SubmissionViewerContextResultErr {
  ok: false;
  error: Response;
}

type SubmissionViewerContextResult =
  | SubmissionViewerContextResultOk
  | SubmissionViewerContextResultErr;

interface SubmissionRecord {
  submission_id: string;
  bounty_id: string;
  worker_did: string;
  status: SubmissionStatus;
  idempotency_key: string | null;

  proof_bundle_envelope: Record<string, unknown>;
  proof_bundle_hash_b64u: string | null;
  proof_verify_status: 'valid' | 'invalid';
  proof_verify_reason: string | null;
  proof_verified_at: string | null;
  proof_tier: ProofTier | null;

  /** Optional evidence array forwarded to clawverify for sandbox-tier uplift (CEA-US-010). */
  execution_attestations: Record<string, unknown>[] | null;

  commit_proof_envelope: Record<string, unknown> | null;
  commit_proof_hash_b64u: string | null;
  commit_sha: string | null;
  repo_url: string | null;
  repo_claim_id: string | null;
  commit_proof_verify_status: 'valid' | 'invalid' | null;
  commit_proof_verify_reason: string | null;
  commit_proof_verified_at: string | null;

  artifacts: unknown[] | null;
  agent_pack: Record<string, unknown> | null;
  result_summary: string | null;

  created_at: string;
  updated_at: string;
}

interface SubmitBountyResponseV1 {
  submission_id: string;
  bounty_id: string;
  status: SubmissionStatus;
  verification: {
    proof_bundle: {
      status: 'valid' | 'invalid';
      reason?: string;
      verified_at?: string;
      tier?: ProofTier | null;
    };
    commit_proof?: {
      status: 'valid' | 'invalid';
      reason?: string;
      verified_at?: string;
    };
  };
}

interface EscrowReleaseResponse {
  escrow_id: string;
  status: 'released';
  ledger_refs: {
    worker_transfer: string;
    fee_transfers: string[];
  };
}

interface EscrowDisputeResponse {
  escrow_id: string;
  status: 'frozen';
  dispute_window_ends_at: string;
}

interface TrialCaseSummary {
  case_id: string;
  status: 'open' | 'appealed' | 'decided';
  judge_did: string;
  opened_at: string;
}

interface ApproveBountyResponseV1 {
  bounty_id: string;
  submission_id: string;
  status: 'approved';
  escrow: EscrowReleaseResponse;
  decided_at: string;
}

interface RejectBountyResponseV1 {
  bounty_id: string;
  submission_id: string;
  status: 'disputed';
  escrow: EscrowDisputeResponse;
  trial_case: TrialCaseSummary;
  decided_at: string;
}

type WorkerStatus = 'online' | 'offline' | 'paused';
type WorkerAuthMode = 'token' | 'scoped_token';
type WorkerAvailabilityMode = 'manual' | 'auto';

interface WorkerListingV1 {
  name: string;
  headline: string;
  tags: string[];
}

interface WorkerCapabilitiesV1 {
  job_types: string[];
  languages: string[];
  max_minutes: number;
}

interface WorkerOfferMcpV1 {
  name: string;
  description: string;
}

interface WorkerOffersV1 {
  skills: string[];
  mcp: WorkerOfferMcpV1[];
}

interface WorkerPricingV1 {
  price_floor_minor: string;
}

interface WorkerAvailabilityV1 {
  mode: WorkerAvailabilityMode;
  paused: boolean;
}

interface WorkerRecordV1 {
  worker_id: string;
  worker_did: string;
  status: WorkerStatus;
  worker_version: string;
  listing: WorkerListingV1;
  capabilities: WorkerCapabilitiesV1;
  offers: WorkerOffersV1;
  pricing: WorkerPricingV1;
  availability: WorkerAvailabilityV1;
  auth_mode: WorkerAuthMode;
  auth_token_hash_hex: string;
  auth_token_prefix: string;
  auth_token_created_at: string;
  auth_token_expires_at: string;
  created_at: string;
  updated_at: string;
}

interface RegisterWorkerResponseV1 {
  worker_id: string;
  auth: { mode: WorkerAuthMode; token: string };
}

interface WorkerListItemV1 {
  worker_id: string;
  worker_did: string;
  status: WorkerStatus;
  listing: WorkerListingV1;
  capabilities: WorkerCapabilitiesV1;
  offers: WorkerOffersV1;
  pricing: WorkerPricingV1;
}

type JobAuthResponseV1 = {
  cst: string;
  token_scope_hash_b64u: string;
  aud: string;
  mission_id: string;
  policy_hash_b64u?: string;
  iat?: number;
  exp?: number;
};

type CwcAuthResponseV1 = JobAuthResponseV1 & { policy_hash_b64u: string };

interface AcceptBountyResponseV1 {
  bounty_id: string;
  escrow_id: string;
  status: 'accepted';
  worker_did: string;
  accepted_at: string;
  fee_policy_version: string;
  payout: { worker_net_minor: string; currency: 'USD' };

  cwc_auth?: CwcAuthResponseV1;
}

interface IssueBountyCstResponseV1 {
  bounty_id: string;
  worker_did: string;
  job_auth?: JobAuthResponseV1;
  cwc_auth?: CwcAuthResponseV1;
}

function escapeHtml(input: string): string {
  return input
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function escapeXml(input: string): string {
  return input
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&apos;');
}

function jsonResponse(body: unknown, status = 200, version?: string): Response {
  const headers = new Headers();
  headers.set('content-type', 'application/json; charset=utf-8');
  if (version) headers.set('X-Bounties-Version', version);
  return new Response(JSON.stringify(body, null, 2), { status, headers });
}

function textResponse(body: string, contentType: string, status = 200, version?: string, extraHeaders?: HeadersInit): Response {
  const headers = new Headers(extraHeaders);
  headers.set('content-type', contentType);
  headers.set('cache-control', 'public, max-age=300');
  if (version) headers.set('X-Bounties-Version', version);
  return new Response(body, { status, headers });
}

function htmlResponse(body: string, status = 200, version?: string): Response {
  return textResponse(body, 'text/html; charset=utf-8', status, version);
}

function errorResponse(code: string, message: string, status = 400, details?: Record<string, unknown>, version?: string): Response {
  return jsonResponse({ error: code, message, details }, status, version);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

function parsePositiveMinor(input: unknown): bigint | null {
  if (typeof input !== 'string') return null;
  const s = input.trim();
  if (!/^[0-9]+$/.test(s)) return null;
  try {
    const n = BigInt(s);
    if (n <= 0n) return null;
    return n;
  } catch {
    return null;
  }
}

function parseDifficultyScalar(input: unknown): number | null {
  if (typeof input !== 'number' || !Number.isFinite(input)) return null;
  if (input < 0.1 || input > 10.0) return null;
  return input;
}

function parseClosureType(input: unknown): ClosureType | null {
  if (!isNonEmptyString(input)) return null;
  const v = input.trim();
  if (v === 'test' || v === 'requester' || v === 'quorum') return v;
  return null;
}

function parseProofTier(input: unknown): ProofTier | null {
  if (!isNonEmptyString(input)) return null;
  const v = input.trim();
  if (v === 'self' || v === 'gateway' || v === 'sandbox') return v;
  return null;
}

function parseSubmissionStatus(input: unknown): SubmissionStatus | null {
  if (!isNonEmptyString(input)) return null;
  const v = input.trim();
  if (v === 'pending_review' || v === 'invalid' || v === 'approved' || v === 'rejected') return v;
  return null;
}

function parseJsonUnknownArray(text: string): unknown[] | null {
  try {
    const parsed = JSON.parse(text) as unknown;
    if (!Array.isArray(parsed)) return null;
    return parsed;
  } catch {
    return null;
  }
}

function parseBountyStatus(input: unknown): BountyStatus | null {
  if (!isNonEmptyString(input)) return null;
  const v = input.trim();
  if (
    v === 'open' ||
    v === 'accepted' ||
    v === 'pending_review' ||
    v === 'approved' ||
    v === 'rejected' ||
    v === 'disputed' ||
    v === 'cancelled'
  ) {
    return v;
  }
  return null;
}

function parseBountyArenaStatus(input: unknown): BountyArenaStatus | null {
  if (!isNonEmptyString(input)) return null;
  const v = input.trim();
  if (v === 'idle' || v === 'started' || v === 'completed' || v === 'failed') {
    return v;
  }
  return null;
}

function parseArenaRunStatus(input: unknown): ArenaRunStatus | null {
  if (!isNonEmptyString(input)) return null;
  const v = input.trim();
  if (v === 'started' || v === 'completed') return v;
  return null;
}

const ARENA_OVERRIDE_REASON_REGISTRY = {
  ARENA_OVERRIDE_SCOPE_MISMATCH: {
    contract_rewrite: 'Tighten acceptance criteria and explicit out-of-scope boundaries in the contract.',
    prompt_rewrite: 'Add a scope-check checklist before final answer generation.',
    weight: 0.8,
  },
  ARENA_OVERRIDE_TEST_FAILURE: {
    contract_rewrite: 'Require deterministic test-harness pass evidence before recommendation.',
    prompt_rewrite: 'Force candidate to run and summarize failing tests before final output.',
    weight: 0.9,
  },
  ARENA_OVERRIDE_POLICY_RISK: {
    contract_rewrite: 'Raise safety and policy constraints to mandatory hard-gate checks.',
    prompt_rewrite: 'Insert explicit policy-risk self-audit and fail-closed escalation path.',
    weight: 1,
  },
  ARENA_OVERRIDE_REQUIRE_HUMAN_CONTEXT: {
    contract_rewrite: 'Add human-context dependency markers and required reviewer checkpoints.',
    prompt_rewrite: 'Require ambiguity classification and human-clarification request when context is missing.',
    weight: 0.5,
  },
  ARENA_OVERRIDE_COST_TOO_HIGH: {
    contract_rewrite: 'Set stricter max-cost / max-latency targets in objective profile.',
    prompt_rewrite: 'Prioritize cost-efficient plans and include tradeoff justification.',
    weight: 0.6,
  },
  ARENA_OVERRIDE_OTHER: {
    contract_rewrite: 'Review override notes and encode recurring blockers into explicit acceptance checks.',
    prompt_rewrite: 'Add a post-mortem checklist seeded from recent override notes.',
    weight: 0.7,
  },
} as const;

type ArenaOverrideReasonCode = keyof typeof ARENA_OVERRIDE_REASON_REGISTRY;

const ARENA_BACKTEST_WEIGHT_SUGGESTIONS: Record<ArenaOverrideReasonCode, {
  delta: { quality: number; speed: number; cost: number; safety: number };
  rationale: string;
}> = {
  ARENA_OVERRIDE_SCOPE_MISMATCH: {
    delta: { quality: 0.04, speed: -0.03, cost: -0.01, safety: 0 },
    rationale: 'Scope mismatches suggest increasing quality weighting and slowing fast-path routing.',
  },
  ARENA_OVERRIDE_TEST_FAILURE: {
    delta: { quality: 0.06, speed: -0.03, cost: -0.01, safety: -0.02 },
    rationale: 'Test failures indicate stronger quality pressure before selecting speed/cost optimized contenders.',
  },
  ARENA_OVERRIDE_POLICY_RISK: {
    delta: { quality: 0.02, speed: -0.04, cost: -0.03, safety: 0.05 },
    rationale: 'Policy-risk overrides require higher safety emphasis and lower speed/cost tradeoffs.',
  },
  ARENA_OVERRIDE_REQUIRE_HUMAN_CONTEXT: {
    delta: { quality: 0.01, speed: -0.05, cost: 0, safety: 0.04 },
    rationale: 'Human-context misses should reduce aggressive autonomy routing and increase safety checks.',
  },
  ARENA_OVERRIDE_COST_TOO_HIGH: {
    delta: { quality: 0, speed: -0.01, cost: 0.07, safety: -0.01 },
    rationale: 'Cost-driven overrides require stronger cost weighting while keeping safety neutral.',
  },
  ARENA_OVERRIDE_OTHER: {
    delta: { quality: 0.02, speed: -0.02, cost: -0.01, safety: 0.01 },
    rationale: 'Generic overrides indicate slight rebalance toward quality/safety and less speed bias.',
  },
};

function normalizeArenaOverrideReasonCode(input: unknown): ArenaOverrideReasonCode | null {
  if (!isNonEmptyString(input)) return null;
  const normalized = input.trim().toUpperCase();
  if (normalized in ARENA_OVERRIDE_REASON_REGISTRY) {
    return normalized as ArenaOverrideReasonCode;
  }
  return null;
}

function parseWorkerStatus(input: unknown): WorkerStatus | null {
  if (!isNonEmptyString(input)) return null;
  const v = input.trim();
  if (v === 'online' || v === 'offline' || v === 'paused') return v;
  return null;
}

function parseWorkerAvailabilityMode(input: unknown): WorkerAvailabilityMode | null {
  if (!isNonEmptyString(input)) return null;
  const v = input.trim();
  if (v === 'manual' || v === 'auto') return v;
  return null;
}

function parseTags(input: unknown): string[] | null {
  if (input === undefined) return [];
  if (!Array.isArray(input)) return null;

  const tags: string[] = [];
  for (const raw of input) {
    if (!isNonEmptyString(raw)) return null;
    const t = raw.trim();
    if (t.length > 50) return null;
    tags.push(t);
  }

  if (tags.length > 10) return null;

  // Deduplicate while preserving order.
  const seen = new Set<string>();
  const out: string[] = [];
  for (const t of tags) {
    if (seen.has(t)) continue;
    seen.add(t);
    out.push(t);
  }

  return out;
}

function parseStringList(input: unknown, maxItems: number, maxLen: number, allowUndefined = false): string[] | null {
  if (input === undefined) return allowUndefined ? [] : null;
  if (!Array.isArray(input)) return null;

  const items: string[] = [];
  for (const raw of input) {
    if (!isNonEmptyString(raw)) return null;
    const v = raw.trim();
    if (v.length > maxLen) return null;
    items.push(v);
  }

  if (items.length > maxItems) return null;

  // Deduplicate while preserving order.
  const seen = new Set<string>();
  const out: string[] = [];
  for (const v of items) {
    if (seen.has(v)) continue;
    seen.add(v);
    out.push(v);
  }

  return out;
}

function parseArenaFleetCostTier(input: unknown): ArenaFleetCostTier | null {
  if (!isNonEmptyString(input)) return null;
  const value = input.trim().toLowerCase();
  if (value === 'low' || value === 'medium' || value === 'high') return value;
  return null;
}

function parseArenaFleetRiskTier(input: unknown): ArenaFleetRiskTier | null {
  if (!isNonEmptyString(input)) return null;
  const value = input.trim().toLowerCase();
  if (value === 'low' || value === 'medium' || value === 'high') return value;
  return null;
}

function parseArenaFleetAvailabilityStatus(input: unknown): ArenaFleetAvailabilityStatus | null {
  if (!isNonEmptyString(input)) return null;
  const value = input.trim().toLowerCase();
  if (value === 'online' || value === 'offline' || value === 'paused') return value;
  return null;
}

function arenaFleetTierRank(tier: ArenaFleetCostTier | ArenaFleetRiskTier): number {
  switch (tier) {
    case 'low':
      return 1;
    case 'medium':
      return 2;
    case 'high':
      return 3;
  }
}

function parseArenaFleetStringJson(value: string, maxItems: number, maxLength: number): string[] | null {
  const parsed = parseJsonStringArray(value);
  if (!parsed) return null;

  const items: string[] = [];
  const seen = new Set<string>();
  for (const raw of parsed) {
    const trimmed = raw.trim();
    if (!trimmed || trimmed.length > maxLength) return null;
    if (seen.has(trimmed)) continue;
    seen.add(trimmed);
    items.push(trimmed);
  }

  if (items.length > maxItems) return null;
  return items;
}

function inferArenaBountyCostTier(amountMinor: string): ArenaFleetCostTier {
  const parsed = parsePositiveMinor(amountMinor);
  if (parsed === null) return 'high';
  if (parsed <= 1_000n) return 'low';
  if (parsed <= 10_000n) return 'medium';
  return 'high';
}

function inferArenaBountyRiskTier(bounty: BountyV2): ArenaFleetRiskTier {
  if (bounty.min_proof_tier === 'sandbox') return 'high';
  if (bounty.tags.some((tag) => tag.toLowerCase().includes('security'))) return 'high';
  if (bounty.tags.some((tag) => tag.toLowerCase().includes('ops'))) return 'medium';
  if (bounty.difficulty_scalar >= 3) return 'high';
  if (bounty.difficulty_scalar >= 1.6) return 'medium';
  return 'low';
}

const ARENA_CONFORMANCE_AGENT_SEED = new Uint8Array(Array.from({ length: 32 }, (_, index) => index + 1));
const ARENA_CONFORMANCE_AGENT_DID = 'did:key:z6MkneMkZqwqRiU5mJzSG3kDwzt9P8C59N4NGTfBLfSGE7c7';
const ARENA_AUTONOMOUS_DEFAULT_REQUESTER_DID = 'did:key:z6Mkseedrequester0000000000000000000000000';
const ARENA_BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Encode(bytes: Uint8Array): string {
  if (bytes.length === 0) return '';

  const digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i += 1) {
      const current = digits[i] ?? 0;
      const x = current * 256 + carry;
      digits[i] = x % 58;
      carry = Math.floor(x / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }

  for (let i = 0; i < bytes.length && bytes[i] === 0; i += 1) {
    digits.push(0);
  }

  return digits.reverse().map((digit) => ARENA_BASE58_ALPHABET[digit] ?? '').join('');
}

function base64UrlEncodeBytes(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  const base64 = btoa(binary);
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64UrlDecodeToBytes(value: string): Uint8Array {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

async function makeArenaConformanceSignerFromSeed(seed: Uint8Array): Promise<{ did: string; privateKey: CryptoKey }> {
  if (seed.length !== 32) {
    throw new Error('ARENA_CONFORMANCE_SEED_INVALID');
  }

  const pkcs8Header = new Uint8Array([
    0x30, 0x2e,
    0x02, 0x01, 0x00,
    0x30, 0x05,
    0x06, 0x03, 0x2b, 0x65, 0x70,
    0x04, 0x22,
    0x04, 0x20,
  ]);

  const pkcs8Key = new Uint8Array(pkcs8Header.length + seed.length);
  pkcs8Key.set(pkcs8Header);
  pkcs8Key.set(seed, pkcs8Header.length);

  const privateKey = await crypto.subtle.importKey('pkcs8', pkcs8Key, { name: 'Ed25519' }, true, ['sign']);
  const jwk = (await crypto.subtle.exportKey('jwk', privateKey)) as JsonWebKey;
  const x = typeof jwk.x === 'string' ? jwk.x : null;
  if (!x) {
    throw new Error('ARENA_CONFORMANCE_DID_DERIVE_FAILED');
  }

  const publicKeyBytes = base64UrlDecodeToBytes(x);
  const prefixed = new Uint8Array(2 + publicKeyBytes.length);
  prefixed[0] = 0xed;
  prefixed[1] = 0x01;
  prefixed.set(publicKeyBytes, 2);

  return {
    did: `did:key:z${base58Encode(prefixed)}`,
    privateKey,
  };
}

async function buildArenaExecutionAutopilotProofArtifacts(
  workerDid: string,
  bountyId: string,
  signer: { did: string; privateKey: CryptoKey },
): Promise<{ runId: string; proofBundleEnvelope: Record<string, unknown>; urm: Record<string, unknown> }> {
  const runId = `arena_exec_${bountyId}_${crypto.randomUUID().replace(/-/g, '')}`;
  const nowMs = Date.now();
  const t0 = new Date(nowMs).toISOString();
  const t1 = new Date(nowMs + 1000).toISOString();

  const eventAHeader = {
    event_id: `evt_${crypto.randomUUID()}`,
    run_id: runId,
    event_type: 'run_start',
    timestamp: t0,
    payload_hash_b64u: await sha256B64uUtf8(JSON.stringify({ event: 'run_start' })),
    prev_hash_b64u: null,
  };
  const eventAHash = await sha256B64uUtf8(JSON.stringify(eventAHeader));

  const eventBHeader = {
    event_id: `evt_${crypto.randomUUID()}`,
    run_id: runId,
    event_type: 'run_end',
    timestamp: t1,
    payload_hash_b64u: await sha256B64uUtf8(JSON.stringify({ event: 'run_end' })),
    prev_hash_b64u: eventAHash,
  };
  const eventBHash = await sha256B64uUtf8(JSON.stringify(eventBHeader));

  const eventChain = [
    { ...eventAHeader, event_hash_b64u: eventAHash },
    { ...eventBHeader, event_hash_b64u: eventBHash },
  ];

  const harness = {
    id: 'arena-submission-autopilot',
    version: '1',
    runtime: 'simulation',
  };

  const harnessConfigHash = await sha256B64uUtf8(JSON.stringify(harness));

  const urm: Record<string, unknown> = {
    urm_version: '1',
    urm_id: `urm_${crypto.randomUUID()}`,
    run_id: runId,
    agent_did: workerDid,
    issued_at: new Date(nowMs + 1500).toISOString(),
    harness: {
      id: harness.id,
      version: harness.version,
      runtime: harness.runtime,
      config_hash_b64u: harnessConfigHash,
    },
    inputs: [],
    outputs: [],
    event_chain_root_hash_b64u: eventAHash,
    metadata: { harness },
  };

  const urmHash = await sha256B64uUtf8(JSON.stringify(urm));

  const payload: Record<string, unknown> = {
    bundle_version: '1',
    bundle_id: `bundle_${crypto.randomUUID()}`,
    agent_did: workerDid,
    urm: {
      urm_version: '1',
      urm_id: String(urm.urm_id),
      resource_type: 'universal_run_manifest',
      resource_hash_b64u: urmHash,
    },
    event_chain: eventChain,
    metadata: { harness },
  };

  const payloadHash = await sha256B64uUtf8(JSON.stringify(payload));
  const signatureBuffer = await crypto.subtle.sign('Ed25519', signer.privateKey, new TextEncoder().encode(payloadHash));
  const signature = base64UrlEncodeBytes(new Uint8Array(signatureBuffer));

  const proofBundleEnvelope: Record<string, unknown> = {
    envelope_version: '1',
    envelope_type: 'proof_bundle',
    payload,
    payload_hash_b64u: payloadHash,
    hash_algorithm: 'SHA-256',
    signature_b64u: signature,
    algorithm: 'Ed25519',
    signer_did: signer.did,
    issued_at: new Date(nowMs + 2000).toISOString(),
  };

  return {
    runId,
    proofBundleEnvelope,
    urm,
  };
}

function parseWorkerListing(input: unknown): WorkerListingV1 | null {
  if (!isRecord(input)) return null;

  const nameRaw = input.name;
  const headlineRaw = input.headline;
  const tagsRaw = input.tags;

  if (!isNonEmptyString(nameRaw)) return null;
  if (!isNonEmptyString(headlineRaw)) return null;

  const name = nameRaw.trim();
  const headline = headlineRaw.trim();

  if (name.length > 100) return null;
  if (headline.length > 200) return null;

  const tags = parseTags(tagsRaw);
  if (!tags) return null;

  return { name, headline, tags };
}

function parseWorkerCapabilities(input: unknown): WorkerCapabilitiesV1 | null {
  if (!isRecord(input)) return null;

  const jobTypes = parseStringList(input.job_types, 20, 32);
  const languages = parseStringList(input.languages, 20, 16);

  const maxMinutesRaw = input.max_minutes;
  if (typeof maxMinutesRaw !== 'number' || !Number.isFinite(maxMinutesRaw) || !Number.isInteger(maxMinutesRaw)) return null;
  if (maxMinutesRaw < 1 || maxMinutesRaw > 240) return null;

  if (!jobTypes || jobTypes.length === 0) return null;
  if (!languages) return null;

  return {
    job_types: jobTypes,
    languages,
    max_minutes: maxMinutesRaw,
  };
}

function parseWorkerOffers(input: unknown): WorkerOffersV1 | null {
  if (!isRecord(input)) return null;

  const skills = parseStringList(input.skills, 50, 64, true);
  if (!skills) return null;

  const mcpRaw = input.mcp;
  const mcp: WorkerOfferMcpV1[] = [];

  if (mcpRaw !== undefined) {
    if (!Array.isArray(mcpRaw)) return null;
    if (mcpRaw.length > 25) return null;

    for (const entry of mcpRaw) {
      if (!isRecord(entry)) return null;

      const nameRaw = entry.name;
      const descriptionRaw = entry.description;

      if (!isNonEmptyString(nameRaw) || !isNonEmptyString(descriptionRaw)) return null;

      const name = nameRaw.trim();
      const description = descriptionRaw.trim();

      if (name.length > 64) return null;
      if (description.length > 256) return null;

      mcp.push({ name, description });
    }
  }

  return { skills, mcp };
}

function parseWorkerPricing(input: unknown): WorkerPricingV1 | null {
  if (!isRecord(input)) return null;

  const floorRaw = input.price_floor_minor;
  const floor = parsePositiveMinor(floorRaw);
  if (floor === null) return null;

  return { price_floor_minor: String(floorRaw).trim() };
}

function parseWorkerAvailability(input: unknown): WorkerAvailabilityV1 | null {
  if (!isRecord(input)) return null;

  const mode = parseWorkerAvailabilityMode(input.mode);
  if (!mode) return null;

  let paused = false;
  if (input.paused !== undefined) {
    if (typeof input.paused !== 'boolean') return null;
    paused = input.paused;
  }

  return { mode, paused };
}

function getBearerToken(header: string | null): string | null {
  if (!header) return null;
  const trimmed = header.trim();
  if (!trimmed) return null;
  if (trimmed.toLowerCase().startsWith('bearer ')) return trimmed.slice(7).trim();
  return trimmed;
}

function looksLikeJwtToken(token: string): boolean {
  return token.split('.').length === 3;
}

function isAdminAuthorized(request: Request, env: Env): boolean {
  if (!env.BOUNTIES_ADMIN_KEY || env.BOUNTIES_ADMIN_KEY.trim().length === 0) return false;
  const token = getBearerToken(request.headers.get('authorization')) ?? request.headers.get('x-admin-key')?.trim() ?? null;
  if (!token) return false;
  return token === env.BOUNTIES_ADMIN_KEY;
}

function requireAdmin(request: Request, env: Env, version: string): Response | null {
  if (!env.BOUNTIES_ADMIN_KEY || env.BOUNTIES_ADMIN_KEY.trim().length === 0) {
    return errorResponse('ADMIN_KEY_NOT_CONFIGURED', 'BOUNTIES_ADMIN_KEY is not configured', 503, undefined, version);
  }

  const token = getBearerToken(request.headers.get('authorization')) ?? request.headers.get('x-admin-key')?.trim() ?? null;
  if (!token) {
    return errorResponse('UNAUTHORIZED', 'Missing admin token', 401, undefined, version);
  }

  if (token !== env.BOUNTIES_ADMIN_KEY) {
    return errorResponse('UNAUTHORIZED', 'Invalid admin token', 401, undefined, version);
  }

  return null;
}

function requireRiskService(request: Request, env: Env, version: string): Response | null {
  if (!env.BOUNTIES_RISK_KEY || env.BOUNTIES_RISK_KEY.trim().length === 0) {
    return errorResponse('RISK_KEY_NOT_CONFIGURED', 'BOUNTIES_RISK_KEY is not configured', 503, undefined, version);
  }

  const token = getBearerToken(request.headers.get('authorization')) ?? request.headers.get('x-admin-key')?.trim() ?? null;
  if (!token) {
    return errorResponse('UNAUTHORIZED', 'Missing risk token', 401, undefined, version);
  }

  if (token !== env.BOUNTIES_RISK_KEY) {
    return errorResponse('UNAUTHORIZED', 'Invalid risk token', 401, undefined, version);
  }

  return null;
}

async function requireWorker(
  request: Request,
  env: Env,
  version: string,
  params?: {
    action?: WorkerAuthAction;
    worker_did_hint?: string | null;
    allow_legacy_local_token?: boolean;
  }
): Promise<{ worker: WorkerRecordV1; auth: WorkerAuthContext } | { error: Response }> {
  const action = params?.action ?? 'worker_self';
  const token = getBearerToken(request.headers.get('authorization'));
  if (!token) {
    return { error: errorResponse('WORKER_TOKEN_REQUIRED', 'Missing worker token', 401, undefined, version) };
  }

  const workerHint = params?.worker_did_hint?.trim() || null;

  if (looksLikeJwtToken(token)) {
    const introspection = await introspectWorkerToken(env, token, version);
    if ('error' in introspection) return introspection;

    const data = introspection.data;
    if (!data.active) {
      return {
        error: errorResponse('WORKER_TOKEN_INVALID', 'Worker scoped token is inactive', 401, undefined, version),
      };
    }

    const worker_did = isNonEmptyString(data.sub) ? data.sub.trim() : null;
    if (!worker_did || !worker_did.startsWith('did:')) {
      return {
        error: errorResponse('WORKER_SUB_INVALID', 'Worker token subject must be a DID', 401, undefined, version),
      };
    }

    if (workerHint && workerHint !== worker_did) {
      return {
        error: errorResponse(
          'WORKER_SUB_MISMATCH',
          'worker_did does not match worker token subject',
          401,
          { worker_did, requested_worker_did: workerHint },
          version
        ),
      };
    }

    const controlClaims = validateControlPlaneTokenContract({
      actor: 'WORKER',
      introspection: data,
      version,
    });
    if ('error' in controlClaims) return controlClaims;

    const scope = parseTokenScopeClaim(data.scope);
    if (!hasWorkerScope(scope, action)) {
      return {
        error: errorResponse(
          'WORKER_SCOPE_REQUIRED',
          'Worker token does not include the required scope for this action',
          403,
          { required_scope: WORKER_AUTH_SCOPE_BY_ACTION[action], scope },
          version
        ),
      };
    }

    const requiredAudience = resolveWorkerAuthRequiredAudience(env);
    const aud = parseTokenAudClaim(data.aud);
    if (!aud.includes(requiredAudience)) {
      return {
        error: errorResponse(
          'WORKER_AUDIENCE_REQUIRED',
          'Worker token audience does not include clawbounties',
          403,
          { required_audience: requiredAudience, aud },
          version
        ),
      };
    }

    const agentDid = isNonEmptyString(data.agent_did) ? data.agent_did.trim() : null;
    if (!agentDid) {
      return {
        error: errorResponse(
          'WORKER_CONTROL_CLAIM_REQUIRED',
          'Worker token is missing required control-plane claim',
          403,
          { claim: 'agent_did' },
          version
        ),
      };
    }

    if (!agentDid.startsWith('did:')) {
      return {
        error: errorResponse(
          'WORKER_CONTROL_CLAIM_INVALID',
          'Worker token control-plane claim is invalid',
          403,
          { claim: 'agent_did' },
          version
        ),
      };
    }

    if (agentDid !== worker_did) {
      return {
        error: errorResponse(
          'WORKER_CONTROL_BINDING_MISMATCH',
          'Worker control-plane claim does not match token subject',
          403,
          { claim: 'agent_did', token_sub: worker_did, agent_did: agentDid },
          version
        ),
      };
    }

    const expectedScopeHash = await computeTokenScopeHashB64uV1({
      sub: worker_did,
      aud,
      scope,
      owner_ref: isNonEmptyString(data.owner_ref) ? data.owner_ref.trim() : undefined,
      owner_did: isNonEmptyString(data.owner_did) ? data.owner_did.trim() : undefined,
      controller_did: isNonEmptyString(data.controller_did) ? data.controller_did.trim() : undefined,
      agent_did: agentDid,
      policy_hash_b64u: isNonEmptyString(data.policy_hash_b64u) ? data.policy_hash_b64u.trim() : undefined,
      control_plane_policy_hash_b64u: isNonEmptyString(data.control_plane_policy_hash_b64u)
        ? data.control_plane_policy_hash_b64u.trim()
        : undefined,
      payment_account_did: isNonEmptyString(data.payment_account_did) ? data.payment_account_did.trim() : undefined,
      spend_cap: typeof data.spend_cap === 'number' && Number.isFinite(data.spend_cap) ? data.spend_cap : undefined,
      mission_id: isNonEmptyString(data.mission_id) ? data.mission_id.trim() : undefined,
    });

    if (controlClaims.token_scope_hash_b64u !== expectedScopeHash) {
      return {
        error: errorResponse(
          'WORKER_CONTROL_BINDING_MISMATCH',
          'Worker token scope hash does not match deterministic control-plane contract',
          403,
          {
            claim: 'token_scope_hash_b64u',
            expected_token_scope_hash_b64u: expectedScopeHash,
            token_scope_hash_b64u: controlClaims.token_scope_hash_b64u,
          },
          version
        ),
      };
    }

    let worker: WorkerRecordV1 | null;
    try {
      worker = await getWorkerByDid(env.BOUNTIES_DB, worker_did);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      return { error: errorResponse('DB_READ_FAILED', message, 500, undefined, version) };
    }

    if (!worker) {
      return {
        error: errorResponse('WORKER_NOT_REGISTERED', 'Worker is not registered in marketplace', 404, undefined, version),
      };
    }

    return {
      worker,
      auth: {
        worker_did,
        auth_mode: 'scoped_token',
        token_hash: controlClaims.token_hash,
        scope,
        aud,
        token_scope_hash_b64u: controlClaims.token_scope_hash_b64u,
        token_lane: controlClaims.token_lane,
        payment_account_did: controlClaims.payment_account_did,
        agent_did: agentDid,
        iat: controlClaims.iat,
        exp: controlClaims.exp,
        bearer_token: token,
      },
    };
  }

  const allowLegacy = params?.allow_legacy_local_token ?? resolveWorkerAuthCompatLegacy(env);
  if (!allowLegacy) {
    return {
      error: errorResponse(
        'WORKER_TOKEN_CANONICAL_REQUIRED',
        'Worker scoped token must be a canonical clawscope JWT',
        401,
        undefined,
        version
      ),
    };
  }

  let worker: WorkerRecordV1 | null;
  try {
    worker = await getWorkerByAuthToken(env.BOUNTIES_DB, token);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return { error: errorResponse('DB_READ_FAILED', message, 500, undefined, version) };
  }

  if (!worker) {
    return { error: errorResponse('WORKER_TOKEN_INVALID', 'Invalid or expired worker token', 401, undefined, version) };
  }

  if (workerHint && workerHint !== worker.worker_did) {
    return {
      error: errorResponse(
        'WORKER_SUB_MISMATCH',
        'worker_did does not match legacy worker token subject',
        401,
        { worker_did: worker.worker_did, requested_worker_did: workerHint },
        version
      ),
    };
  }

  return {
    worker,
    auth: {
      worker_did: worker.worker_did,
      auth_mode: 'token',
      token_hash: worker.auth_token_hash_hex,
      scope: [WORKER_AUTH_SCOPE_BY_ACTION[action]],
      aud: [],
      token_scope_hash_b64u: null,
      token_lane: null,
      payment_account_did: null,
      agent_did: worker.worker_did,
      iat: null,
      exp: null,
      bearer_token: null,
    },
  };
}

function requireRequesterDidLegacy(request: Request, version: string): { requester_did: string } | { error: Response } {
  const didHeader = request.headers.get('x-requester-did');
  if (!didHeader || didHeader.trim().length === 0) {
    return {
      error: errorResponse(
        'REQUESTER_DID_REQUIRED',
        'Missing requester DID. Provide header: x-requester-did: did:key:... (legacy compatibility path).',
        400,
        undefined,
        version
      ),
    };
  }

  const requester_did = didHeader.trim();
  if (!requester_did.startsWith('did:')) {
    return {
      error: errorResponse('INVALID_REQUEST', 'x-requester-did must be a DID string', 400, undefined, version),
    };
  }

  return { requester_did };
}

function parseBooleanEnv(raw: string | undefined, fallback: boolean): boolean {
  if (!raw) return fallback;
  const v = raw.trim().toLowerCase();
  if (v === 'true' || v === '1' || v === 'yes' || v === 'on') return true;
  if (v === 'false' || v === '0' || v === 'no' || v === 'off') return false;
  return fallback;
}

function resolveRequesterAuthCompatLegacy(env: Env): boolean {
  return parseBooleanEnv(env.REQUESTER_AUTH_COMPAT_LEGACY, false);
}

function resolveRequesterAuthRequiredAudience(env: Env): string {
  const raw = env.REQUESTER_AUTH_REQUIRED_AUDIENCE?.trim();
  if (raw && raw.length > 0) return raw;
  return 'clawbounties.com';
}

function resolveRequesterAuthTimeoutMs(env: Env): number {
  const raw = env.REQUESTER_AUTH_TIMEOUT_MS?.trim();
  if (!raw) return 5000;

  const n = Number(raw);
  if (!Number.isFinite(n)) return 5000;

  const timeout = Math.floor(n);
  if (timeout < 1000) return 5000;
  if (timeout > 30000) return 30000;
  return timeout;
}

function resolveWorkerAuthCompatLegacy(env: Env): boolean {
  return parseBooleanEnv(env.WORKER_AUTH_COMPAT_LEGACY, false);
}

function resolveWorkerAuthRequiredAudience(env: Env): string {
  const raw = env.WORKER_AUTH_REQUIRED_AUDIENCE?.trim();
  if (raw && raw.length > 0) return raw;
  return resolveRequesterAuthRequiredAudience(env);
}

function resolveWorkerAuthTimeoutMs(env: Env): number {
  const raw = env.WORKER_AUTH_TIMEOUT_MS?.trim();
  if (!raw) return resolveRequesterAuthTimeoutMs(env);

  const n = Number(raw);
  if (!Number.isFinite(n)) return resolveRequesterAuthTimeoutMs(env);

  const timeout = Math.floor(n);
  if (timeout < 1000) return resolveRequesterAuthTimeoutMs(env);
  if (timeout > 30000) return 30000;
  return timeout;
}

function normalizeTokenClaimStringList(input: unknown): string[] {
  if (!Array.isArray(input)) return [];

  const out: string[] = [];
  for (const item of input) {
    if (!isNonEmptyString(item)) continue;
    const v = item.trim();
    if (!v) continue;
    if (!out.includes(v)) out.push(v);
  }

  return out;
}

function parseTokenScopeClaim(scope: unknown): string[] {
  if (typeof scope === 'string') {
    return scope
      .split(/\s+/g)
      .map((entry) => entry.trim())
      .filter((entry) => entry.length > 0);
  }

  return normalizeTokenClaimStringList(scope);
}

function parseTokenAudClaim(aud: unknown): string[] {
  if (typeof aud === 'string') {
    const value = aud.trim();
    return value ? [value] : [];
  }

  return normalizeTokenClaimStringList(aud);
}

function hasRequesterScope(scope: readonly string[], action: RequesterAuthAction): boolean {
  const required = REQUESTER_AUTH_SCOPE_BY_ACTION[action];
  return scope.includes(required);
}

function hasWorkerScope(scope: readonly string[], action: WorkerAuthAction): boolean {
  const required = WORKER_AUTH_SCOPE_BY_ACTION[action];
  return scope.includes(required);
}

function isHexSha256(value: string): boolean {
  return /^[a-f0-9]{64}$/i.test(value);
}

function parseScopedTokenLane(value: unknown): ScopedTokenLane | null {
  if (!isNonEmptyString(value)) return null;
  const lane = value.trim();
  if (lane === 'legacy' || lane === 'canonical') return lane;
  return null;
}

type ControlPlaneClaimValidationSuccess = {
  token_hash: string;
  token_scope_hash_b64u: string;
  token_lane: ScopedTokenLane;
  payment_account_did: string | null;
  iat: number;
  exp: number;
};

function validateControlPlaneTokenContract(params: {
  actor: 'REQUESTER' | 'WORKER';
  introspection: ScopeIntrospectionResponse;
  version: string;
}): ControlPlaneClaimValidationSuccess | { error: Response } {
  const prefix = params.actor;
  const claims = params.introspection;

  const tokenHashRaw = claims.token_hash;
  if (!isNonEmptyString(tokenHashRaw)) {
    return {
      error: errorResponse(
        `${prefix}_CONTROL_CLAIM_REQUIRED`,
        `${prefix.toLowerCase()} token is missing required control-plane claim`,
        403,
        { claim: 'token_hash' },
        params.version
      ),
    };
  }

  const token_hash = tokenHashRaw.trim();
  if (!isHexSha256(token_hash)) {
    return {
      error: errorResponse(
        `${prefix}_CONTROL_CLAIM_INVALID`,
        `${prefix.toLowerCase()} token control-plane claim is invalid`,
        403,
        { claim: 'token_hash' },
        params.version
      ),
    };
  }

  const tokenScopeHashRaw = claims.token_scope_hash_b64u;
  if (!isNonEmptyString(tokenScopeHashRaw)) {
    return {
      error: errorResponse(
        `${prefix}_CONTROL_CLAIM_REQUIRED`,
        `${prefix.toLowerCase()} token is missing required control-plane claim`,
        403,
        { claim: 'token_scope_hash_b64u' },
        params.version
      ),
    };
  }

  const token_scope_hash_b64u = tokenScopeHashRaw.trim();
  if (!isSha256B64u(token_scope_hash_b64u)) {
    return {
      error: errorResponse(
        `${prefix}_CONTROL_CLAIM_INVALID`,
        `${prefix.toLowerCase()} token control-plane claim is invalid`,
        403,
        { claim: 'token_scope_hash_b64u' },
        params.version
      ),
    };
  }

  const tokenLane = parseScopedTokenLane(claims.token_lane);
  if (!tokenLane) {
    return {
      error: errorResponse(
        `${prefix}_CONTROL_CLAIM_REQUIRED`,
        `${prefix.toLowerCase()} token is missing required control-plane claim`,
        403,
        { claim: 'token_lane' },
        params.version
      ),
    };
  }

  const iat = typeof claims.iat === 'number' && Number.isFinite(claims.iat) ? Math.floor(claims.iat) : null;
  const exp = typeof claims.exp === 'number' && Number.isFinite(claims.exp) ? Math.floor(claims.exp) : null;
  if (iat === null || exp === null) {
    return {
      error: errorResponse(
        `${prefix}_CONTROL_CLAIM_REQUIRED`,
        `${prefix.toLowerCase()} token is missing required control-plane claim`,
        403,
        { claim: iat === null ? 'iat' : 'exp' },
        params.version
      ),
    };
  }

  if (exp <= iat) {
    return {
      error: errorResponse(
        `${prefix}_CONTROL_CLAIM_INVALID`,
        `${prefix.toLowerCase()} token control-plane claim is invalid`,
        403,
        { claim: 'exp' },
        params.version
      ),
    };
  }

  const paymentAccountDid = isNonEmptyString(claims.payment_account_did) ? claims.payment_account_did.trim() : null;
  if (paymentAccountDid && !paymentAccountDid.startsWith('did:')) {
    return {
      error: errorResponse(
        `${prefix}_CONTROL_CLAIM_INVALID`,
        `${prefix.toLowerCase()} token control-plane claim is invalid`,
        403,
        { claim: 'payment_account_did' },
        params.version
      ),
    };
  }

  return {
    token_hash,
    token_scope_hash_b64u,
    token_lane: tokenLane,
    payment_account_did: paymentAccountDid,
    iat,
    exp,
  };
}

async function introspectScopedToken(
  env: Env,
  token: string,
  version: string,
  params: {
    timeoutMs: number;
    upstreamInvalidCode: string;
    upstreamInvalidMessage: string;
    upstreamErrorCode: string;
    upstreamErrorPrefix: string;
    upstreamUnavailableCode: string;
  }
): Promise<{ data: ScopeIntrospectionResponse } | { error: Response }> {
  const baseUrl = resolveScopeBaseUrl(env);
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), params.timeoutMs);

  try {
    const response = await fetch(`${baseUrl}/v1/tokens/introspect`, {
      method: 'POST',
      headers: { 'content-type': 'application/json; charset=utf-8' },
      body: JSON.stringify({ token }),
      signal: controller.signal,
    });

    const text = await response.text();
    let payload: unknown = null;
    try {
      payload = text ? JSON.parse(text) : null;
    } catch {
      payload = null;
    }

    if (!response.ok) {
      if (response.status === 401 || response.status === 400) {
        const upstreamCode = isRecord(payload) && isNonEmptyString(payload.error) ? payload.error.trim() : null;
        return {
          error: errorResponse(
            params.upstreamInvalidCode,
            params.upstreamInvalidMessage,
            401,
            upstreamCode ? { upstream_error: upstreamCode } : undefined,
            version
          ),
        };
      }

      return {
        error: errorResponse(
          params.upstreamErrorCode,
          `${params.upstreamErrorPrefix} ${response.status}`,
          502,
          undefined,
          version
        ),
      };
    }

    if (!isRecord(payload) || typeof payload.active !== 'boolean') {
      return {
        error: errorResponse(
          params.upstreamErrorCode,
          `${params.upstreamErrorPrefix} invalid payload`,
          502,
          undefined,
          version
        ),
      };
    }

    return { data: payload as unknown as ScopeIntrospectionResponse };
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return {
      error: errorResponse(params.upstreamUnavailableCode, message, 502, undefined, version),
    };
  } finally {
    clearTimeout(timeoutId);
  }
}

async function introspectRequesterToken(
  env: Env,
  token: string,
  version: string
): Promise<{ data: ScopeIntrospectionResponse } | { error: Response }> {
  return introspectScopedToken(env, token, version, {
    timeoutMs: resolveRequesterAuthTimeoutMs(env),
    upstreamInvalidCode: 'REQUESTER_TOKEN_INVALID',
    upstreamInvalidMessage: 'Requester scoped token is invalid or expired',
    upstreamErrorCode: 'REQUESTER_AUTH_UPSTREAM_ERROR',
    upstreamErrorPrefix: 'Requester token introspection failed with status',
    upstreamUnavailableCode: 'REQUESTER_AUTH_UPSTREAM_UNAVAILABLE',
  });
}

async function introspectWorkerToken(
  env: Env,
  token: string,
  version: string
): Promise<{ data: ScopeIntrospectionResponse } | { error: Response }> {
  return introspectScopedToken(env, token, version, {
    timeoutMs: resolveWorkerAuthTimeoutMs(env),
    upstreamInvalidCode: 'WORKER_TOKEN_INVALID',
    upstreamInvalidMessage: 'Worker scoped token is invalid or expired',
    upstreamErrorCode: 'WORKER_AUTH_UPSTREAM_ERROR',
    upstreamErrorPrefix: 'Worker token introspection failed with status',
    upstreamUnavailableCode: 'WORKER_AUTH_UPSTREAM_UNAVAILABLE',
  });
}

async function validateRequesterSensitiveTransition(
  env: Env,
  version: string,
  params: {
    auth: RequesterAuthContext;
    transition: 'post_bounty' | 'approve_bounty' | 'reject_bounty';
  }
): Promise<{ evidence: Record<string, unknown> } | { error: Response }> {
  if (params.auth.auth_mode !== 'scoped_token' || !isNonEmptyString(params.auth.bearer_token)) {
    return {
      error: errorResponse(
        'SENSITIVE_TRANSITION_REQUIRES_SCOPED_TOKEN',
        'Sensitive transitions require scoped requester token auth',
        403,
        undefined,
        version
      ),
    };
  }

  const baseUrl = resolveScopeBaseUrl(env);
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), resolveRequesterAuthTimeoutMs(env));

  try {
    const response = await fetch(`${baseUrl}/v1/tokens/introspect/matrix`, {
      method: 'POST',
      headers: { 'content-type': 'application/json; charset=utf-8' },
      body: JSON.stringify({ token: params.auth.bearer_token }),
      signal: controller.signal,
    });

    const text = await response.text();
    let payload: unknown = null;
    try {
      payload = text ? JSON.parse(text) : null;
    } catch {
      payload = null;
    }

    if (!response.ok) {
      if (response.status === 401 || response.status === 400) {
        const upstreamCode = isRecord(payload) && isNonEmptyString(payload.error) ? payload.error.trim() : null;
        return {
          error: errorResponse(
            'REQUESTER_SENSITIVE_AUTH_REVALIDATION_FAILED',
            'Requester sensitive-transition token revalidation failed',
            401,
            upstreamCode ? { upstream_error: upstreamCode } : undefined,
            version
          ),
        };
      }

      return {
        error: errorResponse(
          'REQUESTER_AUTH_UPSTREAM_ERROR',
          `Requester sensitive-transition token revalidation failed with status ${response.status}`,
          502,
          undefined,
          version
        ),
      };
    }

    if (!isRecord(payload) || typeof payload.active !== 'boolean') {
      return {
        error: errorResponse(
          'REQUESTER_AUTH_UPSTREAM_ERROR',
          'Requester sensitive-transition revalidation returned invalid payload',
          502,
          undefined,
          version
        ),
      };
    }

    const active = payload.active;
    const revoked = payload.revoked === true;
    if (!active || revoked) {
      return {
        error: errorResponse(
          'REQUESTER_SENSITIVE_AUTH_REVALIDATION_FAILED',
          'Requester token is inactive or revoked for sensitive transition',
          401,
          {
            active,
            revoked,
            transition: params.transition,
            token_hash: isNonEmptyString(payload.token_hash) ? payload.token_hash.trim() : null,
            upstream_error: isNonEmptyString(payload.error) ? payload.error.trim() : null,
          },
          version
        ),
      };
    }

    const matrixTokenHash = isNonEmptyString(payload.token_hash) ? payload.token_hash.trim() : null;
    if (matrixTokenHash && params.auth.token_hash && matrixTokenHash !== params.auth.token_hash) {
      return {
        error: errorResponse(
          'REQUESTER_CONTROL_BINDING_MISMATCH',
          'Requester token hash mismatch between introspection and matrix revalidation',
          403,
          {
            token_hash: params.auth.token_hash,
            matrix_token_hash: matrixTokenHash,
          },
          version
        ),
      };
    }

    const checked_at = new Date().toISOString();
    return {
      evidence: {
        transition: params.transition,
        checked_at,
        active,
        revoked,
        token_hash: matrixTokenHash,
        matrix: isRecord(payload.matrix) ? payload.matrix : null,
      },
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return {
      error: errorResponse('REQUESTER_AUTH_UPSTREAM_UNAVAILABLE', message, 502, undefined, version),
    };
  } finally {
    clearTimeout(timeoutId);
  }
}

function isSensitiveRequesterAction(action: RequesterAuthAction): boolean {
  return action === 'post_bounty' || action === 'approve_bounty' || action === 'reject_bounty';
}

function buildArenaDeskRequesterAuthContext(requesterDid: string): RequesterAuthContext {
  return {
    requester_did: requesterDid,
    auth_mode: 'legacy_admin_header',
    token_hash: null,
    scope: [
      REQUESTER_AUTH_SCOPE_BY_ACTION.post_bounty,
      REQUESTER_AUTH_SCOPE_BY_ACTION.approve_bounty,
      REQUESTER_AUTH_SCOPE_BY_ACTION.reject_bounty,
      REQUESTER_AUTH_SCOPE_BY_ACTION.read_submission,
    ],
    aud: [],
    token_scope_hash_b64u: null,
    token_lane: null,
    payment_account_did: requesterDid,
    delegation_id: null,
    delegator_did: null,
    delegate_did: null,
    iat: null,
    exp: null,
    bearer_token: null,
  };
}

async function requireRequesterAuth(
  request: Request,
  env: Env,
  version: string,
  params: {
    action: RequesterAuthAction;
    requester_did_hint?: string | null;
    enforce_sensitive_transition?: boolean;
  }
): Promise<{ auth: RequesterAuthContext } | { error: Response }> {
  const bearerToken = getBearerToken(request.headers.get('authorization'));
  const compatLegacyEnabled = resolveRequesterAuthCompatLegacy(env);
  const enforceSensitiveTransition = params.enforce_sensitive_transition ?? isSensitiveRequesterAction(params.action);

  const useLegacyCompatPath =
    compatLegacyEnabled &&
    isAdminAuthorized(request, env) &&
    isNonEmptyString(request.headers.get('x-requester-did'));

  if (bearerToken && !useLegacyCompatPath) {
    const introspection = await introspectRequesterToken(env, bearerToken, version);
    if ('error' in introspection) return introspection;

    const data = introspection.data;
    if (!data.active) {
      return {
        error: errorResponse('REQUESTER_TOKEN_INVALID', 'Requester scoped token is inactive', 401, undefined, version),
      };
    }

    const requesterTokenSub = isNonEmptyString(data.sub) ? data.sub.trim() : null;
    if (!requesterTokenSub || !requesterTokenSub.startsWith('did:')) {
      return {
        error: errorResponse('REQUESTER_SUB_INVALID', 'Requester token subject must be a DID', 401, undefined, version),
      };
    }

    const delegation_id = isNonEmptyString(data.delegation_id) ? data.delegation_id.trim() : null;
    const delegator_did = isNonEmptyString(data.delegator_did) ? data.delegator_did.trim() : null;
    const delegate_did = isNonEmptyString(data.delegate_did) ? data.delegate_did.trim() : null;
    const delegation_policy_hash_b64u = isNonEmptyString(data.delegation_policy_hash_b64u)
      ? data.delegation_policy_hash_b64u.trim()
      : null;
    const delegation_spend_cap_minor = isNonEmptyString(data.delegation_spend_cap_minor)
      ? data.delegation_spend_cap_minor.trim()
      : null;
    const delegation_expires_at =
      typeof data.delegation_expires_at === 'number' && Number.isFinite(data.delegation_expires_at)
        ? Math.floor(data.delegation_expires_at)
        : null;

    if (
      delegation_id ||
      delegator_did ||
      delegate_did ||
      delegation_policy_hash_b64u ||
      delegation_spend_cap_minor ||
      delegation_expires_at !== null
    ) {
      if (!delegation_id || !delegator_did || !delegate_did) {
        return {
          error: errorResponse(
            'REQUESTER_DELEGATION_BINDING_INVALID',
            'Delegated requester token requires delegation_id, delegator_did, and delegate_did',
            401,
            undefined,
            version
          ),
        };
      }

      if (delegate_did !== requesterTokenSub) {
        return {
          error: errorResponse(
            'REQUESTER_DELEGATION_BINDING_INVALID',
            'delegate_did must match requester token subject',
            401,
            { delegate_did, requester_sub: requesterTokenSub },
            version
          ),
        };
      }

      if (delegation_spend_cap_minor && !/^[0-9]+$/.test(delegation_spend_cap_minor)) {
        return {
          error: errorResponse(
            'REQUESTER_DELEGATION_BINDING_INVALID',
            'delegation_spend_cap_minor claim is invalid',
            401,
            undefined,
            version
          ),
        };
      }

      if (delegation_expires_at !== null && delegation_expires_at <= Math.floor(Date.now() / 1000)) {
        return {
          error: errorResponse(
            'REQUESTER_DELEGATION_EXPIRED',
            'Delegated requester token has expired delegation binding',
            401,
            { delegation_expires_at },
            version
          ),
        };
      }
    }

    const requester_did = delegation_id ? delegator_did : requesterTokenSub;
    if (!requester_did) {
      return {
        error: errorResponse('REQUESTER_SUB_INVALID', 'Requester token subject must be a DID', 401, undefined, version),
      };
    }

    const requesterHint = params.requester_did_hint?.trim();
    if (requesterHint && requesterHint !== requester_did) {
      return {
        error: errorResponse(
          'REQUESTER_SUB_MISMATCH',
          'requester_did does not match effective requester DID for this token',
          401,
          { requester_did, requested_requester_did: requesterHint },
          version
        ),
      };
    }

    const controlClaims = validateControlPlaneTokenContract({
      actor: 'REQUESTER',
      introspection: data,
      version,
    });
    if ('error' in controlClaims) return controlClaims;

    const scope = parseTokenScopeClaim(data.scope);
    if (!hasRequesterScope(scope, params.action)) {
      return {
        error: errorResponse(
          'REQUESTER_SCOPE_REQUIRED',
          'Requester token does not include the required scope for this action',
          403,
          { required_scope: REQUESTER_AUTH_SCOPE_BY_ACTION[params.action], scope },
          version
        ),
      };
    }

    const requiredAudience = resolveRequesterAuthRequiredAudience(env);
    const aud = parseTokenAudClaim(data.aud);
    if (!aud.includes(requiredAudience)) {
      return {
        error: errorResponse(
          'REQUESTER_AUDIENCE_REQUIRED',
          'Requester token audience does not include clawbounties',
          403,
          { required_audience: requiredAudience, aud },
          version
        ),
      };
    }

    const expectedScopeHash = await computeTokenScopeHashB64uV1({
      sub: requesterTokenSub,
      aud,
      scope,
      owner_ref: isNonEmptyString(data.owner_ref) ? data.owner_ref.trim() : undefined,
      owner_did: isNonEmptyString(data.owner_did) ? data.owner_did.trim() : undefined,
      controller_did: isNonEmptyString(data.controller_did) ? data.controller_did.trim() : undefined,
      agent_did: isNonEmptyString(data.agent_did) ? data.agent_did.trim() : undefined,
      policy_hash_b64u: isNonEmptyString(data.policy_hash_b64u) ? data.policy_hash_b64u.trim() : undefined,
      control_plane_policy_hash_b64u: isNonEmptyString(data.control_plane_policy_hash_b64u)
        ? data.control_plane_policy_hash_b64u.trim()
        : undefined,
      payment_account_did: isNonEmptyString(data.payment_account_did) ? data.payment_account_did.trim() : undefined,
      spend_cap: typeof data.spend_cap === 'number' && Number.isFinite(data.spend_cap) ? data.spend_cap : undefined,
      mission_id: isNonEmptyString(data.mission_id) ? data.mission_id.trim() : undefined,
      delegation_id: delegation_id ?? undefined,
      delegator_did: delegator_did ?? undefined,
      delegate_did: delegate_did ?? undefined,
      delegation_policy_hash_b64u: delegation_policy_hash_b64u ?? undefined,
      delegation_spend_cap_minor: delegation_spend_cap_minor ?? undefined,
      delegation_expires_at: delegation_expires_at ?? undefined,
    });

    if (controlClaims.token_scope_hash_b64u !== expectedScopeHash) {
      return {
        error: errorResponse(
          'REQUESTER_CONTROL_BINDING_MISMATCH',
          'Requester token scope hash does not match deterministic control-plane contract',
          403,
          {
            claim: 'token_scope_hash_b64u',
            expected_token_scope_hash_b64u: expectedScopeHash,
            token_scope_hash_b64u: controlClaims.token_scope_hash_b64u,
          },
          version
        ),
      };
    }

    if (enforceSensitiveTransition) {
      if (!controlClaims.payment_account_did) {
        return {
          error: errorResponse(
            'REQUESTER_CONTROL_CLAIM_REQUIRED',
            'Requester token is missing required control-plane claim',
            403,
            { claim: 'payment_account_did' },
            version
          ),
        };
      }

      const expectedPaymentDid = delegation_id ? delegator_did : requester_did;
      if (!expectedPaymentDid) {
        return {
          error: errorResponse(
            'REQUESTER_CONTROL_BINDING_MISMATCH',
            'Requester token effective payment binding is invalid',
            403,
            { claim: 'payment_account_did' },
            version
          ),
        };
      }

      if (controlClaims.payment_account_did !== expectedPaymentDid) {
        return {
          error: errorResponse(
            'REQUESTER_CONTROL_BINDING_MISMATCH',
            delegation_id
              ? 'Requester payment_account_did must match delegator_did for delegated sensitive transitions'
              : 'Requester payment_account_did must match requester token subject for sensitive transitions',
            403,
            {
              claim: 'payment_account_did',
              payment_account_did: controlClaims.payment_account_did,
              expected_payment_account_did: expectedPaymentDid,
              requester_did,
              delegation_id,
              delegator_did,
              delegate_did,
              requester_sub: requesterTokenSub,
            },
            version
          ),
        };
      }
    }

    return {
      auth: {
        requester_did,
        auth_mode: 'scoped_token',
        token_hash: controlClaims.token_hash,
        scope,
        aud,
        token_scope_hash_b64u: controlClaims.token_scope_hash_b64u,
        token_lane: controlClaims.token_lane,
        payment_account_did: controlClaims.payment_account_did,
        delegation_id,
        delegator_did,
        delegate_did,
        iat: controlClaims.iat,
        exp: controlClaims.exp,
        bearer_token: bearerToken,
      },
    };
  }

  if (!compatLegacyEnabled) {
    return {
      error: errorResponse(
        'REQUESTER_TOKEN_REQUIRED',
        'Missing requester scoped token. Provide Authorization: Bearer <requester CST/JWT>.',
        401,
        undefined,
        version
      ),
    };
  }

  if (enforceSensitiveTransition) {
    return {
      error: errorResponse(
        'SENSITIVE_TRANSITION_REQUIRES_SCOPED_TOKEN',
        'Sensitive transitions require scoped requester token auth (legacy compat path forbidden)',
        403,
        undefined,
        version
      ),
    };
  }

  const adminError = requireAdmin(request, env, version);
  if (adminError) return { error: adminError };

  const requester = requireRequesterDidLegacy(request, version);
  if ('error' in requester) return requester;

  const requesterHint = params.requester_did_hint?.trim();
  if (requesterHint && requesterHint !== requester.requester_did) {
    return {
      error: errorResponse(
        'REQUESTER_SUB_MISMATCH',
        'requester_did does not match legacy requester header',
        401,
        { requester_did: requester.requester_did, requested_requester_did: requesterHint },
        version
      ),
    };
  }

  return {
    auth: {
      requester_did: requester.requester_did,
      auth_mode: 'legacy_admin_header',
      token_hash: null,
      scope: [REQUESTER_AUTH_SCOPE_BY_ACTION[params.action]],
      aud: [],
      token_scope_hash_b64u: null,
      token_lane: null,
      payment_account_did: null,
      delegation_id: null,
      delegator_did: null,
      delegate_did: null,
      iat: null,
      exp: null,
      bearer_token: null,
    },
  };
}

async function resolveSubmissionViewerContext(
  request: Request,
  env: Env,
  version: string,
  params?: {
    requester_did_hint?: string | null;
  }
): Promise<SubmissionViewerContextResult> {
  if (isAdminAuthorized(request, env)) {
    return { ok: true, context: { kind: 'admin' } };
  }

  const token = getBearerToken(request.headers.get('authorization'));
  if (token) {
    if (looksLikeJwtToken(token)) {
      const requesterAuth = await requireRequesterAuth(request, env, version, {
        action: 'read_submission',
        requester_did_hint: params?.requester_did_hint ?? null,
        enforce_sensitive_transition: false,
      });
      if (!('error' in requesterAuth)) {
        return {
          ok: true,
          context: {
            kind: 'requester',
            requester_did: requesterAuth.auth.requester_did,
            auth: requesterAuth.auth,
          },
        };
      }

      const workerAuth = await requireWorker(request, env, version, {
        action: 'read_submission',
      });
      if (!('error' in workerAuth)) {
        return { ok: true, context: { kind: 'worker', worker: workerAuth.worker } };
      }

      return { ok: false, error: requesterAuth.error };
    }

    const workerAuth = await requireWorker(request, env, version, {
      action: 'read_submission',
    });
    if ('error' in workerAuth) {
      return { ok: false, error: workerAuth.error };
    }

    return { ok: true, context: { kind: 'worker', worker: workerAuth.worker } };
  }

  if (isNonEmptyString(request.headers.get('x-requester-did'))) {
    const requesterDidHint = request.headers.get('x-requester-did')?.trim() ?? null;
    const authResult = await requireRequesterAuth(request, env, version, {
      action: 'read_submission',
      requester_did_hint: requesterDidHint || params?.requester_did_hint || null,
    });
    if ('error' in authResult) {
      return { ok: false, error: authResult.error };
    }

    return {
      ok: true,
      context: {
        kind: 'requester',
        requester_did: authResult.auth.requester_did,
        auth: authResult.auth,
      },
    };
  }

  return {
    ok: false,
    error: errorResponse(
      'UNAUTHORIZED',
      'Provide admin token, worker bearer token, or requester scoped token',
      401,
      undefined,
      version
    ),
  };
}

async function parseJsonBody(request: Request): Promise<unknown | null> {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

function resolveCutsBaseUrl(env: Env): string {
  const v = env.CUTS_BASE_URL?.trim();
  if (v && v.length > 0) return v;
  return 'https://clawcuts.com';
}

function resolveEscrowBaseUrl(env: Env): string {
  const v = env.ESCROW_BASE_URL?.trim();
  if (v && v.length > 0) return v;
  return 'https://clawescrow.com';
}

function resolveVerifyBaseUrl(env: Env): string {
  const v = env.VERIFY_BASE_URL?.trim();
  if (v && v.length > 0) return v;
  return 'https://clawverify.com';
}

function resolveScopeBaseUrl(env: Env): string {
  const v = env.SCOPE_BASE_URL?.trim();
  if (v && v.length > 0) return v;
  return 'https://clawscope.com';
}

function resolveClawrepBaseUrl(env: Env): string {
  const v = env.CLAWREP_BASE_URL?.trim();
  if (v && v.length > 0) return v;
  return 'https://clawrep.com';
}

function resolveTestHarnessBaseUrl(env: Env): string | null {
  const v = env.TEST_HARNESS_BASE_URL?.trim();
  if (v && v.length > 0) return v;
  return null;
}

function resolveTrialsBaseUrl(env: Env): string | null {
  const v = env.TRIALS_BASE_URL?.trim();
  if (v && v.length > 0) return v;

  const harness = resolveTestHarnessBaseUrl(env);
  if (harness) return harness;

  return null;
}

function resolveTestHarnessTimeoutMs(env: Env): number {
  const raw = env.TEST_HARNESS_TIMEOUT_MS?.trim();
  if (!raw) return 60000;

  const n = Number(raw);
  if (!Number.isFinite(n)) return 60000;

  const timeout = Math.floor(n);
  if (timeout < 1000) return 60000;
  if (timeout > 5 * 60 * 1000) return 5 * 60 * 1000;
  return timeout;
}

function resolveWorkerTokenTtlSeconds(env: Env): number {
  const raw = env.WORKER_TOKEN_TTL_SECONDS?.trim();
  if (!raw) return 24 * 60 * 60;

  const n = Number(raw);
  if (!Number.isFinite(n)) return 24 * 60 * 60;

  const ttl = Math.floor(n);
  // Refuse absurd values; keep the surface predictable.
  if (ttl < 60) return 24 * 60 * 60;
  if (ttl > 30 * 24 * 60 * 60) return 24 * 60 * 60;

  return ttl;
}

function generateWorkerToken(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

// ---------------------------------------------------------------------------
// clawscope (CST issuance) — used for CWC job-scoped tokens
// ---------------------------------------------------------------------------

const CWC_JOB_CST_AUD = 'clawproxy.com';
const CWC_JOB_CST_SCOPE: string[] = ['proxy:call', 'clawproxy:call'];
const CWC_JOB_CST_TTL_SEC = 60 * 60;

type IssuedCst = {
  token: string;
  token_scope_hash_b64u: string;
  policy_hash_b64u?: string;
  mission_id?: string;
  iat?: number;
  exp?: number;
};

type TokenScopeHashInputV1 = {
  token_version: '1';
  sub: string;
  aud: string[];
  scope: string[];
  owner_ref?: string;
  owner_did?: string;
  controller_did?: string;
  agent_did?: string;
  policy_hash_b64u?: string;
  control_plane_policy_hash_b64u?: string;
  payment_account_did?: string;
  spend_cap?: number;
  mission_id?: string;
  delegation_id?: string;
  delegator_did?: string;
  delegate_did?: string;
  delegation_policy_hash_b64u?: string;
  delegation_spend_cap_minor?: string;
  delegation_expires_at?: number;
};

function normalizeStringList(values: string[]): string[] {
  const out: string[] = [];

  for (const v of values) {
    const s = v.trim();
    if (s.length === 0) continue;
    out.push(s);
  }

  return Array.from(new Set(out)).sort();
}

function normalizeAud(aud: string | string[]): string[] {
  const raw = typeof aud === 'string' ? [aud] : aud;
  return normalizeStringList(raw);
}

function normalizeScope(scope: string[]): string[] {
  return normalizeStringList(scope);
}

async function computeTokenScopeHashB64uV1(input: {
  sub: string;
  aud: string | string[];
  scope: string[];
  owner_ref?: string;
  owner_did?: string;
  controller_did?: string;
  agent_did?: string;
  policy_hash_b64u?: string;
  control_plane_policy_hash_b64u?: string;
  payment_account_did?: string;
  spend_cap?: number;
  mission_id?: string;
  delegation_id?: string;
  delegator_did?: string;
  delegate_did?: string;
  delegation_policy_hash_b64u?: string;
  delegation_spend_cap_minor?: string;
  delegation_expires_at?: number;
}): Promise<string> {
  const out: TokenScopeHashInputV1 = {
    token_version: '1',
    sub: input.sub.trim(),
    aud: normalizeAud(input.aud),
    scope: normalizeScope(input.scope),
  };

  if (typeof input.owner_ref === 'string' && input.owner_ref.trim().length > 0) {
    out.owner_ref = input.owner_ref.trim();
  }

  if (typeof input.owner_did === 'string' && input.owner_did.trim().length > 0) {
    out.owner_did = input.owner_did.trim();
  }

  if (typeof input.controller_did === 'string' && input.controller_did.trim().length > 0) {
    out.controller_did = input.controller_did.trim();
  }

  if (typeof input.agent_did === 'string' && input.agent_did.trim().length > 0) {
    out.agent_did = input.agent_did.trim();
  }

  if (typeof input.policy_hash_b64u === 'string' && input.policy_hash_b64u.trim().length > 0) {
    out.policy_hash_b64u = input.policy_hash_b64u.trim();
  }

  if (
    typeof input.control_plane_policy_hash_b64u === 'string' &&
    input.control_plane_policy_hash_b64u.trim().length > 0
  ) {
    out.control_plane_policy_hash_b64u = input.control_plane_policy_hash_b64u.trim();
  }

  if (typeof input.payment_account_did === 'string' && input.payment_account_did.trim().length > 0) {
    out.payment_account_did = input.payment_account_did.trim();
  }

  if (typeof input.spend_cap === 'number' && Number.isFinite(input.spend_cap) && input.spend_cap >= 0) {
    out.spend_cap = input.spend_cap;
  }

  if (typeof input.mission_id === 'string' && input.mission_id.trim().length > 0) {
    out.mission_id = input.mission_id.trim();
  }

  if (typeof input.delegation_id === 'string' && input.delegation_id.trim().length > 0) {
    out.delegation_id = input.delegation_id.trim();
  }

  if (typeof input.delegator_did === 'string' && input.delegator_did.trim().length > 0) {
    out.delegator_did = input.delegator_did.trim();
  }

  if (typeof input.delegate_did === 'string' && input.delegate_did.trim().length > 0) {
    out.delegate_did = input.delegate_did.trim();
  }

  if (
    typeof input.delegation_policy_hash_b64u === 'string' &&
    input.delegation_policy_hash_b64u.trim().length > 0
  ) {
    out.delegation_policy_hash_b64u = input.delegation_policy_hash_b64u.trim();
  }

  if (
    typeof input.delegation_spend_cap_minor === 'string' &&
    input.delegation_spend_cap_minor.trim().length > 0
  ) {
    out.delegation_spend_cap_minor = input.delegation_spend_cap_minor.trim();
  }

  if (
    typeof input.delegation_expires_at === 'number' &&
    Number.isFinite(input.delegation_expires_at)
  ) {
    out.delegation_expires_at = Math.floor(input.delegation_expires_at);
  }

  return sha256B64uUtf8(jcsCanonicalize(out));
}

async function issueCwcJobCst(
  env: Env,
  params: {
    worker_did: string;
    bounty_id: string;
    policy_hash_b64u: string;
  },
  version: string
): Promise<{ ok: true; value: IssuedCst } | { ok: false; error: Response }> {
  const adminKey = env.SCOPE_ADMIN_KEY?.trim();
  if (!adminKey) {
    return {
      ok: false,
      error: errorResponse(
        'SCOPE_NOT_CONFIGURED',
        'SCOPE_ADMIN_KEY is not configured (required for CWC job CST issuance)',
        503,
        undefined,
        version
      ),
    };
  }

  const url = `${resolveScopeBaseUrl(env)}/v1/tokens/issue`;

  let response: Response;
  try {
    response = await fetch(url, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${adminKey}`,
        'content-type': 'application/json; charset=utf-8',
      },
      body: JSON.stringify({
        sub: params.worker_did,
        aud: CWC_JOB_CST_AUD,
        scope: CWC_JOB_CST_SCOPE,
        policy_hash_b64u: params.policy_hash_b64u,
        mission_id: params.bounty_id,
        ttl_sec: CWC_JOB_CST_TTL_SEC,
      }),
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return {
      ok: false,
      error: errorResponse(
        'CWC_CST_ISSUE_FAILED',
        `Failed to call clawscope token issuer: ${message}`,
        502,
        undefined,
        version
      ),
    };
  }

  const text = await response.text();
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }

  if (!response.ok) {
    const details = isRecord(json) ? json : { raw: text };
    return {
      ok: false,
      error: errorResponse(
        'CWC_CST_ISSUE_FAILED',
        `clawscope /v1/tokens/issue returned HTTP ${response.status}`,
        502,
        { status: response.status, details },
        version
      ),
    };
  }

  if (!isRecord(json) || !isNonEmptyString(json.token) || !isNonEmptyString(json.token_scope_hash_b64u)) {
    return {
      ok: false,
      error: errorResponse(
        'CWC_CST_ISSUE_FAILED',
        'clawscope /v1/tokens/issue returned an invalid response',
        502,
        { raw: isRecord(json) ? json : text },
        version
      ),
    };
  }

  const token = json.token.trim();
  const token_scope_hash_b64u = json.token_scope_hash_b64u.trim();

  if (!isSha256B64u(token_scope_hash_b64u)) {
    return {
      ok: false,
      error: errorResponse(
        'CWC_CST_ISSUE_FAILED',
        'clawscope returned an invalid token_scope_hash_b64u',
        502,
        { token_scope_hash_b64u },
        version
      ),
    };
  }

  const iat = typeof json.iat === 'number' && Number.isFinite(json.iat) ? Math.floor(json.iat) : undefined;
  const exp = typeof json.exp === 'number' && Number.isFinite(json.exp) ? Math.floor(json.exp) : undefined;

  const value: IssuedCst = {
    token,
    token_scope_hash_b64u,
    policy_hash_b64u: isNonEmptyString(json.policy_hash_b64u) ? json.policy_hash_b64u.trim() : undefined,
    mission_id: params.bounty_id,
    iat,
    exp,
  };

  return { ok: true, value };
}

async function issueJobCst(
  env: Env,
  params: {
    worker_did: string;
    bounty_id: string;
    policy_hash_b64u?: string;
  },
  version: string
): Promise<{ ok: true; value: IssuedCst } | { ok: false; error: Response }> {
  const adminKey = env.SCOPE_ADMIN_KEY?.trim();
  if (!adminKey) {
    return {
      ok: false,
      error: errorResponse(
        'SCOPE_NOT_CONFIGURED',
        'SCOPE_ADMIN_KEY is not configured (required for job CST issuance)',
        503,
        undefined,
        version
      ),
    };
  }

  const url = `${resolveScopeBaseUrl(env)}/v1/tokens/issue`;

  const body: Record<string, unknown> = {
    sub: params.worker_did,
    aud: CWC_JOB_CST_AUD,
    scope: CWC_JOB_CST_SCOPE,
    mission_id: params.bounty_id,
    ttl_sec: CWC_JOB_CST_TTL_SEC,
  };

  if (typeof params.policy_hash_b64u === 'string' && params.policy_hash_b64u.trim().length > 0) {
    body.policy_hash_b64u = params.policy_hash_b64u.trim();
  }

  let response: Response;
  try {
    response = await fetch(url, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${adminKey}`,
        'content-type': 'application/json; charset=utf-8',
      },
      body: JSON.stringify(body),
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return {
      ok: false,
      error: errorResponse('JOB_CST_ISSUE_FAILED', `Failed to call clawscope token issuer: ${message}`, 502, undefined, version),
    };
  }

  const text = await response.text();
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }

  if (!response.ok) {
    const details = isRecord(json) ? json : { raw: text };
    return {
      ok: false,
      error: errorResponse(
        'JOB_CST_ISSUE_FAILED',
        `clawscope /v1/tokens/issue returned HTTP ${response.status}`,
        502,
        { status: response.status, details },
        version
      ),
    };
  }

  if (!isRecord(json) || !isNonEmptyString(json.token) || !isNonEmptyString(json.token_scope_hash_b64u)) {
    return {
      ok: false,
      error: errorResponse(
        'JOB_CST_ISSUE_FAILED',
        'clawscope /v1/tokens/issue returned an invalid response',
        502,
        { raw: isRecord(json) ? json : text },
        version
      ),
    };
  }

  const token = json.token.trim();
  const token_scope_hash_b64u = json.token_scope_hash_b64u.trim();

  if (!isSha256B64u(token_scope_hash_b64u)) {
    return {
      ok: false,
      error: errorResponse(
        'JOB_CST_ISSUE_FAILED',
        'clawscope returned an invalid token_scope_hash_b64u',
        502,
        { token_scope_hash_b64u },
        version
      ),
    };
  }

  const iat = typeof json.iat === 'number' && Number.isFinite(json.iat) ? Math.floor(json.iat) : undefined;
  const exp = typeof json.exp === 'number' && Number.isFinite(json.exp) ? Math.floor(json.exp) : undefined;

  const value: IssuedCst = {
    token,
    token_scope_hash_b64u,
    policy_hash_b64u: isNonEmptyString(json.policy_hash_b64u) ? json.policy_hash_b64u.trim() : undefined,
    mission_id: params.bounty_id,
    iat,
    exp,
  };

  return { ok: true, value };
}

async function cutsSimulateFees(
  env: Env,
  params: {
    requester_did: string;
    amount_minor: string;
    closure_type: ClosureType;
    is_code_bounty: boolean;
    min_proof_tier: ProofTier;
    tags: string[];
  }
): Promise<CutsSimulateResponse> {
  const url = `${resolveCutsBaseUrl(env)}/v1/fees/simulate`;
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json; charset=utf-8',
    },
    body: JSON.stringify({
      product: 'clawbounties',
      policy_id: 'bounties_v1',
      amount_minor: params.amount_minor,
      currency: 'USD',
      params: {
        requester_did: params.requester_did,
        is_code_bounty: params.is_code_bounty,
        closure_type: params.closure_type,
        min_proof_tier: params.min_proof_tier,
        tags: params.tags,
      },
    }),
  });

  const text = await response.text();
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }

  if (!response.ok) {
    const details = isRecord(json) ? json : { raw: text };
    throw new Error(`CUTS_FAILED:${response.status}:${JSON.stringify(details)}`);
  }

  if (!isRecord(json) || !isRecord(json.policy) || !isRecord(json.quote)) {
    throw new Error('CUTS_INVALID_RESPONSE');
  }

  const policy = json.policy;
  const quote = json.quote;

  if (!isNonEmptyString(policy.id) || !isNonEmptyString(policy.version) || !isNonEmptyString(policy.hash_b64u)) {
    throw new Error('CUTS_INVALID_RESPONSE');
  }

  if (!isNonEmptyString(quote.principal_minor) || !isNonEmptyString(quote.buyer_total_minor) || !isNonEmptyString(quote.worker_net_minor)) {
    throw new Error('CUTS_INVALID_RESPONSE');
  }

  if (!Array.isArray(quote.fees)) {
    throw new Error('CUTS_INVALID_RESPONSE');
  }

  const fees: FeeItem[] = [];
  for (const item of quote.fees) {
    if (!isRecord(item)) throw new Error('CUTS_INVALID_RESPONSE');
    if (!isNonEmptyString(item.kind)) throw new Error('CUTS_INVALID_RESPONSE');
    if (item.payer !== 'buyer' && item.payer !== 'worker') throw new Error('CUTS_INVALID_RESPONSE');
    if (!isNonEmptyString(item.amount_minor)) throw new Error('CUTS_INVALID_RESPONSE');
    if (typeof item.rate_bps !== 'number' || !Number.isFinite(item.rate_bps)) throw new Error('CUTS_INVALID_RESPONSE');
    if (!isNonEmptyString(item.min_fee_minor)) throw new Error('CUTS_INVALID_RESPONSE');
    if (typeof item.floor_applied !== 'boolean') throw new Error('CUTS_INVALID_RESPONSE');

    const normalized: FeeItem = {
      kind: item.kind.trim(),
      payer: item.payer,
      amount_minor: item.amount_minor.trim(),
      rate_bps: item.rate_bps,
      min_fee_minor: item.min_fee_minor.trim(),
      floor_applied: item.floor_applied,
    };

    if (isNonEmptyString(item.base_amount_minor)) {
      normalized.base_amount_minor = item.base_amount_minor.trim();
    }

    if (typeof item.discount_bps_applied === 'number' && Number.isFinite(item.discount_bps_applied)) {
      normalized.discount_bps_applied = item.discount_bps_applied;
    }

    if (isNonEmptyString(item.discount_minor)) {
      normalized.discount_minor = item.discount_minor.trim();
    }

    if (item.splits !== undefined) {
      if (!Array.isArray(item.splits)) throw new Error('CUTS_INVALID_RESPONSE');
      const splits: FeeSplit[] = [];

      for (const splitRaw of item.splits) {
        if (!isRecord(splitRaw)) throw new Error('CUTS_INVALID_RESPONSE');
        if (splitRaw.kind !== 'platform' && splitRaw.kind !== 'referral') throw new Error('CUTS_INVALID_RESPONSE');
        if (!isNonEmptyString(splitRaw.account)) throw new Error('CUTS_INVALID_RESPONSE');
        if (splitRaw.bucket !== 'A' && splitRaw.bucket !== 'F') throw new Error('CUTS_INVALID_RESPONSE');
        if (!isNonEmptyString(splitRaw.amount_minor)) throw new Error('CUTS_INVALID_RESPONSE');

        const split: FeeSplit = {
          kind: splitRaw.kind,
          account: splitRaw.account.trim(),
          bucket: splitRaw.bucket,
          amount_minor: splitRaw.amount_minor.trim(),
        };

        if (isNonEmptyString(splitRaw.referrer_did)) {
          split.referrer_did = splitRaw.referrer_did.trim();
        }
        if (isNonEmptyString(splitRaw.referral_code)) {
          split.referral_code = splitRaw.referral_code.trim();
        }

        splits.push(split);
      }

      if (splits.length > 0) {
        normalized.splits = splits;
      }
    }

    fees.push(normalized);
  }

  return {
    policy: {
      id: policy.id.trim(),
      version: policy.version.trim(),
      hash_b64u: policy.hash_b64u.trim(),
    },
    quote: {
      principal_minor: quote.principal_minor.trim(),
      buyer_total_minor: quote.buyer_total_minor.trim(),
      worker_net_minor: quote.worker_net_minor.trim(),
      fees,
    },
  };
}

async function escrowCreateHold(
  env: Env,
  params: {
    idempotency_key: string;
    buyer_did: string;
    amount_minor: string;
    fee_quote: EscrowFeeQuoteSnapshot;
    metadata: Record<string, unknown>;
  }
): Promise<{ escrow_id: string }> {
  if (!env.ESCROW_SERVICE_KEY || env.ESCROW_SERVICE_KEY.trim().length === 0) {
    throw new Error('ESCROW_SERVICE_KEY_NOT_CONFIGURED');
  }

  const url = `${resolveEscrowBaseUrl(env)}/v1/escrows`;
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json; charset=utf-8',
      authorization: `Bearer ${env.ESCROW_SERVICE_KEY}`,
    },
    body: JSON.stringify({
      idempotency_key: params.idempotency_key,
      buyer_did: params.buyer_did,
      worker_did: null,
      currency: 'USD',
      amount_minor: params.amount_minor,
      fee_quote: params.fee_quote,
      metadata: params.metadata,
    }),
  });

  const text = await response.text();
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }

  if (!response.ok) {
    const details = isRecord(json) ? json : { raw: text };
    throw new Error(`ESCROW_FAILED:${response.status}:${JSON.stringify(details)}`);
  }

  if (!isRecord(json) || !isNonEmptyString(json.escrow_id)) {
    throw new Error('ESCROW_INVALID_RESPONSE');
  }

  return { escrow_id: json.escrow_id };
}

async function escrowAssignWorker(
  env: Env,
  params: {
    escrow_id: string;
    idempotency_key: string;
    worker_did: string;
  }
): Promise<{ escrow_id: string; status: string; worker_did: string }> {
  if (!env.ESCROW_SERVICE_KEY || env.ESCROW_SERVICE_KEY.trim().length === 0) {
    throw new Error('ESCROW_SERVICE_KEY_NOT_CONFIGURED');
  }

  const url = `${resolveEscrowBaseUrl(env)}/v1/escrows/${params.escrow_id}/assign`;
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json; charset=utf-8',
      authorization: `Bearer ${env.ESCROW_SERVICE_KEY}`,
    },
    body: JSON.stringify({
      idempotency_key: params.idempotency_key,
      worker_did: params.worker_did,
    }),
  });

  const text = await response.text();
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }

  if (!response.ok) {
    const details = isRecord(json) ? json : { raw: text };
    throw new Error(`ESCROW_FAILED:${response.status}:${JSON.stringify(details)}`);
  }

  if (!isRecord(json) || !isNonEmptyString(json.escrow_id) || !isNonEmptyString(json.status) || !isNonEmptyString(json.worker_did)) {
    throw new Error('ESCROW_INVALID_RESPONSE');
  }

  return { escrow_id: json.escrow_id.trim(), status: json.status.trim(), worker_did: json.worker_did.trim() };
}

async function escrowRelease(
  env: Env,
  params: {
    escrow_id: string;
    idempotency_key: string;
    approved_by: string;
    verification?: Record<string, unknown> | null;
  }
): Promise<EscrowReleaseResponse> {
  if (!env.ESCROW_SERVICE_KEY || env.ESCROW_SERVICE_KEY.trim().length === 0) {
    throw new Error('ESCROW_SERVICE_KEY_NOT_CONFIGURED');
  }

  const url = `${resolveEscrowBaseUrl(env)}/v1/escrows/${params.escrow_id}/release`;
  const body: Record<string, unknown> = {
    idempotency_key: params.idempotency_key,
    approved_by: params.approved_by,
  };
  if (params.verification !== undefined) {
    body.verification = params.verification;
  }

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json; charset=utf-8',
      authorization: `Bearer ${env.ESCROW_SERVICE_KEY}`,
    },
    body: JSON.stringify(body),
  });

  const text = await response.text();
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }

  if (!response.ok) {
    const details = isRecord(json) ? json : { raw: text };
    throw new Error(`ESCROW_FAILED:${response.status}:${JSON.stringify(details)}`);
  }

  if (!isRecord(json) || !isNonEmptyString(json.escrow_id) || !isNonEmptyString(json.status)) {
    throw new Error('ESCROW_INVALID_RESPONSE');
  }

  if (json.status !== 'released' || !isRecord(json.ledger_refs)) {
    throw new Error('ESCROW_INVALID_RESPONSE');
  }

  const ledgerRefs = json.ledger_refs as Record<string, unknown>;
  const workerTransfer = typeof ledgerRefs.worker_transfer === 'string' ? ledgerRefs.worker_transfer : null;
  const feeTransfers = Array.isArray(ledgerRefs.fee_transfers) ? ledgerRefs.fee_transfers : null;

  if (workerTransfer === null || !feeTransfers || !feeTransfers.every((item) => typeof item === 'string')) {
    throw new Error('ESCROW_INVALID_RESPONSE');
  }

  return {
    escrow_id: json.escrow_id.trim(),
    status: 'released',
    ledger_refs: {
      worker_transfer: workerTransfer,
      fee_transfers: feeTransfers as string[],
    },
  };
}

async function escrowDispute(
  env: Env,
  params: {
    escrow_id: string;
    idempotency_key: string;
    disputed_by: string;
    reason?: string | null;
  }
): Promise<EscrowDisputeResponse> {
  if (!env.ESCROW_SERVICE_KEY || env.ESCROW_SERVICE_KEY.trim().length === 0) {
    throw new Error('ESCROW_SERVICE_KEY_NOT_CONFIGURED');
  }

  const url = `${resolveEscrowBaseUrl(env)}/v1/escrows/${params.escrow_id}/dispute`;
  const body: Record<string, unknown> = {
    idempotency_key: params.idempotency_key,
    disputed_by: params.disputed_by,
  };
  if (params.reason) {
    body.reason = params.reason;
  }

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json; charset=utf-8',
      authorization: `Bearer ${env.ESCROW_SERVICE_KEY}`,
    },
    body: JSON.stringify(body),
  });

  const text = await response.text();
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }

  if (!response.ok) {
    const details = isRecord(json) ? json : { raw: text };
    throw new Error(`ESCROW_FAILED:${response.status}:${JSON.stringify(details)}`);
  }

  if (!isRecord(json) || !isNonEmptyString(json.escrow_id) || !isNonEmptyString(json.status)) {
    throw new Error('ESCROW_INVALID_RESPONSE');
  }

  if (json.status !== 'frozen' || !isNonEmptyString(json.dispute_window_ends_at)) {
    throw new Error('ESCROW_INVALID_RESPONSE');
  }

  return {
    escrow_id: json.escrow_id.trim(),
    status: 'frozen',
    dispute_window_ends_at: json.dispute_window_ends_at.trim(),
  };
}

async function escrowGet(env: Env, escrow_id: string): Promise<Record<string, unknown>> {
  if (!env.ESCROW_SERVICE_KEY || env.ESCROW_SERVICE_KEY.trim().length === 0) {
    throw new Error('ESCROW_SERVICE_KEY_NOT_CONFIGURED');
  }

  const url = `${resolveEscrowBaseUrl(env)}/v1/escrows/${escrow_id}`;
  const response = await fetch(url, {
    method: 'GET',
    headers: {
      authorization: `Bearer ${env.ESCROW_SERVICE_KEY}`,
    },
  });

  const text = await response.text();
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }

  if (!response.ok) {
    const details = isRecord(json) ? json : { raw: text };
    throw new Error(`ESCROW_FAILED:${response.status}:${JSON.stringify(details)}`);
  }

  if (!isRecord(json) || !isNonEmptyString(json.escrow_id) || !isNonEmptyString(json.status)) {
    throw new Error('ESCROW_INVALID_RESPONSE');
  }

  return json;
}

async function escrowListHeld(env: Env, limit = 200): Promise<Array<Record<string, unknown>>> {
  if (!env.ESCROW_SERVICE_KEY || env.ESCROW_SERVICE_KEY.trim().length === 0) {
    throw new Error('ESCROW_SERVICE_KEY_NOT_CONFIGURED');
  }

  const boundedLimit = Math.max(1, Math.min(limit, 500));
  const url = `${resolveEscrowBaseUrl(env)}/v1/escrows?status=held&limit=${boundedLimit}`;
  const response = await fetch(url, {
    method: 'GET',
    headers: {
      authorization: `Bearer ${env.ESCROW_SERVICE_KEY}`,
    },
  });

  const text = await response.text();
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }

  if (!response.ok) {
    const details = isRecord(json) ? json : { raw: text };
    throw new Error(`ESCROW_FAILED:${response.status}:${JSON.stringify(details)}`);
  }

  if (!isRecord(json) || !Array.isArray(json.escrows)) {
    throw new Error('ESCROW_INVALID_RESPONSE');
  }

  const escrows: Array<Record<string, unknown>> = [];
  for (const entry of json.escrows) {
    if (!isRecord(entry)) continue;
    escrows.push(entry);
  }
  return escrows;
}

async function escrowGetReleased(env: Env, escrow_id: string): Promise<EscrowReleaseResponse> {
  const json = await escrowGet(env, escrow_id);
  if (json.status !== 'released' || !isRecord(json.ledger_refs)) {
    throw new Error('ESCROW_INVALID_RESPONSE');
  }

  const escrowId = typeof json.escrow_id === 'string' ? json.escrow_id : null;
  if (!escrowId) {
    throw new Error('ESCROW_INVALID_RESPONSE');
  }

  const ledgerRefs = json.ledger_refs as Record<string, unknown>;
  const workerTransfer = typeof ledgerRefs.worker_transfer === 'string' ? ledgerRefs.worker_transfer : null;
  const feeTransfers = Array.isArray(ledgerRefs.fee_transfers) ? ledgerRefs.fee_transfers : null;

  if (workerTransfer === null || !feeTransfers || !feeTransfers.every((item) => typeof item === 'string')) {
    throw new Error('ESCROW_INVALID_RESPONSE');
  }

  return {
    escrow_id: escrowId.trim(),
    status: 'released',
    ledger_refs: {
      worker_transfer: workerTransfer,
      fee_transfers: feeTransfers as string[],
    },
  };
}

async function escrowGetDisputed(env: Env, escrow_id: string): Promise<EscrowDisputeResponse> {
  const json = await escrowGet(env, escrow_id);
  if (json.status !== 'frozen' || !isNonEmptyString(json.dispute_window_ends_at)) {
    throw new Error('ESCROW_INVALID_RESPONSE');
  }

  const escrowId = typeof json.escrow_id === 'string' ? json.escrow_id : null;
  const disputeWindow = typeof json.dispute_window_ends_at === 'string' ? json.dispute_window_ends_at : null;
  if (!escrowId || !disputeWindow) {
    throw new Error('ESCROW_INVALID_RESPONSE');
  }

  return {
    escrow_id: escrowId.trim(),
    status: 'frozen',
    dispute_window_ends_at: disputeWindow.trim(),
  };
}

async function trialsCreateCase(
  env: Env,
  params: {
    idempotency_key: string;
    source_system: string;
    source_ref: string;
    submission_id: string;
    escrow_id: string;
    requester_did: string;
    worker_did: string;
    opened_by: string;
    reason?: string | null;
    evidence: {
      proof_bundle_hash_b64u: string;
      receipt_refs: string[];
      artifact_refs: string[];
    };
  }
): Promise<TrialCaseSummary> {
  const baseUrl = resolveTrialsBaseUrl(env);
  if (!baseUrl) {
    throw new Error('TRIALS_BASE_URL_NOT_CONFIGURED');
  }

  const serviceKey = env.TRIALS_SERVICE_KEY?.trim();
  if (!serviceKey) {
    throw new Error('TRIALS_SERVICE_KEY_NOT_CONFIGURED');
  }

  const response = await fetch(`${baseUrl}/v1/trials/cases`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${serviceKey}`,
      'content-type': 'application/json; charset=utf-8',
    },
    body: JSON.stringify({
      idempotency_key: params.idempotency_key,
      source_system: params.source_system,
      source_ref: params.source_ref,
      submission_id: params.submission_id,
      escrow_id: params.escrow_id,
      requester_did: params.requester_did,
      worker_did: params.worker_did,
      opened_by: params.opened_by,
      reason: params.reason,
      evidence: params.evidence,
    }),
  });

  const text = await response.text();
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }

  if (!response.ok) {
    const details = isRecord(json) ? json : { raw: text };
    throw new Error(`TRIALS_FAILED:${response.status}:${JSON.stringify(details)}`);
  }

  if (!isRecord(json) || !isRecord(json.case) || !isRecord(json.case.judge) || !isRecord(json.case.timestamps)) {
    throw new Error('TRIALS_INVALID_RESPONSE');
  }

  const caseId = json.case.case_id;
  const status = json.case.status;
  const judgeDid = json.case.judge.judge_did;
  const openedAt = json.case.timestamps.opened_at;

  if (!isNonEmptyString(caseId) || !caseId.trim().startsWith('trc_')) {
    throw new Error('TRIALS_INVALID_RESPONSE');
  }

  if (status !== 'open' && status !== 'appealed' && status !== 'decided') {
    throw new Error('TRIALS_INVALID_RESPONSE');
  }

  if (!isNonEmptyString(judgeDid) || !judgeDid.trim().startsWith('did:')) {
    throw new Error('TRIALS_INVALID_RESPONSE');
  }

  if (!isNonEmptyString(openedAt)) {
    throw new Error('TRIALS_INVALID_RESPONSE');
  }

  return {
    case_id: caseId.trim(),
    status,
    judge_did: judgeDid.trim(),
    opened_at: openedAt.trim(),
  };
}

function buildSubmissionTrialEvidence(submission: SubmissionRecord): {
  proof_bundle_hash_b64u: string;
  receipt_refs: string[];
  artifact_refs: string[];
} {
  const proofHash = submission.proof_bundle_hash_b64u?.trim() ?? '';
  if (!proofHash) {
    throw new Error('TRIALS_EVIDENCE_MISSING_PROOF_BUNDLE_HASH');
  }

  const receiptRefs = new Set<string>();
  receiptRefs.add(`proof_bundle:${proofHash}`);
  if (submission.commit_proof_hash_b64u && submission.commit_proof_hash_b64u.trim().length > 0) {
    receiptRefs.add(`commit_proof:${submission.commit_proof_hash_b64u.trim()}`);
  }

  const artifactRefs = new Set<string>();
  if (Array.isArray(submission.artifacts)) {
    for (const artifact of submission.artifacts) {
      if (!isRecord(artifact)) continue;
      const uri = artifact.uri;
      if (isNonEmptyString(uri)) {
        artifactRefs.add(uri.trim());
      }
    }
  }

  artifactRefs.add(`clawbounties:submission:${submission.submission_id}`);

  return {
    proof_bundle_hash_b64u: proofHash,
    receipt_refs: Array.from(receiptRefs),
    artifact_refs: Array.from(artifactRefs),
  };
}

function buildTestHarnessFailureResponse(
  request: TestHarnessRunRequest,
  message: string
): TestHarnessRunResponse {
  return {
    schema_version: '1',
    test_harness_id: request.test_harness_id,
    submission_id: request.submission_id,
    passed: false,
    total_tests: 0,
    passed_tests: 0,
    failed_tests: 0,
    test_results: [],
    execution_time_ms: 0,
    completed_at: new Date().toISOString(),
    error: message,
  };
}

function parseTestHarnessResponse(input: unknown): TestHarnessRunResponse | null {
  if (!isRecord(input)) return null;

  if (input.schema_version !== '1') return null;

  const test_harness_id = input.test_harness_id;
  const submission_id = input.submission_id;
  const passed = input.passed;
  const total_tests = input.total_tests;
  const passed_tests = input.passed_tests;
  const failed_tests = input.failed_tests;
  const test_results = input.test_results;
  const execution_time_ms = input.execution_time_ms;
  const completed_at = input.completed_at;
  const error = input.error;

  if (!isNonEmptyString(test_harness_id) || !isNonEmptyString(submission_id)) return null;
  if (typeof passed !== 'boolean') return null;
  if (typeof total_tests !== 'number' || !Number.isFinite(total_tests) || total_tests < 0) return null;
  if (typeof passed_tests !== 'number' || !Number.isFinite(passed_tests) || passed_tests < 0) return null;
  if (typeof failed_tests !== 'number' || !Number.isFinite(failed_tests) || failed_tests < 0) return null;
  if (typeof execution_time_ms !== 'number' || !Number.isFinite(execution_time_ms) || execution_time_ms < 0) return null;
  if (!isNonEmptyString(completed_at)) return null;
  if (!Array.isArray(test_results)) return null;
  if (error !== undefined && error !== null && typeof error !== 'string') return null;

  return {
    schema_version: '1',
    test_harness_id: test_harness_id.trim(),
    submission_id: submission_id.trim(),
    passed,
    total_tests,
    passed_tests,
    failed_tests,
    test_results,
    execution_time_ms,
    completed_at: completed_at.trim(),
    error: isNonEmptyString(error) ? error.trim() : undefined,
  };
}

async function runTestHarness(env: Env, request: TestHarnessRunRequest): Promise<TestHarnessRunResponse> {
  const baseUrl = resolveTestHarnessBaseUrl(env);
  if (!baseUrl) {
    throw new Error('TEST_HARNESS_NOT_CONFIGURED');
  }

  const timeoutMs = request.timeout_ms ?? resolveTestHarnessTimeoutMs(env);
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(`${baseUrl}/v1/harness/run`, {
      method: 'POST',
      headers: { 'content-type': 'application/json; charset=utf-8' },
      body: JSON.stringify({ ...request, timeout_ms: timeoutMs }),
      signal: controller.signal,
    });

    const text = await response.text();
    let json: unknown;
    try {
      json = JSON.parse(text);
    } catch {
      json = null;
    }

    if (!response.ok) {
      return buildTestHarnessFailureResponse(request, `HTTP ${response.status}: ${text}`);
    }

    const parsed = parseTestHarnessResponse(json);
    if (!parsed) {
      return buildTestHarnessFailureResponse(request, 'Invalid response from test harness service');
    }

    return parsed;
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return buildTestHarnessFailureResponse(request, `Test harness error: ${message}`);
  } finally {
    clearTimeout(timeoutId);
  }
}

async function verifyProofBundle(
  env: Env,
  envelope: unknown,
  urm?: unknown,
  execution_attestations?: unknown
): Promise<VerifyBundleResponse> {
  const url = `${resolveVerifyBaseUrl(env)}/v1/verify/bundle`;
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json; charset=utf-8' },
    body: JSON.stringify({
      envelope,
      urm: urm ?? undefined,
      execution_attestations: execution_attestations ?? undefined,
    }),
  });

  const text = await response.text();
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }

  // Treat 5xx as dependency failure; allow 422 verification results to be parsed.
  if (response.status >= 500) {
    const details = isRecord(json) ? json : { raw: text };
    throw new Error(`VERIFY_FAILED:${response.status}:${JSON.stringify(details)}`);
  }

  if (!isRecord(json) || !isRecord(json.result)) {
    throw new Error(`VERIFY_INVALID_RESPONSE:${response.status}:${text}`);
  }

  const result = json.result as Record<string, unknown>;
  if (!isNonEmptyString(result.status) || !isNonEmptyString(result.reason) || !isNonEmptyString(result.verified_at)) {
    throw new Error(`VERIFY_INVALID_RESPONSE:${response.status}:${text}`);
  }

  return json as unknown as VerifyBundleResponse;
}

async function verifyCommitProof(env: Env, envelope: unknown): Promise<VerifyCommitProofResponse> {
  const url = `${resolveVerifyBaseUrl(env)}/v1/verify/commit-proof`;
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json; charset=utf-8' },
    body: JSON.stringify({ envelope }),
  });

  const text = await response.text();
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }

  // Treat 5xx as dependency failure; allow 422 verification results to be parsed.
  if (response.status >= 500) {
    const details = isRecord(json) ? json : { raw: text };
    throw new Error(`VERIFY_FAILED:${response.status}:${JSON.stringify(details)}`);
  }

  if (!isRecord(json) || !isRecord(json.result)) {
    throw new Error(`VERIFY_INVALID_RESPONSE:${response.status}:${text}`);
  }

  const result = json.result as Record<string, unknown>;
  if (!isNonEmptyString(result.status) || !isNonEmptyString(result.reason) || !isNonEmptyString(result.verified_at)) {
    throw new Error(`VERIFY_INVALID_RESPONSE:${response.status}:${text}`);
  }

  return json as unknown as VerifyCommitProofResponse;
}

async function verifyGatewayReceipt(env: Env, envelope: unknown): Promise<VerifyReceiptResponse> {
  const url = `${resolveVerifyBaseUrl(env)}/v1/verify/receipt`;
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json; charset=utf-8' },
    body: JSON.stringify({ envelope }),
  });

  const text = await response.text();
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }

  // Treat 5xx as dependency failure; allow 422 verification results to be parsed.
  if (response.status >= 500) {
    const details = isRecord(json) ? json : { raw: text };
    throw new Error(`VERIFY_FAILED:${response.status}:${JSON.stringify(details)}`);
  }

  if (!isRecord(json) || !isRecord(json.result)) {
    throw new Error(`VERIFY_INVALID_RESPONSE:${response.status}:${text}`);
  }

  const result = json.result as Record<string, unknown>;
  if (!isNonEmptyString(result.status) || !isNonEmptyString(result.reason) || !isNonEmptyString(result.verified_at)) {
    throw new Error(`VERIFY_INVALID_RESPONSE:${response.status}:${text}`);
  }

  return json as unknown as VerifyReceiptResponse;
}

function deriveProofTier(result: VerifyBundleResult): ProofTier | null {
  if (result.status !== 'VALID') return null;

  // Prefer canonical tier from clawverify (POH-US-013).
  const explicit = parseProofTier(result.proof_tier);
  if (explicit) return explicit;

  // Back-compat (older clawverify): derive from component booleans.
  // Note: sandbox is considered >= gateway (higher tier wins).
  if (result.component_results?.execution_attestations_valid) return 'sandbox';
  if (result.component_results?.attestations_valid) return 'sandbox';
  if (result.component_results?.receipts_valid) return 'gateway';
  return 'self';
}

function proofTierRank(tier: ProofTier): number {
  // Canonical ordering: self < gateway < sandbox
  switch (tier) {
    case 'self':
      return 1;
    case 'gateway':
      return 2;
    case 'sandbox':
      return 3;
  }
}

type ReplayReceiptKey = {
  receipt_signer_did: string;
  receipt_id: string;
};

function extractProofBundleAgentDid(envelope: Record<string, unknown>): string | null {
  const payload = envelope.payload;
  if (!isRecord(payload)) return null;
  const agentDid = payload.agent_did;
  if (!isNonEmptyString(agentDid)) return null;
  return agentDid.trim();
}

function extractRunIdAndEventHashesFromProofBundle(envelope: Record<string, unknown>): {
  run_id: string;
  event_hashes_b64u: Set<string>;
} | null {
  const payload = envelope.payload;
  if (!isRecord(payload)) return null;

  const eventChain = payload.event_chain;
  if (!Array.isArray(eventChain) || eventChain.length === 0) return null;

  const first = eventChain[0];
  if (!isRecord(first)) return null;

  const runId = first.run_id;
  if (!isNonEmptyString(runId)) return null;

  const eventHashes = new Set<string>();
  for (const e of eventChain) {
    if (!isRecord(e)) continue;
    const h = e.event_hash_b64u;
    if (isNonEmptyString(h)) eventHashes.add(h.trim());
  }

  return { run_id: runId.trim(), event_hashes_b64u: eventHashes };
}

type TrustPulseStorageStatus = 'verified' | 'unverified';

type StoredTrustPulseRow = {
  submission_id: string;
  run_id: string;
  agent_did: string;
  trust_pulse_json: string;
  hash_b64u: string;
  status: TrustPulseStorageStatus;
  created_at: string;
};

const MAX_TRUST_PULSE_BYTES = 64 * 1024;

// CEA-US-010 evidence can be large-ish; hard cap to prevent DoS.
const MAX_EXECUTION_ATTESTATIONS_COUNT = 5;
const MAX_EXECUTION_ATTESTATIONS_BYTES = 256 * 1024;

function utf8ByteSize(s: string): number {
  return new TextEncoder().encode(s).byteLength;
}

function extractExpectedTrustPulseHashFromUrm(urm: Record<string, unknown> | null): string | null {
  if (!urm) return null;

  const md = urm.metadata;
  if (!isRecord(md)) return null;

  const tp = md.trust_pulse;
  if (!isRecord(tp)) return null;

  const h = tp.artifact_hash_b64u;
  if (!isNonEmptyString(h)) return null;

  return h.trim();
}

function isSafeRelativePath(p: string): boolean {
  if (!p) return false;
  if (p.startsWith('/') || p.startsWith('~') || p.includes('\\')) return false;
  const parts = p.split('/');
  if (parts.some((seg) => seg === '..')) return false;
  return true;
}

function validateTrustPulseV1(tp: Record<string, unknown>): { ok: true } | { ok: false; code: string; message: string; field?: string } {
  const v = tp.trust_pulse_version;
  if (v !== '1') {
    return { ok: false, code: 'INVALID_REQUEST', message: 'trust_pulse.trust_pulse_version must be "1"', field: 'trust_pulse.trust_pulse_version' };
  }

  const evidence = tp.evidence_class;
  if (evidence !== 'self_reported') {
    return { ok: false, code: 'INVALID_REQUEST', message: 'trust_pulse.evidence_class must be "self_reported"', field: 'trust_pulse.evidence_class' };
  }

  if (tp.tier_uplift !== false) {
    return { ok: false, code: 'INVALID_REQUEST', message: 'trust_pulse.tier_uplift must be false', field: 'trust_pulse.tier_uplift' };
  }

  if (!isNonEmptyString(tp.run_id)) {
    return { ok: false, code: 'INVALID_REQUEST', message: 'trust_pulse.run_id is required', field: 'trust_pulse.run_id' };
  }

  if (!isNonEmptyString(tp.agent_did) || !tp.agent_did.trim().startsWith('did:')) {
    return { ok: false, code: 'INVALID_REQUEST', message: 'trust_pulse.agent_did must be a DID string', field: 'trust_pulse.agent_did' };
  }

  if (!Array.isArray(tp.tools)) {
    return { ok: false, code: 'INVALID_REQUEST', message: 'trust_pulse.tools must be an array', field: 'trust_pulse.tools' };
  }

  if (!Array.isArray(tp.files)) {
    return { ok: false, code: 'INVALID_REQUEST', message: 'trust_pulse.files must be an array', field: 'trust_pulse.files' };
  }

  // Enforce safe relative paths (best-effort; schema already defines stricter pattern).
  for (let i = 0; i < tp.files.length; i++) {
    const item = tp.files[i];
    if (!isRecord(item)) continue;
    const path = item.path;
    if (isNonEmptyString(path) && !isSafeRelativePath(path.trim())) {
      return {
        ok: false,
        code: 'INVALID_REQUEST',
        message: 'trust_pulse.files contains an unsafe path (must be relative; no .. traversal)',
        field: `trust_pulse.files[${i}].path`,
      };
    }
  }

  return { ok: true };
}

function extractTrustPulseBindingFromProofBundle(envelope: Record<string, unknown>): { agent_did: string; run_id: string } | null {
  const agent_did = extractProofBundleAgentDid(envelope);
  const binding = extractRunIdAndEventHashesFromProofBundle(envelope);
  if (!agent_did || !binding) return null;
  return { agent_did, run_id: binding.run_id };
}

function extractTrustPulseBindingFromUrm(urm: Record<string, unknown> | null): { agent_did: string; run_id: string } | null {
  if (!urm) return null;
  const agent_did = urm.agent_did;
  const run_id = urm.run_id;
  if (!isNonEmptyString(agent_did) || !isNonEmptyString(run_id)) return null;
  return { agent_did: agent_did.trim(), run_id: run_id.trim() };
}

function extractTrustPulseCanonicalJson(tp: Record<string, unknown>): { json: string; bytes: number } {
  const json = JSON.stringify(tp);
  const bytes = utf8ByteSize(json);
  return { json, bytes };
}

function extractReceiptsFromProofBundle(envelope: Record<string, unknown>): unknown[] {
  const payload = envelope.payload;
  if (!isRecord(payload)) return [];
  const receipts = payload.receipts;
  if (!Array.isArray(receipts)) return [];
  return receipts;
}

function extractBoundReceiptKey(
  receiptEnvelope: Record<string, unknown>,
  bindingContext: { run_id: string; allowed_event_hashes_b64u: ReadonlySet<string> }
): ReplayReceiptKey | null {
  const signerDid = receiptEnvelope.signer_did;
  if (!isNonEmptyString(signerDid)) return null;

  const payload = receiptEnvelope.payload;
  if (!isRecord(payload)) return null;

  const receiptId = payload.receipt_id;
  if (!isNonEmptyString(receiptId)) return null;

  const binding = payload.binding;
  if (!isRecord(binding)) return null;

  const runId = binding.run_id;
  const eventHash = binding.event_hash_b64u;
  if (!isNonEmptyString(runId) || runId.trim() !== bindingContext.run_id) return null;
  if (!isNonEmptyString(eventHash) || !bindingContext.allowed_event_hashes_b64u.has(eventHash.trim())) return null;

  return {
    receipt_signer_did: signerDid.trim(),
    receipt_id: receiptId.trim(),
  };
}

type ReplayReceiptComputation = {
  keys: ReplayReceiptKey[];
  /** Count of receipts that are (a) cryptographically verified and (b) bound to this run/event chain. */
  verified_bound_receipt_count: number;
  /** Observed binding.policy_hash values across verified+bound receipts. */
  verified_bound_policy_hashes: Set<string>;
  /** Verified+bound receipts missing binding.policy_hash. */
  verified_bound_missing_policy_hash_count: number;

  /** Observed binding.token_scope_hash_b64u values across verified+bound receipts. */
  verified_bound_token_scope_hashes: Set<string>;
  /** Verified+bound receipts missing binding.token_scope_hash_b64u. */
  verified_bound_missing_token_scope_hash_count: number;
};

async function computeReplayReceiptKeys(
  env: Env,
  proofBundleEnvelope: Record<string, unknown>,
  bindingContext: { run_id: string; allowed_event_hashes_b64u: ReadonlySet<string> }
): Promise<ReplayReceiptComputation> {
  const receipts = extractReceiptsFromProofBundle(proofBundleEnvelope);
  if (receipts.length === 0) {
    return {
      keys: [],
      verified_bound_receipt_count: 0,
      verified_bound_policy_hashes: new Set(),
      verified_bound_missing_policy_hash_count: 0,
      verified_bound_token_scope_hashes: new Set(),
      verified_bound_missing_token_scope_hash_count: 0,
    };
  }

  const keys: ReplayReceiptKey[] = [];
  let verified_bound_receipt_count = 0;
  const verified_bound_policy_hashes = new Set<string>();
  let verified_bound_missing_policy_hash_count = 0;
  const verified_bound_token_scope_hashes = new Set<string>();
  let verified_bound_missing_token_scope_hash_count = 0;

  // Verify each receipt signature via clawverify, then enforce binding to this run/event chain.
  for (const receipt of receipts) {
    if (!isRecord(receipt)) continue;

    let verification: VerifyReceiptResponse;
    try {
      verification = await verifyGatewayReceipt(env, receipt);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      throw new Error(`REPLAY_RECEIPT_VERIFY_FAILED:${message}`);
    }

    if (verification.result.status !== 'VALID') continue;

    const key = extractBoundReceiptKey(receipt, bindingContext);
    if (!key) continue;

    keys.push(key);
    verified_bound_receipt_count++;

    const payload = receipt.payload;
    const binding = isRecord(payload) ? payload.binding : null;

    const policyHash = isRecord(binding) ? binding.policy_hash : null;
    if (isNonEmptyString(policyHash)) {
      verified_bound_policy_hashes.add(policyHash.trim());
    } else {
      verified_bound_missing_policy_hash_count++;
    }

    const tokenScopeHash = isRecord(binding) ? binding.token_scope_hash_b64u : null;
    if (isNonEmptyString(tokenScopeHash)) {
      verified_bound_token_scope_hashes.add(tokenScopeHash.trim());
    } else {
      verified_bound_missing_token_scope_hash_count++;
    }
  }

  return {
    keys,
    verified_bound_receipt_count,
    verified_bound_policy_hashes,
    verified_bound_missing_policy_hash_count,
    verified_bound_token_scope_hashes,
    verified_bound_missing_token_scope_hash_count,
  };
}

function buildSubmitResponse(record: SubmissionRecord): SubmitBountyResponseV1 {
  const response: SubmitBountyResponseV1 = {
    submission_id: record.submission_id,
    bounty_id: record.bounty_id,
    status: record.status,
    verification: {
      proof_bundle: {
        status: record.proof_verify_status,
        reason: record.proof_verify_reason ?? undefined,
        verified_at: record.proof_verified_at ?? undefined,
        tier: record.proof_tier ?? undefined,
      },
    },
  };

  if (record.commit_proof_verify_status) {
    response.verification.commit_proof = {
      status: record.commit_proof_verify_status,
      reason: record.commit_proof_verify_reason ?? undefined,
      verified_at: record.commit_proof_verified_at ?? undefined,
    };
  }

  return response;
}

function parseNonNegativeMinor(input: unknown): bigint | null {
  if (typeof input !== 'string') return null;
  const s = input.trim();
  if (!/^[0-9]+$/.test(s)) return null;
  try {
    const n = BigInt(s);
    if (n < 0n) return null;
    return n;
  } catch {
    return null;
  }
}

type ClawrepLoopEnvelope = {
  schema_version: '1';
  source_event_id: string;
  source_service: 'clawbounties';
  kind: 'closure' | 'penalty' | 'recovery';
  did: string;
  occurred_at: string;
  closure?: {
    value_usd: number;
    closure_type: 'auto_approve' | 'quorum_approve' | 'manual_approve' | 'dispute_resolved';
    proof_tier: 'unknown' | 'self' | 'gateway' | 'sandbox' | 'tee' | 'witnessed_web';
    owner_verified?: boolean;
    owner_attestation_ref?: string;
  };
  penalty?: {
    penalty_type:
      | 'dispute_upheld_against_reviewer'
      | 'dispute_upheld_against_worker'
      | 'fraud_confirmed'
      | 'spam_review'
      | 'policy_violation';
    severity?: number;
    reason?: string;
  };
  recovery?: {
    recovery_type: 'appeal_upheld_for_reviewer' | 'appeal_upheld_for_worker';
    severity?: number;
    reason?: string;
  };
  metadata?: Record<string, unknown>;
};

function minorToUsd(minor: string): number {
  const parsed = parseNonNegativeMinor(minor);
  if (parsed === null) return 0;
  const integer = Number(parsed / 100n);
  const cents = Number(parsed % 100n);
  return integer + cents / 100;
}

function toRepProofTier(value: string | null | undefined): 'unknown' | 'self' | 'gateway' | 'sandbox' | 'tee' | 'witnessed_web' {
  if (value === 'self' || value === 'gateway' || value === 'sandbox') {
    return value;
  }
  if (value === 'tee') return 'tee';
  if (value === 'witnessed_web') return 'witnessed_web';
  return 'unknown';
}

async function emitClawrepLoopEvent(env: Env, envelope: ClawrepLoopEnvelope): Promise<void> {
  try {
    if (env.REP_EVENTS) {
      await env.REP_EVENTS.send(envelope, { contentType: 'json' });
      return;
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`[clawbounties] clawrep queue send failed source_event_id=${envelope.source_event_id}: ${message}`);
  }

  if (!env.CLAWREP_INGEST_KEY || env.CLAWREP_INGEST_KEY.trim().length === 0) {
    return;
  }

  const url = `${resolveClawrepBaseUrl(env)}/v1/events/ingest-loop`;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json; charset=utf-8',
        authorization: `Bearer ${env.CLAWREP_INGEST_KEY}`,
      },
      body: JSON.stringify(envelope),
      signal: controller.signal,
    });

    if (!response.ok && response.status !== 409) {
      const text = await response.text();
      console.error(
        `[clawbounties] clawrep ingest-loop failed status=${response.status} source_event_id=${envelope.source_event_id} body=${text.slice(0, 240)}`
      );
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`[clawbounties] clawrep ingest-loop error source_event_id=${envelope.source_event_id}: ${message}`);
  } finally {
    clearTimeout(timeout);
  }
}

function sumFeesMinor(items: FeeItem[]): bigint {
  let total = 0n;
  for (const item of items) {
    const n = parseNonNegativeMinor(item.amount_minor);
    if (n === null) throw new Error('INVALID_FEE_ITEM_AMOUNT');
    total += n;
  }
  return total;
}

function stableStringify(value: unknown): string {
  if (value === null) return 'null';

  if (Array.isArray(value)) {
    return `[${value.map((v) => stableStringify(v)).join(',')}]`;
  }

  switch (typeof value) {
    case 'string':
      return JSON.stringify(value);
    case 'number': {
      if (!Number.isFinite(value)) throw new Error('Non-finite number');
      return JSON.stringify(value);
    }
    case 'boolean':
      return value ? 'true' : 'false';
    case 'bigint':
      return JSON.stringify(value.toString());
    case 'object': {
      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj).sort();
      return `{${keys
        .map((k) => {
          const v = obj[k];
          return `${JSON.stringify(k)}:${stableStringify(v)}`;
        })
        .join(',')}}`;
    }
    default:
      return 'null';
  }
}

/**
 * RFC 8785 — JSON Canonicalization Scheme (JCS)
 *
 * Produces a deterministic JSON string suitable for hashing/signing.
 */
function jcsCanonicalize(value: unknown): string {
  if (value === null) return 'null';

  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';

    case 'number':
      if (!Number.isFinite(value)) {
        throw new Error('Non-finite number not allowed in JCS');
      }
      // JSON.stringify() uses the ECMAScript number-to-string algorithm.
      return JSON.stringify(value);

    case 'string':
      return JSON.stringify(value);

    case 'object': {
      if (Array.isArray(value)) {
        return `[${value.map(jcsCanonicalize).join(',')}]`;
      }

      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj).sort();
      const parts: string[] = [];

      for (const k of keys) {
        parts.push(`${JSON.stringify(k)}:${jcsCanonicalize(obj[k])}`);
      }

      return `{${parts.join(',')}}`;
    }

    default:
      // undefined | function | symbol | bigint
      throw new Error(`Unsupported value type for JCS: ${typeof value}`);
  }
}

function base64UrlEncode(bytes: Uint8Array): string {
  // btoa expects a binary string.
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  const base64 = btoa(binary);
  return base64.replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

function base64UrlDecode(str: string): Uint8Array {
  const base64 = str.replaceAll('-', '+').replaceAll('_', '/');
  const padding = '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(base64 + padding);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Decode(str: string): Uint8Array {
  const bytes: number[] = [0];

  for (const char of str) {
    const value = BASE58_ALPHABET.indexOf(char);
    if (value === -1) {
      throw new Error(`Invalid base58 character: ${char}`);
    }

    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = bytes[i]! * 58;
    }
    bytes[0] = bytes[0]! + value;

    let carry = 0;
    for (let i = 0; i < bytes.length; i++) {
      const next = bytes[i]! + carry;
      bytes[i] = next & 0xff;
      carry = next >> 8;
    }

    while (carry) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }

  // Handle leading zeros
  for (const char of str) {
    if (char !== '1') break;
    bytes.push(0);
  }

  return new Uint8Array(bytes.reverse());
}

/**
 * Extract raw Ed25519 public key bytes from did:key.
 * Expects multibase base58btc (z) and Ed25519 multicodec prefix 0xed01.
 */
function extractEd25519PublicKeyFromDidKey(did: string): Uint8Array | null {
  if (!did.startsWith('did:key:z')) return null;

  try {
    const multibase = did.slice(9);
    const decoded = base58Decode(multibase);
    if (decoded[0] === 0xed && decoded[1] === 0x01) return decoded.slice(2);
    return null;
  } catch {
    return null;
  }
}

async function verifyEd25519DidKeySignature(params: {
  signer_did: string;
  message: string;
  signature_b64u: string;
}): Promise<boolean> {
  const publicKeyBytes = extractEd25519PublicKeyFromDidKey(params.signer_did);
  if (!publicKeyBytes) return false;

  let signatureBytes: Uint8Array;
  try {
    signatureBytes = base64UrlDecode(params.signature_b64u);
  } catch {
    return false;
  }

  const messageBytes = new TextEncoder().encode(params.message);

  try {
    const publicKey = await crypto.subtle.importKey('raw', publicKeyBytes, { name: 'Ed25519' }, false, ['verify']);

    return await crypto.subtle.verify({ name: 'Ed25519' }, publicKey, signatureBytes, messageBytes);
  } catch {
    return false;
  }
}

function hexEncode(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

async function sha256HexUtf8(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return hexEncode(new Uint8Array(digest));
}

async function sha256B64uUtf8(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return base64UrlEncode(new Uint8Array(digest));
}

// ---------------------------------------------------------------------------
// Confidential Work Contract (CWC)
// ---------------------------------------------------------------------------

const SHA256_B64U_RE = /^[A-Za-z0-9_-]{43}$/;

function isSha256B64u(value: string): boolean {
  return SHA256_B64U_RE.test(value);
}

type CwcReceiptPrivacyMode = 'hash_only' | 'encrypted';

type ConfidentialWorkContractV1 = {
  cwc_version: '1';
  cwc_id: string;

  buyer_did: string;
  worker_did: string;

  /** Pinned WPC hash (policy_hash_b64u). */
  wpc_policy_hash_b64u: string;

  /** Required proof tier for submissions. */
  required_proof_tier: ProofTier;

  /** Receipt privacy mode expectation. */
  receipt_privacy_mode: CwcReceiptPrivacyMode;

  /** Optional egress allowlist (future mediated egress). */
  egress_allowlist?: string[];

  /** Optional dispute terms (free-form). */
  dispute_terms?: string;

  /** Optional metadata (hash-bound). */
  metadata?: Record<string, unknown>;
};

type ConfidentialWorkContractEnvelopeV1 = {
  envelope_version: '1';
  envelope_type: 'confidential_work_contract';
  payload: ConfidentialWorkContractV1;
  payload_hash_b64u: string;
  hash_algorithm: 'SHA-256';
  signature_b64u: string;
  algorithm: 'Ed25519';
  signer_did: string;
  issued_at: string;
};

function isStringArrayBounded(value: unknown, opts: { maxItems: number; maxLen: number }): value is string[] {
  if (!Array.isArray(value)) return false;
  if (value.length > opts.maxItems) return false;

  for (const v of value) {
    if (!isNonEmptyString(v)) return false;
    if (v.trim().length > opts.maxLen) return false;
  }

  return true;
}

function isConfidentialWorkContractV1(value: unknown): value is ConfidentialWorkContractV1 {
  if (!isRecord(value)) return false;

  const allowedKeys = new Set([
    'cwc_version',
    'cwc_id',
    'buyer_did',
    'worker_did',
    'wpc_policy_hash_b64u',
    'required_proof_tier',
    'receipt_privacy_mode',
    'egress_allowlist',
    'dispute_terms',
    'metadata',
  ]);

  for (const k of Object.keys(value)) {
    if (!allowedKeys.has(k)) return false;
  }

  if (value.cwc_version !== '1') return false;
  if (!isNonEmptyString(value.cwc_id) || value.cwc_id.trim().length > 128) return false;

  if (!isNonEmptyString(value.buyer_did) || !value.buyer_did.trim().startsWith('did:') || value.buyer_did.trim().length > 256) return false;
  if (!isNonEmptyString(value.worker_did) || !value.worker_did.trim().startsWith('did:') || value.worker_did.trim().length > 256) return false;

  if (!isNonEmptyString(value.wpc_policy_hash_b64u) || !isSha256B64u(value.wpc_policy_hash_b64u.trim())) return false;

  if (!isNonEmptyString(value.required_proof_tier) || !parseProofTier(value.required_proof_tier)) return false;

  if (value.receipt_privacy_mode !== 'hash_only' && value.receipt_privacy_mode !== 'encrypted') return false;

  if (value.egress_allowlist !== undefined && !isStringArrayBounded(value.egress_allowlist, { maxItems: 256, maxLen: 256 })) {
    return false;
  }

  if (value.dispute_terms !== undefined) {
    if (!isNonEmptyString(value.dispute_terms) || value.dispute_terms.trim().length > 10000) return false;
  }

  if (value.metadata !== undefined && !isRecord(value.metadata)) {
    return false;
  }

  return true;
}

function isConfidentialWorkContractEnvelopeV1(value: unknown): value is ConfidentialWorkContractEnvelopeV1 {
  if (!isRecord(value)) return false;

  const allowedKeys = new Set([
    'envelope_version',
    'envelope_type',
    'payload',
    'payload_hash_b64u',
    'hash_algorithm',
    'signature_b64u',
    'algorithm',
    'signer_did',
    'issued_at',
  ]);

  for (const k of Object.keys(value)) {
    if (!allowedKeys.has(k)) return false;
  }

  if (value.envelope_version !== '1') return false;
  if (value.envelope_type !== 'confidential_work_contract') return false;
  if (value.hash_algorithm !== 'SHA-256') return false;
  if (value.algorithm !== 'Ed25519') return false;

  if (!isNonEmptyString(value.payload_hash_b64u) || !isSha256B64u(value.payload_hash_b64u.trim())) return false;
  if (!isNonEmptyString(value.signature_b64u) || !/^[A-Za-z0-9_-]+$/.test(value.signature_b64u.trim())) return false;
  if (!isNonEmptyString(value.signer_did) || !value.signer_did.trim().startsWith('did:')) return false;
  if (!isNonEmptyString(value.issued_at)) return false;

  if (!isConfidentialWorkContractV1(value.payload)) return false;

  return true;
}

async function verifyCwcEnvelope(envelope: ConfidentialWorkContractEnvelopeV1): Promise<
  | { ok: true; payload_hash_b64u: string; payload: ConfidentialWorkContractV1 }
  | { ok: false; code: string; message: string }
> {
  const payload_hash_b64u = envelope.payload_hash_b64u.trim();

  // Recompute hash from canonical payload bytes (JCS)
  let computed: string;
  try {
    computed = await sha256B64uUtf8(jcsCanonicalize(envelope.payload));
  } catch {
    return { ok: false, code: 'CWC_HASH_FAILED', message: 'Failed to canonicalize/hash CWC payload' };
  }

  if (computed !== payload_hash_b64u) {
    return {
      ok: false,
      code: 'CWC_HASH_MISMATCH',
      message: 'CWC payload_hash_b64u does not match sha256(JCS(payload))',
    };
  }

  const sigOk = await verifyEd25519DidKeySignature({
    signer_did: envelope.signer_did,
    message: payload_hash_b64u,
    signature_b64u: envelope.signature_b64u,
  });

  if (!sigOk) {
    return { ok: false, code: 'CWC_SIGNATURE_INVALID', message: 'CWC signature verification failed' };
  }

  return { ok: true, payload_hash_b64u, payload: envelope.payload };
}

async function deriveIdempotencyKey(requester_did: string, body: Record<string, unknown>): Promise<string> {
  const canonical = stableStringify({
    schema: 'clawbounties.post_bounty.v2',
    requester_did,
    body,
  });
  const hash = await sha256B64uUtf8(canonical);
  return `postbounty:auto:${hash}`;
}

function d1String(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  if (typeof value === 'string') return value;
  if (typeof value === 'number') return value.toString();
  return null;
}

function d1Number(value: unknown): number | null {
  if (value === null || value === undefined) return null;
  if (typeof value === 'number') return value;
  if (typeof value === 'string') {
    const n = Number(value);
    if (!Number.isFinite(n)) return null;
    return n;
  }
  return null;
}

function d1Boolean(value: unknown): boolean | null {
  if (value === true || value === false) return value;
  if (typeof value === 'number') {
    if (value === 1) return true;
    if (value === 0) return false;
  }
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    if (normalized === '1' || normalized === 'true') return true;
    if (normalized === '0' || normalized === 'false') return false;
  }
  return null;
}

function parseJsonObject(text: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(text) as unknown;
    if (!isRecord(parsed)) return null;
    return parsed;
  } catch {
    return null;
  }
}

function parseJsonStringArray(text: string): string[] | null {
  try {
    const parsed = JSON.parse(text) as unknown;
    if (!Array.isArray(parsed)) return null;
    const out: string[] = [];
    for (const v of parsed) {
      if (typeof v !== 'string') return null;
      out.push(v);
    }
    return out;
  } catch {
    return null;
  }
}

function parseBountyRow(row: Record<string, unknown>): BountyV2 | null {
  const bounty_id = d1String(row.bounty_id);
  const create_idempotency_key = d1String(row.create_idempotency_key);
  const requester_did = d1String(row.requester_did);
  const title = d1String(row.title);
  const description = d1String(row.description);

  const reward_amount_minor = d1String(row.reward_amount_minor);
  const reward_currency = d1String(row.reward_currency);

  const closure_type = parseClosureType(d1String(row.closure_type));
  const difficulty_scalar = d1Number(row.difficulty_scalar);

  const escrow_id = d1String(row.escrow_id);
  const status = parseBountyStatus(d1String(row.status));

  const created_at = d1String(row.created_at);
  const updated_at = d1String(row.updated_at);

  const worker_did = d1String(row.worker_did);
  const accept_idempotency_key = d1String(row.accept_idempotency_key);
  const accepted_at = d1String(row.accepted_at);
  const job_token_scope_hash_b64u = d1String(row.job_token_scope_hash_b64u);

  const cwc_hash_b64u = d1String(row.cwc_hash_b64u);
  const cwc_wpc_policy_hash_b64u = d1String(row.cwc_wpc_policy_hash_b64u);
  const cwc_required_proof_tier = parseProofTier(d1String(row.cwc_required_proof_tier));
  const cwc_token_scope_hash_b64u = d1String(row.cwc_token_scope_hash_b64u);
  const cwc_buyer_envelope_json = d1String(row.cwc_buyer_envelope_json);
  const cwc_worker_envelope_json = d1String(row.cwc_worker_envelope_json);

  const approved_submission_id = d1String(row.approved_submission_id);
  const approve_idempotency_key = d1String(row.approve_idempotency_key);
  const approved_at = d1String(row.approved_at);
  const rejected_submission_id = d1String(row.rejected_submission_id);
  const reject_idempotency_key = d1String(row.reject_idempotency_key);
  const rejected_at = d1String(row.rejected_at);
  const trial_case_id = d1String(row.trial_case_id);
  const trial_opened_at = d1String(row.trial_opened_at);

  const arena_status = parseBountyArenaStatus(d1String(row.arena_status)) ?? 'idle';
  const arena_id = d1String(row.arena_id);
  const arena_task_fingerprint = d1String(row.arena_task_fingerprint);
  const arena_winner_contender_id = d1String(row.arena_winner_contender_id);
  const arena_evidence_links_json = d1String(row.arena_evidence_links_json);
  const arena_updated_at = d1String(row.arena_updated_at);

  const is_code_bounty_num = d1Number(row.is_code_bounty);
  const tags_json = d1String(row.tags_json);
  const min_proof_tier = parseProofTier(d1String(row.min_proof_tier));
  const require_owner_verified_votes_num = d1Number(row.require_owner_verified_votes);
  const test_harness_id = d1String(row.test_harness_id);

  const metadata_json = d1String(row.metadata_json);
  const fee_quote_json = d1String(row.fee_quote_json);
  const fee_policy_version = d1String(row.fee_policy_version);
  const all_in_cost_json = d1String(row.all_in_cost_json);

  if (
    !bounty_id ||
    !create_idempotency_key ||
    !requester_did ||
    !title ||
    !description ||
    !reward_amount_minor ||
    reward_currency !== 'USD' ||
    !closure_type ||
    difficulty_scalar === null ||
    !escrow_id ||
    !status ||
    !created_at ||
    !updated_at ||
    is_code_bounty_num === null ||
    !tags_json ||
    !min_proof_tier ||
    require_owner_verified_votes_num === null ||
    !metadata_json ||
    !fee_quote_json ||
    !fee_policy_version ||
    !all_in_cost_json
  ) {
    return null;
  }

  const tags = parseJsonStringArray(tags_json);
  const metadata = parseJsonObject(metadata_json);
  let fee_quote: CutsSimulateResponse;
  try {
    fee_quote = JSON.parse(fee_quote_json) as CutsSimulateResponse;
  } catch {
    return null;
  }

  let all_in_cost: AllInCostV2;
  try {
    const parsed = JSON.parse(all_in_cost_json) as unknown;
    if (!isRecord(parsed)) return null;

    const principal_minor = parsed.principal_minor;
    const platform_fee_minor = parsed.platform_fee_minor;
    const total_minor = parsed.total_minor;
    const currency = parsed.currency;

    if (!isNonEmptyString(principal_minor) || !isNonEmptyString(platform_fee_minor) || !isNonEmptyString(total_minor) || currency !== 'USD') {
      return null;
    }

    all_in_cost = {
      principal_minor: principal_minor.trim(),
      platform_fee_minor: platform_fee_minor.trim(),
      total_minor: total_minor.trim(),
      currency: 'USD',
    };
  } catch {
    return null;
  }

  if (!tags || !metadata) return null;

  let arena_evidence_links: ArenaScoreExplainLink[] = [];
  if (arena_evidence_links_json) {
    try {
      const parsed = JSON.parse(arena_evidence_links_json) as unknown;
      arena_evidence_links = parseArenaScoreExplainLinks(parsed);
    } catch {
      return null;
    }
  }

  const cwc_buyer_envelope = cwc_buyer_envelope_json ? parseJsonObject(cwc_buyer_envelope_json) : null;
  const cwc_worker_envelope = cwc_worker_envelope_json ? parseJsonObject(cwc_worker_envelope_json) : null;

  if (job_token_scope_hash_b64u && !isSha256B64u(job_token_scope_hash_b64u.trim())) return null;

  const hasAnyCwc = Boolean(
    cwc_hash_b64u ||
      cwc_wpc_policy_hash_b64u ||
      cwc_required_proof_tier ||
      cwc_token_scope_hash_b64u ||
      cwc_buyer_envelope_json ||
      cwc_worker_envelope_json
  );

  if (hasAnyCwc) {
    if (!cwc_hash_b64u || !isSha256B64u(cwc_hash_b64u.trim())) return null;
    if (!cwc_wpc_policy_hash_b64u || !isSha256B64u(cwc_wpc_policy_hash_b64u.trim())) return null;
    if (!cwc_required_proof_tier) return null;
    if (cwc_token_scope_hash_b64u && !isSha256B64u(cwc_token_scope_hash_b64u.trim())) return null;
    if (!cwc_buyer_envelope) return null;
    if (cwc_worker_envelope_json && !cwc_worker_envelope) return null;
  }

  return {
    schema_version: '2',
    bounty_id,
    requester_did,
    title,
    description,
    reward: {
      amount_minor: reward_amount_minor,
      currency: 'USD',
    },
    closure_type,
    difficulty_scalar,
    escrow_id,
    status,
    created_at,

    worker_did: worker_did && worker_did.trim().startsWith('did:') ? worker_did.trim() : null,
    accept_idempotency_key: accept_idempotency_key ? accept_idempotency_key.trim() : null,
    accepted_at: accepted_at ? accepted_at.trim() : null,
    job_token_scope_hash_b64u: job_token_scope_hash_b64u ? job_token_scope_hash_b64u.trim() : null,

    cwc_hash_b64u: hasAnyCwc ? cwc_hash_b64u!.trim() : null,
    cwc_wpc_policy_hash_b64u: hasAnyCwc ? cwc_wpc_policy_hash_b64u!.trim() : null,
    cwc_required_proof_tier: hasAnyCwc ? cwc_required_proof_tier! : null,
    cwc_token_scope_hash_b64u: hasAnyCwc ? (cwc_token_scope_hash_b64u ? cwc_token_scope_hash_b64u.trim() : null) : null,
    cwc_buyer_envelope: hasAnyCwc ? cwc_buyer_envelope : null,
    cwc_worker_envelope: hasAnyCwc ? cwc_worker_envelope : null,

    approved_submission_id: approved_submission_id ? approved_submission_id.trim() : null,
    approve_idempotency_key: approve_idempotency_key ? approve_idempotency_key.trim() : null,
    approved_at: approved_at ? approved_at.trim() : null,
    rejected_submission_id: rejected_submission_id ? rejected_submission_id.trim() : null,
    reject_idempotency_key: reject_idempotency_key ? reject_idempotency_key.trim() : null,
    rejected_at: rejected_at ? rejected_at.trim() : null,
    trial_case_id: trial_case_id ? trial_case_id.trim() : null,
    trial_opened_at: trial_opened_at ? trial_opened_at.trim() : null,

    arena_status,
    arena_id: arena_id ? arena_id.trim() : null,
    arena_task_fingerprint: arena_task_fingerprint ? arena_task_fingerprint.trim() : null,
    arena_winner_contender_id: arena_winner_contender_id ? arena_winner_contender_id.trim() : null,
    arena_evidence_links,
    arena_updated_at: arena_updated_at ? arena_updated_at.trim() : null,

    is_code_bounty: Boolean(is_code_bounty_num),
    tags,
    min_proof_tier,
    require_owner_verified_votes: Boolean(require_owner_verified_votes_num),
    test_harness_id,
    metadata,
    idempotency_key: create_idempotency_key,

    fee_policy_version,
    all_in_cost,

    fee_quote,
    updated_at,
  };
}

function parseSubmissionRow(row: Record<string, unknown>): SubmissionRecord | null {
  const submission_id = d1String(row.submission_id);
  const bounty_id = d1String(row.bounty_id);
  const worker_did = d1String(row.worker_did);
  const status = parseSubmissionStatus(d1String(row.status));
  const idempotency_key = d1String(row.idempotency_key);

  const proof_bundle_envelope_json = d1String(row.proof_bundle_envelope_json);
  const proof_bundle_hash_b64u = d1String(row.proof_bundle_hash_b64u);
  const proof_verify_status_raw = d1String(row.proof_verify_status);
  const proof_verify_reason = d1String(row.proof_verify_reason);
  const proof_verified_at = d1String(row.proof_verified_at);
  const proof_tier = parseProofTier(d1String(row.proof_tier));
  const execution_attestations_json = d1String(row.execution_attestations_json);

  const commit_proof_envelope_json = d1String(row.commit_proof_envelope_json);
  const commit_proof_hash_b64u = d1String(row.commit_proof_hash_b64u);
  const commit_sha = d1String(row.commit_sha);
  const repo_url = d1String(row.repo_url);
  const repo_claim_id = d1String(row.repo_claim_id);
  const commit_proof_verify_status_raw = d1String(row.commit_proof_verify_status);
  const commit_proof_verify_reason = d1String(row.commit_proof_verify_reason);
  const commit_proof_verified_at = d1String(row.commit_proof_verified_at);

  const artifacts_json = d1String(row.artifacts_json);
  const agent_pack_json = d1String(row.agent_pack_json);
  const result_summary = d1String(row.result_summary);

  const created_at = d1String(row.created_at);
  const updated_at = d1String(row.updated_at);

  if (!submission_id || !bounty_id || !worker_did || !status || !proof_bundle_envelope_json || !proof_verify_status_raw || !created_at || !updated_at) {
    return null;
  }

  const proof_verify_status = proof_verify_status_raw === 'valid' ? 'valid' : proof_verify_status_raw === 'invalid' ? 'invalid' : null;
  if (!proof_verify_status) return null;

  const proof_bundle_envelope = parseJsonObject(proof_bundle_envelope_json);
  if (!proof_bundle_envelope) return null;

  let commit_proof_envelope: Record<string, unknown> | null = null;
  if (commit_proof_envelope_json) {
    commit_proof_envelope = parseJsonObject(commit_proof_envelope_json);
    if (!commit_proof_envelope) return null;
  }

  let commit_proof_verify_status: 'valid' | 'invalid' | null = null;
  if (commit_proof_verify_status_raw) {
    commit_proof_verify_status = commit_proof_verify_status_raw === 'valid' ? 'valid' : commit_proof_verify_status_raw === 'invalid' ? 'invalid' : null;
    if (!commit_proof_verify_status) return null;
  }

  let artifacts: unknown[] | null = null;
  if (artifacts_json) {
    artifacts = parseJsonUnknownArray(artifacts_json);
    if (!artifacts) return null;
  }

  let agent_pack: Record<string, unknown> | null = null;
  if (agent_pack_json) {
    agent_pack = parseJsonObject(agent_pack_json);
    if (!agent_pack) return null;
  }

  let execution_attestations: Record<string, unknown>[] | null = null;
  if (execution_attestations_json) {
    const arr = parseJsonUnknownArray(execution_attestations_json);
    if (!arr) return null;

    const out: Record<string, unknown>[] = [];
    for (const item of arr) {
      if (!isRecord(item)) return null;
      out.push(item);
    }

    execution_attestations = out;
  }

  return {
    submission_id,
    bounty_id,
    worker_did,
    status,
    idempotency_key: idempotency_key ? idempotency_key.trim() : null,
    proof_bundle_envelope,
    proof_bundle_hash_b64u: proof_bundle_hash_b64u ? proof_bundle_hash_b64u.trim() : null,
    proof_verify_status,
    proof_verify_reason: proof_verify_reason ? proof_verify_reason.trim() : null,
    proof_verified_at: proof_verified_at ? proof_verified_at.trim() : null,
    proof_tier: proof_tier ?? null,
    execution_attestations,
    commit_proof_envelope,
    commit_proof_hash_b64u: commit_proof_hash_b64u ? commit_proof_hash_b64u.trim() : null,
    commit_sha: commit_sha ? commit_sha.trim() : null,
    repo_url: repo_url ? repo_url.trim() : null,
    repo_claim_id: repo_claim_id ? repo_claim_id.trim() : null,
    commit_proof_verify_status,
    commit_proof_verify_reason: commit_proof_verify_reason ? commit_proof_verify_reason.trim() : null,
    commit_proof_verified_at: commit_proof_verified_at ? commit_proof_verified_at.trim() : null,
    artifacts,
    agent_pack,
    result_summary: result_summary ? result_summary.trim() : null,
    created_at,
    updated_at,
  };
}

function parseTestResultRow(row: Record<string, unknown>): TestResultRecord | null {
  const test_result_id = d1String(row.test_result_id);
  const submission_id = d1String(row.submission_id);
  const bounty_id = d1String(row.bounty_id);
  const test_harness_id = d1String(row.test_harness_id);
  const passedRaw = d1Number(row.passed);
  const total_tests = d1Number(row.total_tests);
  const passed_tests = d1Number(row.passed_tests);
  const failed_tests = d1Number(row.failed_tests);
  const execution_time_ms = d1Number(row.execution_time_ms);
  const completed_at = d1String(row.completed_at);
  const error = d1String(row.error);
  const test_results_json = d1String(row.test_results_json);
  const created_at = d1String(row.created_at);
  const updated_at = d1String(row.updated_at);

  if (
    !test_result_id ||
    !submission_id ||
    !bounty_id ||
    !test_harness_id ||
    passedRaw === null ||
    total_tests === null ||
    passed_tests === null ||
    failed_tests === null ||
    execution_time_ms === null ||
    !completed_at ||
    !test_results_json ||
    !created_at ||
    !updated_at
  ) {
    return null;
  }

  const test_results = parseJsonUnknownArray(test_results_json);
  if (!test_results) {
    return null;
  }

  return {
    test_result_id,
    submission_id,
    bounty_id,
    test_harness_id,
    passed: passedRaw !== 0,
    total_tests,
    passed_tests,
    failed_tests,
    execution_time_ms,
    completed_at,
    error: error ? error.trim() : null,
    test_results,
    created_at,
    updated_at,
  };
}

async function listSubmissionsByBounty(
  db: D1Database,
  params: {
    bounty_id: string;
    status?: SubmissionStatus;
    worker_did?: string;
    limit: number;
  }
): Promise<SubmissionRecord[]> {
  let sql = 'SELECT * FROM submissions WHERE bounty_id = ?';
  const binds: unknown[] = [params.bounty_id];

  if (params.status) {
    sql += ' AND status = ?';
    binds.push(params.status);
  }

  if (params.worker_did) {
    sql += ' AND worker_did = ?';
    binds.push(params.worker_did);
  }

  sql += ' ORDER BY created_at DESC, submission_id DESC LIMIT ?';
  binds.push(params.limit);

  const rows = await db.prepare(sql).bind(...binds).all();
  const out: SubmissionRecord[] = [];
  for (const row of rows.results ?? []) {
    if (!isRecord(row)) continue;
    const parsed = parseSubmissionRow(row);
    if (parsed) out.push(parsed);
  }

  return out;
}

async function getLatestTestResultBySubmissionId(
  db: D1Database,
  submission_id: string
): Promise<TestResultRecord | null> {
  const row = await db
    .prepare('SELECT * FROM test_results WHERE submission_id = ? ORDER BY created_at DESC, test_result_id DESC LIMIT 1')
    .bind(submission_id)
    .first();

  if (!row || !isRecord(row)) return null;
  return parseTestResultRow(row);
}

function classifyTestLaneFailure(errorMessage: string): DeterministicTestLaneFailure {
  const msg = errorMessage.trim();

  if (msg === 'TEST_HARNESS_NOT_CONFIGURED' || msg.includes('TEST_HARNESS_NOT_CONFIGURED')) {
    return {
      code: 'TEST_HARNESS_NOT_CONFIGURED',
      message: 'Test harness base URL is not configured',
      status: 503,
    };
  }

  if (msg.startsWith('Invalid response from test harness service')) {
    return {
      code: 'TEST_HARNESS_INVALID_RESPONSE',
      message: msg,
      status: 502,
    };
  }

  if (msg.startsWith('HARNESS_NOT_FOUND')) {
    return {
      code: 'TEST_HARNESS_INVALID',
      message: msg,
      status: 422,
    };
  }

  const httpMatch = msg.match(/^HTTP\s+([0-9]{3})(:.*)?$/i);
  if (httpMatch) {
    const status = Number.parseInt(httpMatch[1] ?? '500', 10);
    if (status >= 500 || status === 404) {
      return {
        code: 'TEST_HARNESS_UNAVAILABLE',
        message: msg,
        status: 503,
      };
    }

    return {
      code: 'TEST_HARNESS_INVALID_RESPONSE',
      message: msg,
      status: 502,
    };
  }

  if (msg.startsWith('Test harness error:')) {
    return {
      code: 'TEST_HARNESS_UNAVAILABLE',
      message: msg,
      status: 503,
    };
  }

  return {
    code: 'TEST_HARNESS_FAILED',
    message: msg,
    status: 502,
  };
}

async function resolveSubmissionTestLaneFailure(
  db: D1Database,
  bounty: BountyV2,
  submission: SubmissionRecord
): Promise<DeterministicTestLaneFailure | null> {
  if (bounty.closure_type !== 'test') return null;

  if (!isNonEmptyString(bounty.test_harness_id)) {
    return {
      code: 'TEST_HARNESS_NOT_CONFIGURED',
      message: 'Bounty is missing test_harness_id for closure_type=test',
      status: 503,
      details: {
        submission_id: submission.submission_id,
      },
    };
  }

  if (!isNonEmptyString(submission.proof_bundle_hash_b64u)) {
    return {
      code: 'TEST_HARNESS_INPUT_INVALID',
      message: 'Submission is missing proof_bundle_hash_b64u',
      status: 500,
      details: {
        submission_id: submission.submission_id,
      },
    };
  }

  const latest = await getLatestTestResultBySubmissionId(db, submission.submission_id);
  if (!latest || !isNonEmptyString(latest.error)) return null;

  const classified = classifyTestLaneFailure(latest.error);
  return {
    code: classified.code,
    message: classified.message,
    status: classified.status,
    details: {
      submission_id: submission.submission_id,
      test_result_id: latest.test_result_id,
      test_harness_id: latest.test_harness_id,
    },
  };
}

function resolveArenaExplorerBaseUrl(env: Env): string {
  const environment = env.ENVIRONMENT?.trim().toLowerCase() ?? 'production';
  return environment === 'staging'
    ? 'https://staging-explorer.clawsig.com'
    : 'https://explorer.clawsig.com';
}

function buildArenaReviewArtifactLinks(
  arenaExplorerBaseUrl: string,
  arenaId: string,
  contenderId: string,
): {
  review_paste: string;
  manager_review: string;
} {
  const encodedArenaId = encodeURIComponent(arenaId);
  const encodedContenderId = encodeURIComponent(contenderId);
  return {
    review_paste: `${arenaExplorerBaseUrl}/arena/${encodedArenaId}?contender=${encodedContenderId}#review-paste-${encodedContenderId}`,
    manager_review: `${arenaExplorerBaseUrl}/arena/${encodedArenaId}?contender=${encodedContenderId}#manager-review-${encodedContenderId}`,
  };
}

async function buildArenaStartActionTemplateView(
  bounty: BountyV2,
  submission: SubmissionRecord,
): Promise<ArenaStartActionTemplateView> {
  const taskFingerprint = deriveLiveArenaTaskFingerprint(bounty);
  const objectiveProfile = parseArenaObjectiveProfile(buildLiveArenaObjectiveProfile(bounty)) ?? {
    name: 'balanced',
    weights: { quality: 0.45, speed: 0.2, cost: 0.15, safety: 0.2 },
    tie_breakers: ['hard_gate_pass', 'quality_score', 'cost_usd'],
  };

  const arenaId = `arena_${bounty.bounty_id}_review_${submission.submission_id}`.slice(0, 120);
  const contractId = `contract_${bounty.bounty_id}_${submission.submission_id}`.slice(0, 120);

  const contractHashMaterial = stableStringify({
    bounty_id: bounty.bounty_id,
    submission_id: submission.submission_id,
    worker_did: submission.worker_did,
    task_fingerprint: taskFingerprint,
    source: 'bounty-review-start',
  });

  const contractHashB64u = await sha256B64uUtf8(contractHashMaterial);

  return {
    endpoint: `/v1/bounties/${bounty.bounty_id}/arena/start`,
    method: 'POST',
    payload_template: {
      idempotency_key: `arena-review:${submission.submission_id}`.slice(0, 128),
      arena_id: arenaId,
      contract: {
        bounty_id: bounty.bounty_id,
        contract_id: contractId,
        contract_hash_b64u: contractHashB64u,
        task_fingerprint: taskFingerprint,
      },
      objective_profile: objectiveProfile,
    },
  };
}

function buildArenaInlineReviewSummaryView(
  run: ArenaRunRecord | null,
  winnerContender: ArenaContenderResult | null,
  arenaExplorerBaseUrl: string,
): ArenaInlineReviewSummaryView | null {
  if (!run) return null;

  const tradeoffs = run.tradeoffs_json
    ? (parseJsonStringArray(run.tradeoffs_json) ?? [])
    : [];

  const managerReview = winnerContender?.manager_review && isRecord(winnerContender.manager_review)
    ? winnerContender.manager_review
    : null;

  const winnerConfidenceRaw = managerReview ? d1Number(managerReview.confidence) : null;
  const winnerConfidence = winnerConfidenceRaw === null
    ? null
    : Math.max(0, Math.min(1, winnerConfidenceRaw));

  const winnerContenderId = run.winner_contender_id ?? winnerContender?.contender_id ?? null;
  const reviewLinks = winnerContenderId
    ? buildArenaReviewArtifactLinks(arenaExplorerBaseUrl, run.arena_id, winnerContenderId)
    : { review_paste: null, manager_review: null };

  return {
    arena_id: run.arena_id,
    status: run.status,
    winner_contender_id: winnerContenderId,
    winner_reason: run.winner_reason,
    winner_confidence: winnerConfidence,
    tradeoffs,
    review_links: reviewLinks,
  };
}

function buildArenaOutcomeStatusOptions(): ArenaOutcomeStatusOptionView[] {
  return [
    {
      value: 'ACCEPTED',
      requires_override_reason: false,
      calibration_impact: 'Improves empirical accept rate for selected contender.',
    },
    {
      value: 'OVERRIDDEN',
      requires_override_reason: true,
      calibration_impact: 'Increases override rate and applies override reason weighting in policy-learning.',
    },
    {
      value: 'REWORK',
      requires_override_reason: false,
      calibration_impact: 'Increases rework rate for selected contender.',
    },
    {
      value: 'REJECTED',
      requires_override_reason: false,
      calibration_impact: 'Counts as non-accept and raises calibration gap when confidence was high.',
    },
    {
      value: 'DISPUTED',
      requires_override_reason: false,
      calibration_impact: 'Marks outcome as disputed for risk tracking and review-depth analytics.',
    },
  ];
}

function buildArenaReviewerDecisionOptions(): ArenaReviewerDecisionOptionView[] {
  return [
    {
      value: 'approve',
      recommendation: 'APPROVE',
      default_outcome_status: 'ACCEPTED',
      calibration_impact: 'Improves accept-rate and low-friction routing confidence for this contender.',
    },
    {
      value: 'request_changes',
      recommendation: 'REQUEST_CHANGES',
      default_outcome_status: 'REWORK',
      calibration_impact: 'Increases rework and iterative feedback signals for policy adaptation.',
    },
    {
      value: 'reject',
      recommendation: 'REJECT',
      default_outcome_status: 'REJECTED',
      calibration_impact: 'Counts as failed selection signal and increases risk-aware downweighting.',
    },
  ];
}

function buildArenaOverrideReasonOptions(): ArenaOverrideReasonOptionView[] {
  return (Object.entries(ARENA_OVERRIDE_REASON_REGISTRY) as [ArenaOverrideReasonCode, (typeof ARENA_OVERRIDE_REASON_REGISTRY)[ArenaOverrideReasonCode]][])
    .map(([code, info]) => ({
      code,
      weight: info.weight,
      contract_rewrite: info.contract_rewrite,
      prompt_rewrite: info.prompt_rewrite,
    }))
    .sort((a, b) => b.weight - a.weight || a.code.localeCompare(b.code));
}

function buildArenaDecisionCaptureView(
  submission: SubmissionRecord,
  run: ArenaRunRecord | null,
  winnerContender: ArenaContenderResult | null,
  latestThreadForContender: ArenaReviewThreadEntry | null,
): ArenaDecisionCaptureView | null {
  if (!run) return null;

  const winnerContenderId = run.winner_contender_id ?? winnerContender?.contender_id ?? null;
  const managerReview = winnerContender?.manager_review && isRecord(winnerContender.manager_review)
    ? winnerContender.manager_review
    : null;

  const fallbackRecommendation = mapManagerDecisionToArenaRecommendation(managerReview?.decision);
  const recommendation = latestThreadForContender
    ? latestThreadForContender.recommendation
    : fallbackRecommendation;

  const managerConfidence = d1Number(managerReview?.confidence);
  const predictedConfidence = latestThreadForContender
    ? latestThreadForContender.confidence
    : managerConfidence === null
      ? 0.5
      : Math.max(0, Math.min(1, managerConfidence));

  const reviewerDecision = recommendationToReviewerDecision(recommendation);
  const defaultOutcomeStatus: ArenaOutcomeStatusView = reviewerDecision === 'approve'
    ? 'ACCEPTED'
    : reviewerDecision === 'request_changes'
      ? 'REWORK'
      : 'REJECTED';

  return {
    outcome_endpoint: {
      endpoint: `/v1/bounties/${submission.bounty_id}/arena/outcome`,
      method: 'POST',
      payload_template: {
        idempotency_key: `arena-outcome:${submission.submission_id}:${run.arena_id}`.slice(0, 128),
        arena_id: run.arena_id,
        contender_id: winnerContenderId,
        outcome_status: defaultOutcomeStatus,
        recommendation,
        reviewer_decision: reviewerDecision,
        rework_required: defaultOutcomeStatus === 'REWORK',
        reviewer_rationale: '',
        decision_taxonomy_tags: ['arena-review'],
        predicted_confidence: Number(predictedConfidence.toFixed(4)),
        review_time_minutes: 0,
        time_to_accept_minutes: null,
        override_reason_code: null,
        notes: '',
        source: 'bounty-review-ui',
        metadata: {
          decision_rationale: '',
          override_rationale: '',
          calibration_signal_tags: ['arena-review'],
        },
      },
    },
    outcome_status_options: buildArenaOutcomeStatusOptions(),
    reviewer_decision_options: buildArenaReviewerDecisionOptions(),
    override_reason_options: buildArenaOverrideReasonOptions(),
    calibration_bindings: {
      notes_path: 'notes',
      rationale_path: 'metadata.decision_rationale',
      override_reason_path: 'override_reason_code',
      reviewer_decision_path: 'reviewer_decision',
      reviewer_rationale_path: 'reviewer_rationale',
      decision_taxonomy_tags_path: 'decision_taxonomy_tags',
    },
  };
}

async function buildBountyReviewArenaFlowView(
  bounty: BountyV2,
  submission: SubmissionRecord,
  latestArena: ArenaInlineReviewSummaryView | null,
  decisionCapture: ArenaDecisionCaptureView | null,
): Promise<BountyReviewArenaFlowView> {
  return {
    start_arena: await buildArenaStartActionTemplateView(bounty, submission),
    latest_arena: latestArena,
    decision_capture: decisionCapture,
  };
}

function toSubmissionSummaryView(
  record: SubmissionRecord,
  latestTest: TestResultRecord | null,
  arenaReviewFlow: BountyReviewArenaFlowView,
): SubmissionSummaryView {
  return {
    submission_id: record.submission_id,
    bounty_id: record.bounty_id,
    worker_did: record.worker_did,
    status: record.status,
    proof_verify_status: record.proof_verify_status,
    proof_tier: record.proof_tier,
    commit_proof_verify_status: record.commit_proof_verify_status,
    commit_sha: record.commit_sha,
    created_at: record.created_at,
    updated_at: record.updated_at,
    latest_test_result: latestTest
      ? {
          test_result_id: latestTest.test_result_id,
          test_harness_id: latestTest.test_harness_id,
          passed: latestTest.passed,
          completed_at: latestTest.completed_at,
          error: latestTest.error,
        }
      : null,
    arena_review_flow: arenaReviewFlow,
  };
}

function toSubmissionDetailView(
  record: SubmissionRecord,
  latestTest: TestResultRecord | null,
  arenaReviewFlow: BountyReviewArenaFlowView,
): SubmissionDetailView {
  return {
    submission_id: record.submission_id,
    bounty_id: record.bounty_id,
    worker_did: record.worker_did,
    status: record.status,
    idempotency_key: record.idempotency_key,
    verification: {
      proof_bundle: {
        status: record.proof_verify_status,
        reason: record.proof_verify_reason,
        verified_at: record.proof_verified_at,
        proof_tier: record.proof_tier,
        proof_bundle_hash_b64u: record.proof_bundle_hash_b64u,
      },
      commit_proof: {
        status: record.commit_proof_verify_status,
        reason: record.commit_proof_verify_reason,
        verified_at: record.commit_proof_verified_at,
        commit_proof_hash_b64u: record.commit_proof_hash_b64u,
      },
    },
    source: {
      commit_sha: record.commit_sha,
      repo_url: record.repo_url,
      repo_claim_id: record.repo_claim_id,
    },
    output: {
      result_summary: record.result_summary,
      artifacts: record.artifacts,
      agent_pack: record.agent_pack,
      execution_attestations: record.execution_attestations,
    },
    latest_test_result: latestTest
      ? {
          test_result_id: latestTest.test_result_id,
          test_harness_id: latestTest.test_harness_id,
          passed: latestTest.passed,
          total_tests: latestTest.total_tests,
          passed_tests: latestTest.passed_tests,
          failed_tests: latestTest.failed_tests,
          execution_time_ms: latestTest.execution_time_ms,
          completed_at: latestTest.completed_at,
          error: latestTest.error,
        }
      : null,
    arena_review_flow: arenaReviewFlow,
    created_at: record.created_at,
    updated_at: record.updated_at,
  };
}

async function getBountyByIdempotencyKey(db: D1Database, key: string): Promise<BountyV2 | null> {
  const row = await db.prepare('SELECT * FROM bounties WHERE create_idempotency_key = ?').bind(key).first();
  if (!row || !isRecord(row)) return null;
  return parseBountyRow(row);
}

async function getBountyById(db: D1Database, bountyId: string): Promise<BountyV2 | null> {
  const row = await db.prepare('SELECT * FROM bounties WHERE bounty_id = ?').bind(bountyId).first();
  if (!row || !isRecord(row)) return null;
  return parseBountyRow(row);
}

async function getBountyByEscrowId(db: D1Database, escrowId: string): Promise<BountyV2 | null> {
  const row = await db
    .prepare('SELECT * FROM bounties WHERE escrow_id = ? ORDER BY created_at DESC, bounty_id DESC LIMIT 1')
    .bind(escrowId)
    .first();
  if (!row || !isRecord(row)) return null;
  return parseBountyRow(row);
}

async function updateBountyAccepted(
  db: D1Database,
  params: {
    bounty_id: string;
    worker_did: string;
    accepted_at: string;
    idempotency_key: string;
    cwc_worker_envelope_json: string | null;
    cwc_token_scope_hash_b64u: string | null;
    job_token_scope_hash_b64u: string | null;
    now: string;
  }
): Promise<void> {
  await db
    .prepare(
      `UPDATE bounties
         SET worker_did = ?,
             accepted_at = ?,
             status = 'accepted',
             accept_idempotency_key = COALESCE(accept_idempotency_key, ?),
             cwc_worker_envelope_json = COALESCE(cwc_worker_envelope_json, ?),
             cwc_token_scope_hash_b64u = COALESCE(cwc_token_scope_hash_b64u, ?),
             job_token_scope_hash_b64u = COALESCE(job_token_scope_hash_b64u, ?),
             updated_at = ?
       WHERE bounty_id = ?
         AND (worker_did IS NULL OR worker_did = ?)`
    )
    .bind(
      params.worker_did,
      params.accepted_at,
      params.idempotency_key,
      params.cwc_worker_envelope_json,
      params.cwc_token_scope_hash_b64u,
      params.job_token_scope_hash_b64u,
      params.now,
      params.bounty_id,
      params.worker_did
    )
    .run();
}

async function updateBountyCwcWorkerEnvelope(
  db: D1Database,
  params: {
    bounty_id: string;
    worker_did: string;
    cwc_worker_envelope_json: string;
    now: string;
  }
): Promise<void> {
  const result = await db
    .prepare(
      `UPDATE bounties
         SET cwc_worker_envelope_json = COALESCE(cwc_worker_envelope_json, ?),
             updated_at = ?
       WHERE bounty_id = ?
         AND worker_did = ?`
    )
    .bind(params.cwc_worker_envelope_json, params.now, params.bounty_id, params.worker_did)
    .run();

  if (!result || !result.success || !result.meta || result.meta.changes === 0) {
    throw new Error('CWC_COUNTERSIGN_UPDATE_FAILED');
  }
}

async function updateBountyCwcTokenScopeHash(
  db: D1Database,
  params: {
    bounty_id: string;
    worker_did: string;
    cwc_token_scope_hash_b64u: string;
    now: string;
  }
): Promise<void> {
  const result = await db
    .prepare(
      `UPDATE bounties
         SET cwc_token_scope_hash_b64u = COALESCE(cwc_token_scope_hash_b64u, ?),
             updated_at = ?
       WHERE bounty_id = ?
         AND worker_did = ?`
    )
    .bind(params.cwc_token_scope_hash_b64u, params.now, params.bounty_id, params.worker_did)
    .run();

  if (!result || !result.success || !result.meta || result.meta.changes === 0) {
    throw new Error('CWC_TOKEN_SCOPE_UPDATE_FAILED');
  }
}

async function updateBountyJobTokenScopeHash(
  db: D1Database,
  params: {
    bounty_id: string;
    worker_did: string;
    job_token_scope_hash_b64u: string;
    now: string;
  }
): Promise<void> {
  const result = await db
    .prepare(
      `UPDATE bounties
         SET job_token_scope_hash_b64u = COALESCE(job_token_scope_hash_b64u, ?),
             updated_at = ?
       WHERE bounty_id = ?
         AND worker_did = ?`
    )
    .bind(params.job_token_scope_hash_b64u, params.now, params.bounty_id, params.worker_did)
    .run();

  if (!result || !result.success || !result.meta || result.meta.changes === 0) {
    throw new Error('JOB_TOKEN_SCOPE_UPDATE_FAILED');
  }
}

async function updateBountyApproved(
  db: D1Database,
  params: {
    bounty_id: string;
    submission_id: string;
    idempotency_key: string;
    approved_at: string;
    now: string;
  }
): Promise<void> {
  const result = await db
    .prepare(
      `UPDATE bounties
         SET status = 'approved',
             approved_submission_id = COALESCE(approved_submission_id, ?),
             approve_idempotency_key = COALESCE(approve_idempotency_key, ?),
             approved_at = COALESCE(approved_at, ?),
             updated_at = ?
       WHERE bounty_id = ?
         AND status = 'pending_review'`
    )
    .bind(
      params.submission_id,
      params.idempotency_key,
      params.approved_at,
      params.now,
      params.bounty_id
    )
    .run();

  if (!result || !result.success || !result.meta || result.meta.changes === 0) {
    throw new Error('BOUNTY_DECISION_UPDATE_FAILED');
  }
}

async function updateBountyRejected(
  db: D1Database,
  params: {
    bounty_id: string;
    submission_id: string;
    idempotency_key: string;
    rejected_at: string;
    now: string;
    trial_case_id?: string | null;
    trial_opened_at?: string | null;
  }
): Promise<void> {
  const result = await db
    .prepare(
      `UPDATE bounties
         SET status = 'disputed',
             rejected_submission_id = COALESCE(rejected_submission_id, ?),
             reject_idempotency_key = COALESCE(reject_idempotency_key, ?),
             rejected_at = COALESCE(rejected_at, ?),
             trial_case_id = COALESCE(trial_case_id, ?),
             trial_opened_at = COALESCE(trial_opened_at, ?),
             updated_at = ?
       WHERE bounty_id = ?
         AND status = 'pending_review'`
    )
    .bind(
      params.submission_id,
      params.idempotency_key,
      params.rejected_at,
      params.trial_case_id ?? null,
      params.trial_opened_at ?? null,
      params.now,
      params.bounty_id
    )
    .run();

  if (!result || !result.success || !result.meta || result.meta.changes === 0) {
    throw new Error('BOUNTY_DECISION_UPDATE_FAILED');
  }
}

async function updateBountyTrialCase(
  db: D1Database,
  params: {
    bounty_id: string;
    trial_case_id: string;
    trial_opened_at: string;
    now: string;
  }
): Promise<void> {
  const result = await db
    .prepare(
      `UPDATE bounties
         SET trial_case_id = COALESCE(trial_case_id, ?),
             trial_opened_at = COALESCE(trial_opened_at, ?),
             updated_at = ?
       WHERE bounty_id = ?`
    )
    .bind(params.trial_case_id, params.trial_opened_at, params.now, params.bounty_id)
    .run();

  if (!result || !result.success || !result.meta || result.meta.changes === 0) {
    throw new Error('BOUNTY_TRIAL_CASE_UPDATE_FAILED');
  }
}

async function insertBounty(db: D1Database, record: BountyV2): Promise<void> {
  await db
    .prepare(
      `INSERT INTO bounties (
        bounty_id,
        create_idempotency_key,
        requester_did,
        title,
        description,
        reward_amount_minor,
        reward_currency,
        closure_type,
        difficulty_scalar,
        is_code_bounty,
        tags_json,
        min_proof_tier,
        require_owner_verified_votes,
        test_harness_id,
        metadata_json,
        job_token_scope_hash_b64u,
        cwc_hash_b64u,
        cwc_wpc_policy_hash_b64u,
        cwc_required_proof_tier,
        cwc_token_scope_hash_b64u,
        cwc_buyer_envelope_json,
        cwc_worker_envelope_json,
        fee_quote_json,
        fee_policy_version,
        all_in_cost_json,
        escrow_id,
        status,
        created_at,
        updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      record.bounty_id,
      record.idempotency_key,
      record.requester_did,
      record.title,
      record.description,
      record.reward.amount_minor,
      record.reward.currency,
      record.closure_type,
      record.difficulty_scalar,
      record.is_code_bounty ? 1 : 0,
      JSON.stringify(record.tags),
      record.min_proof_tier,
      record.require_owner_verified_votes ? 1 : 0,
      record.test_harness_id,
      JSON.stringify(record.metadata),
      record.job_token_scope_hash_b64u,
      record.cwc_hash_b64u,
      record.cwc_wpc_policy_hash_b64u,
      record.cwc_required_proof_tier,
      record.cwc_token_scope_hash_b64u,
      record.cwc_buyer_envelope ? JSON.stringify(record.cwc_buyer_envelope) : null,
      record.cwc_worker_envelope ? JSON.stringify(record.cwc_worker_envelope) : null,
      JSON.stringify(record.fee_quote),
      record.fee_policy_version,
      JSON.stringify(record.all_in_cost),
      record.escrow_id,
      record.status,
      record.created_at,
      record.updated_at
    )
    .run();
}

function prepareInsertSubmission(db: D1Database, record: SubmissionRecord): D1PreparedStatement {
  return db
    .prepare(
      `INSERT INTO submissions (
        submission_id,
        bounty_id,
        worker_did,
        status,
        idempotency_key,
        proof_bundle_envelope_json,
        proof_bundle_hash_b64u,
        proof_verify_status,
        proof_verify_reason,
        proof_verified_at,
        proof_tier,
        execution_attestations_json,
        commit_proof_envelope_json,
        commit_proof_hash_b64u,
        commit_sha,
        repo_url,
        repo_claim_id,
        commit_proof_verify_status,
        commit_proof_verify_reason,
        commit_proof_verified_at,
        artifacts_json,
        agent_pack_json,
        result_summary,
        created_at,
        updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      record.submission_id,
      record.bounty_id,
      record.worker_did,
      record.status,
      record.idempotency_key,
      JSON.stringify(record.proof_bundle_envelope),
      record.proof_bundle_hash_b64u,
      record.proof_verify_status,
      record.proof_verify_reason,
      record.proof_verified_at,
      record.proof_tier,
      record.execution_attestations ? JSON.stringify(record.execution_attestations) : null,
      record.commit_proof_envelope ? JSON.stringify(record.commit_proof_envelope) : null,
      record.commit_proof_hash_b64u,
      record.commit_sha,
      record.repo_url,
      record.repo_claim_id,
      record.commit_proof_verify_status,
      record.commit_proof_verify_reason,
      record.commit_proof_verified_at,
      record.artifacts ? JSON.stringify(record.artifacts) : null,
      record.agent_pack ? JSON.stringify(record.agent_pack) : null,
      record.result_summary,
      record.created_at,
      record.updated_at
    );
}

async function insertSubmission(db: D1Database, record: SubmissionRecord): Promise<void> {
  await prepareInsertSubmission(db, record).run();
}

function prepareInsertSubmissionTrustPulse(db: D1Database, row: StoredTrustPulseRow): D1PreparedStatement {
  return db
    .prepare(
      `INSERT INTO submission_trust_pulse (
        submission_id,
        run_id,
        agent_did,
        trust_pulse_json,
        hash_b64u,
        status,
        created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      row.submission_id,
      row.run_id,
      row.agent_did,
      row.trust_pulse_json,
      row.hash_b64u,
      row.status,
      row.created_at
    );
}

async function getSubmissionTrustPulseBySubmissionId(
  db: D1Database,
  submissionId: string
): Promise<StoredTrustPulseRow | null> {
  const row = await db
    .prepare(
      'SELECT submission_id, run_id, agent_did, trust_pulse_json, hash_b64u, status, created_at FROM submission_trust_pulse WHERE submission_id = ?'
    )
    .bind(submissionId)
    .first();

  if (!row || !isRecord(row)) return null;

  const submission_id = d1String(row.submission_id);
  const run_id = d1String(row.run_id);
  const agent_did = d1String(row.agent_did);
  const trust_pulse_json = d1String(row.trust_pulse_json);
  const hash_b64u = d1String(row.hash_b64u);
  const statusRaw = d1String(row.status);
  const created_at = d1String(row.created_at);

  const status: TrustPulseStorageStatus | null =
    statusRaw === 'verified' ? 'verified' : statusRaw === 'unverified' ? 'unverified' : null;

  if (!submission_id || !run_id || !agent_did || !trust_pulse_json || !hash_b64u || !status || !created_at) {
    return null;
  }

  return {
    submission_id,
    run_id,
    agent_did,
    trust_pulse_json,
    hash_b64u,
    status,
    created_at,
  };
}

function prepareInsertReplayRun(
  db: D1Database,
  params: {
    agent_did: string;
    run_id: string;
    bounty_id: string;
    submission_id: string;
  }
): D1PreparedStatement {
  return db
    .prepare(
      `INSERT INTO replay_runs (
        agent_did,
        run_id,
        bounty_id,
        submission_id
      ) VALUES (?, ?, ?, ?)`
    )
    .bind(params.agent_did, params.run_id, params.bounty_id, params.submission_id);
}

function prepareInsertReplayReceipt(
  db: D1Database,
  params: {
    receipt_signer_did: string;
    receipt_id: string;
    bounty_id: string;
    submission_id: string;
  }
): D1PreparedStatement {
  return db
    .prepare(
      `INSERT INTO replay_receipts (
        receipt_signer_did,
        receipt_id,
        bounty_id,
        submission_id
      ) VALUES (?, ?, ?, ?)`
    )
    .bind(
      params.receipt_signer_did,
      params.receipt_id,
      params.bounty_id,
      params.submission_id
    );
}

async function getReplayRun(
  db: D1Database,
  params: { agent_did: string; run_id: string }
): Promise<{ bounty_id: string; submission_id: string; first_seen_at: string } | null> {
  const row = await db
    .prepare(
      'SELECT bounty_id, submission_id, first_seen_at FROM replay_runs WHERE agent_did = ? AND run_id = ?'
    )
    .bind(params.agent_did, params.run_id)
    .first();

  if (!row || !isRecord(row)) return null;

  const bounty_id = d1String(row.bounty_id);
  const submission_id = d1String(row.submission_id);
  const first_seen_at = d1String(row.first_seen_at);

  if (!bounty_id || !submission_id || !first_seen_at) return null;

  return { bounty_id, submission_id, first_seen_at };
}

async function getReplayReceipt(
  db: D1Database,
  params: { receipt_signer_did: string; receipt_id: string }
): Promise<{ bounty_id: string; submission_id: string; first_seen_at: string } | null> {
  const row = await db
    .prepare(
      'SELECT bounty_id, submission_id, first_seen_at FROM replay_receipts WHERE receipt_signer_did = ? AND receipt_id = ?'
    )
    .bind(params.receipt_signer_did, params.receipt_id)
    .first();

  if (!row || !isRecord(row)) return null;

  const bounty_id = d1String(row.bounty_id);
  const submission_id = d1String(row.submission_id);
  const first_seen_at = d1String(row.first_seen_at);

  if (!bounty_id || !submission_id || !first_seen_at) return null;

  return { bounty_id, submission_id, first_seen_at };
}

async function insertSubmissionWithReplayGuards(
  db: D1Database,
  params: {
    record: SubmissionRecord;
    agent_did?: string | null;
    run_id?: string | null;
    receipt_keys?: ReplayReceiptKey[];
    trust_pulse?: StoredTrustPulseRow | null;
  }
): Promise<void> {
  const stmts: D1PreparedStatement[] = [];

  if (params.agent_did && params.run_id) {
    stmts.push(
      prepareInsertReplayRun(db, {
        agent_did: params.agent_did,
        run_id: params.run_id,
        bounty_id: params.record.bounty_id,
        submission_id: params.record.submission_id,
      })
    );
  }

  if (params.receipt_keys && params.receipt_keys.length > 0) {
    for (const k of params.receipt_keys) {
      stmts.push(
        prepareInsertReplayReceipt(db, {
          receipt_signer_did: k.receipt_signer_did,
          receipt_id: k.receipt_id,
          bounty_id: params.record.bounty_id,
          submission_id: params.record.submission_id,
        })
      );
    }
  }

  // Insert submission first (trust pulse references submission_id).
  stmts.push(prepareInsertSubmission(db, params.record));

  if (params.trust_pulse) {
    stmts.push(prepareInsertSubmissionTrustPulse(db, params.trust_pulse));
  }

  await db.batch(stmts);
}

async function insertTestResult(db: D1Database, record: TestResultRecord): Promise<void> {
  await db
    .prepare(
      `INSERT INTO test_results (
        test_result_id,
        submission_id,
        bounty_id,
        test_harness_id,
        passed,
        total_tests,
        passed_tests,
        failed_tests,
        execution_time_ms,
        completed_at,
        error,
        test_results_json,
        created_at,
        updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      record.test_result_id,
      record.submission_id,
      record.bounty_id,
      record.test_harness_id,
      record.passed ? 1 : 0,
      record.total_tests,
      record.passed_tests,
      record.failed_tests,
      record.execution_time_ms,
      record.completed_at,
      record.error,
      JSON.stringify(record.test_results),
      record.created_at,
      record.updated_at
    )
    .run();
}

async function insertRequesterAuthEvent(
  db: D1Database,
  params: {
    action: RequesterAuthAction;
    bounty_id: string | null;
    submission_id: string | null;
    auth: RequesterAuthContext;
    created_at: string;
    sensitive_transition: boolean;
    control_plane_check?: Record<string, unknown> | null;
  }
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO requester_auth_events (
         auth_event_id,
         action,
         bounty_id,
         submission_id,
         requester_did,
         auth_mode,
         token_hash,
         scope_json,
         aud_json,
         token_scope_hash_b64u,
         token_lane,
         payment_account_did,
         token_iat,
         token_exp,
         sensitive_transition,
         control_plane_check_json,
         created_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      `rae_${crypto.randomUUID()}`,
      params.action,
      params.bounty_id,
      params.submission_id,
      params.auth.requester_did,
      params.auth.auth_mode,
      params.auth.token_hash,
      JSON.stringify(params.auth.scope),
      JSON.stringify(params.auth.aud),
      params.auth.token_scope_hash_b64u,
      params.auth.token_lane,
      params.auth.payment_account_did,
      params.auth.iat,
      params.auth.exp,
      params.sensitive_transition ? 1 : 0,
      params.control_plane_check ? JSON.stringify(params.control_plane_check) : null,
      params.created_at
    )
    .run();
}

async function getSubmissionById(db: D1Database, submissionId: string): Promise<SubmissionRecord | null> {
  const row = await db.prepare('SELECT * FROM submissions WHERE submission_id = ?').bind(submissionId).first();
  if (!row || !isRecord(row)) return null;
  return parseSubmissionRow(row);
}

async function getSubmissionByIdempotencyKey(
  db: D1Database,
  key: string,
  workerDid: string,
  bountyId: string
): Promise<{ record: SubmissionRecord } | { conflict: SubmissionRecord } | null> {
  const row = await db.prepare('SELECT * FROM submissions WHERE idempotency_key = ?').bind(key).first();
  if (!row || !isRecord(row)) return null;
  const record = parseSubmissionRow(row);
  if (!record) return null;
  if (record.worker_did !== workerDid || record.bounty_id !== bountyId) {
    return { conflict: record };
  }
  return { record };
}

async function updateBountyStatus(
  db: D1Database,
  bountyId: string,
  status: BountyStatus,
  now: string,
  expectedCurrentStatus?: BountyStatus
): Promise<void> {
  let sql = 'UPDATE bounties SET status = ?, updated_at = ? WHERE bounty_id = ?';
  const bindings: unknown[] = [status, now, bountyId];

  if (expectedCurrentStatus) {
    sql += ' AND status = ?';
    bindings.push(expectedCurrentStatus);
  }

  const result = await db.prepare(sql).bind(...bindings).run();
  if (!result || !result.success || !result.meta || result.meta.changes === 0) {
    throw new Error('BOUNTY_STATUS_UPDATE_FAILED');
  }
}

async function updateSubmissionStatus(
  db: D1Database,
  submissionId: string,
  status: SubmissionStatus,
  now: string,
  expectedCurrentStatus?: SubmissionStatus
): Promise<void> {
  let sql = 'UPDATE submissions SET status = ?, updated_at = ? WHERE submission_id = ?';
  const bindings: unknown[] = [status, now, submissionId];

  if (expectedCurrentStatus) {
    sql += ' AND status = ?';
    bindings.push(expectedCurrentStatus);
  }

  const result = await db.prepare(sql).bind(...bindings).run();
  if (!result || !result.success || !result.meta || result.meta.changes === 0) {
    throw new Error('SUBMISSION_STATUS_UPDATE_FAILED');
  }
}

function parseBountyRiskEventRow(row: unknown): BountyRiskEventRecord | null {
  if (!isRecord(row)) return null;

  const risk_event_id = d1String(row.risk_event_id);
  const idempotency_key = d1String(row.idempotency_key);
  const source_loss_event_id = d1String(row.source_loss_event_id);
  const source_service = d1String(row.source_service);
  const source_event_id = d1String(row.source_event_id);
  const bounty_id = d1String(row.bounty_id);
  const account_did = d1String(row.account_did);
  const amount_minor = d1String(row.amount_minor);
  const currency = d1String(row.currency);
  const reason_code = d1String(row.reason_code);
  const severityRaw = d1String(row.severity);
  const metadata_json = d1String(row.metadata_json);
  const created_at = d1String(row.created_at);
  const updated_at = d1String(row.updated_at);

  if (!risk_event_id || !idempotency_key || !source_loss_event_id || !source_service || !bounty_id || !amount_minor || !currency || !reason_code || !severityRaw || !created_at || !updated_at) {
    return null;
  }

  if (currency !== 'USD') return null;
  if (severityRaw !== 'low' && severityRaw !== 'medium' && severityRaw !== 'high' && severityRaw !== 'critical') {
    return null;
  }

  return {
    risk_event_id,
    idempotency_key,
    source_loss_event_id,
    source_service,
    source_event_id,
    bounty_id,
    account_did,
    amount_minor,
    currency: 'USD',
    reason_code,
    severity: severityRaw,
    metadata_json,
    created_at,
    updated_at,
  };
}

async function getBountyRiskEventByIdempotencyKey(db: D1Database, key: string): Promise<BountyRiskEventRecord | null> {
  const row = await db.prepare('SELECT * FROM bounty_risk_events WHERE idempotency_key = ?').bind(key).first();
  return parseBountyRiskEventRow(row);
}

async function getBountyRiskEventById(db: D1Database, riskEventId: string): Promise<BountyRiskEventRecord | null> {
  const row = await db.prepare('SELECT * FROM bounty_risk_events WHERE risk_event_id = ?').bind(riskEventId).first();
  return parseBountyRiskEventRow(row);
}

function parseBountyRiskClearRow(row: unknown): BountyRiskClearRecord | null {
  if (!isRecord(row)) return null;

  const clear_id = d1String(row.clear_id);
  const idempotency_key = d1String(row.idempotency_key);
  const source_loss_event_id = d1String(row.source_loss_event_id);
  const bounty_id = d1String(row.bounty_id);
  const reason = d1String(row.reason);
  const metadata_json = d1String(row.metadata_json);
  const created_at = d1String(row.created_at);
  const updated_at = d1String(row.updated_at);

  if (!clear_id || !idempotency_key || !source_loss_event_id || !bounty_id || !created_at || !updated_at) {
    return null;
  }

  return {
    clear_id,
    idempotency_key,
    source_loss_event_id,
    bounty_id,
    reason,
    metadata_json,
    created_at,
    updated_at,
  };
}

async function getBountyRiskClearByIdempotencyKey(db: D1Database, key: string): Promise<BountyRiskClearRecord | null> {
  const row = await db.prepare('SELECT * FROM bounty_risk_event_clears WHERE idempotency_key = ?').bind(key).first();
  return parseBountyRiskClearRow(row);
}

async function getBountyRiskClearById(db: D1Database, clearId: string): Promise<BountyRiskClearRecord | null> {
  const row = await db.prepare('SELECT * FROM bounty_risk_event_clears WHERE clear_id = ?').bind(clearId).first();
  return parseBountyRiskClearRow(row);
}

async function getBountyRiskClearByPair(
  db: D1Database,
  sourceLossEventId: string,
  bountyId: string
): Promise<BountyRiskClearRecord | null> {
  const row = await db
    .prepare('SELECT * FROM bounty_risk_event_clears WHERE source_loss_event_id = ? AND bounty_id = ?')
    .bind(sourceLossEventId, bountyId)
    .first();

  return parseBountyRiskClearRow(row);
}

function parseArenaRunRow(row: unknown): ArenaRunRecord | null {
  if (!isRecord(row)) return null;

  const run_id = d1String(row.run_id);
  const arena_id = d1String(row.arena_id);
  const bounty_id = d1String(row.bounty_id);
  const status = parseArenaRunStatus(d1String(row.status));
  const contract_id = d1String(row.contract_id);
  const contract_hash_b64u = d1String(row.contract_hash_b64u);
  const task_fingerprint = d1String(row.task_fingerprint);
  const objective_profile_json = d1String(row.objective_profile_json);
  const arena_report_json = d1String(row.arena_report_json);
  const winner_contender_id = d1String(row.winner_contender_id);
  const winner_reason = d1String(row.winner_reason);
  const reason_codes_json = d1String(row.reason_codes_json);
  const tradeoffs_json = d1String(row.tradeoffs_json);
  const registry_version = d1String(row.registry_version);
  const experiment_id = d1String(row.experiment_id);
  const experiment_arm = d1String(row.experiment_arm);
  const start_idempotency_key = d1String(row.start_idempotency_key);
  const result_idempotency_key = d1String(row.result_idempotency_key);
  const report_hash_b64u = d1String(row.report_hash_b64u);
  const started_at = d1String(row.started_at);
  const completed_at = d1String(row.completed_at);
  const created_at = d1String(row.created_at);
  const updated_at = d1String(row.updated_at);

  if (
    !run_id ||
    !arena_id ||
    !bounty_id ||
    !status ||
    !contract_id ||
    !contract_hash_b64u ||
    !task_fingerprint ||
    !objective_profile_json ||
    !start_idempotency_key ||
    !started_at ||
    !created_at ||
    !updated_at
  ) {
    return null;
  }

  return {
    run_id,
    arena_id,
    bounty_id,
    status,
    contract_id,
    contract_hash_b64u,
    task_fingerprint,
    objective_profile_json,
    arena_report_json,
    winner_contender_id,
    winner_reason,
    reason_codes_json,
    tradeoffs_json,
    registry_version: registry_version ? registry_version.trim() : null,
    experiment_id: experiment_id ? experiment_id.trim() : null,
    experiment_arm: experiment_arm ? experiment_arm.trim() : null,
    start_idempotency_key,
    result_idempotency_key,
    report_hash_b64u,
    started_at,
    completed_at,
    created_at,
    updated_at,
  };
}

function parseArenaContenderRow(row: unknown): ArenaContenderRecord | null {
  if (!isRecord(row)) return null;

  const run_id = d1String(row.run_id);
  const contender_id = d1String(row.contender_id);
  const label = d1String(row.label);
  const model = d1String(row.model);
  const harness = d1String(row.harness);
  const tools_json = d1String(row.tools_json);
  const skills_json = d1String(row.skills_json);
  const plugins_json = d1String(row.plugins_json);
  const version_pin = d1String(row.version_pin);
  const prompt_template = d1String(row.prompt_template);
  const experiment_arm = d1String(row.experiment_arm);
  const score = d1Number(row.score);
  const hard_gate_pass_num = d1Number(row.hard_gate_pass);
  const mandatory_failed = d1Number(row.mandatory_failed);
  const metrics_json = d1String(row.metrics_json);
  const check_results_json = d1String(row.check_results_json);
  const proof_pack_json = d1String(row.proof_pack_json);
  const manager_review_json = d1String(row.manager_review_json);
  const review_paste = d1String(row.review_paste);
  const created_at = d1String(row.created_at);
  const updated_at = d1String(row.updated_at);

  if (
    !run_id ||
    !contender_id ||
    !label ||
    !model ||
    !harness ||
    !tools_json ||
    !skills_json ||
    !plugins_json ||
    score === null ||
    hard_gate_pass_num === null ||
    mandatory_failed === null ||
    !metrics_json ||
    !check_results_json ||
    !review_paste ||
    !created_at ||
    !updated_at
  ) {
    return null;
  }

  return {
    run_id,
    contender_id,
    label,
    model,
    harness,
    tools_json,
    skills_json,
    plugins_json,
    version_pin: version_pin ? version_pin.trim() : null,
    prompt_template: prompt_template ? prompt_template.trim() : null,
    experiment_arm: experiment_arm ? experiment_arm.trim() : null,
    score,
    hard_gate_pass: hard_gate_pass_num !== 0,
    mandatory_failed,
    metrics_json,
    check_results_json,
    proof_pack_json,
    manager_review_json,
    review_paste,
    created_at,
    updated_at,
  };
}

function parseArenaMetrics(value: Record<string, unknown>): ArenaContenderResult['metrics'] | null {
  const quality_score = d1Number(value.quality_score);
  const risk_score = d1Number(value.risk_score);
  const efficiency_score = d1Number(value.efficiency_score);
  const latency_ms = d1Number(value.latency_ms);
  const cost_usd = d1Number(value.cost_usd);
  const autonomy_score = d1Number(value.autonomy_score);

  if (
    quality_score === null ||
    risk_score === null ||
    efficiency_score === null ||
    latency_ms === null ||
    cost_usd === null ||
    autonomy_score === null
  ) {
    return null;
  }

  return {
    quality_score,
    risk_score,
    efficiency_score,
    latency_ms,
    cost_usd,
    autonomy_score,
  };
}

function parseArenaCheckResults(input: unknown): ArenaCheckResult[] {
  if (!Array.isArray(input)) return [];

  const out: ArenaCheckResult[] = [];
  for (const item of input) {
    if (!isRecord(item)) continue;

    const criterion_id = d1String(item.criterion_id);
    const requiredRaw = item.required;
    const statusRaw = d1String(item.status);
    const reason_code = d1String(item.reason_code);

    if (!criterion_id || !statusRaw || !reason_code) continue;
    if (statusRaw !== 'PASS' && statusRaw !== 'FAIL') continue;

    out.push({
      criterion_id,
      required: requiredRaw === true,
      status: statusRaw,
      reason_code,
    });
  }

  return out;
}

function parseArenaScoreExplainLinks(value: unknown): ArenaScoreExplainLink[] {
  if (!Array.isArray(value)) return [];

  const evidenceLinks: ArenaScoreExplainLink[] = [];
  for (const raw of value) {
    if (!isRecord(raw)) continue;
    const label = d1String(raw.label);
    const url = d1String(raw.url);
    const source = d1String(raw.source);

    if (!label || !url) continue;
    evidenceLinks.push(source ? { label, url, source } : { label, url });
  }

  return evidenceLinks;
}

function parseArenaScoreExplain(value: unknown, fallbackFinalScore = 0): ArenaScoreExplain {
  if (!isRecord(value)) {
    return {
      final_score: fallbackFinalScore,
      reason_codes: [],
      evidence_links: [],
    };
  }

  const derived = isRecord(value.derived) ? value.derived : null;
  const reasonCodes = parseStringList(value.reason_codes, 32, 128, true) ?? [];
  const evidenceLinks = parseArenaScoreExplainLinks(value.evidence_links);

  const finalScore = d1Number(derived?.final_score);

  return {
    final_score: finalScore ?? fallbackFinalScore,
    reason_codes: reasonCodes,
    evidence_links: evidenceLinks,
  };
}

function parseArenaThreadLinks(value: unknown): ArenaThreadLink[] {
  if (!Array.isArray(value)) return [];

  const out: ArenaThreadLink[] = [];
  for (const raw of value) {
    if (!isRecord(raw)) continue;
    const label = d1String(raw.label);
    const url = d1String(raw.url);
    if (!label || !url) continue;
    out.push({ label, url });
  }

  return out;
}

function parseArenaContenderResult(record: ArenaContenderRecord): ArenaContenderResult | null {
  const tools = parseJsonStringArray(record.tools_json);
  const skills = parseJsonStringArray(record.skills_json);
  const plugins = parseJsonStringArray(record.plugins_json);
  const metricsObj = parseJsonObject(record.metrics_json);
  const checkResultsRaw = parseJsonUnknownArray(record.check_results_json);

  if (!tools || !skills || !plugins || !metricsObj) return null;

  const metrics = parseArenaMetrics(metricsObj);
  if (!metrics) return null;

  const proofPack = record.proof_pack_json ? parseJsonObject(record.proof_pack_json) : null;
  const managerReview = record.manager_review_json ? parseJsonObject(record.manager_review_json) : null;

  const proofPackConfig = parseArenaContenderConfigFromProofPack(proofPack);

  return {
    contender_id: record.contender_id,
    label: record.label,
    model: record.model,
    harness: record.harness,
    tools,
    skills,
    plugins,
    version_pin: record.version_pin,
    prompt_template: record.prompt_template,
    experiment_arm: record.experiment_arm,
    score: record.score,
    hard_gate_pass: record.hard_gate_pass,
    mandatory_failed: record.mandatory_failed,
    metrics,
    check_results: parseArenaCheckResults(checkResultsRaw),
    score_explain: parseArenaScoreExplain(proofPack?.score_explain, record.score),
    insights: proofPackConfig.insights,
    proof_pack: proofPack,
    manager_review: managerReview,
    review_paste: record.review_paste,
  };
}

async function getArenaRunByArenaId(db: D1Database, arenaId: string): Promise<ArenaRunRecord | null> {
  const row = await db.prepare('SELECT * FROM bounty_arena_runs WHERE arena_id = ?').bind(arenaId).first();
  return parseArenaRunRow(row);
}

async function getArenaRunByStartIdempotencyKey(db: D1Database, key: string): Promise<ArenaRunRecord | null> {
  const row = await db.prepare('SELECT * FROM bounty_arena_runs WHERE start_idempotency_key = ?').bind(key).first();
  return parseArenaRunRow(row);
}

async function getArenaRunByResultIdempotencyKey(db: D1Database, key: string): Promise<ArenaRunRecord | null> {
  const row = await db.prepare('SELECT * FROM bounty_arena_runs WHERE result_idempotency_key = ?').bind(key).first();
  return parseArenaRunRow(row);
}

async function getLatestArenaRunByBountyId(db: D1Database, bountyId: string): Promise<ArenaRunRecord | null> {
  const row = await db
    .prepare('SELECT * FROM bounty_arena_runs WHERE bounty_id = ? ORDER BY updated_at DESC, run_id DESC LIMIT 1')
    .bind(bountyId)
    .first();

  return parseArenaRunRow(row);
}

async function listArenaRuns(
  db: D1Database,
  limit: number,
): Promise<ArenaRunRecord[]> {
  const rows = await db
    .prepare('SELECT * FROM bounty_arena_runs ORDER BY updated_at DESC, run_id DESC LIMIT ?')
    .bind(limit)
    .all<Record<string, unknown>>();

  const out: ArenaRunRecord[] = [];
  for (const row of rows.results ?? []) {
    const parsed = parseArenaRunRow(row);
    if (parsed) out.push(parsed);
  }

  return out;
}

async function listPendingArenaRuns(
  db: D1Database,
  params: {
    limit: number;
    arenaIds?: string[];
  },
): Promise<ArenaRunRecord[]> {
  const arenaIds = params.arenaIds ?? [];

  let query = `SELECT *
                 FROM bounty_arena_runs
                WHERE status = 'started'`;

  const binds: unknown[] = [];
  if (arenaIds.length > 0) {
    query += ` AND arena_id IN (${arenaIds.map(() => '?').join(', ')})`;
    binds.push(...arenaIds);
  }

  query += ' ORDER BY started_at ASC, run_id ASC LIMIT ?';
  binds.push(params.limit);

  const rows = await db
    .prepare(query)
    .bind(...binds)
    .all<Record<string, unknown>>();

  const out: ArenaRunRecord[] = [];
  for (const row of rows.results ?? []) {
    const parsed = parseArenaRunRow(row);
    if (parsed) out.push(parsed);
  }

  return out;
}

async function listCompletedArenaRunsByTaskFingerprint(
  db: D1Database,
  taskFingerprint: string,
  limit: number,
): Promise<ArenaRunRecord[]> {
  const rows = await db
    .prepare(
      `SELECT *
         FROM bounty_arena_runs
        WHERE status = 'completed'
          AND task_fingerprint = ?
        ORDER BY updated_at DESC, run_id DESC
        LIMIT ?`
    )
    .bind(taskFingerprint, limit)
    .all<Record<string, unknown>>();

  const out: ArenaRunRecord[] = [];
  for (const row of rows.results ?? []) {
    const parsed = parseArenaRunRow(row);
    if (parsed) out.push(parsed);
  }

  return out;
}

async function listArenaContendersByRunId(db: D1Database, runId: string): Promise<ArenaContenderRecord[]> {
  const rows = await db
    .prepare('SELECT * FROM bounty_arena_contenders WHERE run_id = ? ORDER BY score DESC, contender_id ASC')
    .bind(runId)
    .all<Record<string, unknown>>();

  const out: ArenaContenderRecord[] = [];
  for (const row of rows.results ?? []) {
    const parsed = parseArenaContenderRow(row);
    if (parsed) out.push(parsed);
  }

  return out;
}

function parseArenaReviewThreadRow(row: unknown): ArenaReviewThreadEntry | null {
  if (!isRecord(row)) return null;

  const thread_entry_id = d1String(row.thread_entry_id);
  const idempotency_key = d1String(row.idempotency_key);
  const bounty_id = d1String(row.bounty_id);
  const arena_id = d1String(row.arena_id);
  const contender_id = d1String(row.contender_id);
  const recommendationRaw = d1String(row.recommendation);
  const confidence = d1Number(row.confidence);
  const body_markdown = d1String(row.body_markdown);
  const links_json = d1String(row.links_json);
  const source = d1String(row.source);
  const metadata_json = d1String(row.metadata_json);
  const created_at = d1String(row.created_at);
  const updated_at = d1String(row.updated_at);

  if (
    !thread_entry_id ||
    !idempotency_key ||
    !bounty_id ||
    !arena_id ||
    !contender_id ||
    !recommendationRaw ||
    confidence === null ||
    !body_markdown ||
    !links_json ||
    !source ||
    !created_at ||
    !updated_at
  ) {
    return null;
  }

  if (recommendationRaw !== 'APPROVE' && recommendationRaw !== 'REQUEST_CHANGES' && recommendationRaw !== 'REJECT') {
    return null;
  }

  return {
    thread_entry_id,
    idempotency_key,
    bounty_id,
    arena_id,
    contender_id,
    recommendation: recommendationRaw,
    confidence,
    body_markdown,
    links_json,
    source,
    metadata_json,
    created_at,
    updated_at,
  };
}

async function getArenaReviewThreadByIdempotencyKey(db: D1Database, key: string): Promise<ArenaReviewThreadEntry | null> {
  const row = await db
    .prepare('SELECT * FROM bounty_arena_review_thread WHERE idempotency_key = ?')
    .bind(key)
    .first();

  return parseArenaReviewThreadRow(row);
}

async function listArenaReviewThreadByBountyId(
  db: D1Database,
  bountyId: string,
  limit: number,
): Promise<ArenaReviewThreadEntry[]> {
  const rows = await db
    .prepare('SELECT * FROM bounty_arena_review_thread WHERE bounty_id = ? ORDER BY created_at DESC, thread_entry_id DESC LIMIT ?')
    .bind(bountyId, limit)
    .all<Record<string, unknown>>();

  const out: ArenaReviewThreadEntry[] = [];
  for (const row of rows.results ?? []) {
    const parsed = parseArenaReviewThreadRow(row);
    if (parsed) out.push(parsed);
  }

  return out;
}

async function listArenaReviewThreadByArenaId(
  db: D1Database,
  arenaId: string,
  limit: number,
): Promise<ArenaReviewThreadEntry[]> {
  const rows = await db
    .prepare('SELECT * FROM bounty_arena_review_thread WHERE arena_id = ? ORDER BY created_at DESC, thread_entry_id DESC LIMIT ?')
    .bind(arenaId, limit)
    .all<Record<string, unknown>>();

  const out: ArenaReviewThreadEntry[] = [];
  for (const row of rows.results ?? []) {
    const parsed = parseArenaReviewThreadRow(row);
    if (parsed) out.push(parsed);
  }

  return out;
}

async function writeArenaReviewThreadEntry(
  db: D1Database,
  entry: ArenaReviewThreadEntry,
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO bounty_arena_review_thread (
        thread_entry_id,
        idempotency_key,
        bounty_id,
        arena_id,
        contender_id,
        recommendation,
        confidence,
        body_markdown,
        links_json,
        source,
        metadata_json,
        created_at,
        updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      entry.thread_entry_id,
      entry.idempotency_key,
      entry.bounty_id,
      entry.arena_id,
      entry.contender_id,
      entry.recommendation,
      entry.confidence,
      entry.body_markdown,
      entry.links_json,
      entry.source,
      entry.metadata_json,
      entry.created_at,
      entry.updated_at,
    )
    .run();
}

function parseArenaOutcomeRow(row: unknown): ArenaOutcomeRecord | null {
  if (!isRecord(row)) return null;

  const outcome_id = d1String(row.outcome_id);
  const idempotency_key = d1String(row.idempotency_key);
  const bounty_id = d1String(row.bounty_id);
  const arena_id = d1String(row.arena_id);
  const contender_id = d1String(row.contender_id);
  const outcome_status = d1String(row.outcome_status);
  const accepted = d1Boolean(row.accepted);
  const overridden = d1Boolean(row.overridden);
  const rework_required = d1Boolean(row.rework_required);
  const disputed = d1Boolean(row.disputed);
  const review_time_minutes = d1Number(row.review_time_minutes);
  const time_to_accept_minutes = d1Number(row.time_to_accept_minutes);
  const predicted_confidence = d1Number(row.predicted_confidence);
  const recommendation = d1String(row.recommendation);
  const reviewer_decision_raw = d1String(row.reviewer_decision);
  const reviewer_rationale = d1String(row.reviewer_rationale);
  const decision_taxonomy_json_raw = d1String(row.decision_taxonomy_json);
  const override_reason_code = d1String(row.override_reason_code);
  const notes = d1String(row.notes);
  const source = d1String(row.source);
  const metadata_json = d1String(row.metadata_json);
  const created_at = d1String(row.created_at);
  const updated_at = d1String(row.updated_at);

  if (
    !outcome_id ||
    !idempotency_key ||
    !bounty_id ||
    !arena_id ||
    !contender_id ||
    !outcome_status ||
    accepted === null ||
    overridden === null ||
    rework_required === null ||
    disputed === null ||
    review_time_minutes === null ||
    predicted_confidence === null ||
    !recommendation ||
    !source ||
    !created_at ||
    !updated_at
  ) {
    return null;
  }

  if (
    outcome_status !== 'ACCEPTED' &&
    outcome_status !== 'OVERRIDDEN' &&
    outcome_status !== 'REWORK' &&
    outcome_status !== 'REJECTED' &&
    outcome_status !== 'DISPUTED'
  ) {
    return null;
  }

  if (recommendation !== 'APPROVE' && recommendation !== 'REQUEST_CHANGES' && recommendation !== 'REJECT') {
    return null;
  }

  const recommendationValue = recommendation as ArenaRecommendationView;
  const reviewer_decision = normalizeArenaReviewerDecision(reviewer_decision_raw)
    ?? recommendationToReviewerDecision(recommendationValue);

  let decision_taxonomy_json = '[]';
  if (decision_taxonomy_json_raw) {
    const parsedTags = parseJsonUnknownArray(decision_taxonomy_json_raw);
    if (!parsedTags) return null;
    const normalizedTags = parseStringList(parsedTags, 30, 64, true) ?? [];
    decision_taxonomy_json = stableStringify(normalizedTags);
  }

  const normalizedOverrideReason = normalizeArenaOverrideReasonCode(override_reason_code);

  return {
    outcome_id,
    idempotency_key,
    bounty_id,
    arena_id,
    contender_id,
    outcome_status,
    accepted,
    overridden,
    rework_required,
    disputed,
    review_time_minutes,
    time_to_accept_minutes,
    predicted_confidence,
    recommendation: recommendationValue,
    reviewer_decision,
    reviewer_rationale,
    decision_taxonomy_json,
    override_reason_code: overridden
      ? (normalizedOverrideReason ?? 'ARENA_OVERRIDE_OTHER')
      : (normalizedOverrideReason ?? null),
    notes,
    source,
    metadata_json,
    created_at,
    updated_at,
  };
}

async function getArenaOutcomeByIdempotencyKey(db: D1Database, key: string): Promise<ArenaOutcomeRecord | null> {
  const row = await db
    .prepare('SELECT * FROM bounty_arena_outcomes WHERE idempotency_key = ?')
    .bind(key)
    .first();

  return parseArenaOutcomeRow(row);
}

async function listArenaOutcomes(db: D1Database, limit: number): Promise<ArenaOutcomeRecord[]> {
  const rows = await db
    .prepare('SELECT * FROM bounty_arena_outcomes ORDER BY created_at DESC, outcome_id DESC LIMIT ?')
    .bind(limit)
    .all<Record<string, unknown>>();

  const out: ArenaOutcomeRecord[] = [];
  for (const row of rows.results ?? []) {
    const parsed = parseArenaOutcomeRow(row);
    if (parsed) out.push(parsed);
  }

  return out;
}

async function listArenaOutcomesByArenaId(
  db: D1Database,
  arenaId: string,
  limit: number,
): Promise<ArenaOutcomeRecord[]> {
  const rows = await db
    .prepare('SELECT * FROM bounty_arena_outcomes WHERE arena_id = ? ORDER BY created_at DESC, outcome_id DESC LIMIT ?')
    .bind(arenaId, limit)
    .all<Record<string, unknown>>();

  const out: ArenaOutcomeRecord[] = [];
  for (const row of rows.results ?? []) {
    const parsed = parseArenaOutcomeRow(row);
    if (parsed) out.push(parsed);
  }

  return out;
}

async function writeArenaOutcome(
  db: D1Database,
  outcome: ArenaOutcomeRecord,
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO bounty_arena_outcomes (
        outcome_id,
        idempotency_key,
        bounty_id,
        arena_id,
        contender_id,
        outcome_status,
        accepted,
        overridden,
        rework_required,
        disputed,
        review_time_minutes,
        time_to_accept_minutes,
        predicted_confidence,
        recommendation,
        reviewer_decision,
        reviewer_rationale,
        decision_taxonomy_json,
        override_reason_code,
        notes,
        source,
        metadata_json,
        created_at,
        updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      outcome.outcome_id,
      outcome.idempotency_key,
      outcome.bounty_id,
      outcome.arena_id,
      outcome.contender_id,
      outcome.outcome_status,
      outcome.accepted ? 1 : 0,
      outcome.overridden ? 1 : 0,
      outcome.rework_required ? 1 : 0,
      outcome.disputed ? 1 : 0,
      outcome.review_time_minutes,
      outcome.time_to_accept_minutes,
      outcome.predicted_confidence,
      outcome.recommendation,
      outcome.reviewer_decision,
      outcome.reviewer_rationale,
      outcome.decision_taxonomy_json,
      outcome.override_reason_code,
      outcome.notes,
      outcome.source,
      outcome.metadata_json,
      outcome.created_at,
      outcome.updated_at,
    )
    .run();
}

function parseArenaContractLanguageSuggestionRow(row: unknown): ArenaContractLanguageSuggestionRecord | null {
  if (!isRecord(row)) return null;

  const suggestion_id = d1String(row.suggestion_id);
  const task_fingerprint = d1String(row.task_fingerprint);
  const scope = d1String(row.scope);
  const contender_id = d1String(row.contender_id);
  const reason_code_raw = d1String(row.reason_code);
  const failures = d1Number(row.failures);
  const overrides = d1Number(row.overrides);
  const share = d1Number(row.share);
  const priority_score = d1Number(row.priority_score);
  const contract_rewrite = d1String(row.contract_rewrite);
  const prompt_rewrite = d1String(row.prompt_rewrite);
  const contract_language_patch = d1String(row.contract_language_patch);
  const prompt_language_patch = d1String(row.prompt_language_patch);
  const sample_notes_json = d1String(row.sample_notes_json);
  const tags_json = d1String(row.tags_json);
  const computed_at = d1String(row.computed_at);
  const created_at = d1String(row.created_at);
  const updated_at = d1String(row.updated_at);

  if (
    !suggestion_id ||
    !task_fingerprint ||
    !scope ||
    contender_id === null ||
    !reason_code_raw ||
    failures === null ||
    overrides === null ||
    share === null ||
    priority_score === null ||
    !contract_rewrite ||
    !prompt_rewrite ||
    !contract_language_patch ||
    !prompt_language_patch ||
    !sample_notes_json ||
    !tags_json ||
    !computed_at ||
    !created_at ||
    !updated_at
  ) {
    return null;
  }

  if (scope !== 'global' && scope !== 'contender') return null;

  const reason_code = normalizeArenaOverrideReasonCode(reason_code_raw);
  if (!reason_code) return null;

  return {
    suggestion_id,
    task_fingerprint,
    scope,
    contender_id,
    reason_code,
    failures,
    overrides,
    share,
    priority_score,
    contract_rewrite,
    prompt_rewrite,
    contract_language_patch,
    prompt_language_patch,
    sample_notes_json,
    tags_json,
    computed_at,
    created_at,
    updated_at,
  };
}

async function listArenaContractLanguageSuggestions(
  db: D1Database,
  params: {
    taskFingerprint?: string | null;
    contenderId?: string | null;
    limit: number;
  },
): Promise<ArenaContractLanguageSuggestionRecord[]> {
  const taskFingerprint = params.taskFingerprint?.trim() ?? null;
  const contenderId = params.contenderId?.trim() ?? null;

  let sql = 'SELECT * FROM bounty_arena_contract_language_suggestions';
  const binds: Array<string | number> = [];
  const where: string[] = [];

  if (taskFingerprint) {
    where.push('task_fingerprint = ?');
    binds.push(taskFingerprint);
  }

  if (contenderId) {
    where.push('contender_id = ?');
    binds.push(contenderId);
  }

  if (where.length > 0) {
    sql += ` WHERE ${where.join(' AND ')}`;
  }

  sql += ' ORDER BY priority_score DESC, failures DESC, updated_at DESC, suggestion_id ASC LIMIT ?';
  binds.push(params.limit);

  const rows = await db
    .prepare(sql)
    .bind(...binds)
    .all<Record<string, unknown>>();

  const out: ArenaContractLanguageSuggestionRecord[] = [];
  for (const row of rows.results ?? []) {
    const parsed = parseArenaContractLanguageSuggestionRow(row);
    if (parsed) out.push(parsed);
  }

  return out;
}

async function replaceArenaContractLanguageSuggestions(
  db: D1Database,
  taskFingerprint: string,
  suggestions: ArenaContractLanguageSuggestionRecord[],
): Promise<void> {
  await db
    .prepare('DELETE FROM bounty_arena_contract_language_suggestions WHERE task_fingerprint = ?')
    .bind(taskFingerprint)
    .run();

  for (const suggestion of suggestions) {
    await db
      .prepare(
        `INSERT INTO bounty_arena_contract_language_suggestions (
          suggestion_id,
          task_fingerprint,
          scope,
          contender_id,
          reason_code,
          failures,
          overrides,
          share,
          priority_score,
          contract_rewrite,
          prompt_rewrite,
          contract_language_patch,
          prompt_language_patch,
          sample_notes_json,
          tags_json,
          computed_at,
          created_at,
          updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        suggestion.suggestion_id,
        suggestion.task_fingerprint,
        suggestion.scope,
        suggestion.contender_id,
        suggestion.reason_code,
        suggestion.failures,
        suggestion.overrides,
        suggestion.share,
        suggestion.priority_score,
        suggestion.contract_rewrite,
        suggestion.prompt_rewrite,
        suggestion.contract_language_patch,
        suggestion.prompt_language_patch,
        suggestion.sample_notes_json,
        suggestion.tags_json,
        suggestion.computed_at,
        suggestion.created_at,
        suggestion.updated_at,
      )
      .run();
  }
}

function parseArenaContractCopilotSourceEvidence(
  input: string,
): Array<{
  arena_id: string;
  outcome_id: string;
  contender_id: string;
  criterion_id: string;
  reason_code: ArenaOverrideReasonCode;
}> {
  try {
    const parsed = JSON.parse(input);
    if (!Array.isArray(parsed)) return [];

    const entries = parsed
      .map((entry) => {
        if (!isRecord(entry)) return null;
        const arena_id = d1String(entry.arena_id)?.trim();
        const outcome_id = d1String(entry.outcome_id)?.trim();
        const contender_id = d1String(entry.contender_id)?.trim();
        const criterion_id = d1String(entry.criterion_id)?.trim();
        const reason_code_raw = d1String(entry.reason_code);
        const reason_code = normalizeArenaOverrideReasonCode(reason_code_raw);

        if (!arena_id || !outcome_id || !contender_id || !criterion_id || !reason_code) {
          return null;
        }

        return {
          arena_id,
          outcome_id,
          contender_id,
          criterion_id,
          reason_code,
        };
      })
      .filter((entry): entry is {
        arena_id: string;
        outcome_id: string;
        contender_id: string;
        criterion_id: string;
        reason_code: ArenaOverrideReasonCode;
      } => entry !== null);

    return entries;
  } catch {
    return [];
  }
}

function parseArenaContractCopilotSuggestionRow(row: unknown): ArenaContractCopilotSuggestionRecord | null {
  if (!isRecord(row)) return null;

  const suggestion_id = d1String(row.suggestion_id);
  const task_fingerprint = d1String(row.task_fingerprint);
  const scope = d1String(row.scope);
  const contender_id = d1String(row.contender_id);
  const reason_code_raw = d1String(row.reason_code);
  const before_text = d1String(row.before_text);
  const after_text = d1String(row.after_text);
  const rationale = d1String(row.rationale);
  const confidence = d1Number(row.confidence);
  const expected_override_reduction = d1Number(row.expected_override_reduction);
  const expected_rework_reduction = d1Number(row.expected_rework_reduction);
  const evidence_count = d1Number(row.evidence_count);
  const arena_count = d1Number(row.arena_count);
  const outcome_count = d1Number(row.outcome_count);
  const source_evidence_json = d1String(row.source_evidence_json);
  const computed_at = d1String(row.computed_at);
  const created_at = d1String(row.created_at);
  const updated_at = d1String(row.updated_at);

  if (
    !suggestion_id ||
    !task_fingerprint ||
    !scope ||
    contender_id === null ||
    !reason_code_raw ||
    !before_text ||
    !after_text ||
    !rationale ||
    confidence === null ||
    expected_override_reduction === null ||
    expected_rework_reduction === null ||
    evidence_count === null ||
    arena_count === null ||
    outcome_count === null ||
    !source_evidence_json ||
    !computed_at ||
    !created_at ||
    !updated_at
  ) {
    return null;
  }

  if (scope !== 'global' && scope !== 'contender') return null;

  const reason_code = normalizeArenaOverrideReasonCode(reason_code_raw);
  if (!reason_code) return null;

  if (parseArenaContractCopilotSourceEvidence(source_evidence_json).length === 0) {
    return null;
  }

  return {
    suggestion_id,
    task_fingerprint,
    scope,
    contender_id,
    reason_code,
    before_text,
    after_text,
    rationale,
    confidence,
    expected_override_reduction,
    expected_rework_reduction,
    evidence_count,
    arena_count,
    outcome_count,
    source_evidence_json,
    computed_at,
    created_at,
    updated_at,
  };
}

async function listArenaContractCopilotSuggestions(
  db: D1Database,
  params: {
    taskFingerprint?: string | null;
    contenderId?: string | null;
    limit: number;
  },
): Promise<ArenaContractCopilotSuggestionRecord[]> {
  const taskFingerprint = params.taskFingerprint?.trim() ?? null;
  const contenderId = params.contenderId?.trim() ?? null;

  let sql = 'SELECT * FROM bounty_arena_contract_copilot_suggestions';
  const binds: Array<string | number> = [];
  const where: string[] = [];

  if (taskFingerprint) {
    where.push('task_fingerprint = ?');
    binds.push(taskFingerprint);
  }

  if (contenderId) {
    where.push('contender_id = ?');
    binds.push(contenderId);
  }

  if (where.length > 0) {
    sql += ` WHERE ${where.join(' AND ')}`;
  }

  sql += ' ORDER BY confidence DESC, evidence_count DESC, updated_at DESC, suggestion_id ASC LIMIT ?';
  binds.push(params.limit);

  const rows = await db
    .prepare(sql)
    .bind(...binds)
    .all<Record<string, unknown>>();

  const out: ArenaContractCopilotSuggestionRecord[] = [];
  for (const row of rows.results ?? []) {
    const parsed = parseArenaContractCopilotSuggestionRow(row);
    if (parsed) out.push(parsed);
  }

  return out;
}

async function replaceArenaContractCopilotSuggestions(
  db: D1Database,
  taskFingerprint: string,
  suggestions: ArenaContractCopilotSuggestionRecord[],
): Promise<void> {
  await db
    .prepare('DELETE FROM bounty_arena_contract_copilot_suggestions WHERE task_fingerprint = ?')
    .bind(taskFingerprint)
    .run();

  for (const suggestion of suggestions) {
    await db
      .prepare(
        `INSERT INTO bounty_arena_contract_copilot_suggestions (
          suggestion_id,
          task_fingerprint,
          scope,
          contender_id,
          reason_code,
          before_text,
          after_text,
          rationale,
          confidence,
          expected_override_reduction,
          expected_rework_reduction,
          evidence_count,
          arena_count,
          outcome_count,
          source_evidence_json,
          computed_at,
          created_at,
          updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        suggestion.suggestion_id,
        suggestion.task_fingerprint,
        suggestion.scope,
        suggestion.contender_id,
        suggestion.reason_code,
        suggestion.before_text,
        suggestion.after_text,
        suggestion.rationale,
        suggestion.confidence,
        suggestion.expected_override_reduction,
        suggestion.expected_rework_reduction,
        suggestion.evidence_count,
        suggestion.arena_count,
        suggestion.outcome_count,
        suggestion.source_evidence_json,
        suggestion.computed_at,
        suggestion.created_at,
        suggestion.updated_at,
      )
      .run();
  }
}

function parseArenaHarnessFleetWorkerRow(row: unknown): ArenaHarnessFleetWorkerRecord | null {
  if (!isRecord(row)) return null;

  const worker_did = d1String(row.worker_did)?.trim();
  const harness = d1String(row.harness)?.trim();
  const model = d1String(row.model)?.trim();
  const skills_json = d1String(row.skills_json);
  const tools_json = d1String(row.tools_json);
  const objective_profiles_json = d1String(row.objective_profiles_json);
  const cost_tier = parseArenaFleetCostTier(row.cost_tier);
  const risk_tier = parseArenaFleetRiskTier(row.risk_tier);
  const availability_status = parseArenaFleetAvailabilityStatus(row.availability_status);
  const heartbeat_at = d1String(row.heartbeat_at);
  const heartbeat_seq = d1Number(row.heartbeat_seq);
  const metadata_json = d1String(row.metadata_json);
  const created_at = d1String(row.created_at);
  const updated_at = d1String(row.updated_at);

  if (
    !worker_did ||
    !harness ||
    !model ||
    !skills_json ||
    !tools_json ||
    !objective_profiles_json ||
    !cost_tier ||
    !risk_tier ||
    !availability_status ||
    heartbeat_seq === null ||
    !created_at ||
    !updated_at
  ) {
    return null;
  }

  const skills = parseArenaFleetStringJson(skills_json, 80, 120);
  const tools = parseArenaFleetStringJson(tools_json, 80, 120);
  const objectiveProfiles = parseArenaFleetStringJson(objective_profiles_json, 40, 120);

  if (!skills || !tools || !objectiveProfiles) return null;

  return {
    worker_did,
    harness,
    model,
    skills_json: stableStringify(skills),
    tools_json: stableStringify(tools),
    objective_profiles_json: stableStringify(objectiveProfiles),
    cost_tier,
    risk_tier,
    availability_status,
    heartbeat_at: heartbeat_at ? heartbeat_at.trim() : null,
    heartbeat_seq,
    metadata_json,
    created_at,
    updated_at,
  };
}

function buildArenaHarnessFleetWorkerPayload(record: ArenaHarnessFleetWorkerRecord): Record<string, unknown> {
  const skills = parseJsonStringArray(record.skills_json) ?? [];
  const tools = parseJsonStringArray(record.tools_json) ?? [];
  const objectiveProfiles = parseJsonStringArray(record.objective_profiles_json) ?? [];

  return {
    worker_did: record.worker_did,
    harness: record.harness,
    model: record.model,
    skills,
    tools,
    objective_profiles: objectiveProfiles,
    cost_tier: record.cost_tier,
    risk_tier: record.risk_tier,
    availability_status: record.availability_status,
    heartbeat_at: record.heartbeat_at,
    heartbeat_seq: record.heartbeat_seq,
    metadata: parseJsonObject(record.metadata_json ?? ''),
    created_at: record.created_at,
    updated_at: record.updated_at,
  };
}

async function getArenaHarnessFleetWorker(
  db: D1Database,
  workerDid: string,
): Promise<ArenaHarnessFleetWorkerRecord | null> {
  const row = await db
    .prepare('SELECT * FROM bounty_arena_harness_fleet_workers WHERE worker_did = ? LIMIT 1')
    .bind(workerDid)
    .first();

  return parseArenaHarnessFleetWorkerRow(row);
}

async function listArenaHarnessFleetWorkers(
  db: D1Database,
  params: {
    limit: number;
    availabilityStatus?: ArenaFleetAvailabilityStatus | null;
    harness?: string | null;
    objectiveProfileName?: string | null;
    costTier?: ArenaFleetCostTier | null;
    riskTier?: ArenaFleetRiskTier | null;
  },
): Promise<ArenaHarnessFleetWorkerRecord[]> {
  let sql = 'SELECT * FROM bounty_arena_harness_fleet_workers';
  const where: string[] = [];
  const binds: Array<string | number> = [];

  if (params.availabilityStatus) {
    where.push('availability_status = ?');
    binds.push(params.availabilityStatus);
  }

  if (params.harness) {
    where.push('harness = ?');
    binds.push(params.harness);
  }

  if (params.objectiveProfileName) {
    where.push('objective_profiles_json LIKE ?');
    binds.push(`%"${params.objectiveProfileName}"%`);
  }

  if (params.costTier) {
    where.push('cost_tier = ?');
    binds.push(params.costTier);
  }

  if (params.riskTier) {
    where.push('risk_tier = ?');
    binds.push(params.riskTier);
  }

  if (where.length > 0) {
    sql += ` WHERE ${where.join(' AND ')}`;
  }

  sql += ' ORDER BY availability_status ASC, heartbeat_at DESC, updated_at DESC LIMIT ?';
  binds.push(params.limit);

  const rows = await db.prepare(sql).bind(...binds).all<Record<string, unknown>>();
  const out: ArenaHarnessFleetWorkerRecord[] = [];
  for (const row of rows.results ?? []) {
    const parsed = parseArenaHarnessFleetWorkerRow(row);
    if (parsed) out.push(parsed);
  }
  return out;
}

async function upsertArenaHarnessFleetWorker(
  db: D1Database,
  record: ArenaHarnessFleetWorkerRecord,
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO bounty_arena_harness_fleet_workers (
        worker_did,
        harness,
        model,
        skills_json,
        tools_json,
        objective_profiles_json,
        cost_tier,
        risk_tier,
        availability_status,
        heartbeat_at,
        heartbeat_seq,
        metadata_json,
        created_at,
        updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(worker_did)
      DO UPDATE SET
        harness = excluded.harness,
        model = excluded.model,
        skills_json = excluded.skills_json,
        tools_json = excluded.tools_json,
        objective_profiles_json = excluded.objective_profiles_json,
        cost_tier = excluded.cost_tier,
        risk_tier = excluded.risk_tier,
        availability_status = excluded.availability_status,
        heartbeat_at = excluded.heartbeat_at,
        heartbeat_seq = excluded.heartbeat_seq,
        metadata_json = excluded.metadata_json,
        updated_at = excluded.updated_at`
    )
    .bind(
      record.worker_did,
      record.harness,
      record.model,
      record.skills_json,
      record.tools_json,
      record.objective_profiles_json,
      record.cost_tier,
      record.risk_tier,
      record.availability_status,
      record.heartbeat_at,
      record.heartbeat_seq,
      record.metadata_json,
      record.created_at,
      record.updated_at,
    )
    .run();
}

async function heartbeatArenaHarnessFleetWorker(
  db: D1Database,
  params: {
    workerDid: string;
    availabilityStatus: ArenaFleetAvailabilityStatus;
    metadataJson: string | null;
    now: string;
  },
): Promise<ArenaHarnessFleetWorkerRecord | null> {
  await db
    .prepare(
      `UPDATE bounty_arena_harness_fleet_workers
          SET availability_status = ?,
              heartbeat_at = ?,
              heartbeat_seq = heartbeat_seq + 1,
              metadata_json = COALESCE(?, metadata_json),
              updated_at = ?
        WHERE worker_did = ?`
    )
    .bind(
      params.availabilityStatus,
      params.now,
      params.metadataJson,
      params.now,
      params.workerDid,
    )
    .run();

  return getArenaHarnessFleetWorker(db, params.workerDid);
}

async function computeArenaFleetCapabilityMatch(
  db: D1Database,
  params: {
    objectiveProfileName?: string | null;
    harness?: string | null;
    contenderId?: string | null;
    requiredSkills?: string[];
    requiredTools?: string[];
    maxCostTier?: ArenaFleetCostTier | null;
    maxRiskTier?: ArenaFleetRiskTier | null;
    limit: number;
  },
): Promise<Record<string, unknown>> {
  const workers = await listArenaHarnessFleetWorkers(db, {
    limit: Math.max(params.limit * 4, 40),
    availabilityStatus: 'online',
    harness: params.harness?.trim() || null,
    objectiveProfileName: params.objectiveProfileName?.trim() || null,
  });

  const requiredSkills = dedupeStrings((params.requiredSkills ?? []).map((entry) => entry.trim()).filter((entry) => entry.length > 0));
  const requiredTools = dedupeStrings((params.requiredTools ?? []).map((entry) => entry.trim()).filter((entry) => entry.length > 0));

  const maxCostRank = params.maxCostTier ? arenaFleetTierRank(params.maxCostTier) : null;
  const maxRiskRank = params.maxRiskTier ? arenaFleetTierRank(params.maxRiskTier) : null;

  const candidates = workers
    .map((worker) => {
      const skills = parseJsonStringArray(worker.skills_json) ?? [];
      const tools = parseJsonStringArray(worker.tools_json) ?? [];
      const objectiveProfiles = parseJsonStringArray(worker.objective_profiles_json) ?? [];

      const skillHits = requiredSkills.filter((entry) => skills.includes(entry));
      const toolHits = requiredTools.filter((entry) => tools.includes(entry));
      const objectiveMatched = params.objectiveProfileName
        ? objectiveProfiles.includes(params.objectiveProfileName)
        : false;

      const costRank = arenaFleetTierRank(worker.cost_tier);
      const riskRank = arenaFleetTierRank(worker.risk_tier);

      const costBlocked = maxCostRank !== null && costRank > maxCostRank;
      const riskBlocked = maxRiskRank !== null && riskRank > maxRiskRank;

      const score =
        (objectiveMatched ? 35 : 0) +
        (skillHits.length * 12) +
        (toolHits.length * 8) +
        (worker.heartbeat_at ? 10 : 0) +
        (worker.availability_status === 'online' ? 10 : 0) -
        (costRank * 2) -
        (riskRank * 3);

      return {
        worker,
        score,
        skill_hits: skillHits,
        tool_hits: toolHits,
        objective_matched: objectiveMatched,
        cost_blocked: costBlocked,
        risk_blocked: riskBlocked,
      };
    })
    .filter((entry) => !entry.cost_blocked && !entry.risk_blocked)
    .sort((a, b) => b.score - a.score || a.worker.worker_did.localeCompare(b.worker.worker_did))
    .slice(0, params.limit);

  const reasonCodes: string[] = [];
  if (workers.length === 0) {
    reasonCodes.push('ARENA_FLEET_EMPTY');
  }
  if (workers.length > 0 && candidates.length === 0) {
    reasonCodes.push('ARENA_FLEET_CAPABILITY_BLOCKED');
  }
  if (candidates.length > 0) {
    reasonCodes.push('ARENA_FLEET_MATCHED');
  }
  if (params.contenderId) {
    reasonCodes.push('ARENA_FLEET_CONTENDER_BOUND');
  }

  const status = candidates.length > 0 ? 'matched' : 'unavailable';

  return {
    schema_version: 'arena_harness_fleet_match.v1',
    computed_at: new Date().toISOString(),
    status,
    reason_codes: reasonCodes,
    contender_id: params.contenderId ?? null,
    objective_profile_name: params.objectiveProfileName ?? null,
    harness: params.harness ?? null,
    required_skills: requiredSkills,
    required_tools: requiredTools,
    max_cost_tier: params.maxCostTier ?? null,
    max_risk_tier: params.maxRiskTier ?? null,
    total_online_workers: workers.length,
    candidates: candidates.map((entry) => ({
      ...buildArenaHarnessFleetWorkerPayload(entry.worker),
      match_score: Number(entry.score.toFixed(4)),
      skill_hits: entry.skill_hits,
      tool_hits: entry.tool_hits,
      objective_matched: entry.objective_matched,
    })),
  };
}

function parseArenaAutoClaimLockRow(row: unknown): ArenaAutoClaimLockRecord | null {
  if (!isRecord(row)) return null;

  const bounty_id = d1String(row.bounty_id);
  const lock_id = d1String(row.lock_id);
  const loop_id = d1String(row.loop_id);
  const claim_status = d1String(row.claim_status);
  const worker_did = d1String(row.worker_did);
  const contender_id = d1String(row.contender_id);
  const reason_code = d1String(row.reason_code);
  const claim_idempotency_key = d1String(row.claim_idempotency_key);
  const budget_minor_before = d1String(row.budget_minor_before);
  const budget_minor_after = d1String(row.budget_minor_after);
  const route_reason_codes_json = d1String(row.route_reason_codes_json);
  const metadata_json = d1String(row.metadata_json);
  const created_at = d1String(row.created_at);
  const updated_at = d1String(row.updated_at);

  if (
    !bounty_id ||
    !lock_id ||
    !loop_id ||
    !claim_status ||
    !reason_code ||
    !claim_idempotency_key ||
    !budget_minor_before ||
    !budget_minor_after ||
    !route_reason_codes_json ||
    !created_at ||
    !updated_at
  ) {
    return null;
  }

  if (claim_status !== 'processing' && claim_status !== 'claimed' && claim_status !== 'skipped' && claim_status !== 'failed') {
    return null;
  }

  return {
    bounty_id,
    lock_id,
    loop_id,
    claim_status,
    worker_did,
    contender_id,
    reason_code,
    claim_idempotency_key,
    budget_minor_before,
    budget_minor_after,
    route_reason_codes_json,
    metadata_json,
    created_at,
    updated_at,
  };
}

async function getArenaAutoClaimLockByBountyId(
  db: D1Database,
  bountyId: string,
): Promise<ArenaAutoClaimLockRecord | null> {
  const row = await db
    .prepare('SELECT * FROM bounty_arena_auto_claim_locks WHERE bounty_id = ? LIMIT 1')
    .bind(bountyId)
    .first();

  return parseArenaAutoClaimLockRow(row);
}

async function listArenaAutoClaimLocks(
  db: D1Database,
  params: {
    limit: number;
    claimStatus?: ArenaAutoClaimLockRecord['claim_status'] | null;
  },
): Promise<ArenaAutoClaimLockRecord[]> {
  let sql = 'SELECT * FROM bounty_arena_auto_claim_locks';
  const binds: Array<string | number> = [];

  if (params.claimStatus) {
    sql += ' WHERE claim_status = ?';
    binds.push(params.claimStatus);
  }

  sql += ' ORDER BY updated_at DESC, created_at DESC LIMIT ?';
  binds.push(params.limit);

  const rows = await db.prepare(sql).bind(...binds).all<Record<string, unknown>>();
  const out: ArenaAutoClaimLockRecord[] = [];
  for (const row of rows.results ?? []) {
    const parsed = parseArenaAutoClaimLockRow(row);
    if (parsed) out.push(parsed);
  }

  return out;
}

async function tryInsertArenaAutoClaimProcessingLock(
  db: D1Database,
  lock: ArenaAutoClaimLockRecord,
): Promise<boolean> {
  const result = await db
    .prepare(
      `INSERT OR IGNORE INTO bounty_arena_auto_claim_locks (
        bounty_id,
        lock_id,
        loop_id,
        claim_status,
        worker_did,
        contender_id,
        reason_code,
        claim_idempotency_key,
        budget_minor_before,
        budget_minor_after,
        route_reason_codes_json,
        metadata_json,
        created_at,
        updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      lock.bounty_id,
      lock.lock_id,
      lock.loop_id,
      lock.claim_status,
      lock.worker_did,
      lock.contender_id,
      lock.reason_code,
      lock.claim_idempotency_key,
      lock.budget_minor_before,
      lock.budget_minor_after,
      lock.route_reason_codes_json,
      lock.metadata_json,
      lock.created_at,
      lock.updated_at,
    )
    .run();

  return Boolean(result?.meta?.changes && result.meta.changes > 0);
}

async function finalizeArenaAutoClaimLock(
  db: D1Database,
  params: {
    bountyId: string;
    claimStatus: ArenaAutoClaimLockRecord['claim_status'];
    workerDid: string | null;
    contenderId: string | null;
    reasonCode: string;
    budgetMinorAfter: string;
    routeReasonCodes: string[];
    metadataJson: string | null;
    now: string;
  },
): Promise<void> {
  await db
    .prepare(
      `UPDATE bounty_arena_auto_claim_locks
          SET claim_status = ?,
              worker_did = ?,
              contender_id = ?,
              reason_code = ?,
              budget_minor_after = ?,
              route_reason_codes_json = ?,
              metadata_json = ?,
              updated_at = ?
        WHERE bounty_id = ?`
    )
    .bind(
      params.claimStatus,
      params.workerDid,
      params.contenderId,
      params.reasonCode,
      params.budgetMinorAfter,
      stableStringify(params.routeReasonCodes),
      params.metadataJson,
      params.now,
      params.bountyId,
    )
    .run();
}

function parseArenaRoutePolicyOptimizerStateRow(row: unknown): ArenaRoutePolicyOptimizerStateRecord | null {
  if (!isRecord(row)) return null;

  const state_id = d1String(row.state_id);
  const task_fingerprint = d1String(row.task_fingerprint);
  const environment = d1String(row.environment);
  const objective_profile_name = d1String(row.objective_profile_name);
  const experiment_id = d1String(row.experiment_id);
  const experiment_arm = d1String(row.experiment_arm);
  const active_policy_json = d1String(row.active_policy_json);
  const shadow_policy_json = d1String(row.shadow_policy_json);
  const last_promotion_event_json = d1String(row.last_promotion_event_json);
  const reason_codes_json = d1String(row.reason_codes_json);
  const sample_count = d1Number(row.sample_count);
  const confidence_score = d1Number(row.confidence_score);
  const min_samples = d1Number(row.min_samples);
  const min_confidence = d1Number(row.min_confidence);
  const promotion_status = d1String(row.promotion_status);
  const created_at = d1String(row.created_at);
  const updated_at = d1String(row.updated_at);

  if (
    !state_id ||
    !task_fingerprint ||
    !environment ||
    objective_profile_name === null ||
    experiment_id === null ||
    experiment_arm === null ||
    !shadow_policy_json ||
    !reason_codes_json ||
    sample_count === null ||
    confidence_score === null ||
    min_samples === null ||
    min_confidence === null ||
    !promotion_status ||
    !created_at ||
    !updated_at
  ) {
    return null;
  }

  if (promotion_status !== 'PROMOTED' && promotion_status !== 'NOT_READY') {
    return null;
  }

  return {
    state_id,
    task_fingerprint,
    environment,
    objective_profile_name,
    experiment_id,
    experiment_arm,
    active_policy_json,
    shadow_policy_json,
    last_promotion_event_json,
    reason_codes_json,
    sample_count,
    confidence_score,
    min_samples,
    min_confidence,
    promotion_status,
    created_at,
    updated_at,
  };
}

async function getArenaRoutePolicyOptimizerState(
  db: D1Database,
  params: {
    taskFingerprint: string;
    environment: string;
    objectiveProfileName: string;
    experimentId: string;
    experimentArm: string;
  },
): Promise<ArenaRoutePolicyOptimizerStateRecord | null> {
  const row = await db
    .prepare(
      `SELECT *
       FROM bounty_arena_route_policy_optimizer_state
       WHERE task_fingerprint = ?
         AND environment = ?
         AND objective_profile_name = ?
         AND experiment_id = ?
         AND experiment_arm = ?
       LIMIT 1`
    )
    .bind(
      params.taskFingerprint,
      params.environment,
      params.objectiveProfileName,
      params.experimentId,
      params.experimentArm,
    )
    .first();

  const parsed = parseArenaRoutePolicyOptimizerStateRow(row);
  if (parsed) return parsed;

  if (params.objectiveProfileName !== '' || params.experimentId !== '' || params.experimentArm !== '') {
    const fallbackRow = await db
      .prepare(
        `SELECT *
         FROM bounty_arena_route_policy_optimizer_state
         WHERE task_fingerprint = ?
           AND environment = ?
           AND objective_profile_name = ''
           AND experiment_id = ''
           AND experiment_arm = ''
         LIMIT 1`
      )
      .bind(params.taskFingerprint, params.environment)
      .first();
    return parseArenaRoutePolicyOptimizerStateRow(fallbackRow);
  }

  return null;
}

async function upsertArenaRoutePolicyOptimizerState(
  db: D1Database,
  state: ArenaRoutePolicyOptimizerStateRecord,
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO bounty_arena_route_policy_optimizer_state (
        state_id,
        task_fingerprint,
        environment,
        objective_profile_name,
        experiment_id,
        experiment_arm,
        active_policy_json,
        shadow_policy_json,
        last_promotion_event_json,
        reason_codes_json,
        sample_count,
        confidence_score,
        min_samples,
        min_confidence,
        promotion_status,
        created_at,
        updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(task_fingerprint, environment, objective_profile_name, experiment_id, experiment_arm)
      DO UPDATE SET
        state_id = excluded.state_id,
        active_policy_json = excluded.active_policy_json,
        shadow_policy_json = excluded.shadow_policy_json,
        last_promotion_event_json = excluded.last_promotion_event_json,
        reason_codes_json = excluded.reason_codes_json,
        sample_count = excluded.sample_count,
        confidence_score = excluded.confidence_score,
        min_samples = excluded.min_samples,
        min_confidence = excluded.min_confidence,
        promotion_status = excluded.promotion_status,
        updated_at = excluded.updated_at`
    )
    .bind(
      state.state_id,
      state.task_fingerprint,
      state.environment,
      state.objective_profile_name,
      state.experiment_id,
      state.experiment_arm,
      state.active_policy_json,
      state.shadow_policy_json,
      state.last_promotion_event_json,
      state.reason_codes_json,
      state.sample_count,
      state.confidence_score,
      state.min_samples,
      state.min_confidence,
      state.promotion_status,
      state.created_at,
      state.updated_at,
    )
    .run();
}

async function buildArenaRoutePolicyOptimizerStateId(params: {
  taskFingerprint: string;
  environment: string;
  objectiveProfileName: string;
  experimentId: string;
  experimentArm: string;
}): Promise<string> {
  const material = stableStringify({
    task_fingerprint: params.taskFingerprint,
    environment: params.environment,
    objective_profile_name: params.objectiveProfileName,
    experiment_id: params.experimentId,
    experiment_arm: params.experimentArm,
  });
  return `arps_${(await sha256B64uUtf8(material)).slice(0, 32)}`;
}

async function writeArenaContenderRecords(
  db: D1Database,
  runId: string,
  contenders: ArenaContenderResult[],
  now: string,
): Promise<void> {
  await db.prepare('DELETE FROM bounty_arena_contenders WHERE run_id = ?').bind(runId).run();

  for (const contender of contenders) {
    await db
      .prepare(
        `INSERT INTO bounty_arena_contenders (
          run_id,
          contender_id,
          label,
          model,
          harness,
          tools_json,
          skills_json,
          plugins_json,
          version_pin,
          prompt_template,
          experiment_arm,
          score,
          hard_gate_pass,
          mandatory_failed,
          metrics_json,
          check_results_json,
          proof_pack_json,
          manager_review_json,
          review_paste,
          created_at,
          updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        runId,
        contender.contender_id,
        contender.label,
        contender.model,
        contender.harness,
        stableStringify(contender.tools),
        stableStringify(contender.skills),
        stableStringify(contender.plugins),
        contender.version_pin,
        contender.prompt_template,
        contender.experiment_arm,
        contender.score,
        contender.hard_gate_pass ? 1 : 0,
        contender.mandatory_failed,
        stableStringify(contender.metrics),
        stableStringify(contender.check_results),
        contender.proof_pack ? stableStringify(contender.proof_pack) : null,
        contender.manager_review ? stableStringify(contender.manager_review) : null,
        contender.review_paste,
        now,
        now,
      )
      .run();
  }
}

async function annotatePendingArenaRunReasonCodes(
  db: D1Database,
  params: {
    runId: string;
    reasonCodes: string[];
    now: string;
  },
): Promise<void> {
  await db
    .prepare(
      `UPDATE bounty_arena_runs
          SET reason_codes_json = ?,
              updated_at = ?
        WHERE run_id = ?
          AND status = 'started'`
    )
    .bind(stableStringify(params.reasonCodes), params.now, params.runId)
    .run();
}

async function finalizeArenaRunResolution(
  db: D1Database,
  params: {
    runId: string;
    winnerContenderId: string | null;
    winnerReason: string;
    reasonCodes: string[];
    tradeoffs: string[];
    resultIdempotencyKey: string;
    arenaReport: Record<string, unknown> | null;
    now: string;
  },
): Promise<void> {
  const reportCanonical = params.arenaReport ? stableStringify(params.arenaReport) : null;
  const reportHash = reportCanonical ? await sha256B64uUtf8(reportCanonical) : null;

  await db
    .prepare(
      `UPDATE bounty_arena_runs
          SET status = 'completed',
              winner_contender_id = ?,
              winner_reason = ?,
              reason_codes_json = ?,
              tradeoffs_json = ?,
              arena_report_json = ?,
              result_idempotency_key = ?,
              report_hash_b64u = ?,
              completed_at = ?,
              updated_at = ?
        WHERE run_id = ?
          AND status = 'started'`
    )
    .bind(
      params.winnerContenderId,
      params.winnerReason,
      stableStringify(params.reasonCodes),
      stableStringify(params.tradeoffs),
      reportCanonical,
      params.resultIdempotencyKey,
      reportHash,
      params.now,
      params.now,
      params.runId,
    )
    .run();
}

function sanitizeArenaTaskFingerprint(input: string): string {
  const normalized = input
    .toLowerCase()
    .replace(/[^a-z0-9:_-]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-+|-+$/g, '');

  if (normalized.length === 0) return 'task:unknown';
  return normalized.slice(0, 120);
}

function deriveLiveArenaTaskFingerprint(bounty: BountyV2): string {
  const metadataFingerprint = d1String(bounty.metadata.task_fingerprint);
  if (metadataFingerprint && metadataFingerprint.trim().length > 0) {
    return sanitizeArenaTaskFingerprint(metadataFingerprint.trim());
  }

  const topTags = bounty.tags
    .slice(0, 3)
    .map((tag) => sanitizeArenaTaskFingerprint(tag))
    .filter((tag) => tag !== 'task:unknown')
    .join(':');

  const base = topTags ? `${bounty.closure_type}:${bounty.min_proof_tier}:${topTags}` : `${bounty.closure_type}:${bounty.min_proof_tier}`;
  return sanitizeArenaTaskFingerprint(base);
}

function buildLiveArenaObjectiveProfile(bounty: BountyV2): Record<string, unknown> {
  const fromMetadata = parseArenaObjectiveProfile(bounty.metadata.arena_objective_profile);
  if (fromMetadata) return fromMetadata;

  if (bounty.closure_type === 'test') {
    return {
      name: 'latency-balanced',
      weights: { quality: 0.35, speed: 0.3, cost: 0.15, safety: 0.2 },
      tie_breakers: ['hard_gate_pass', 'latency_ms', 'cost_usd'],
    };
  }

  if (bounty.min_proof_tier === 'sandbox') {
    return {
      name: 'safety-first',
      weights: { quality: 0.4, speed: 0.15, cost: 0.1, safety: 0.35 },
      tie_breakers: ['hard_gate_pass', 'risk_score', 'cost_usd'],
    };
  }

  return {
    name: 'balanced',
    weights: { quality: 0.45, speed: 0.2, cost: 0.15, safety: 0.2 },
    tie_breakers: ['hard_gate_pass', 'quality_score', 'cost_usd'],
  };
}

function buildSubmissionEvidenceLinks(submission: SubmissionRecord): ArenaScoreExplainLink[] {
  const links: ArenaScoreExplainLink[] = [];

  if (submission.repo_url) {
    links.push({
      label: 'submission_repo',
      url: submission.repo_url,
      source: 'submission',
    });

    if (submission.commit_sha) {
      const trimmedRepo = submission.repo_url.replace(/\.git$/i, '').replace(/\/$/, '');
      links.push({
        label: 'submission_commit',
        url: `${trimmedRepo}/commit/${submission.commit_sha}`,
        source: 'submission',
      });
    }
  }

  if (submission.proof_bundle_hash_b64u) {
    links.push({
      label: 'proof_bundle_hash',
      url: `urn:sha256:${submission.proof_bundle_hash_b64u}`,
      source: 'proof_bundle',
    });
  }

  return links;
}

function buildLiveArenaBaselineContender(bounty: BountyV2, submission: SubmissionRecord): ArenaContenderResult {
  const agentPack = submission.agent_pack;
  const model = d1String(agentPack?.model)?.trim() || 'unknown';
  const harness = bounty.test_harness_id ?? 'clawbounties-live';

  const tools = parseStringList(agentPack?.tools, 32, 120, true) ?? [];
  const skills = parseStringList(agentPack?.skills, 32, 120, true) ?? [];
  const plugins = parseStringList(agentPack?.plugins, 32, 120, true) ?? [];

  return {
    contender_id: `contender_submission_${submission.submission_id.slice(-12)}`,
    label: 'Live bounty submission',
    model,
    harness,
    tools,
    skills,
    plugins,
    version_pin: null,
    prompt_template: null,
    experiment_arm: null,
    score: 0,
    hard_gate_pass: false,
    mandatory_failed: 0,
    metrics: {
      quality_score: 0,
      risk_score: 0,
      efficiency_score: 0,
      latency_ms: 0,
      cost_usd: 0,
      autonomy_score: 0,
    },
    check_results: [],
    score_explain: {
      final_score: 0,
      reason_codes: ['ARENA_LIVE_TRIGGERED'],
      evidence_links: buildSubmissionEvidenceLinks(submission),
    },
    insights: {
      bottlenecks: [],
      contract_improvements: [],
      next_delegation_hints: [],
    },
    proof_pack: null,
    manager_review: null,
    review_paste: 'Live arena trigger created from submission; contender evaluation pending.',
  };
}

function getWinnerEvidenceLinks(contenders: ArenaContenderResult[], winnerContenderId: string): ArenaScoreExplainLink[] {
  const winner = contenders.find((entry) => entry.contender_id === winnerContenderId);
  if (!winner) return [];
  return winner.score_explain.evidence_links.slice(0, 20);
}

function mapArenaManagerDecisionToRecommendation(
  decision: string | null,
  hardGatePass: boolean,
): 'APPROVE' | 'REQUEST_CHANGES' | 'REJECT' {
  const normalized = String(decision ?? '').trim().toLowerCase();
  if (normalized === 'promote') return 'APPROVE';
  if (normalized === 'conditional' || normalized === 'iterate') return 'REQUEST_CHANGES';
  if (normalized === 'reject') return 'REJECT';
  return hardGatePass ? 'APPROVE' : 'REQUEST_CHANGES';
}

function buildArenaAutoReviewThreadBody(
  contender: ArenaContenderResult,
  recommendation: 'APPROVE' | 'REQUEST_CHANGES' | 'REJECT',
  confidence: number,
  reasonCodes: string[],
): string {
  const managerDecision = isRecord(contender.manager_review) ? d1String(contender.manager_review.decision) : null;
  const nextAction = isRecord(contender.manager_review)
    ? d1String(contender.manager_review.recommended_next_action)
    : null;

  const managerSummaryLines = [
    `## Arena Auto Decision — ${contender.label} (${contender.contender_id})`,
    '',
    `Recommendation: **${recommendation}**`,
    `Confidence: **${(confidence * 100).toFixed(1)}%**`,
    managerDecision ? `Manager decision: \`${managerDecision}\`` : null,
    `Hard-gate pass: **${contender.hard_gate_pass ? 'yes' : 'no'}**`,
    `Metrics: quality=${contender.metrics.quality_score.toFixed(2)}, risk=${contender.metrics.risk_score.toFixed(2)}, efficiency=${contender.metrics.efficiency_score.toFixed(2)}, cost=$${contender.metrics.cost_usd.toFixed(4)}, latency=${Math.round(contender.metrics.latency_ms)}ms`,
  ].filter((line) => line !== null);

  if (reasonCodes.length > 0) {
    managerSummaryLines.push('', '### Reason codes', ...reasonCodes.map((code) => `- \`${code}\``));
  }

  if (nextAction && nextAction.trim().length > 0) {
    managerSummaryLines.push('', `Next action: ${nextAction.trim()}`);
  }

  const reviewPaste = contender.review_paste.trim();
  const reviewPasteBody = reviewPaste.length > 0 ? reviewPaste : 'No review paste available.';

  return `${managerSummaryLines.join('\n')}\n\n---\n\n${reviewPasteBody}`;
}

async function autoPostArenaWinnerReviewThread(
  db: D1Database,
  params: {
    bounty_id: string;
    arena_id: string;
    result_idempotency_key: string;
    contender: ArenaContenderResult;
    source: string;
    now: string;
    arena_explorer_base_url: string;
  },
): Promise<ArenaReviewThreadEntry> {
  const managerReview = isRecord(params.contender.manager_review) ? params.contender.manager_review : null;
  const managerDecision = d1String(managerReview?.decision);
  const recommendation = mapArenaManagerDecisionToRecommendation(managerDecision, params.contender.hard_gate_pass);
  const confidenceRaw = d1Number(managerReview?.confidence);
  const confidence = Math.max(0, Math.min(1, confidenceRaw ?? (params.contender.hard_gate_pass ? 0.72 : 0.45)));
  const managerReasonCodes = parseStringList(managerReview?.reason_codes, 32, 128, true) ?? [];
  const reasonCodes = managerReasonCodes.length > 0
    ? managerReasonCodes
    : params.contender.score_explain.reason_codes;

  const arenaExplorerBaseUrl = params.arena_explorer_base_url.replace(/\/$/, '');
  const encodedArenaId = encodeURIComponent(params.arena_id);
  const encodedContenderId = encodeURIComponent(params.contender.contender_id);

  const reviewArtifactLinks = [
    {
      label: 'Review paste',
      url: `${arenaExplorerBaseUrl}/arena/${encodedArenaId}?contender=${encodedContenderId}#review-paste-${encodedContenderId}`,
    },
    {
      label: 'Manager review',
      url: `${arenaExplorerBaseUrl}/arena/${encodedArenaId}?contender=${encodedContenderId}#manager-review-${encodedContenderId}`,
    },
  ];

  const linkSeen = new Set<string>();
  const links = [
    ...params.contender.score_explain.evidence_links
      .slice(0, 10)
      .map((entry) => ({ label: entry.label, url: entry.url })),
    ...reviewArtifactLinks,
  ].filter((entry) => {
    if (!entry.url || !entry.label) return false;
    const key = `${entry.label}::${entry.url}`;
    if (linkSeen.has(key)) return false;
    linkSeen.add(key);
    return true;
  }).slice(0, 12);

  const bodyMarkdown = buildArenaAutoReviewThreadBody(params.contender, recommendation, confidence, reasonCodes);
  const idempotencyMaterial = stableStringify({
    arena_id: params.arena_id,
    contender_id: params.contender.contender_id,
    recommendation,
    confidence,
    result_idempotency_key: params.result_idempotency_key,
    body_hash: await sha256B64uUtf8(bodyMarkdown),
  });
  const idempotencyKey = `arena-thread-auto:${await sha256B64uUtf8(idempotencyMaterial)}`;

  const existing = await getArenaReviewThreadByIdempotencyKey(db, idempotencyKey);
  if (existing) return existing;

  const metadata = {
    manager_decision: managerDecision,
    reason_codes: reasonCodes,
    evidence_links: params.contender.score_explain.evidence_links,
    review_links: reviewArtifactLinks,
    auto_posted: true,
  };

  const entry: ArenaReviewThreadEntry = {
    thread_entry_id: `ath_${crypto.randomUUID()}`,
    idempotency_key: idempotencyKey,
    bounty_id: params.bounty_id,
    arena_id: params.arena_id,
    contender_id: params.contender.contender_id,
    recommendation,
    confidence,
    body_markdown: bodyMarkdown,
    links_json: stableStringify(links),
    source: params.source,
    metadata_json: stableStringify(metadata),
    created_at: params.now,
    updated_at: params.now,
  };

  await writeArenaReviewThreadEntry(db, entry);
  return entry;
}

async function updateBountyArenaLifecycle(
  db: D1Database,
  params: {
    bounty_id: string;
    arena_status: BountyArenaStatus;
    arena_id: string | null;
    arena_task_fingerprint: string | null;
    arena_winner_contender_id: string | null;
    arena_evidence_links: ArenaScoreExplainLink[];
    arena_updated_at: string;
  },
): Promise<void> {
  const result = await db
    .prepare(
      `UPDATE bounties
          SET arena_status = ?,
              arena_id = ?,
              arena_task_fingerprint = ?,
              arena_winner_contender_id = ?,
              arena_evidence_links_json = ?,
              arena_updated_at = ?,
              updated_at = ?
        WHERE bounty_id = ?`
    )
    .bind(
      params.arena_status,
      params.arena_id,
      params.arena_task_fingerprint,
      params.arena_winner_contender_id,
      stableStringify(params.arena_evidence_links),
      params.arena_updated_at,
      params.arena_updated_at,
      params.bounty_id,
    )
    .run();

  if (!result || !result.success || !result.meta || result.meta.changes === 0) {
    throw new Error('BOUNTY_ARENA_LIFECYCLE_UPDATE_FAILED');
  }
}

async function triggerLiveArenaFromSubmission(
  db: D1Database,
  bounty: BountyV2,
  submission: SubmissionRecord,
  now: string,
): Promise<{ replay: boolean; run: ArenaRunRecord }> {
  const arenaId = `arena_${bounty.bounty_id}_live_${submission.submission_id}`.slice(0, 120);
  const startIdempotencyKey = `arena-live:${submission.submission_id}`;
  const taskFingerprint = deriveLiveArenaTaskFingerprint(bounty);
  const objectiveProfile = buildLiveArenaObjectiveProfile(bounty);

  const existingByIdempotency = await getArenaRunByStartIdempotencyKey(db, startIdempotencyKey);
  if (existingByIdempotency) {
    return { replay: true, run: existingByIdempotency };
  }

  const existingArena = await getArenaRunByArenaId(db, arenaId);
  if (existingArena) {
    return { replay: true, run: existingArena };
  }

  const runId = `arn_${crypto.randomUUID()}`;
  const contractId = `contract_${bounty.bounty_id}_${submission.submission_id}`;
  const contractPayload = stableStringify({
    bounty_id: bounty.bounty_id,
    submission_id: submission.submission_id,
    status: submission.status,
    task_fingerprint: taskFingerprint,
  });
  const contractHashB64u = await sha256B64uUtf8(contractPayload);

  await db
    .prepare(
      `INSERT INTO bounty_arena_runs (
          run_id,
          arena_id,
          bounty_id,
          status,
          contract_id,
          contract_hash_b64u,
          task_fingerprint,
          objective_profile_json,
          arena_report_json,
          winner_contender_id,
          winner_reason,
          reason_codes_json,
          tradeoffs_json,
          start_idempotency_key,
          result_idempotency_key,
          report_hash_b64u,
          started_at,
          completed_at,
          created_at,
          updated_at
        ) VALUES (?, ?, ?, 'started', ?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, ?, NULL, NULL, ?, NULL, ?, ?)`
    )
    .bind(
      runId,
      arenaId,
      bounty.bounty_id,
      contractId,
      contractHashB64u,
      taskFingerprint,
      stableStringify(objectiveProfile),
      startIdempotencyKey,
      now,
      now,
      now,
    )
    .run();

  const baselineContender = buildLiveArenaBaselineContender(bounty, submission);
  await writeArenaContenderRecords(db, runId, [baselineContender], now);

  await updateBountyArenaLifecycle(db, {
    bounty_id: bounty.bounty_id,
    arena_status: 'started',
    arena_id: arenaId,
    arena_task_fingerprint: taskFingerprint,
    arena_winner_contender_id: null,
    arena_evidence_links: baselineContender.score_explain.evidence_links,
    arena_updated_at: now,
  });

  const savedRun = await getArenaRunByArenaId(db, arenaId);
  if (!savedRun) {
    throw new Error('ARENA_LIVE_TRIGGER_PERSISTENCE_FAILED');
  }

  return { replay: false, run: savedRun };
}

function dedupeStrings(items: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];

  for (const item of items) {
    const trimmed = item.trim();
    if (!trimmed || seen.has(trimmed)) continue;
    seen.add(trimmed);
    out.push(trimmed);
  }

  return out;
}

function buildArenaReviewThreadEntryPayload(entry: ArenaReviewThreadEntry): Record<string, unknown> {
  let linksValue: unknown = [];
  let metadataValue: unknown = null;

  try {
    linksValue = JSON.parse(entry.links_json);
  } catch {
    linksValue = [];
  }

  try {
    metadataValue = entry.metadata_json ? JSON.parse(entry.metadata_json) : null;
  } catch {
    metadataValue = null;
  }

  const links = parseArenaThreadLinks(linksValue);

  return {
    thread_entry_id: entry.thread_entry_id,
    idempotency_key: entry.idempotency_key,
    bounty_id: entry.bounty_id,
    arena_id: entry.arena_id,
    contender_id: entry.contender_id,
    recommendation: entry.recommendation,
    confidence: entry.confidence,
    body_markdown: entry.body_markdown,
    links,
    source: entry.source,
    metadata: isRecord(metadataValue) ? metadataValue : null,
    created_at: entry.created_at,
    updated_at: entry.updated_at,
  };
}

function buildArenaOutcomePayload(outcome: ArenaOutcomeRecord): Record<string, unknown> {
  let metadataValue: unknown = null;
  try {
    metadataValue = outcome.metadata_json ? JSON.parse(outcome.metadata_json) : null;
  } catch {
    metadataValue = null;
  }

  return {
    outcome_id: outcome.outcome_id,
    idempotency_key: outcome.idempotency_key,
    bounty_id: outcome.bounty_id,
    arena_id: outcome.arena_id,
    contender_id: outcome.contender_id,
    outcome_status: outcome.outcome_status,
    accepted: outcome.accepted,
    overridden: outcome.overridden,
    rework_required: outcome.rework_required,
    disputed: outcome.disputed,
    review_time_minutes: outcome.review_time_minutes,
    time_to_accept_minutes: outcome.time_to_accept_minutes,
    predicted_confidence: outcome.predicted_confidence,
    recommendation: outcome.recommendation,
    reviewer_decision: outcome.reviewer_decision,
    reviewer_rationale: outcome.reviewer_rationale,
    decision_taxonomy_tags: parseJsonStringArray(outcome.decision_taxonomy_json) ?? [],
    override_reason_code: outcome.override_reason_code,
    notes: outcome.notes,
    source: outcome.source,
    metadata: isRecord(metadataValue) ? metadataValue : null,
    created_at: outcome.created_at,
    updated_at: outcome.updated_at,
  };
}

function parseArenaOutcomeMetadata(
  metadataJson: string | null,
): {
  decision_rationale: string | null;
  override_rationale: string | null;
  calibration_signal_tags: string[];
} {
  if (!metadataJson) {
    return {
      decision_rationale: null,
      override_rationale: null,
      calibration_signal_tags: [],
    };
  }

  const metadata = parseJsonObject(metadataJson);
  if (!metadata) {
    return {
      decision_rationale: null,
      override_rationale: null,
      calibration_signal_tags: [],
    };
  }

  const decisionRationaleRaw = d1String(metadata.decision_rationale)?.trim() ?? null;
  const overrideRationaleRaw = d1String(metadata.override_rationale)?.trim() ?? null;
  const tagsRaw = parseStringList(metadata.calibration_signal_tags, 20, 64, true) ?? [];

  return {
    decision_rationale: decisionRationaleRaw && decisionRationaleRaw.length > 0 ? decisionRationaleRaw : null,
    override_rationale: overrideRationaleRaw && overrideRationaleRaw.length > 0 ? overrideRationaleRaw : null,
    calibration_signal_tags: tagsRaw,
  };
}

function parseArenaOutcomeDecisionTaxonomyTags(outcome: ArenaOutcomeRecord): string[] {
  const parsed = parseJsonStringArray(outcome.decision_taxonomy_json);
  if (!parsed) return [];
  return dedupeStrings(parsed.map((tag) => tag.trim()).filter((tag) => tag.length > 0));
}

function buildArenaCalibrationSummary(
  outcomes: ArenaOutcomeRecord[],
  runByArenaId: Map<string, ArenaRunRecord>,
): Record<string, unknown> {
  const total = outcomes.length;
  const accepted = outcomes.filter((row) => row.accepted).length;
  const overridden = outcomes.filter((row) => row.overridden).length;
  const rework = outcomes.filter((row) => row.rework_required).length;
  const disputed = outcomes.filter((row) => row.disputed).length;

  const reviewerDecisionOrder: ArenaReviewerDecisionView[] = ['approve', 'request_changes', 'reject'];
  const reviewerDecisionCounts = new Map<ArenaReviewerDecisionView, number>();
  for (const decision of reviewerDecisionOrder) reviewerDecisionCounts.set(decision, 0);
  for (const row of outcomes) {
    reviewerDecisionCounts.set(
      row.reviewer_decision,
      (reviewerDecisionCounts.get(row.reviewer_decision) ?? 0) + 1,
    );
  }

  const reviewTimeSum = outcomes.reduce((sum, row) => sum + row.review_time_minutes, 0);
  const reviewTimeAvg = total > 0 ? reviewTimeSum / total : 0;

  const acceptedRows = outcomes.filter((row) => row.accepted);
  const timeToAcceptRows = acceptedRows.filter((row) => row.time_to_accept_minutes !== null);
  const timeToAcceptAvg = timeToAcceptRows.length > 0
    ? timeToAcceptRows.reduce((sum, row) => sum + (row.time_to_accept_minutes ?? 0), 0) / timeToAcceptRows.length
    : 0;

  const costAcceptedRows = acceptedRows
    .map((row) => {
      const run = runByArenaId.get(row.arena_id);
      if (!run || !run.arena_report_json) return null;
      const report = parseJsonObject(run.arena_report_json);
      if (!report) return null;
      const contendersRaw = Array.isArray(report.contenders) ? report.contenders : [];
      for (const contender of contendersRaw) {
        if (!isRecord(contender)) continue;
        const contenderId = d1String(contender.contender_id);
        if (contenderId !== row.contender_id) continue;
        const metrics = isRecord(contender.metrics) ? contender.metrics : null;
        const cost = d1Number(metrics?.cost_usd);
        if (cost === null) return null;
        return cost;
      }
      return null;
    })
    .filter((value): value is number => value !== null);

  const costPerAccepted = costAcceptedRows.length > 0
    ? costAcceptedRows.reduce((sum, value) => sum + value, 0) / costAcceptedRows.length
    : 0;

  const contenderGroups = new Map<string, ArenaOutcomeRecord[]>();
  for (const row of outcomes) {
    const list = contenderGroups.get(row.contender_id) ?? [];
    list.push(row);
    contenderGroups.set(row.contender_id, list);
  }

  const globalTagCounts = new Map<string, number>();
  const globalDecisionTaxonomyCounts = new Map<string, number>();
  const globalOverrideReasonCounts = new Map<ArenaOverrideReasonCode, number>();
  const globalRationaleRows: Array<{
    outcome_id: string;
    contender_id: string;
    outcome_status: ArenaOutcomeRecord['outcome_status'];
    override_reason_code: ArenaOverrideReasonCode | null;
    rationale: string;
    override_rationale: string | null;
    tags: string[];
    updated_at: string;
  }> = [];

  const contenders = [...contenderGroups.entries()]
    .map(([contenderId, rows]) => {
      const count = rows.length;
      const avgConfidence = rows.reduce((sum, row) => sum + row.predicted_confidence, 0) / count;
      const empiricalAcceptRate = rows.filter((row) => row.accepted).length / count;
      const overrideRate = rows.filter((row) => row.overridden).length / count;
      const reworkRate = rows.filter((row) => row.rework_required).length / count;
      const meanReviewTime = rows.reduce((sum, row) => sum + row.review_time_minutes, 0) / count;

      const tagCounts = new Map<string, number>();
      const decisionTaxonomyCounts = new Map<string, number>();
      const reviewerDecisionCountsForContender = new Map<ArenaReviewerDecisionView, number>();
      for (const decision of reviewerDecisionOrder) reviewerDecisionCountsForContender.set(decision, 0);
      const overrideReasonCounts = new Map<ArenaOverrideReasonCode, number>();
      const rationaleRows: Array<{
        outcome_id: string;
        outcome_status: ArenaOutcomeRecord['outcome_status'];
        override_reason_code: ArenaOverrideReasonCode | null;
        rationale: string;
        override_rationale: string | null;
        tags: string[];
        updated_at: string;
      }> = [];

      for (const row of rows) {
        const metadata = parseArenaOutcomeMetadata(row.metadata_json);
        const notes = row.notes?.trim() ?? null;
        const decisionRationale = metadata.decision_rationale ?? notes;
        const overrideRationale = metadata.override_rationale ?? (row.overridden ? notes : null);
        const overrideReasonCode = row.overridden
          ? (normalizeArenaOverrideReasonCode(row.override_reason_code) ?? 'ARENA_OVERRIDE_OTHER')
          : null;
        const decisionTaxonomyTags = parseArenaOutcomeDecisionTaxonomyTags(row);

        reviewerDecisionCountsForContender.set(
          row.reviewer_decision,
          (reviewerDecisionCountsForContender.get(row.reviewer_decision) ?? 0) + 1,
        );

        if (overrideReasonCode) {
          overrideReasonCounts.set(overrideReasonCode, (overrideReasonCounts.get(overrideReasonCode) ?? 0) + 1);
          globalOverrideReasonCounts.set(overrideReasonCode, (globalOverrideReasonCounts.get(overrideReasonCode) ?? 0) + 1);
        }

        for (const decisionTag of decisionTaxonomyTags) {
          decisionTaxonomyCounts.set(decisionTag, (decisionTaxonomyCounts.get(decisionTag) ?? 0) + 1);
          globalDecisionTaxonomyCounts.set(decisionTag, (globalDecisionTaxonomyCounts.get(decisionTag) ?? 0) + 1);
        }

        for (const tag of metadata.calibration_signal_tags) {
          tagCounts.set(tag, (tagCounts.get(tag) ?? 0) + 1);
          globalTagCounts.set(tag, (globalTagCounts.get(tag) ?? 0) + 1);
        }

        if (decisionRationale) {
          const rationaleEntry = {
            outcome_id: row.outcome_id,
            outcome_status: row.outcome_status,
            override_reason_code: overrideReasonCode,
            rationale: decisionRationale,
            override_rationale: overrideRationale,
            tags: dedupeStrings([...decisionTaxonomyTags, ...metadata.calibration_signal_tags]),
            updated_at: row.updated_at,
          };
          rationaleRows.push(rationaleEntry);
          globalRationaleRows.push({ contender_id: contenderId, ...rationaleEntry });
        }
      }

      const overrideReasonBreakdown = [...overrideReasonCounts.entries()]
        .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
        .map(([reason_code, reasonCount]) => ({
          reason_code,
          count: reasonCount,
          share: Number((reasonCount / count).toFixed(4)),
          contract_rewrite: ARENA_OVERRIDE_REASON_REGISTRY[reason_code].contract_rewrite,
          prompt_rewrite: ARENA_OVERRIDE_REASON_REGISTRY[reason_code].prompt_rewrite,
        }));

      const topRationaleTags = [...tagCounts.entries()]
        .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
        .slice(0, 5)
        .map(([tag, tagCount]) => ({
          tag,
          count: tagCount,
          share: Number((tagCount / count).toFixed(4)),
        }));

      const recentRationales = [...rationaleRows]
        .sort((a, b) => b.updated_at.localeCompare(a.updated_at))
        .slice(0, 3);

      const reviewerDecisionBreakdown = reviewerDecisionOrder.map((decision) => {
        const decisionCount = reviewerDecisionCountsForContender.get(decision) ?? 0;
        return {
          reviewer_decision: decision,
          count: decisionCount,
          share: Number((decisionCount / count).toFixed(4)),
        };
      });

      const topDecisionTaxonomyTags = [...decisionTaxonomyCounts.entries()]
        .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
        .slice(0, 5)
        .map(([tag, tagCount]) => ({
          tag,
          count: tagCount,
          share: Number((tagCount / count).toFixed(4)),
        }));

      return {
        contender_id: contenderId,
        samples: count,
        average_predicted_confidence: avgConfidence,
        empirical_accept_rate: empiricalAcceptRate,
        calibration_gap: avgConfidence - empiricalAcceptRate,
        override_rate: overrideRate,
        rework_rate: reworkRate,
        average_review_time_minutes: meanReviewTime,
        reviewer_decision_breakdown: reviewerDecisionBreakdown,
        top_decision_taxonomy_tags: topDecisionTaxonomyTags,
        top_override_reason_code: overrideReasonBreakdown[0]?.reason_code ?? null,
        override_reason_breakdown: overrideReasonBreakdown,
        rationale_samples: rationaleRows.length,
        top_rationale_tags: topRationaleTags,
        recent_rationales: recentRationales,
      };
    })
    .sort((a, b) => b.samples - a.samples || a.contender_id.localeCompare(b.contender_id));

  const taskWinnerCounts = new Map<string, Map<string, number>>();
  for (const row of outcomes) {
    const run = runByArenaId.get(row.arena_id);
    if (!run) continue;
    const key = run.task_fingerprint;
    const winners = taskWinnerCounts.get(key) ?? new Map<string, number>();
    const winnerId = run.winner_contender_id ?? row.contender_id;
    winners.set(winnerId, (winners.get(winnerId) ?? 0) + 1);
    taskWinnerCounts.set(key, winners);
  }

  const winnerStability = [...taskWinnerCounts.entries()]
    .map(([taskFingerprint, winners]) => {
      const totalRuns = [...winners.values()].reduce((sum, value) => sum + value, 0);
      const ranked = [...winners.entries()].sort((a, b) => b[1] - a[1]);
      const top = ranked[0];
      if (!top || totalRuns === 0) return null;
      return {
        task_fingerprint: taskFingerprint,
        top_winner_contender_id: top[0],
        stability_ratio: top[1] / totalRuns,
        sample_runs: totalRuns,
      };
    })
    .filter((entry): entry is { task_fingerprint: string; top_winner_contender_id: string; stability_ratio: number; sample_runs: number } => entry !== null)
    .sort((a, b) => b.sample_runs - a.sample_runs || a.task_fingerprint.localeCompare(b.task_fingerprint));

  const overrideTaxonomy = [...globalOverrideReasonCounts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([reason_code, countForReason]) => ({
      reason_code,
      count: countForReason,
      share: total > 0 ? Number((countForReason / total).toFixed(4)) : 0,
      contract_rewrite: ARENA_OVERRIDE_REASON_REGISTRY[reason_code].contract_rewrite,
      prompt_rewrite: ARENA_OVERRIDE_REASON_REGISTRY[reason_code].prompt_rewrite,
      priority_score: Number((countForReason * ARENA_OVERRIDE_REASON_REGISTRY[reason_code].weight).toFixed(4)),
    }));

  const rationaleSignals = {
    top_tags: [...globalTagCounts.entries()]
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
      .slice(0, 10)
      .map(([tag, countForTag]) => ({
        tag,
        count: countForTag,
        share: total > 0 ? Number((countForTag / total).toFixed(4)) : 0,
      })),
    recent_decisions: [...globalRationaleRows]
      .sort((a, b) => b.updated_at.localeCompare(a.updated_at))
      .slice(0, 8),
  };

  const reviewerDecisionBreakdown = reviewerDecisionOrder.map((decision) => {
    const decisionCount = reviewerDecisionCounts.get(decision) ?? 0;
    return {
      reviewer_decision: decision,
      count: decisionCount,
      share: total > 0 ? Number((decisionCount / total).toFixed(4)) : 0,
    };
  });

  const decisionTaxonomyBreakdown = [...globalDecisionTaxonomyCounts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, 12)
    .map(([tag, tagCount]) => ({
      tag,
      count: tagCount,
      share: total > 0 ? Number((tagCount / total).toFixed(4)) : 0,
    }));

  return {
    totals: {
      samples: total,
      accepted,
      overridden,
      rework,
      disputed,
      review_time_avg_minutes: reviewTimeAvg,
      time_to_accept_avg_minutes: timeToAcceptAvg,
      cost_per_accepted_bounty_usd: costPerAccepted,
      override_rate: total > 0 ? overridden / total : 0,
      rework_rate: total > 0 ? rework / total : 0,
      reviewer_decisions: {
        approve: reviewerDecisionCounts.get('approve') ?? 0,
        request_changes: reviewerDecisionCounts.get('request_changes') ?? 0,
        reject: reviewerDecisionCounts.get('reject') ?? 0,
      },
    },
    contenders,
    override_taxonomy: {
      reason_breakdown: overrideTaxonomy,
    },
    reviewer_decision_capture: {
      decision_breakdown: reviewerDecisionBreakdown,
      decision_taxonomy_tags: decisionTaxonomyBreakdown,
    },
    rationale_signals: rationaleSignals,
    winner_stability: winnerStability,
  };
}

function buildArenaDelegationInsights(
  contenders: ArenaContenderResult[],
  winnerContenderId: string | null,
): Record<string, unknown> {
  const winner = winnerContenderId
    ? contenders.find((contender) => contender.contender_id === winnerContenderId) ?? null
    : null;

  const allBottlenecks = dedupeStrings(contenders.flatMap((contender) => contender.insights.bottlenecks));
  const allContractImprovements = dedupeStrings(contenders.flatMap((contender) => contender.insights.contract_improvements));
  const allNextHints = dedupeStrings(contenders.flatMap((contender) => contender.insights.next_delegation_hints));

  const eligibleBackups = contenders
    .filter((contender) => contender.hard_gate_pass)
    .sort((a, b) => b.score - a.score)
    .map((contender) => contender.contender_id)
    .filter((contenderId) => contenderId !== winnerContenderId)
    .slice(0, 3);

  return {
    winner_hints: winner ? winner.insights.next_delegation_hints : [],
    winner_bottlenecks: winner ? winner.insights.bottlenecks : [],
    bottlenecks: allBottlenecks,
    contract_improvements: allContractImprovements,
    next_delegation_hints: allNextHints,
    manager_routing: {
      default_contender_id: winnerContenderId,
      backup_contenders: eligibleBackups,
    },
    contenders: contenders
      .sort((a, b) => b.score - a.score)
      .map((contender) => ({
        contender_id: contender.contender_id,
        score: contender.score,
        hard_gate_pass: contender.hard_gate_pass,
        mandatory_failed: contender.mandatory_failed,
        next_delegation_hints: contender.insights.next_delegation_hints,
        bottlenecks: contender.insights.bottlenecks,
      })),
  };
}

async function buildArenaPayloadFromRun(
  db: D1Database,
  run: ArenaRunRecord,
): Promise<Record<string, unknown> | null> {
  const objectiveProfile = parseJsonObject(run.objective_profile_json);
  if (!objectiveProfile) return null;

  const contenders = await listArenaContendersByRunId(db, run.run_id);
  const contenderViews: ArenaContenderResult[] = [];
  for (const contender of contenders) {
    const view = parseArenaContenderResult(contender);
    if (!view) return null;
    contenderViews.push(view);
  }

  const reasonCodes = run.reason_codes_json ? parseJsonStringArray(run.reason_codes_json) : [];
  const tradeoffs = run.tradeoffs_json ? parseJsonStringArray(run.tradeoffs_json) : [];
  if (!reasonCodes || !tradeoffs) return null;

  let generatedAt = run.updated_at;
  let reportScoreExplain: Record<string, unknown> | null = null;
  if (run.arena_report_json) {
    const reportObj = parseJsonObject(run.arena_report_json);
    const generated = reportObj ? d1String(reportObj.generated_at) : null;
    if (generated) generatedAt = generated;
    if (reportObj && isRecord(reportObj.score_explain)) {
      reportScoreExplain = reportObj.score_explain;
    }
  }

  return {
    run_id: run.run_id,
    arena_id: run.arena_id,
    status: run.status,
    generated_at: generatedAt,
    contract: {
      bounty_id: run.bounty_id,
      contract_id: run.contract_id,
      contract_hash_b64u: run.contract_hash_b64u,
      task_fingerprint: run.task_fingerprint,
    },
    objective_profile: objectiveProfile,
    registry: run.registry_version
      ? {
        registry_version: run.registry_version,
        objective_profile_name: getArenaObjectiveProfileNameFromRun(run),
      }
      : null,
    experiment: run.experiment_id
      ? {
        experiment_id: run.experiment_id,
        arm: run.experiment_arm,
      }
      : null,
    score_explain: reportScoreExplain ?? {
      formula: {
        summary: 'final_score = quality*Wq + speed*Ws + cost*Wc + safety*Wsafe - optional_penalty',
        components: ['derived from stored contender score_explain payloads'],
      },
      weights: isRecord(objectiveProfile.weights) ? objectiveProfile.weights : {},
      contender_breakdown: contenderViews.map((contender) => ({
        contender_id: contender.contender_id,
        final_score: contender.score_explain.final_score,
        reason_codes: contender.score_explain.reason_codes,
        evidence_links: contender.score_explain.evidence_links,
      })),
    },
    contenders: contenderViews.map((contender) => ({
      contender_id: contender.contender_id,
      label: contender.label,
      model: contender.model,
      harness: contender.harness,
      tools: contender.tools,
      skills: contender.skills,
      plugins: contender.plugins,
      version_pin: contender.version_pin,
      prompt_template: contender.prompt_template,
      experiment_arm: contender.experiment_arm,
      score: contender.score,
      hard_gate_pass: contender.hard_gate_pass,
      mandatory_failed: contender.mandatory_failed,
      metrics: contender.metrics,
      check_results: contender.check_results,
      score_explain: contender.score_explain,
      insights: contender.insights,
      review_paste: contender.review_paste,
      manager_review_json: contender.manager_review,
    })),
    winner: {
      contender_id: run.winner_contender_id,
      reason: run.winner_reason,
    },
    tradeoffs,
    reason_codes: reasonCodes,
    delegation_insights: buildArenaDelegationInsights(contenderViews, run.winner_contender_id),
  };
}

function parseArenaObjectiveWeights(input: unknown): { quality: number; speed: number; cost: number; safety: number } | null {
  if (!isRecord(input)) return null;

  const quality = d1Number(input.quality);
  const speed = d1Number(input.speed);
  const cost = d1Number(input.cost);
  const safety = d1Number(input.safety);

  if (quality === null || speed === null || cost === null || safety === null) return null;

  if (quality < 0 || quality > 1 || speed < 0 || speed > 1 || cost < 0 || cost > 1 || safety < 0 || safety > 1) {
    return null;
  }

  return { quality, speed, cost, safety };
}

function parseArenaObjectiveProfile(input: unknown): Record<string, unknown> | null {
  if (!isRecord(input)) return null;

  const name = d1String(input.name);
  if (!name || name.trim().length < 2 || name.trim().length > 64) return null;

  const weights = parseArenaObjectiveWeights(input.weights);
  if (!weights) return null;

  const tieBreakers = parseStringList(input.tie_breakers, 10, 64, true);
  if (!tieBreakers) return null;

  return {
    name: name.trim(),
    weights,
    tie_breakers: tieBreakers,
  };
}

function getArenaObjectiveProfileNameFromRun(run: ArenaRunRecord): string | null {
  const profile = parseJsonObject(run.objective_profile_json);
  const name = profile ? d1String(profile.name) : null;
  return name ? name.trim() : null;
}

function parseArenaRegistryContext(input: unknown): ArenaRegistryContext | null {
  if (!isRecord(input)) return null;

  const registryVersion = d1String(input.registry_version)?.trim() ?? null;
  if (!registryVersion || registryVersion.length > 128) return null;

  const objectiveProfileNameRaw = d1String(input.objective_profile_name)?.trim() ?? null;
  const objective_profile_name = objectiveProfileNameRaw && objectiveProfileNameRaw.length > 0
    ? objectiveProfileNameRaw.slice(0, 64)
    : null;

  const selectedRaw = Array.isArray(input.selected_contenders) ? input.selected_contenders : [];
  const selected_contenders: ArenaRegistrySelection[] = [];
  const seen = new Set<string>();

  for (const row of selectedRaw) {
    if (!isRecord(row)) return null;
    const contenderId = d1String(row.contender_id)?.trim();
    if (!contenderId || contenderId.length > 128 || seen.has(contenderId)) continue;

    const versionPinRaw = d1String(row.version_pin)?.trim() ?? null;
    const version_pin = versionPinRaw && versionPinRaw.length > 0
      ? versionPinRaw.slice(0, 128)
      : null;

    selected_contenders.push({ contender_id: contenderId, version_pin });
    seen.add(contenderId);
  }

  return {
    registry_version: registryVersion,
    objective_profile_name,
    selected_contenders,
  };
}

function parseArenaExperimentContext(input: unknown): ArenaExperimentContext | null {
  if (!isRecord(input)) return null;

  const experimentId = d1String(input.experiment_id)?.trim() ?? null;
  if (!experimentId || experimentId.length > 128) return null;

  const armRaw = d1String(input.arm)?.trim() ?? null;
  const arm = armRaw && armRaw.length > 0 ? armRaw.slice(0, 64) : null;

  return {
    experiment_id: experimentId,
    arm,
  };
}

function parseArenaContract(
  input: unknown,
  expectedBountyId: string,
): {
  bounty_id: string;
  contract_id: string;
  contract_hash_b64u: string;
  task_fingerprint: string;
} | null {
  if (!isRecord(input)) return null;

  const bounty_id = d1String(input.bounty_id);
  const contract_id = d1String(input.contract_id);
  const contract_hash_b64u = d1String(input.contract_hash_b64u);
  const task_fingerprint = d1String(input.task_fingerprint);

  if (!bounty_id || !contract_id || !contract_hash_b64u || !task_fingerprint) return null;
  if (bounty_id.trim() !== expectedBountyId) return null;
  if (!isSha256B64u(contract_hash_b64u.trim())) return null;

  return {
    bounty_id: bounty_id.trim(),
    contract_id: contract_id.trim(),
    contract_hash_b64u: contract_hash_b64u.trim(),
    task_fingerprint: task_fingerprint.trim(),
  };
}

function buildArenaReviewPaste(contender: ArenaContenderResult): string {
  const passFail = contender.hard_gate_pass ? 'PASS' : 'FAIL';

  return [
    `Decision Summary: ${contender.hard_gate_pass ? 'Promote contender' : 'Manual review required'}`,
    `Contract Compliance: ${passFail} (mandatory_failed=${contender.mandatory_failed})`,
    `Delivery/Risk: quality=${contender.metrics.quality_score.toFixed(2)}, risk=${contender.metrics.risk_score.toFixed(2)}, efficiency=${contender.metrics.efficiency_score.toFixed(2)}, cost=$${contender.metrics.cost_usd.toFixed(4)}, latency=${Math.round(contender.metrics.latency_ms)}ms`,
    `Contender: ${contender.contender_id} (${contender.label})`,
  ].join('\n');
}

function parseArenaContenderArtifactsMap(input: unknown): Map<string, {
  proof_pack: Record<string, unknown> | null;
  manager_review: Record<string, unknown> | null;
  review_paste: string | null;
}> | null {
  const map = new Map<string, {
    proof_pack: Record<string, unknown> | null;
    manager_review: Record<string, unknown> | null;
    review_paste: string | null;
  }>();

  if (input === undefined) return map;
  if (!Array.isArray(input)) return null;

  for (const row of input) {
    if (!isRecord(row)) return null;

    const contenderId = d1String(row.contender_id);
    if (!contenderId) return null;

    const proofPack = row.proof_pack;
    const managerReview = row.manager_review;
    const reviewPaste = d1String(row.review_paste);

    if (proofPack !== undefined && proofPack !== null && !isRecord(proofPack)) return null;
    if (managerReview !== undefined && managerReview !== null && !isRecord(managerReview)) return null;
    if (reviewPaste !== null && reviewPaste !== undefined && reviewPaste.trim().length === 0) return null;

    map.set(contenderId.trim(), {
      proof_pack: proofPack && isRecord(proofPack) ? proofPack : null,
      manager_review: managerReview && isRecord(managerReview) ? managerReview : null,
      review_paste: reviewPaste ? reviewPaste.trim() : null,
    });
  }

  return map;
}

function parseArenaContenderConfigFromProofPack(proofPack: Record<string, unknown> | null): {
  model: string;
  harness: string;
  tools: string[];
  skills: string[];
  plugins: string[];
  check_results: ArenaCheckResult[];
  score_explain: ArenaScoreExplain;
  insights: {
    bottlenecks: string[];
    contract_improvements: string[];
    next_delegation_hints: string[];
  };
} {
  if (!proofPack) {
    return {
      model: 'unknown-model',
      harness: 'unknown-harness',
      tools: [],
      skills: [],
      plugins: [],
      check_results: [],
      score_explain: {
        final_score: 0,
        reason_codes: [],
        evidence_links: [],
      },
      insights: {
        bottlenecks: [],
        contract_improvements: [],
        next_delegation_hints: [],
      },
    };
  }

  const contender = isRecord(proofPack.contender) ? proofPack.contender : null;
  const config = contender && isRecord(contender.config) ? contender.config : null;

  const model = config ? d1String(config.model) : null;
  const harness = config ? d1String(config.harness) : null;
  const tools = config ? parseStringList(config.tools, 64, 120, true) : [];
  const skills = config ? parseStringList(config.skills, 64, 120, true) : [];
  const plugins = config ? parseStringList(config.plugins, 64, 120, true) : [];

  const compliance = isRecord(proofPack.compliance) ? proofPack.compliance : null;
  const checks = compliance ? parseArenaCheckResults(compliance.checks) : [];

  const insightsRaw = isRecord(proofPack.insights) ? proofPack.insights : null;
  const bottlenecks = insightsRaw ? parseStringList(insightsRaw.bottlenecks, 30, 300, true) : [];
  const contractImprovements = insightsRaw ? parseStringList(insightsRaw.contract_improvements, 30, 300, true) : [];
  const nextDelegationHints = insightsRaw ? parseStringList(insightsRaw.next_delegation_hints, 30, 300, true) : [];

  const scoreExplain = parseArenaScoreExplain(proofPack.score_explain, 0);

  return {
    model: model?.trim() ?? 'unknown-model',
    harness: harness?.trim() ?? 'unknown-harness',
    tools: tools ?? [],
    skills: skills ?? [],
    plugins: plugins ?? [],
    check_results: checks,
    score_explain: scoreExplain,
    insights: {
      bottlenecks: bottlenecks ?? [],
      contract_improvements: contractImprovements ?? [],
      next_delegation_hints: nextDelegationHints ?? [],
    },
  };
}

function parseArenaContenderFromReportRow(
  row: unknown,
  artifacts: Map<string, {
    proof_pack: Record<string, unknown> | null;
    manager_review: Record<string, unknown> | null;
    review_paste: string | null;
  }>,
): ArenaContenderResult | null {
  if (!isRecord(row)) return null;

  const contender_id = d1String(row.contender_id);
  const label = d1String(row.label);
  const hard_gate_pass = row.hard_gate_pass === true;
  const mandatory_failed = d1Number(row.mandatory_failed);
  const score = d1Number(row.score);
  const metricsRaw = row.metrics;

  if (!contender_id || !label || mandatory_failed === null || score === null || !isRecord(metricsRaw)) {
    return null;
  }

  const metrics = parseArenaMetrics(metricsRaw);
  if (!metrics) return null;

  const artifact = artifacts.get(contender_id.trim()) ?? {
    proof_pack: null,
    manager_review: null,
    review_paste: null,
  };

  const versionPinRaw = d1String(row.version_pin);
  const promptTemplateRaw = d1String(row.prompt_template);
  const experimentArmRaw = d1String(row.experiment_arm);

  const config = parseArenaContenderConfigFromProofPack(artifact.proof_pack);

  const directCheckResults = parseArenaCheckResults(row.check_results);
  const check_results = directCheckResults.length > 0 ? directCheckResults : config.check_results;

  const directScoreExplain = parseArenaScoreExplain(row.score_explain, score);
  const result: ArenaContenderResult = {
    contender_id: contender_id.trim(),
    label: label.trim(),
    model: config.model,
    harness: config.harness,
    tools: config.tools,
    skills: config.skills,
    plugins: config.plugins,
    version_pin: versionPinRaw ? versionPinRaw.trim() : null,
    prompt_template: promptTemplateRaw ? promptTemplateRaw.trim() : null,
    experiment_arm: experimentArmRaw ? experimentArmRaw.trim() : null,
    score,
    hard_gate_pass,
    mandatory_failed,
    metrics,
    check_results,
    score_explain: directScoreExplain.evidence_links.length > 0 || directScoreExplain.reason_codes.length > 0
      ? directScoreExplain
      : parseArenaScoreExplain(config.score_explain, score),
    insights: config.insights,
    proof_pack: artifact.proof_pack,
    manager_review: artifact.manager_review,
    review_paste: artifact.review_paste ?? '',
  };

  if (!result.review_paste) {
    result.review_paste = buildArenaReviewPaste(result);
  }

  return result;
}

function buildArenaRunSummary(run: ArenaRunRecord): {
  arena_id: string;
  bounty_id: string;
  contract_id: string;
  generated_at: string;
  winner_contender_id: string;
  reason_code: string;
  status: ArenaRunStatus;
  registry_version: string | null;
  experiment_id: string | null;
  experiment_arm: string | null;
} {
  const reasonCodes = run.reason_codes_json ? parseJsonStringArray(run.reason_codes_json) : [];
  const reason_code = reasonCodes && reasonCodes.length > 0
    ? (reasonCodes[0] ?? 'ARENA_RESULT_RECORDED')
    : run.status === 'completed'
      ? 'ARENA_RESULT_RECORDED'
      : 'ARENA_PENDING';

  return {
    arena_id: run.arena_id,
    bounty_id: run.bounty_id,
    contract_id: run.contract_id,
    generated_at: run.completed_at ?? run.updated_at,
    winner_contender_id: run.winner_contender_id ?? 'pending',
    reason_code,
    status: run.status,
    registry_version: run.registry_version,
    experiment_id: run.experiment_id,
    experiment_arm: run.experiment_arm,
  };
}

function buildBountyArenaLifecycleSummary(bounty: BountyV2): Record<string, unknown> {
  return {
    status: bounty.arena_status,
    arena_id: bounty.arena_id,
    task_fingerprint: bounty.arena_task_fingerprint,
    winner_contender_id: bounty.arena_winner_contender_id,
    evidence_links: bounty.arena_evidence_links,
    updated_at: bounty.arena_updated_at,
  };
}

function buildTestHarnessOutput(submission: SubmissionRecord): Record<string, unknown> {
  return {
    artifacts: submission.artifacts ?? [],
    agent_pack: submission.agent_pack ?? null,
    result_summary: submission.result_summary ?? null,
    commit_sha: submission.commit_sha ?? null,
    repo_url: submission.repo_url ?? null,
    repo_claim_id: submission.repo_claim_id ?? null,
    worker_did: submission.worker_did,
    proof_tier: submission.proof_tier ?? null,
  };
}

async function autoApproveTestSubmission(env: Env, bounty: BountyV2, submission: SubmissionRecord): Promise<TestAutoDecisionResult> {
  if (bounty.closure_type !== 'test') return { applied: false };

  const test_harness_id = bounty.test_harness_id;
  if (!test_harness_id) {
    return {
      applied: false,
      failure: {
        code: 'TEST_HARNESS_NOT_CONFIGURED',
        message: 'Bounty is missing test_harness_id for closure_type=test',
        status: 503,
      },
    };
  }

  const proofBundleHash = submission.proof_bundle_hash_b64u?.trim();
  if (!proofBundleHash) {
    return {
      applied: false,
      failure: {
        code: 'TEST_HARNESS_INPUT_INVALID',
        message: 'Submission is missing proof_bundle_hash_b64u',
        status: 500,
      },
    };
  }

  const request: TestHarnessRunRequest = {
    schema_version: '1',
    test_harness_id,
    submission_id: submission.submission_id,
    bounty_id: bounty.bounty_id,
    output: buildTestHarnessOutput(submission),
    proof_bundle_hash: proofBundleHash,
    timeout_ms: resolveTestHarnessTimeoutMs(env),
  };

  let testResponse: TestHarnessRunResponse;
  try {
    testResponse = await runTestHarness(env, request);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    testResponse = buildTestHarnessFailureResponse(request, message);
  }

  const now = new Date().toISOString();
  const testResultId = `tst_${crypto.randomUUID()}`;
  const harnessError = isNonEmptyString(testResponse.error);
  const passed = Boolean(testResponse.passed);
  const recordPassed = harnessError ? false : passed;

  const testRecord: TestResultRecord = {
    test_result_id: testResultId,
    submission_id: submission.submission_id,
    bounty_id: bounty.bounty_id,
    test_harness_id,
    passed: recordPassed,
    total_tests: testResponse.total_tests,
    passed_tests: testResponse.passed_tests,
    failed_tests: testResponse.failed_tests,
    execution_time_ms: testResponse.execution_time_ms,
    completed_at: testResponse.completed_at,
    error: testResponse.error ?? null,
    test_results: testResponse.test_results,
    created_at: now,
    updated_at: now,
  };

  try {
    await insertTestResult(env.BOUNTIES_DB, testRecord);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    console.error(`Failed to store test result for submission ${submission.submission_id}: ${message}`);
  }

  if (harnessError) {
    const classified = classifyTestLaneFailure(testResponse.error ?? 'Test harness failed');
    return {
      applied: false,
      failure: {
        code: classified.code,
        message: classified.message,
        status: classified.status,
        details: {
          submission_id: submission.submission_id,
          test_result_id: testResultId,
          test_harness_id,
        },
      },
    };
  }

  if (passed) {
    const approveKey = `auto-approve:${submission.submission_id}`;

    try {
      await escrowRelease(env, {
        escrow_id: bounty.escrow_id,
        idempotency_key: approveKey,
        approved_by: bounty.requester_did,
        verification: {
          submission_id: submission.submission_id,
          proof_bundle_hash_b64u: submission.proof_bundle_hash_b64u ?? undefined,
          proof_tier: submission.proof_tier ?? undefined,
          commit_sha: submission.commit_sha ?? undefined,
          repo_url: submission.repo_url ?? undefined,
          repo_claim_id: submission.repo_claim_id ?? undefined,
          test_result_id: testResultId,
        },
      });
    } catch (err) {
      const parsed = parseEscrowFailedError(err);
      if (parsed) {
        const code = isNonEmptyString(parsed.payload.error) ? parsed.payload.error.trim() : 'ESCROW_FAILED';
        const message = isNonEmptyString(parsed.payload.message) ? parsed.payload.message.trim() : 'Escrow failed';
        return {
          applied: false,
          failure: {
            code: 'AUTO_APPROVAL_ESCROW_FAILED',
            message: `${code}: ${message}`,
            status: 502,
          },
        };
      }

      const message = err instanceof Error ? err.message : 'Unknown error';
      return {
        applied: false,
        failure: {
          code: 'AUTO_APPROVAL_ESCROW_FAILED',
          message,
          status: 502,
        },
      };
    }

    try {
      await updateBountyApproved(env.BOUNTIES_DB, {
        bounty_id: bounty.bounty_id,
        submission_id: submission.submission_id,
        idempotency_key: approveKey,
        approved_at: now,
        now,
      });
    } catch (err) {
      try {
        const updated = await getBountyById(env.BOUNTIES_DB, bounty.bounty_id);
        if (!updated || updated.status !== 'approved') {
          throw err;
        }

        if (updated.approve_idempotency_key && updated.approve_idempotency_key !== approveKey) {
          return {
            applied: false,
            failure: {
              code: 'AUTO_APPROVAL_STATE_CONFLICT',
              message: 'Auto-approval idempotency key mismatch',
              status: 409,
            },
          };
        }

        if (updated.approved_submission_id && updated.approved_submission_id !== submission.submission_id) {
          return {
            applied: false,
            failure: {
              code: 'AUTO_APPROVAL_STATE_CONFLICT',
              message: 'Auto-approval submission mismatch',
              status: 409,
            },
          };
        }
      } catch (lookupErr) {
        const message = lookupErr instanceof Error ? lookupErr.message : 'Unknown error';
        return {
          applied: false,
          failure: {
            code: 'AUTO_APPROVAL_STATE_FAILED',
            message,
            status: 500,
          },
        };
      }
    }

    try {
      await updateSubmissionStatus(env.BOUNTIES_DB, submission.submission_id, 'approved', now, 'pending_review');
    } catch (err) {
      try {
        const updated = await getSubmissionById(env.BOUNTIES_DB, submission.submission_id);
        if (!updated || updated.status !== 'approved') {
          throw err;
        }
      } catch (lookupErr) {
        const message = lookupErr instanceof Error ? lookupErr.message : 'Unknown error';
        return {
          applied: false,
          failure: {
            code: 'AUTO_APPROVAL_STATE_FAILED',
            message,
            status: 500,
          },
        };
      }
    }

    await emitClawrepLoopEvent(env, {
      schema_version: '1',
      source_event_id: `clawbounties:auto-approve:${bounty.bounty_id}:${submission.submission_id}:${approveKey}`,
      source_service: 'clawbounties',
      kind: 'closure',
      did: submission.worker_did,
      occurred_at: now,
      closure: {
        value_usd: minorToUsd(bounty.reward.amount_minor),
        closure_type: 'auto_approve',
        proof_tier: toRepProofTier(submission.proof_tier),
        owner_verified: false,
      },
      metadata: {
        bounty_id: bounty.bounty_id,
        submission_id: submission.submission_id,
        test_harness_id,
        test_result_id: testResultId,
        closure_type: bounty.closure_type,
      },
    });

    return { applied: true };
  }

  const rejectKey = `auto-test-failure:${submission.submission_id}`;

  try {
    await escrowDispute(env, {
      escrow_id: bounty.escrow_id,
      idempotency_key: rejectKey,
      disputed_by: bounty.requester_did,
      reason: 'Auto-rejected: test harness failed',
    });
  } catch (err) {
    const parsed = parseEscrowFailedError(err);
    if (parsed) {
      const code = isNonEmptyString(parsed.payload.error) ? parsed.payload.error.trim() : 'ESCROW_FAILED';
      const message = isNonEmptyString(parsed.payload.message) ? parsed.payload.message.trim() : 'Escrow failed';
      return {
        applied: false,
        failure: {
          code: 'AUTO_REJECTION_ESCROW_FAILED',
          message: `${code}: ${message}`,
          status: 502,
        },
      };
    }

    const message = err instanceof Error ? err.message : 'Unknown error';
    return {
      applied: false,
      failure: {
        code: 'AUTO_REJECTION_ESCROW_FAILED',
        message,
        status: 502,
      },
    };
  }

  let trialCase: TrialCaseSummary;
  try {
    trialCase = await trialsCreateCase(env, {
      idempotency_key: `trial:reject:${bounty.bounty_id}:${rejectKey}`,
      source_system: 'clawbounties',
      source_ref: bounty.bounty_id,
      submission_id: submission.submission_id,
      escrow_id: bounty.escrow_id,
      requester_did: bounty.requester_did,
      worker_did: submission.worker_did,
      opened_by: bounty.requester_did,
      reason: 'Auto-rejected: test harness failed',
      evidence: buildSubmissionTrialEvidence(submission),
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return {
      applied: false,
      failure: {
        code: 'AUTO_REJECTION_TRIALS_FAILED',
        message,
        status: 502,
      },
    };
  }

  try {
    await updateBountyRejected(env.BOUNTIES_DB, {
      bounty_id: bounty.bounty_id,
      submission_id: submission.submission_id,
      idempotency_key: rejectKey,
      rejected_at: now,
      now,
      trial_case_id: trialCase.case_id,
      trial_opened_at: trialCase.opened_at,
    });
  } catch (err) {
    try {
      const updated = await getBountyById(env.BOUNTIES_DB, bounty.bounty_id);
      if (!updated || updated.status !== 'disputed') {
        throw err;
      }

      if (updated.reject_idempotency_key && updated.reject_idempotency_key !== rejectKey) {
        return {
          applied: false,
          failure: {
            code: 'AUTO_REJECTION_STATE_CONFLICT',
            message: 'Auto-rejection idempotency key mismatch',
            status: 409,
          },
        };
      }

      if (updated.rejected_submission_id && updated.rejected_submission_id !== submission.submission_id) {
        return {
          applied: false,
          failure: {
            code: 'AUTO_REJECTION_STATE_CONFLICT',
            message: 'Auto-rejection submission mismatch',
            status: 409,
          },
        };
      }
    } catch (lookupErr) {
      const message = lookupErr instanceof Error ? lookupErr.message : 'Unknown error';
      return {
        applied: false,
        failure: {
          code: 'AUTO_REJECTION_STATE_FAILED',
          message,
          status: 500,
        },
      };
    }
  }

  try {
    await updateSubmissionStatus(env.BOUNTIES_DB, submission.submission_id, 'rejected', now, 'pending_review');
  } catch (err) {
    try {
      const updated = await getSubmissionById(env.BOUNTIES_DB, submission.submission_id);
      if (!updated || updated.status !== 'rejected') {
        throw err;
      }
    } catch (lookupErr) {
      const message = lookupErr instanceof Error ? lookupErr.message : 'Unknown error';
      return {
        applied: false,
        failure: {
          code: 'AUTO_REJECTION_STATE_FAILED',
          message,
          status: 500,
        },
      };
    }
  }

  await emitClawrepLoopEvent(env, {
    schema_version: '1',
    source_event_id: `clawbounties:auto-reject:${bounty.bounty_id}:${submission.submission_id}:${rejectKey}`,
    source_service: 'clawbounties',
    kind: 'penalty',
    did: submission.worker_did,
    occurred_at: now,
    penalty: {
      penalty_type: 'dispute_upheld_against_worker',
      severity: 2,
      reason: 'Auto-rejected: test harness failed',
    },
    metadata: {
      bounty_id: bounty.bounty_id,
      submission_id: submission.submission_id,
      test_harness_id,
      test_result_id: testResultId,
      closure_type: bounty.closure_type,
    },
  });

  return { applied: true };
}

async function listBounties(
  db: D1Database,
  filters: { status: BountyStatus; is_code_bounty?: boolean; tags?: string[] },
  limit = 50
): Promise<BountyListItemV2[]> {
  const status = filters.status;
  const isCode = filters.is_code_bounty;

  let query =
    'SELECT bounty_id, requester_did, title, reward_amount_minor, reward_currency, closure_type, difficulty_scalar, status, created_at, escrow_id, is_code_bounty, tags_json, min_proof_tier FROM bounties WHERE status = ?';
  const bindings: unknown[] = [status];

  if (isCode !== undefined) {
    query += ' AND is_code_bounty = ?';
    bindings.push(isCode ? 1 : 0);
  }

  query += ' ORDER BY created_at DESC LIMIT ?';
  bindings.push(limit);

  const results = await db.prepare(query).bind(...bindings).all();

  const parsed: BountyListItemV2[] = [];
  for (const raw of results.results ?? []) {
    if (!isRecord(raw)) continue;

    const bounty_id = d1String(raw.bounty_id);
    const requester_did = d1String(raw.requester_did);
    const title = d1String(raw.title);
    const reward_amount_minor = d1String(raw.reward_amount_minor);
    const reward_currency = d1String(raw.reward_currency);
    const closure_type = parseClosureType(d1String(raw.closure_type));
    const difficulty_scalar = d1Number(raw.difficulty_scalar);
    const statusParsed = parseBountyStatus(d1String(raw.status));
    const created_at = d1String(raw.created_at);
    const escrow_id = d1String(raw.escrow_id);
    const is_code_bounty_num = d1Number(raw.is_code_bounty);
    const tags_json = d1String(raw.tags_json);
    const min_proof_tier = parseProofTier(d1String(raw.min_proof_tier));

    if (
      !bounty_id ||
      !requester_did ||
      !title ||
      !reward_amount_minor ||
      reward_currency !== 'USD' ||
      !closure_type ||
      difficulty_scalar === null ||
      !statusParsed ||
      !created_at ||
      !escrow_id ||
      is_code_bounty_num === null ||
      !tags_json ||
      !min_proof_tier
    ) {
      continue;
    }

    const tags = parseJsonStringArray(tags_json);
    if (!tags) continue;

    parsed.push({
      schema_version: '2',
      bounty_id,
      requester_did,
      title,
      reward: { amount_minor: reward_amount_minor, currency: 'USD' },
      closure_type,
      difficulty_scalar,
      status: statusParsed,
      created_at,
      escrow_id,
      is_code_bounty: Boolean(is_code_bounty_num),
      tags,
      min_proof_tier,
    });
  }

  const wantedTags = filters.tags ?? [];
  if (wantedTags.length === 0) return parsed;

  return parsed.filter((b) => wantedTags.some((t) => b.tags.includes(t)));
}

async function listWorkerBounties(
  db: D1Database,
  workerDid: string,
  filters: { status: BountyStatus; is_code_bounty?: boolean; tags?: string[] },
  limit = 50
): Promise<WorkerBountyListItemV2[]> {
  const status = filters.status;
  const isCode = filters.is_code_bounty;

  let query =
    'SELECT bounty_id, title, reward_amount_minor, reward_currency, closure_type, difficulty_scalar, status, created_at, is_code_bounty, tags_json, min_proof_tier, metadata_json FROM bounties WHERE status = ?';
  const bindings: unknown[] = [status];

  if (isCode !== undefined) {
    query += ' AND is_code_bounty = ?';
    bindings.push(isCode ? 1 : 0);
  }

  query += ' ORDER BY created_at DESC LIMIT ?';
  bindings.push(limit);

  const results = await db.prepare(query).bind(...bindings).all();

  const parsed: WorkerBountyListItemV2[] = [];
  for (const raw of results.results ?? []) {
    if (!isRecord(raw)) continue;

    const bounty_id = d1String(raw.bounty_id);
    const title = d1String(raw.title);
    const reward_amount_minor = d1String(raw.reward_amount_minor);
    const reward_currency = d1String(raw.reward_currency);
    const closure_type = parseClosureType(d1String(raw.closure_type));
    const difficulty_scalar = d1Number(raw.difficulty_scalar);
    const statusParsed = parseBountyStatus(d1String(raw.status));
    const created_at = d1String(raw.created_at);
    const is_code_bounty_num = d1Number(raw.is_code_bounty);
    const tags_json = d1String(raw.tags_json);
    const min_proof_tier = parseProofTier(d1String(raw.min_proof_tier));
    const metadata_json = d1String(raw.metadata_json);

    if (
      !bounty_id ||
      !title ||
      !reward_amount_minor ||
      reward_currency !== 'USD' ||
      !closure_type ||
      difficulty_scalar === null ||
      !statusParsed ||
      !created_at ||
      is_code_bounty_num === null ||
      !tags_json ||
      !min_proof_tier ||
      !metadata_json
    ) {
      continue;
    }

    const tags = parseJsonStringArray(tags_json);
    const metadata = parseJsonObject(metadata_json);
    if (!tags || !metadata) continue;

    const requested_raw = metadata.requested_worker_did;
    if (requested_raw !== undefined && requested_raw !== null) {
      if (!isNonEmptyString(requested_raw) || !requested_raw.trim().startsWith('did:')) {
        continue;
      }

      if (requested_raw.trim() !== workerDid) {
        continue;
      }
    }

    parsed.push({
      schema_version: '2',
      bounty_id,
      title,
      reward: { amount_minor: reward_amount_minor, currency: 'USD' },
      closure_type,
      difficulty_scalar,
      status: statusParsed,
      created_at,
      is_code_bounty: Boolean(is_code_bounty_num),
      tags,
      min_proof_tier,
    });
  }

  const wantedTags = filters.tags ?? [];
  if (wantedTags.length === 0) return parsed;

  return parsed.filter((b) => wantedTags.some((t) => b.tags.includes(t)));
}

function parseWorkerRow(row: Record<string, unknown>): WorkerRecordV1 | null {
  const worker_id = d1String(row.worker_id);
  const worker_did = d1String(row.worker_did);
  const status = parseWorkerStatus(d1String(row.status));
  const worker_version = d1String(row.worker_version);

  const listing_json = d1String(row.listing_json);
  const capabilities_json = d1String(row.capabilities_json);
  const offers_json = d1String(row.offers_json);
  const price_floor_minor = d1String(row.price_floor_minor);
  const availability_json = d1String(row.availability_json);

  const auth_mode_raw = d1String(row.auth_mode);
  const auth_mode: WorkerAuthMode | null = auth_mode_raw === 'token' ? 'token' : null;

  const auth_token_hash_hex = d1String(row.auth_token_hash_hex);
  const auth_token_prefix = d1String(row.auth_token_prefix);
  const auth_token_created_at = d1String(row.auth_token_created_at);
  const auth_token_expires_at = d1String(row.auth_token_expires_at);

  const created_at = d1String(row.created_at);
  const updated_at = d1String(row.updated_at);

  if (
    !worker_id ||
    !worker_did ||
    !status ||
    !worker_version ||
    !listing_json ||
    !capabilities_json ||
    !offers_json ||
    !price_floor_minor ||
    !availability_json ||
    !auth_mode ||
    !auth_token_hash_hex ||
    !auth_token_prefix ||
    !auth_token_created_at ||
    !auth_token_expires_at ||
    !created_at ||
    !updated_at
  ) {
    return null;
  }

  if (parsePositiveMinor(price_floor_minor) === null) return null;

  const listingObj = parseJsonObject(listing_json);
  const capabilitiesObj = parseJsonObject(capabilities_json);
  const offersObj = parseJsonObject(offers_json);
  const availabilityObj = parseJsonObject(availability_json);

  if (!listingObj || !capabilitiesObj || !offersObj || !availabilityObj) return null;

  const listing = parseWorkerListing(listingObj);
  const capabilities = parseWorkerCapabilities(capabilitiesObj);
  const offers = parseWorkerOffers(offersObj);
  const availability = parseWorkerAvailability(availabilityObj);

  if (!listing || !capabilities || !offers || !availability) return null;

  return {
    worker_id,
    worker_did,
    status,
    worker_version,
    listing,
    capabilities,
    offers,
    pricing: { price_floor_minor: price_floor_minor.trim() },
    availability,
    auth_mode,
    auth_token_hash_hex,
    auth_token_prefix,
    auth_token_created_at,
    auth_token_expires_at,
    created_at,
    updated_at,
  };
}

function workerToListItem(worker: WorkerRecordV1): WorkerListItemV1 {
  return {
    worker_id: worker.worker_id,
    worker_did: worker.worker_did,
    status: worker.status,
    listing: worker.listing,
    capabilities: worker.capabilities,
    offers: worker.offers,
    pricing: worker.pricing,
  };
}

async function getWorkerByDid(db: D1Database, workerDid: string): Promise<WorkerRecordV1 | null> {
  const row = await db.prepare('SELECT * FROM workers WHERE worker_did = ?').bind(workerDid).first();
  if (!row || !isRecord(row)) return null;
  return parseWorkerRow(row);
}

async function getWorkerByAuthToken(db: D1Database, token: string): Promise<WorkerRecordV1 | null> {
  const hash = await sha256HexUtf8(token);
  const row = await db.prepare('SELECT * FROM workers WHERE auth_token_hash_hex = ?').bind(hash).first();
  if (!row || !isRecord(row)) return null;

  const worker = parseWorkerRow(row);
  if (!worker) return null;

  const exp = Date.parse(worker.auth_token_expires_at);
  if (!Number.isFinite(exp)) return null;
  if (exp <= Date.now()) return null;

  return worker;
}

async function upsertWorker(db: D1Database, record: WorkerRecordV1): Promise<void> {
  await db
    .prepare(
      `INSERT INTO workers (
        worker_id,
        worker_did,
        status,
        worker_version,
        listing_json,
        capabilities_json,
        offers_json,
        price_floor_minor,
        availability_json,
        auth_mode,
        auth_token_hash_hex,
        auth_token_prefix,
        auth_token_created_at,
        auth_token_expires_at,
        created_at,
        updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(worker_did) DO UPDATE SET
        status = excluded.status,
        worker_version = excluded.worker_version,
        listing_json = excluded.listing_json,
        capabilities_json = excluded.capabilities_json,
        offers_json = excluded.offers_json,
        price_floor_minor = excluded.price_floor_minor,
        availability_json = excluded.availability_json,
        auth_mode = excluded.auth_mode,
        auth_token_hash_hex = excluded.auth_token_hash_hex,
        auth_token_prefix = excluded.auth_token_prefix,
        auth_token_created_at = excluded.auth_token_created_at,
        auth_token_expires_at = excluded.auth_token_expires_at,
        updated_at = excluded.updated_at`
    )
    .bind(
      record.worker_id,
      record.worker_did,
      record.status,
      record.worker_version,
      JSON.stringify(record.listing),
      JSON.stringify(record.capabilities),
      JSON.stringify(record.offers),
      record.pricing.price_floor_minor,
      JSON.stringify(record.availability),
      record.auth_mode,
      record.auth_token_hash_hex,
      record.auth_token_prefix,
      record.auth_token_created_at,
      record.auth_token_expires_at,
      record.created_at,
      record.updated_at
    )
    .run();
}

async function listWorkers(db: D1Database, limit = 50): Promise<WorkerListItemV1[]> {
  const results = await db.prepare('SELECT * FROM workers ORDER BY updated_at DESC LIMIT ?').bind(limit).all();

  const out: WorkerListItemV1[] = [];
  for (const raw of results.results ?? []) {
    if (!isRecord(raw)) continue;
    const worker = parseWorkerRow(raw);
    if (!worker) continue;
    out.push(workerToListItem(worker));
  }

  return out;
}

function landingPage(origin: string, env: Env): string {
  const environment = escapeHtml(env.ENVIRONMENT ?? 'unknown');
  const version = escapeHtml(env.BOUNTIES_VERSION ?? '0.1.0');

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>clawbounties</title>
  </head>
  <body>
    <main style="max-width: 820px; margin: 2rem auto; font-family: ui-sans-serif, system-ui; line-height: 1.5; padding: 0 16px;">
      <h1>clawbounties</h1>
      <p>Bounty marketplace for agent work (posting, acceptance, submissions, quorum review).</p>
      <ul>
        <li><a href="${origin}/docs">Docs</a></li>
        <li><a href="${origin}/duel">UI duel workbench</a></li>
        <li><a href="${origin}/trust-pulse">Trust Pulse viewer</a></li>
        <li><a href="${origin}/skill.md">OpenClaw skill</a></li>
        <li><a href="${origin}/health">Health</a></li>
      </ul>
      <p><small>Environment: ${environment} · Version: ${version}</small></p>
    </main>
  </body>
</html>`;
}

function docsPage(origin: string): string {
  const o = escapeHtml(origin);

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>clawbounties docs</title>
  </head>
  <body>
    <main style="max-width: 900px; margin: 2rem auto; font-family: ui-sans-serif, system-ui; line-height: 1.5; padding: 0 16px;">
      <h1>clawbounties docs</h1>
      <p>Minimal public discovery docs for the clawbounties service.</p>

      <p><strong>Trust Pulse:</strong> If your harness emits a Trust Pulse artifact (tools + relative file touches; self-reported, non-tier), you can view it at <a href="${o}/trust-pulse">${o}/trust-pulse</a>. If you stored it alongside a submission, use <code>/trust-pulse?submission_id=sub_...</code> and load it via token (header auth; token never goes in URL).</p>

      <h2>Public endpoints</h2>
      <ul>
        <li><code>GET /</code> — landing</li>
        <li><code>GET /docs</code> — this page</li>
        <li><code>GET /duel</code> — UI duel workbench (browse/details/claim/submit journey)</li>
        <li><code>GET /trust-pulse</code> — Trust Pulse viewer (self-reported, non-tier)</li>
        <li><code>GET /skill.md</code> — OpenClaw skill descriptor</li>
        <li><code>GET /health</code> — health check</li>
      </ul>

      <h2>Marketplace API</h2>

      <h3>Worker API (public bootstrap + token auth)</h3>
      <ul>
        <li><code>POST /v1/workers/register</code> — register a worker and receive an auth token (MVP)</li>
        <li><code>GET /v1/workers?job_type=code&amp;tag=typescript</code> — list workers</li>
        <li><code>GET /v1/workers/self</code> — show your worker record (requires <code>Authorization: Bearer &lt;token&gt;</code>)</li>
        <li><code>GET /v1/bounties?status=open&amp;is_code_bounty=true&amp;tag=typescript</code> — list open bounties (requires <code>Authorization: Bearer &lt;token&gt;</code>)</li>
        <li><code>POST /v1/bounties/{bounty_id}/accept</code> — accept a bounty (requires <code>Authorization: Bearer &lt;token&gt;</code>)</li>
        <li><code>POST /v1/bounties/{bounty_id}/submit</code> — submit work (requires <code>Authorization: Bearer &lt;token&gt;</code>)</li>
        <li><code>GET /v1/bounties/{bounty_id}/submissions</code> — list submissions (admin OR worker token OR <code>x-requester-did</code>)</li>
        <li><code>GET /v1/submissions/{submission_id}</code> — submission detail (admin OR worker token OR <code>x-requester-did</code>)</li>
        <li><code>GET /v1/submissions/{submission_id}/trust-pulse</code> — fetch a stored Trust Pulse (requires <code>Authorization: Bearer &lt;token&gt;</code> OR admin key)</li>
      </ul>

      <h3>POST /v1/workers/register</h3>
      <pre>curl -sS \
  -X POST "${o}/v1/workers/register" \
  -H 'content-type: application/json' \
  -d '{
    "worker_did": "did:key:zWorker...",
    "worker_version": "openclaw-worker/0.1.0",
    "listing": {"name": "Example worker", "headline": "Fast TypeScript fixes + reliable tests", "tags": ["typescript", "openclaw"]},
    "capabilities": {"job_types": ["code"], "languages": ["ts"], "max_minutes": 20},
    "offers": {"skills": ["did-work"], "mcp": [{"name": "github", "description": "Read repos/issues/PRs via MCP"}]},
    "pricing": {"price_floor_minor": "500"},
    "availability": {"mode": "manual", "paused": false}
  }'</pre>

      <h3>GET /v1/bounties (open)</h3>
      <pre>curl -sS "${o}/v1/bounties?status=open&amp;is_code_bounty=true&amp;tag=typescript" \
  -H "Authorization: Bearer &lt;WORKER_TOKEN&gt;"</pre>

      <h3>POST /v1/bounties/{bounty_id}/accept</h3>
      <pre>curl -sS \
  -X POST "${o}/v1/bounties/bty_.../accept" \
  -H "Authorization: Bearer &lt;WORKER_TOKEN&gt;" \
  -H 'content-type: application/json' \
  -d '{
    "idempotency_key": "bounty:bty_123:accept:did:key:zWorker",
    "worker_did": "did:key:zWorker..."
  }'</pre>

      <h3>POST /v1/bounties/{bounty_id}/submit</h3>
      <pre>curl -sS \
  -X POST "${o}/v1/bounties/bty_.../submit" \
  -H "Authorization: Bearer &lt;WORKER_TOKEN&gt;" \
  -H 'content-type: application/json' \
  -d '{
    "worker_did": "did:key:zWorker...",
    "proof_bundle_envelope": {"...": "..."},
    "urm": {"...": "..."},
    "commit_proof_envelope": {"...": "..."},
    "artifacts": [],
    "result_summary": "Short summary of the work",
    "trust_pulse": {"trust_pulse_version": "1", "evidence_class": "self_reported", "tier_uplift": false, "run_id": "run_...", "agent_did": "did:key:...", "tools": [], "files": []}
  }'</pre>

      <h3>Requester API (scoped CST/JWT)</h3>
      <p>Requester bounty actions are fail-closed and require <code>Authorization: Bearer &lt;REQUESTER_TOKEN&gt;</code>. Tokens are introspected against clawscope and must include explicit scopes + requester DID subject. The temporary legacy path (<code>admin + x-requester-did</code>) remains behind <code>REQUESTER_AUTH_COMPAT_LEGACY=true</code> only.</p>
      <ul>
        <li><code>clawbounties:bounty:create</code> → <code>POST /v1/bounties</code></li>
        <li><code>clawbounties:bounty:approve</code> → <code>POST /v1/bounties/{bounty_id}/approve</code></li>
        <li><code>clawbounties:bounty:reject</code> → <code>POST /v1/bounties/{bounty_id}/reject</code></li>
        <li><code>clawbounties:bounty:read</code> → <code>GET /v1/bounties/{bounty_id}/submissions</code>, <code>GET /v1/submissions/{submission_id}</code></li>
      </ul>
      <p>Admin auth still supports operational endpoints like <code>GET /v1/bounties</code> and <code>GET /v1/bounties/{bounty_id}</code>.</p>

      <ul>
        <li><code>POST /v1/bounties</code> — post a bounty (schema v2; calls clawcuts + clawescrow)</li>
        <li><code>POST /v1/bounties/{bounty_id}/approve</code> — approve requester-closure bounty (release escrow)</li>
        <li><code>POST /v1/bounties/{bounty_id}/reject</code> — reject requester-closure bounty (freeze escrow + open clawtrials case)</li>
        <li><code>GET /v1/bounties/{bounty_id}/submissions</code> — list bounty submissions (requester read scope or admin)</li>
        <li><code>GET /v1/submissions/{submission_id}</code> — submission detail (requester read scope, owning worker, or admin)</li>
      </ul>

      <h3>POST /v1/bounties (v2)</h3>
      <pre>curl -sS \
  -X POST "${o}/v1/bounties" \
  -H "Authorization: Bearer &lt;REQUESTER_TOKEN&gt;" \
  -H 'content-type: application/json' \
  -d '{
    "requester_did": "did:key:zRequester...",
    "title": "Fix failing unit tests",
    "description": "...",
    "reward": {"amount_minor": "5000", "currency": "USD"},
    "closure_type": "requester",
    "difficulty_scalar": 1.0,
    "is_code_bounty": false,
    "min_proof_tier": "self",
    "tags": ["typescript", "testing"],
    "idempotency_key": "post:example:001",
    "metadata": {"requested_worker_did": "did:key:zWorker..."}
  }'</pre>

      <h3>POST /v1/bounties/{bounty_id}/approve</h3>
      <pre>curl -sS \
  -X POST "${o}/v1/bounties/bty_.../approve" \
  -H "Authorization: Bearer &lt;REQUESTER_TOKEN&gt;" \
  -H 'content-type: application/json' \
  -d '{
    "idempotency_key": "bounty:bty_123:approve",
    "requester_did": "did:key:zRequester",
    "submission_id": "sub_123"
  }'</pre>

      <h3>POST /v1/bounties/{bounty_id}/reject</h3>
      <pre>curl -sS \
  -X POST "${o}/v1/bounties/bty_.../reject" \
  -H "Authorization: Bearer &lt;REQUESTER_TOKEN&gt;" \
  -H 'content-type: application/json' \
  -d '{
    "idempotency_key": "bounty:bty_123:reject",
    "requester_did": "did:key:zRequester",
    "submission_id": "sub_123",
    "reason": "Missing required deliverables"
  }'</pre>

      <h3>GET /v1/bounties/{bounty_id}/submissions</h3>
      <pre>curl -sS "${o}/v1/bounties/bty_.../submissions?limit=20" \
  -H "Authorization: Bearer &lt;REQUESTER_TOKEN&gt;"</pre>

      <h3>GET /v1/submissions/{submission_id}</h3>
      <pre>curl -sS "${o}/v1/submissions/sub_..." \
  -H "Authorization: Bearer &lt;REQUESTER_TOKEN_OR_WORKER_TOKEN&gt;"</pre>

      <p style="margin-top: 24px;">Quick start:</p>
      <pre>curl -sS "${o}/skill.md"</pre>
    </main>
  </body>
</html>`;
}

function trustPulseViewerPage(origin: string): string {
  const o = escapeHtml(origin);

  // Viewer runs client-side (paste/upload a trust pulse JSON), and can optionally fetch
  // a stored Trust Pulse by submission_id when an admin key or worker token is provided.
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Trust Pulse viewer</title>
  </head>
  <body>
    <main style="max-width: 980px; margin: 2rem auto; font-family: ui-sans-serif, system-ui; line-height: 1.5; padding: 0 16px;">
      <h1>Trust Pulse viewer</h1>
      <p>
        Trust Pulse is a small, <strong>self-reported</strong> (non-tier) run summary: tools used + relative file touches.
        It is designed for UX and review convenience and must not be used to uplift trust tiers.
      </p>
      <p>
        Paste a <code>trust_pulse.v1</code> JSON document below, or upload the <code>*-trust-pulse.json</code> emitted by <code>clawsig-wrap</code>.
      </p>
      <p><a href="${o}/docs">Back to docs</a></p>

      <div style="margin: 16px 0; padding: 12px; border: 1px solid #e5e7eb; border-radius: 10px; background: #fafafa;">
        <h2 style="margin: 0 0 8px 0; font-size: 16px;">Load from submission</h2>
        <div style="display:flex; gap:12px; align-items:center; flex-wrap:wrap;">
          <label style="display:flex; flex-direction:column; gap:4px; font-size: 13px;">
            <span>submission_id</span>
            <input id="submissionId" placeholder="sub_..." style="padding: 8px; min-width: 260px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas; font-size: 13px;" />
          </label>
          <label style="display:flex; flex-direction:column; gap:4px; font-size: 13px;">
            <span>token (admin key or worker token)</span>
            <input id="token" type="password" placeholder="Bearer ..." style="padding: 8px; min-width: 320px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas; font-size: 13px;" />
          </label>
          <div style="display:flex; flex-direction:column; gap:4px;">
            <span style="font-size: 13px;">&nbsp;</span>
            <button id="fetch">Fetch</button>
          </div>
          <div id="fetchMeta" style="font-size: 13px; color:#374151;"></div>
        </div>
        <p style="margin: 8px 0 0 0; font-size: 12px; color:#6b7280;">
          Uses <code>Authorization: Bearer ...</code> header. Token is never placed in the URL.
        </p>
      </div>

      <div style="display:flex; gap:12px; align-items:center; flex-wrap:wrap; margin: 16px 0;">
        <button id="loadSample">Load sample</button>
        <button id="render">Render</button>
        <label style="display:inline-flex; gap:8px; align-items:center;">
          <span style="font-size: 14px;">Upload JSON</span>
          <input id="file" type="file" accept="application/json,.json" />
        </label>
      </div>

      <textarea id="input" spellcheck="false" style="width: 100%; min-height: 240px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas; font-size: 13px; padding: 12px;"></textarea>

      <div id="error" style="margin-top: 12px; color: #b91c1c; white-space: pre-wrap;"></div>

      <div id="out" style="margin-top: 18px; display: grid; grid-template-columns: 1fr 1fr; gap: 18px;"></div>

      <script>
        (function(){
          const elInput = document.getElementById('input');
          const elError = document.getElementById('error');
          const elOut = document.getElementById('out');
          const elFile = document.getElementById('file');
          const elSubmissionId = document.getElementById('submissionId');
          const elToken = document.getElementById('token');
          const elFetch = document.getElementById('fetch');
          const elFetchMeta = document.getElementById('fetchMeta');

          const SAMPLE = {
            trust_pulse_version: '1',
            trust_pulse_id: 'tp_example',
            run_id: 'run_example',
            agent_did: 'did:key:zExample',
            issued_at: new Date().toISOString(),
            evidence_class: 'self_reported',
            tier_uplift: false,
            started_at: new Date().toISOString(),
            ended_at: new Date().toISOString(),
            duration_ms: 1234,
            tools: [
              { name: 'Read', calls: 3 },
              { name: 'Edit', calls: 1 }
            ],
            files: [
              { path: 'src/index.ts', touches: 2 },
              { path: 'README.md', touches: 1 }
            ]
          };

          function esc(s){
            return String(s)
              .replace(/&/g, '&amp;')
              .replace(/</g, '&lt;')
              .replace(/>/g, '&gt;')
              .replace(/"/g, '&quot;')
              .replace(/'/g, '&#39;');
          }

          function fmtMeta(tp){
            const rows = [];
            rows.push(['run_id', tp.run_id]);
            rows.push(['agent_did', tp.agent_did]);
            rows.push(['issued_at', tp.issued_at]);
            if (tp.duration_ms !== undefined) rows.push(['duration_ms', tp.duration_ms]);
            rows.push(['evidence_class', tp.evidence_class]);
            rows.push(['tier_uplift', tp.tier_uplift]);

            return '<div style="grid-column: 1 / -1; padding: 12px; border: 1px solid #e5e7eb; border-radius: 10px; background: #fafafa;">'
              + '<h2 style="margin: 0 0 8px 0; font-size: 16px;">Metadata</h2>'
              + '<table style="width:100%; border-collapse: collapse; font-size: 13px;">'
              + rows.map(([k,v]) => '<tr><td style="padding: 6px 8px; width: 160px; color:#374151;">'+esc(k)+'</td><td style="padding: 6px 8px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas;">'+esc(v)+'</td></tr>').join('')
              + '</table>'
              + '</div>';
          }

          function renderList(title, items, key, val){
            const rows = items.map((it) => {
              return '<div style="display:flex; justify-content: space-between; gap: 12px; padding: 6px 0; border-bottom: 1px dashed #e5e7eb;">'
                + '<div style="font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas;">'+esc(it[key])+'</div>'
                + '<div style="font-variant-numeric: tabular-nums; color:#111827;">'+esc(it[val])+'</div>'
                + '</div>';
            }).join('');

            return '<div style="padding: 12px; border: 1px solid #e5e7eb; border-radius: 10px;">'
              + '<h2 style="margin: 0 0 8px 0; font-size: 16px;">'+esc(title)+'</h2>'
              + (items.length === 0 ? '<p style="margin:0; color:#6b7280;">(none)</p>' : rows)
              + '</div>';
          }

          function validate(tp){
            const errs = [];
            if (!tp || typeof tp !== 'object') errs.push('Expected JSON object');
            if (tp.trust_pulse_version !== '1') errs.push('trust_pulse_version must be "1"');
            if (tp.evidence_class !== 'self_reported') errs.push('evidence_class must be "self_reported"');
            if (tp.tier_uplift !== false) errs.push('tier_uplift must be false');
            if (!tp.run_id) errs.push('run_id is required');
            if (!tp.agent_did) errs.push('agent_did is required');
            if (!Array.isArray(tp.tools)) errs.push('tools must be an array');
            if (!Array.isArray(tp.files)) errs.push('files must be an array');
            return errs;
          }

          function doRender(){
            elError.textContent = '';
            elOut.innerHTML = '';

            let tp;
            try {
              tp = JSON.parse(elInput.value);
            } catch(e) {
              elError.textContent = 'Invalid JSON: ' + (e && e.message ? e.message : String(e));
              return;
            }

            const errs = validate(tp);
            if (errs.length) {
              elError.textContent = 'Validation failed:\n- ' + errs.join('\n- ');
              return;
            }

            const tools = (tp.tools || []).slice().sort((a,b) => (b.calls||0)-(a.calls||0));
            const files = (tp.files || []).slice().sort((a,b) => (b.touches||0)-(a.touches||0));

            elOut.innerHTML = fmtMeta(tp)
              + renderList('Tools', tools, 'name', 'calls')
              + renderList('Files touched', files, 'path', 'touches');
          }

          function normalizeToken(raw){
            const s = String(raw || '').trim();
            return s.replace(/^bearer\s+/i, '').trim();
          }

          async function fetchFromSubmission(auto){
            elError.textContent = '';
            elFetchMeta.textContent = '';

            const submissionId = elSubmissionId && elSubmissionId.value ? elSubmissionId.value.trim() : '';
            const token = normalizeToken(elToken && elToken.value ? elToken.value : '');

            if (!submissionId) {
              elError.textContent = 'submission_id is required.';
              return;
            }
            if (!token) {
              elError.textContent = 'token is required.';
              return;
            }

            if (elFetch) {
              elFetch.disabled = true;
              elFetch.textContent = auto ? 'Fetching…' : 'Fetching…';
            }

            try {
              const res = await fetch('/v1/submissions/' + encodeURIComponent(submissionId) + '/trust-pulse', {
                method: 'GET',
                headers: {
                  'authorization': 'Bearer ' + token
                }
              });

              const data = await res.json().catch(() => null);
              if (!res.ok) {
                const msg = data && data.message ? data.message : ('HTTP ' + res.status);
                elError.textContent = 'Fetch failed: ' + msg;
                return;
              }

              try { sessionStorage.setItem('trust_pulse_token', token); } catch(e) {}

              elInput.value = JSON.stringify(data.trust_pulse, null, 2);
              doRender();

              const status = data.status || 'unknown';
              const hash = data.hash_b64u ? String(data.hash_b64u) : '';
              elFetchMeta.textContent = 'Loaded: ' + status + (hash ? (' · hash ' + hash) : '');
            } catch(e) {
              elError.textContent = 'Fetch error: ' + (e && e.message ? e.message : String(e));
            } finally {
              if (elFetch) {
                elFetch.disabled = false;
                elFetch.textContent = 'Fetch';
              }
            }
          }

          if (elFetch) {
            elFetch.addEventListener('click', function(){
              fetchFromSubmission(false);
            });
          }

          try {
            const qs = new URLSearchParams(window.location.search);
            const qid = (qs.get('submission_id') || '').trim();
            if (qid && elSubmissionId) elSubmissionId.value = qid;

            const tok = sessionStorage.getItem('trust_pulse_token');
            if (tok && elToken) elToken.value = tok;

            if (qid && tok) {
              fetchFromSubmission(true);
            }
          } catch(e) {}

          document.getElementById('loadSample').addEventListener('click', function(){
            elInput.value = JSON.stringify(SAMPLE, null, 2);
            doRender();
          });

          document.getElementById('render').addEventListener('click', function(){
            doRender();
          });

          elFile.addEventListener('change', async function(){
            const f = elFile.files && elFile.files[0];
            if (!f) return;
            const text = await f.text();
            elInput.value = text;
            doRender();
          });

          // start with a sample
          elInput.value = JSON.stringify(SAMPLE, null, 2);
          doRender();
        })();
      </script>
    </main>
  </body>
</html>`;
}

function skillMarkdown(origin: string): string {
  const metadata = {
    name: 'clawbounties',
    version: '1',
    description: 'Bounty marketplace for agent work (posting, acceptance, submissions, quorum review).',
    endpoints: [
      { method: 'GET', path: '/' },
      { method: 'GET', path: '/docs' },
      { method: 'GET', path: '/trust-pulse' },
      { method: 'GET', path: '/skill.md' },
      { method: 'GET', path: '/health' },
      { method: 'POST', path: '/v1/workers/register' },
      { method: 'GET', path: '/v1/workers' },
      { method: 'GET', path: '/v1/workers/self' },
      { method: 'GET', path: '/v1/bounties' },
      { method: 'POST', path: '/v1/bounties' },
      { method: 'POST', path: '/v1/bounties/{bounty_id}/accept' },
      { method: 'POST', path: '/v1/bounties/{bounty_id}/submit' },
      { method: 'GET', path: '/v1/bounties/{bounty_id}/submissions' },
      { method: 'GET', path: '/v1/submissions/{submission_id}' },
      { method: 'GET', path: '/v1/submissions/{submission_id}/trust-pulse' },
      { method: 'GET', path: '/v1/bounties/{bounty_id}/submissions' },
      { method: 'GET', path: '/v1/submissions/{submission_id}' },
      { method: 'POST', path: '/v1/bounties/{bounty_id}/approve' },
      { method: 'POST', path: '/v1/bounties/{bounty_id}/reject' },
    ],
  };

  // OpenClaw requirement: metadata must be a single-line JSON object string
  return `---
metadata: '${JSON.stringify(metadata)}'
---

# clawbounties

Developer discovery + minimal marketplace API.

Public worker endpoints:
- POST ${origin}/v1/workers/register
- GET ${origin}/v1/workers?job_type=code&tag=typescript
- GET ${origin}/v1/workers/self (requires Authorization: Bearer <token>)
- GET ${origin}/v1/bounties?status=open&is_code_bounty=true&tag=typescript (requires Authorization: Bearer <token>)
- POST ${origin}/v1/bounties/{bounty_id}/accept (requires Authorization: Bearer <token>)
- POST ${origin}/v1/bounties/{bounty_id}/submit (requires Authorization: Bearer <token>)
- GET ${origin}/v1/bounties/{bounty_id}/submissions (admin OR worker token OR x-requester-did)
- GET ${origin}/v1/submissions/{submission_id} (admin OR worker token OR x-requester-did)
- GET ${origin}/v1/submissions/{submission_id}/trust-pulse (requires Authorization: Bearer <worker token> OR admin key)

Requester bounty endpoints (require Authorization: Bearer <requester token>):
- POST ${origin}/v1/bounties (scope: clawbounties:bounty:create)
- POST ${origin}/v1/bounties/{bounty_id}/approve (scope: clawbounties:bounty:approve)
- POST ${origin}/v1/bounties/{bounty_id}/reject (scope: clawbounties:bounty:reject)
- GET ${origin}/v1/bounties/{bounty_id}/submissions (scope: clawbounties:bounty:read)
- GET ${origin}/v1/submissions/{submission_id} (scope: clawbounties:bounty:read; workers can read their own submission by worker token)

Admin ops endpoints (require BOUNTIES_ADMIN_KEY):
- GET ${origin}/v1/bounties
- GET ${origin}/v1/bounties/{bounty_id}

Docs: ${origin}/docs
`;
}

function robotsTxt(origin: string): string {
  return `User-agent: *\nAllow: /\nSitemap: ${origin}/sitemap.xml\n`;
}

function sitemapXml(origin: string): string {
  const urls = [`${origin}/`, `${origin}/docs`, `${origin}/trust-pulse`, `${origin}/skill.md`, `${origin}/health`];

  const urlset = urls
    .map((u) => `  <url><loc>${escapeXml(u)}</loc></url>`)
    .join('\n');

  return `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urlset}
</urlset>
`;
}

function securityTxt(origin: string): string {
  const expires = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();
  return `Contact: mailto:security@clawbounties.com\nPreferred-Languages: en\nExpires: ${expires}\nCanonical: ${origin}/.well-known/security.txt\n`;
}

async function handleRegisterWorker(request: Request, env: Env, version: string): Promise<Response> {
  const bodyRaw = await parseJsonBody(request);
  if (!isRecord(bodyRaw)) {
    return errorResponse('INVALID_REQUEST', 'Invalid JSON body', 400, undefined, version);
  }

  const worker_did_raw = bodyRaw.worker_did;
  const worker_version_raw = bodyRaw.worker_version;
  const listing_raw = bodyRaw.listing;
  const capabilities_raw = bodyRaw.capabilities;
  const offers_raw = bodyRaw.offers;
  const pricing_raw = bodyRaw.pricing;
  const availability_raw = bodyRaw.availability;

  if (!isNonEmptyString(worker_did_raw)) {
    return errorResponse('INVALID_REQUEST', 'worker_did is required', 400, undefined, version);
  }

  const worker_did = worker_did_raw.trim();
  if (!worker_did.startsWith('did:')) {
    return errorResponse('INVALID_REQUEST', 'worker_did must be a DID string', 400, undefined, version);
  }

  if (!isNonEmptyString(worker_version_raw)) {
    return errorResponse('INVALID_REQUEST', 'worker_version is required', 400, undefined, version);
  }
  const worker_version = worker_version_raw.trim();
  if (worker_version.length > 80) {
    return errorResponse('INVALID_REQUEST', 'worker_version is too long', 400, undefined, version);
  }

  const listing = parseWorkerListing(listing_raw);
  if (!listing) {
    return errorResponse('INVALID_REQUEST', 'listing is invalid', 400, undefined, version);
  }

  const capabilities = parseWorkerCapabilities(capabilities_raw);
  if (!capabilities) {
    return errorResponse('INVALID_REQUEST', 'capabilities is invalid', 400, undefined, version);
  }

  const offers = parseWorkerOffers(offers_raw);
  if (!offers) {
    return errorResponse('INVALID_REQUEST', 'offers is invalid', 400, undefined, version);
  }

  const pricing = parseWorkerPricing(pricing_raw);
  if (!pricing) {
    return errorResponse('INVALID_REQUEST', 'pricing is invalid', 400, undefined, version);
  }

  const availability = parseWorkerAvailability(availability_raw);
  if (!availability) {
    return errorResponse('INVALID_REQUEST', 'availability is invalid', 400, undefined, version);
  }

  const now = new Date().toISOString();

  let existing: WorkerRecordV1 | null;
  try {
    existing = await getWorkerByDid(env.BOUNTIES_DB, worker_did);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('DB_READ_FAILED', message, 500, undefined, version);
  }

  // Prevent trivial DID takeover: if a worker DID already exists, require authenticated worker ownership.
  if (existing) {
    const auth = await requireWorker(request, env, version, {
      action: 'worker_self',
      worker_did_hint: worker_did,
    });
    if ('error' in auth) return auth.error;
  }

  const worker_id = existing?.worker_id ?? `wrk_${crypto.randomUUID()}`;
  const created_at = existing?.created_at ?? now;

  const authToken = generateWorkerToken();
  const auth_token_hash_hex = await sha256HexUtf8(authToken);
  const ttlSeconds = resolveWorkerTokenTtlSeconds(env);
  const auth_token_expires_at = new Date(Date.now() + ttlSeconds * 1000).toISOString();

  const record: WorkerRecordV1 = {
    worker_id,
    worker_did,
    status: availability.paused ? 'paused' : 'online',
    worker_version,
    listing,
    capabilities,
    offers,
    pricing,
    availability,
    auth_mode: 'token',
    auth_token_hash_hex,
    auth_token_prefix: authToken.slice(0, 8),
    auth_token_created_at: now,
    auth_token_expires_at,
    created_at,
    updated_at: now,
  };

  try {
    await upsertWorker(env.BOUNTIES_DB, record);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('DB_WRITE_FAILED', message, 500, undefined, version);
  }

  // Re-read after upsert to avoid returning an incorrect worker_id under concurrent registrations.
  let persisted: WorkerRecordV1 | null;
  try {
    persisted = await getWorkerByDid(env.BOUNTIES_DB, worker_did);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('DB_READ_FAILED', message, 500, undefined, version);
  }

  if (!persisted) {
    return errorResponse('DB_READ_FAILED', 'Worker record not found after upsert', 500, undefined, version);
  }

  const response: RegisterWorkerResponseV1 = {
    worker_id: persisted.worker_id,
    auth: { mode: 'token', token: authToken },
  };

  return jsonResponse(response, existing ? 200 : 201, version);
}

async function handleListWorkers(url: URL, env: Env, version: string): Promise<Response> {
  const jobTypeRaw = url.searchParams.get('job_type');
  const job_type = jobTypeRaw?.trim().length ? jobTypeRaw.trim() : null;

  const tags = url.searchParams
    .getAll('tag')
    .map((t) => t.trim())
    .filter((t) => t.length > 0);

  let limit = 50;
  const limitRaw = url.searchParams.get('limit');
  if (limitRaw !== null) {
    const n = Number(limitRaw);
    if (!Number.isFinite(n) || !Number.isInteger(n) || n < 1 || n > 100) {
      return errorResponse('INVALID_REQUEST', 'limit must be an integer between 1 and 100', 400, undefined, version);
    }
    limit = n;
  }

  // NOTE: We currently store filterable worker fields (job_types/tags) inside JSON.
  // Until we project/index those fields in SQL, we over-fetch a bounded window, filter in-memory,
  // then apply the requested limit so discovery results are not accidentally empty.
  const scanLimit = (job_type || tags.length > 0) ? Math.min(500, Math.max(limit, limit * 10)) : limit;

  let workers: WorkerListItemV1[];
  try {
    workers = await listWorkers(env.BOUNTIES_DB, scanLimit);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('DB_READ_FAILED', message, 500, undefined, version);
  }

  if (job_type) {
    workers = workers.filter((w) => w.capabilities.job_types.includes(job_type));
  }

  if (tags.length > 0) {
    workers = workers.filter((w) => tags.some((t) => w.listing.tags.includes(t)));
  }

  workers = workers.slice(0, limit);

  return jsonResponse({ workers }, 200, version);
}

async function handleGetWorkerSelf(request: Request, env: Env, version: string): Promise<Response> {
  const auth = await requireWorker(request, env, version, {
    action: 'worker_self',
  });
  if ('error' in auth) return auth.error;

  const w = auth.worker;
  return jsonResponse(
    {
      worker_id: w.worker_id,
      worker_did: w.worker_did,
      status: w.status,
      worker_version: w.worker_version,
      listing: w.listing,
      capabilities: w.capabilities,
      offers: w.offers,
      pricing: w.pricing,
      availability: w.availability,
      auth: {
        mode: auth.auth.auth_mode,
        expires_at:
          auth.auth.auth_mode === 'scoped_token' && typeof auth.auth.exp === 'number'
            ? new Date(auth.auth.exp * 1000).toISOString()
            : w.auth_token_expires_at,
        token_lane: auth.auth.token_lane,
      },
      created_at: w.created_at,
      updated_at: w.updated_at,
    },
    200,
    version
  );
}

function parseEscrowFailedError(err: unknown): { status: number; payload: Record<string, unknown> } | null {
  if (!(err instanceof Error)) return null;
  const prefix = 'ESCROW_FAILED:';
  if (!err.message.startsWith(prefix)) return null;

  const rest = err.message.slice(prefix.length);
  const idx = rest.indexOf(':');
  if (idx === -1) return null;

  const statusRaw = rest.slice(0, idx);
  const status = Number(statusRaw);
  if (!Number.isFinite(status)) return null;

  const payloadRaw = rest.slice(idx + 1);
  try {
    const parsed = JSON.parse(payloadRaw) as unknown;
    if (isRecord(parsed)) return { status, payload: parsed };
    return { status, payload: { raw: parsed } };
  } catch {
    return { status, payload: { raw: payloadRaw } };
  }
}

async function handleAcceptBounty(bountyId: string, request: Request, env: Env, version: string): Promise<Response> {
  const auth = await requireWorker(request, env, version, {
    action: 'accept_bounty',
  });
  if ('error' in auth) return auth.error;

  const bodyRaw = await parseJsonBody(request);
  if (!isRecord(bodyRaw)) {
    return errorResponse('INVALID_REQUEST', 'Invalid JSON body', 400, undefined, version);
  }

  const idempotency_key_raw = bodyRaw.idempotency_key;
  const worker_did_raw = bodyRaw.worker_did;
  const cwc_worker_envelope_raw = bodyRaw.cwc_worker_envelope;

  if (!isNonEmptyString(idempotency_key_raw)) {
    return errorResponse('INVALID_REQUEST', 'idempotency_key is required', 400, undefined, version);
  }

  const idempotency_key = idempotency_key_raw.trim();
  if (idempotency_key.length > 200) {
    return errorResponse('INVALID_REQUEST', 'idempotency_key is too long', 400, undefined, version);
  }

  if (!isNonEmptyString(worker_did_raw) || !worker_did_raw.trim().startsWith('did:')) {
    return errorResponse('INVALID_REQUEST', 'worker_did must be a DID string', 400, undefined, version);
  }

  const worker_did = worker_did_raw.trim();
  if (worker_did !== auth.worker.worker_did) {
    return errorResponse('UNAUTHORIZED', 'worker_did must match authenticated worker', 401, undefined, version);
  }

  if (cwc_worker_envelope_raw !== undefined && cwc_worker_envelope_raw !== null && !isRecord(cwc_worker_envelope_raw)) {
    return errorResponse('INVALID_REQUEST', 'cwc_worker_envelope must be an object', 400, undefined, version);
  }

  let bounty: BountyV2 | null;
  try {
    bounty = await getBountyById(env.BOUNTIES_DB, bountyId);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('DB_READ_FAILED', message, 500, undefined, version);
  }

  if (!bounty) {
    return errorResponse('NOT_FOUND', 'Bounty not found', 404, undefined, version);
  }

  const requested = bounty.metadata.requested_worker_did;
  if (requested !== undefined && requested !== null) {
    if (!isNonEmptyString(requested) || !requested.trim().startsWith('did:')) {
      return errorResponse('BOUNTY_METADATA_INVALID', 'metadata.requested_worker_did is invalid', 500, undefined, version);
    }

    const requestedDid = requested.trim();
    if (requestedDid !== worker_did) {
      return errorResponse(
        'FORBIDDEN',
        'Bounty is direct-hire to a different worker',
        403,
        { requested_worker_did: requestedDid },
        version
      );
    }
  }

  if (bounty.worker_did && bounty.worker_did !== worker_did) {
    return errorResponse(
      'BOUNTY_ALREADY_ACCEPTED',
      'Bounty already accepted',
      409,
      { worker_did: bounty.worker_did },
      version
    );
  }

  // If the bounty is not already accepted by this worker, it must be open.
  if (!bounty.worker_did && bounty.status !== 'open') {
    return errorResponse('INVALID_STATUS', `Cannot accept bounty in status '${bounty.status}'`, 409, undefined, version);
  }

  const cwcNeedsCountersign = bounty.cwc_hash_b64u !== null && !bounty.cwc_worker_envelope;
  let cwc_worker_envelope_json: string | null = null;

  if (cwcNeedsCountersign) {
    if (!isRecord(cwc_worker_envelope_raw) || !isConfidentialWorkContractEnvelopeV1(cwc_worker_envelope_raw)) {
      return errorResponse(
        'CWC_COUNTERSIGN_REQUIRED',
        'cwc_worker_envelope is required and must be a valid confidential_work_contract envelope',
        400,
        undefined,
        version
      );
    }

    const envelope = cwc_worker_envelope_raw as unknown as ConfidentialWorkContractEnvelopeV1;
    const verified = await verifyCwcEnvelope(envelope);

    if (!verified.ok) {
      return errorResponse(verified.code, verified.message, 400, undefined, version);
    }

    if (verified.payload_hash_b64u !== bounty.cwc_hash_b64u) {
      return errorResponse(
        'CWC_HASH_MISMATCH',
        'cwc_worker_envelope must sign the exact CWC hash pinned to the bounty',
        400,
        { expected_hash_b64u: bounty.cwc_hash_b64u, actual_hash_b64u: verified.payload_hash_b64u },
        version
      );
    }

    const buyerDid = verified.payload.buyer_did.trim();
    const workerDid = verified.payload.worker_did.trim();

    if (buyerDid !== bounty.requester_did) {
      return errorResponse('CWC_PARTY_MISMATCH', 'CWC buyer_did does not match bounty requester', 400, undefined, version);
    }

    if (workerDid !== worker_did) {
      return errorResponse('UNAUTHORIZED', 'CWC worker_did must match worker_did', 401, { worker_did: workerDid }, version);
    }

    if (envelope.signer_did.trim() !== workerDid) {
      return errorResponse('INVALID_REQUEST', 'CWC worker envelope signer_did must equal payload.worker_did', 400, undefined, version);
    }

    if (verified.payload.wpc_policy_hash_b64u.trim() !== bounty.cwc_wpc_policy_hash_b64u) {
      return errorResponse(
        'CWC_POLICY_HASH_MISMATCH',
        'CWC wpc_policy_hash_b64u does not match bounty pinned policy hash',
        400,
        { expected_policy_hash_b64u: bounty.cwc_wpc_policy_hash_b64u },
        version
      );
    }

    if (verified.payload.required_proof_tier !== bounty.cwc_required_proof_tier) {
      return errorResponse(
        'CWC_TIER_MISMATCH',
        'CWC required_proof_tier does not match bounty pinned required tier',
        400,
        { expected_required_proof_tier: bounty.cwc_required_proof_tier },
        version
      );
    }

    if (verified.payload.required_proof_tier !== bounty.min_proof_tier) {
      return errorResponse(
        'CWC_TIER_MISMATCH',
        'CWC required_proof_tier must match bounty min_proof_tier',
        400,
        { required_proof_tier: verified.payload.required_proof_tier, min_proof_tier: bounty.min_proof_tier },
        version
      );
    }

    cwc_worker_envelope_json = JSON.stringify(cwc_worker_envelope_raw);
  }

  const isCwcBounty = bounty.cwc_hash_b64u !== null;
  const cwcPolicyHash = isCwcBounty ? bounty.cwc_wpc_policy_hash_b64u : null;

  let expectedTokenScopeHash: string | null = null;
  let issuedCst: IssuedCst | null = null;

  if (isCwcBounty) {
    if (!cwcPolicyHash) {
      return errorResponse('CWC_INVALID_BOUNTY', 'Bounty is missing cwc_wpc_policy_hash_b64u', 500, undefined, version);
    }

    // Note: CST issuance (via clawscope) is best-effort. We still compute and persist
    // the deterministic expected token_scope_hash_b64u even if clawscope is not configured.

    try {
      expectedTokenScopeHash = await computeTokenScopeHashB64uV1({
        sub: worker_did,
        aud: CWC_JOB_CST_AUD,
        scope: CWC_JOB_CST_SCOPE,
        policy_hash_b64u: cwcPolicyHash,
        mission_id: bounty.bounty_id,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      return errorResponse(
        'CWC_TOKEN_SCOPE_HASH_FAILED',
        `Failed to compute token_scope_hash_b64u: ${message}`,
        500,
        undefined,
        version
      );
    }

    if (!expectedTokenScopeHash || !isSha256B64u(expectedTokenScopeHash)) {
      return errorResponse(
        'CWC_TOKEN_SCOPE_HASH_FAILED',
        'Computed token_scope_hash_b64u is invalid',
        500,
        { token_scope_hash_b64u: expectedTokenScopeHash },
        version
      );
    }

    const stored = bounty.cwc_token_scope_hash_b64u;
    const canValidateStoredScope = bounty.worker_did === null || bounty.worker_did === worker_did;

    if (stored && stored.trim().length > 0 && canValidateStoredScope && stored.trim() !== expectedTokenScopeHash) {
      return errorResponse(
        'CWC_TOKEN_SCOPE_HASH_MISMATCH',
        'Stored cwc_token_scope_hash_b64u does not match computed expected token scope hash',
        500,
        {
          stored_token_scope_hash_b64u: stored.trim(),
          expected_token_scope_hash_b64u: expectedTokenScopeHash,
        },
        version
      );
    }
  }

  // POH-US-022: deterministic job token binding (non-transferable receipts)
  //
  // For bounties that require gateway-tier proofs (min_proof_tier != self), we compute a deterministic
  // expected token_scope_hash_b64u for a job-scoped CST. This binds gateway receipts to:
  // - worker DID (sub)
  // - bounty id (mission_id)
  // - (optionally) pinned policy hash (CWC)
  //
  // We persist this at acceptance time (open -> accepted). For older already-accepted bounties,
  // we do not auto-backfill here to avoid unintentionally changing submission requirements mid-flight.
  let expectedJobTokenScopeHash: string | null = null;
  const shouldBindJobToken = bounty.min_proof_tier !== 'self';

  if (shouldBindJobToken) {
    try {
      expectedJobTokenScopeHash = await computeTokenScopeHashB64uV1({
        sub: worker_did,
        aud: CWC_JOB_CST_AUD,
        scope: CWC_JOB_CST_SCOPE,
        policy_hash_b64u: cwcPolicyHash ?? undefined,
        mission_id: bounty.bounty_id,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      return errorResponse(
        'JOB_TOKEN_SCOPE_HASH_FAILED',
        `Failed to compute job token_scope_hash_b64u: ${message}`,
        500,
        undefined,
        version
      );
    }

    if (!expectedJobTokenScopeHash || !isSha256B64u(expectedJobTokenScopeHash)) {
      return errorResponse(
        'JOB_TOKEN_SCOPE_HASH_FAILED',
        'Computed job token_scope_hash_b64u is invalid',
        500,
        { token_scope_hash_b64u: expectedJobTokenScopeHash },
        version
      );
    }

    const stored = bounty.job_token_scope_hash_b64u;
    const canValidateStoredScope = bounty.worker_did === null || bounty.worker_did === worker_did;

    if (stored && stored.trim().length > 0 && canValidateStoredScope && stored.trim() !== expectedJobTokenScopeHash) {
      return errorResponse(
        'JOB_TOKEN_SCOPE_HASH_MISMATCH',
        'Stored job_token_scope_hash_b64u does not match computed expected token scope hash',
        500,
        {
          stored_token_scope_hash_b64u: stored.trim(),
          expected_token_scope_hash_b64u: expectedJobTokenScopeHash,
        },
        version
      );
    }
  }

  // Already accepted.
  if (bounty.worker_did) {
    if (bounty.worker_did === worker_did) {
      if (bounty.status !== 'accepted') {
        return errorResponse(
          'INVALID_STATUS',
          `Cannot accept bounty in status '${bounty.status}'`,
          409,
          { status: bounty.status },
          version
        );
      }

      // If this bounty is governed by a CWC and is missing the worker countersign,
      // allow an idempotent accept call to provide/store it.
      if (cwcNeedsCountersign && cwc_worker_envelope_json) {
        try {
          await updateBountyCwcWorkerEnvelope(env.BOUNTIES_DB, {
            bounty_id: bountyId,
            worker_did,
            cwc_worker_envelope_json,
            now: new Date().toISOString(),
          });
        } catch (err) {
          const message = err instanceof Error ? err.message : 'Unknown error';
          return errorResponse('DB_WRITE_FAILED', message, 500, undefined, version);
        }
      }

      if (isCwcBounty && expectedTokenScopeHash) {
        try {
          await updateBountyCwcTokenScopeHash(env.BOUNTIES_DB, {
            bounty_id: bountyId,
            worker_did,
            cwc_token_scope_hash_b64u: expectedTokenScopeHash,
            now: new Date().toISOString(),
          });
        } catch (err) {
          const message = err instanceof Error ? err.message : 'Unknown error';
          return errorResponse('DB_WRITE_FAILED', message, 500, undefined, version);
        }

        const issued = await issueCwcJobCst(
          env,
          {
            worker_did,
            bounty_id: bounty.bounty_id,
            policy_hash_b64u: cwcPolicyHash!,
          },
          version
        );

        if (issued.ok) {
          issuedCst = issued.value;

          if (issuedCst.token_scope_hash_b64u !== expectedTokenScopeHash) {
            return errorResponse(
              'CWC_CST_ISSUE_FAILED',
              'clawscope returned a token_scope_hash_b64u that does not match the expected deterministic hash',
              502,
              {
                expected_token_scope_hash_b64u: expectedTokenScopeHash,
                issued_token_scope_hash_b64u: issuedCst.token_scope_hash_b64u,
              },
              version
            );
          }
        }
      }

      const accepted_at = bounty.accepted_at ?? bounty.updated_at;
      const response: AcceptBountyResponseV1 = {
        bounty_id: bounty.bounty_id,
        escrow_id: bounty.escrow_id,
        status: 'accepted',
        worker_did,
        accepted_at,
        fee_policy_version: bounty.fee_policy_version,
        payout: {
          worker_net_minor: bounty.fee_quote.quote.worker_net_minor,
          currency: 'USD',
        },
      };

      if (issuedCst) {
        response.cwc_auth = {
          cst: issuedCst.token,
          token_scope_hash_b64u: issuedCst.token_scope_hash_b64u,
          aud: CWC_JOB_CST_AUD,
          policy_hash_b64u: bounty.cwc_wpc_policy_hash_b64u!,
          mission_id: bounty.bounty_id,
          iat: issuedCst.iat,
          exp: issuedCst.exp,
        };
      }

      return jsonResponse(response, 200, version);
    }

    return errorResponse('BOUNTY_ALREADY_ACCEPTED', 'Bounty already accepted', 409, { worker_did: bounty.worker_did }, version);
  }

  if (bounty.status !== 'open') {
    return errorResponse('INVALID_STATUS', `Cannot accept bounty in status '${bounty.status}'`, 409, undefined, version);
  }

  const now = new Date().toISOString();

  // Assign escrow (canonical lock)
  try {
    await escrowAssignWorker(env, {
      escrow_id: bounty.escrow_id,
      idempotency_key,
      worker_did,
    });
  } catch (err) {
    const parsed = parseEscrowFailedError(err);
    if (parsed && parsed.status === 409) {
      const code = isNonEmptyString(parsed.payload.error) ? parsed.payload.error.trim() : 'ESCROW_CONFLICT';
      const message = isNonEmptyString(parsed.payload.message) ? parsed.payload.message.trim() : 'Escrow conflict';
      return errorResponse(code, message, 409, undefined, version);
    }

    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('ESCROW_FAILED', message, 502, undefined, version);
  }

  if (isCwcBounty && expectedTokenScopeHash) {
    const issued = await issueCwcJobCst(
      env,
      {
        worker_did,
        bounty_id: bounty.bounty_id,
        policy_hash_b64u: cwcPolicyHash!,
      },
      version
    );

    if (issued.ok) {
      issuedCst = issued.value;

      if (issuedCst.token_scope_hash_b64u !== expectedTokenScopeHash) {
        return errorResponse(
          'CWC_CST_ISSUE_FAILED',
          'clawscope returned a token_scope_hash_b64u that does not match the expected deterministic hash',
          502,
          {
            expected_token_scope_hash_b64u: expectedTokenScopeHash,
            issued_token_scope_hash_b64u: issuedCst.token_scope_hash_b64u,
          },
          version
        );
      }
    }
  }

  // Persist acceptance on bounty.
  try {
    await updateBountyAccepted(env.BOUNTIES_DB, {
      bounty_id: bountyId,
      worker_did,
      accepted_at: now,
      idempotency_key,
      cwc_worker_envelope_json,
      cwc_token_scope_hash_b64u: expectedTokenScopeHash,
      job_token_scope_hash_b64u: expectedJobTokenScopeHash,
      now,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('DB_WRITE_FAILED', message, 500, undefined, version);
  }

  const updated = await getBountyById(env.BOUNTIES_DB, bountyId);
  if (!updated || updated.status !== 'accepted' || updated.worker_did !== worker_did) {
    return errorResponse('DB_WRITE_FAILED', 'Failed to persist bounty acceptance', 500, undefined, version);
  }

  const response: AcceptBountyResponseV1 = {
    bounty_id: updated.bounty_id,
    escrow_id: updated.escrow_id,
    status: 'accepted',
    worker_did,
    accepted_at: updated.accepted_at ?? now,
    fee_policy_version: updated.fee_policy_version,
    payout: {
      worker_net_minor: updated.fee_quote.quote.worker_net_minor,
      currency: 'USD',
    },
  };

  if (issuedCst) {
    response.cwc_auth = {
      cst: issuedCst.token,
      token_scope_hash_b64u: issuedCst.token_scope_hash_b64u,
      aud: CWC_JOB_CST_AUD,
      policy_hash_b64u: bounty.cwc_wpc_policy_hash_b64u!,
      mission_id: bounty.bounty_id,
      iat: issuedCst.iat,
      exp: issuedCst.exp,
    };
  }

  return jsonResponse(response, 201, version);
}

async function handleIssueBountyCst(bountyId: string, request: Request, env: Env, version: string): Promise<Response> {
  const auth = await requireWorker(request, env, version, {
    action: 'issue_bounty_cst',
  });
  if ('error' in auth) return auth.error;

  const worker_did = auth.worker.worker_did;

  let bounty: BountyV2 | null;
  try {
    bounty = await getBountyById(env.BOUNTIES_DB, bountyId);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('DB_READ_FAILED', message, 500, undefined, version);
  }

  if (!bounty) {
    return errorResponse('NOT_FOUND', 'Bounty not found', 404, undefined, version);
  }

  if (!bounty.worker_did) {
    return errorResponse('BOUNTY_NOT_ACCEPTED', 'Bounty is not accepted', 409, undefined, version);
  }

  if (bounty.worker_did !== worker_did) {
    return errorResponse(
      'FORBIDDEN',
      'Bounty is accepted by a different worker',
      403,
      { worker_did: bounty.worker_did },
      version
    );
  }

  if (bounty.status !== 'accepted') {
    return errorResponse(
      'INVALID_STATUS',
      `Cannot issue CST for bounty in status '${bounty.status}'`,
      409,
      { status: bounty.status },
      version
    );
  }

  const isCwcBounty = bounty.cwc_hash_b64u !== null;
  const cwcPolicyHash = isCwcBounty ? bounty.cwc_wpc_policy_hash_b64u : null;

  if (isCwcBounty) {
    if (!cwcPolicyHash) {
      return errorResponse('CWC_INVALID_BOUNTY', 'Bounty is missing cwc_wpc_policy_hash_b64u', 500, undefined, version);
    }

    if (!bounty.cwc_worker_envelope) {
      return errorResponse('CWC_COUNTERSIGN_REQUIRED', 'CWC worker countersign is required', 409, undefined, version);
    }
  }

  let expectedTokenScopeHash: string;
  try {
    expectedTokenScopeHash = await computeTokenScopeHashB64uV1({
      sub: worker_did,
      aud: CWC_JOB_CST_AUD,
      scope: CWC_JOB_CST_SCOPE,
      policy_hash_b64u: cwcPolicyHash ?? undefined,
      mission_id: bounty.bounty_id,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    const code = isCwcBounty ? 'CWC_TOKEN_SCOPE_HASH_FAILED' : 'JOB_TOKEN_SCOPE_HASH_FAILED';
    return errorResponse(code, `Failed to compute token_scope_hash_b64u: ${message}`, 500, undefined, version);
  }

  if (!isSha256B64u(expectedTokenScopeHash)) {
    const code = isCwcBounty ? 'CWC_TOKEN_SCOPE_HASH_FAILED' : 'JOB_TOKEN_SCOPE_HASH_FAILED';
    return errorResponse(
      code,
      'Computed token_scope_hash_b64u is invalid',
      500,
      { token_scope_hash_b64u: expectedTokenScopeHash },
      version
    );
  }

  const stored = isCwcBounty ? bounty.cwc_token_scope_hash_b64u : bounty.job_token_scope_hash_b64u;
  if (stored && stored.trim().length > 0 && stored.trim() !== expectedTokenScopeHash) {
    const code = isCwcBounty ? 'CWC_TOKEN_SCOPE_HASH_MISMATCH' : 'JOB_TOKEN_SCOPE_HASH_MISMATCH';
    const message = isCwcBounty
      ? 'Stored cwc_token_scope_hash_b64u does not match computed expected token scope hash'
      : 'Stored job_token_scope_hash_b64u does not match computed expected token scope hash';

    return errorResponse(
      code,
      message,
      500,
      { stored_token_scope_hash_b64u: stored.trim(), expected_token_scope_hash_b64u: expectedTokenScopeHash },
      version
    );
  }

  // Persist expected hash (best-effort idempotent).
  try {
    const now = new Date().toISOString();

    if (isCwcBounty) {
      await updateBountyCwcTokenScopeHash(env.BOUNTIES_DB, {
        bounty_id: bounty.bounty_id,
        worker_did,
        cwc_token_scope_hash_b64u: expectedTokenScopeHash,
        now,
      });
    } else if (bounty.min_proof_tier !== 'self') {
      // POH-US-022: only persist non-CWC job binding for bounties that require gateway-tier proofs.
      await updateBountyJobTokenScopeHash(env.BOUNTIES_DB, {
        bounty_id: bounty.bounty_id,
        worker_did,
        job_token_scope_hash_b64u: expectedTokenScopeHash,
        now,
      });
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('DB_WRITE_FAILED', message, 500, undefined, version);
  }

  const issued = isCwcBounty
    ? await issueCwcJobCst(
        env,
        {
          worker_did,
          bounty_id: bounty.bounty_id,
          policy_hash_b64u: cwcPolicyHash!,
        },
        version
      )
    : await issueJobCst(
        env,
        {
          worker_did,
          bounty_id: bounty.bounty_id,
        },
        version
      );

  if (!issued.ok) return issued.error;

  const issuedCst = issued.value;
  if (issuedCst.token_scope_hash_b64u !== expectedTokenScopeHash) {
    const code = isCwcBounty ? 'CWC_CST_ISSUE_FAILED' : 'JOB_CST_ISSUE_FAILED';
    return errorResponse(
      code,
      'clawscope returned a token_scope_hash_b64u that does not match the expected deterministic hash',
      502,
      {
        expected_token_scope_hash_b64u: expectedTokenScopeHash,
        issued_token_scope_hash_b64u: issuedCst.token_scope_hash_b64u,
      },
      version
    );
  }

  const response: IssueBountyCstResponseV1 = {
    bounty_id: bounty.bounty_id,
    worker_did,
  };

  if (isCwcBounty) {
    response.cwc_auth = {
      cst: issuedCst.token,
      token_scope_hash_b64u: issuedCst.token_scope_hash_b64u,
      aud: CWC_JOB_CST_AUD,
      policy_hash_b64u: cwcPolicyHash!,
      mission_id: bounty.bounty_id,
      iat: issuedCst.iat,
      exp: issuedCst.exp,
    };
  } else {
    const jobAuth: JobAuthResponseV1 = {
      cst: issuedCst.token,
      token_scope_hash_b64u: issuedCst.token_scope_hash_b64u,
      aud: CWC_JOB_CST_AUD,
      mission_id: bounty.bounty_id,
      iat: issuedCst.iat,
      exp: issuedCst.exp,
    };

    if (issuedCst.policy_hash_b64u) jobAuth.policy_hash_b64u = issuedCst.policy_hash_b64u;

    response.job_auth = jobAuth;
  }

  return jsonResponse(response, 200, version);
}

async function handleSubmitBounty(
  bountyId: string,
  request: Request,
  env: Env,
  version: string,
  options?: {
    authOverride?: { worker: WorkerRecordV1; auth: WorkerAuthContext };
  },
): Promise<Response> {
  const auth = options?.authOverride ?? (await requireWorker(request, env, version, {
    action: 'submit_bounty',
  }));
  if ('error' in auth) return auth.error;

  const bodyRaw = await parseJsonBody(request);
  if (!isRecord(bodyRaw)) {
    return errorResponse('INVALID_REQUEST', 'Invalid JSON body', 400, undefined, version);
  }

  const worker_did_raw = bodyRaw.worker_did;
  const idempotency_key_raw = bodyRaw.idempotency_key;
  const proof_bundle_envelope_raw = bodyRaw.proof_bundle_envelope;
  const urm_raw = bodyRaw.urm;
  const commit_proof_envelope_raw = bodyRaw.commit_proof_envelope;
  const artifacts_raw = bodyRaw.artifacts;
  const agent_pack_raw = bodyRaw.agent_pack;
  const result_summary_raw = bodyRaw.result_summary;
  const trust_pulse_raw = bodyRaw.trust_pulse;
  const execution_attestations_raw = bodyRaw.execution_attestations;

  if (!isNonEmptyString(worker_did_raw) || !worker_did_raw.trim().startsWith('did:')) {
    return errorResponse('INVALID_REQUEST', 'worker_did must be a DID string', 400, undefined, version);
  }

  const worker_did = worker_did_raw.trim();
  if (worker_did !== auth.worker.worker_did) {
    return errorResponse('UNAUTHORIZED', 'worker_did must match authenticated worker', 401, undefined, version);
  }

  if (!isRecord(proof_bundle_envelope_raw)) {
    return errorResponse('INVALID_REQUEST', 'proof_bundle_envelope is required', 400, undefined, version);
  }

  if (urm_raw !== undefined && urm_raw !== null && !isRecord(urm_raw)) {
    return errorResponse('INVALID_REQUEST', 'urm must be an object', 400, undefined, version);
  }

  // POH-US-015: URM materialization is required when the proof bundle includes a URM reference.
  const proofPayload = (proof_bundle_envelope_raw as Record<string, unknown>).payload;
  const hasUrmRef = isRecord(proofPayload) && proofPayload.urm !== undefined && proofPayload.urm !== null;
  if (hasUrmRef && (urm_raw === undefined || urm_raw === null)) {
    return errorResponse(
      'INVALID_REQUEST',
      'urm is required when proof_bundle_envelope.payload.urm is present',
      400,
      undefined,
      version
    );
  }

  if (commit_proof_envelope_raw !== undefined && commit_proof_envelope_raw !== null && !isRecord(commit_proof_envelope_raw)) {
    return errorResponse('INVALID_REQUEST', 'commit_proof_envelope must be an object', 400, undefined, version);
  }

  if (artifacts_raw !== undefined && artifacts_raw !== null && !Array.isArray(artifacts_raw)) {
    return errorResponse('INVALID_REQUEST', 'artifacts must be an array', 400, undefined, version);
  }

  if (agent_pack_raw !== undefined && agent_pack_raw !== null && !isRecord(agent_pack_raw)) {
    return errorResponse('INVALID_REQUEST', 'agent_pack must be an object', 400, undefined, version);
  }

  if (result_summary_raw !== undefined && result_summary_raw !== null && typeof result_summary_raw !== 'string') {
    return errorResponse('INVALID_REQUEST', 'result_summary must be a string', 400, undefined, version);
  }

  if (trust_pulse_raw !== undefined && trust_pulse_raw !== null && !isRecord(trust_pulse_raw)) {
    return errorResponse('INVALID_REQUEST', 'trust_pulse must be an object', 400, undefined, version);
  }

  let execution_attestations: Record<string, unknown>[] | null = null;
  if (execution_attestations_raw !== undefined && execution_attestations_raw !== null) {
    if (!Array.isArray(execution_attestations_raw)) {
      return errorResponse('INVALID_REQUEST', 'execution_attestations must be an array', 400, undefined, version);
    }

    if (execution_attestations_raw.length === 0) {
      return errorResponse(
        'INVALID_REQUEST',
        'execution_attestations must be non-empty when provided',
        400,
        undefined,
        version
      );
    }

    if (execution_attestations_raw.length > MAX_EXECUTION_ATTESTATIONS_COUNT) {
      return errorResponse(
        'INVALID_REQUEST',
        `execution_attestations exceeds max count (${MAX_EXECUTION_ATTESTATIONS_COUNT})`,
        400,
        { count: execution_attestations_raw.length },
        version
      );
    }

    const out: Record<string, unknown>[] = [];
    for (let i = 0; i < execution_attestations_raw.length; i++) {
      const item = execution_attestations_raw[i];
      if (!isRecord(item)) {
        return errorResponse(
          'INVALID_REQUEST',
          `execution_attestations[${i}] must be an object`,
          400,
          undefined,
          version
        );
      }
      out.push(item);
    }

    const bytes = utf8ByteSize(JSON.stringify(out));
    if (bytes > MAX_EXECUTION_ATTESTATIONS_BYTES) {
      return errorResponse(
        'INVALID_REQUEST',
        `execution_attestations exceeds max size (${MAX_EXECUTION_ATTESTATIONS_BYTES} bytes)`,
        400,
        { bytes },
        version
      );
    }

    execution_attestations = out;
  }

  let idempotency_key: string;
  if (isNonEmptyString(idempotency_key_raw)) {
    idempotency_key = idempotency_key_raw.trim();
    if (idempotency_key.length > 200) {
      return errorResponse('INVALID_REQUEST', 'idempotency_key is too long', 400, undefined, version);
    }
  } else {
    const derived = await sha256B64uUtf8(
      stableStringify({
        schema: 'clawbounties.submit.v1',
        bounty_id: bountyId,
        worker_did,
        proof_bundle_envelope: proof_bundle_envelope_raw,
        commit_proof_envelope: commit_proof_envelope_raw ?? null,
        artifacts: artifacts_raw ?? null,
        agent_pack: agent_pack_raw ?? null,
        result_summary: result_summary_raw ?? null,
        trust_pulse: trust_pulse_raw ?? null,
        execution_attestations: execution_attestations ?? null,
      })
    );
    idempotency_key = `submit:auto:${derived}`;
  }

  try {
    const existing = await getSubmissionByIdempotencyKey(env.BOUNTIES_DB, idempotency_key, worker_did, bountyId);
    if (existing) {
      if ('conflict' in existing) {
        return errorResponse(
          'IDEMPOTENCY_CONFLICT',
          'idempotency_key already used for a different submission',
          409,
          { submission_id: existing.conflict.submission_id },
          version
        );
      }

      const existingBounty = await getBountyById(env.BOUNTIES_DB, bountyId);
      if (existingBounty) {
        const deterministicFailure = await resolveSubmissionTestLaneFailure(env.BOUNTIES_DB, existingBounty, existing.record);
        if (deterministicFailure) {
          return errorResponse(
            deterministicFailure.code,
            deterministicFailure.message,
            deterministicFailure.status,
            deterministicFailure.details,
            version
          );
        }
      }

      const response = buildSubmitResponse(existing.record);
      return jsonResponse(response, 200, version);
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('DB_READ_FAILED', message, 500, undefined, version);
  }

  let bounty: BountyV2 | null;
  try {
    bounty = await getBountyById(env.BOUNTIES_DB, bountyId);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('DB_READ_FAILED', message, 500, undefined, version);
  }

  if (!bounty) {
    return errorResponse('NOT_FOUND', 'Bounty not found', 404, undefined, version);
  }

  if (bounty.status !== 'accepted') {
    return errorResponse('INVALID_STATUS', `Cannot submit bounty in status '${bounty.status}'`, 409, undefined, version);
  }

  if (!bounty.worker_did) {
    return errorResponse('BOUNTY_NOT_ASSIGNED', 'Bounty has no assigned worker', 409, undefined, version);
  }

  if (bounty.worker_did !== worker_did) {
    return errorResponse('BOUNTY_ALREADY_ACCEPTED', 'Bounty already accepted by another worker', 409, { worker_did: bounty.worker_did }, version);
  }

  if (bounty.is_code_bounty && !commit_proof_envelope_raw) {
    return errorResponse('INVALID_REQUEST', 'commit_proof_envelope is required for code bounties', 400, undefined, version);
  }

  if (bounty.cwc_hash_b64u && !bounty.cwc_worker_envelope) {
    return errorResponse(
      'CWC_COUNTERSIGN_REQUIRED',
      'Bounty requires a Confidential Work Contract (CWC) worker countersign before submission',
      409,
      undefined,
      version
    );
  }

  const now = new Date().toISOString();

  let proofBundleResponse: VerifyBundleResponse;
  try {
    proofBundleResponse = await verifyProofBundle(env, proof_bundle_envelope_raw, urm_raw, execution_attestations ?? undefined);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('VERIFY_FAILED', message, 502, undefined, version);
  }

  const proofBundleAgentDid = extractProofBundleAgentDid(proof_bundle_envelope_raw);

  // Trust Pulse storage (self-reported, non-tier): optional `trust_pulse` field.
  const trustPulseInput = isRecord(trust_pulse_raw) ? (trust_pulse_raw as Record<string, unknown>) : null;
  let trustPulseRow: Omit<StoredTrustPulseRow, 'submission_id'> | null = null;

  if (trustPulseInput) {
    const validation = validateTrustPulseV1(trustPulseInput);
    if (!validation.ok) {
      return errorResponse(
        validation.code,
        validation.message,
        400,
        validation.field ? { field: validation.field } : undefined,
        version
      );
    }

    const bindingFromBundle = extractTrustPulseBindingFromProofBundle(proof_bundle_envelope_raw);
    if (!bindingFromBundle) {
      return errorResponse(
        'TRUST_PULSE_UNBOUND',
        'proof_bundle_envelope.payload.agent_did and payload.event_chain are required when trust_pulse is provided',
        400,
        undefined,
        version
      );
    }

    const tpRunId = isNonEmptyString(trustPulseInput.run_id) ? trustPulseInput.run_id.trim() : '';
    const tpAgentDid = isNonEmptyString(trustPulseInput.agent_did) ? trustPulseInput.agent_did.trim() : '';

    if (tpAgentDid !== worker_did) {
      return errorResponse(
        'UNAUTHORIZED',
        'trust_pulse.agent_did must match worker_did',
        401,
        { agent_did: tpAgentDid },
        version
      );
    }

    if (tpAgentDid !== bindingFromBundle.agent_did) {
      return errorResponse(
        'TRUST_PULSE_BINDING_MISMATCH',
        'trust_pulse.agent_did must match proof bundle agent_did',
        400,
        { agent_did: bindingFromBundle.agent_did },
        version
      );
    }

    if (tpRunId !== bindingFromBundle.run_id) {
      return errorResponse(
        'TRUST_PULSE_BINDING_MISMATCH',
        'trust_pulse.run_id must match proof bundle run_id',
        400,
        { run_id: bindingFromBundle.run_id },
        version
      );
    }

    const urmRecord = isRecord(urm_raw) ? (urm_raw as Record<string, unknown>) : null;
    const bindingFromUrm = extractTrustPulseBindingFromUrm(urmRecord);
    if (bindingFromUrm) {
      if (bindingFromUrm.agent_did !== tpAgentDid || bindingFromUrm.run_id !== tpRunId) {
        return errorResponse(
          'TRUST_PULSE_BINDING_MISMATCH',
          'trust_pulse must match URM (run_id + agent_did)',
          400,
          { urm_agent_did: bindingFromUrm.agent_did, urm_run_id: bindingFromUrm.run_id },
          version
        );
      }
    }

    const canonical = extractTrustPulseCanonicalJson(trustPulseInput);
    if (canonical.bytes > MAX_TRUST_PULSE_BYTES) {
      return errorResponse(
        'TRUST_PULSE_TOO_LARGE',
        `trust_pulse exceeds max size (${MAX_TRUST_PULSE_BYTES} bytes)`,
        400,
        { bytes: canonical.bytes },
        version
      );
    }

    const trustPulseHash = await sha256B64uUtf8(canonical.json);

    const expectedHash = extractExpectedTrustPulseHashFromUrm(urmRecord);
    if (expectedHash && expectedHash !== trustPulseHash) {
      return errorResponse(
        'TRUST_PULSE_HASH_MISMATCH',
        'trust_pulse hash does not match URM.metadata.trust_pulse.artifact_hash_b64u',
        400,
        { expected_hash_b64u: expectedHash, actual_hash_b64u: trustPulseHash },
        version
      );
    }

    const status: TrustPulseStorageStatus = expectedHash ? 'verified' : 'unverified';

    trustPulseRow = {
      run_id: bindingFromBundle.run_id,
      agent_did: bindingFromBundle.agent_did,
      trust_pulse_json: canonical.json,
      hash_b64u: trustPulseHash,
      status,
      created_at: now,
    };
  }

  if (proofBundleResponse.result.status === 'VALID') {
    if (!proofBundleAgentDid) {
      return errorResponse('INVALID_REQUEST', 'proof_bundle_envelope.payload.agent_did is required', 400, undefined, version);
    }

    if (proofBundleAgentDid !== worker_did) {
      return errorResponse(
        'UNAUTHORIZED',
        'proof_bundle_envelope.payload.agent_did must match worker_did',
        401,
        { agent_did: proofBundleAgentDid },
        version
      );
    }
  }

  let proofStatus: 'valid' | 'invalid' = proofBundleResponse.result.status === 'VALID' ? 'valid' : 'invalid';
  let proofReason = proofBundleResponse.result.reason.trim();
  const proofTier = deriveProofTier(proofBundleResponse.result);

  const minProofTierOk = proofTier !== null && proofTierRank(proofTier) >= proofTierRank(bounty.min_proof_tier);
  if (proofStatus === 'valid' && !minProofTierOk) {
    proofStatus = 'invalid';
    proofReason = `proof tier '${proofTier ?? 'unknown'}' does not meet min_proof_tier '${bounty.min_proof_tier}'`;
  }

  let commitProofResponse: VerifyCommitProofResponse | null = null;
  let commitStatus: 'valid' | 'invalid' | null = null;
  if (commit_proof_envelope_raw) {
    try {
      commitProofResponse = await verifyCommitProof(env, commit_proof_envelope_raw);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      return errorResponse('VERIFY_FAILED', message, 502, undefined, version);
    }

    commitStatus = commitProofResponse.result.status === 'VALID' ? 'valid' : 'invalid';
  }

  let replayRunId: string | null = null;
  let replayReceiptKeys: ReplayReceiptKey[] = [];
  let verifiedBoundReceiptCount = 0;
  let verifiedBoundPolicyHashes = new Set<string>();
  let verifiedBoundMissingPolicyHashCount = 0;
  let verifiedBoundTokenScopeHashes = new Set<string>();
  let verifiedBoundMissingTokenScopeHashCount = 0;

  const replayAgentDid = proofBundleResponse.result.status === 'VALID' ? proofBundleAgentDid : null;
  if (proofBundleResponse.result.status === 'VALID') {
    const binding = extractRunIdAndEventHashesFromProofBundle(proof_bundle_envelope_raw);

    if (binding) {
      replayRunId = binding.run_id;
      try {
        const computed = await computeReplayReceiptKeys(env, proof_bundle_envelope_raw, {
          run_id: binding.run_id,
          allowed_event_hashes_b64u: binding.event_hashes_b64u,
        });

        replayReceiptKeys = computed.keys;
        verifiedBoundReceiptCount = computed.verified_bound_receipt_count;
        verifiedBoundPolicyHashes = computed.verified_bound_policy_hashes;
        verifiedBoundMissingPolicyHashCount = computed.verified_bound_missing_policy_hash_count;
        verifiedBoundTokenScopeHashes = computed.verified_bound_token_scope_hashes;
        verifiedBoundMissingTokenScopeHashCount = computed.verified_bound_missing_token_scope_hash_count;
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Unknown error';
        return errorResponse('REPLAY_PROTECTION_FAILED', message, 502, undefined, version);
      }
    } else {
      const receipts = extractReceiptsFromProofBundle(proof_bundle_envelope_raw);
      if (receipts.length > 0) {
        return errorResponse(
          'INVALID_REQUEST',
          'proof_bundle_envelope.payload.event_chain is required when receipts are present',
          400,
          undefined,
          version
        );
      }
    }
  }

  // Enforce Confidential Work Contract (CWC) binding for otherwise-valid submissions.
  // We only evaluate this when the proof bundle verified as VALID and passes min_proof_tier.
  if (bounty.cwc_hash_b64u && proofStatus === 'valid' && proofBundleResponse.result.status === 'VALID') {
    const expectedPolicyHash = bounty.cwc_wpc_policy_hash_b64u;
    if (!expectedPolicyHash) {
      return errorResponse('CWC_INVALID_BOUNTY', 'Bounty is missing cwc_wpc_policy_hash_b64u', 500, undefined, version);
    }

    let expectedTokenScopeHash = bounty.cwc_token_scope_hash_b64u;

    // Backwards compatibility: if the token scope hash isn't stored yet, compute it deterministically
    // from the CWC job CST claims.
    if (!expectedTokenScopeHash) {
      try {
        expectedTokenScopeHash = await computeTokenScopeHashB64uV1({
          sub: worker_did,
          aud: CWC_JOB_CST_AUD,
          scope: CWC_JOB_CST_SCOPE,
          policy_hash_b64u: expectedPolicyHash,
          mission_id: bounty.bounty_id,
        });
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Unknown error';
        return errorResponse(
          'CWC_TOKEN_SCOPE_HASH_FAILED',
          `Failed to compute token_scope_hash_b64u: ${message}`,
          500,
          undefined,
          version
        );
      }

      if (!expectedTokenScopeHash || !isSha256B64u(expectedTokenScopeHash)) {
        return errorResponse(
          'CWC_TOKEN_SCOPE_HASH_FAILED',
          'Computed token_scope_hash_b64u is invalid',
          500,
          { token_scope_hash_b64u: expectedTokenScopeHash },
          version
        );
      }
    }

    if (verifiedBoundReceiptCount === 0) {
      proofStatus = 'invalid';
      proofReason = 'CWC requires at least one verified, run-bound gateway receipt';
    } else if (verifiedBoundMissingPolicyHashCount > 0) {
      proofStatus = 'invalid';
      proofReason = 'CWC requires binding.policy_hash on all verified, run-bound gateway receipts';
    } else {
      const mismatched = Array.from(verifiedBoundPolicyHashes).filter((h) => h !== expectedPolicyHash);
      if (mismatched.length > 0 || !verifiedBoundPolicyHashes.has(expectedPolicyHash)) {
        proofStatus = 'invalid';
        proofReason = `CWC policy_hash mismatch (expected ${expectedPolicyHash}, got ${Array.from(verifiedBoundPolicyHashes).join(', ') || 'none'})`;
      }
    }

    if (proofStatus === 'valid') {
      if (verifiedBoundMissingTokenScopeHashCount > 0) {
        proofStatus = 'invalid';
        proofReason = 'CWC requires binding.token_scope_hash_b64u on all verified, run-bound gateway receipts';
      } else if (verifiedBoundTokenScopeHashes.size !== 1 || !verifiedBoundTokenScopeHashes.has(expectedTokenScopeHash)) {
        proofStatus = 'invalid';
        proofReason = `CWC token_scope_hash mismatch (expected ${expectedTokenScopeHash}, got ${Array.from(verifiedBoundTokenScopeHashes).join(', ') || 'none'})`;
      }
    }
  }

  // POH-US-022: enforce job-scoped CST binding for non-CWC bounties (when configured).
  //
  // We only enforce this when:
  // - the proof bundle verified as VALID
  // - min_proof_tier passed (proofStatus still 'valid')
  // - the bounty requires gateway-tier proofs (min_proof_tier !== 'self')
  // - the bounty has a stored job_token_scope_hash_b64u (new regime)
  if (
    bounty.job_token_scope_hash_b64u &&
    !bounty.cwc_hash_b64u &&
    bounty.min_proof_tier !== 'self' &&
    proofStatus === 'valid' &&
    proofBundleResponse.result.status === 'VALID'
  ) {
    const expectedTokenScopeHash = bounty.job_token_scope_hash_b64u;

    if (verifiedBoundReceiptCount === 0) {
      proofStatus = 'invalid';
      proofReason = 'Job binding requires at least one verified, run-bound gateway receipt';
    } else if (verifiedBoundMissingTokenScopeHashCount > 0) {
      proofStatus = 'invalid';
      proofReason = 'Job binding requires binding.token_scope_hash_b64u on all verified, run-bound gateway receipts';
    } else if (verifiedBoundTokenScopeHashes.size !== 1 || !verifiedBoundTokenScopeHashes.has(expectedTokenScopeHash)) {
      proofStatus = 'invalid';
      proofReason = `Job token_scope_hash mismatch (expected ${expectedTokenScopeHash}, got ${Array.from(verifiedBoundTokenScopeHashes).join(', ') || 'none'})`;
    }
  }

  const isValid = proofStatus === 'valid' && (commitStatus ?? 'valid') === 'valid';
  const submissionStatus: SubmissionStatus = isValid ? 'pending_review' : 'invalid';

  const proof_bundle_hash_b64u = isRecord(proof_bundle_envelope_raw) ? d1String(proof_bundle_envelope_raw.payload_hash_b64u) : null;
  const commit_proof_hash_b64u = isRecord(commit_proof_envelope_raw) ? d1String(commit_proof_envelope_raw.payload_hash_b64u) : null;

  let commit_sha: string | null = null;
  let repo_url: string | null = null;
  let repo_claim_id: string | null = null;

  if (isRecord(commit_proof_envelope_raw) && isRecord(commit_proof_envelope_raw.payload)) {
    const payload = commit_proof_envelope_raw.payload as Record<string, unknown>;
    commit_sha = isNonEmptyString(payload.commit_sha) ? payload.commit_sha.trim() : null;
    repo_url = isNonEmptyString(payload.repo_url) ? payload.repo_url.trim() : isNonEmptyString(payload.repository) ? payload.repository.trim() : null;
    repo_claim_id = isNonEmptyString(payload.repo_claim_id) ? payload.repo_claim_id.trim() : null;
  }

  if (commitProofResponse) {
    if (isNonEmptyString(commitProofResponse.commit_sha)) commit_sha = commitProofResponse.commit_sha.trim();
    if (isNonEmptyString(commitProofResponse.repository)) repo_url = commitProofResponse.repository.trim();
    if (isNonEmptyString(commitProofResponse.repo_claim_id)) repo_claim_id = commitProofResponse.repo_claim_id.trim();
  }

  const submission_id = `sub_${crypto.randomUUID()}`;

  const storedTrustPulse: StoredTrustPulseRow | null = trustPulseRow
    ? { submission_id, ...trustPulseRow }
    : null;

  const record: SubmissionRecord = {
    submission_id,
    bounty_id: bounty.bounty_id,
    worker_did,
    status: submissionStatus,
    idempotency_key,
    proof_bundle_envelope: proof_bundle_envelope_raw,
    proof_bundle_hash_b64u: proof_bundle_hash_b64u ? proof_bundle_hash_b64u.trim() : null,
    proof_verify_status: proofStatus,
    proof_verify_reason: proofReason,
    proof_verified_at: proofBundleResponse.result.verified_at.trim(),
    proof_tier: proofTier,
    execution_attestations,
    commit_proof_envelope: isRecord(commit_proof_envelope_raw) ? commit_proof_envelope_raw : null,
    commit_proof_hash_b64u: commit_proof_hash_b64u ? commit_proof_hash_b64u.trim() : null,
    commit_sha,
    repo_url,
    repo_claim_id,
    commit_proof_verify_status: commitStatus,
    commit_proof_verify_reason: commitProofResponse ? commitProofResponse.result.reason.trim() : null,
    commit_proof_verified_at: commitProofResponse ? commitProofResponse.result.verified_at.trim() : null,
    artifacts: Array.isArray(artifacts_raw) ? artifacts_raw : null,
    agent_pack: isRecord(agent_pack_raw) ? agent_pack_raw : null,
    result_summary: isNonEmptyString(result_summary_raw) ? result_summary_raw.trim() : null,
    created_at: now,
    updated_at: now,
  };

  try {
    if (proofBundleResponse.result.status === 'VALID') {
      await insertSubmissionWithReplayGuards(env.BOUNTIES_DB, {
        record,
        agent_did: replayAgentDid,
        run_id: replayRunId,
        receipt_keys: replayReceiptKeys,
        trust_pulse: storedTrustPulse,
      });
    } else {
      if (storedTrustPulse) {
        await env.BOUNTIES_DB.batch([
          prepareInsertSubmission(env.BOUNTIES_DB, record),
          prepareInsertSubmissionTrustPulse(env.BOUNTIES_DB, storedTrustPulse),
        ]);
      } else {
        await insertSubmission(env.BOUNTIES_DB, record);
      }
    }
  } catch (err) {
    try {
      const existing = await getSubmissionByIdempotencyKey(env.BOUNTIES_DB, idempotency_key, worker_did, bounty.bounty_id);
      if (existing) {
        if ('conflict' in existing) {
          return errorResponse(
            'IDEMPOTENCY_CONFLICT',
            'idempotency_key already used for a different submission',
            409,
            { submission_id: existing.conflict.submission_id },
            version
          );
        }
        const deterministicFailure = await resolveSubmissionTestLaneFailure(env.BOUNTIES_DB, bounty, existing.record);
        if (deterministicFailure) {
          return errorResponse(
            deterministicFailure.code,
            deterministicFailure.message,
            deterministicFailure.status,
            deterministicFailure.details,
            version
          );
        }

        const response = buildSubmitResponse(existing.record);
        return jsonResponse(response, 200, version);
      }
    } catch (lookupErr) {
      const message = lookupErr instanceof Error ? lookupErr.message : 'Unknown error';
      return errorResponse('DB_READ_FAILED', message, 500, undefined, version);
    }

    if (proofBundleResponse.result.status === 'VALID') {
      try {
        if (replayAgentDid && replayRunId) {
          const seen = await getReplayRun(env.BOUNTIES_DB, {
            agent_did: replayAgentDid,
            run_id: replayRunId,
          });
          if (seen) {
            return errorResponse(
              'REPLAY_RUN_ID_REUSED',
              'run_id already used in a prior submission',
              409,
              { run_id: replayRunId, first_seen: seen },
              version
            );
          }
        }

        if (replayReceiptKeys.length > 0) {
          for (const k of replayReceiptKeys) {
            const seen = await getReplayReceipt(env.BOUNTIES_DB, {
              receipt_signer_did: k.receipt_signer_did,
              receipt_id: k.receipt_id,
            });
            if (seen) {
              return errorResponse(
                'REPLAY_RECEIPT_ID_REUSED',
                'receipt_id already used in a prior submission',
                409,
                {
                  receipt_signer_did: k.receipt_signer_did,
                  receipt_id: k.receipt_id,
                  first_seen: seen,
                },
                version
              );
            }
          }
        }
      } catch (lookupErr) {
        const message = lookupErr instanceof Error ? lookupErr.message : 'Unknown error';
        return errorResponse('DB_READ_FAILED', message, 500, undefined, version);
      }
    }

    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('DB_WRITE_FAILED', message, 500, undefined, version);
  }

  if (isValid) {
    try {
      await updateBountyStatus(env.BOUNTIES_DB, bounty.bounty_id, 'pending_review', now, 'accepted');
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      console.error(
        `Failed to update bounty status to 'pending_review' for bounty ${bounty.bounty_id} after submission ${submission_id}: ${message}`
      );
    }

    try {
      await triggerLiveArenaFromSubmission(env.BOUNTIES_DB, bounty, record, now);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      console.error(
        `Failed to trigger live arena for bounty ${bounty.bounty_id} submission ${submission_id}: ${message}`,
      );

      try {
        const failedArenaId = `arena_${bounty.bounty_id}_live_${submission_id}`.slice(0, 120);
        await updateBountyArenaLifecycle(env.BOUNTIES_DB, {
          bounty_id: bounty.bounty_id,
          arena_status: 'failed',
          arena_id: failedArenaId,
          arena_task_fingerprint: deriveLiveArenaTaskFingerprint(bounty),
          arena_winner_contender_id: null,
          arena_evidence_links: [],
          arena_updated_at: new Date().toISOString(),
        });
      } catch (syncErr) {
        const syncMessage = syncErr instanceof Error ? syncErr.message : 'Unknown error';
        console.error(
          `Failed to persist arena failure lifecycle for bounty ${bounty.bounty_id} submission ${submission_id}: ${syncMessage}`,
        );
      }
    }
  }

  let autoDecision: TestAutoDecisionResult | null = null;
  if (isValid && bounty.closure_type === 'test') {
    try {
      autoDecision = await autoApproveTestSubmission(env, bounty, record);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      autoDecision = {
        applied: false,
        failure: {
          code: 'TEST_HARNESS_FAILED',
          message,
          status: 502,
          details: {
            submission_id,
            bounty_id: bounty.bounty_id,
          },
        },
      };
    }
  }

  if (autoDecision?.failure) {
    const details: Record<string, unknown> = {
      submission_id,
      bounty_id: bounty.bounty_id,
      ...(autoDecision.failure.details ?? {}),
    };

    return errorResponse(
      autoDecision.failure.code,
      autoDecision.failure.message,
      autoDecision.failure.status,
      details,
      version
    );
  }

  const decisionApplied = autoDecision?.applied ?? false;

  let responseRecord = record;
  if (decisionApplied) {
    try {
      const refreshed = await getSubmissionById(env.BOUNTIES_DB, submission_id);
      if (refreshed) responseRecord = refreshed;
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      console.error(`Failed to refresh submission ${submission_id} after auto-approval: ${message}`);
    }
  }

  const response = buildSubmitResponse(responseRecord);
  return jsonResponse(response, isValid ? 201 : 422, version);
}

async function handleApproveBounty(
  bountyId: string,
  request: Request,
  env: Env,
  version: string,
  options?: RequesterAuthOverrideOptions,
): Promise<Response> {
  const bodyRaw = await parseJsonBody(request);
  if (!isRecord(bodyRaw)) {
    return errorResponse('INVALID_REQUEST', 'Invalid JSON body', 400, undefined, version);
  }

  const requester_did_raw = bodyRaw.requester_did;
  const submission_id_raw = bodyRaw.submission_id;
  const idempotency_key_raw = bodyRaw.idempotency_key;

  const requesterDidHint = isNonEmptyString(requester_did_raw) ? requester_did_raw.trim() : null;
  if (requesterDidHint && !requesterDidHint.startsWith('did:')) {
    return errorResponse('INVALID_REQUEST', 'requester_did must be a DID string', 400, undefined, version);
  }

  let requesterAuth: RequesterAuthContext;
  let controlPlaneCheck: Record<string, unknown> | null;

  if (options?.authOverride) {
    requesterAuth = options.authOverride;
    if (requesterDidHint && requesterDidHint !== requesterAuth.requester_did) {
      return errorResponse(
        'REQUESTER_SUB_MISMATCH',
        'requester_did does not match auth override requester DID',
        401,
        {
          requester_did: requesterAuth.requester_did,
          requested_requester_did: requesterDidHint,
        },
        version,
      );
    }

    controlPlaneCheck = options.controlPlaneCheckOverride ?? {
      source: 'arena_desk_auth_override',
      checked_at: new Date().toISOString(),
    };
  } else {
    if (!requesterDidHint) {
      return errorResponse('INVALID_REQUEST', 'requester_did is required', 400, undefined, version);
    }

    const requesterAuthResult = await requireRequesterAuth(request, env, version, {
      action: 'approve_bounty',
      requester_did_hint: requesterDidHint,
    });
    if ('error' in requesterAuthResult) return requesterAuthResult.error;

    requesterAuth = requesterAuthResult.auth;

    const transitionAuthCheck = await validateRequesterSensitiveTransition(env, version, {
      auth: requesterAuth,
      transition: 'approve_bounty',
    });
    if ('error' in transitionAuthCheck) return transitionAuthCheck.error;

    controlPlaneCheck = transitionAuthCheck.evidence;
  }

  if (!isNonEmptyString(submission_id_raw)) {
    return errorResponse('INVALID_REQUEST', 'submission_id is required', 400, undefined, version);
  }

  if (!isNonEmptyString(idempotency_key_raw)) {
    return errorResponse('INVALID_REQUEST', 'idempotency_key is required', 400, undefined, version);
  }

  const submission_id = submission_id_raw.trim();
  const idempotency_key = idempotency_key_raw.trim();

  if (idempotency_key.length > 200) {
    return errorResponse('INVALID_REQUEST', 'idempotency_key is too long', 400, undefined, version);
  }

  let bounty: BountyV2 | null;
  try {
    bounty = await getBountyById(env.BOUNTIES_DB, bountyId);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('DB_READ_FAILED', message, 500, undefined, version);
  }

  if (!bounty) {
    return errorResponse('NOT_FOUND', 'Bounty not found', 404, undefined, version);
  }

  if (bounty.closure_type !== 'requester') {
    return errorResponse('INVALID_STATUS', 'Bounty closure_type must be requester', 409, undefined, version);
  }

  if (bounty.requester_did !== requesterAuth.requester_did) {
    return errorResponse('UNAUTHORIZED', 'requester_did does not match bounty requester', 401, undefined, version);
  }

  if (!bounty.worker_did) {
    return errorResponse('BOUNTY_NOT_ASSIGNED', 'Bounty has no assigned worker', 409, undefined, version);
  }

  try {
    await insertRequesterAuthEvent(env.BOUNTIES_DB, {
      action: 'approve_bounty',
      bounty_id: bounty.bounty_id,
      submission_id,
      auth: requesterAuth,
      created_at: new Date().toISOString(),
      sensitive_transition: true,
      control_plane_check: controlPlaneCheck,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('DB_WRITE_FAILED', message, 500, undefined, version);
  }

  const alreadyApproved = bounty.status === 'approved';
  if (alreadyApproved) {
    if (bounty.approve_idempotency_key && bounty.approve_idempotency_key !== idempotency_key) {
      return errorResponse(
        'IDEMPOTENCY_CONFLICT',
        'idempotency_key already used for a different approval',
        409,
        { approve_idempotency_key: bounty.approve_idempotency_key },
        version
      );
    }

    if (bounty.approved_submission_id && bounty.approved_submission_id !== submission_id) {
      return errorResponse(
        'IDEMPOTENCY_CONFLICT',
        'submission_id does not match approved submission',
        409,
        { submission_id: bounty.approved_submission_id },
        version
      );
    }

    let escrowResponse: EscrowReleaseResponse;
    try {
      escrowResponse = await escrowGetReleased(env, bounty.escrow_id);
    } catch (err) {
      const parsed = parseEscrowFailedError(err);
      if (parsed) {
        const code = isNonEmptyString(parsed.payload.error) ? parsed.payload.error.trim() : 'ESCROW_FAILED';
        const message = isNonEmptyString(parsed.payload.message) ? parsed.payload.message.trim() : 'Escrow failed';
        return errorResponse(code, message, parsed.status, undefined, version);
      }

      const message = err instanceof Error ? err.message : 'Unknown error';
      return errorResponse('ESCROW_FAILED', message, 502, undefined, version);
    }

    const now = new Date().toISOString();
    const resolvedSubmissionId = bounty.approved_submission_id ?? submission_id;

    try {
      await updateSubmissionStatus(env.BOUNTIES_DB, resolvedSubmissionId, 'approved', now, 'pending_review');
    } catch (err) {
      try {
        const existing = await getSubmissionById(env.BOUNTIES_DB, resolvedSubmissionId);
        if (!existing || existing.status !== 'approved') {
          throw err;
        }
      } catch (lookupErr) {
        const message = lookupErr instanceof Error ? lookupErr.message : 'Unknown error';
        return errorResponse('DB_WRITE_FAILED', message, 500, undefined, version);
      }
    }

    const response: ApproveBountyResponseV1 = {
      bounty_id: bounty.bounty_id,
      submission_id: resolvedSubmissionId,
      status: 'approved',
      escrow: escrowResponse,
      decided_at: bounty.approved_at ?? bounty.updated_at,
    };

    const sourceId = `clawbounties:approve:${bounty.bounty_id}:${resolvedSubmissionId}:${
      bounty.approve_idempotency_key ?? idempotency_key
    }`;
    await emitClawrepLoopEvent(env, {
      schema_version: '1',
      source_event_id: sourceId,
      source_service: 'clawbounties',
      kind: 'closure',
      did: bounty.worker_did,
      occurred_at: response.decided_at,
      closure: {
        value_usd: minorToUsd(bounty.reward.amount_minor),
        closure_type: 'manual_approve',
        proof_tier: 'unknown',
        owner_verified: false,
      },
      metadata: {
        bounty_id: bounty.bounty_id,
        submission_id: resolvedSubmissionId,
        closure_path: 'requester_already_approved',
      },
    });

    return jsonResponse(response, 200, version);
  }

  if (bounty.status !== 'pending_review') {
    return errorResponse('INVALID_STATUS', `Cannot approve bounty in status '${bounty.status}'`, 409, undefined, version);
  }

  let submission: SubmissionRecord | null;
  try {
    submission = await getSubmissionById(env.BOUNTIES_DB, submission_id);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('DB_READ_FAILED', message, 500, undefined, version);
  }

  if (!submission) {
    return errorResponse('NOT_FOUND', 'Submission not found', 404, { submission_id }, version);
  }

  if (submission.bounty_id !== bounty.bounty_id) {
    return errorResponse('INVALID_REQUEST', 'submission_id does not belong to bounty', 400, undefined, version);
  }

  if (submission.worker_did !== bounty.worker_did) {
    return errorResponse('INVALID_REQUEST', 'submission worker does not match bounty worker', 400, undefined, version);
  }

  if (submission.status !== 'pending_review') {
    return errorResponse('INVALID_STATUS', `Submission status is '${submission.status}'`, 409, undefined, version);
  }

  if (submission.proof_verify_status !== 'valid') {
    return errorResponse('SUBMISSION_INVALID', 'Submission proof bundle is invalid', 422, undefined, version);
  }

  if (submission.commit_proof_verify_status === 'invalid') {
    return errorResponse('SUBMISSION_INVALID', 'Submission commit proof is invalid', 422, undefined, version);
  }

  if (bounty.is_code_bounty && submission.commit_proof_verify_status !== 'valid') {
    return errorResponse('SUBMISSION_INVALID', 'Submission commit proof is required for code bounties', 422, undefined, version);
  }

  const verification: Record<string, unknown> = {
    submission_id: submission.submission_id,
    proof_bundle_hash_b64u: submission.proof_bundle_hash_b64u ?? undefined,
    proof_tier: submission.proof_tier ?? undefined,
    commit_sha: submission.commit_sha ?? undefined,
    repo_url: submission.repo_url ?? undefined,
    repo_claim_id: submission.repo_claim_id ?? undefined,
  };

  let escrowResponse: EscrowReleaseResponse;
  try {
    escrowResponse = await escrowRelease(env, {
      escrow_id: bounty.escrow_id,
      idempotency_key,
      approved_by: requesterAuth.requester_did,
      verification,
    });
  } catch (err) {
    const parsed = parseEscrowFailedError(err);
    if (parsed) {
      const code = isNonEmptyString(parsed.payload.error) ? parsed.payload.error.trim() : 'ESCROW_FAILED';
      const message = isNonEmptyString(parsed.payload.message) ? parsed.payload.message.trim() : 'Escrow failed';
      return errorResponse(code, message, parsed.status, undefined, version);
    }

    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('ESCROW_FAILED', message, 502, undefined, version);
  }

  const now = new Date().toISOString();
  let decidedAt = now;

  try {
    await updateBountyApproved(env.BOUNTIES_DB, {
      bounty_id: bounty.bounty_id,
      submission_id: submission.submission_id,
      idempotency_key,
      approved_at: now,
      now,
    });
  } catch (err) {
    try {
      const updated = await getBountyById(env.BOUNTIES_DB, bounty.bounty_id);
      if (!updated || updated.status !== 'approved') {
        throw err;
      }

      if (updated.approve_idempotency_key && updated.approve_idempotency_key !== idempotency_key) {
        return errorResponse(
          'IDEMPOTENCY_CONFLICT',
          'idempotency_key already used for a different approval',
          409,
          { approve_idempotency_key: updated.approve_idempotency_key },
          version
        );
      }

      if (updated.approved_submission_id && updated.approved_submission_id !== submission.submission_id) {
        return errorResponse(
          'IDEMPOTENCY_CONFLICT',
          'submission_id does not match approved submission',
          409,
          { submission_id: updated.approved_submission_id },
          version
        );
      }

      decidedAt = updated.approved_at ?? updated.updated_at;
    } catch (lookupErr) {
      const message = lookupErr instanceof Error ? lookupErr.message : 'Unknown error';
      return errorResponse('DB_WRITE_FAILED', message, 500, undefined, version);
    }
  }

  try {
    await updateSubmissionStatus(env.BOUNTIES_DB, submission.submission_id, 'approved', now, 'pending_review');
  } catch (err) {
    try {
      const existing = await getSubmissionById(env.BOUNTIES_DB, submission.submission_id);
      if (!existing || existing.status !== 'approved') {
        throw err;
      }
    } catch (lookupErr) {
      const message = lookupErr instanceof Error ? lookupErr.message : 'Unknown error';
      return errorResponse('DB_WRITE_FAILED', message, 500, undefined, version);
    }
  }

  const response: ApproveBountyResponseV1 = {
    bounty_id: bounty.bounty_id,
    submission_id: submission.submission_id,
    status: 'approved',
    escrow: escrowResponse,
    decided_at: decidedAt,
  };

  await emitClawrepLoopEvent(env, {
    schema_version: '1',
    source_event_id: `clawbounties:approve:${bounty.bounty_id}:${submission.submission_id}:${idempotency_key}`,
    source_service: 'clawbounties',
    kind: 'closure',
    did: submission.worker_did,
    occurred_at: decidedAt,
    closure: {
      value_usd: minorToUsd(bounty.reward.amount_minor),
      closure_type: 'manual_approve',
      proof_tier: toRepProofTier(submission.proof_tier),
      owner_verified: false,
    },
    metadata: {
      bounty_id: bounty.bounty_id,
      submission_id: submission.submission_id,
      closure_type: bounty.closure_type,
      requester_did: requesterAuth.requester_did,
    },
  });

  return jsonResponse(response, 200, version);
}

async function handleRejectBounty(
  bountyId: string,
  request: Request,
  env: Env,
  version: string,
  options?: RequesterAuthOverrideOptions,
): Promise<Response> {
  const bodyRaw = await parseJsonBody(request);
  if (!isRecord(bodyRaw)) {
    return errorResponse('INVALID_REQUEST', 'Invalid JSON body', 400, undefined, version);
  }

  const requester_did_raw = bodyRaw.requester_did;
  const submission_id_raw = bodyRaw.submission_id;
  const idempotency_key_raw = bodyRaw.idempotency_key;
  const reason_raw = bodyRaw.reason;

  const requesterDidHint = isNonEmptyString(requester_did_raw) ? requester_did_raw.trim() : null;
  if (requesterDidHint && !requesterDidHint.startsWith('did:')) {
    return errorResponse('INVALID_REQUEST', 'requester_did must be a DID string', 400, undefined, version);
  }

  let requesterAuth: RequesterAuthContext;
  let controlPlaneCheck: Record<string, unknown> | null;

  if (options?.authOverride) {
    requesterAuth = options.authOverride;
    if (requesterDidHint && requesterDidHint !== requesterAuth.requester_did) {
      return errorResponse(
        'REQUESTER_SUB_MISMATCH',
        'requester_did does not match auth override requester DID',
        401,
        {
          requester_did: requesterAuth.requester_did,
          requested_requester_did: requesterDidHint,
        },
        version,
      );
    }

    controlPlaneCheck = options.controlPlaneCheckOverride ?? {
      source: 'arena_desk_auth_override',
      checked_at: new Date().toISOString(),
    };
  } else {
    if (!requesterDidHint) {
      return errorResponse('INVALID_REQUEST', 'requester_did is required', 400, undefined, version);
    }

    const requesterAuthResult = await requireRequesterAuth(request, env, version, {
      action: 'reject_bounty',
      requester_did_hint: requesterDidHint,
    });
    if ('error' in requesterAuthResult) return requesterAuthResult.error;

    requesterAuth = requesterAuthResult.auth;

    const transitionAuthCheck = await validateRequesterSensitiveTransition(env, version, {
      auth: requesterAuth,
      transition: 'reject_bounty',
    });
    if ('error' in transitionAuthCheck) return transitionAuthCheck.error;

    controlPlaneCheck = transitionAuthCheck.evidence;
  }

  if (!isNonEmptyString(submission_id_raw)) {
    return errorResponse('INVALID_REQUEST', 'submission_id is required', 400, undefined, version);
  }

  if (!isNonEmptyString(idempotency_key_raw)) {
    return errorResponse('INVALID_REQUEST', 'idempotency_key is required', 400, undefined, version);
  }

  if (reason_raw !== undefined && reason_raw !== null && typeof reason_raw !== 'string') {
    return errorResponse('INVALID_REQUEST', 'reason must be a string', 400, undefined, version);
  }

  const submission_id = submission_id_raw.trim();
  const idempotency_key = idempotency_key_raw.trim();
  const reason = isNonEmptyString(reason_raw) ? reason_raw.trim() : null;

  if (idempotency_key.length > 200) {
    return errorResponse('INVALID_REQUEST', 'idempotency_key is too long', 400, undefined, version);
  }

  let bounty: BountyV2 | null;
  try {
    bounty = await getBountyById(env.BOUNTIES_DB, bountyId);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('DB_READ_FAILED', message, 500, undefined, version);
  }

  if (!bounty) {
    return errorResponse('NOT_FOUND', 'Bounty not found', 404, undefined, version);
  }

  if (bounty.closure_type !== 'requester') {
    return errorResponse('INVALID_STATUS', 'Bounty closure_type must be requester', 409, undefined, version);
  }

  if (bounty.requester_did !== requesterAuth.requester_did) {
    return errorResponse('UNAUTHORIZED', 'requester_did does not match bounty requester', 401, undefined, version);
  }

  if (!bounty.worker_did) {
    return errorResponse('BOUNTY_NOT_ASSIGNED', 'Bounty has no assigned worker', 409, undefined, version);
  }

  try {
    await insertRequesterAuthEvent(env.BOUNTIES_DB, {
      action: 'reject_bounty',
      bounty_id: bounty.bounty_id,
      submission_id,
      auth: requesterAuth,
      created_at: new Date().toISOString(),
      sensitive_transition: true,
      control_plane_check: controlPlaneCheck,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('DB_WRITE_FAILED', message, 500, undefined, version);
  }

  const alreadyDisputed = bounty.status === 'disputed';
  if (alreadyDisputed) {
    if (bounty.reject_idempotency_key && bounty.reject_idempotency_key !== idempotency_key) {
      return errorResponse(
        'IDEMPOTENCY_CONFLICT',
        'idempotency_key already used for a different rejection',
        409,
        { reject_idempotency_key: bounty.reject_idempotency_key },
        version
      );
    }

    if (bounty.rejected_submission_id && bounty.rejected_submission_id !== submission_id) {
      return errorResponse(
        'IDEMPOTENCY_CONFLICT',
        'submission_id does not match rejected submission',
        409,
        { submission_id: bounty.rejected_submission_id },
        version
      );
    }

    let escrowResponse: EscrowDisputeResponse;
    try {
      escrowResponse = await escrowGetDisputed(env, bounty.escrow_id);
    } catch (err) {
      const parsed = parseEscrowFailedError(err);
      if (parsed) {
        const code = isNonEmptyString(parsed.payload.error) ? parsed.payload.error.trim() : 'ESCROW_FAILED';
        const message = isNonEmptyString(parsed.payload.message) ? parsed.payload.message.trim() : 'Escrow failed';
        return errorResponse(code, message, parsed.status, undefined, version);
      }

      const message = err instanceof Error ? err.message : 'Unknown error';
      return errorResponse('ESCROW_FAILED', message, 502, undefined, version);
    }

    const now = new Date().toISOString();
    const resolvedSubmissionId = bounty.rejected_submission_id ?? submission_id;

    let resolvedSubmission: SubmissionRecord | null;
    try {
      resolvedSubmission = await getSubmissionById(env.BOUNTIES_DB, resolvedSubmissionId);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      return errorResponse('DB_READ_FAILED', message, 500, undefined, version);
    }

    if (!resolvedSubmission) {
      return errorResponse('NOT_FOUND', 'Submission not found', 404, { submission_id: resolvedSubmissionId }, version);
    }

    if (resolvedSubmission.bounty_id !== bounty.bounty_id) {
      return errorResponse('INVALID_REQUEST', 'submission_id does not belong to bounty', 400, undefined, version);
    }

    if (resolvedSubmission.worker_did !== bounty.worker_did) {
      return errorResponse('INVALID_REQUEST', 'submission worker does not match bounty worker', 400, undefined, version);
    }

    let trialCase: TrialCaseSummary;
    try {
      trialCase = await trialsCreateCase(env, {
        idempotency_key: `trial:reject:${bounty.bounty_id}:${idempotency_key}`,
        source_system: 'clawbounties',
        source_ref: bounty.bounty_id,
        submission_id: resolvedSubmission.submission_id,
        escrow_id: bounty.escrow_id,
        requester_did: requesterAuth.requester_did,
        worker_did: bounty.worker_did,
        opened_by: requesterAuth.requester_did,
        reason,
        evidence: buildSubmissionTrialEvidence(resolvedSubmission),
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      return errorResponse('TRIALS_FAILED', message, 502, undefined, version);
    }

    try {
      await updateBountyTrialCase(env.BOUNTIES_DB, {
        bounty_id: bounty.bounty_id,
        trial_case_id: trialCase.case_id,
        trial_opened_at: trialCase.opened_at,
        now,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      return errorResponse('DB_WRITE_FAILED', message, 500, undefined, version);
    }

    try {
      await updateSubmissionStatus(env.BOUNTIES_DB, resolvedSubmissionId, 'rejected', now, 'pending_review');
    } catch (err) {
      try {
        const existing = await getSubmissionById(env.BOUNTIES_DB, resolvedSubmissionId);
        if (!existing || existing.status !== 'rejected') {
          throw err;
        }
      } catch (lookupErr) {
        const message = lookupErr instanceof Error ? lookupErr.message : 'Unknown error';
        return errorResponse('DB_WRITE_FAILED', message, 500, undefined, version);
      }
    }

    const response: RejectBountyResponseV1 = {
      bounty_id: bounty.bounty_id,
      submission_id: resolvedSubmissionId,
      status: 'disputed',
      escrow: escrowResponse,
      trial_case: trialCase,
      decided_at: bounty.rejected_at ?? bounty.updated_at,
    };

    const sourceId = `clawbounties:reject:${bounty.bounty_id}:${resolvedSubmissionId}:${
      bounty.reject_idempotency_key ?? idempotency_key
    }`;
    await emitClawrepLoopEvent(env, {
      schema_version: '1',
      source_event_id: sourceId,
      source_service: 'clawbounties',
      kind: 'penalty',
      did: bounty.worker_did,
      occurred_at: response.decided_at,
      penalty: {
        penalty_type: 'dispute_upheld_against_worker',
        severity: 2,
        reason: reason ?? 'Requester disputed submission',
      },
      metadata: {
        bounty_id: bounty.bounty_id,
        submission_id: resolvedSubmissionId,
        dispute_path: 'requester_already_disputed',
      },
    });

    return jsonResponse(response, 200, version);
  }

  if (bounty.status !== 'pending_review') {
    return errorResponse('INVALID_STATUS', `Cannot reject bounty in status '${bounty.status}'`, 409, undefined, version);
  }

  let submission: SubmissionRecord | null;
  try {
    submission = await getSubmissionById(env.BOUNTIES_DB, submission_id);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('DB_READ_FAILED', message, 500, undefined, version);
  }

  if (!submission) {
    return errorResponse('NOT_FOUND', 'Submission not found', 404, { submission_id }, version);
  }

  if (submission.bounty_id !== bounty.bounty_id) {
    return errorResponse('INVALID_REQUEST', 'submission_id does not belong to bounty', 400, undefined, version);
  }

  if (submission.worker_did !== bounty.worker_did) {
    return errorResponse('INVALID_REQUEST', 'submission worker does not match bounty worker', 400, undefined, version);
  }

  if (submission.status !== 'pending_review') {
    return errorResponse('INVALID_STATUS', `Submission status is '${submission.status}'`, 409, undefined, version);
  }

  // Rejection is allowed even if proofs are invalid; the requester can dispute any submission.

  const now = new Date().toISOString();

  let escrowResponse: EscrowDisputeResponse;
  try {
    escrowResponse = await escrowDispute(env, {
      escrow_id: bounty.escrow_id,
      idempotency_key,
      disputed_by: requesterAuth.requester_did,
      reason,
    });
  } catch (err) {
    const parsed = parseEscrowFailedError(err);
    if (parsed) {
      const code = isNonEmptyString(parsed.payload.error) ? parsed.payload.error.trim() : 'ESCROW_FAILED';
      const message = isNonEmptyString(parsed.payload.message) ? parsed.payload.message.trim() : 'Escrow failed';
      return errorResponse(code, message, parsed.status, undefined, version);
    }

    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('ESCROW_FAILED', message, 502, undefined, version);
  }

  let trialCase: TrialCaseSummary;
  try {
    trialCase = await trialsCreateCase(env, {
      idempotency_key: `trial:reject:${bounty.bounty_id}:${idempotency_key}`,
      source_system: 'clawbounties',
      source_ref: bounty.bounty_id,
      submission_id: submission.submission_id,
      escrow_id: bounty.escrow_id,
      requester_did: requesterAuth.requester_did,
      worker_did: bounty.worker_did,
      opened_by: requesterAuth.requester_did,
      reason,
      evidence: buildSubmissionTrialEvidence(submission),
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('TRIALS_FAILED', message, 502, undefined, version);
  }

  let decidedAt = now;

  try {
    await updateBountyRejected(env.BOUNTIES_DB, {
      bounty_id: bounty.bounty_id,
      submission_id: submission.submission_id,
      idempotency_key,
      rejected_at: now,
      now,
      trial_case_id: trialCase.case_id,
      trial_opened_at: trialCase.opened_at,
    });
  } catch (err) {
    try {
      const updated = await getBountyById(env.BOUNTIES_DB, bounty.bounty_id);
      if (!updated || updated.status !== 'disputed') {
        throw err;
      }

      if (updated.reject_idempotency_key && updated.reject_idempotency_key !== idempotency_key) {
        return errorResponse(
          'IDEMPOTENCY_CONFLICT',
          'idempotency_key already used for a different rejection',
          409,
          { reject_idempotency_key: updated.reject_idempotency_key },
          version
        );
      }

      if (updated.rejected_submission_id && updated.rejected_submission_id !== submission.submission_id) {
        return errorResponse(
          'IDEMPOTENCY_CONFLICT',
          'submission_id does not match rejected submission',
          409,
          { submission_id: updated.rejected_submission_id },
          version
        );
      }

      decidedAt = updated.rejected_at ?? updated.updated_at;
    } catch (lookupErr) {
      const message = lookupErr instanceof Error ? lookupErr.message : 'Unknown error';
      return errorResponse('DB_WRITE_FAILED', message, 500, undefined, version);
    }
  }

  try {
    await updateSubmissionStatus(env.BOUNTIES_DB, submission.submission_id, 'rejected', now, 'pending_review');
  } catch (err) {
    try {
      const existing = await getSubmissionById(env.BOUNTIES_DB, submission.submission_id);
      if (!existing || existing.status !== 'rejected') {
        throw err;
      }
    } catch (lookupErr) {
      const message = lookupErr instanceof Error ? lookupErr.message : 'Unknown error';
      return errorResponse('DB_WRITE_FAILED', message, 500, undefined, version);
    }
  }

  const response: RejectBountyResponseV1 = {
    bounty_id: bounty.bounty_id,
    submission_id: submission.submission_id,
    status: 'disputed',
    escrow: escrowResponse,
    trial_case: trialCase,
    decided_at: decidedAt,
  };

  await emitClawrepLoopEvent(env, {
    schema_version: '1',
    source_event_id: `clawbounties:reject:${bounty.bounty_id}:${submission.submission_id}:${idempotency_key}`,
    source_service: 'clawbounties',
    kind: 'penalty',
    did: submission.worker_did,
    occurred_at: decidedAt,
    penalty: {
      penalty_type: 'dispute_upheld_against_worker',
      severity: 2,
      reason: reason ?? 'Requester disputed submission',
    },
    metadata: {
      bounty_id: bounty.bounty_id,
      submission_id: submission.submission_id,
      closure_type: bounty.closure_type,
      requester_did: requesterAuth.requester_did,
    },
  });

  return jsonResponse(response, 200, version);
}

async function handlePostBounty(
  request: Request,
  env: Env,
  version: string,
  options?: RequesterAuthOverrideOptions,
): Promise<Response> {
  const bodyRaw = await parseJsonBody(request);
  if (!isRecord(bodyRaw)) {
    return errorResponse('INVALID_REQUEST', 'Invalid JSON body', 400, undefined, version);
  }

  const requester_did_hint_raw = bodyRaw.requester_did;
  if (
    requester_did_hint_raw !== undefined &&
    requester_did_hint_raw !== null &&
    (!isNonEmptyString(requester_did_hint_raw) || !requester_did_hint_raw.trim().startsWith('did:'))
  ) {
    return errorResponse('INVALID_REQUEST', 'requester_did must be a DID string when provided', 400, undefined, version);
  }

  const requester_did_hint = isNonEmptyString(requester_did_hint_raw) ? requester_did_hint_raw.trim() : null;

  let requesterAuth: RequesterAuthContext;
  let controlPlaneCheck: Record<string, unknown> | null;

  if (options?.authOverride) {
    requesterAuth = options.authOverride;
    if (requester_did_hint && requester_did_hint !== requesterAuth.requester_did) {
      return errorResponse(
        'REQUESTER_SUB_MISMATCH',
        'requester_did does not match auth override requester DID',
        401,
        {
          requester_did: requesterAuth.requester_did,
          requested_requester_did: requester_did_hint,
        },
        version,
      );
    }

    controlPlaneCheck = options.controlPlaneCheckOverride ?? {
      source: 'arena_desk_auth_override',
      checked_at: new Date().toISOString(),
    };
  } else {
    const requesterAuthResult = await requireRequesterAuth(request, env, version, {
      action: 'post_bounty',
      requester_did_hint,
    });
    if ('error' in requesterAuthResult) return requesterAuthResult.error;

    requesterAuth = requesterAuthResult.auth;

    const transitionAuthCheck = await validateRequesterSensitiveTransition(env, version, {
      auth: requesterAuth,
      transition: 'post_bounty',
    });
    if ('error' in transitionAuthCheck) return transitionAuthCheck.error;

    controlPlaneCheck = transitionAuthCheck.evidence;
  }

  const title = bodyRaw.title;
  const description = bodyRaw.description;
  const reward = bodyRaw.reward;
  const closure_type_raw = bodyRaw.closure_type;
  const difficulty_raw = bodyRaw.difficulty_scalar;

  const is_code_bounty_raw = bodyRaw.is_code_bounty;
  const tags_raw = bodyRaw.tags;
  const min_proof_tier_raw = bodyRaw.min_proof_tier;
  const require_owner_verified_votes_raw = bodyRaw.require_owner_verified_votes;
  const test_harness_id_raw = bodyRaw.test_harness_id;
  const idempotency_key_raw = bodyRaw.idempotency_key;
  const metadata_raw = bodyRaw.metadata;
  const cwc_buyer_envelope_raw = bodyRaw.cwc_buyer_envelope;

  if (!isNonEmptyString(title)) {
    return errorResponse('INVALID_REQUEST', 'title is required', 400, undefined, version);
  }

  if (!isNonEmptyString(description)) {
    return errorResponse('INVALID_REQUEST', 'description is required', 400, undefined, version);
  }

  if (!isRecord(reward)) {
    return errorResponse('INVALID_REQUEST', 'reward must be an object', 400, undefined, version);
  }

  const amount_minor_raw = reward.amount_minor;
  const currency_raw = reward.currency;

  const amountMinor = parsePositiveMinor(amount_minor_raw);
  if (amountMinor === null) {
    return errorResponse('INVALID_REQUEST', 'reward.amount_minor must be a positive integer string', 400, undefined, version);
  }

  if (currency_raw !== 'USD') {
    return errorResponse('UNSUPPORTED_CURRENCY', 'Only USD is supported', 400, undefined, version);
  }

  const closure_type = parseClosureType(closure_type_raw);
  if (!closure_type) {
    return errorResponse('INVALID_REQUEST', 'closure_type must be one of test|requester|quorum', 400, undefined, version);
  }

  const difficulty_scalar = parseDifficultyScalar(difficulty_raw);
  if (difficulty_scalar === null) {
    return errorResponse('INVALID_REQUEST', 'difficulty_scalar must be a number between 0.1 and 10.0', 400, undefined, version);
  }

  let is_code_bounty = false;
  if (is_code_bounty_raw !== undefined) {
    if (typeof is_code_bounty_raw !== 'boolean') {
      return errorResponse('INVALID_REQUEST', 'is_code_bounty must be a boolean', 400, undefined, version);
    }
    is_code_bounty = is_code_bounty_raw;
  }

  const tags = parseTags(tags_raw);
  if (tags === null) {
    return errorResponse('INVALID_REQUEST', 'tags must be an array of non-empty strings (max 10)', 400, undefined, version);
  }

  const min_proof_tier = parseProofTier(min_proof_tier_raw) ?? 'self';

  let require_owner_verified_votes = false;
  if (require_owner_verified_votes_raw !== undefined) {
    if (typeof require_owner_verified_votes_raw !== 'boolean') {
      return errorResponse('INVALID_REQUEST', 'require_owner_verified_votes must be a boolean', 400, undefined, version);
    }
    require_owner_verified_votes = require_owner_verified_votes_raw;
  }

  let test_harness_id: string | null = null;
  if (test_harness_id_raw !== undefined) {
    if (test_harness_id_raw !== null && !isNonEmptyString(test_harness_id_raw)) {
      return errorResponse('INVALID_REQUEST', 'test_harness_id must be a string', 400, undefined, version);
    }
    test_harness_id = test_harness_id_raw === null || test_harness_id_raw === undefined ? null : test_harness_id_raw.trim();
  }

  if (closure_type === 'test') {
    if (!is_code_bounty) {
      return errorResponse('INVALID_REQUEST', 'closure_type=test requires is_code_bounty=true', 400, undefined, version);
    }
    if (!test_harness_id) {
      return errorResponse('INVALID_REQUEST', 'test_harness_id is required when closure_type=test', 400, undefined, version);
    }
  }

  const metadata = metadata_raw === undefined || metadata_raw === null ? {} : metadata_raw;
  if (!isRecord(metadata)) {
    return errorResponse('INVALID_REQUEST', 'metadata must be an object', 400, undefined, version);
  }

  const requested_worker_did = metadata.requested_worker_did;
  if (requested_worker_did !== undefined) {
    if (requested_worker_did !== null && (!isNonEmptyString(requested_worker_did) || !requested_worker_did.trim().startsWith('did:'))) {
      return errorResponse('INVALID_REQUEST', 'metadata.requested_worker_did must be a DID string when provided', 400, undefined, version);
    }
  }

  // Confidential Work Contract (CWC) is optional, but when present it MUST be direct-hire.
  let cwc_hash_b64u: string | null = null;
  let cwc_wpc_policy_hash_b64u: string | null = null;
  let cwc_required_proof_tier: ProofTier | null = null;
  let cwc_buyer_envelope: Record<string, unknown> | null = null;

  if (cwc_buyer_envelope_raw !== undefined && cwc_buyer_envelope_raw !== null) {
    if (!isRecord(cwc_buyer_envelope_raw) || !isConfidentialWorkContractEnvelopeV1(cwc_buyer_envelope_raw)) {
      return errorResponse('INVALID_REQUEST', 'cwc_buyer_envelope must be a valid confidential_work_contract envelope', 400, undefined, version);
    }

    if (!isNonEmptyString(requested_worker_did)) {
      return errorResponse(
        'INVALID_REQUEST',
        'cwc_buyer_envelope requires metadata.requested_worker_did (direct-hire)',
        400,
        undefined,
        version
      );
    }

    const envelope = cwc_buyer_envelope_raw as unknown as ConfidentialWorkContractEnvelopeV1;
    const verified = await verifyCwcEnvelope(envelope);

    if (!verified.ok) {
      return errorResponse(verified.code, verified.message, 400, undefined, version);
    }

    const buyerDid = verified.payload.buyer_did.trim();
    const workerDid = verified.payload.worker_did.trim();

    if (buyerDid !== requesterAuth.requester_did) {
      return errorResponse(
        'REQUESTER_SUB_MISMATCH',
        'CWC buyer_did must match requester token subject',
        401,
        { buyer_did: buyerDid },
        version
      );
    }

    if (envelope.signer_did.trim() !== buyerDid) {
      return errorResponse('INVALID_REQUEST', 'CWC buyer envelope signer_did must equal payload.buyer_did', 400, undefined, version);
    }

    if (workerDid !== requested_worker_did.trim()) {
      return errorResponse(
        'INVALID_REQUEST',
        'CWC worker_did must match metadata.requested_worker_did',
        400,
        { worker_did: workerDid, requested_worker_did: requested_worker_did.trim() },
        version
      );
    }

    if (verified.payload.required_proof_tier !== min_proof_tier) {
      return errorResponse(
        'INVALID_REQUEST',
        'CWC required_proof_tier must match bounty min_proof_tier',
        400,
        { required_proof_tier: verified.payload.required_proof_tier, min_proof_tier },
        version
      );
    }

    if (verified.payload.required_proof_tier === 'self') {
      return errorResponse('INVALID_REQUEST', 'CWC requires required_proof_tier to be gateway or sandbox', 400, undefined, version);
    }

    cwc_hash_b64u = verified.payload_hash_b64u;
    cwc_wpc_policy_hash_b64u = verified.payload.wpc_policy_hash_b64u.trim();
    cwc_required_proof_tier = verified.payload.required_proof_tier;
    cwc_buyer_envelope = cwc_buyer_envelope_raw as Record<string, unknown>;
  }

  let idempotency_key: string;
  if (idempotency_key_raw !== undefined && idempotency_key_raw !== null) {
    if (!isNonEmptyString(idempotency_key_raw)) {
      return errorResponse('INVALID_REQUEST', 'idempotency_key must be a non-empty string', 400, undefined, version);
    }
    idempotency_key = idempotency_key_raw.trim();
  } else {
    idempotency_key = await deriveIdempotencyKey(requesterAuth.requester_did, bodyRaw);
  }

  const existing = await getBountyByIdempotencyKey(env.BOUNTIES_DB, idempotency_key);
  if (existing) {
    try {
      await insertRequesterAuthEvent(env.BOUNTIES_DB, {
        action: 'post_bounty',
        bounty_id: existing.bounty_id,
        submission_id: null,
        auth: requesterAuth,
        created_at: new Date().toISOString(),
        sensitive_transition: true,
        control_plane_check: controlPlaneCheck,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      return errorResponse('DB_WRITE_FAILED', message, 500, undefined, version);
    }

    const response: PostBountyResponseV2 = {
      schema_version: '2',
      bounty_id: existing.bounty_id,
      escrow_id: existing.escrow_id,
      status: 'open',
      all_in_cost: existing.all_in_cost,
      fee_policy_version: existing.fee_policy_version,
      created_at: existing.created_at,
    };
    return jsonResponse(response, 200, version);
  }

  // 1) Fee quote (clawcuts)
  let feeQuote: CutsSimulateResponse;
  try {
    feeQuote = await cutsSimulateFees(env, {
      requester_did: requesterAuth.requester_did,
      amount_minor: amountMinor.toString(),
      closure_type,
      is_code_bounty,
      min_proof_tier,
      tags,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('CUTS_FAILED', message, 502, undefined, version);
  }

  const buyerFees = feeQuote.quote.fees.filter((f) => f.payer === 'buyer');
  let platformFeeMinor: string;
  try {
    platformFeeMinor = sumFeesMinor(buyerFees).toString();
  } catch {
    return errorResponse('CUTS_INVALID_RESPONSE', 'Invalid fee item amounts in cuts response', 502, undefined, version);
  }

  const all_in_cost: AllInCostV2 = {
    principal_minor: feeQuote.quote.principal_minor,
    platform_fee_minor: platformFeeMinor,
    total_minor: feeQuote.quote.buyer_total_minor,
    currency: 'USD',
  };

  // 2) Create escrow hold (clawescrow)
  const bounty_id = `bty_${crypto.randomUUID()}`;

  try {
    await insertRequesterAuthEvent(env.BOUNTIES_DB, {
      action: 'post_bounty',
      bounty_id,
      submission_id: null,
      auth: requesterAuth,
      created_at: new Date().toISOString(),
      sensitive_transition: true,
      control_plane_check: controlPlaneCheck,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('DB_WRITE_FAILED', message, 500, undefined, version);
  }

  const escrowFeeSnapshot: EscrowFeeQuoteSnapshot = {
    policy_id: feeQuote.policy.id,
    policy_version: feeQuote.policy.version,
    policy_hash_b64u: feeQuote.policy.hash_b64u,
    buyer_total_minor: feeQuote.quote.buyer_total_minor,
    worker_net_minor: feeQuote.quote.worker_net_minor,
    fees: feeQuote.quote.fees,
  };

  let escrow_id: string;
  try {
    const escrow = await escrowCreateHold(env, {
      idempotency_key: `bounty:${idempotency_key}:escrow`,
      buyer_did: requesterAuth.requester_did,
      amount_minor: amountMinor.toString(),
      fee_quote: escrowFeeSnapshot,
      metadata: {
        product: 'clawbounties',
        schema_version: '2',
        bounty_id,
        closure_type,
        difficulty_scalar,
        is_code_bounty,
        tags,
        min_proof_tier,
        requested_worker_did: requested_worker_did ?? null,
        cwc_hash_b64u,
        cwc_wpc_policy_hash_b64u,
        cwc_required_proof_tier,
        fee_policy: {
          id: feeQuote.policy.id,
          version: feeQuote.policy.version,
          hash_b64u: feeQuote.policy.hash_b64u,
        },
      },
    });
    escrow_id = escrow.escrow_id;
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('ESCROW_FAILED', message, 502, undefined, version);
  }

  const now = new Date().toISOString();

  const record: BountyV2 = {
    schema_version: '2',
    bounty_id,
    requester_did: requesterAuth.requester_did,
    title: title.trim(),
    description: description.trim(),
    reward: { amount_minor: amountMinor.toString(), currency: 'USD' },
    closure_type,
    difficulty_scalar,
    escrow_id,
    status: 'open',
    created_at: now,

    worker_did: null,
    accept_idempotency_key: null,
    accepted_at: null,
    job_token_scope_hash_b64u: null,

    cwc_hash_b64u,
    cwc_wpc_policy_hash_b64u,
    cwc_required_proof_tier,
    cwc_token_scope_hash_b64u: null,
    cwc_buyer_envelope,
    cwc_worker_envelope: null,

    approved_submission_id: null,
    approve_idempotency_key: null,
    approved_at: null,
    rejected_submission_id: null,
    reject_idempotency_key: null,
    rejected_at: null,
    trial_case_id: null,
    trial_opened_at: null,

    arena_status: 'idle',
    arena_id: null,
    arena_task_fingerprint: null,
    arena_winner_contender_id: null,
    arena_evidence_links: [],
    arena_updated_at: null,

    is_code_bounty,
    tags,
    min_proof_tier,
    require_owner_verified_votes,
    test_harness_id,
    metadata,
    idempotency_key,

    fee_policy_version: feeQuote.policy.version,
    all_in_cost,

    fee_quote: feeQuote,
    updated_at: now,
  };

  try {
    await insertBounty(env.BOUNTIES_DB, record);
  } catch (err) {
    const existingAfter = await getBountyByIdempotencyKey(env.BOUNTIES_DB, idempotency_key);
    if (existingAfter) {
      const response: PostBountyResponseV2 = {
        schema_version: '2',
        bounty_id: existingAfter.bounty_id,
        escrow_id: existingAfter.escrow_id,
        status: 'open',
        all_in_cost: existingAfter.all_in_cost,
        fee_policy_version: existingAfter.fee_policy_version,
        created_at: existingAfter.created_at,
      };
      return jsonResponse(response, 200, version);
    }

    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('DB_WRITE_FAILED', message, 500, undefined, version);
  }

  const response: PostBountyResponseV2 = {
    schema_version: '2',
    bounty_id,
    escrow_id,
    status: 'open',
    all_in_cost,
    fee_policy_version: feeQuote.policy.version,
    created_at: now,
  };

  return jsonResponse(response, 201, version);
}

async function handleListBounties(url: URL, env: Env, version: string): Promise<Response> {
  const statusRaw = url.searchParams.get('status') ?? 'open';
  const status = parseBountyStatus(statusRaw);
  if (!status) {
    return errorResponse('INVALID_REQUEST', 'status must be open|accepted|pending_review|approved|rejected|disputed|cancelled', 400, undefined, version);
  }

  const isCodeRaw = url.searchParams.get('is_code_bounty');
  let is_code_bounty: boolean | undefined;
  if (isCodeRaw !== null) {
    const v = isCodeRaw.trim().toLowerCase();
    if (v !== 'true' && v !== 'false') {
      return errorResponse('INVALID_REQUEST', 'is_code_bounty must be true|false', 400, undefined, version);
    }
    is_code_bounty = v === 'true';
  }

  const tags = url.searchParams.getAll('tag').map((t) => t.trim()).filter((t) => t.length > 0);

  const bounties = await listBounties(env.BOUNTIES_DB, { status, is_code_bounty, tags }, 100);
  return jsonResponse({ bounties }, 200, version);
}

async function handleListBountiesForWorker(request: Request, url: URL, env: Env, version: string): Promise<Response> {
  const auth = await requireWorker(request, env, version, {
    action: 'worker_self',
  });
  if ('error' in auth) return auth.error;

  const statusRaw = url.searchParams.get('status') ?? 'open';
  const status = parseBountyStatus(statusRaw);
  if (!status) {
    return errorResponse(
      'INVALID_REQUEST',
      'status must be open|accepted|pending_review|approved|rejected|disputed|cancelled',
      400,
      undefined,
      version
    );
  }

  if (status !== 'open') {
    return errorResponse('FORBIDDEN', 'Workers may only list open bounties', 403, undefined, version);
  }

  const isCodeRaw = url.searchParams.get('is_code_bounty');
  let is_code_bounty: boolean | undefined;
  if (isCodeRaw !== null) {
    const v = isCodeRaw.trim().toLowerCase();
    if (v !== 'true' && v !== 'false') {
      return errorResponse('INVALID_REQUEST', 'is_code_bounty must be true|false', 400, undefined, version);
    }
    is_code_bounty = v === 'true';
  }

  const tags = url.searchParams.getAll('tag').map((t) => t.trim()).filter((t) => t.length > 0);

  const bounties = await listWorkerBounties(
    env.BOUNTIES_DB,
    auth.worker.worker_did,
    { status, is_code_bounty, tags },
    100
  );
  return jsonResponse({ bounties }, 200, version);
}

async function handleRiskLossEvent(
  request: Request,
  env: Env,
  version: string
): Promise<Response> {
  const authError = requireRiskService(request, env, version);
  if (authError) return authError;

  const body = await parseJsonBody(request);
  if (!isRecord(body)) {
    return errorResponse('INVALID_REQUEST', 'Invalid JSON body', 400, undefined, version);
  }

  if (!isNonEmptyString(body.idempotency_key)) {
    return errorResponse('INVALID_REQUEST', 'idempotency_key is required', 400, { field: 'idempotency_key' }, version);
  }
  if (!isNonEmptyString(body.source_loss_event_id)) {
    return errorResponse('INVALID_REQUEST', 'source_loss_event_id is required', 400, { field: 'source_loss_event_id' }, version);
  }
  if (!isNonEmptyString(body.bounty_id) || !body.bounty_id.trim().startsWith('bty_')) {
    return errorResponse('INVALID_REQUEST', 'bounty_id must be a bounty id', 400, { field: 'bounty_id' }, version);
  }
  if (!isNonEmptyString(body.amount_minor) || parsePositiveMinor(body.amount_minor) === null) {
    return errorResponse('INVALID_REQUEST', 'amount_minor must be a positive integer string', 400, { field: 'amount_minor' }, version);
  }
  if (!isNonEmptyString(body.reason_code)) {
    return errorResponse('INVALID_REQUEST', 'reason_code is required', 400, { field: 'reason_code' }, version);
  }

  const severityRaw = isNonEmptyString(body.severity) ? body.severity.trim() : 'high';
  if (severityRaw !== 'low' && severityRaw !== 'medium' && severityRaw !== 'high' && severityRaw !== 'critical') {
    return errorResponse('INVALID_REQUEST', 'severity must be low|medium|high|critical', 400, { field: 'severity' }, version);
  }

  if (body.currency !== undefined && (!isNonEmptyString(body.currency) || body.currency.trim().toUpperCase() !== 'USD')) {
    return errorResponse('UNSUPPORTED_CURRENCY', 'currency must be USD', 400, { field: 'currency' }, version);
  }

  if (body.metadata !== undefined && body.metadata !== null && !isRecord(body.metadata)) {
    return errorResponse('INVALID_REQUEST', 'metadata must be an object', 400, { field: 'metadata' }, version);
  }

  const idempotencyKey = body.idempotency_key.trim();
  const sourceLossEventId = body.source_loss_event_id.trim();
  const bountyId = body.bounty_id.trim();
  const amountMinor = body.amount_minor.trim();
  const reasonCode = body.reason_code.trim();
  const metadata = isRecord(body.metadata) ? body.metadata : null;

  const existing = await getBountyRiskEventByIdempotencyKey(env.BOUNTIES_DB, idempotencyKey);
  if (existing) {
    if (
      existing.source_loss_event_id !== sourceLossEventId ||
      existing.bounty_id !== bountyId ||
      existing.amount_minor !== amountMinor ||
      existing.reason_code !== reasonCode ||
      existing.severity !== severityRaw
    ) {
      return errorResponse(
        'IDEMPOTENCY_CONFLICT',
        'idempotency_key already used with a different payload',
        409,
        { idempotency_key: idempotencyKey, risk_event_id: existing.risk_event_id },
        version
      );
    }

    const replayBounty = await getBountyById(env.BOUNTIES_DB, existing.bounty_id);
    return jsonResponse(
      {
        ok: true,
        replay: true,
        risk_event: existing,
        bounty: replayBounty
          ? {
              bounty_id: replayBounty.bounty_id,
              status: replayBounty.status,
              trial_case_id: replayBounty.trial_case_id,
            }
          : null,
      },
      200,
      version
    );
  }

  const bounty = await getBountyById(env.BOUNTIES_DB, bountyId);
  if (!bounty) {
    return errorResponse('NOT_FOUND', 'Bounty not found', 404, { bounty_id: bountyId }, version);
  }

  const now = new Date().toISOString();
  const riskEventId = `brk_${crypto.randomUUID()}`;

  try {
    await env.BOUNTIES_DB
      .prepare(
        `INSERT INTO bounty_risk_events (
          risk_event_id,
          idempotency_key,
          source_loss_event_id,
          source_service,
          source_event_id,
          bounty_id,
          account_did,
          amount_minor,
          currency,
          reason_code,
          severity,
          metadata_json,
          created_at,
          updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'USD', ?, ?, ?, ?, ?)`
      )
      .bind(
        riskEventId,
        idempotencyKey,
        sourceLossEventId,
        isNonEmptyString(body.source_service) ? body.source_service.trim() : 'clawsettle',
        isNonEmptyString(body.source_event_id) ? body.source_event_id.trim() : null,
        bountyId,
        isNonEmptyString(body.account_did) ? body.account_did.trim() : null,
        amountMinor,
        reasonCode,
        severityRaw,
        metadata ? JSON.stringify(metadata) : null,
        now,
        now
      )
      .run();
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    if (message.includes('UNIQUE constraint failed')) {
      const raced = await getBountyRiskEventByIdempotencyKey(env.BOUNTIES_DB, idempotencyKey);
      if (raced) {
        return jsonResponse({ ok: true, replay: true, risk_event: raced }, 200, version);
      }
      return errorResponse('CONFLICT', 'Risk event already exists', 409, undefined, version);
    }
    return errorResponse('DB_WRITE_FAILED', message, 500, undefined, version);
  }

  if (bounty.status !== 'disputed' && bounty.status !== 'cancelled') {
    try {
      await updateBountyStatus(env.BOUNTIES_DB, bounty.bounty_id, 'disputed', now);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      return errorResponse('DB_WRITE_FAILED', message, 500, undefined, version);
    }
  }

  if (metadata && isNonEmptyString(metadata.trial_case_id) && isNonEmptyString(metadata.trial_opened_at)) {
    try {
      await updateBountyTrialCase(env.BOUNTIES_DB, {
        bounty_id: bounty.bounty_id,
        trial_case_id: metadata.trial_case_id.trim(),
        trial_opened_at: metadata.trial_opened_at.trim(),
        now,
      });
    } catch {
      // best-effort only
    }
  }

  const saved = await getBountyRiskEventById(env.BOUNTIES_DB, riskEventId);
  const refreshedBounty = await getBountyById(env.BOUNTIES_DB, bounty.bounty_id);

  return jsonResponse(
    {
      ok: true,
      replay: false,
      risk_event: saved,
      bounty: refreshedBounty
        ? {
            bounty_id: refreshedBounty.bounty_id,
            status: refreshedBounty.status,
            trial_case_id: refreshedBounty.trial_case_id,
          }
        : null,
    },
    201,
    version
  );
}

async function handleRiskLossEventClear(
  request: Request,
  env: Env,
  version: string
): Promise<Response> {
  const authError = requireRiskService(request, env, version);
  if (authError) return authError;

  const body = await parseJsonBody(request);
  if (!isRecord(body)) {
    return errorResponse('INVALID_REQUEST', 'Invalid JSON body', 400, undefined, version);
  }

  if (!isNonEmptyString(body.idempotency_key)) {
    return errorResponse('INVALID_REQUEST', 'idempotency_key is required', 400, { field: 'idempotency_key' }, version);
  }
  if (!isNonEmptyString(body.source_loss_event_id)) {
    return errorResponse('INVALID_REQUEST', 'source_loss_event_id is required', 400, { field: 'source_loss_event_id' }, version);
  }
  if (!isNonEmptyString(body.bounty_id) || !body.bounty_id.trim().startsWith('bty_')) {
    return errorResponse('INVALID_REQUEST', 'bounty_id must be a bounty id', 400, { field: 'bounty_id' }, version);
  }

  if (body.reason !== undefined && body.reason !== null && !isNonEmptyString(body.reason)) {
    return errorResponse('INVALID_REQUEST', 'reason must be a non-empty string when provided', 400, { field: 'reason' }, version);
  }

  if (body.metadata !== undefined && body.metadata !== null && !isRecord(body.metadata)) {
    return errorResponse('INVALID_REQUEST', 'metadata must be an object', 400, { field: 'metadata' }, version);
  }

  const idempotencyKey = body.idempotency_key.trim();
  const sourceLossEventId = body.source_loss_event_id.trim();
  const bountyId = body.bounty_id.trim();
  const reason = isNonEmptyString(body.reason) ? body.reason.trim() : null;
  const metadata = isRecord(body.metadata) ? body.metadata : null;
  const metadataJson = metadata ? stableStringify(metadata) : null;

  const existing = await getBountyRiskClearByIdempotencyKey(env.BOUNTIES_DB, idempotencyKey);
  if (existing) {
    if (
      existing.source_loss_event_id !== sourceLossEventId ||
      existing.bounty_id !== bountyId ||
      (existing.reason ?? null) !== reason ||
      (existing.metadata_json ?? null) !== metadataJson
    ) {
      return errorResponse(
        'IDEMPOTENCY_CONFLICT',
        'idempotency_key already used with a different payload',
        409,
        { idempotency_key: idempotencyKey, clear_id: existing.clear_id },
        version
      );
    }

    const replayBounty = await getBountyById(env.BOUNTIES_DB, bountyId);
    return jsonResponse(
      {
        ok: true,
        replay: true,
        clear: existing,
        bounty: replayBounty
          ? {
              bounty_id: replayBounty.bounty_id,
              status: replayBounty.status,
              trial_case_id: replayBounty.trial_case_id,
            }
          : null,
      },
      200,
      version
    );
  }

  const bounty = await getBountyById(env.BOUNTIES_DB, bountyId);
  if (!bounty) {
    return errorResponse('NOT_FOUND', 'Bounty not found', 404, { bounty_id: bountyId }, version);
  }

  const now = new Date().toISOString();
  const clearId = `brc_${crypto.randomUUID()}`;

  try {
    await env.BOUNTIES_DB
      .prepare(
        `INSERT INTO bounty_risk_event_clears (
          clear_id,
          idempotency_key,
          source_loss_event_id,
          bounty_id,
          reason,
          metadata_json,
          created_at,
          updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        clearId,
        idempotencyKey,
        sourceLossEventId,
        bountyId,
        reason,
        metadataJson,
        now,
        now
      )
      .run();
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    if (message.includes('UNIQUE constraint failed')) {
      const raced = await getBountyRiskClearByIdempotencyKey(env.BOUNTIES_DB, idempotencyKey);
      if (raced) {
        return jsonResponse({ ok: true, replay: true, clear: raced }, 200, version);
      }

      const pair = await getBountyRiskClearByPair(env.BOUNTIES_DB, sourceLossEventId, bountyId);
      if (pair) {
        return errorResponse(
          'RISK_CLEAR_ALREADY_EXISTS',
          'Risk clear already exists for loss event and bounty',
          409,
          { existing_clear_id: pair.clear_id, existing_idempotency_key: pair.idempotency_key },
          version
        );
      }

      return errorResponse('CONFLICT', 'Risk clear already exists', 409, undefined, version);
    }

    return errorResponse('DB_WRITE_FAILED', message, 500, undefined, version);
  }

  const saved = await getBountyRiskClearById(env.BOUNTIES_DB, clearId);
  if (!saved) {
    return errorResponse('DB_WRITE_FAILED', 'Risk clear persistence failed', 500, undefined, version);
  }

  const refreshedBounty = await getBountyById(env.BOUNTIES_DB, bountyId);

  return jsonResponse(
    {
      ok: true,
      replay: false,
      clear: saved,
      bounty: refreshedBounty
        ? {
            bounty_id: refreshedBounty.bounty_id,
            status: refreshedBounty.status,
            trial_case_id: refreshedBounty.trial_case_id,
          }
        : null,
    },
    201,
    version
  );
}

async function handleStartBountyArena(
  bountyId: string,
  request: Request,
  env: Env,
  version: string,
): Promise<Response> {
  const adminError = requireAdmin(request, env, version);
  if (adminError) return adminError;

  const body = await parseJsonBody(request);
  if (!isRecord(body)) {
    return errorResponse('INVALID_REQUEST', 'Invalid JSON body', 400, undefined, version);
  }

  const idempotencyKey = d1String(body.idempotency_key)?.trim();
  if (!idempotencyKey) {
    return errorResponse('INVALID_REQUEST', 'idempotency_key is required', 400, { field: 'idempotency_key' }, version);
  }

  const arenaId = d1String(body.arena_id)?.trim();
  if (!arenaId || arenaId.length < 3 || arenaId.length > 128) {
    return errorResponse('INVALID_REQUEST', 'arena_id must be a non-empty string (3-128 chars)', 400, { field: 'arena_id' }, version);
  }

  const contract = parseArenaContract(body.contract, bountyId);
  if (!contract) {
    return errorResponse('INVALID_REQUEST', 'contract must include bounty_id, contract_id, contract_hash_b64u, and task_fingerprint', 400, { field: 'contract' }, version);
  }

  const objectiveProfile = parseArenaObjectiveProfile(body.objective_profile);
  if (!objectiveProfile) {
    return errorResponse('INVALID_REQUEST', 'objective_profile is invalid', 400, { field: 'objective_profile' }, version);
  }

  const registryContext = body.registry === undefined
    ? null
    : parseArenaRegistryContext(body.registry);
  if (body.registry !== undefined && !registryContext) {
    return errorResponse('INVALID_REQUEST', 'registry is invalid', 400, { field: 'registry' }, version);
  }

  const experimentContext = body.experiment === undefined
    ? null
    : parseArenaExperimentContext(body.experiment);
  if (body.experiment !== undefined && !experimentContext) {
    return errorResponse('INVALID_REQUEST', 'experiment is invalid', 400, { field: 'experiment' }, version);
  }

  const objectiveProfileName = d1String(objectiveProfile.name)?.trim() ?? null;
  if (registryContext?.objective_profile_name && objectiveProfileName && registryContext.objective_profile_name !== objectiveProfileName) {
    return errorResponse(
      'INVALID_REQUEST',
      'registry.objective_profile_name must match objective_profile.name',
      400,
      { field: 'registry.objective_profile_name' },
      version,
    );
  }

  const registryVersionByContender = new Map<string, string | null>();
  for (const selection of registryContext?.selected_contenders ?? []) {
    registryVersionByContender.set(selection.contender_id, selection.version_pin);
  }

  const baselineContenders: ArenaContenderResult[] = [];
  if (body.contenders !== undefined) {
    if (!Array.isArray(body.contenders)) {
      return errorResponse('INVALID_REQUEST', 'contenders must be an array when provided', 400, { field: 'contenders' }, version);
    }

    for (const contenderRaw of body.contenders) {
      if (!isRecord(contenderRaw)) {
        return errorResponse('INVALID_REQUEST', 'contenders entries must be objects', 400, { field: 'contenders' }, version);
      }

      const contenderId = d1String(contenderRaw.contender_id)?.trim();
      const label = d1String(contenderRaw.label)?.trim();
      const model = d1String(contenderRaw.model)?.trim();
      const harness = d1String(contenderRaw.harness)?.trim();
      const tools = parseStringList(contenderRaw.tools, 64, 120, true);
      const skills = parseStringList(contenderRaw.skills, 64, 120, true);
      const plugins = parseStringList(contenderRaw.plugins, 64, 120, true);
      const versionPinRaw = d1String(contenderRaw.version_pin)?.trim() ?? null;
      const promptTemplateRaw = d1String(contenderRaw.prompt_template)?.trim() ?? null;
      const contenderArmRaw = d1String(contenderRaw.experiment_arm)?.trim() ?? null;

      if (!contenderId || !label || !model || !harness || !tools || !skills || !plugins) {
        return errorResponse('INVALID_REQUEST', 'contender entry is invalid', 400, { contender: contenderRaw }, version);
      }

      baselineContenders.push({
        contender_id: contenderId,
        label,
        model,
        harness,
        tools,
        skills,
        plugins,
        version_pin: versionPinRaw && versionPinRaw.length > 0
          ? versionPinRaw.slice(0, 128)
          : (registryVersionByContender.get(contenderId) ?? null),
        prompt_template: promptTemplateRaw && promptTemplateRaw.length > 0
          ? promptTemplateRaw.slice(0, 256)
          : null,
        experiment_arm: contenderArmRaw && contenderArmRaw.length > 0
          ? contenderArmRaw.slice(0, 64)
          : (experimentContext?.arm ?? null),
        score: 0,
        hard_gate_pass: false,
        mandatory_failed: 0,
        metrics: {
          quality_score: 0,
          risk_score: 0,
          efficiency_score: 0,
          latency_ms: 0,
          cost_usd: 0,
          autonomy_score: 0,
        },
        check_results: [],
        score_explain: {
          final_score: 0,
          reason_codes: ['ARENA_PENDING'],
          evidence_links: [],
        },
        insights: {
          bottlenecks: [],
          contract_improvements: [],
          next_delegation_hints: [],
        },
        proof_pack: null,
        manager_review: null,
        review_paste: 'Arena run started; result payload pending.',
      });
    }
  }

  const bounty = await getBountyById(env.BOUNTIES_DB, bountyId);
  if (!bounty) {
    return errorResponse('NOT_FOUND', 'Bounty not found', 404, { bounty_id: bountyId }, version);
  }

  const existingByIdempotency = await getArenaRunByStartIdempotencyKey(env.BOUNTIES_DB, idempotencyKey);
  if (existingByIdempotency) {
    const samePayload =
      existingByIdempotency.bounty_id === bountyId &&
      existingByIdempotency.arena_id === arenaId &&
      existingByIdempotency.contract_id === contract.contract_id &&
      existingByIdempotency.contract_hash_b64u === contract.contract_hash_b64u &&
      existingByIdempotency.task_fingerprint === contract.task_fingerprint &&
      existingByIdempotency.objective_profile_json === stableStringify(objectiveProfile) &&
      (existingByIdempotency.registry_version ?? null) === (registryContext?.registry_version ?? null) &&
      (existingByIdempotency.experiment_id ?? null) === (experimentContext?.experiment_id ?? null) &&
      (existingByIdempotency.experiment_arm ?? null) === (experimentContext?.arm ?? null);

    if (!samePayload) {
      return errorResponse(
        'IDEMPOTENCY_CONFLICT',
        'idempotency_key already used with a different payload',
        409,
        { idempotency_key: idempotencyKey, run_id: existingByIdempotency.run_id },
        version,
      );
    }

    await updateBountyArenaLifecycle(env.BOUNTIES_DB, {
      bounty_id: bountyId,
      arena_status: 'started',
      arena_id: existingByIdempotency.arena_id,
      arena_task_fingerprint: existingByIdempotency.task_fingerprint,
      arena_winner_contender_id: null,
      arena_evidence_links: [],
      arena_updated_at: new Date().toISOString(),
    });

    const replayPayload = await buildArenaPayloadFromRun(env.BOUNTIES_DB, existingByIdempotency);
    return jsonResponse(
      {
        ok: true,
        replay: true,
        arena: replayPayload ?? buildArenaRunSummary(existingByIdempotency),
      },
      200,
      version,
    );
  }

  const existingArena = await getArenaRunByArenaId(env.BOUNTIES_DB, arenaId);
  if (existingArena) {
    return errorResponse(
      'ARENA_ALREADY_EXISTS',
      'arena_id already exists',
      409,
      { arena_id: arenaId, run_id: existingArena.run_id },
      version,
    );
  }

  const now = new Date().toISOString();
  const runId = `arn_${crypto.randomUUID()}`;

  try {
    await env.BOUNTIES_DB
      .prepare(
        `INSERT INTO bounty_arena_runs (
          run_id,
          arena_id,
          bounty_id,
          status,
          contract_id,
          contract_hash_b64u,
          task_fingerprint,
          objective_profile_json,
          arena_report_json,
          winner_contender_id,
          winner_reason,
          reason_codes_json,
          tradeoffs_json,
          registry_version,
          experiment_id,
          experiment_arm,
          start_idempotency_key,
          result_idempotency_key,
          report_hash_b64u,
          started_at,
          completed_at,
          created_at,
          updated_at
        ) VALUES (?, ?, ?, 'started', ?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, ?, ?, ?, ?, NULL, NULL, ?, NULL, ?, ?)`
      )
      .bind(
        runId,
        arenaId,
        bountyId,
        contract.contract_id,
        contract.contract_hash_b64u,
        contract.task_fingerprint,
        stableStringify(objectiveProfile),
        registryContext?.registry_version ?? null,
        experimentContext?.experiment_id ?? null,
        experimentContext?.arm ?? null,
        idempotencyKey,
        now,
        now,
        now,
      )
      .run();

    if (baselineContenders.length > 0) {
      await writeArenaContenderRecords(env.BOUNTIES_DB, runId, baselineContenders, now);
    }

    const seededEvidenceLinks = baselineContenders.length > 0 ? (baselineContenders[0]?.score_explain.evidence_links ?? []) : [];
    await updateBountyArenaLifecycle(env.BOUNTIES_DB, {
      bounty_id: bountyId,
      arena_status: 'started',
      arena_id: arenaId,
      arena_task_fingerprint: contract.task_fingerprint,
      arena_winner_contender_id: null,
      arena_evidence_links: seededEvidenceLinks,
      arena_updated_at: now,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('DB_WRITE_FAILED', message, 500, undefined, version);
  }

  const saved = await getArenaRunByArenaId(env.BOUNTIES_DB, arenaId);
  if (!saved) {
    return errorResponse('DB_WRITE_FAILED', 'Arena run could not be loaded after insert', 500, undefined, version);
  }

  const payload = await buildArenaPayloadFromRun(env.BOUNTIES_DB, saved);

  return jsonResponse(
    {
      ok: true,
      replay: false,
      arena: payload ?? buildArenaRunSummary(saved),
    },
    201,
    version,
  );
}

async function handleSubmitBountyArenaResult(
  bountyId: string,
  request: Request,
  env: Env,
  version: string,
): Promise<Response> {
  const adminError = requireAdmin(request, env, version);
  if (adminError) return adminError;

  const body = await parseJsonBody(request);
  if (!isRecord(body)) {
    return errorResponse('INVALID_REQUEST', 'Invalid JSON body', 400, undefined, version);
  }

  const idempotencyKey = d1String(body.idempotency_key)?.trim();
  if (!idempotencyKey) {
    return errorResponse('INVALID_REQUEST', 'idempotency_key is required', 400, { field: 'idempotency_key' }, version);
  }

  const report = body.arena_report;
  if (!isRecord(report)) {
    return errorResponse('INVALID_REQUEST', 'arena_report must be an object', 400, { field: 'arena_report' }, version);
  }

  const arenaId = d1String(report.arena_id)?.trim();
  if (!arenaId) {
    return errorResponse('INVALID_REQUEST', 'arena_report.arena_id is required', 400, { field: 'arena_report.arena_id' }, version);
  }

  const contract = parseArenaContract(report.contract, bountyId);
  if (!contract) {
    return errorResponse('INVALID_REQUEST', 'arena_report.contract is invalid or bounty mismatch', 400, { field: 'arena_report.contract' }, version);
  }

  const objectiveProfile = parseArenaObjectiveProfile(report.objective_profile);
  if (!objectiveProfile) {
    return errorResponse('INVALID_REQUEST', 'arena_report.objective_profile is invalid', 400, { field: 'arena_report.objective_profile' }, version);
  }

  const winner = report.winner;
  if (!isRecord(winner)) {
    return errorResponse('INVALID_REQUEST', 'arena_report.winner must be an object', 400, { field: 'arena_report.winner' }, version);
  }

  const winnerContenderId = d1String(winner.contender_id)?.trim();
  const winnerReason = d1String(winner.reason)?.trim();
  if (!winnerContenderId || !winnerReason) {
    return errorResponse('INVALID_REQUEST', 'arena_report.winner.contender_id and winner.reason are required', 400, { field: 'arena_report.winner' }, version);
  }

  const reasonCodes = parseStringList(report.reason_codes, 20, 128, true);
  if (!reasonCodes) {
    return errorResponse('INVALID_REQUEST', 'arena_report.reason_codes must be string[]', 400, { field: 'arena_report.reason_codes' }, version);
  }

  const tradeoffs = parseStringList(report.tradeoffs, 50, 300, true);
  if (!tradeoffs) {
    return errorResponse('INVALID_REQUEST', 'arena_report.tradeoffs must be string[]', 400, { field: 'arena_report.tradeoffs' }, version);
  }

  if (!Array.isArray(report.contenders) || report.contenders.length === 0) {
    return errorResponse('INVALID_REQUEST', 'arena_report.contenders must contain at least one contender', 400, { field: 'arena_report.contenders' }, version);
  }

  const artifactsMap = parseArenaContenderArtifactsMap(body.contender_artifacts);
  if (!artifactsMap) {
    return errorResponse('INVALID_REQUEST', 'contender_artifacts is invalid', 400, { field: 'contender_artifacts' }, version);
  }

  const contenders: ArenaContenderResult[] = [];
  for (const contenderRaw of report.contenders) {
    const contender = parseArenaContenderFromReportRow(contenderRaw, artifactsMap);
    if (!contender) {
      return errorResponse('INVALID_REQUEST', 'arena_report.contenders contains an invalid contender', 400, { contender: contenderRaw }, version);
    }
    contenders.push(contender);
  }

  const winnerContender = contenders.find((entry) => entry.contender_id === winnerContenderId) ?? null;
  if (!winnerContender) {
    return errorResponse(
      'INVALID_REQUEST',
      'arena_report.winner.contender_id must reference an existing contender',
      400,
      { winner_contender_id: winnerContenderId },
      version,
    );
  }

  const run = await getArenaRunByArenaId(env.BOUNTIES_DB, arenaId);
  if (!run) {
    return errorResponse('ARENA_RUN_NOT_STARTED', 'Arena run must be started before result ingestion', 404, { arena_id: arenaId }, version);
  }

  if (run.bounty_id !== bountyId) {
    return errorResponse('ARENA_BOUNTY_MISMATCH', 'Arena run is bound to a different bounty', 409, { arena_id: arenaId, run_bounty_id: run.bounty_id }, version);
  }

  if (
    run.contract_id !== contract.contract_id ||
    run.contract_hash_b64u !== contract.contract_hash_b64u ||
    run.task_fingerprint !== contract.task_fingerprint
  ) {
    return errorResponse(
      'ARENA_CONTRACT_MISMATCH',
      'Arena result contract does not match started arena contract',
      409,
      {
        arena_id: arenaId,
        expected_contract_id: run.contract_id,
        expected_contract_hash_b64u: run.contract_hash_b64u,
      },
      version,
    );
  }

  const existingByResultKey = await getArenaRunByResultIdempotencyKey(env.BOUNTIES_DB, idempotencyKey);
  if (existingByResultKey) {
    if (existingByResultKey.run_id !== run.run_id) {
      return errorResponse(
        'IDEMPOTENCY_CONFLICT',
        'idempotency_key already used by another arena run',
        409,
        { idempotency_key: idempotencyKey, run_id: existingByResultKey.run_id },
        version,
      );
    }

    const winnerEvidenceLinks = getWinnerEvidenceLinks(contenders, winnerContenderId);
    const replayNow = new Date().toISOString();
    await updateBountyArenaLifecycle(env.BOUNTIES_DB, {
      bounty_id: bountyId,
      arena_status: 'completed',
      arena_id: arenaId,
      arena_task_fingerprint: contract.task_fingerprint,
      arena_winner_contender_id: winnerContenderId,
      arena_evidence_links: winnerEvidenceLinks,
      arena_updated_at: replayNow,
    });

    await autoPostArenaWinnerReviewThread(env.BOUNTIES_DB, {
      bounty_id: bountyId,
      arena_id: arenaId,
      result_idempotency_key: idempotencyKey,
      contender: winnerContender,
      source: 'arena-result-autopost',
      now: replayNow,
      arena_explorer_base_url: resolveArenaExplorerBaseUrl(env),
    });

    const replayPayload = await buildArenaPayloadFromRun(env.BOUNTIES_DB, existingByResultKey);
    const replayThread = await listArenaReviewThreadByArenaId(env.BOUNTIES_DB, arenaId, 20);

    return jsonResponse(
      {
        ok: true,
        replay: true,
        arena: replayPayload ?? buildArenaRunSummary(existingByResultKey),
        review_thread: replayThread.map((entry) => buildArenaReviewThreadEntryPayload(entry)),
      },
      200,
      version,
    );
  }

  if (run.result_idempotency_key) {
    return errorResponse(
      'ARENA_RESULT_ALREADY_RECORDED',
      'Arena result already recorded for this run',
      409,
      { run_id: run.run_id, result_idempotency_key: run.result_idempotency_key },
      version,
    );
  }

  const reportCanonical = stableStringify(report);
  const reportHashB64u = await sha256B64uUtf8(reportCanonical);
  const now = new Date().toISOString();

  try {
    await env.BOUNTIES_DB
      .prepare(
        `UPDATE bounty_arena_runs
            SET status = 'completed',
                contract_id = ?,
                contract_hash_b64u = ?,
                task_fingerprint = ?,
                objective_profile_json = ?,
                arena_report_json = ?,
                winner_contender_id = ?,
                winner_reason = ?,
                reason_codes_json = ?,
                tradeoffs_json = ?,
                result_idempotency_key = ?,
                report_hash_b64u = ?,
                completed_at = ?,
                updated_at = ?
          WHERE run_id = ?`
      )
      .bind(
        contract.contract_id,
        contract.contract_hash_b64u,
        contract.task_fingerprint,
        stableStringify(objectiveProfile),
        reportCanonical,
        winnerContenderId,
        winnerReason,
        stableStringify(reasonCodes),
        stableStringify(tradeoffs),
        idempotencyKey,
        reportHashB64u,
        now,
        now,
        run.run_id,
      )
      .run();

    await writeArenaContenderRecords(env.BOUNTIES_DB, run.run_id, contenders, now);

    const winnerEvidenceLinks = getWinnerEvidenceLinks(contenders, winnerContenderId);
    await updateBountyArenaLifecycle(env.BOUNTIES_DB, {
      bounty_id: bountyId,
      arena_status: 'completed',
      arena_id: arenaId,
      arena_task_fingerprint: contract.task_fingerprint,
      arena_winner_contender_id: winnerContenderId,
      arena_evidence_links: winnerEvidenceLinks,
      arena_updated_at: now,
    });

    await autoPostArenaWinnerReviewThread(env.BOUNTIES_DB, {
      bounty_id: bountyId,
      arena_id: arenaId,
      result_idempotency_key: idempotencyKey,
      contender: winnerContender,
      source: 'arena-result-autopost',
      now,
      arena_explorer_base_url: resolveArenaExplorerBaseUrl(env),
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('DB_WRITE_FAILED', message, 500, undefined, version);
  }

  const saved = await getArenaRunByArenaId(env.BOUNTIES_DB, arenaId);
  if (!saved) {
    return errorResponse('DB_WRITE_FAILED', 'Arena run could not be loaded after update', 500, undefined, version);
  }

  const payload = await buildArenaPayloadFromRun(env.BOUNTIES_DB, saved);
  const reviewThread = await listArenaReviewThreadByArenaId(env.BOUNTIES_DB, arenaId, 20);

  return jsonResponse(
    {
      ok: true,
      replay: false,
      arena: payload ?? buildArenaRunSummary(saved),
      review_thread: reviewThread.map((entry) => buildArenaReviewThreadEntryPayload(entry)),
    },
    201,
    version,
  );
}

async function handleGetBountyArena(
  bountyId: string,
  env: Env,
  version: string,
): Promise<Response> {
  const run = await getLatestArenaRunByBountyId(env.BOUNTIES_DB, bountyId);
  if (!run) {
    return errorResponse('NOT_FOUND', 'Arena payload not found for bounty', 404, { bounty_id: bountyId }, version);
  }

  const payload = await buildArenaPayloadFromRun(env.BOUNTIES_DB, run);
  if (!payload) {
    return errorResponse('DATA_INTEGRITY_ERROR', 'Arena payload could not be rendered', 500, { run_id: run.run_id }, version);
  }

  const bounty = await getBountyById(env.BOUNTIES_DB, bountyId);
  const thread = await listArenaReviewThreadByBountyId(env.BOUNTIES_DB, bountyId, 20);
  const outcomes = await listArenaOutcomesByArenaId(env.BOUNTIES_DB, run.arena_id, 50);
  const calibration = buildArenaCalibrationSummary(outcomes, new Map([[run.arena_id, run]]));

  return jsonResponse(
    {
      bounty_id: bountyId,
      arena_lifecycle: bounty ? buildBountyArenaLifecycleSummary(bounty) : null,
      arena: payload,
      review_thread: thread.map((entry) => buildArenaReviewThreadEntryPayload(entry)),
      outcomes: outcomes.map((row) => buildArenaOutcomePayload(row)),
      calibration,
    },
    200,
    version,
  );
}

async function handlePostArenaReviewThread(
  bountyId: string,
  request: Request,
  env: Env,
  version: string,
): Promise<Response> {
  const adminError = requireAdmin(request, env, version);
  if (adminError) return adminError;

  const body = await parseJsonBody(request);
  if (!isRecord(body)) {
    return errorResponse('INVALID_REQUEST', 'Invalid JSON body', 400, undefined, version);
  }

  const idempotencyKey = d1String(body.idempotency_key)?.trim();
  const arenaId = d1String(body.arena_id)?.trim();
  const contenderId = d1String(body.contender_id)?.trim();
  const recommendationRaw = d1String(body.recommendation)?.trim();
  const confidence = d1Number(body.confidence);
  const bodyMarkdown = d1String(body.body_markdown);
  const links = parseArenaThreadLinks(body.links);
  const source = d1String(body.source)?.trim() ?? 'automation';
  const metadata = isRecord(body.metadata) ? body.metadata : null;

  if (!idempotencyKey || idempotencyKey.length > 128) {
    return errorResponse('INVALID_REQUEST', 'idempotency_key is required (<=128 chars)', 400, { field: 'idempotency_key' }, version);
  }

  if (!arenaId || arenaId.length > 128) {
    return errorResponse('INVALID_REQUEST', 'arena_id is required (<=128 chars)', 400, { field: 'arena_id' }, version);
  }

  if (!contenderId || contenderId.length > 128) {
    return errorResponse('INVALID_REQUEST', 'contender_id is required (<=128 chars)', 400, { field: 'contender_id' }, version);
  }

  if (recommendationRaw !== 'APPROVE' && recommendationRaw !== 'REQUEST_CHANGES' && recommendationRaw !== 'REJECT') {
    return errorResponse('INVALID_REQUEST', 'recommendation must be APPROVE | REQUEST_CHANGES | REJECT', 400, { field: 'recommendation' }, version);
  }

  if (confidence === null || Number.isNaN(confidence) || confidence < 0 || confidence > 1) {
    return errorResponse('INVALID_REQUEST', 'confidence must be within [0,1]', 400, { field: 'confidence' }, version);
  }

  if (!bodyMarkdown || bodyMarkdown.length > 24000) {
    return errorResponse('INVALID_REQUEST', 'body_markdown is required (<=24000 chars)', 400, { field: 'body_markdown' }, version);
  }

  if (source.length > 64) {
    return errorResponse('INVALID_REQUEST', 'source must be <=64 chars', 400, { field: 'source' }, version);
  }

  if (links.length === 0) {
    return errorResponse('INVALID_REQUEST', 'links must contain at least one entry', 400, { field: 'links' }, version);
  }

  const run = await getArenaRunByArenaId(env.BOUNTIES_DB, arenaId);
  if (!run || run.bounty_id !== bountyId) {
    return errorResponse('NOT_FOUND', 'Arena run not found for bounty', 404, { bounty_id: bountyId, arena_id: arenaId }, version);
  }

  const contenderRows = await listArenaContendersByRunId(env.BOUNTIES_DB, run.run_id);
  if (!contenderRows.some((row) => row.contender_id === contenderId)) {
    return errorResponse('INVALID_REQUEST', 'contender_id not found for arena run', 400, { contender_id: contenderId, arena_id: arenaId }, version);
  }

  const metadataJson = metadata ? stableStringify(metadata) : null;
  const linksJson = stableStringify(links);

  const existing = await getArenaReviewThreadByIdempotencyKey(env.BOUNTIES_DB, idempotencyKey);
  if (existing) {
    const samePayload =
      existing.bounty_id === bountyId &&
      existing.arena_id === arenaId &&
      existing.contender_id === contenderId &&
      existing.recommendation === recommendationRaw &&
      existing.confidence === confidence &&
      existing.body_markdown === bodyMarkdown &&
      existing.links_json === linksJson &&
      existing.source === source &&
      (existing.metadata_json ?? null) === metadataJson;

    if (!samePayload) {
      return errorResponse(
        'IDEMPOTENCY_CONFLICT',
        'idempotency_key already used with a different payload',
        409,
        { idempotency_key: idempotencyKey, thread_entry_id: existing.thread_entry_id },
        version,
      );
    }

    return jsonResponse(
      {
        ok: true,
        replay: true,
        thread_entry: buildArenaReviewThreadEntryPayload(existing),
      },
      200,
      version,
    );
  }

  const now = new Date().toISOString();
  const entry: ArenaReviewThreadEntry = {
    thread_entry_id: `art_${crypto.randomUUID()}`,
    idempotency_key: idempotencyKey,
    bounty_id: bountyId,
    arena_id: arenaId,
    contender_id: contenderId,
    recommendation: recommendationRaw,
    confidence,
    body_markdown: bodyMarkdown,
    links_json: linksJson,
    source,
    metadata_json: metadataJson,
    created_at: now,
    updated_at: now,
  };

  try {
    await writeArenaReviewThreadEntry(env.BOUNTIES_DB, entry);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('DB_WRITE_FAILED', message, 500, undefined, version);
  }

  return jsonResponse(
    {
      ok: true,
      replay: false,
      thread_entry: buildArenaReviewThreadEntryPayload(entry),
    },
    201,
    version,
  );
}

async function handleListArenaReviewThread(
  bountyId: string,
  request: Request,
  url: URL,
  env: Env,
  version: string,
): Promise<Response> {
  const adminError = requireAdmin(request, env, version);
  if (adminError) return adminError;

  const limitRaw = url.searchParams.get('limit');
  let limit = 20;
  if (isNonEmptyString(limitRaw)) {
    const parsed = Number.parseInt(limitRaw.trim(), 10);
    if (!Number.isFinite(parsed) || parsed <= 0) {
      return errorResponse('INVALID_REQUEST', 'limit must be a positive integer', 400, { field: 'limit' }, version);
    }
    limit = Math.min(parsed, 100);
  }

  const entries = await listArenaReviewThreadByBountyId(env.BOUNTIES_DB, bountyId, limit);

  return jsonResponse(
    {
      bounty_id: bountyId,
      review_thread: entries.map((entry) => buildArenaReviewThreadEntryPayload(entry)),
    },
    200,
    version,
  );
}

function mapManagerDecisionToArenaRecommendation(value: unknown): 'APPROVE' | 'REQUEST_CHANGES' | 'REJECT' {
  const normalized = d1String(value)?.trim().toLowerCase();
  if (normalized === 'promote') return 'APPROVE';
  if (normalized === 'iterate' || normalized === 'conditional') return 'REQUEST_CHANGES';
  return 'REJECT';
}

function recommendationToReviewerDecision(
  recommendation: ArenaRecommendationView,
): ArenaReviewerDecisionView {
  if (recommendation === 'APPROVE') return 'approve';
  if (recommendation === 'REQUEST_CHANGES') return 'request_changes';
  return 'reject';
}

function reviewerDecisionToRecommendation(
  reviewerDecision: ArenaReviewerDecisionView,
): ArenaRecommendationView {
  if (reviewerDecision === 'approve') return 'APPROVE';
  if (reviewerDecision === 'request_changes') return 'REQUEST_CHANGES';
  return 'REJECT';
}

function outcomeStatusToReviewerDecision(
  outcomeStatus: ArenaOutcomeStatusView,
): ArenaReviewerDecisionView {
  if (outcomeStatus === 'ACCEPTED') return 'approve';
  if (outcomeStatus === 'REWORK' || outcomeStatus === 'OVERRIDDEN') return 'request_changes';
  return 'reject';
}

function normalizeArenaReviewerDecision(value: unknown): ArenaReviewerDecisionView | null {
  const normalized = d1String(value)?.trim().toLowerCase();
  if (!normalized) return null;

  if (normalized === 'approve' || normalized === 'approved') return 'approve';
  if (
    normalized === 'request_changes' ||
    normalized === 'request-changes' ||
    normalized === 'requestchanges' ||
    normalized === 'revise' ||
    normalized === 'iterate'
  ) {
    return 'request_changes';
  }
  if (normalized === 'reject' || normalized === 'rejected') return 'reject';

  return null;
}

function normalizeArenaPolicyOptimizerEnvironment(value: unknown, fallback: string): string {
  const normalized = d1String(value)?.trim().toLowerCase();
  if (!normalized) return fallback;
  if (normalized === 'prod') return 'production';
  return normalized;
}

function normalizeArenaPolicyDimensionValue(value: string | null): string {
  return value ? value.trim() : '';
}

async function buildArenaRunMap(
  db: D1Database,
  arenaIds: Iterable<string>,
): Promise<Map<string, ArenaRunRecord>> {
  const out = new Map<string, ArenaRunRecord>();
  for (const arenaId of arenaIds) {
    if (!arenaId || out.has(arenaId)) continue;
    const run = await getArenaRunByArenaId(db, arenaId);
    if (run) out.set(arenaId, run);
  }
  return out;
}

async function handlePostArenaOutcome(
  bountyId: string,
  request: Request,
  env: Env,
  version: string,
): Promise<Response> {
  const adminError = requireAdmin(request, env, version);
  if (adminError) return adminError;

  const body = await parseJsonBody(request);
  if (!isRecord(body)) {
    return errorResponse('INVALID_REQUEST', 'Invalid JSON body', 400, undefined, version);
  }

  const idempotencyKey = d1String(body.idempotency_key)?.trim();
  const arenaId = d1String(body.arena_id)?.trim();
  const contenderIdRaw = d1String(body.contender_id)?.trim() ?? null;
  const outcomeStatus = d1String(body.outcome_status)?.trim();
  const reviewTime = d1Number(body.review_time_minutes) ?? 0;
  const timeToAcceptRaw = d1Number(body.time_to_accept_minutes);
  const source = d1String(body.source)?.trim() ?? 'human-review';
  const overrideReasonRaw = d1String(body.override_reason_code)?.trim() ?? null;
  const notes = d1String(body.notes)?.trim() ?? null;
  const reviewerDecisionRaw = body.reviewer_decision;
  const reviewerRationale = d1String(body.reviewer_rationale)?.trim() ?? null;
  const decisionTaxonomyTagsRaw = body.decision_taxonomy_tags;
  const hasReworkRequiredField = Object.prototype.hasOwnProperty.call(body, 'rework_required');
  const reworkRequiredRaw = hasReworkRequiredField ? d1Boolean(body.rework_required) : null;
  const metadata = isRecord(body.metadata) ? body.metadata : null;

  if (!idempotencyKey || idempotencyKey.length > 128) {
    return errorResponse('INVALID_REQUEST', 'idempotency_key is required (<=128 chars)', 400, { field: 'idempotency_key' }, version);
  }

  if (!arenaId || arenaId.length > 128) {
    return errorResponse('INVALID_REQUEST', 'arena_id is required (<=128 chars)', 400, { field: 'arena_id' }, version);
  }

  if (
    outcomeStatus !== 'ACCEPTED' &&
    outcomeStatus !== 'OVERRIDDEN' &&
    outcomeStatus !== 'REWORK' &&
    outcomeStatus !== 'REJECTED' &&
    outcomeStatus !== 'DISPUTED'
  ) {
    return errorResponse(
      'INVALID_REQUEST',
      'outcome_status must be ACCEPTED | OVERRIDDEN | REWORK | REJECTED | DISPUTED',
      400,
      { field: 'outcome_status' },
      version,
    );
  }

  const outcomeStatusValue = outcomeStatus as 'ACCEPTED' | 'OVERRIDDEN' | 'REWORK' | 'REJECTED' | 'DISPUTED';

  const overrideReasonCode = normalizeArenaOverrideReasonCode(overrideReasonRaw);
  if (overrideReasonRaw && !overrideReasonCode) {
    return errorResponse(
      'INVALID_REQUEST',
      `override_reason_code must be one of: ${Object.keys(ARENA_OVERRIDE_REASON_REGISTRY).join(', ')}`,
      400,
      { field: 'override_reason_code' },
      version,
    );
  }

  if (outcomeStatusValue === 'OVERRIDDEN' && !overrideReasonCode) {
    return errorResponse(
      'INVALID_REQUEST',
      'override_reason_code is required when outcome_status=OVERRIDDEN',
      400,
      { field: 'override_reason_code' },
      version,
    );
  }

  if (outcomeStatusValue !== 'OVERRIDDEN' && overrideReasonCode) {
    return errorResponse(
      'INVALID_REQUEST',
      'override_reason_code is only valid when outcome_status=OVERRIDDEN',
      400,
      { field: 'override_reason_code' },
      version,
    );
  }

  if (!Number.isFinite(reviewTime) || reviewTime < 0) {
    return errorResponse('INVALID_REQUEST', 'review_time_minutes must be >= 0', 400, { field: 'review_time_minutes' }, version);
  }

  if (timeToAcceptRaw !== null && (!Number.isFinite(timeToAcceptRaw) || timeToAcceptRaw < 0)) {
    return errorResponse('INVALID_REQUEST', 'time_to_accept_minutes must be >= 0', 400, { field: 'time_to_accept_minutes' }, version);
  }

  if (source.length > 64) {
    return errorResponse('INVALID_REQUEST', 'source must be <=64 chars', 400, { field: 'source' }, version);
  }

  if (notes && notes.length > 4000) {
    return errorResponse('INVALID_REQUEST', 'notes must be <=4000 chars', 400, { field: 'notes' }, version);
  }

  if (reviewerRationale && reviewerRationale.length > 4000) {
    return errorResponse('INVALID_REQUEST', 'reviewer_rationale must be <=4000 chars', 400, { field: 'reviewer_rationale' }, version);
  }

  if (hasReworkRequiredField && reworkRequiredRaw === null) {
    return errorResponse('INVALID_REQUEST', 'rework_required must be a boolean', 400, { field: 'rework_required' }, version);
  }

  const run = await getArenaRunByArenaId(env.BOUNTIES_DB, arenaId);
  if (!run || run.bounty_id !== bountyId) {
    return errorResponse('NOT_FOUND', 'Arena run not found for bounty', 404, { bounty_id: bountyId, arena_id: arenaId }, version);
  }

  const contenderRows = await listArenaContendersByRunId(env.BOUNTIES_DB, run.run_id);
  const contenderId = contenderIdRaw ?? run.winner_contender_id ?? contenderRows[0]?.contender_id ?? null;
  if (!contenderId) {
    return errorResponse('DATA_INTEGRITY_ERROR', 'No contender available for outcome record', 500, { arena_id: arenaId }, version);
  }

  const contenderRow = contenderRows.find((row) => row.contender_id === contenderId);
  if (!contenderRow) {
    return errorResponse('INVALID_REQUEST', 'contender_id not found for arena run', 400, { contender_id: contenderId }, version);
  }

  const contender = parseArenaContenderResult(contenderRow);
  if (!contender) {
    return errorResponse('DATA_INTEGRITY_ERROR', 'Contender payload is invalid', 500, { contender_id: contenderId }, version);
  }

  const existing = await getArenaOutcomeByIdempotencyKey(env.BOUNTIES_DB, idempotencyKey);

  const threadEntries = await listArenaReviewThreadByArenaId(env.BOUNTIES_DB, arenaId, 50);
  const latestThreadForContender = threadEntries.find((entry) => entry.contender_id === contenderId) ?? null;

  const managerReview = contender.manager_review && isRecord(contender.manager_review)
    ? contender.manager_review
    : null;

  const defaultRecommendation = latestThreadForContender
    ? latestThreadForContender.recommendation
    : mapManagerDecisionToArenaRecommendation(managerReview?.decision);

  const managerConfidence = d1Number(managerReview?.confidence) ?? 0;
  const defaultConfidence = latestThreadForContender
    ? latestThreadForContender.confidence
    : Math.max(0, Math.min(1, managerConfidence));

  const recommendationRaw = d1String(body.recommendation)?.trim();
  const predictedConfidenceRaw = d1Number(body.predicted_confidence);

  if (
    recommendationRaw &&
    recommendationRaw !== 'APPROVE' &&
    recommendationRaw !== 'REQUEST_CHANGES' &&
    recommendationRaw !== 'REJECT'
  ) {
    return errorResponse(
      'INVALID_REQUEST',
      'recommendation must be APPROVE | REQUEST_CHANGES | REJECT',
      400,
      { field: 'recommendation' },
      version,
    );
  }

  const recommendationFromInput = recommendationRaw
    ? (recommendationRaw as ArenaRecommendationView)
    : null;

  const reviewerDecisionFromInput = normalizeArenaReviewerDecision(reviewerDecisionRaw);
  if (reviewerDecisionRaw !== undefined && reviewerDecisionFromInput === null) {
    return errorResponse(
      'INVALID_REQUEST',
      'reviewer_decision must be approve | request_changes | reject',
      400,
      { field: 'reviewer_decision' },
      version,
    );
  }

  const reviewerDecision = reviewerDecisionFromInput
    ?? (recommendationFromInput ? recommendationToReviewerDecision(recommendationFromInput) : null)
    ?? outcomeStatusToReviewerDecision(outcomeStatusValue)
    ?? recommendationToReviewerDecision(defaultRecommendation);

  const recommendation = recommendationFromInput
    ?? reviewerDecisionToRecommendation(reviewerDecision);

  if (recommendation !== reviewerDecisionToRecommendation(reviewerDecision)) {
    return errorResponse(
      'INVALID_REQUEST',
      'recommendation must align with reviewer_decision',
      400,
      { field: 'recommendation' },
      version,
    );
  }

  if (outcomeStatusValue === 'ACCEPTED' && reviewerDecision !== 'approve') {
    return errorResponse(
      'INVALID_REQUEST',
      'reviewer_decision=approve is required when outcome_status=ACCEPTED',
      400,
      { field: 'reviewer_decision' },
      version,
    );
  }

  if (outcomeStatusValue === 'REWORK' && reviewerDecision !== 'request_changes') {
    return errorResponse(
      'INVALID_REQUEST',
      'reviewer_decision=request_changes is required when outcome_status=REWORK',
      400,
      { field: 'reviewer_decision' },
      version,
    );
  }

  if (outcomeStatusValue === 'REJECTED' && reviewerDecision !== 'reject') {
    return errorResponse(
      'INVALID_REQUEST',
      'reviewer_decision=reject is required when outcome_status=REJECTED',
      400,
      { field: 'reviewer_decision' },
      version,
    );
  }

  const predictedConfidence = predictedConfidenceRaw === null
    ? defaultConfidence
    : predictedConfidenceRaw;

  if (!Number.isFinite(predictedConfidence) || predictedConfidence < 0 || predictedConfidence > 1) {
    return errorResponse('INVALID_REQUEST', 'predicted_confidence must be within [0,1]', 400, { field: 'predicted_confidence' }, version);
  }

  let decisionTaxonomyTags: string[] = [];
  if (decisionTaxonomyTagsRaw !== undefined) {
    const parsedTags = parseStringList(decisionTaxonomyTagsRaw, 20, 64, true);
    if (!parsedTags) {
      return errorResponse(
        'INVALID_REQUEST',
        'decision_taxonomy_tags must be a string array (<=20 items, each <=64 chars)',
        400,
        { field: 'decision_taxonomy_tags' },
        version,
      );
    }
    decisionTaxonomyTags = parsedTags;
  }

  if (decisionTaxonomyTags.length === 0) {
    const metadataTags = parseStringList(metadata?.calibration_signal_tags, 20, 64, true) ?? [];
    const derivedTags = [
      ...metadataTags,
      `decision:${reviewerDecision}`,
      `outcome:${outcomeStatusValue.toLowerCase()}`,
    ];
    if (overrideReasonCode) {
      derivedTags.push(`override:${overrideReasonCode.toLowerCase()}`);
    }
    decisionTaxonomyTags = dedupeStrings(
      derivedTags
        .map((tag) => tag.trim().toLowerCase())
        .filter((tag) => tag.length > 0),
    ).slice(0, 20);
  }

  const decisionTaxonomyJson = stableStringify(decisionTaxonomyTags);

  const accepted = outcomeStatusValue === 'ACCEPTED';
  const overridden = outcomeStatusValue === 'OVERRIDDEN';
  const derivedReworkRequired = outcomeStatusValue === 'REWORK' || reviewerDecision === 'request_changes';
  const reworkRequired = hasReworkRequiredField ? (reworkRequiredRaw as boolean) : derivedReworkRequired;

  if (hasReworkRequiredField && reworkRequired !== derivedReworkRequired) {
    return errorResponse(
      'INVALID_REQUEST',
      'rework_required must align with outcome_status/reviewer_decision',
      400,
      { field: 'rework_required' },
      version,
    );
  }

  const disputed = outcomeStatusValue === 'DISPUTED';
  const timeToAccept = accepted ? (timeToAcceptRaw ?? reviewTime) : null;

  const metadataWithDecisionCapture = {
    ...(metadata ?? {}),
    reviewer_decision: reviewerDecision,
    reviewer_rationale: reviewerRationale,
    decision_taxonomy_tags: decisionTaxonomyTags,
    rework_required: reworkRequired,
  };

  const metadataJson = stableStringify(metadataWithDecisionCapture);

  if (existing) {
    const samePayload =
      existing.bounty_id === bountyId &&
      existing.arena_id === arenaId &&
      existing.contender_id === contenderId &&
      existing.outcome_status === outcomeStatusValue &&
      existing.accepted === accepted &&
      existing.overridden === overridden &&
      existing.rework_required === reworkRequired &&
      existing.disputed === disputed &&
      existing.review_time_minutes === reviewTime &&
      (existing.time_to_accept_minutes ?? null) === timeToAccept &&
      existing.predicted_confidence === predictedConfidence &&
      existing.recommendation === recommendation &&
      existing.reviewer_decision === reviewerDecision &&
      (existing.reviewer_rationale ?? null) === (reviewerRationale ?? null) &&
      existing.decision_taxonomy_json === decisionTaxonomyJson &&
      (existing.override_reason_code ?? null) === (overrideReasonCode ?? null) &&
      (existing.notes ?? null) === notes &&
      existing.source === source &&
      (existing.metadata_json ?? null) === metadataJson;

    if (!samePayload) {
      return errorResponse(
        'IDEMPOTENCY_CONFLICT',
        'idempotency_key already used with a different payload',
        409,
        { idempotency_key: idempotencyKey, outcome_id: existing.outcome_id },
        version,
      );
    }

    return jsonResponse(
      {
        ok: true,
        replay: true,
        outcome: buildArenaOutcomePayload(existing),
      },
      200,
      version,
    );
  }

  const now = new Date().toISOString();
  const outcome: ArenaOutcomeRecord = {
    outcome_id: `aot_${crypto.randomUUID()}`,
    idempotency_key: idempotencyKey,
    bounty_id: bountyId,
    arena_id: arenaId,
    contender_id: contenderId,
    outcome_status: outcomeStatusValue,
    accepted,
    overridden,
    rework_required: reworkRequired,
    disputed,
    review_time_minutes: reviewTime,
    time_to_accept_minutes: timeToAccept,
    predicted_confidence: predictedConfidence,
    recommendation,
    reviewer_decision: reviewerDecision,
    reviewer_rationale: reviewerRationale,
    decision_taxonomy_json: decisionTaxonomyJson,
    override_reason_code: overrideReasonCode,
    notes,
    source,
    metadata_json: metadataJson,
    created_at: now,
    updated_at: now,
  };

  try {
    await writeArenaOutcome(env.BOUNTIES_DB, outcome);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('DB_WRITE_FAILED', message, 500, undefined, version);
  }

  const outcomes = await listArenaOutcomes(env.BOUNTIES_DB, 500);
  const runMap = await buildArenaRunMap(env.BOUNTIES_DB, outcomes.map((row) => row.arena_id));

  return jsonResponse(
    {
      ok: true,
      replay: false,
      outcome: buildArenaOutcomePayload(outcome),
      calibration: buildArenaCalibrationSummary(outcomes, runMap),
    },
    201,
    version,
  );
}

async function handleListArenaCalibration(
  url: URL,
  env: Env,
  version: string,
): Promise<Response> {
  const limitRaw = url.searchParams.get('limit');
  let limit = 500;
  if (isNonEmptyString(limitRaw)) {
    const parsed = Number.parseInt(limitRaw.trim(), 10);
    if (!Number.isFinite(parsed) || parsed <= 0) {
      return errorResponse('INVALID_REQUEST', 'limit must be a positive integer', 400, { field: 'limit' }, version);
    }
    limit = Math.min(parsed, 2000);
  }

  const taskFingerprintFilter = d1String(url.searchParams.get('task_fingerprint'))?.trim() ?? null;
  const contenderFilter = d1String(url.searchParams.get('contender_id'))?.trim() ?? null;

  const outcomes = await listArenaOutcomes(env.BOUNTIES_DB, limit);
  const runMap = await buildArenaRunMap(env.BOUNTIES_DB, outcomes.map((row) => row.arena_id));

  const filtered = outcomes.filter((row) => {
    if (contenderFilter && row.contender_id !== contenderFilter) return false;
    if (taskFingerprintFilter) {
      const run = runMap.get(row.arena_id);
      if (!run || run.task_fingerprint !== taskFingerprintFilter) return false;
    }
    return true;
  });

  const filteredRunMap = new Map<string, ArenaRunRecord>();
  for (const row of filtered) {
    const run = runMap.get(row.arena_id);
    if (run) filteredRunMap.set(row.arena_id, run);
  }

  return jsonResponse(
    {
      calibration: buildArenaCalibrationSummary(filtered, filteredRunMap),
      outcomes: filtered.map((row) => buildArenaOutcomePayload(row)),
    },
    200,
    version,
  );
}

async function handleGetArenaOutcomeFeed(
  arenaId: string,
  url: URL,
  env: Env,
  version: string,
): Promise<Response> {
  const run = await getArenaRunByArenaId(env.BOUNTIES_DB, arenaId);
  if (!run) {
    return errorResponse('NOT_FOUND', 'Arena run not found', 404, { arena_id: arenaId }, version);
  }

  const limitRaw = url.searchParams.get('limit');
  let limit = 50;
  if (isNonEmptyString(limitRaw)) {
    const parsed = Number.parseInt(limitRaw.trim(), 10);
    if (!Number.isFinite(parsed) || parsed <= 0) {
      return errorResponse('INVALID_REQUEST', 'limit must be a positive integer', 400, { field: 'limit' }, version);
    }
    limit = Math.min(parsed, 200);
  }

  const outcomes = await listArenaOutcomesByArenaId(env.BOUNTIES_DB, arenaId, limit);
  const runMap = new Map<string, ArenaRunRecord>([[arenaId, run]]);

  return jsonResponse(
    {
      arena_id: arenaId,
      bounty_id: run.bounty_id,
      outcomes: outcomes.map((row) => buildArenaOutcomePayload(row)),
      calibration: buildArenaCalibrationSummary(outcomes, runMap),
    },
    200,
    version,
  );
}

async function handleGetArena(
  arenaId: string,
  env: Env,
  version: string,
): Promise<Response> {
  const run = await getArenaRunByArenaId(env.BOUNTIES_DB, arenaId);
  if (!run) {
    return errorResponse('NOT_FOUND', 'Arena run not found', 404, { arena_id: arenaId }, version);
  }

  const payload = await buildArenaPayloadFromRun(env.BOUNTIES_DB, run);
  if (!payload || !isRecord(payload)) {
    return errorResponse('DATA_INTEGRITY_ERROR', 'Arena payload could not be rendered', 500, { run_id: run.run_id }, version);
  }

  const thread = await listArenaReviewThreadByArenaId(env.BOUNTIES_DB, arenaId, 20);
  const outcomes = await listArenaOutcomesByArenaId(env.BOUNTIES_DB, arenaId, 50);
  const calibration = buildArenaCalibrationSummary(outcomes, new Map([[arenaId, run]]));

  const autopilot = buildArenaAutopilotPreview(run, payload, calibration);
  const policyOptimizer = await buildArenaPolicyOptimizerPreview(
    env.BOUNTIES_DB,
    run,
    env.ENVIRONMENT?.trim().toLowerCase() ?? 'production',
  );
  const roiDashboard = await buildArenaRoiDashboardPreview(env.BOUNTIES_DB, run);
  const contractCopilot = await buildArenaContractCopilotPreview(env.BOUNTIES_DB, run.task_fingerprint);
  const contractLanguageOptimizer = await buildArenaContractLanguageOptimizerPreview(env.BOUNTIES_DB, run.task_fingerprint);

  return jsonResponse(
    {
      ...payload,
      review_thread: thread.map((entry) => buildArenaReviewThreadEntryPayload(entry)),
      outcomes: outcomes.map((row) => buildArenaOutcomePayload(row)),
      calibration,
      autopilot,
      policy_optimizer: policyOptimizer,
      roi_dashboard: roiDashboard,
      contract_copilot: contractCopilot,
      contract_language_optimizer: contractLanguageOptimizer,
    },
    200,
    version,
  );
}

async function handleGetArenaDelegationInsights(
  arenaId: string,
  env: Env,
  version: string,
): Promise<Response> {
  const run = await getArenaRunByArenaId(env.BOUNTIES_DB, arenaId);
  if (!run) {
    return errorResponse('NOT_FOUND', 'Arena run not found', 404, { arena_id: arenaId }, version);
  }

  const payload = await buildArenaPayloadFromRun(env.BOUNTIES_DB, run);
  if (!payload || !isRecord(payload)) {
    return errorResponse('DATA_INTEGRITY_ERROR', 'Arena payload could not be rendered', 500, { run_id: run.run_id }, version);
  }

  const insights = payload.delegation_insights;
  if (!isRecord(insights)) {
    return errorResponse('DATA_INTEGRITY_ERROR', 'Delegation insights are unavailable', 500, { run_id: run.run_id }, version);
  }

  return jsonResponse({
    arena_id: run.arena_id,
    winner_contender_id: run.winner_contender_id,
    delegation_insights: insights,
  }, 200, version);
}

async function handleGetArenaReviewThread(
  arenaId: string,
  url: URL,
  env: Env,
  version: string,
): Promise<Response> {
  const run = await getArenaRunByArenaId(env.BOUNTIES_DB, arenaId);
  if (!run) {
    return errorResponse('NOT_FOUND', 'Arena run not found', 404, { arena_id: arenaId }, version);
  }

  const limitRaw = url.searchParams.get('limit');
  let limit = 20;
  if (isNonEmptyString(limitRaw)) {
    const parsed = Number.parseInt(limitRaw.trim(), 10);
    if (!Number.isFinite(parsed) || parsed <= 0) {
      return errorResponse('INVALID_REQUEST', 'limit must be a positive integer', 400, { field: 'limit' }, version);
    }
    limit = Math.min(parsed, 100);
  }

  const entries = await listArenaReviewThreadByArenaId(env.BOUNTIES_DB, arenaId, limit);

  return jsonResponse(
    {
      arena_id: arenaId,
      bounty_id: run.bounty_id,
      review_thread: entries.map((entry) => buildArenaReviewThreadEntryPayload(entry)),
    },
    200,
    version,
  );
}

async function handleListArena(
  url: URL,
  env: Env,
  version: string,
): Promise<Response> {
  const limitRaw = url.searchParams.get('limit');
  let limit = 20;

  if (isNonEmptyString(limitRaw)) {
    const parsed = Number.parseInt(limitRaw.trim(), 10);
    if (!Number.isFinite(parsed) || parsed <= 0) {
      return errorResponse('INVALID_REQUEST', 'limit must be a positive integer', 400, { field: 'limit' }, version);
    }
    limit = Math.min(parsed, 100);
  }

  const runs = await listArenaRuns(env.BOUNTIES_DB, limit);
  const arenas = runs.map((run) => buildArenaRunSummary(run));

  return jsonResponse({ arenas }, 200, version);
}

async function handleArenaPolicyLearning(
  request: Request,
  url: URL,
  env: Env,
  version: string,
): Promise<Response> {
  const adminError = requireAdmin(request, env, version);
  if (adminError) return adminError;

  const limitRaw = url.searchParams.get('limit');
  let limit = 500;
  if (isNonEmptyString(limitRaw)) {
    const parsed = Number.parseInt(limitRaw.trim(), 10);
    if (!Number.isFinite(parsed) || parsed <= 0) {
      return errorResponse('INVALID_REQUEST', 'limit must be a positive integer', 400, { field: 'limit' }, version);
    }
    limit = Math.min(parsed, 5000);
  }

  const taskFingerprintFilter = d1String(url.searchParams.get('task_fingerprint'))?.trim() ?? null;

  const outcomes = await listArenaOutcomes(env.BOUNTIES_DB, limit);
  const runMap = await buildArenaRunMap(env.BOUNTIES_DB, outcomes.map((row) => row.arena_id));

  const filtered = outcomes.filter((row) => {
    if (!taskFingerprintFilter) return true;
    const run = runMap.get(row.arena_id);
    return Boolean(run && run.task_fingerprint === taskFingerprintFilter);
  });

  const overrides = filtered.filter((row) => row.overridden);
  const reasonCounts = new Map<ArenaOverrideReasonCode, number>();
  const contenderReasonCounts = new Map<string, Map<ArenaOverrideReasonCode, number>>();
  const noteSamples: string[] = [];

  for (const outcome of overrides) {
    const reasonCode = normalizeArenaOverrideReasonCode(outcome.override_reason_code) ?? 'ARENA_OVERRIDE_OTHER';
    reasonCounts.set(reasonCode, (reasonCounts.get(reasonCode) ?? 0) + 1);

    const contenderMap = contenderReasonCounts.get(outcome.contender_id) ?? new Map<ArenaOverrideReasonCode, number>();
    contenderMap.set(reasonCode, (contenderMap.get(reasonCode) ?? 0) + 1);
    contenderReasonCounts.set(outcome.contender_id, contenderMap);

    if (outcome.notes && outcome.notes.trim().length > 0 && noteSamples.length < 20) {
      noteSamples.push(outcome.notes.trim());
    }
  }

  const totalOverrides = overrides.length;
  const reasonBreakdown = [...reasonCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([reason_code, count]) => ({
      reason_code,
      count,
      share: totalOverrides > 0 ? Number((count / totalOverrides).toFixed(4)) : 0,
      weight: ARENA_OVERRIDE_REASON_REGISTRY[reason_code].weight,
    }));

  const recommendations = reasonBreakdown
    .map((entry) => ({
      ...entry,
      priority_score: Number((entry.count * entry.weight).toFixed(4)),
      contract_rewrite: ARENA_OVERRIDE_REASON_REGISTRY[entry.reason_code].contract_rewrite,
      prompt_rewrite: ARENA_OVERRIDE_REASON_REGISTRY[entry.reason_code].prompt_rewrite,
    }))
    .sort((a, b) => b.priority_score - a.priority_score);

  const contenderProfiles = [...contenderReasonCounts.entries()]
    .map(([contender_id, counts]) => {
      const breakdown = [...counts.entries()]
        .sort((a, b) => b[1] - a[1])
        .map(([reason_code, count]) => ({
          reason_code,
          count,
          contract_rewrite: ARENA_OVERRIDE_REASON_REGISTRY[reason_code].contract_rewrite,
          prompt_rewrite: ARENA_OVERRIDE_REASON_REGISTRY[reason_code].prompt_rewrite,
        }));

      const topReason = breakdown[0] ?? null;
      const total = [...counts.values()].reduce((sum, value) => sum + value, 0);

      return {
        contender_id,
        overrides: total,
        top_reason_code: topReason?.reason_code ?? null,
        top_contract_rewrite: topReason?.contract_rewrite ?? null,
        top_prompt_rewrite: topReason?.prompt_rewrite ?? null,
        breakdown,
      };
    })
    .sort((a, b) => b.overrides - a.overrides);

  return jsonResponse(
    {
      schema_version: 'arena_policy_learning.v1',
      computed_at: new Date().toISOString(),
      task_fingerprint: taskFingerprintFilter,
      totals: {
        outcomes: filtered.length,
        overrides: totalOverrides,
        override_rate: filtered.length > 0 ? Number((totalOverrides / filtered.length).toFixed(4)) : 0,
      },
      reason_breakdown: reasonBreakdown,
      recommendations,
      contender_profiles: contenderProfiles,
      note_samples: noteSamples,
    },
    200,
    version,
  );
}

function computeMedian(values: number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  if (sorted.length % 2 === 0) {
    const left = sorted[middle - 1] ?? 0;
    const right = sorted[middle] ?? left;
    return (left + right) / 2;
  }
  return sorted[middle] ?? 0;
}

function computeAverage(values: number[]): number {
  if (values.length === 0) return 0;
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

async function buildArenaContenderCostMap(
  db: D1Database,
  runs: ArenaRunRecord[],
): Promise<Map<string, number>> {
  const costMap = new Map<string, number>();

  for (const run of runs) {
    const contenders = await listArenaContendersByRunId(db, run.run_id);
    for (const contender of contenders) {
      const metrics = parseJsonObject(contender.metrics_json);
      const costUsd = metrics ? d1Number(metrics.cost_usd) : null;
      if (costUsd === null) continue;
      costMap.set(`${run.arena_id}::${contender.contender_id}`, costUsd);
    }
  }

  return costMap;
}

function normalizeArenaRoiFilterValue(value: string | null): string {
  return value ? value.trim() : '';
}

async function computeArenaRoiDashboard(
  db: D1Database,
  params: {
    taskFingerprint: string;
    objectiveProfileName: string;
    contenderId: string;
    experimentId: string;
    experimentArm: string;
    limit: number;
    minSamples: number;
    nowIso?: string;
  },
): Promise<Record<string, unknown>> {
  const outcomes = await listArenaOutcomes(db, params.limit);
  const runMap = await buildArenaRunMap(db, outcomes.map((row) => row.arena_id));

  const filteredOutcomes = outcomes.filter((row) => {
    const run = runMap.get(row.arena_id);
    if (!run) return false;

    if (params.taskFingerprint && run.task_fingerprint !== params.taskFingerprint) return false;

    const objectiveProfileName = normalizeArenaRoiFilterValue(getArenaObjectiveProfileNameFromRun(run));
    if (params.objectiveProfileName && objectiveProfileName !== params.objectiveProfileName) return false;

    const experimentId = normalizeArenaRoiFilterValue(run.experiment_id);
    if (params.experimentId && experimentId !== params.experimentId) return false;

    const experimentArm = normalizeArenaRoiFilterValue(run.experiment_arm);
    if (params.experimentArm && experimentArm !== params.experimentArm) return false;

    if (params.contenderId && row.contender_id !== params.contenderId) return false;

    return true;
  });

  const filteredRunIds = dedupeStrings(filteredOutcomes.map((row) => row.arena_id));
  const filteredRuns = filteredRunIds
    .map((arenaId) => runMap.get(arenaId) ?? null)
    .filter((run): run is ArenaRunRecord => run !== null);

  const contenderCostMap = await buildArenaContenderCostMap(db, filteredRuns);

  const computeMetricsForRows = (rows: ArenaOutcomeRecord[]) => {
    const sampleCount = rows.length;
    const accepted = rows.filter((row) => row.accepted).length;
    const firstPassAccepted = rows.filter((row) => row.accepted && !row.overridden && !row.rework_required).length;
    const overridden = rows.filter((row) => row.overridden).length;
    const rework = rows.filter((row) => row.rework_required).length;

    const reviewTimes = rows.map((row) => row.review_time_minutes).filter((value) => Number.isFinite(value));
    const cycleTimes = rows
      .map((row) => (row.time_to_accept_minutes ?? row.review_time_minutes))
      .filter((value) => Number.isFinite(value));

    const acceptedCosts = rows
      .filter((row) => row.accepted)
      .map((row) => contenderCostMap.get(`${row.arena_id}::${row.contender_id}`) ?? null)
      .filter((value): value is number => value !== null && Number.isFinite(value));

    const rowsRunIds = dedupeStrings(rows.map((row) => row.arena_id));
    const rowsRuns = rowsRunIds
      .map((arenaId) => runMap.get(arenaId) ?? null)
      .filter((run): run is ArenaRunRecord => run !== null);

    const winnerCounts = new Map<string, number>();
    for (const run of rowsRuns) {
      const winnerContenderId = run.winner_contender_id?.trim();
      if (!winnerContenderId) continue;
      winnerCounts.set(winnerContenderId, (winnerCounts.get(winnerContenderId) ?? 0) + 1);
    }

    const maxWinnerCount = winnerCounts.size > 0
      ? Math.max(...winnerCounts.values())
      : 0;
    const winnerStability = rowsRuns.length > 0 ? maxWinnerCount / rowsRuns.length : 0;

    const reasonCounts = new Map<string, number>();
    for (const row of rows) {
      if (!isArenaFailedOutcome(row)) continue;
      const reasonCode = normalizeArenaOverrideReasonCode(row.override_reason_code) ?? deriveArenaContractLanguageReasonCode(row);
      reasonCounts.set(reasonCode, (reasonCounts.get(reasonCode) ?? 0) + 1);
    }

    const reasonBreakdown = [...reasonCounts.entries()]
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
      .map(([reason_code, count]) => ({
        reason_code,
        count,
        share: sampleCount > 0 ? Number((count / sampleCount).toFixed(4)) : 0,
      }));

    return {
      sampleCount,
      arenaCount: rowsRunIds.length,
      reasonBreakdown,
      metrics: {
        median_review_time_minutes: Number(computeMedian(reviewTimes).toFixed(2)),
        first_pass_accept_rate: sampleCount > 0 ? Number((firstPassAccepted / sampleCount).toFixed(4)) : 0,
        override_rate: sampleCount > 0 ? Number((overridden / sampleCount).toFixed(4)) : 0,
        rework_rate: sampleCount > 0 ? Number((rework / sampleCount).toFixed(4)) : 0,
        cost_per_accepted_bounty_usd: Number(computeAverage(acceptedCosts).toFixed(4)),
        cycle_time_minutes: Number(computeMedian(cycleTimes).toFixed(2)),
        winner_stability: Number(winnerStability.toFixed(4)),
        accepted_outcomes: accepted,
      },
    };
  };

  const now = params.nowIso ? new Date(params.nowIso) : new Date();

  const overall = computeMetricsForRows(filteredOutcomes);

  const buildTrendWindow = (windowDays: number) => {
    const cutoff = new Date(now.getTime() - (windowDays * 24 * 60 * 60 * 1000));
    const rows = filteredOutcomes.filter((row) => {
      const createdAt = new Date(row.created_at);
      return Number.isFinite(createdAt.getTime()) && createdAt >= cutoff;
    });

    const metrics = computeMetricsForRows(rows);
    if (metrics.sampleCount < params.minSamples) {
      return {
        status: 'INSUFFICIENT_SAMPLE',
        sample_count: metrics.sampleCount,
        reason_codes: ['ARENA_ROI_INSUFFICIENT_SAMPLE'],
      };
    }

    return {
      status: 'available',
      sample_count: metrics.sampleCount,
      metrics: metrics.metrics,
    };
  };

  const window7d = buildTrendWindow(7);
  const window30d = buildTrendWindow(30);

  const status = overall.sampleCount >= params.minSamples
    ? 'available'
    : 'INSUFFICIENT_SAMPLE';

  const statusReasonCodes = status === 'available'
    ? ['ARENA_ROI_READY']
    : ['ARENA_ROI_INSUFFICIENT_SAMPLE'];

  return {
    schema_version: 'arena_roi_dashboard.v1',
    computed_at: now.toISOString(),
    status,
    filters: {
      task_fingerprint: params.taskFingerprint || null,
      objective_profile_name: params.objectiveProfileName || null,
      contender_id: params.contenderId || null,
      experiment_id: params.experimentId || null,
      experiment_arm: params.experimentArm || null,
      limit: params.limit,
      min_samples: params.minSamples,
    },
    totals: {
      sample_count: overall.sampleCount,
      arena_count: overall.arenaCount,
      available_runs: filteredRuns.length,
    },
    reason_codes: statusReasonCodes,
    metrics: status === 'available' ? overall.metrics : null,
    trends: {
      window_7d: window7d,
      window_30d: window30d,
    },
    reason_code_drilldown: overall.reasonBreakdown,
  };
}

async function buildArenaRoiDashboardPreview(
  db: D1Database,
  run: ArenaRunRecord,
): Promise<Record<string, unknown>> {
  return computeArenaRoiDashboard(db, {
    taskFingerprint: run.task_fingerprint,
    objectiveProfileName: normalizeArenaRoiFilterValue(getArenaObjectiveProfileNameFromRun(run)),
    contenderId: '',
    experimentId: normalizeArenaRoiFilterValue(run.experiment_id),
    experimentArm: normalizeArenaRoiFilterValue(run.experiment_arm),
    limit: 2000,
    minSamples: 5,
  });
}

async function handleGetArenaRoiDashboard(
  request: Request,
  url: URL,
  env: Env,
  version: string,
): Promise<Response> {
  const adminError = requireAdmin(request, env, version);
  if (adminError) return adminError;

  const taskFingerprint = normalizeArenaRoiFilterValue(d1String(url.searchParams.get('task_fingerprint')));
  const objectiveProfileName = normalizeArenaRoiFilterValue(d1String(url.searchParams.get('objective_profile_name')));
  const contenderId = normalizeArenaRoiFilterValue(d1String(url.searchParams.get('contender_id')));
  const experimentId = normalizeArenaRoiFilterValue(d1String(url.searchParams.get('experiment_id')));
  const experimentArm = normalizeArenaRoiFilterValue(d1String(url.searchParams.get('experiment_arm')));

  const limitRaw = url.searchParams.get('limit');
  let limit = 2000;
  if (isNonEmptyString(limitRaw)) {
    const parsed = Number.parseInt(limitRaw.trim(), 10);
    if (!Number.isFinite(parsed) || parsed <= 0) {
      return errorResponse('INVALID_REQUEST', 'limit must be a positive integer', 400, { field: 'limit' }, version);
    }
    limit = Math.min(parsed, 5000);
  }

  const minSamplesRaw = url.searchParams.get('min_samples');
  let minSamples = 5;
  if (isNonEmptyString(minSamplesRaw)) {
    const parsed = Number.parseInt(minSamplesRaw.trim(), 10);
    if (!Number.isFinite(parsed) || parsed <= 0) {
      return errorResponse('INVALID_REQUEST', 'min_samples must be a positive integer', 400, { field: 'min_samples' }, version);
    }
    minSamples = Math.min(parsed, 2000);
  }

  const payload = await computeArenaRoiDashboard(env.BOUNTIES_DB, {
    taskFingerprint,
    objectiveProfileName,
    contenderId,
    experimentId,
    experimentArm,
    limit,
    minSamples,
  });

  return jsonResponse(payload, 200, version);
}

function isArenaFailedOutcome(row: ArenaOutcomeRecord): boolean {
  return row.overridden || row.rework_required || row.disputed || row.outcome_status === 'REJECTED';
}

function deriveArenaContractLanguageReasonCode(row: ArenaOutcomeRecord): ArenaOverrideReasonCode {
  const explicit = normalizeArenaOverrideReasonCode(row.override_reason_code);
  if (explicit) return explicit;

  const metadata = parseArenaOutcomeMetadata(row.metadata_json);
  for (const tag of metadata.calibration_signal_tags) {
    const normalized = normalizeArenaOverrideReasonCode(tag);
    if (normalized) return normalized;
  }

  if (row.rework_required) return 'ARENA_OVERRIDE_TEST_FAILURE';
  if (row.disputed) return 'ARENA_OVERRIDE_REQUIRE_HUMAN_CONTEXT';
  if (row.outcome_status === 'REJECTED') return 'ARENA_OVERRIDE_POLICY_RISK';
  return 'ARENA_OVERRIDE_OTHER';
}

function parseStringArrayJson(input: string): string[] {
  try {
    const parsed = JSON.parse(input);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((entry): entry is string => typeof entry === 'string');
  } catch {
    return [];
  }
}

function buildArenaContractLanguageSuggestionPayload(
  suggestion: ArenaContractLanguageSuggestionRecord,
): Record<string, unknown> {
  return {
    suggestion_id: suggestion.suggestion_id,
    task_fingerprint: suggestion.task_fingerprint,
    scope: suggestion.scope,
    contender_id: suggestion.scope === 'global' ? null : suggestion.contender_id,
    reason_code: suggestion.reason_code,
    failures: suggestion.failures,
    overrides: suggestion.overrides,
    share: Number(suggestion.share.toFixed(4)),
    priority_score: Number(suggestion.priority_score.toFixed(4)),
    contract_rewrite: suggestion.contract_rewrite,
    prompt_rewrite: suggestion.prompt_rewrite,
    contract_language_patch: suggestion.contract_language_patch,
    prompt_language_patch: suggestion.prompt_language_patch,
    sample_notes: parseStringArrayJson(suggestion.sample_notes_json),
    top_tags: parseStringArrayJson(suggestion.tags_json),
    computed_at: suggestion.computed_at,
  };
}

function buildArenaContractLanguagePatch(params: {
  reasonCode: ArenaOverrideReasonCode;
  failures: number;
  topTags: string[];
  statusBreakdown: Array<{ status: ArenaOutcomeRecord['outcome_status']; count: number }>;
}): string {
  const reasonInfo = ARENA_OVERRIDE_REASON_REGISTRY[params.reasonCode];
  const statusSummary = params.statusBreakdown
    .map((entry) => `${entry.status}=${entry.count}`)
    .join(', ');
  const tagsSummary = params.topTags.length > 0 ? params.topTags.join(', ') : 'contract acceptance criteria';

  return [
    `Observed ${params.failures} failed/overridden outcomes (${statusSummary || 'mixed'}) tied to ${params.reasonCode}.`,
    `Contract rewrite: ${reasonInfo.contract_rewrite}`,
    `Explicitly encode reviewer checks for: ${tagsSummary}.`,
    'Fail closed: unresolved checklist items must require manual reviewer approval.',
  ].join(' ');
}

function buildArenaPromptLanguagePatch(params: {
  reasonCode: ArenaOverrideReasonCode;
  topTags: string[];
}): string {
  const reasonInfo = ARENA_OVERRIDE_REASON_REGISTRY[params.reasonCode];
  const tagsSummary = params.topTags.length > 0 ? params.topTags.join(', ') : 'acceptance checklist';

  return [
    `Prompt rewrite: ${reasonInfo.prompt_rewrite}`,
    `Require explicit self-check against: ${tagsSummary}.`,
    'If any mandatory check fails, emit REQUEST_CHANGES with concrete remediation steps.',
  ].join(' ');
}

async function buildArenaContractLanguageSuggestionId(params: {
  taskFingerprint: string;
  scope: 'global' | 'contender';
  contenderId: string;
  reasonCode: ArenaOverrideReasonCode;
}): Promise<string> {
  const material = stableStringify({
    task_fingerprint: params.taskFingerprint,
    scope: params.scope,
    contender_id: params.contenderId,
    reason_code: params.reasonCode,
  });
  return `acls_${(await sha256B64uUtf8(material)).slice(0, 32)}`;
}

async function computeArenaContractLanguageOptimizer(
  db: D1Database,
  params: {
    taskFingerprint: string;
    limit: number;
  },
): Promise<{
  payload: Record<string, unknown>;
  suggestions: ArenaContractLanguageSuggestionRecord[];
}> {
  const outcomes = await listArenaOutcomes(db, params.limit);
  const runMap = await buildArenaRunMap(db, outcomes.map((row) => row.arena_id));

  const filtered = outcomes.filter((row) => {
    const run = runMap.get(row.arena_id);
    return Boolean(run && run.task_fingerprint === params.taskFingerprint);
  });

  const failed = filtered.filter((row) => isArenaFailedOutcome(row));

  type Aggregate = {
    failures: number;
    overrides: number;
    statusCounts: Map<ArenaOutcomeRecord['outcome_status'], number>;
    tagCounts: Map<string, number>;
    noteSamples: string[];
  };

  const ensureAggregate = (): Aggregate => ({
    failures: 0,
    overrides: 0,
    statusCounts: new Map(),
    tagCounts: new Map(),
    noteSamples: [],
  });

  const globalAggregates = new Map<ArenaOverrideReasonCode, Aggregate>();
  const contenderAggregates = new Map<string, Map<ArenaOverrideReasonCode, Aggregate>>();

  for (const row of failed) {
    const reasonCode = deriveArenaContractLanguageReasonCode(row);
    const metadata = parseArenaOutcomeMetadata(row.metadata_json);

    const note = metadata.override_rationale
      ?? metadata.decision_rationale
      ?? (row.notes?.trim() && row.notes.trim().length > 0 ? row.notes.trim() : null);

    const updateAggregate = (aggregate: Aggregate) => {
      aggregate.failures += 1;
      if (row.overridden) aggregate.overrides += 1;
      aggregate.statusCounts.set(row.outcome_status, (aggregate.statusCounts.get(row.outcome_status) ?? 0) + 1);

      for (const tag of metadata.calibration_signal_tags) {
        aggregate.tagCounts.set(tag, (aggregate.tagCounts.get(tag) ?? 0) + 1);
      }

      if (note && !aggregate.noteSamples.includes(note) && aggregate.noteSamples.length < 4) {
        aggregate.noteSamples.push(note);
      }
    };

    const global = globalAggregates.get(reasonCode) ?? ensureAggregate();
    updateAggregate(global);
    globalAggregates.set(reasonCode, global);

    const contenderMap = contenderAggregates.get(row.contender_id) ?? new Map<ArenaOverrideReasonCode, Aggregate>();
    const contenderAggregate = contenderMap.get(reasonCode) ?? ensureAggregate();
    updateAggregate(contenderAggregate);
    contenderMap.set(reasonCode, contenderAggregate);
    contenderAggregates.set(row.contender_id, contenderMap);
  }

  const computedAt = new Date().toISOString();
  const createdAt = computedAt;

  const totalFailed = failed.length;

  const toStatusBreakdown = (aggregate: Aggregate) => [...aggregate.statusCounts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([status, count]) => ({ status, count }));

  const toTopTags = (aggregate: Aggregate) => [...aggregate.tagCounts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, 5)
    .map(([tag]) => tag);

  const suggestions: ArenaContractLanguageSuggestionRecord[] = [];

  for (const [reasonCode, aggregate] of [...globalAggregates.entries()].sort((a, b) => b[1].failures - a[1].failures || a[0].localeCompare(b[0]))) {
    const topTags = toTopTags(aggregate);
    const statusBreakdown = toStatusBreakdown(aggregate);
    const share = totalFailed > 0 ? aggregate.failures / totalFailed : 0;
    const priorityScore = Number((aggregate.failures * ARENA_OVERRIDE_REASON_REGISTRY[reasonCode].weight + aggregate.overrides * 0.35).toFixed(4));

    suggestions.push({
      suggestion_id: await buildArenaContractLanguageSuggestionId({
        taskFingerprint: params.taskFingerprint,
        scope: 'global',
        contenderId: '__global__',
        reasonCode,
      }),
      task_fingerprint: params.taskFingerprint,
      scope: 'global',
      contender_id: '__global__',
      reason_code: reasonCode,
      failures: aggregate.failures,
      overrides: aggregate.overrides,
      share: Number(share.toFixed(4)),
      priority_score: priorityScore,
      contract_rewrite: ARENA_OVERRIDE_REASON_REGISTRY[reasonCode].contract_rewrite,
      prompt_rewrite: ARENA_OVERRIDE_REASON_REGISTRY[reasonCode].prompt_rewrite,
      contract_language_patch: buildArenaContractLanguagePatch({
        reasonCode,
        failures: aggregate.failures,
        topTags,
        statusBreakdown,
      }),
      prompt_language_patch: buildArenaPromptLanguagePatch({ reasonCode, topTags }),
      sample_notes_json: stableStringify(aggregate.noteSamples),
      tags_json: stableStringify(topTags),
      computed_at: computedAt,
      created_at: createdAt,
      updated_at: createdAt,
    });
  }

  for (const [contenderId, reasonMap] of [...contenderAggregates.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    const contenderFailures = [...reasonMap.values()].reduce((sum, aggregate) => sum + aggregate.failures, 0);
    const rankedReasons = [...reasonMap.entries()]
      .sort((a, b) => b[1].failures - a[1].failures || a[0].localeCompare(b[0]))
      .slice(0, 3);

    for (const [reasonCode, aggregate] of rankedReasons) {
      const topTags = toTopTags(aggregate);
      const statusBreakdown = toStatusBreakdown(aggregate);
      const share = contenderFailures > 0 ? aggregate.failures / contenderFailures : 0;
      const priorityScore = Number((aggregate.failures * ARENA_OVERRIDE_REASON_REGISTRY[reasonCode].weight + aggregate.overrides * 0.35).toFixed(4));

      suggestions.push({
        suggestion_id: await buildArenaContractLanguageSuggestionId({
          taskFingerprint: params.taskFingerprint,
          scope: 'contender',
          contenderId,
          reasonCode,
        }),
        task_fingerprint: params.taskFingerprint,
        scope: 'contender',
        contender_id: contenderId,
        reason_code: reasonCode,
        failures: aggregate.failures,
        overrides: aggregate.overrides,
        share: Number(share.toFixed(4)),
        priority_score: priorityScore,
        contract_rewrite: ARENA_OVERRIDE_REASON_REGISTRY[reasonCode].contract_rewrite,
        prompt_rewrite: ARENA_OVERRIDE_REASON_REGISTRY[reasonCode].prompt_rewrite,
        contract_language_patch: buildArenaContractLanguagePatch({
          reasonCode,
          failures: aggregate.failures,
          topTags,
          statusBreakdown,
        }),
        prompt_language_patch: buildArenaPromptLanguagePatch({ reasonCode, topTags }),
        sample_notes_json: stableStringify(aggregate.noteSamples),
        tags_json: stableStringify(topTags),
        computed_at: computedAt,
        created_at: createdAt,
        updated_at: createdAt,
      });
    }
  }

  const globalSuggestions = suggestions
    .filter((entry) => entry.scope === 'global')
    .sort((a, b) => b.priority_score - a.priority_score || b.failures - a.failures)
    .map((entry) => buildArenaContractLanguageSuggestionPayload(entry));

  const contenderSuggestions = suggestions
    .filter((entry) => entry.scope === 'contender')
    .sort((a, b) => b.priority_score - a.priority_score || b.failures - a.failures)
    .map((entry) => buildArenaContractLanguageSuggestionPayload(entry));

  return {
    payload: {
      schema_version: 'arena_contract_language_optimizer.v1',
      computed_at: computedAt,
      task_fingerprint: params.taskFingerprint,
      totals: {
        outcomes: filtered.length,
        failed_or_overridden_outcomes: totalFailed,
        overridden_outcomes: failed.filter((row) => row.overridden).length,
        suggestions: suggestions.length,
      },
      global_suggestions: globalSuggestions,
      contender_suggestions: contenderSuggestions,
    },
    suggestions,
  };
}

async function computeAndPersistArenaContractLanguageOptimizer(
  db: D1Database,
  params: {
    taskFingerprint: string;
    limit: number;
  },
): Promise<Record<string, unknown>> {
  const optimizer = await computeArenaContractLanguageOptimizer(db, params);
  await replaceArenaContractLanguageSuggestions(db, params.taskFingerprint, optimizer.suggestions);

  return {
    ...optimizer.payload,
    persistence: {
      table: 'bounty_arena_contract_language_suggestions',
      rows_written: optimizer.suggestions.length,
      mode: 'replace_by_task_fingerprint',
    },
  };
}

function deriveArenaContractCopilotCriterionId(
  row: ArenaOutcomeRecord,
  reasonCode: ArenaOverrideReasonCode,
): string {
  const decisionTaxonomyTags = parseJsonStringArray(row.decision_taxonomy_json) ?? [];
  const metadata = parseArenaOutcomeMetadata(row.metadata_json);

  const candidateTags = dedupeStrings([
    ...decisionTaxonomyTags,
    ...metadata.calibration_signal_tags,
  ]);

  for (const tag of candidateTags) {
    const trimmed = tag.trim().toLowerCase();
    if (!trimmed) continue;

    if (trimmed.startsWith('criterion:')) {
      const criterion = trimmed.slice('criterion:'.length).trim();
      if (criterion) return criterion;
    }

    if (trimmed.startsWith('ac_')) {
      return trimmed;
    }
  }

  if (reasonCode === 'ARENA_OVERRIDE_SCOPE_MISMATCH') return 'scope_alignment';
  if (reasonCode === 'ARENA_OVERRIDE_TEST_FAILURE') return 'test_coverage';
  if (reasonCode === 'ARENA_OVERRIDE_POLICY_RISK') return 'policy_risk_guardrail';
  if (reasonCode === 'ARENA_OVERRIDE_REQUIRE_HUMAN_CONTEXT') return 'human_context_capture';

  return 'acceptance_checklist';
}

function buildArenaContractCopilotBeforeText(params: {
  reasonCode: ArenaOverrideReasonCode;
  criterionId: string;
  evidenceCount: number;
  overrides: number;
  reworks: number;
}): string {
  const criterion = params.criterionId.replace(/_/g, ' ');
  return [
    `Current contract language under-specifies ${criterion}, creating reviewer friction.`,
    `Observed ${params.evidenceCount} real failure outcomes (overrides=${params.overrides}, reworks=${params.reworks}) linked to ${params.reasonCode}.`,
    'Failure mode: checklist and acceptance boundaries are ambiguous at review time.',
  ].join(' ');
}

function buildArenaContractCopilotAfterText(params: {
  reasonCode: ArenaOverrideReasonCode;
  criterionId: string;
}): string {
  const reasonInfo = ARENA_OVERRIDE_REASON_REGISTRY[params.reasonCode];
  const criterion = params.criterionId.replace(/_/g, ' ');

  return [
    `Add explicit acceptance criterion "${criterion}" with pass/fail evidence requirements and fail-closed escalation.`,
    `Rewrite guidance: ${reasonInfo.contract_rewrite}`,
    'Require worker output to quote criterion IDs and attach evidence for each mandatory check.',
  ].join(' ');
}

function buildArenaContractCopilotRationale(params: {
  reasonCode: ArenaOverrideReasonCode;
  evidenceCount: number;
  arenaCount: number;
  overrides: number;
  reworks: number;
}): string {
  const reasonInfo = ARENA_OVERRIDE_REASON_REGISTRY[params.reasonCode];
  return [
    `Pattern repeated across ${params.arenaCount} arenas and ${params.evidenceCount} outcomes.`,
    `Observed overrides=${params.overrides}, reworks=${params.reworks}.`,
    `Root-cause rewrite target: ${reasonInfo.prompt_rewrite}`,
  ].join(' ');
}

function computeArenaContractCopilotConfidence(params: {
  evidenceCount: number;
  arenaCount: number;
  overrideRate: number;
  reworkRate: number;
  reasonWeight: number;
}): number {
  const coverageScore = Math.min(1, params.evidenceCount / 12);
  const arenaScore = Math.min(1, params.arenaCount / 5);
  const severityScore = Math.min(1, params.overrideRate + params.reworkRate);

  const weighted =
    0.35 +
    (coverageScore * 0.3) +
    (arenaScore * 0.2) +
    (severityScore * 0.1) +
    (Math.min(1, params.reasonWeight) * 0.05);

  return Number(Math.max(0, Math.min(0.99, weighted)).toFixed(4));
}

function computeArenaContractCopilotExpectedImpact(params: {
  confidence: number;
  overrideRate: number;
  reworkRate: number;
}): { expectedOverrideReduction: number; expectedReworkReduction: number } {
  const expectedOverrideReduction = Number(
    Math.max(0, Math.min(0.75, params.overrideRate * 0.55 + params.confidence * 0.2)).toFixed(4),
  );
  const expectedReworkReduction = Number(
    Math.max(0, Math.min(0.7, params.reworkRate * 0.5 + params.confidence * 0.18)).toFixed(4),
  );

  return {
    expectedOverrideReduction,
    expectedReworkReduction,
  };
}

async function buildArenaContractCopilotSuggestionId(params: {
  taskFingerprint: string;
  scope: 'global' | 'contender';
  contenderId: string;
  reasonCode: ArenaOverrideReasonCode;
  criterionId: string;
}): Promise<string> {
  const material = stableStringify({
    task_fingerprint: params.taskFingerprint,
    scope: params.scope,
    contender_id: params.contenderId,
    reason_code: params.reasonCode,
    criterion_id: params.criterionId,
  });
  return `accs_${(await sha256B64uUtf8(material)).slice(0, 32)}`;
}

function buildArenaContractCopilotSuggestionPayload(
  suggestion: ArenaContractCopilotSuggestionRecord,
): Record<string, unknown> {
  return {
    suggestion_id: suggestion.suggestion_id,
    task_fingerprint: suggestion.task_fingerprint,
    scope: suggestion.scope,
    contender_id: suggestion.scope === 'global' ? null : suggestion.contender_id,
    reason_code: suggestion.reason_code,
    before_text: suggestion.before_text,
    after_text: suggestion.after_text,
    rationale: suggestion.rationale,
    confidence: Number(suggestion.confidence.toFixed(4)),
    expected_impact: {
      override_rate_reduction: Number(suggestion.expected_override_reduction.toFixed(4)),
      rework_rate_reduction: Number(suggestion.expected_rework_reduction.toFixed(4)),
    },
    evidence_count: suggestion.evidence_count,
    arena_count: suggestion.arena_count,
    outcome_count: suggestion.outcome_count,
    source_evidence: parseArenaContractCopilotSourceEvidence(suggestion.source_evidence_json),
    computed_at: suggestion.computed_at,
  };
}

async function computeArenaContractCopilot(
  db: D1Database,
  params: {
    taskFingerprint: string;
    limit: number;
    minOutcomes: number;
    minArenas: number;
    maxSuggestions: number;
  },
): Promise<{
  payload: Record<string, unknown>;
  suggestions: ArenaContractCopilotSuggestionRecord[];
}> {
  const outcomes = await listArenaOutcomes(db, params.limit);
  const runMap = await buildArenaRunMap(db, outcomes.map((row) => row.arena_id));

  const filtered = outcomes.filter((row) => {
    const run = runMap.get(row.arena_id);
    return Boolean(run && run.task_fingerprint === params.taskFingerprint);
  });

  const uniqueArenaIds = new Set(filtered.map((row) => row.arena_id));
  const reasonCodes: string[] = [];

  if (filtered.length < params.minOutcomes) {
    reasonCodes.push('ARENA_CONTRACT_COPILOT_INSUFFICIENT_OUTCOMES');
  }
  if (uniqueArenaIds.size < params.minArenas) {
    reasonCodes.push('ARENA_CONTRACT_COPILOT_INSUFFICIENT_ARENAS');
  }

  if (reasonCodes.length > 0) {
    return {
      payload: {
        schema_version: 'arena_contract_copilot.v1',
        status: 'INSUFFICIENT_SAMPLE',
        computed_at: new Date().toISOString(),
        task_fingerprint: params.taskFingerprint,
        minimums: {
          min_outcomes: params.minOutcomes,
          min_arenas: params.minArenas,
        },
        totals: {
          outcomes: filtered.length,
          arenas: uniqueArenaIds.size,
          failed_outcomes: 0,
          suggestions: 0,
        },
        reason_codes: reasonCodes,
        suggestions: [],
      },
      suggestions: [],
    };
  }

  const failed = filtered.filter((row) => isArenaFailedOutcome(row));
  if (failed.length === 0) {
    return {
      payload: {
        schema_version: 'arena_contract_copilot.v1',
        status: 'INSUFFICIENT_SAMPLE',
        computed_at: new Date().toISOString(),
        task_fingerprint: params.taskFingerprint,
        minimums: {
          min_outcomes: params.minOutcomes,
          min_arenas: params.minArenas,
        },
        totals: {
          outcomes: filtered.length,
          arenas: uniqueArenaIds.size,
          failed_outcomes: 0,
          suggestions: 0,
        },
        reason_codes: ['ARENA_CONTRACT_COPILOT_NO_FAILURE_SIGNAL'],
        suggestions: [],
      },
      suggestions: [],
    };
  }

  type EvidenceEntry = {
    arena_id: string;
    outcome_id: string;
    contender_id: string;
    criterion_id: string;
    reason_code: ArenaOverrideReasonCode;
    overridden: boolean;
    rework_required: boolean;
  };

  type Aggregate = {
    evidence: EvidenceEntry[];
    arenaIds: Set<string>;
    overrides: number;
    reworks: number;
    criterionCounts: Map<string, number>;
  };

  const ensureAggregate = (): Aggregate => ({
    evidence: [],
    arenaIds: new Set<string>(),
    overrides: 0,
    reworks: 0,
    criterionCounts: new Map<string, number>(),
  });

  const globalAggregates = new Map<ArenaOverrideReasonCode, Aggregate>();
  const contenderAggregates = new Map<string, Map<ArenaOverrideReasonCode, Aggregate>>();

  for (const row of failed) {
    const reasonCode = deriveArenaContractLanguageReasonCode(row);
    const criterionId = deriveArenaContractCopilotCriterionId(row, reasonCode);

    const evidence: EvidenceEntry = {
      arena_id: row.arena_id,
      outcome_id: row.outcome_id,
      contender_id: row.contender_id,
      criterion_id: criterionId,
      reason_code: reasonCode,
      overridden: row.overridden,
      rework_required: row.rework_required,
    };

    const update = (aggregate: Aggregate) => {
      aggregate.evidence.push(evidence);
      aggregate.arenaIds.add(row.arena_id);
      if (row.overridden) aggregate.overrides += 1;
      if (row.rework_required) aggregate.reworks += 1;
      aggregate.criterionCounts.set(criterionId, (aggregate.criterionCounts.get(criterionId) ?? 0) + 1);
    };

    const global = globalAggregates.get(reasonCode) ?? ensureAggregate();
    update(global);
    globalAggregates.set(reasonCode, global);

    const contenderMap = contenderAggregates.get(row.contender_id) ?? new Map<ArenaOverrideReasonCode, Aggregate>();
    const contenderAggregate = contenderMap.get(reasonCode) ?? ensureAggregate();
    update(contenderAggregate);
    contenderMap.set(reasonCode, contenderAggregate);
    contenderAggregates.set(row.contender_id, contenderMap);
  }

  const now = new Date().toISOString();
  const suggestions: ArenaContractCopilotSuggestionRecord[] = [];

  const topCriterionForAggregate = (aggregate: Aggregate): string => {
    const sorted = [...aggregate.criterionCounts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
    return sorted[0]?.[0] ?? 'acceptance_checklist';
  };

  const addSuggestion = async (
    scope: 'global' | 'contender',
    contenderId: string,
    reasonCode: ArenaOverrideReasonCode,
    aggregate: Aggregate,
  ) => {
    if (aggregate.evidence.length === 0) return;

    const evidenceCount = aggregate.evidence.length;
    const arenaCount = aggregate.arenaIds.size;
    const outcomeCount = evidenceCount;
    const overrideRate = evidenceCount > 0 ? aggregate.overrides / evidenceCount : 0;
    const reworkRate = evidenceCount > 0 ? aggregate.reworks / evidenceCount : 0;
    const criterionId = topCriterionForAggregate(aggregate);
    const reasonWeight = ARENA_OVERRIDE_REASON_REGISTRY[reasonCode].weight;

    const confidence = computeArenaContractCopilotConfidence({
      evidenceCount,
      arenaCount,
      overrideRate,
      reworkRate,
      reasonWeight,
    });

    const expectedImpact = computeArenaContractCopilotExpectedImpact({
      confidence,
      overrideRate,
      reworkRate,
    });

    const beforeText = buildArenaContractCopilotBeforeText({
      reasonCode,
      criterionId,
      evidenceCount,
      overrides: aggregate.overrides,
      reworks: aggregate.reworks,
    });

    const afterText = buildArenaContractCopilotAfterText({
      reasonCode,
      criterionId,
    });

    const rationale = buildArenaContractCopilotRationale({
      reasonCode,
      evidenceCount,
      arenaCount,
      overrides: aggregate.overrides,
      reworks: aggregate.reworks,
    });

    suggestions.push({
      suggestion_id: await buildArenaContractCopilotSuggestionId({
        taskFingerprint: params.taskFingerprint,
        scope,
        contenderId,
        reasonCode,
        criterionId,
      }),
      task_fingerprint: params.taskFingerprint,
      scope,
      contender_id: contenderId,
      reason_code: reasonCode,
      before_text: beforeText,
      after_text: afterText,
      rationale,
      confidence,
      expected_override_reduction: expectedImpact.expectedOverrideReduction,
      expected_rework_reduction: expectedImpact.expectedReworkReduction,
      evidence_count: evidenceCount,
      arena_count: arenaCount,
      outcome_count: outcomeCount,
      source_evidence_json: stableStringify(
        aggregate.evidence
          .slice(0, 24)
          .map((entry) => ({
            arena_id: entry.arena_id,
            outcome_id: entry.outcome_id,
            contender_id: entry.contender_id,
            criterion_id: entry.criterion_id,
            reason_code: entry.reason_code,
          })),
      ),
      computed_at: now,
      created_at: now,
      updated_at: now,
    });
  };

  const sortedGlobal = [...globalAggregates.entries()]
    .sort((a, b) => b[1].evidence.length - a[1].evidence.length || a[0].localeCompare(b[0]))
    .slice(0, 4);

  for (const [reasonCode, aggregate] of sortedGlobal) {
    await addSuggestion('global', '__global__', reasonCode, aggregate);
  }

  const contenderSuggestionCandidates: Array<{
    contenderId: string;
    reasonCode: ArenaOverrideReasonCode;
    aggregate: Aggregate;
  }> = [];

  for (const [contenderId, reasonMap] of contenderAggregates.entries()) {
    const topReasons = [...reasonMap.entries()]
      .sort((a, b) => b[1].evidence.length - a[1].evidence.length || a[0].localeCompare(b[0]))
      .slice(0, 2);

    for (const [reasonCode, aggregate] of topReasons) {
      contenderSuggestionCandidates.push({ contenderId, reasonCode, aggregate });
    }
  }

  contenderSuggestionCandidates
    .sort((a, b) => b.aggregate.evidence.length - a.aggregate.evidence.length || a.contenderId.localeCompare(b.contenderId));

  for (const candidate of contenderSuggestionCandidates.slice(0, Math.max(0, params.maxSuggestions - suggestions.length))) {
    await addSuggestion('contender', candidate.contenderId, candidate.reasonCode, candidate.aggregate);
  }

  const rankedSuggestions = suggestions
    .sort((a, b) => b.confidence - a.confidence || b.evidence_count - a.evidence_count || a.suggestion_id.localeCompare(b.suggestion_id))
    .slice(0, params.maxSuggestions);

  const status = rankedSuggestions.length >= 3 ? 'available' : 'INSUFFICIENT_SAMPLE';
  const payloadReasonCodes = status === 'available'
    ? ['ARENA_CONTRACT_COPILOT_READY']
    : ['ARENA_CONTRACT_COPILOT_INSUFFICIENT_SIGNAL_VARIETY'];

  return {
    payload: {
      schema_version: 'arena_contract_copilot.v1',
      status,
      computed_at: now,
      task_fingerprint: params.taskFingerprint,
      minimums: {
        min_outcomes: params.minOutcomes,
        min_arenas: params.minArenas,
      },
      totals: {
        outcomes: filtered.length,
        arenas: uniqueArenaIds.size,
        failed_outcomes: failed.length,
        suggestions: rankedSuggestions.length,
      },
      reason_codes: payloadReasonCodes,
      suggestions: rankedSuggestions.map((entry) => buildArenaContractCopilotSuggestionPayload(entry)),
    },
    suggestions: status === 'available' ? rankedSuggestions : [],
  };
}

async function computeAndPersistArenaContractCopilot(
  db: D1Database,
  params: {
    taskFingerprint: string;
    limit: number;
    minOutcomes: number;
    minArenas: number;
    maxSuggestions: number;
  },
): Promise<Record<string, unknown>> {
  const copilot = await computeArenaContractCopilot(db, params);
  await replaceArenaContractCopilotSuggestions(db, params.taskFingerprint, copilot.suggestions);

  return {
    ...copilot.payload,
    persistence: {
      table: 'bounty_arena_contract_copilot_suggestions',
      rows_written: copilot.suggestions.length,
      mode: 'replace_by_task_fingerprint',
    },
  };
}

async function buildArenaContractCopilotPreview(
  db: D1Database,
  taskFingerprint: string,
): Promise<Record<string, unknown>> {
  try {
    const rows = await listArenaContractCopilotSuggestions(db, {
      taskFingerprint,
      limit: 10,
    });

    const globalSuggestions = rows
      .filter((entry) => entry.scope === 'global')
      .map((entry) => buildArenaContractCopilotSuggestionPayload(entry));

    const contenderSuggestions = rows
      .filter((entry) => entry.scope === 'contender')
      .map((entry) => buildArenaContractCopilotSuggestionPayload(entry));

    return {
      schema_version: 'arena_contract_copilot_preview.v1',
      task_fingerprint: taskFingerprint,
      status: rows.length > 0 ? 'available' : 'empty',
      global_suggestions: globalSuggestions,
      contender_suggestions: contenderSuggestions,
    };
  } catch {
    return {
      schema_version: 'arena_contract_copilot_preview.v1',
      task_fingerprint: taskFingerprint,
      status: 'unavailable',
      global_suggestions: [],
      contender_suggestions: [],
    };
  }
}

async function handleGetArenaContractCopilot(
  request: Request,
  url: URL,
  env: Env,
  version: string,
): Promise<Response> {
  const adminError = requireAdmin(request, env, version);
  if (adminError) return adminError;

  const taskFingerprint = d1String(url.searchParams.get('task_fingerprint'))?.trim() ?? null;
  const contenderId = d1String(url.searchParams.get('contender_id'))?.trim() ?? null;

  const limitRaw = url.searchParams.get('limit');
  let limit = 100;
  if (isNonEmptyString(limitRaw)) {
    const parsed = Number.parseInt(limitRaw.trim(), 10);
    if (!Number.isFinite(parsed) || parsed <= 0) {
      return errorResponse('INVALID_REQUEST', 'limit must be a positive integer', 400, { field: 'limit' }, version);
    }
    limit = Math.min(parsed, 500);
  }

  const rows = await listArenaContractCopilotSuggestions(env.BOUNTIES_DB, {
    taskFingerprint,
    contenderId,
    limit,
  });

  return jsonResponse(
    {
      schema_version: 'arena_contract_copilot_store.v1',
      computed_at: new Date().toISOString(),
      task_fingerprint: taskFingerprint,
      contender_id: contenderId,
      status: rows.length > 0 ? 'available' : 'empty',
      totals: {
        suggestions: rows.length,
      },
      suggestions: rows.map((row) => buildArenaContractCopilotSuggestionPayload(row)),
    },
    200,
    version,
  );
}

async function handlePostArenaContractCopilot(
  request: Request,
  env: Env,
  version: string,
): Promise<Response> {
  const adminError = requireAdmin(request, env, version);
  if (adminError) return adminError;

  const body = await parseJsonBody(request);
  if (!isRecord(body)) {
    return errorResponse('INVALID_REQUEST', 'Invalid JSON body', 400, undefined, version);
  }

  const taskFingerprint = d1String(body.task_fingerprint)?.trim();
  if (!taskFingerprint || taskFingerprint.length > 256) {
    return errorResponse('INVALID_REQUEST', 'task_fingerprint is required (<=256 chars)', 400, { field: 'task_fingerprint' }, version);
  }

  const limitRaw = d1Number(body.limit);
  let limit = 1000;
  if (limitRaw !== null) {
    if (!Number.isInteger(limitRaw) || limitRaw <= 0) {
      return errorResponse('INVALID_REQUEST', 'limit must be a positive integer', 400, { field: 'limit' }, version);
    }
    limit = Math.min(limitRaw, 5000);
  }

  const minOutcomesRaw = d1Number(body.min_outcomes);
  let minOutcomes = 10;
  if (minOutcomesRaw !== null) {
    if (!Number.isInteger(minOutcomesRaw) || minOutcomesRaw <= 0) {
      return errorResponse('INVALID_REQUEST', 'min_outcomes must be a positive integer', 400, { field: 'min_outcomes' }, version);
    }
    minOutcomes = Math.min(minOutcomesRaw, 5000);
  }

  const minArenasRaw = d1Number(body.min_arenas);
  let minArenas = 3;
  if (minArenasRaw !== null) {
    if (!Number.isInteger(minArenasRaw) || minArenasRaw <= 0) {
      return errorResponse('INVALID_REQUEST', 'min_arenas must be a positive integer', 400, { field: 'min_arenas' }, version);
    }
    minArenas = Math.min(minArenasRaw, 200);
  }

  const maxSuggestionsRaw = d1Number(body.max_suggestions);
  let maxSuggestions = 12;
  if (maxSuggestionsRaw !== null) {
    if (!Number.isInteger(maxSuggestionsRaw) || maxSuggestionsRaw <= 0) {
      return errorResponse('INVALID_REQUEST', 'max_suggestions must be a positive integer', 400, { field: 'max_suggestions' }, version);
    }
    maxSuggestions = Math.min(maxSuggestionsRaw, 50);
  }

  const copilot = await computeAndPersistArenaContractCopilot(env.BOUNTIES_DB, {
    taskFingerprint,
    limit,
    minOutcomes,
    minArenas,
    maxSuggestions,
  });

  return jsonResponse(copilot, 200, version);
}

async function buildArenaContractLanguageOptimizerPreview(
  db: D1Database,
  taskFingerprint: string,
): Promise<Record<string, unknown>> {
  try {
    const rows = await listArenaContractLanguageSuggestions(db, {
      taskFingerprint,
      limit: 12,
    });

    const globalSuggestions = rows
      .filter((entry) => entry.scope === 'global')
      .map((entry) => buildArenaContractLanguageSuggestionPayload(entry));
    const contenderSuggestions = rows
      .filter((entry) => entry.scope === 'contender')
      .map((entry) => buildArenaContractLanguageSuggestionPayload(entry));

    return {
      schema_version: 'arena_contract_language_optimizer_preview.v1',
      task_fingerprint: taskFingerprint,
      status: rows.length > 0 ? 'available' : 'empty',
      global_suggestions: globalSuggestions,
      contender_suggestions: contenderSuggestions,
    };
  } catch {
    return {
      schema_version: 'arena_contract_language_optimizer_preview.v1',
      task_fingerprint: taskFingerprint,
      status: 'unavailable',
      global_suggestions: [],
      contender_suggestions: [],
    };
  }
}

async function handleGetArenaContractLanguageOptimizer(
  request: Request,
  url: URL,
  env: Env,
  version: string,
): Promise<Response> {
  const adminError = requireAdmin(request, env, version);
  if (adminError) return adminError;

  const taskFingerprint = d1String(url.searchParams.get('task_fingerprint'))?.trim() ?? null;
  const contenderId = d1String(url.searchParams.get('contender_id'))?.trim() ?? null;

  const limitRaw = url.searchParams.get('limit');
  let limit = 100;
  if (isNonEmptyString(limitRaw)) {
    const parsed = Number.parseInt(limitRaw.trim(), 10);
    if (!Number.isFinite(parsed) || parsed <= 0) {
      return errorResponse('INVALID_REQUEST', 'limit must be a positive integer', 400, { field: 'limit' }, version);
    }
    limit = Math.min(parsed, 500);
  }

  const rows = await listArenaContractLanguageSuggestions(env.BOUNTIES_DB, {
    taskFingerprint,
    contenderId,
    limit,
  });

  return jsonResponse(
    {
      schema_version: 'arena_contract_language_optimizer_store.v1',
      computed_at: new Date().toISOString(),
      task_fingerprint: taskFingerprint,
      contender_id: contenderId,
      totals: {
        suggestions: rows.length,
      },
      suggestions: rows.map((row) => buildArenaContractLanguageSuggestionPayload(row)),
    },
    200,
    version,
  );
}

async function handlePostArenaContractLanguageOptimizer(
  request: Request,
  env: Env,
  version: string,
): Promise<Response> {
  const adminError = requireAdmin(request, env, version);
  if (adminError) return adminError;

  const body = await parseJsonBody(request);
  if (!isRecord(body)) {
    return errorResponse('INVALID_REQUEST', 'Invalid JSON body', 400, undefined, version);
  }

  const taskFingerprint = d1String(body.task_fingerprint)?.trim();
  if (!taskFingerprint || taskFingerprint.length > 256) {
    return errorResponse('INVALID_REQUEST', 'task_fingerprint is required (<=256 chars)', 400, { field: 'task_fingerprint' }, version);
  }

  const limitRaw = d1Number(body.limit);
  let limit = 500;
  if (limitRaw !== null) {
    if (!Number.isInteger(limitRaw) || limitRaw <= 0) {
      return errorResponse('INVALID_REQUEST', 'limit must be a positive integer', 400, { field: 'limit' }, version);
    }
    limit = Math.min(limitRaw, 5000);
  }

  const optimizer = await computeAndPersistArenaContractLanguageOptimizer(env.BOUNTIES_DB, {
    taskFingerprint,
    limit,
  });

  return jsonResponse(optimizer, 200, version);
}

function parseArenaRoutePolicyJson(input: string | null): Record<string, unknown> | null {
  if (!input) return null;
  return parseJsonObject(input);
}

function parseArenaPolicyReasonCodes(input: string): string[] {
  return parseJsonStringArray(input) ?? [];
}

function parseArenaRunReasonCodes(input: string | null): string[] {
  if (!input) return [];
  return parseJsonStringArray(input) ?? [];
}

function arenaRunHasUnresolvedReasonCode(run: ArenaRunRecord): boolean {
  const reasonCodes = parseArenaRunReasonCodes(run.reason_codes_json);
  return reasonCodes.some((code) => code.startsWith('ARENA_RESOLVE_UNRESOLVED_'));
}

function isArenaRunRoutingEligible(run: ArenaRunRecord): boolean {
  if (run.status !== 'completed') return false;
  if (!run.winner_contender_id) return false;
  if (arenaRunHasUnresolvedReasonCode(run)) return false;
  return true;
}

function parseIsoTimestamp(value: string): number | null {
  const epochMs = Date.parse(value);
  if (!Number.isFinite(epochMs)) return null;
  return epochMs;
}

function computeP95MinutesFromDurations(minutes: number[]): number {
  if (minutes.length === 0) return 0;
  const sorted = [...minutes].sort((a, b) => a - b);
  const idx = Math.max(0, Math.min(sorted.length - 1, Math.ceil(sorted.length * 0.95) - 1));
  return Number((sorted[idx] ?? 0).toFixed(2));
}

function computeArenaPolicyOptimizerConfidence(params: {
  winRate: number;
  acceptRate: number;
  overrideRate: number;
  reworkRate: number;
  calibrationGap: number;
}): number {
  const reliability = 1 - Math.min(1, Math.max(0, params.overrideRate) + Math.max(0, params.reworkRate));
  const calibrationQuality = 1 - Math.min(1, Math.abs(params.calibrationGap));

  const score =
    (Math.max(0, params.winRate) * 0.35) +
    (Math.max(0, params.acceptRate) * 0.35) +
    (Math.max(0, reliability) * 0.2) +
    (Math.max(0, calibrationQuality) * 0.1);

  return Number(Math.max(0, Math.min(1, score)).toFixed(4));
}

function buildArenaPolicyOptimizerPayloadFromState(
  state: ArenaRoutePolicyOptimizerStateRecord,
): Record<string, unknown> {
  return {
    schema_version: 'arena_policy_optimizer.v1',
    computed_at: state.updated_at,
    task_fingerprint: state.task_fingerprint,
    environment: state.environment,
    objective_profile_name: state.objective_profile_name || null,
    experiment_id: state.experiment_id || null,
    experiment_arm: state.experiment_arm || null,
    gates: {
      min_samples: state.min_samples,
      min_confidence: Number(state.min_confidence.toFixed(4)),
      sample_count: state.sample_count,
      confidence_score: Number(state.confidence_score.toFixed(4)),
    },
    current_active_policy: parseArenaRoutePolicyJson(state.active_policy_json),
    candidate_shadow_policy: parseArenaRoutePolicyJson(state.shadow_policy_json),
    promotion: parseArenaRoutePolicyJson(state.last_promotion_event_json),
    reason_codes: parseArenaPolicyReasonCodes(state.reason_codes_json),
    promotion_status: state.promotion_status,
  };
}

async function handlePostArenaFleetWorkerRegister(
  request: Request,
  env: Env,
  version: string,
): Promise<Response> {
  const adminError = requireAdmin(request, env, version);
  if (adminError) return adminError;

  const body = await parseJsonBody(request);
  if (!isRecord(body)) {
    return errorResponse('INVALID_REQUEST', 'Invalid JSON body', 400, undefined, version);
  }

  const workerDid = d1String(body.worker_did)?.trim();
  const harness = d1String(body.harness)?.trim();
  const model = d1String(body.model)?.trim();
  const skills = parseStringList(body.skills, 80, 120, true);
  const tools = parseStringList(body.tools, 80, 120, true);
  const objectiveProfiles = parseStringList(body.objective_profiles, 40, 120, true);
  const costTier = parseArenaFleetCostTier(body.cost_tier ?? 'medium');
  const riskTier = parseArenaFleetRiskTier(body.risk_tier ?? 'medium');
  const availabilityStatus = parseArenaFleetAvailabilityStatus(body.availability_status ?? 'online');
  const metadata = isRecord(body.metadata) ? body.metadata : null;
  const touchHeartbeat = body.touch_heartbeat !== false;

  if (!workerDid || !workerDid.startsWith('did:')) {
    return errorResponse('INVALID_REQUEST', 'worker_did must be a DID string', 400, { field: 'worker_did' }, version);
  }

  if (!harness || harness.length > 80) {
    return errorResponse('INVALID_REQUEST', 'harness is required (<=80 chars)', 400, { field: 'harness' }, version);
  }

  if (!model || model.length > 200) {
    return errorResponse('INVALID_REQUEST', 'model is required (<=200 chars)', 400, { field: 'model' }, version);
  }

  if (!skills || !tools || !objectiveProfiles || !costTier || !riskTier || !availabilityStatus) {
    return errorResponse('INVALID_REQUEST', 'skills/tools/objective_profiles/cost_tier/risk_tier/availability_status are invalid', 400, undefined, version);
  }

  const now = new Date().toISOString();
  const existing = await getArenaHarnessFleetWorker(env.BOUNTIES_DB, workerDid);

  const record: ArenaHarnessFleetWorkerRecord = {
    worker_did: workerDid,
    harness,
    model,
    skills_json: stableStringify(skills),
    tools_json: stableStringify(tools),
    objective_profiles_json: stableStringify(objectiveProfiles),
    cost_tier: costTier,
    risk_tier: riskTier,
    availability_status: availabilityStatus,
    heartbeat_at: touchHeartbeat ? now : (existing?.heartbeat_at ?? null),
    heartbeat_seq: existing ? existing.heartbeat_seq + (touchHeartbeat ? 1 : 0) : (touchHeartbeat ? 1 : 0),
    metadata_json: metadata ? stableStringify(metadata) : null,
    created_at: existing?.created_at ?? now,
    updated_at: now,
  };

  await upsertArenaHarnessFleetWorker(env.BOUNTIES_DB, record);
  const saved = await getArenaHarnessFleetWorker(env.BOUNTIES_DB, workerDid);

  if (!saved) {
    return errorResponse('DB_WRITE_FAILED', 'Fleet worker could not be loaded after write', 500, undefined, version);
  }

  return jsonResponse(
    {
      ok: true,
      replay: existing !== null,
      worker: buildArenaHarnessFleetWorkerPayload(saved),
    },
    existing ? 200 : 201,
    version,
  );
}

async function handlePostArenaFleetWorkerHeartbeat(
  request: Request,
  env: Env,
  version: string,
): Promise<Response> {
  const adminError = requireAdmin(request, env, version);
  if (adminError) return adminError;

  const body = await parseJsonBody(request);
  if (!isRecord(body)) {
    return errorResponse('INVALID_REQUEST', 'Invalid JSON body', 400, undefined, version);
  }

  const workerDid = d1String(body.worker_did)?.trim();
  const availabilityStatus = parseArenaFleetAvailabilityStatus(body.availability_status ?? 'online');
  const metadata = isRecord(body.metadata) ? body.metadata : null;

  if (!workerDid || !workerDid.startsWith('did:')) {
    return errorResponse('INVALID_REQUEST', 'worker_did must be a DID string', 400, { field: 'worker_did' }, version);
  }

  if (!availabilityStatus) {
    return errorResponse('INVALID_REQUEST', 'availability_status must be online|offline|paused', 400, { field: 'availability_status' }, version);
  }

  const existing = await getArenaHarnessFleetWorker(env.BOUNTIES_DB, workerDid);
  if (!existing) {
    return errorResponse('NOT_FOUND', 'Fleet worker not found', 404, { worker_did: workerDid }, version);
  }

  const now = new Date().toISOString();
  const updated = await heartbeatArenaHarnessFleetWorker(env.BOUNTIES_DB, {
    workerDid,
    availabilityStatus,
    metadataJson: metadata ? stableStringify(metadata) : null,
    now,
  });

  if (!updated) {
    return errorResponse('DB_WRITE_FAILED', 'Fleet worker heartbeat update failed', 500, undefined, version);
  }

  return jsonResponse(
    {
      ok: true,
      worker: buildArenaHarnessFleetWorkerPayload(updated),
    },
    200,
    version,
  );
}

async function handleListArenaFleetWorkers(
  request: Request,
  url: URL,
  env: Env,
  version: string,
): Promise<Response> {
  const adminError = requireAdmin(request, env, version);
  if (adminError) return adminError;

  const limitRaw = url.searchParams.get('limit');
  let limit = 50;
  if (isNonEmptyString(limitRaw)) {
    const parsed = Number.parseInt(limitRaw.trim(), 10);
    if (!Number.isFinite(parsed) || parsed <= 0) {
      return errorResponse('INVALID_REQUEST', 'limit must be a positive integer', 400, { field: 'limit' }, version);
    }
    limit = Math.min(parsed, 200);
  }

  const availabilityStatusRaw = d1String(url.searchParams.get('availability_status'))?.trim() ?? null;
  const harness = d1String(url.searchParams.get('harness'))?.trim() ?? null;
  const objectiveProfileName = d1String(url.searchParams.get('objective_profile_name'))?.trim() ?? null;
  const costTierRaw = d1String(url.searchParams.get('cost_tier'))?.trim() ?? null;
  const riskTierRaw = d1String(url.searchParams.get('risk_tier'))?.trim() ?? null;

  const availabilityStatus = availabilityStatusRaw ? parseArenaFleetAvailabilityStatus(availabilityStatusRaw) : null;
  const costTier = costTierRaw ? parseArenaFleetCostTier(costTierRaw) : null;
  const riskTier = riskTierRaw ? parseArenaFleetRiskTier(riskTierRaw) : null;

  if (availabilityStatusRaw && !availabilityStatus) {
    return errorResponse('INVALID_REQUEST', 'availability_status must be online|offline|paused', 400, { field: 'availability_status' }, version);
  }

  if (costTierRaw && !costTier) {
    return errorResponse('INVALID_REQUEST', 'cost_tier must be low|medium|high', 400, { field: 'cost_tier' }, version);
  }

  if (riskTierRaw && !riskTier) {
    return errorResponse('INVALID_REQUEST', 'risk_tier must be low|medium|high', 400, { field: 'risk_tier' }, version);
  }

  const workers = await listArenaHarnessFleetWorkers(env.BOUNTIES_DB, {
    limit,
    availabilityStatus,
    harness,
    objectiveProfileName,
    costTier,
    riskTier,
  });

  return jsonResponse(
    {
      schema_version: 'arena_harness_fleet_workers.v1',
      computed_at: new Date().toISOString(),
      filters: {
        availability_status: availabilityStatus,
        harness,
        objective_profile_name: objectiveProfileName,
        cost_tier: costTier,
        risk_tier: riskTier,
        limit,
      },
      totals: {
        workers: workers.length,
      },
      workers: workers.map((worker) => buildArenaHarnessFleetWorkerPayload(worker)),
    },
    200,
    version,
  );
}

async function handlePostArenaFleetMatch(
  request: Request,
  env: Env,
  version: string,
): Promise<Response> {
  const adminError = requireAdmin(request, env, version);
  if (adminError) return adminError;

  const body = await parseJsonBody(request);
  if (!isRecord(body)) {
    return errorResponse('INVALID_REQUEST', 'Invalid JSON body', 400, undefined, version);
  }

  const objectiveProfileName = d1String(body.objective_profile_name)?.trim() ?? null;
  const harness = d1String(body.harness)?.trim() ?? null;
  const contenderId = d1String(body.contender_id)?.trim() ?? null;
  const requiredSkills = parseStringList(body.required_skills, 40, 120, true);
  const requiredTools = parseStringList(body.required_tools, 40, 120, true);
  const maxCostTier = body.max_cost_tier === undefined || body.max_cost_tier === null
    ? null
    : parseArenaFleetCostTier(body.max_cost_tier);
  const maxRiskTier = body.max_risk_tier === undefined || body.max_risk_tier === null
    ? null
    : parseArenaFleetRiskTier(body.max_risk_tier);

  let limit = 5;
  const limitRaw = body.limit;
  if (limitRaw !== undefined && limitRaw !== null) {
    const parsed = d1Number(limitRaw);
    if (parsed === null || !Number.isInteger(parsed) || parsed <= 0) {
      return errorResponse('INVALID_REQUEST', 'limit must be a positive integer', 400, { field: 'limit' }, version);
    }
    limit = Math.min(parsed, 20);
  }

  if (!requiredSkills || !requiredTools) {
    return errorResponse('INVALID_REQUEST', 'required_skills/required_tools must be string[]', 400, undefined, version);
  }

  if (body.max_cost_tier !== undefined && body.max_cost_tier !== null && !maxCostTier) {
    return errorResponse('INVALID_REQUEST', 'max_cost_tier must be low|medium|high', 400, { field: 'max_cost_tier' }, version);
  }

  if (body.max_risk_tier !== undefined && body.max_risk_tier !== null && !maxRiskTier) {
    return errorResponse('INVALID_REQUEST', 'max_risk_tier must be low|medium|high', 400, { field: 'max_risk_tier' }, version);
  }

  const payload = await computeArenaFleetCapabilityMatch(env.BOUNTIES_DB, {
    objectiveProfileName,
    harness,
    contenderId,
    requiredSkills,
    requiredTools,
    maxCostTier,
    maxRiskTier,
    limit,
  });

  return jsonResponse(payload, 200, version);
}

function parseArenaAutoClaimLockStatus(raw: unknown): ArenaAutoClaimLockRecord['claim_status'] | null {
  if (raw === 'processing' || raw === 'claimed' || raw === 'skipped' || raw === 'failed') {
    return raw;
  }

  return null;
}

function mapArenaAutoClaimFailureReason(message: string): string {
  if (message.includes('ESCROW_FAILED:409')) return 'ARENA_AUTOCLAIM_ESCROW_CONFLICT';
  if (message.includes('ESCROW_FAILED:401')) return 'ARENA_AUTOCLAIM_ESCROW_UNAUTHORIZED';
  if (message.includes('ESCROW_SERVICE_KEY_NOT_CONFIGURED')) return 'ARENA_AUTOCLAIM_ESCROW_NOT_CONFIGURED';
  if (message.includes('BOUNTY_ACCEPT_STATE_MISMATCH')) return 'ARENA_AUTOCLAIM_STATE_MISMATCH';
  return 'ARENA_AUTOCLAIM_CLAIM_FAILED';
}

async function isWorkerRegisteredForArenaAutoClaim(db: D1Database, workerDid: string): Promise<boolean> {
  const row = await db.prepare('SELECT worker_did FROM workers WHERE worker_did = ?').bind(workerDid).first();
  return !!(isRecord(row) && d1String(row.worker_did)?.trim() === workerDid);
}

async function resolveArenaAutoClaimRouteSelection(
  env: Env,
  version: string,
  params: {
    bounty: BountyV2;
    objectiveProfileName: string | null;
    maxFleetCostTier: ArenaFleetCostTier | null;
    maxFleetRiskTier: ArenaFleetRiskTier | null;
    allowRouteFallback: boolean;
  },
): Promise<{
  source: 'route' | 'fleet_fallback' | 'none';
  contenderId: string | null;
  workerDid: string | null;
  routeReasonCodes: string[];
  fleetStatus: string;
}> {
  const objectiveFromBounty = buildLiveArenaObjectiveProfile(params.bounty);
  const objectiveProfileName = params.objectiveProfileName ?? d1String(objectiveFromBounty.name)?.trim() ?? null;
  const requiredSkills = params.bounty.tags.slice(0, 6).map((tag) => tag.trim().toLowerCase()).filter((tag) => tag.length > 0);
  const requiredTools = ['bash'];

  let contenderId: string | null = null;
  let contenderHarness: string | null = null;
  let routeReasonCodes: string[] = [];

  if (env.BOUNTIES_ADMIN_KEY && env.BOUNTIES_ADMIN_KEY.trim().length > 0) {
    const routeBody = {
      task_fingerprint: deriveLiveArenaTaskFingerprint(params.bounty),
      objective_profile_name: objectiveProfileName ?? undefined,
      required_skills: requiredSkills,
      required_tools: requiredTools,
      max_fleet_cost_tier: params.maxFleetCostTier ?? undefined,
      max_fleet_risk_tier: params.maxFleetRiskTier ?? undefined,
      allow_fallback: true,
      require_hard_gate_pass: true,
      use_active_policy: true,
    };

    const internalRouteRequest = new Request('https://internal/v1/arena/manager/route', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-admin-key': env.BOUNTIES_ADMIN_KEY,
      },
      body: stableStringify(routeBody),
    });

    const routeResponse = await handleArenaManagerRoute(internalRouteRequest, env, version, 'route');
    if (routeResponse.status === 200) {
      const routePayload = await routeResponse.json();
      if (isRecord(routePayload)) {
        const recommended = isRecord(routePayload.recommended) ? routePayload.recommended : null;
        const contenderSnapshot = recommended && isRecord(recommended.contender_snapshot) ? recommended.contender_snapshot : null;
        contenderId = d1String(recommended?.contender_id)?.trim() ?? null;
        contenderHarness = d1String(contenderSnapshot?.harness)?.trim() ?? null;

        const reasonCodes = parseStringList(routePayload.reason_codes, 120, 160, true);
        routeReasonCodes = reasonCodes ?? [];

        const fleetMatch = isRecord(routePayload.fleet_match) ? routePayload.fleet_match : null;
        const candidates = Array.isArray(fleetMatch?.candidates) ? fleetMatch.candidates : [];
        for (const candidate of candidates) {
          if (!isRecord(candidate)) continue;
          const workerDid = d1String(candidate.worker_did)?.trim() ?? null;
          if (!workerDid) continue;
          const isRegisteredWorker = await isWorkerRegisteredForArenaAutoClaim(env.BOUNTIES_DB, workerDid);
          if (!isRegisteredWorker) {
            routeReasonCodes = [...routeReasonCodes, 'ARENA_AUTOCLAIM_WORKER_NOT_REGISTERED'];
            continue;
          }
          return {
            source: 'route',
            contenderId,
            workerDid,
            routeReasonCodes,
            fleetStatus: d1String(fleetMatch?.status) ?? 'matched',
          };
        }
      }
    } else {
      routeReasonCodes = ['ARENA_AUTOCLAIM_ROUTE_UNAVAILABLE'];
    }
  } else {
    routeReasonCodes = ['ARENA_AUTOCLAIM_ADMIN_KEY_UNAVAILABLE'];
  }

  if (!params.allowRouteFallback) {
    return {
      source: 'none',
      contenderId,
      workerDid: null,
      routeReasonCodes,
      fleetStatus: 'unmatched',
    };
  }

  const fallbackMatch = await computeArenaFleetCapabilityMatch(env.BOUNTIES_DB, {
    objectiveProfileName,
    harness: contenderHarness,
    contenderId,
    requiredSkills,
    requiredTools,
    maxCostTier: params.maxFleetCostTier,
    maxRiskTier: params.maxFleetRiskTier,
    limit: 3,
  });

  const fallbackStatus = d1String(fallbackMatch.status) ?? 'unmatched';
  const fallbackReasonCodes = parseStringList(fallbackMatch.reason_codes, 120, 160, true) ?? [];
  const fallbackCandidatesRaw = Array.isArray(fallbackMatch.candidates) ? fallbackMatch.candidates : [];
  let fallbackWorker: string | null = null;
  for (const candidate of fallbackCandidatesRaw) {
    if (!isRecord(candidate)) continue;
    const workerDid = d1String(candidate.worker_did)?.trim() ?? null;
    if (!workerDid) continue;
    const isRegisteredWorker = await isWorkerRegisteredForArenaAutoClaim(env.BOUNTIES_DB, workerDid);
    if (!isRegisteredWorker) {
      fallbackReasonCodes.push('ARENA_AUTOCLAIM_WORKER_NOT_REGISTERED');
      continue;
    }
    fallbackWorker = workerDid;
    break;
  }

  if (fallbackWorker) {
    return {
      source: 'fleet_fallback',
      contenderId,
      workerDid: fallbackWorker,
      routeReasonCodes: [...routeReasonCodes, ...fallbackReasonCodes, 'ARENA_AUTOCLAIM_FLEET_FALLBACK'],
      fleetStatus: fallbackStatus,
    };
  }

  return {
    source: 'none',
    contenderId,
    workerDid: null,
    routeReasonCodes: [...routeReasonCodes, ...fallbackReasonCodes, 'ARENA_AUTOCLAIM_NO_ELIGIBLE_WORKER'],
    fleetStatus: fallbackStatus,
  };
}

const ARENA_MISSION_DEFAULT_WINDOW_HOURS = 24;
const ARENA_MISSION_DEFAULT_THRESHOLDS = Object.freeze({
  min_online_workers: 3,
  min_claim_success_rate: 0.8,
  min_submission_success_rate: 0.8,
  min_proof_valid_rate: 0.95,
  max_claim_submission_gap: 5,
  max_accepted_backlog: 5,
});

type ArenaMissionKpiThresholds = {
  min_online_workers: number;
  min_claim_success_rate: number;
  min_submission_success_rate: number;
  min_proof_valid_rate: number;
  max_claim_submission_gap: number;
  max_accepted_backlog: number;
};

function asCount(value: unknown): number {
  const numeric = d1Number(value);
  if (numeric !== null && Number.isFinite(numeric)) {
    return Math.max(0, Math.trunc(numeric));
  }

  const asText = d1String(value);
  if (asText) {
    const parsed = Number.parseInt(asText, 10);
    if (Number.isFinite(parsed)) return Math.max(0, parsed);
  }

  return 0;
}

function computeRatio(numerator: number, denominator: number): number | null {
  if (!Number.isFinite(numerator) || !Number.isFinite(denominator) || denominator <= 0) return null;
  return Number((numerator / denominator).toFixed(4));
}

function parseArenaMissionWindowHours(raw: string | null): number | null {
  if (!raw || raw.trim().length === 0) return ARENA_MISSION_DEFAULT_WINDOW_HOURS;
  const parsed = Number.parseInt(raw.trim(), 10);
  if (!Number.isFinite(parsed) || parsed <= 0) return null;
  return Math.min(parsed, 24 * 30);
}

function parseArenaMissionThresholds(body: Record<string, unknown>): {
  thresholds: ArenaMissionKpiThresholds | null;
  errorField: string | null;
  errorMessage: string | null;
} {
  const minOnlineWorkersRaw = d1Number(body.min_online_workers);
  const minClaimSuccessRateRaw = d1Number(body.min_claim_success_rate);
  const minSubmissionSuccessRateRaw = d1Number(body.min_submission_success_rate);
  const minProofValidRateRaw = d1Number(body.min_proof_valid_rate);
  const maxClaimSubmissionGapRaw = d1Number(body.max_claim_submission_gap);
  const maxAcceptedBacklogRaw = d1Number(body.max_accepted_backlog);

  const thresholds: ArenaMissionKpiThresholds = {
    min_online_workers: ARENA_MISSION_DEFAULT_THRESHOLDS.min_online_workers,
    min_claim_success_rate: ARENA_MISSION_DEFAULT_THRESHOLDS.min_claim_success_rate,
    min_submission_success_rate: ARENA_MISSION_DEFAULT_THRESHOLDS.min_submission_success_rate,
    min_proof_valid_rate: ARENA_MISSION_DEFAULT_THRESHOLDS.min_proof_valid_rate,
    max_claim_submission_gap: ARENA_MISSION_DEFAULT_THRESHOLDS.max_claim_submission_gap,
    max_accepted_backlog: ARENA_MISSION_DEFAULT_THRESHOLDS.max_accepted_backlog,
  };

  if (minOnlineWorkersRaw !== null) {
    if (!Number.isInteger(minOnlineWorkersRaw) || minOnlineWorkersRaw <= 0) {
      return { thresholds: null, errorField: 'min_online_workers', errorMessage: 'min_online_workers must be a positive integer' };
    }
    thresholds.min_online_workers = Math.min(minOnlineWorkersRaw, 1000);
  }

  if (minClaimSuccessRateRaw !== null) {
    if (!Number.isFinite(minClaimSuccessRateRaw) || minClaimSuccessRateRaw < 0 || minClaimSuccessRateRaw > 1) {
      return { thresholds: null, errorField: 'min_claim_success_rate', errorMessage: 'min_claim_success_rate must be within [0,1]' };
    }
    thresholds.min_claim_success_rate = Number(minClaimSuccessRateRaw.toFixed(4));
  }

  if (minSubmissionSuccessRateRaw !== null) {
    if (!Number.isFinite(minSubmissionSuccessRateRaw) || minSubmissionSuccessRateRaw < 0 || minSubmissionSuccessRateRaw > 1) {
      return { thresholds: null, errorField: 'min_submission_success_rate', errorMessage: 'min_submission_success_rate must be within [0,1]' };
    }
    thresholds.min_submission_success_rate = Number(minSubmissionSuccessRateRaw.toFixed(4));
  }

  if (minProofValidRateRaw !== null) {
    if (!Number.isFinite(minProofValidRateRaw) || minProofValidRateRaw < 0 || minProofValidRateRaw > 1) {
      return { thresholds: null, errorField: 'min_proof_valid_rate', errorMessage: 'min_proof_valid_rate must be within [0,1]' };
    }
    thresholds.min_proof_valid_rate = Number(minProofValidRateRaw.toFixed(4));
  }

  if (maxClaimSubmissionGapRaw !== null) {
    if (!Number.isInteger(maxClaimSubmissionGapRaw) || maxClaimSubmissionGapRaw < 0) {
      return { thresholds: null, errorField: 'max_claim_submission_gap', errorMessage: 'max_claim_submission_gap must be >= 0' };
    }
    thresholds.max_claim_submission_gap = Math.min(maxClaimSubmissionGapRaw, 10_000);
  }

  if (maxAcceptedBacklogRaw !== null) {
    if (!Number.isInteger(maxAcceptedBacklogRaw) || maxAcceptedBacklogRaw < 0) {
      return { thresholds: null, errorField: 'max_accepted_backlog', errorMessage: 'max_accepted_backlog must be >= 0' };
    }
    thresholds.max_accepted_backlog = Math.min(maxAcceptedBacklogRaw, 10_000);
  }

  return {
    thresholds,
    errorField: null,
    errorMessage: null,
  };
}

type ArenaDeskDecisionMode = 'approve_valid' | 'reject_invalid' | 'mixed';

function parseArenaDeskDecisionMode(raw: unknown): ArenaDeskDecisionMode | null {
  if (!isNonEmptyString(raw)) return 'approve_valid';
  const normalized = raw.trim().toLowerCase();
  if (normalized === 'approve_valid' || normalized === 'reject_invalid' || normalized === 'mixed') {
    return normalized;
  }
  return null;
}

async function buildArenaMissionSummary(
  db: D1Database,
  params: {
    workerDid: string;
    windowHours: number;
    thresholds: ArenaMissionKpiThresholds;
  },
): Promise<Record<string, unknown>> {
  const since = new Date(Date.now() - (params.windowHours * 60 * 60 * 1000)).toISOString();

  const fleetRows = await db
    .prepare(
      `SELECT availability_status, COUNT(*) AS count
         FROM bounty_arena_harness_fleet_workers
        GROUP BY availability_status`
    )
    .all<Record<string, unknown>>();

  const fleetTotals = {
    total: 0,
    online: 0,
    offline: 0,
    paused: 0,
  };

  for (const row of fleetRows.results ?? []) {
    if (!isRecord(row)) continue;
    const status = d1String(row.availability_status);
    const count = asCount(row.count);
    fleetTotals.total += count;
    if (status === 'online') fleetTotals.online += count;
    if (status === 'offline') fleetTotals.offline += count;
    if (status === 'paused') fleetTotals.paused += count;
  }

  const claimRows = await db
    .prepare(
      `SELECT claim_status, COUNT(*) AS count
         FROM bounty_arena_auto_claim_locks
        WHERE created_at >= ?
        GROUP BY claim_status`
    )
    .bind(since)
    .all<Record<string, unknown>>();

  const claimsWindow = {
    processing: 0,
    claimed: 0,
    skipped: 0,
    failed: 0,
    total: 0,
  };

  for (const row of claimRows.results ?? []) {
    if (!isRecord(row)) continue;
    const status = d1String(row.claim_status);
    const count = asCount(row.count);
    claimsWindow.total += count;
    if (status === 'processing') claimsWindow.processing += count;
    if (status === 'claimed') claimsWindow.claimed += count;
    if (status === 'skipped') claimsWindow.skipped += count;
    if (status === 'failed') claimsWindow.failed += count;
  }

  const claimedRows = await db
    .prepare(
      `SELECT bounty_id
         FROM bounty_arena_auto_claim_locks
        WHERE created_at >= ?
          AND claim_status = 'claimed'
        ORDER BY created_at DESC
        LIMIT 600`
    )
    .bind(since)
    .all<Record<string, unknown>>();

  const claimedBountyIds = dedupeStrings(
    (claimedRows.results ?? [])
      .map((row) => (isRecord(row) ? d1String(row.bounty_id)?.trim() ?? '' : ''))
      .filter((entry) => entry.length > 0)
  );

  const submissionsWindow = {
    total: claimedBountyIds.length,
    with_submission: 0,
    pending_review_valid: 0,
    pending_review_invalid: 0,
    approved: 0,
    rejected: 0,
    proof_valid: 0,
    proof_invalid: 0,
  };

  if (claimedBountyIds.length > 0) {
    const placeholders = claimedBountyIds.map(() => '?').join(', ');
    const submissionRows = await db
      .prepare(
        `SELECT
            bounty_id,
            MAX(CASE WHEN status = 'pending_review' AND proof_verify_status = 'valid' THEN 1 ELSE 0 END) AS has_pending_review_valid,
            MAX(CASE WHEN status = 'pending_review' AND proof_verify_status = 'invalid' THEN 1 ELSE 0 END) AS has_pending_review_invalid,
            MAX(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) AS has_approved,
            MAX(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) AS has_rejected,
            MAX(CASE WHEN proof_verify_status = 'valid' THEN 1 ELSE 0 END) AS has_valid_proof,
            MAX(CASE WHEN proof_verify_status = 'invalid' THEN 1 ELSE 0 END) AS has_invalid_proof
          FROM submissions
         WHERE bounty_id IN (${placeholders})
         GROUP BY bounty_id`
      )
      .bind(...claimedBountyIds)
      .all<Record<string, unknown>>();

    const submissionByBounty = new Map<string, Record<string, unknown>>();
    for (const row of submissionRows.results ?? []) {
      if (!isRecord(row)) continue;
      const bountyId = d1String(row.bounty_id)?.trim() ?? null;
      if (!bountyId) continue;
      submissionByBounty.set(bountyId, row);
    }

    for (const bountyId of claimedBountyIds) {
      const row = submissionByBounty.get(bountyId);
      if (!row) continue;

      const hasPendingValid = asCount(row.has_pending_review_valid) > 0;
      const hasPendingInvalid = asCount(row.has_pending_review_invalid) > 0;
      const hasApproved = asCount(row.has_approved) > 0;
      const hasRejected = asCount(row.has_rejected) > 0;
      const hasValidProof = asCount(row.has_valid_proof) > 0;
      const hasInvalidProof = asCount(row.has_invalid_proof) > 0;
      const hasActionableSubmission = hasPendingValid || hasPendingInvalid || hasApproved || hasRejected;

      if (hasActionableSubmission) submissionsWindow.with_submission += 1;
      if (hasPendingValid) submissionsWindow.pending_review_valid += 1;
      if (hasPendingInvalid) submissionsWindow.pending_review_invalid += 1;
      if (hasApproved) submissionsWindow.approved += 1;
      if (hasRejected) submissionsWindow.rejected += 1;

      if (hasValidProof) {
        submissionsWindow.proof_valid += 1;
      } else if (hasInvalidProof) {
        submissionsWindow.proof_invalid += 1;
      }
    }
  }

  const backlogRow = await db
    .prepare(
      `SELECT
          COUNT(*) AS accepted_total,
          SUM(CASE WHEN NOT EXISTS (
            SELECT 1
              FROM submissions s
             WHERE s.bounty_id = b.bounty_id
               AND s.proof_verify_status = 'valid'
          ) THEN 1 ELSE 0 END) AS accepted_without_valid_submission
        FROM bounties b
       WHERE b.status = 'accepted'
         AND b.is_code_bounty = 0
         AND b.accepted_at >= ?`
    )
    .bind(since)
    .first<Record<string, unknown>>();

  const claimGapRows = await db
    .prepare(
      `SELECT l.bounty_id
         FROM bounty_arena_auto_claim_locks l
        WHERE l.claim_status = 'claimed'
          AND l.created_at >= ?
          AND NOT EXISTS (
            SELECT 1
              FROM submissions s
             WHERE s.bounty_id = l.bounty_id
               AND s.proof_verify_status = 'valid'
          )
        ORDER BY l.created_at DESC
        LIMIT 200`
    )
    .bind(since)
    .all<Record<string, unknown>>();

  const claimGapBountyIds = dedupeStrings(
    (claimGapRows.results ?? [])
      .map((row) => (isRecord(row) ? d1String(row.bounty_id)?.trim() ?? '' : ''))
      .filter((entry) => entry.length > 0)
  );

  const claimSuccessRate = computeRatio(claimsWindow.claimed, claimsWindow.claimed + claimsWindow.failed);
  const submissionSuccessRate = computeRatio(submissionsWindow.with_submission, submissionsWindow.total);
  const proofValidRate = computeRatio(submissionsWindow.proof_valid, submissionsWindow.with_submission);

  const claimSubmissionGap = claimGapBountyIds.length;
  const acceptedBacklog = asCount(backlogRow?.accepted_without_valid_submission);

  const kpiReasonCodes: string[] = [];

  if (fleetTotals.online < params.thresholds.min_online_workers) {
    kpiReasonCodes.push('ARENA_MISSION_KPI_ONLINE_WORKERS_LOW');
  }

  if (claimSuccessRate === null) {
    kpiReasonCodes.push('ARENA_MISSION_KPI_CLAIM_SAMPLE_MISSING');
  } else if (claimSuccessRate < params.thresholds.min_claim_success_rate) {
    kpiReasonCodes.push('ARENA_MISSION_KPI_CLAIM_SUCCESS_LOW');
  }

  if (submissionSuccessRate === null) {
    kpiReasonCodes.push('ARENA_MISSION_KPI_SUBMISSION_SAMPLE_MISSING');
  } else if (submissionSuccessRate < params.thresholds.min_submission_success_rate) {
    kpiReasonCodes.push('ARENA_MISSION_KPI_SUBMISSION_SUCCESS_LOW');
  }

  if (proofValidRate === null) {
    kpiReasonCodes.push('ARENA_MISSION_KPI_PROOF_SAMPLE_MISSING');
  } else if (proofValidRate < params.thresholds.min_proof_valid_rate) {
    kpiReasonCodes.push('ARENA_MISSION_KPI_PROOF_VALIDITY_LOW');
  }

  if (claimSubmissionGap > params.thresholds.max_claim_submission_gap) {
    kpiReasonCodes.push('ARENA_MISSION_KPI_CLAIM_SUBMISSION_GAP_HIGH');
  }

  if (acceptedBacklog > params.thresholds.max_accepted_backlog) {
    kpiReasonCodes.push('ARENA_MISSION_KPI_ACCEPTED_BACKLOG_HIGH');
  }

  const gateStatus = kpiReasonCodes.length === 0 ? 'PASS' : 'FAIL';
  if (kpiReasonCodes.length === 0) {
    kpiReasonCodes.push('ARENA_MISSION_KPI_PASS');
  }

  return {
    schema_version: 'arena_mission_summary.v1',
    computed_at: new Date().toISOString(),
    worker_did: params.workerDid,
    window_hours: params.windowHours,
    window_started_at: since,
    thresholds: params.thresholds,
    fleet: fleetTotals,
    claims_window: claimsWindow,
    submissions_window: {
      ...submissionsWindow,
      without_submission: Math.max(0, submissionsWindow.total - submissionsWindow.with_submission),
    },
    backlog: {
      accepted_total: asCount(backlogRow?.accepted_total),
      accepted_without_valid_submission: acceptedBacklog,
      claim_submission_gap: claimSubmissionGap,
      claim_submission_gap_bounty_ids: claimGapBountyIds.slice(0, 50),
    },
    kpi: {
      claim_success_rate: claimSuccessRate,
      submission_success_rate: submissionSuccessRate,
      proof_valid_rate: proofValidRate,
      gate_status: gateStatus,
      reason_codes: kpiReasonCodes,
    },
  };
}

async function handleGetArenaMission(
  url: URL,
  env: Env,
  version: string,
): Promise<Response> {
  const windowHours = parseArenaMissionWindowHours(url.searchParams.get('window_hours'));
  if (windowHours === null) {
    return errorResponse('INVALID_REQUEST', 'window_hours must be a positive integer', 400, { field: 'window_hours' }, version);
  }

  const workerDid = d1String(url.searchParams.get('worker_did'))?.trim() ?? ARENA_CONFORMANCE_AGENT_DID;
  if (!workerDid.startsWith('did:')) {
    return errorResponse('INVALID_REQUEST', 'worker_did must be a DID', 400, { field: 'worker_did' }, version);
  }

  let summary: Record<string, unknown>;
  try {
    summary = await buildArenaMissionSummary(env.BOUNTIES_DB, {
      workerDid,
      windowHours,
      thresholds: {
        min_online_workers: ARENA_MISSION_DEFAULT_THRESHOLDS.min_online_workers,
        min_claim_success_rate: ARENA_MISSION_DEFAULT_THRESHOLDS.min_claim_success_rate,
        min_submission_success_rate: ARENA_MISSION_DEFAULT_THRESHOLDS.min_submission_success_rate,
        min_proof_valid_rate: ARENA_MISSION_DEFAULT_THRESHOLDS.min_proof_valid_rate,
        max_claim_submission_gap: ARENA_MISSION_DEFAULT_THRESHOLDS.max_claim_submission_gap,
        max_accepted_backlog: ARENA_MISSION_DEFAULT_THRESHOLDS.max_accepted_backlog,
      },
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('DB_READ_FAILED', message, 500, undefined, version);
  }

  return jsonResponse(summary, 200, version);
}

async function handlePostArenaDeskKpiGate(
  request: Request,
  env: Env,
  version: string,
): Promise<Response> {
  const adminError = requireAdmin(request, env, version);
  if (adminError) return adminError;

  const body = await parseJsonBody(request);
  if (!isRecord(body)) {
    return errorResponse('INVALID_REQUEST', 'Invalid JSON body', 400, undefined, version);
  }

  const windowHours = parseArenaMissionWindowHours(d1String(body.window_hours));
  if (windowHours === null) {
    return errorResponse('INVALID_REQUEST', 'window_hours must be a positive integer', 400, { field: 'window_hours' }, version);
  }

  const workerDid = d1String(body.worker_did)?.trim() ?? ARENA_CONFORMANCE_AGENT_DID;
  if (!workerDid.startsWith('did:')) {
    return errorResponse('INVALID_REQUEST', 'worker_did must be a DID', 400, { field: 'worker_did' }, version);
  }

  const thresholdsResult = parseArenaMissionThresholds(body);
  if (!thresholdsResult.thresholds) {
    return errorResponse('INVALID_REQUEST', thresholdsResult.errorMessage ?? 'Invalid thresholds', 400, { field: thresholdsResult.errorField }, version);
  }

  const enforce = body.enforce === true;

  let summary: Record<string, unknown>;
  try {
    summary = await buildArenaMissionSummary(env.BOUNTIES_DB, {
      workerDid,
      windowHours,
      thresholds: thresholdsResult.thresholds,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('DB_READ_FAILED', message, 500, undefined, version);
  }

  const kpi = isRecord(summary.kpi) ? summary.kpi : null;
  const gateStatus = d1String(kpi?.gate_status) ?? 'FAIL';
  const gatePassed = gateStatus === 'PASS';

  const payload = {
    ...summary,
    gate: {
      enforce,
      passed: gatePassed,
      blocked: enforce && !gatePassed,
    },
  };

  if (enforce && !gatePassed) {
    return jsonResponse(payload, 409, version);
  }

  return jsonResponse(payload, 200, version);
}

async function handlePostArenaDeskSelfTuneRollout(
  request: Request,
  env: Env,
  version: string,
): Promise<Response> {
  const adminError = requireAdmin(request, env, version);
  if (adminError) return adminError;

  const body = await parseJsonBody(request);
  if (!isRecord(body)) {
    return errorResponse('INVALID_REQUEST', 'Invalid JSON body', 400, undefined, version);
  }

  const taskFingerprint = d1String(body.task_fingerprint)?.trim();
  if (!taskFingerprint || taskFingerprint.length > 256) {
    return errorResponse('INVALID_REQUEST', 'task_fingerprint is required (<=256 chars)', 400, { field: 'task_fingerprint' }, version);
  }

  const workerDid = d1String(body.worker_did)?.trim() ?? ARENA_CONFORMANCE_AGENT_DID;
  if (!workerDid.startsWith('did:')) {
    return errorResponse('INVALID_REQUEST', 'worker_did must be a DID', 400, { field: 'worker_did' }, version);
  }

  const windowHours = parseArenaMissionWindowHours(d1String(body.window_hours));
  if (windowHours === null) {
    return errorResponse('INVALID_REQUEST', 'window_hours must be a positive integer', 400, { field: 'window_hours' }, version);
  }

  const thresholdsResult = parseArenaMissionThresholds(body);
  if (!thresholdsResult.thresholds) {
    return errorResponse('INVALID_REQUEST', thresholdsResult.errorMessage ?? 'Invalid thresholds', 400, { field: thresholdsResult.errorField }, version);
  }

  const gateEnforce = body.gate_enforce !== false;

  const environment = normalizeArenaPolicyOptimizerEnvironment(
    body.environment,
    env.ENVIRONMENT?.trim().toLowerCase() ?? 'production',
  );

  const objectiveProfileName = normalizeArenaPolicyDimensionValue(
    d1String(body.objective_profile_name)?.trim() ?? null,
  );
  const experimentId = normalizeArenaPolicyDimensionValue(
    d1String(body.experiment_id)?.trim() ?? null,
  );
  const experimentArm = normalizeArenaPolicyDimensionValue(
    d1String(body.experiment_arm)?.trim() ?? null,
  );

  const maxRunsRaw = d1Number(body.max_runs);
  let maxRuns = 80;
  if (maxRunsRaw !== null) {
    if (!Number.isInteger(maxRunsRaw) || maxRunsRaw <= 0) {
      return errorResponse('INVALID_REQUEST', 'max_runs must be a positive integer', 400, { field: 'max_runs' }, version);
    }
    maxRuns = Math.min(maxRunsRaw, 200);
  }

  const minSamplesRaw = d1Number(body.min_samples);
  let minSamples = 6;
  if (minSamplesRaw !== null) {
    if (!Number.isInteger(minSamplesRaw) || minSamplesRaw <= 0) {
      return errorResponse('INVALID_REQUEST', 'min_samples must be a positive integer', 400, { field: 'min_samples' }, version);
    }
    minSamples = Math.min(minSamplesRaw, 200);
  }

  const minConfidenceRaw = d1Number(body.min_confidence);
  let minConfidence = 0.62;
  if (minConfidenceRaw !== null) {
    if (!Number.isFinite(minConfidenceRaw) || minConfidenceRaw < 0 || minConfidenceRaw > 1) {
      return errorResponse('INVALID_REQUEST', 'min_confidence must be within [0,1]', 400, { field: 'min_confidence' }, version);
    }
    minConfidence = minConfidenceRaw;
  }

  let missionSummary: Record<string, unknown>;
  try {
    missionSummary = await buildArenaMissionSummary(env.BOUNTIES_DB, {
      workerDid,
      windowHours,
      thresholds: thresholdsResult.thresholds,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('DB_READ_FAILED', message, 500, undefined, version);
  }

  const missionKpi = isRecord(missionSummary.kpi) ? missionSummary.kpi : null;
  const gateStatus = d1String(missionKpi?.gate_status) ?? 'FAIL';
  const gatePassed = gateStatus === 'PASS';

  const reasonCodes: string[] = ['ARENA_SELF_TUNE_EVALUATED'];
  if (gatePassed) {
    reasonCodes.push('ARENA_SELF_TUNE_GATE_PASS');
  } else if (gateEnforce) {
    reasonCodes.push('ARENA_SELF_TUNE_GATE_BLOCKED');
  } else {
    reasonCodes.push('ARENA_SELF_TUNE_GATE_WARN_ONLY');
  }

  if (gateEnforce && !gatePassed) {
    return jsonResponse(
      {
        schema_version: 'arena_self_tune_rollout.v1',
        computed_at: new Date().toISOString(),
        task_fingerprint: taskFingerprint,
        environment,
        rollout_status: 'BLOCKED',
        reason_codes: reasonCodes,
        mission_summary: missionSummary,
        gate: {
          enforce: gateEnforce,
          passed: gatePassed,
          blocked: true,
        },
      },
      409,
      version,
    );
  }

  if (!env.BOUNTIES_ADMIN_KEY || env.BOUNTIES_ADMIN_KEY.trim().length === 0) {
    return errorResponse('CONFIG_ERROR', 'BOUNTIES_ADMIN_KEY secret is required for self-tune rollout', 500, undefined, version);
  }

  const optimizerRequestBody = {
    task_fingerprint: taskFingerprint,
    environment,
    objective_profile_name: objectiveProfileName || undefined,
    experiment_id: experimentId || undefined,
    experiment_arm: experimentArm || undefined,
    max_runs: maxRuns,
    min_samples: minSamples,
    min_confidence: minConfidence,
  };

  const optimizerRequest = new Request('https://internal/v1/arena/policy-optimizer', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-admin-key': env.BOUNTIES_ADMIN_KEY,
    },
    body: stableStringify(optimizerRequestBody),
  });

  const optimizerResponse = await handlePostArenaPolicyOptimizer(optimizerRequest, env, version);
  const optimizerText = await optimizerResponse.text();
  let optimizerPayload: unknown;
  try {
    optimizerPayload = JSON.parse(optimizerText);
  } catch {
    optimizerPayload = { raw: optimizerText };
  }

  if (optimizerResponse.status !== 200) {
    return jsonResponse(
      {
        schema_version: 'arena_self_tune_rollout.v1',
        computed_at: new Date().toISOString(),
        task_fingerprint: taskFingerprint,
        environment,
        rollout_status: 'FAILED',
        reason_codes: [...reasonCodes, 'ARENA_SELF_TUNE_POLICY_OPTIMIZER_FAILED'],
        mission_summary: missionSummary,
        gate: {
          enforce: gateEnforce,
          passed: gatePassed,
          blocked: false,
        },
        optimizer_http_status: optimizerResponse.status,
        optimizer_response: optimizerPayload,
      },
      optimizerResponse.status,
      version,
    );
  }

  const optimizerRecord = isRecord(optimizerPayload) ? optimizerPayload : null;
  const optimizerReasonCodes = Array.isArray(optimizerRecord?.reason_codes)
    ? optimizerRecord.reason_codes.filter((entry): entry is string => typeof entry === 'string')
    : [];

  const promotionStatus = d1String(optimizerRecord?.promotion_status) ?? 'NOT_READY';
  const rolloutStatus = promotionStatus === 'PROMOTED' ? 'PROMOTED' : 'NOT_READY';

  reasonCodes.push(...optimizerReasonCodes);
  if (rolloutStatus === 'PROMOTED') {
    reasonCodes.push('ARENA_SELF_TUNE_PROMOTED');
  } else {
    reasonCodes.push('ARENA_SELF_TUNE_NOT_READY');
  }

  return jsonResponse(
    {
      schema_version: 'arena_self_tune_rollout.v1',
      computed_at: new Date().toISOString(),
      task_fingerprint: taskFingerprint,
      environment,
      rollout_status: rolloutStatus,
      promotion_status: promotionStatus,
      reason_codes: dedupeStrings(reasonCodes),
      gate: {
        enforce: gateEnforce,
        passed: gatePassed,
        blocked: false,
      },
      mission_summary: missionSummary,
      optimizer_request: optimizerRequestBody,
      optimizer_response: optimizerPayload,
    },
    200,
    version,
  );
}

async function handlePostArenaDeskDiscoverLoop(
  request: Request,
  env: Env,
  version: string,
): Promise<Response> {
  const adminError = requireAdmin(request, env, version);
  if (adminError) return adminError;

  const body = await parseJsonBody(request);
  if (!isRecord(body)) {
    return errorResponse('INVALID_REQUEST', 'Invalid JSON body', 400, undefined, version);
  }

  const targetOpenRaw = d1Number(body.target_open_bounties);
  let targetOpenBounties = 25;
  if (targetOpenRaw !== null) {
    if (!Number.isInteger(targetOpenRaw) || targetOpenRaw <= 0) {
      return errorResponse('INVALID_REQUEST', 'target_open_bounties must be a positive integer', 400, { field: 'target_open_bounties' }, version);
    }
    targetOpenBounties = Math.min(targetOpenRaw, 400);
  }

  const seedLimitRaw = d1Number(body.seed_limit);
  let seedLimit = targetOpenBounties;
  if (seedLimitRaw !== null) {
    if (!Number.isInteger(seedLimitRaw) || seedLimitRaw <= 0) {
      return errorResponse('INVALID_REQUEST', 'seed_limit must be a positive integer', 400, { field: 'seed_limit' }, version);
    }
    seedLimit = Math.min(seedLimitRaw, 400);
  }

  const seedRewardRaw = d1String(body.seed_reward_minor)?.trim() ?? '25';
  const seedRewardMinor = parsePositiveMinor(seedRewardRaw);
  if (seedRewardMinor === null) {
    return errorResponse('INVALID_REQUEST', 'seed_reward_minor must be a positive integer string', 400, { field: 'seed_reward_minor' }, version);
  }

  const seedRequesterDids = parseStringList(body.seed_requester_dids, 100, 200, true);
  if (seedRequesterDids === null || seedRequesterDids.some((did) => !did.startsWith('did:'))) {
    return errorResponse('INVALID_REQUEST', 'seed_requester_dids must be DID strings', 400, { field: 'seed_requester_dids' }, version);
  }

  const seedTagsInput = body.seed_tags === undefined ? ['arena', 'autonomous', 'seed'] : body.seed_tags;
  const seedTags = parseTags(seedTagsInput);
  if (!seedTags || seedTags.length === 0) {
    return errorResponse('INVALID_REQUEST', 'seed_tags must be a non-empty string[]', 400, { field: 'seed_tags' }, version);
  }

  const seedTitlePrefix = d1String(body.seed_title_prefix)?.trim() || 'Arena autonomous task';
  const seedDescription = d1String(body.seed_description)?.trim() || 'Autonomous arena-seeded bounty for desk throughput operations.';
  const objectiveProfileName = normalizeArenaPolicyDimensionValue(d1String(body.objective_profile_name)?.trim() ?? null) ?? 'arena-autonomous';
  const discoverIdRaw = d1String(body.discover_id)?.trim() ?? null;
  const discoverId = discoverIdRaw && discoverIdRaw.length <= 120
    ? discoverIdRaw
    : `arena_discover_${crypto.randomUUID().replace(/-/g, '')}`;

  const dryRun = body.dry_run === true;
  const seedWhenBelowTarget = body.seed_when_below_target !== false;

  const openBefore = await listBounties(env.BOUNTIES_DB, { status: 'open', is_code_bounty: false }, 500);
  const openBeforeCount = openBefore.length;
  const neededSeeds = Math.max(targetOpenBounties - openBeforeCount, 0);
  const plannedSeeds = seedWhenBelowTarget ? Math.min(neededSeeds, seedLimit) : 0;

  const candidateRequesterDids = dedupeStrings([
    ...seedRequesterDids,
    ...openBefore.map((entry) => entry.requester_did).filter((did) => did.startsWith('did:')),
    ARENA_AUTONOMOUS_DEFAULT_REQUESTER_DID,
  ]);

  if (candidateRequesterDids.length === 0) {
    return errorResponse('INVALID_REQUEST', 'No requester DID candidates available for seed loop', 400, undefined, version);
  }

  const seedActions: Array<Record<string, unknown>> = [];
  let seededCreated = 0;
  let seededFailed = 0;

  let escrowReusePoolLoaded = false;
  let escrowReusePoolError: string | null = null;
  const escrowReusePool: Array<{ escrow_id: string; buyer_did: string; amount_minor: string; buyer_total_minor: string }> = [];

  const loadEscrowReusePool = async (): Promise<void> => {
    if (escrowReusePoolLoaded) return;
    escrowReusePoolLoaded = true;

    try {
      const escrowRows = await escrowListHeld(env, 500);
      for (const row of escrowRows) {
        const escrowId = d1String(row.escrow_id)?.trim() ?? null;
        const status = d1String(row.status)?.trim() ?? null;
        const buyerDid = d1String(row.buyer_did)?.trim() ?? null;
        const workerDid = d1String(row.worker_did)?.trim() ?? null;
        const currency = d1String(row.currency)?.trim() ?? null;
        const amountMinor = d1String(row.amount_minor)?.trim() ?? null;
        const buyerTotalMinor = d1String(row.buyer_total_minor)?.trim() ?? amountMinor;
        const riskHold = isRecord(row.risk_hold) ? row.risk_hold : null;
        const riskHoldStatus = d1String(riskHold?.status)?.trim() ?? null;

        if (!escrowId || status !== 'held' || !buyerDid || !buyerDid.startsWith('did:') || workerDid || currency !== 'USD' || !amountMinor) {
          continue;
        }

        if (riskHoldStatus === 'active') {
          continue;
        }

        const existingBounty = await getBountyByEscrowId(env.BOUNTIES_DB, escrowId);
        if (
          existingBounty &&
          (existingBounty.status === 'open' || existingBounty.status === 'accepted' || existingBounty.status === 'pending_review')
        ) {
          continue;
        }

        escrowReusePool.push({
          escrow_id: escrowId,
          buyer_did: buyerDid,
          amount_minor: amountMinor,
          buyer_total_minor: buyerTotalMinor ?? amountMinor,
        });
      }
    } catch (err) {
      escrowReusePoolError = err instanceof Error ? err.message : 'Unknown error';
    }
  };

  const takeEscrowReuseCandidate = (preferredRequesterDid: string): {
    escrow_id: string;
    buyer_did: string;
    amount_minor: string;
    buyer_total_minor: string;
  } | null => {
    if (escrowReusePool.length === 0) return null;

    const preferredIndex = escrowReusePool.findIndex((entry) => entry.buyer_did === preferredRequesterDid);
    if (preferredIndex >= 0) {
      const [picked] = escrowReusePool.splice(preferredIndex, 1);
      return picked ?? null;
    }

    const [fallback] = escrowReusePool.splice(0, 1);
    return fallback ?? null;
  };

  for (let index = 0; index < plannedSeeds; index += 1) {
    const requesterDid = candidateRequesterDids[index % candidateRequesterDids.length] ?? ARENA_AUTONOMOUS_DEFAULT_REQUESTER_DID;
    const idempotencyKey = `arena-seed:${discoverId}:${index + 1}`;
    const payload = {
      requester_did: requesterDid,
      title: `${seedTitlePrefix} ${index + 1}`,
      description: seedDescription,
      reward: {
        amount_minor: seedRewardMinor.toString(),
        currency: 'USD',
      },
      closure_type: 'requester',
      difficulty_scalar: 1,
      is_code_bounty: false,
      tags: seedTags,
      min_proof_tier: 'self',
      metadata: {
        arena_seed: true,
        arena_seed_version: '1',
        arena_seed_discover_id: discoverId,
        arena_seed_index: index + 1,
        objective_profile_name: objectiveProfileName,
        requested_worker_did: ARENA_CONFORMANCE_AGENT_DID,
      },
      idempotency_key: idempotencyKey,
    };

    if (dryRun) {
      seedActions.push({
        status: 'planned',
        requester_did: requesterDid,
        idempotency_key: idempotencyKey,
        payload,
      });
      continue;
    }

    const postRequest = new Request('https://internal/v1/bounties', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
      },
      body: stableStringify(payload),
    });

    const postResponse = await handlePostBounty(postRequest, env, version, {
      authOverride: buildArenaDeskRequesterAuthContext(requesterDid),
      controlPlaneCheckOverride: {
        source: 'arena_desk_discover_loop',
        discover_id: discoverId,
        requester_did: requesterDid,
      },
    });

    const responseText = await postResponse.text();
    let responsePayload: unknown;
    try {
      responsePayload = JSON.parse(responseText);
    } catch {
      responsePayload = { raw: responseText };
    }

    const payloadRecord = isRecord(responsePayload) ? responsePayload : null;
    const bountyId = d1String(payloadRecord?.bounty_id)?.trim() ?? null;

    if (postResponse.status === 200 || postResponse.status === 201) {
      seededCreated += 1;
      seedActions.push({
        status: 'created',
        requester_did: requesterDid,
        bounty_id: bountyId,
        idempotency_key: idempotencyKey,
        http_status: postResponse.status,
      });
      continue;
    }

    const errorCode = d1String(payloadRecord?.error)?.trim() ?? null;
    const errorMessage = d1String(payloadRecord?.message)?.trim() ?? null;
    const canReuseEscrow = errorCode === 'ESCROW_FAILED' && !!errorMessage;

    if (canReuseEscrow) {
      await loadEscrowReusePool();
      const escrowCandidate = takeEscrowReuseCandidate(requesterDid);

      if (escrowCandidate) {
        const reuseIdempotencyKey = `arena-seed-reuse:${discoverId}:${escrowCandidate.escrow_id}`;
        const existingReuse = await getBountyByIdempotencyKey(env.BOUNTIES_DB, reuseIdempotencyKey);

        if (existingReuse) {
          seededCreated += 1;
          seedActions.push({
            status: 'replay',
            seed_source: 'escrow_reuse',
            requester_did: existingReuse.requester_did,
            bounty_id: existingReuse.bounty_id,
            escrow_id: existingReuse.escrow_id,
            idempotency_key: reuseIdempotencyKey,
            fallback_error_code: errorCode,
          });
          continue;
        }

        const now = new Date().toISOString();
        const bountyIdFromEscrow = `bty_${crypto.randomUUID()}`;
        const principalMinor = escrowCandidate.amount_minor;
        const buyerTotalMinor = escrowCandidate.buyer_total_minor;

        const feeQuote: CutsSimulateResponse = {
          policy: {
            id: 'arena_escrow_reuse',
            version: 'v1',
            hash_b64u: 'arena_escrow_reuse',
          },
          quote: {
            principal_minor: principalMinor,
            buyer_total_minor: buyerTotalMinor,
            worker_net_minor: principalMinor,
            fees: [],
          },
        };

        const allInCost: AllInCostV2 = {
          principal_minor: principalMinor,
          platform_fee_minor: (() => {
            try {
              const total = BigInt(buyerTotalMinor);
              const principal = BigInt(principalMinor);
              const fee = total - principal;
              return fee > 0n ? fee.toString() : '0';
            } catch {
              return '0';
            }
          })(),
          total_minor: buyerTotalMinor,
          currency: 'USD',
        };

        const seededRecord: BountyV2 = {
          schema_version: '2',
          bounty_id: bountyIdFromEscrow,
          requester_did: escrowCandidate.buyer_did,
          title: `${seedTitlePrefix} ${index + 1}`,
          description: `${seedDescription} (seed_source=escrow_reuse escrow_id=${escrowCandidate.escrow_id})`,
          reward: {
            amount_minor: principalMinor,
            currency: 'USD',
          },
          closure_type: 'requester',
          difficulty_scalar: 1,
          escrow_id: escrowCandidate.escrow_id,
          status: 'open',
          created_at: now,
          worker_did: null,
          accept_idempotency_key: null,
          accepted_at: null,
          job_token_scope_hash_b64u: null,
          cwc_hash_b64u: null,
          cwc_wpc_policy_hash_b64u: null,
          cwc_required_proof_tier: null,
          cwc_token_scope_hash_b64u: null,
          cwc_buyer_envelope: null,
          cwc_worker_envelope: null,
          approved_submission_id: null,
          approve_idempotency_key: null,
          approved_at: null,
          rejected_submission_id: null,
          reject_idempotency_key: null,
          rejected_at: null,
          trial_case_id: null,
          trial_opened_at: null,
          arena_status: 'idle',
          arena_id: null,
          arena_task_fingerprint: null,
          arena_winner_contender_id: null,
          arena_evidence_links: [],
          arena_updated_at: null,
          is_code_bounty: false,
          tags: seedTags,
          min_proof_tier: 'self',
          require_owner_verified_votes: false,
          test_harness_id: null,
          metadata: {
            arena_seed: true,
            arena_seed_version: '1',
            arena_seed_discover_id: discoverId,
            arena_seed_index: index + 1,
            objective_profile_name: objectiveProfileName,
            requested_worker_did: ARENA_CONFORMANCE_AGENT_DID,
            seed_source: 'escrow_reuse',
            source_escrow_id: escrowCandidate.escrow_id,
            fallback_error_code: errorCode,
          },
          idempotency_key: reuseIdempotencyKey,
          fee_policy_version: feeQuote.policy.version,
          all_in_cost: allInCost,
          fee_quote: feeQuote,
          updated_at: now,
        };

        try {
          await insertBounty(env.BOUNTIES_DB, seededRecord);
          seededCreated += 1;
          seedActions.push({
            status: 'created',
            seed_source: 'escrow_reuse',
            requester_did: seededRecord.requester_did,
            bounty_id: seededRecord.bounty_id,
            escrow_id: seededRecord.escrow_id,
            idempotency_key: reuseIdempotencyKey,
            fallback_error_code: errorCode,
          });
          continue;
        } catch (err) {
          seededFailed += 1;
          seedActions.push({
            status: 'failed',
            seed_source: 'escrow_reuse',
            requester_did: requesterDid,
            escrow_id: escrowCandidate.escrow_id,
            idempotency_key: reuseIdempotencyKey,
            http_status: postResponse.status,
            response: {
              fallback_error_code: errorCode,
              fallback_error_message: errorMessage,
              insert_error: err instanceof Error ? err.message : 'Unknown error',
            },
          });
          continue;
        }
      }

      if (escrowReusePoolError) {
        seededFailed += 1;
        seedActions.push({
          status: 'failed',
          requester_did: requesterDid,
          idempotency_key: idempotencyKey,
          http_status: postResponse.status,
          response: responsePayload,
          fallback: {
            seed_source: 'escrow_reuse',
            error: escrowReusePoolError,
          },
        });
        continue;
      }
    }

    seededFailed += 1;
    seedActions.push({
      status: 'failed',
      requester_did: requesterDid,
      idempotency_key: idempotencyKey,
      http_status: postResponse.status,
      response: responsePayload,
      fallback: canReuseEscrow
        ? {
            seed_source: 'escrow_reuse',
            error: 'NO_ELIGIBLE_ESCROW_CANDIDATE',
          }
        : null,
    });
  }

  const openAfter = dryRun
    ? openBefore
    : await listBounties(env.BOUNTIES_DB, { status: 'open', is_code_bounty: false }, 500);

  return jsonResponse(
    {
      schema_version: 'arena_desk_discovery_loop.v1',
      discover_id: discoverId,
      computed_at: new Date().toISOString(),
      dry_run: dryRun,
      objective_profile_name: objectiveProfileName,
      limits: {
        target_open_bounties: targetOpenBounties,
        seed_limit: seedLimit,
        seed_reward_minor: seedRewardMinor.toString(),
        seed_when_below_target: seedWhenBelowTarget,
        seed_tags: seedTags,
      },
      totals: {
        open_before: openBeforeCount,
        open_after: openAfter.length,
        needed_seeds: neededSeeds,
        planned_seeds: plannedSeeds,
        seeded_created: seededCreated,
        seeded_failed: seededFailed,
        target_met: openAfter.length >= targetOpenBounties,
      },
      requester_did_candidates: candidateRequesterDids,
      open_bounty_sample: openAfter.slice(0, 50).map((entry) => ({
        bounty_id: entry.bounty_id,
        requester_did: entry.requester_did,
        reward: entry.reward,
        status: entry.status,
        closure_type: entry.closure_type,
      })),
      seed_actions: seedActions,
    },
    200,
    version,
  );
}

async function listArenaDeskPendingReviewCandidateIds(
  db: D1Database,
  params: {
    limit: number;
    bountyIds: string[];
    requireClaimed: boolean;
  },
): Promise<Array<{ bounty_id: string; submission_id: string }>> {
  let sql = `
    SELECT s.bounty_id, s.submission_id
      FROM submissions s
      INNER JOIN bounties b ON b.bounty_id = s.bounty_id
     WHERE s.status = 'pending_review'
       AND b.status = 'pending_review'
       AND b.closure_type = 'requester'
  `;

  const bindings: unknown[] = [];

  if (params.requireClaimed) {
    sql += `
      AND EXISTS (
        SELECT 1
          FROM bounty_arena_auto_claim_locks l
         WHERE l.bounty_id = s.bounty_id
           AND l.claim_status = 'claimed'
      )
    `;
  }

  if (params.bountyIds.length > 0) {
    const placeholders = params.bountyIds.map(() => '?').join(', ');
    sql += ` AND s.bounty_id IN (${placeholders})`;
    bindings.push(...params.bountyIds);
  }

  sql += ' ORDER BY s.created_at ASC, s.submission_id ASC LIMIT ?';
  bindings.push(params.limit);

  const rows = await db.prepare(sql).bind(...bindings).all<Record<string, unknown>>();
  const out: Array<{ bounty_id: string; submission_id: string }> = [];

  for (const row of rows.results ?? []) {
    if (!isRecord(row)) continue;
    const bountyId = d1String(row.bounty_id)?.trim() ?? null;
    const submissionId = d1String(row.submission_id)?.trim() ?? null;
    if (!bountyId || !submissionId) continue;
    out.push({ bounty_id: bountyId, submission_id: submissionId });
  }

  return out;
}

async function handlePostArenaDeskDecisionLoop(
  request: Request,
  env: Env,
  version: string,
): Promise<Response> {
  const adminError = requireAdmin(request, env, version);
  if (adminError) return adminError;

  const body = await parseJsonBody(request);
  if (!isRecord(body)) {
    return errorResponse('INVALID_REQUEST', 'Invalid JSON body', 400, undefined, version);
  }

  const limitRaw = d1Number(body.limit);
  let limit = 120;
  if (limitRaw !== null) {
    if (!Number.isInteger(limitRaw) || limitRaw <= 0) {
      return errorResponse('INVALID_REQUEST', 'limit must be a positive integer', 400, { field: 'limit' }, version);
    }
    limit = Math.min(limitRaw, 400);
  }

  const targetRaw = d1Number(body.target_decisions);
  let targetDecisions = Math.min(limit, 20);
  if (targetRaw !== null) {
    if (!Number.isInteger(targetRaw) || targetRaw <= 0) {
      return errorResponse('INVALID_REQUEST', 'target_decisions must be a positive integer', 400, { field: 'target_decisions' }, version);
    }
    targetDecisions = Math.min(targetRaw, limit);
  }

  const decisionMode = parseArenaDeskDecisionMode(body.decision_mode);
  if (!decisionMode) {
    return errorResponse('INVALID_REQUEST', 'decision_mode must be approve_valid|reject_invalid|mixed', 400, { field: 'decision_mode' }, version);
  }

  const bountyIdsParsed = parseStringList(body.bounty_ids, 500, 160, true);
  if (bountyIdsParsed === null || bountyIdsParsed.some((entry) => !entry.startsWith('bty_'))) {
    return errorResponse('INVALID_REQUEST', 'bounty_ids must contain bounty IDs (bty_*)', 400, { field: 'bounty_ids' }, version);
  }
  const bountyIds = dedupeStrings(bountyIdsParsed);

  const rejectReasonRaw = d1String(body.reject_reason)?.trim() ?? null;
  const rejectReason = rejectReasonRaw && rejectReasonRaw.length > 0 ? rejectReasonRaw.slice(0, 512) : 'Arena desk auto-rejection';

  const requireClaimed = body.require_claimed !== false;
  const dryRun = body.dry_run === true;

  const loopIdRaw = d1String(body.loop_id)?.trim() ?? null;
  const loopId = loopIdRaw && loopIdRaw.length <= 120
    ? loopIdRaw
    : `arena_decision_${crypto.randomUUID().replace(/-/g, '')}`;

  const candidateIds = await listArenaDeskPendingReviewCandidateIds(env.BOUNTIES_DB, {
    limit,
    bountyIds,
    requireClaimed,
  });

  const decisions: Array<Record<string, unknown>> = [];
  let approvedCount = 0;
  let rejectedCount = 0;
  let failedCount = 0;

  for (const candidate of candidateIds) {
    if (decisions.length >= limit) break;
    if ((approvedCount + rejectedCount) >= targetDecisions) break;

    const bounty = await getBountyById(env.BOUNTIES_DB, candidate.bounty_id);
    const submission = await getSubmissionById(env.BOUNTIES_DB, candidate.submission_id);

    if (!bounty || !submission) {
      decisions.push({
        bounty_id: candidate.bounty_id,
        submission_id: candidate.submission_id,
        status: 'skipped',
        reason_code: 'ARENA_DECISION_ENTITY_NOT_FOUND',
      });
      continue;
    }

    const proofValid = submission.proof_verify_status === 'valid';
    const commitValidForCode = !bounty.is_code_bounty || submission.commit_proof_verify_status === 'valid';
    const eligibleForApproval = proofValid && commitValidForCode;

    let action: 'approve' | 'reject' | null = null;
    if (decisionMode === 'approve_valid') {
      action = eligibleForApproval ? 'approve' : null;
    } else if (decisionMode === 'reject_invalid') {
      action = eligibleForApproval ? null : 'reject';
    } else {
      action = eligibleForApproval ? 'approve' : 'reject';
    }

    if (!action) {
      decisions.push({
        bounty_id: bounty.bounty_id,
        submission_id: submission.submission_id,
        status: 'skipped',
        reason_code: eligibleForApproval
          ? 'ARENA_DECISION_MODE_SKIP_VALID'
          : 'ARENA_DECISION_MODE_SKIP_INVALID',
        decision_mode: decisionMode,
      });
      continue;
    }

    const idempotencyKey = action === 'approve'
      ? `arena-desk-approve:${submission.submission_id}`
      : `arena-desk-reject:${submission.submission_id}`;

    const requestBody: Record<string, unknown> = {
      requester_did: bounty.requester_did,
      submission_id: submission.submission_id,
      idempotency_key: idempotencyKey,
    };

    if (action === 'reject') {
      requestBody.reason = rejectReason;
    }

    if (dryRun) {
      decisions.push({
        bounty_id: bounty.bounty_id,
        submission_id: submission.submission_id,
        status: 'planned',
        action,
        idempotency_key: idempotencyKey,
        requester_did: bounty.requester_did,
        proof_verify_status: submission.proof_verify_status,
        commit_proof_verify_status: submission.commit_proof_verify_status,
      });
      continue;
    }

    const innerRequest = new Request(`https://internal/v1/bounties/${encodeURIComponent(bounty.bounty_id)}/${action}`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
      },
      body: stableStringify(requestBody),
    });

    const handlerOptions: RequesterAuthOverrideOptions = {
      authOverride: buildArenaDeskRequesterAuthContext(bounty.requester_did),
      controlPlaneCheckOverride: {
        source: 'arena_desk_decision_loop',
        loop_id: loopId,
        decision_mode: decisionMode,
        action,
      },
    };

    const response = action === 'approve'
      ? await handleApproveBounty(bounty.bounty_id, innerRequest, env, version, handlerOptions)
      : await handleRejectBounty(bounty.bounty_id, innerRequest, env, version, handlerOptions);

    const responseText = await response.text();
    let responsePayload: unknown;
    try {
      responsePayload = JSON.parse(responseText);
    } catch {
      responsePayload = { raw: responseText };
    }

    if (response.status === 200) {
      if (action === 'approve') approvedCount += 1;
      if (action === 'reject') rejectedCount += 1;
      decisions.push({
        bounty_id: bounty.bounty_id,
        submission_id: submission.submission_id,
        status: 'applied',
        action,
        idempotency_key: idempotencyKey,
        http_status: response.status,
        response: responsePayload,
      });
    } else {
      failedCount += 1;
      decisions.push({
        bounty_id: bounty.bounty_id,
        submission_id: submission.submission_id,
        status: 'failed',
        action,
        idempotency_key: idempotencyKey,
        http_status: response.status,
        response: responsePayload,
      });
    }
  }

  return jsonResponse(
    {
      schema_version: 'arena_desk_decision_loop.v1',
      loop_id: loopId,
      computed_at: new Date().toISOString(),
      dry_run: dryRun,
      decision_mode: decisionMode,
      limits: {
        limit,
        target_decisions: targetDecisions,
        require_claimed: requireClaimed,
        bounty_ids: bountyIds,
      },
      totals: {
        candidates: candidateIds.length,
        decisions: decisions.length,
        approved: approvedCount,
        rejected: rejectedCount,
        failed: failedCount,
        target_met: (approvedCount + rejectedCount) >= targetDecisions,
      },
      decisions,
    },
    200,
    version,
  );
}

async function handleGetArenaDeskClaimLocks(
  request: Request,
  env: Env,
  version: string,
): Promise<Response> {
  const adminError = requireAdmin(request, env, version);
  if (adminError) return adminError;

  const url = new URL(request.url);
  const limitRaw = d1String(url.searchParams.get('limit'))?.trim();
  let limit = 50;
  if (limitRaw) {
    const parsed = Number.parseInt(limitRaw, 10);
    if (!Number.isFinite(parsed) || parsed <= 0) {
      return errorResponse('INVALID_REQUEST', 'limit must be a positive integer', 400, { field: 'limit' }, version);
    }
    limit = Math.min(parsed, 200);
  }

  const statusRaw = d1String(url.searchParams.get('status'))?.trim() ?? null;
  const claimStatus = statusRaw ? parseArenaAutoClaimLockStatus(statusRaw) : null;
  if (statusRaw && !claimStatus) {
    return errorResponse('INVALID_REQUEST', 'status must be processing|claimed|skipped|failed', 400, { field: 'status' }, version);
  }

  const rows = await listArenaAutoClaimLocks(env.BOUNTIES_DB, {
    limit,
    claimStatus,
  });

  const totals = {
    processing: 0,
    claimed: 0,
    skipped: 0,
    failed: 0,
  };

  for (const row of rows) {
    totals[row.claim_status] += 1;
  }

  return jsonResponse(
    {
      schema_version: 'arena_auto_claim_locks.v1',
      computed_at: new Date().toISOString(),
      filters: {
        status: claimStatus,
        limit,
      },
      totals,
      locks: rows.map((row) => ({
        bounty_id: row.bounty_id,
        lock_id: row.lock_id,
        loop_id: row.loop_id,
        claim_status: row.claim_status,
        worker_did: row.worker_did,
        contender_id: row.contender_id,
        reason_code: row.reason_code,
        claim_idempotency_key: row.claim_idempotency_key,
        budget_minor_before: row.budget_minor_before,
        budget_minor_after: row.budget_minor_after,
        route_reason_codes: parseJsonStringArray(row.route_reason_codes_json) ?? [],
        metadata: row.metadata_json ? parseJsonObject(row.metadata_json) : null,
        created_at: row.created_at,
        updated_at: row.updated_at,
      })),
    },
    200,
    version,
  );
}

function deriveArenaResolveUnresolvedReasonCode(outcomes: ArenaOutcomeRecord[]): string {
  if (outcomes.length === 0) return 'ARENA_RESOLVE_UNRESOLVED_NO_OUTCOMES';
  if (outcomes.some((entry) => entry.disputed)) return 'ARENA_RESOLVE_UNRESOLVED_DISPUTED';
  if (outcomes.some((entry) => entry.rework_required)) return 'ARENA_RESOLVE_UNRESOLVED_REWORK_REQUIRED';
  if (outcomes.some((entry) => entry.overridden)) return 'ARENA_RESOLVE_UNRESOLVED_OVERRIDDEN_NO_ACCEPTED';
  if (outcomes.some((entry) => entry.outcome_status === 'REJECTED')) return 'ARENA_RESOLVE_UNRESOLVED_REJECTED';
  return 'ARENA_RESOLVE_UNRESOLVED_NO_ACCEPTED_OUTCOME';
}

function buildArenaPendingBacklogMetrics(runs: ArenaRunRecord[]): {
  pending_count: number;
  pending_with_reason_code: number;
  pending_without_reason_code: number;
  p95_pending_age_minutes: number;
} {
  const nowMs = Date.now();
  const ages: number[] = [];
  let withReason = 0;

  for (const run of runs) {
    const reasonCodes = parseArenaRunReasonCodes(run.reason_codes_json);
    if (reasonCodes.length > 0) withReason += 1;

    const startedAtEpoch = parseIsoTimestamp(run.started_at);
    if (startedAtEpoch !== null) {
      const ageMinutes = Math.max(0, (nowMs - startedAtEpoch) / 60000);
      ages.push(ageMinutes);
    }
  }

  return {
    pending_count: runs.length,
    pending_with_reason_code: withReason,
    pending_without_reason_code: Math.max(0, runs.length - withReason),
    p95_pending_age_minutes: computeP95MinutesFromDurations(ages),
  };
}

async function handlePostArenaDeskResolveLoop(
  request: Request,
  env: Env,
  version: string,
): Promise<Response> {
  const adminError = requireAdmin(request, env, version);
  if (adminError) return adminError;

  const body = await parseJsonBody(request);
  if (!isRecord(body)) {
    return errorResponse('INVALID_REQUEST', 'Invalid JSON body', 400, undefined, version);
  }

  const limitRaw = d1Number(body.limit);
  let limit = 150;
  if (limitRaw !== null) {
    if (!Number.isInteger(limitRaw) || limitRaw <= 0) {
      return errorResponse('INVALID_REQUEST', 'limit must be a positive integer', 400, { field: 'limit' }, version);
    }
    limit = Math.min(limitRaw, 500);
  }

  const targetResolvedRaw = d1Number(body.target_resolved);
  let targetResolved = Math.min(limit, 80);
  if (targetResolvedRaw !== null) {
    if (!Number.isInteger(targetResolvedRaw) || targetResolvedRaw <= 0) {
      return errorResponse('INVALID_REQUEST', 'target_resolved must be a positive integer', 400, { field: 'target_resolved' }, version);
    }
    targetResolved = Math.min(targetResolvedRaw, limit);
  }

  const minPendingAgeMinutesRaw = d1Number(body.min_pending_age_minutes);
  let minPendingAgeMinutes = 30;
  if (minPendingAgeMinutesRaw !== null) {
    if (!Number.isFinite(minPendingAgeMinutesRaw) || minPendingAgeMinutesRaw < 0) {
      return errorResponse('INVALID_REQUEST', 'min_pending_age_minutes must be >= 0', 400, { field: 'min_pending_age_minutes' }, version);
    }
    minPendingAgeMinutes = Math.min(minPendingAgeMinutesRaw, 24 * 60);
  }

  const finalizeUnresolved = body.finalize_unresolved !== false;
  const dryRun = body.dry_run === true;

  const arenaIdsRaw = body.arena_ids;
  const parsedArenaIds = arenaIdsRaw === undefined || arenaIdsRaw === null
    ? []
    : parseStringList(arenaIdsRaw, 500, 160, true);

  if (arenaIdsRaw !== undefined && arenaIdsRaw !== null && parsedArenaIds === null) {
    return errorResponse('INVALID_REQUEST', 'arena_ids must be string[]', 400, { field: 'arena_ids' }, version);
  }

  const arenaIds = dedupeStrings((parsedArenaIds ?? []).map((entry) => entry.trim()));
  if (arenaIds.some((entry) => !entry.startsWith('arena_'))) {
    return errorResponse('INVALID_REQUEST', 'arena_ids must contain arena IDs (arena_*)', 400, { field: 'arena_ids' }, version);
  }

  const loopIdRaw = d1String(body.loop_id)?.trim() ?? null;
  const loopId = loopIdRaw && loopIdRaw.length <= 120
    ? loopIdRaw
    : `arena_resolve_${crypto.randomUUID().replace(/-/g, '')}`;

  const pendingBeforeRuns = await listPendingArenaRuns(env.BOUNTIES_DB, {
    limit: 5000,
  });
  const pendingBefore = buildArenaPendingBacklogMetrics(pendingBeforeRuns);

  const candidates = await listPendingArenaRuns(env.BOUNTIES_DB, {
    limit,
    arenaIds,
  });

  let resolvedWinnerCount = 0;
  let resolvedUnresolvedCount = 0;
  let unresolvedPendingCount = 0;
  let failedCount = 0;

  const decisions: Array<Record<string, unknown>> = [];

  for (const run of candidates) {
    if ((resolvedWinnerCount + resolvedUnresolvedCount) >= targetResolved) {
      break;
    }

    const now = new Date().toISOString();
    const nowMs = Date.now();
    const startedAtEpoch = parseIsoTimestamp(run.started_at);
    const ageMinutes = startedAtEpoch === null
      ? null
      : Number(Math.max(0, (nowMs - startedAtEpoch) / 60000).toFixed(2));

    const existingReasonCodes = parseArenaRunReasonCodes(run.reason_codes_json);

    if (ageMinutes !== null && ageMinutes < minPendingAgeMinutes) {
      const reasonCodes = dedupeStrings([...existingReasonCodes, 'ARENA_RESOLVE_PENDING_RECENT']);
      if (!dryRun) {
        await annotatePendingArenaRunReasonCodes(env.BOUNTIES_DB, {
          runId: run.run_id,
          reasonCodes,
          now,
        });
      }

      decisions.push({
        arena_id: run.arena_id,
        run_id: run.run_id,
        bounty_id: run.bounty_id,
        status: 'skipped',
        reason_code: 'ARENA_RESOLVE_PENDING_RECENT',
        age_minutes: ageMinutes,
      });
      continue;
    }

    const contenderRows = await listArenaContendersByRunId(env.BOUNTIES_DB, run.run_id);
    const contenderViews: ArenaContenderResult[] = [];
    let invalidContenderPayload = false;
    for (const contenderRow of contenderRows) {
      const contender = parseArenaContenderResult(contenderRow);
      if (!contender) {
        invalidContenderPayload = true;
        break;
      }
      contenderViews.push(contender);
    }

    if (invalidContenderPayload) {
      failedCount += 1;
      const reasonCodes = dedupeStrings([...existingReasonCodes, 'ARENA_RESOLVE_FAILED_INVALID_CONTENDER_PAYLOAD']);
      if (!dryRun) {
        await annotatePendingArenaRunReasonCodes(env.BOUNTIES_DB, {
          runId: run.run_id,
          reasonCodes,
          now,
        });
      }

      decisions.push({
        arena_id: run.arena_id,
        run_id: run.run_id,
        bounty_id: run.bounty_id,
        status: 'failed',
        reason_code: 'ARENA_RESOLVE_FAILED_INVALID_CONTENDER_PAYLOAD',
      });
      continue;
    }

    const outcomes = await listArenaOutcomesByArenaId(env.BOUNTIES_DB, run.arena_id, 200);
    const acceptedOutcomes = outcomes
      .filter((entry) => entry.accepted)
      .sort((a, b) => {
        if (a.updated_at !== b.updated_at) return b.updated_at.localeCompare(a.updated_at);
        return a.outcome_id.localeCompare(b.outcome_id);
      });

    const objectiveProfile = parseJsonObject(run.objective_profile_json) ?? {
      name: 'unknown',
      weights: { quality: 0.25, speed: 0.25, cost: 0.25, safety: 0.25 },
      tie_breakers: ['contender_id'],
    };

    const baseTradeoffs = parseJsonStringArray(run.tradeoffs_json ?? '[]') ?? [];

    const buildContenderReportRows = () => contenderViews.map((entry) => ({
      contender_id: entry.contender_id,
      label: entry.label,
      score: entry.score,
      hard_gate_pass: entry.hard_gate_pass,
      mandatory_failed: entry.mandatory_failed,
      version_pin: entry.version_pin,
      prompt_template: entry.prompt_template,
      experiment_arm: entry.experiment_arm,
      metrics: entry.metrics,
      check_results: entry.check_results,
      score_explain: entry.score_explain,
    }));

    if (acceptedOutcomes.length > 0) {
      const selected = acceptedOutcomes[0] ?? null;
      const winnerContenderId = selected?.contender_id ?? null;
      const winnerContender = winnerContenderId
        ? contenderViews.find((entry) => entry.contender_id === winnerContenderId) ?? null
        : null;

      if (!winnerContenderId || !winnerContender) {
        const unresolvedReason = 'ARENA_RESOLVE_UNRESOLVED_WINNER_NOT_IN_CONTENDERS';
        const reasonCodes = dedupeStrings([...existingReasonCodes, unresolvedReason]);

        if (finalizeUnresolved) {
          const terminalReasonCodes = dedupeStrings([...reasonCodes, 'ARENA_RESOLVE_UNRESOLVED_FINALIZED']);
          const unresolvedReport = {
            schema_version: 'arena_report.resolve.v1',
            generated_at: now,
            arena_id: run.arena_id,
            contract: {
              bounty_id: run.bounty_id,
              contract_id: run.contract_id,
              contract_hash_b64u: run.contract_hash_b64u,
              task_fingerprint: run.task_fingerprint,
            },
            objective_profile: objectiveProfile,
            contenders: buildContenderReportRows(),
            winner: {
              contender_id: null,
              reason: `Unresolved: ${unresolvedReason}`,
            },
            tradeoffs: baseTradeoffs,
            reason_codes: terminalReasonCodes,
          };

          if (!dryRun) {
            const resultIdempotencyKey = run.result_idempotency_key ?? `arena-resolve-unresolved:${await sha256B64uUtf8(`${run.run_id}:${unresolvedReason}`)}`;
            await finalizeArenaRunResolution(env.BOUNTIES_DB, {
              runId: run.run_id,
              winnerContenderId: null,
              winnerReason: `Unresolved: ${unresolvedReason}`,
              reasonCodes: terminalReasonCodes,
              tradeoffs: baseTradeoffs,
              resultIdempotencyKey,
              arenaReport: unresolvedReport,
              now,
            });

            await updateBountyArenaLifecycle(env.BOUNTIES_DB, {
              bounty_id: run.bounty_id,
              arena_status: 'failed',
              arena_id: run.arena_id,
              arena_task_fingerprint: run.task_fingerprint,
              arena_winner_contender_id: null,
              arena_evidence_links: [],
              arena_updated_at: now,
            });
          }

          resolvedUnresolvedCount += 1;
          decisions.push({
            arena_id: run.arena_id,
            run_id: run.run_id,
            bounty_id: run.bounty_id,
            status: 'resolved_unresolved',
            reason_code: unresolvedReason,
            outcome_count: outcomes.length,
            accepted_outcome_count: acceptedOutcomes.length,
            age_minutes: ageMinutes,
          });
          continue;
        }

        if (!dryRun) {
          await annotatePendingArenaRunReasonCodes(env.BOUNTIES_DB, {
            runId: run.run_id,
            reasonCodes,
            now,
          });
        }

        unresolvedPendingCount += 1;
        decisions.push({
          arena_id: run.arena_id,
          run_id: run.run_id,
          bounty_id: run.bounty_id,
          status: 'unresolved',
          reason_code: unresolvedReason,
          age_minutes: ageMinutes,
        });
        continue;
      }

      const resolveReason = acceptedOutcomes.length > 1
        ? 'ARENA_RESOLVE_FROM_ACCEPTED_OUTCOME_LATEST'
        : 'ARENA_RESOLVE_FROM_ACCEPTED_OUTCOME';
      const reasonCodes = dedupeStrings([...existingReasonCodes, resolveReason, 'ARENA_RESOLVE_LOOP_COMPLETED']);

      const resolvedReport = {
        schema_version: 'arena_report.resolve.v1',
        generated_at: now,
        arena_id: run.arena_id,
        contract: {
          bounty_id: run.bounty_id,
          contract_id: run.contract_id,
          contract_hash_b64u: run.contract_hash_b64u,
          task_fingerprint: run.task_fingerprint,
        },
        objective_profile: objectiveProfile,
        contenders: buildContenderReportRows(),
        winner: {
          contender_id: winnerContenderId,
          reason: `Resolved from outcome ${selected?.outcome_id ?? 'unknown'}`,
        },
        tradeoffs: baseTradeoffs,
        reason_codes: reasonCodes,
      };

      if (!dryRun) {
        const resultIdempotencyKey = run.result_idempotency_key ?? `arena-resolve:${await sha256B64uUtf8(`${run.run_id}:${selected?.outcome_id ?? winnerContenderId}`)}`;
        await finalizeArenaRunResolution(env.BOUNTIES_DB, {
          runId: run.run_id,
          winnerContenderId,
          winnerReason: `Resolved from outcome ${selected?.outcome_id ?? 'unknown'}`,
          reasonCodes,
          tradeoffs: baseTradeoffs,
          resultIdempotencyKey,
          arenaReport: resolvedReport,
          now,
        });

        await updateBountyArenaLifecycle(env.BOUNTIES_DB, {
          bounty_id: run.bounty_id,
          arena_status: 'completed',
          arena_id: run.arena_id,
          arena_task_fingerprint: run.task_fingerprint,
          arena_winner_contender_id: winnerContenderId,
          arena_evidence_links: getWinnerEvidenceLinks(contenderViews, winnerContenderId),
          arena_updated_at: now,
        });

        await autoPostArenaWinnerReviewThread(env.BOUNTIES_DB, {
          bounty_id: run.bounty_id,
          arena_id: run.arena_id,
          result_idempotency_key: resultIdempotencyKey,
          contender: winnerContender,
          source: 'arena-resolve-loop-autopost',
          now,
          arena_explorer_base_url: resolveArenaExplorerBaseUrl(env),
        });
      }

      resolvedWinnerCount += 1;
      decisions.push({
        arena_id: run.arena_id,
        run_id: run.run_id,
        bounty_id: run.bounty_id,
        status: 'resolved',
        reason_code: resolveReason,
        winner_contender_id: winnerContenderId,
        outcome_id: selected?.outcome_id ?? null,
        age_minutes: ageMinutes,
      });
      continue;
    }

    const unresolvedReason = deriveArenaResolveUnresolvedReasonCode(outcomes);
    const reasonCodes = dedupeStrings([...existingReasonCodes, unresolvedReason]);

    if (finalizeUnresolved) {
      const terminalReasonCodes = dedupeStrings([...reasonCodes, 'ARENA_RESOLVE_UNRESOLVED_FINALIZED']);
      const unresolvedReport = {
        schema_version: 'arena_report.resolve.v1',
        generated_at: now,
        arena_id: run.arena_id,
        contract: {
          bounty_id: run.bounty_id,
          contract_id: run.contract_id,
          contract_hash_b64u: run.contract_hash_b64u,
          task_fingerprint: run.task_fingerprint,
        },
        objective_profile: objectiveProfile,
        contenders: buildContenderReportRows(),
        winner: {
          contender_id: null,
          reason: `Unresolved: ${unresolvedReason}`,
        },
        tradeoffs: baseTradeoffs,
        reason_codes: terminalReasonCodes,
      };

      if (!dryRun) {
        const resultIdempotencyKey = run.result_idempotency_key ?? `arena-resolve-unresolved:${await sha256B64uUtf8(`${run.run_id}:${unresolvedReason}`)}`;
        await finalizeArenaRunResolution(env.BOUNTIES_DB, {
          runId: run.run_id,
          winnerContenderId: null,
          winnerReason: `Unresolved: ${unresolvedReason}`,
          reasonCodes: terminalReasonCodes,
          tradeoffs: baseTradeoffs,
          resultIdempotencyKey,
          arenaReport: unresolvedReport,
          now,
        });

        await updateBountyArenaLifecycle(env.BOUNTIES_DB, {
          bounty_id: run.bounty_id,
          arena_status: 'failed',
          arena_id: run.arena_id,
          arena_task_fingerprint: run.task_fingerprint,
          arena_winner_contender_id: null,
          arena_evidence_links: [],
          arena_updated_at: now,
        });
      }

      resolvedUnresolvedCount += 1;
      decisions.push({
        arena_id: run.arena_id,
        run_id: run.run_id,
        bounty_id: run.bounty_id,
        status: 'resolved_unresolved',
        reason_code: unresolvedReason,
        outcome_count: outcomes.length,
        accepted_outcome_count: 0,
        age_minutes: ageMinutes,
      });
      continue;
    }

    if (!dryRun) {
      await annotatePendingArenaRunReasonCodes(env.BOUNTIES_DB, {
        runId: run.run_id,
        reasonCodes,
        now,
      });
    }

    unresolvedPendingCount += 1;
    decisions.push({
      arena_id: run.arena_id,
      run_id: run.run_id,
      bounty_id: run.bounty_id,
      status: 'unresolved',
      reason_code: unresolvedReason,
      age_minutes: ageMinutes,
      outcome_count: outcomes.length,
    });
  }

  const pendingAfterRuns = dryRun
    ? pendingBeforeRuns
    : await listPendingArenaRuns(env.BOUNTIES_DB, { limit: 5000 });
  const pendingAfter = buildArenaPendingBacklogMetrics(pendingAfterRuns);

  return jsonResponse(
    {
      schema_version: 'arena_desk_resolve_loop.v1',
      loop_id: loopId,
      computed_at: new Date().toISOString(),
      dry_run: dryRun,
      limits: {
        limit,
        target_resolved: targetResolved,
        min_pending_age_minutes: minPendingAgeMinutes,
        finalize_unresolved: finalizeUnresolved,
        arena_ids: arenaIds,
      },
      totals: {
        candidates: candidates.length,
        processed: decisions.length,
        resolved_winner: resolvedWinnerCount,
        resolved_unresolved: resolvedUnresolvedCount,
        unresolved_pending: unresolvedPendingCount,
        failed: failedCount,
        target_met: (resolvedWinnerCount + resolvedUnresolvedCount) >= targetResolved,
      },
      pending_before: pendingBefore,
      pending_after: pendingAfter,
      decisions,
    },
    200,
    version,
  );
}

async function handlePostArenaDeskClaimLoop(
  request: Request,
  env: Env,
  version: string,
): Promise<Response> {
  const adminError = requireAdmin(request, env, version);
  if (adminError) return adminError;

  const body = await parseJsonBody(request);
  if (!isRecord(body)) {
    return errorResponse('INVALID_REQUEST', 'Invalid JSON body', 400, undefined, version);
  }

  const limitRaw = d1Number(body.limit);
  let limit = 20;
  if (limitRaw !== null) {
    if (!Number.isInteger(limitRaw) || limitRaw <= 0) {
      return errorResponse('INVALID_REQUEST', 'limit must be a positive integer', 400, { field: 'limit' }, version);
    }
    limit = Math.min(limitRaw, 120);
  }

  const targetClaimsRaw = d1Number(body.target_claims);
  let targetClaims = Math.min(limit, 20);
  if (targetClaimsRaw !== null) {
    if (!Number.isInteger(targetClaimsRaw) || targetClaimsRaw <= 0) {
      return errorResponse('INVALID_REQUEST', 'target_claims must be a positive integer', 400, { field: 'target_claims' }, version);
    }
    targetClaims = Math.min(targetClaimsRaw, limit);
  }

  const budgetMinorRaw = d1String(body.budget_minor)?.trim() ?? '1000000';
  const budgetMinor = parsePositiveMinor(budgetMinorRaw);
  if (budgetMinor === null) {
    return errorResponse('INVALID_REQUEST', 'budget_minor must be a positive integer string', 400, { field: 'budget_minor' }, version);
  }

  const maxFleetCostTier = body.max_fleet_cost_tier === undefined || body.max_fleet_cost_tier === null
    ? null
    : parseArenaFleetCostTier(body.max_fleet_cost_tier);
  const maxFleetRiskTier = body.max_fleet_risk_tier === undefined || body.max_fleet_risk_tier === null
    ? null
    : parseArenaFleetRiskTier(body.max_fleet_risk_tier);

  if (body.max_fleet_cost_tier !== undefined && body.max_fleet_cost_tier !== null && !maxFleetCostTier) {
    return errorResponse('INVALID_REQUEST', 'max_fleet_cost_tier must be low|medium|high', 400, { field: 'max_fleet_cost_tier' }, version);
  }

  if (body.max_fleet_risk_tier !== undefined && body.max_fleet_risk_tier !== null && !maxFleetRiskTier) {
    return errorResponse('INVALID_REQUEST', 'max_fleet_risk_tier must be low|medium|high', 400, { field: 'max_fleet_risk_tier' }, version);
  }

  const objectiveProfileName = d1String(body.objective_profile_name)?.trim() ?? null;
  const allowRouteFallback = body.allow_route_fallback !== false;
  const includeCodeBounties = body.include_code_bounties === true;
  const dryRun = body.dry_run === true;

  const loopIdRaw = d1String(body.loop_id)?.trim() ?? null;
  const loopId = loopIdRaw && loopIdRaw.length <= 120
    ? loopIdRaw
    : `arena_autoclaim_${crypto.randomUUID().replace(/-/g, '')}`;

  const scanLimit = Math.min(Math.max(limit * 8, targetClaims * 10), 300);
  const openBounties = await listBounties(
    env.BOUNTIES_DB,
    includeCodeBounties ? { status: 'open' } : { status: 'open', is_code_bounty: false },
    scanLimit,
  );

  let remainingBudgetMinor = budgetMinor;
  let claimedCount = 0;
  let duplicateLockIncidents = 0;
  const decisions: Array<Record<string, unknown>> = [];

  for (const bountyItem of openBounties) {
    if (decisions.length >= limit) break;
    if (claimedCount >= targetClaims) break;

    const bounty = await getBountyById(env.BOUNTIES_DB, bountyItem.bounty_id);
    if (!bounty) continue;

    const rewardMinor = parsePositiveMinor(bounty.reward.amount_minor);
    if (rewardMinor === null) {
      decisions.push({
        bounty_id: bounty.bounty_id,
        status: 'skipped',
        reason_code: 'ARENA_AUTOCLAIM_INVALID_REWARD',
      });
      continue;
    }

    if (bounty.status !== 'open' || bounty.worker_did !== null) {
      decisions.push({
        bounty_id: bounty.bounty_id,
        status: 'skipped',
        reason_code: 'ARENA_AUTOCLAIM_NOT_OPEN',
      });
      continue;
    }

    const budgetBefore = remainingBudgetMinor.toString();
    if (rewardMinor > remainingBudgetMinor) {
      decisions.push({
        bounty_id: bounty.bounty_id,
        status: 'skipped',
        reason_code: 'ARENA_AUTOCLAIM_BUDGET_EXCEEDED',
        reward_amount_minor: bounty.reward.amount_minor,
        budget_minor_before: budgetBefore,
      });
      continue;
    }

    const bountyCostTier = inferArenaBountyCostTier(bounty.reward.amount_minor);
    const bountyRiskTier = inferArenaBountyRiskTier(bounty);

    if (maxFleetCostTier && arenaFleetTierRank(bountyCostTier) > arenaFleetTierRank(maxFleetCostTier)) {
      decisions.push({
        bounty_id: bounty.bounty_id,
        status: 'skipped',
        reason_code: 'ARENA_AUTOCLAIM_COST_GUARD',
        bounty_cost_tier: bountyCostTier,
      });
      continue;
    }

    if (maxFleetRiskTier && arenaFleetTierRank(bountyRiskTier) > arenaFleetTierRank(maxFleetRiskTier)) {
      decisions.push({
        bounty_id: bounty.bounty_id,
        status: 'skipped',
        reason_code: 'ARENA_AUTOCLAIM_RISK_GUARD',
        bounty_risk_tier: bountyRiskTier,
      });
      continue;
    }

    const routeSelection = await resolveArenaAutoClaimRouteSelection(env, version, {
      bounty,
      objectiveProfileName,
      maxFleetCostTier,
      maxFleetRiskTier,
      allowRouteFallback,
    });

    if (!routeSelection.workerDid) {
      decisions.push({
        bounty_id: bounty.bounty_id,
        status: 'skipped',
        reason_code: 'ARENA_AUTOCLAIM_NO_ELIGIBLE_WORKER',
        route_reason_codes: routeSelection.routeReasonCodes,
      });
      continue;
    }

    const requestedWorkerDid = d1String(bounty.metadata.requested_worker_did)?.trim() ?? null;
    if (requestedWorkerDid && requestedWorkerDid !== routeSelection.workerDid) {
      decisions.push({
        bounty_id: bounty.bounty_id,
        status: 'skipped',
        reason_code: 'ARENA_AUTOCLAIM_REQUESTED_WORKER_MISMATCH',
        requested_worker_did: requestedWorkerDid,
        selected_worker_did: routeSelection.workerDid,
      });
      continue;
    }

    const claimIdempotencyKey = `arena-autoclaim:${bounty.bounty_id}`;
    const lockNow = new Date().toISOString();
    const lock: ArenaAutoClaimLockRecord = {
      bounty_id: bounty.bounty_id,
      lock_id: `aclk_${crypto.randomUUID().replace(/-/g, '')}`,
      loop_id: loopId,
      claim_status: 'processing',
      worker_did: null,
      contender_id: routeSelection.contenderId,
      reason_code: 'ARENA_AUTOCLAIM_PROCESSING',
      claim_idempotency_key: claimIdempotencyKey,
      budget_minor_before: budgetBefore,
      budget_minor_after: budgetBefore,
      route_reason_codes_json: stableStringify(routeSelection.routeReasonCodes),
      metadata_json: stableStringify({
        source: routeSelection.source,
        fleet_status: routeSelection.fleetStatus,
      }),
      created_at: lockNow,
      updated_at: lockNow,
    };

    const acquired = await tryInsertArenaAutoClaimProcessingLock(env.BOUNTIES_DB, lock);
    if (!acquired) {
      duplicateLockIncidents += 1;
      const existing = await getArenaAutoClaimLockByBountyId(env.BOUNTIES_DB, bounty.bounty_id);
      decisions.push({
        bounty_id: bounty.bounty_id,
        status: 'replay',
        reason_code: existing?.reason_code ?? 'ARENA_AUTOCLAIM_LOCK_EXISTS',
        existing_claim_status: existing?.claim_status ?? null,
      });
      continue;
    }

    const currentBounty = await getBountyById(env.BOUNTIES_DB, bounty.bounty_id);
    if (!currentBounty || currentBounty.status !== 'open' || currentBounty.worker_did !== null) {
      await finalizeArenaAutoClaimLock(env.BOUNTIES_DB, {
        bountyId: bounty.bounty_id,
        claimStatus: 'skipped',
        workerDid: routeSelection.workerDid,
        contenderId: routeSelection.contenderId,
        reasonCode: 'ARENA_AUTOCLAIM_RACE_NOT_OPEN',
        budgetMinorAfter: budgetBefore,
        routeReasonCodes: routeSelection.routeReasonCodes,
        metadataJson: stableStringify({ source: routeSelection.source, fleet_status: routeSelection.fleetStatus }),
        now: new Date().toISOString(),
      });

      decisions.push({
        bounty_id: bounty.bounty_id,
        status: 'skipped',
        reason_code: 'ARENA_AUTOCLAIM_RACE_NOT_OPEN',
      });
      continue;
    }

    if (dryRun) {
      await finalizeArenaAutoClaimLock(env.BOUNTIES_DB, {
        bountyId: bounty.bounty_id,
        claimStatus: 'skipped',
        workerDid: routeSelection.workerDid,
        contenderId: routeSelection.contenderId,
        reasonCode: 'ARENA_AUTOCLAIM_DRY_RUN',
        budgetMinorAfter: budgetBefore,
        routeReasonCodes: routeSelection.routeReasonCodes,
        metadataJson: stableStringify({ source: routeSelection.source, fleet_status: routeSelection.fleetStatus }),
        now: new Date().toISOString(),
      });

      decisions.push({
        bounty_id: bounty.bounty_id,
        status: 'skipped',
        reason_code: 'ARENA_AUTOCLAIM_DRY_RUN',
        selected_worker_did: routeSelection.workerDid,
      });
      continue;
    }

    let finalStatus: ArenaAutoClaimLockRecord['claim_status'] = 'claimed';
    let finalReason = 'ARENA_AUTOCLAIM_CLAIMED';
    let claimError: string | null = null;

    try {
      await escrowAssignWorker(env, {
        escrow_id: currentBounty.escrow_id,
        idempotency_key: claimIdempotencyKey,
        worker_did: routeSelection.workerDid,
      });

      const acceptedAt = new Date().toISOString();
      await updateBountyAccepted(env.BOUNTIES_DB, {
        bounty_id: currentBounty.bounty_id,
        worker_did: routeSelection.workerDid,
        accepted_at: acceptedAt,
        idempotency_key: claimIdempotencyKey,
        cwc_worker_envelope_json: null,
        cwc_token_scope_hash_b64u: null,
        job_token_scope_hash_b64u: null,
        now: acceptedAt,
      });

      const updated = await getBountyById(env.BOUNTIES_DB, currentBounty.bounty_id);
      if (!updated || updated.status !== 'accepted' || updated.worker_did !== routeSelection.workerDid) {
        throw new Error('BOUNTY_ACCEPT_STATE_MISMATCH');
      }

      remainingBudgetMinor -= rewardMinor;
      claimedCount += 1;
    } catch (err) {
      finalStatus = 'failed';
      claimError = err instanceof Error ? err.message : 'Unknown error';
      finalReason = mapArenaAutoClaimFailureReason(claimError);
    }

    await finalizeArenaAutoClaimLock(env.BOUNTIES_DB, {
      bountyId: bounty.bounty_id,
      claimStatus: finalStatus,
      workerDid: routeSelection.workerDid,
      contenderId: routeSelection.contenderId,
      reasonCode: finalReason,
      budgetMinorAfter: remainingBudgetMinor.toString(),
      routeReasonCodes: routeSelection.routeReasonCodes,
      metadataJson: stableStringify({
        source: routeSelection.source,
        fleet_status: routeSelection.fleetStatus,
        claim_error: claimError,
      }),
      now: new Date().toISOString(),
    });

    decisions.push({
      bounty_id: bounty.bounty_id,
      status: finalStatus,
      reason_code: finalReason,
      contender_id: routeSelection.contenderId,
      selected_worker_did: routeSelection.workerDid,
      route_reason_codes: routeSelection.routeReasonCodes,
      source: routeSelection.source,
      reward_amount_minor: bounty.reward.amount_minor,
      budget_minor_before: budgetBefore,
      budget_minor_after: remainingBudgetMinor.toString(),
      error: claimError,
    });
  }

  const summary = {
    schema_version: 'arena_auto_claim_loop.v1',
    loop_id: loopId,
    generated_at: new Date().toISOString(),
    dry_run: dryRun,
    objective_profile_name: objectiveProfileName,
    limits: {
      limit,
      target_claims: targetClaims,
      scan_limit: scanLimit,
      budget_minor: budgetMinor.toString(),
      max_fleet_cost_tier: maxFleetCostTier,
      max_fleet_risk_tier: maxFleetRiskTier,
      include_code_bounties: includeCodeBounties,
      allow_route_fallback: allowRouteFallback,
    },
    totals: {
      scanned_open_bounties: openBounties.length,
      decisions: decisions.length,
      claimed: claimedCount,
      failed: decisions.filter((entry) => entry.status === 'failed').length,
      skipped: decisions.filter((entry) => entry.status === 'skipped').length,
      replay: decisions.filter((entry) => entry.status === 'replay').length,
      duplicate_lock_incidents: duplicateLockIncidents,
      budget_minor_remaining: remainingBudgetMinor.toString(),
      target_met: claimedCount >= targetClaims,
    },
    decisions,
  };

  return jsonResponse(summary, 200, version);
}

async function handlePostArenaDeskSubmissionLoop(
  request: Request,
  env: Env,
  version: string,
): Promise<Response> {
  const adminError = requireAdmin(request, env, version);
  if (adminError) return adminError;

  const body = await parseJsonBody(request);
  if (!isRecord(body)) {
    return errorResponse('INVALID_REQUEST', 'Invalid JSON body', 400, undefined, version);
  }

  const workerDid = d1String(body.worker_did)?.trim();
  if (!workerDid || !workerDid.startsWith('did:')) {
    return errorResponse('INVALID_REQUEST', 'worker_did is required', 400, { field: 'worker_did' }, version);
  }

  const bountyIdsRaw = body.bounty_ids;
  const bountyIdsParsed = bountyIdsRaw === undefined || bountyIdsRaw === null
    ? []
    : parseStringList(bountyIdsRaw, 500, 160, true);

  if (bountyIdsRaw !== undefined && bountyIdsRaw !== null && bountyIdsParsed === null) {
    return errorResponse('INVALID_REQUEST', 'bounty_ids must be string[]', 400, { field: 'bounty_ids' }, version);
  }

  const bountyIds = dedupeStrings((bountyIdsParsed ?? []).map((entry) => entry.trim()));
  if (bountyIds.some((entry) => !entry.startsWith('bty_'))) {
    return errorResponse('INVALID_REQUEST', 'bounty_ids must contain bounty IDs (bty_*)', 400, { field: 'bounty_ids' }, version);
  }

  const targetRaw = d1Number(body.target_submissions);
  let targetSubmissions = bountyIds.length > 0 ? bountyIds.length : 10;
  if (targetRaw !== null) {
    if (!Number.isInteger(targetRaw) || targetRaw <= 0) {
      return errorResponse('INVALID_REQUEST', 'target_submissions must be a positive integer', 400, { field: 'target_submissions' }, version);
    }
    targetSubmissions = Math.min(targetRaw, 200);
  }

  const limitRaw = d1Number(body.limit);
  let limit = Math.max(targetSubmissions * 2, 30);
  if (limitRaw !== null) {
    if (!Number.isInteger(limitRaw) || limitRaw <= 0) {
      return errorResponse('INVALID_REQUEST', 'limit must be a positive integer', 400, { field: 'limit' }, version);
    }
    limit = Math.min(limitRaw, 400);
  }

  const dryRun = body.dry_run === true;

  const allowWorkerRebindOnMismatchRaw = body.allow_worker_rebind_on_mismatch;
  if (allowWorkerRebindOnMismatchRaw !== undefined && typeof allowWorkerRebindOnMismatchRaw !== 'boolean') {
    return errorResponse(
      'INVALID_REQUEST',
      'allow_worker_rebind_on_mismatch must be boolean',
      400,
      { field: 'allow_worker_rebind_on_mismatch' },
      version,
    );
  }
  const allowWorkerRebindOnMismatch = allowWorkerRebindOnMismatchRaw === true;

  let worker: WorkerRecordV1 | null;
  try {
    worker = await getWorkerByDid(env.BOUNTIES_DB, workerDid);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('DB_READ_FAILED', message, 500, undefined, version);
  }

  if (!worker) {
    return errorResponse('WORKER_NOT_REGISTERED', 'Worker is not registered in marketplace', 404, { worker_did: workerDid }, version);
  }

  let signer: { did: string; privateKey: CryptoKey };
  try {
    signer = await makeArenaConformanceSignerFromSeed(ARENA_CONFORMANCE_AGENT_SEED);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('INTERNAL_ERROR', `Failed to load conformance signer: ${message}`, 500, undefined, version);
  }

  if (signer.did !== workerDid) {
    return errorResponse(
      'INVALID_REQUEST',
      'worker_did must match conformance proof signer DID for execution autopilot',
      400,
      { expected_worker_did: signer.did },
      version,
    );
  }

  const candidateBountyIds = bountyIds.length > 0
    ? bountyIds
    : (await listBounties(env.BOUNTIES_DB, { status: 'accepted', is_code_bounty: false }, Math.max(limit, targetSubmissions * 3)))
        .map((entry) => entry.bounty_id);

  const makeWorkerAuthOverride = (effectiveWorkerDid: string): WorkerAuthContext => ({
    worker_did: effectiveWorkerDid,
    auth_mode: 'scoped_token',
    token_hash: null,
    scope: [WORKER_AUTH_SCOPE_BY_ACTION.submit_bounty],
    aud: [resolveWorkerAuthRequiredAudience(env)],
    token_scope_hash_b64u: null,
    token_lane: 'canonical',
    payment_account_did: null,
    agent_did: effectiveWorkerDid,
    iat: null,
    exp: null,
    bearer_token: null,
  });

  const decisions: Array<Record<string, unknown>> = [];
  for (const bountyId of candidateBountyIds) {
    if (decisions.length >= limit) break;
    if (decisions.filter((entry) => entry.submission_status === 'pending_review' && entry.proof_verify_status === 'valid').length >= targetSubmissions) {
      break;
    }

    let bounty: BountyV2 | null;
    try {
      bounty = await getBountyById(env.BOUNTIES_DB, bountyId);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      decisions.push({ bounty_id: bountyId, status: 'failed', reason_code: 'DB_READ_FAILED', error: message });
      continue;
    }

    if (!bounty) {
      decisions.push({ bounty_id: bountyId, status: 'skipped', reason_code: 'BOUNTY_NOT_FOUND' });
      continue;
    }

    if (bounty.status !== 'accepted') {
      decisions.push({ bounty_id: bountyId, status: 'skipped', reason_code: 'BOUNTY_NOT_ACCEPTED', bounty_status: bounty.status });
      continue;
    }

    if (!bounty.worker_did) {
      if (dryRun) {
        decisions.push({
          bounty_id: bountyId,
          status: 'dry_run',
          reason_code: 'ARENA_SUBMISSION_ASSIGNMENT_RECOVERY_DRY_RUN',
          expected_worker_did: workerDid,
        });
        continue;
      }

      try {
        await escrowAssignWorker(env, {
          escrow_id: bounty.escrow_id,
          idempotency_key: `arena-autosubmit-bind:${bountyId}:${workerDid}`,
          worker_did: workerDid,
        });

        const now = new Date().toISOString();
        await updateBountyAccepted(env.BOUNTIES_DB, {
          bounty_id: bountyId,
          worker_did: workerDid,
          accepted_at: now,
          idempotency_key: `arena-autosubmit-bind:${bountyId}:${workerDid}`,
          cwc_worker_envelope_json: null,
          cwc_token_scope_hash_b64u: null,
          job_token_scope_hash_b64u: null,
          now,
        });

        bounty = await getBountyById(env.BOUNTIES_DB, bountyId);
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Unknown error';
        decisions.push({
          bounty_id: bountyId,
          status: 'failed',
          reason_code: 'ARENA_SUBMISSION_ASSIGNMENT_RECOVERY_FAILED',
          error: message,
        });
        continue;
      }
    }

    let effectiveWorkerDid = workerDid;
    let effectiveWorker = worker;
    let workerMismatchDispatched = false;
    let previousWorkerDid: string | null = null;

    if (!bounty || bounty.worker_did !== workerDid) {
      if (!allowWorkerRebindOnMismatch) {
        decisions.push({
          bounty_id: bountyId,
          status: 'skipped',
          reason_code: 'WORKER_MISMATCH',
          bounty_worker_did: bounty?.worker_did ?? null,
        });
        continue;
      }

      const assignedWorkerDid = bounty?.worker_did ?? null;
      if (!assignedWorkerDid || !assignedWorkerDid.startsWith('did:')) {
        decisions.push({
          bounty_id: bountyId,
          status: 'failed',
          reason_code: 'ARENA_SUBMISSION_WORKER_DISPATCH_FAILED',
          error: 'Assigned worker DID is missing or invalid for mismatch dispatch',
        });
        continue;
      }

      previousWorkerDid = assignedWorkerDid;
      effectiveWorkerDid = assignedWorkerDid;

      if (dryRun) {
        decisions.push({
          bounty_id: bountyId,
          status: 'dry_run',
          reason_code: 'ARENA_SUBMISSION_WORKER_DISPATCH_DRY_RUN',
          previous_worker_did: previousWorkerDid,
          effective_worker_did: effectiveWorkerDid,
          requested_worker_did: workerDid,
        });
        continue;
      }

      try {
        const assignedWorker = await getWorkerByDid(env.BOUNTIES_DB, effectiveWorkerDid);
        if (!assignedWorker) {
          throw new Error('Assigned worker is not registered');
        }
        effectiveWorker = assignedWorker;
        workerMismatchDispatched = true;
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Unknown error';
        decisions.push({
          bounty_id: bountyId,
          status: 'failed',
          reason_code: 'ARENA_SUBMISSION_WORKER_DISPATCH_FAILED',
          previous_worker_did: previousWorkerDid,
          effective_worker_did: effectiveWorkerDid,
          requested_worker_did: workerDid,
          error: message,
        });
        continue;
      }
    }

    if (!bounty) {
      decisions.push({ bounty_id: bountyId, status: 'failed', reason_code: 'BOUNTY_NOT_FOUND_AFTER_ASSIGNMENT' });
      continue;
    }

    if (bounty.is_code_bounty) {
      decisions.push({ bounty_id: bountyId, status: 'skipped', reason_code: 'CODE_BOUNTY_UNSUPPORTED' });
      continue;
    }

    const idempotencyKey = `arena-autosubmit:${bountyId}:${effectiveWorkerDid}:${crypto.randomUUID().replace(/-/g, '')}`;
    let proofArtifacts: { runId: string; proofBundleEnvelope: Record<string, unknown>; urm: Record<string, unknown> };
    try {
      proofArtifacts = await buildArenaExecutionAutopilotProofArtifacts(effectiveWorkerDid, bountyId, signer);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      decisions.push({ bounty_id: bountyId, status: 'failed', reason_code: 'PROOF_BUILD_FAILED', error: message });
      continue;
    }

    if (dryRun) {
      decisions.push({
        bounty_id: bountyId,
        status: 'dry_run',
        reason_code: 'ARENA_SUBMISSION_DRY_RUN',
        run_id: proofArtifacts.runId,
        idempotency_key: idempotencyKey,
        worker_mismatch_dispatch: workerMismatchDispatched,
        previous_worker_did: previousWorkerDid,
        effective_worker_did: effectiveWorkerDid,
        requested_worker_did: workerDid,
      });
      continue;
    }

    const submitRequest = new Request(`https://internal/v1/bounties/${encodeURIComponent(bountyId)}/submit`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        worker_did: effectiveWorkerDid,
        idempotency_key: idempotencyKey,
        proof_bundle_envelope: proofArtifacts.proofBundleEnvelope,
        urm: proofArtifacts.urm,
        result_summary: `arena execution autopilot submission for ${bountyId}`,
        artifacts: [
          {
            kind: 'execution_log',
            label: 'arena-autopilot-log',
            url: `urn:arena:execution:${proofArtifacts.runId}`,
          },
        ],
      }),
    });

    const submitResponse = await handleSubmitBounty(bountyId, submitRequest, env, version, {
      authOverride: {
        worker: effectiveWorker,
        auth: makeWorkerAuthOverride(effectiveWorkerDid),
      },
    });

    let submitPayload: unknown;
    let submitPayloadRaw = '';
    try {
      submitPayloadRaw = await submitResponse.text();
      submitPayload = JSON.parse(submitPayloadRaw);
    } catch {
      submitPayload = { raw: submitPayloadRaw };
    }

    const payloadRecord = isRecord(submitPayload) ? submitPayload : null;
    const submission = payloadRecord && isRecord(payloadRecord.submission) ? payloadRecord.submission : null;
    const verification = payloadRecord && isRecord(payloadRecord.verification) ? payloadRecord.verification : null;
    const verificationProof = verification && isRecord(verification.proof_bundle) ? verification.proof_bundle : null;

    const submissionStatus = d1String(submission?.status) ?? d1String(payloadRecord?.status) ?? null;
    const proofVerifyStatus = d1String(submission?.proof_verify_status) ?? d1String(verificationProof?.status) ?? null;

    decisions.push({
      bounty_id: bountyId,
      http_status: submitResponse.status,
      submission_id: d1String(submission?.submission_id) ?? null,
      submission_status: submissionStatus,
      proof_verify_status: proofVerifyStatus,
      idempotency_key: idempotencyKey,
      run_id: proofArtifacts.runId,
      worker_mismatch_dispatch: workerMismatchDispatched,
      previous_worker_did: previousWorkerDid,
      effective_worker_did: effectiveWorkerDid,
      requested_worker_did: workerDid,
      response: submitPayload,
    });
  }

  const successfulPendingReview = decisions.filter(
    (entry) => entry.submission_status === 'pending_review' && entry.proof_verify_status === 'valid',
  ).length;
  const workerMismatchDispatchCount = decisions.filter((entry) => entry.worker_mismatch_dispatch === true).length;

  return jsonResponse(
    {
      schema_version: 'arena_execution_submission_autopilot.v1',
      computed_at: new Date().toISOString(),
      worker_did: workerDid,
      dry_run: dryRun,
      limits: {
        target_submissions: targetSubmissions,
        limit,
        candidate_bounty_ids: candidateBountyIds,
        allow_worker_rebind_on_mismatch: allowWorkerRebindOnMismatch,
      },
      totals: {
        decisions: decisions.length,
        successful_pending_review: successfulPendingReview,
        worker_mismatch_dispatch: workerMismatchDispatchCount,
        target_met: successfulPendingReview >= targetSubmissions,
      },
      decisions,
    },
    200,
    version,
  );
}

async function handleGetArenaPolicyOptimizer(
  request: Request,
  url: URL,
  env: Env,
  version: string,
): Promise<Response> {
  const adminError = requireAdmin(request, env, version);
  if (adminError) return adminError;

  const taskFingerprint = d1String(url.searchParams.get('task_fingerprint'))?.trim();
  if (!taskFingerprint || taskFingerprint.length > 256) {
    return errorResponse('INVALID_REQUEST', 'task_fingerprint is required (<=256 chars)', 400, { field: 'task_fingerprint' }, version);
  }

  const environment = normalizeArenaPolicyOptimizerEnvironment(
    url.searchParams.get('environment'),
    env.ENVIRONMENT?.trim().toLowerCase() ?? 'production',
  );

  const objectiveProfileName = normalizeArenaPolicyDimensionValue(
    d1String(url.searchParams.get('objective_profile_name'))?.trim() ?? null,
  );
  const experimentId = normalizeArenaPolicyDimensionValue(
    d1String(url.searchParams.get('experiment_id'))?.trim() ?? null,
  );
  const experimentArm = normalizeArenaPolicyDimensionValue(
    d1String(url.searchParams.get('experiment_arm'))?.trim() ?? null,
  );

  const state = await getArenaRoutePolicyOptimizerState(env.BOUNTIES_DB, {
    taskFingerprint,
    environment,
    objectiveProfileName,
    experimentId,
    experimentArm,
  });

  if (!state) {
    return errorResponse(
      'ARENA_POLICY_OPTIMIZER_NOT_FOUND',
      'No policy optimizer state found for query',
      404,
      {
        task_fingerprint: taskFingerprint,
        environment,
        objective_profile_name: objectiveProfileName || null,
        experiment_id: experimentId || null,
        experiment_arm: experimentArm || null,
      },
      version,
    );
  }

  return jsonResponse(buildArenaPolicyOptimizerPayloadFromState(state), 200, version);
}

async function handlePostArenaPolicyOptimizer(
  request: Request,
  env: Env,
  version: string,
): Promise<Response> {
  const adminError = requireAdmin(request, env, version);
  if (adminError) return adminError;

  const body = await parseJsonBody(request);
  if (!isRecord(body)) {
    return errorResponse('INVALID_REQUEST', 'Invalid JSON body', 400, undefined, version);
  }

  const taskFingerprint = d1String(body.task_fingerprint)?.trim();
  if (!taskFingerprint || taskFingerprint.length > 256) {
    return errorResponse('INVALID_REQUEST', 'task_fingerprint is required (<=256 chars)', 400, { field: 'task_fingerprint' }, version);
  }

  const environment = normalizeArenaPolicyOptimizerEnvironment(
    body.environment,
    env.ENVIRONMENT?.trim().toLowerCase() ?? 'production',
  );

  const objectiveProfileName = normalizeArenaPolicyDimensionValue(
    d1String(body.objective_profile_name)?.trim() ?? null,
  );
  const experimentId = normalizeArenaPolicyDimensionValue(
    d1String(body.experiment_id)?.trim() ?? null,
  );
  const experimentArm = normalizeArenaPolicyDimensionValue(
    d1String(body.experiment_arm)?.trim() ?? null,
  );

  const maxRunsRaw = d1Number(body.max_runs);
  let maxRuns = 80;
  if (maxRunsRaw !== null) {
    if (!Number.isInteger(maxRunsRaw) || maxRunsRaw <= 0) {
      return errorResponse('INVALID_REQUEST', 'max_runs must be a positive integer', 400, { field: 'max_runs' }, version);
    }
    maxRuns = Math.min(maxRunsRaw, 200);
  }

  const minSamplesRaw = d1Number(body.min_samples);
  let minSamples = 6;
  if (minSamplesRaw !== null) {
    if (!Number.isInteger(minSamplesRaw) || minSamplesRaw <= 0) {
      return errorResponse('INVALID_REQUEST', 'min_samples must be a positive integer', 400, { field: 'min_samples' }, version);
    }
    minSamples = Math.min(minSamplesRaw, 200);
  }

  const minConfidenceRaw = d1Number(body.min_confidence);
  let minConfidence = 0.62;
  if (minConfidenceRaw !== null) {
    if (!Number.isFinite(minConfidenceRaw) || minConfidenceRaw < 0 || minConfidenceRaw > 1) {
      return errorResponse('INVALID_REQUEST', 'min_confidence must be within [0,1]', 400, { field: 'min_confidence' }, version);
    }
    minConfidence = minConfidenceRaw;
  }

  if (!env.BOUNTIES_ADMIN_KEY || env.BOUNTIES_ADMIN_KEY.trim().length === 0) {
    return errorResponse('CONFIG_ERROR', 'BOUNTIES_ADMIN_KEY secret is required for policy optimizer routing snapshots', 500, undefined, version);
  }

  const routeBody = {
    task_fingerprint: taskFingerprint,
    environment,
    objective_profile_name: objectiveProfileName || undefined,
    experiment_id: experimentId || undefined,
    experiment_arm: experimentArm || undefined,
    max_runs: maxRuns,
    require_hard_gate_pass: true,
    allow_fallback: true,
    use_active_policy: false,
  };

  const internalRouteRequest = new Request('https://internal/v1/arena/manager/route', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-admin-key': env.BOUNTIES_ADMIN_KEY,
    },
    body: stableStringify(routeBody),
  });

  const routeResponse = await handleArenaManagerRoute(internalRouteRequest, env, version, 'route');
  if (routeResponse.status !== 200) {
    return routeResponse;
  }

  let routePayload: unknown;
  try {
    routePayload = await routeResponse.json();
  } catch {
    return errorResponse('INTERNAL_ERROR', 'Failed to parse manager route payload', 500, undefined, version);
  }

  if (!isRecord(routePayload)) {
    return errorResponse('DATA_INTEGRITY_ERROR', 'Manager route payload is invalid', 500, undefined, version);
  }

  const recommended = isRecord(routePayload.recommended) ? routePayload.recommended : null;
  const evidence = recommended && isRecord(recommended.evidence) ? recommended.evidence : null;
  const contenderId = d1String(recommended?.contender_id)?.trim() ?? null;

  if (!recommended || !evidence || !contenderId) {
    return errorResponse('DATA_INTEGRITY_ERROR', 'Policy optimizer could not parse routing recommendation', 500, undefined, version);
  }

  const sampleCount = Math.trunc(d1Number(evidence.outcome_samples) ?? d1Number(evidence.appearances) ?? 0);
  const winRate = d1Number(evidence.win_rate) ?? 0;
  const acceptRate = d1Number(evidence.empirical_accept_rate) ?? 0;
  const overrideRate = d1Number(evidence.override_rate) ?? 0;
  const reworkRate = d1Number(evidence.rework_rate) ?? 0;
  const calibrationGap = d1Number(evidence.calibration_gap) ?? 0;
  const routingScore = d1Number(recommended.routing_score) ?? 0;

  const confidenceScore = computeArenaPolicyOptimizerConfidence({
    winRate,
    acceptRate,
    overrideRate,
    reworkRate,
    calibrationGap,
  });

  const now = new Date().toISOString();
  const shadowMaterial = stableStringify({
    task_fingerprint: taskFingerprint,
    environment,
    objective_profile_name: objectiveProfileName,
    experiment_id: experimentId,
    experiment_arm: experimentArm,
    contender_id: contenderId,
    routing_score: routingScore,
    sample_count: sampleCount,
    confidence_score: confidenceScore,
    computed_at: now,
  });
  const shadowPolicyId = `arp_shadow_${(await sha256B64uUtf8(shadowMaterial)).slice(0, 24)}`;

  const routeReasonCodesSource = Array.isArray(routePayload.reason_codes)
    ? routePayload.reason_codes
    : (Array.isArray(recommended.reason_codes) ? recommended.reason_codes : []);

  const routeReasonCodes = routeReasonCodesSource.filter((entry): entry is string => typeof entry === 'string');

  const shadowPolicy = {
    schema_version: 'arena_route_policy_shadow.v1',
    route_policy_id: shadowPolicyId,
    contender_id: contenderId,
    routing_score: Number(routingScore.toFixed(6)),
    sample_count: sampleCount,
    confidence_score: confidenceScore,
    win_rate: Number(winRate.toFixed(4)),
    empirical_accept_rate: Number(acceptRate.toFixed(4)),
    override_rate: Number(overrideRate.toFixed(4)),
    rework_rate: Number(reworkRate.toFixed(4)),
    calibration_gap: Number(calibrationGap.toFixed(4)),
    objective_profile_name: objectiveProfileName || null,
    experiment_id: experimentId || null,
    experiment_arm: experimentArm || null,
    computed_at: now,
    reason_codes: routeReasonCodes,
  };

  const existingState = await getArenaRoutePolicyOptimizerState(env.BOUNTIES_DB, {
    taskFingerprint,
    environment,
    objectiveProfileName,
    experimentId,
    experimentArm,
  });

  const existingActive = parseArenaRoutePolicyJson(existingState?.active_policy_json ?? null);
  const previousContenderId = d1String(existingActive?.contender_id)?.trim() ?? null;

  const reasonCodes = ['ARENA_POLICY_SHADOW_REFRESHED'];
  const thresholdsMet = sampleCount >= minSamples && confidenceScore >= minConfidence;

  if (sampleCount < minSamples) {
    reasonCodes.push('ARENA_POLICY_NOT_READY_INSUFFICIENT_SAMPLE');
  }
  if (confidenceScore < minConfidence) {
    reasonCodes.push('ARENA_POLICY_NOT_READY_CONFIDENCE_BELOW_THRESHOLD');
  }

  let promotionStatus: 'PROMOTED' | 'NOT_READY' = 'NOT_READY';
  let promoted = false;
  let activePolicy: Record<string, unknown> | null = existingActive;

  if (thresholdsMet) {
    promotionStatus = 'PROMOTED';
    activePolicy = {
      ...shadowPolicy,
      schema_version: 'arena_route_policy_active.v1',
      promoted_at: now,
    };

    if (!previousContenderId) {
      reasonCodes.push('ARENA_POLICY_PROMOTED_INITIAL_ACTIVE');
      promoted = true;
    } else if (previousContenderId !== contenderId) {
      reasonCodes.push('ARENA_POLICY_PROMOTED_REPLACED_ACTIVE');
      promoted = true;
    } else {
      reasonCodes.push('ARENA_POLICY_PROMOTION_NOOP_ALREADY_ACTIVE');
    }
  } else {
    promotionStatus = 'NOT_READY';
    if (reasonCodes.length === 1) {
      reasonCodes.push('ARENA_POLICY_NOT_READY_UNKNOWN');
    }
  }

  const promotionEvent = {
    schema_version: 'arena_policy_promotion_event.v1',
    event_id: `arpe_${crypto.randomUUID()}`,
    status: promotionStatus,
    promoted,
    reason_codes: reasonCodes,
    previous_contender_id: previousContenderId,
    active_contender_id: d1String(activePolicy?.contender_id) ?? null,
    shadow_contender_id: contenderId,
    sample_count: sampleCount,
    confidence_score: confidenceScore,
    min_samples: minSamples,
    min_confidence: Number(minConfidence.toFixed(4)),
    computed_at: now,
  };

  const stateId = await buildArenaRoutePolicyOptimizerStateId({
    taskFingerprint,
    environment,
    objectiveProfileName,
    experimentId,
    experimentArm,
  });

  const state: ArenaRoutePolicyOptimizerStateRecord = {
    state_id: stateId,
    task_fingerprint: taskFingerprint,
    environment,
    objective_profile_name: objectiveProfileName,
    experiment_id: experimentId,
    experiment_arm: experimentArm,
    active_policy_json: activePolicy ? stableStringify(activePolicy) : null,
    shadow_policy_json: stableStringify(shadowPolicy),
    last_promotion_event_json: stableStringify(promotionEvent),
    reason_codes_json: stableStringify(reasonCodes),
    sample_count: sampleCount,
    confidence_score: confidenceScore,
    min_samples: minSamples,
    min_confidence: Number(minConfidence.toFixed(4)),
    promotion_status: promotionStatus,
    created_at: existingState?.created_at ?? now,
    updated_at: now,
  };

  try {
    await upsertArenaRoutePolicyOptimizerState(env.BOUNTIES_DB, state);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('DB_WRITE_FAILED', message, 500, undefined, version);
  }

  const payload = {
    ...buildArenaPolicyOptimizerPayloadFromState(state),
    route_snapshot: {
      analyzed_runs: d1Number(routePayload.analyzed_runs) ?? 0,
      winner_stability_ratio: d1Number(routePayload.winner_stability_ratio) ?? 0,
      recommended,
      backups: Array.isArray(routePayload.backups)
        ? routePayload.backups
        : [],
    },
  };

  return jsonResponse(payload, 200, version);
}

async function handleArenaBacktesting(
  request: Request,
  url: URL,
  env: Env,
  version: string,
): Promise<Response> {
  const adminError = requireAdmin(request, env, version);
  if (adminError) return adminError;

  const limitRaw = url.searchParams.get('limit');
  let limit = 200;
  if (isNonEmptyString(limitRaw)) {
    const parsed = Number.parseInt(limitRaw.trim(), 10);
    if (!Number.isFinite(parsed) || parsed <= 0) {
      return errorResponse('INVALID_REQUEST', 'limit must be a positive integer', 400, { field: 'limit' }, version);
    }
    limit = Math.min(parsed, 2000);
  }

  const taskFingerprintFilter = d1String(url.searchParams.get('task_fingerprint'))?.trim() ?? null;

  const candidateRuns = await listArenaRuns(env.BOUNTIES_DB, Math.min(limit * 3, 5000));
  const runs = candidateRuns
    .filter((run) => run.status === 'completed')
    .filter((run) => (taskFingerprintFilter ? run.task_fingerprint === taskFingerprintFilter : true))
    .slice(0, limit);

  const missReasonCounts = new Map<ArenaOverrideReasonCode, number>();
  const records: Array<{
    arena_id: string;
    bounty_id: string;
    task_fingerprint: string;
    predicted_winner_contender_id: string | null;
    actual_accepted_contender_id: string | null;
    predicted_confidence: number | null;
    prediction_hit: boolean | null;
    calibration_drift: number | null;
    miss_reason_code: ArenaOverrideReasonCode | null;
    completed_at: string | null;
  }> = [];

  for (const run of runs) {
    const outcomeRows = await listArenaOutcomesByArenaId(env.BOUNTIES_DB, run.arena_id, 200);

    const acceptedOutcome = outcomeRows.find((row) => row.accepted) ?? null;
    const predictedWinnerContenderId = run.winner_contender_id;
    const predictedOutcome = predictedWinnerContenderId
      ? outcomeRows.find((row) => row.contender_id === predictedWinnerContenderId) ?? null
      : null;

    const actualAcceptedContenderId = acceptedOutcome?.contender_id ?? null;
    const predictionHit = (predictedWinnerContenderId && actualAcceptedContenderId)
      ? predictedWinnerContenderId === actualAcceptedContenderId
      : null;

    const predictedConfidence = predictedOutcome?.predicted_confidence ?? null;
    const calibrationDrift = (predictionHit === null || predictedConfidence === null)
      ? null
      : Math.abs(predictedConfidence - (predictionHit ? 1 : 0));

    const missReasonCode = predictionHit === false
      ? (normalizeArenaOverrideReasonCode(acceptedOutcome?.override_reason_code) ?? 'ARENA_OVERRIDE_OTHER')
      : null;

    if (missReasonCode) {
      missReasonCounts.set(missReasonCode, (missReasonCounts.get(missReasonCode) ?? 0) + 1);
    }

    records.push({
      arena_id: run.arena_id,
      bounty_id: run.bounty_id,
      task_fingerprint: run.task_fingerprint,
      predicted_winner_contender_id: predictedWinnerContenderId,
      actual_accepted_contender_id: actualAcceptedContenderId,
      predicted_confidence: predictedConfidence,
      prediction_hit: predictionHit,
      calibration_drift: calibrationDrift === null ? null : Number(calibrationDrift.toFixed(4)),
      miss_reason_code: missReasonCode,
      completed_at: run.completed_at,
    });
  }

  const evaluatedRecords = records.filter((row) => row.prediction_hit !== null);
  const hits = evaluatedRecords.filter((row) => row.prediction_hit === true).length;
  const misses = evaluatedRecords.filter((row) => row.prediction_hit === false).length;
  const drifts = evaluatedRecords
    .map((row) => row.calibration_drift)
    .filter((row): row is number => row !== null);

  const avgDrift = drifts.length > 0
    ? drifts.reduce((sum, value) => sum + value, 0) / drifts.length
    : 0;

  const missReasonBreakdown = [...missReasonCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([reason_code, count]) => ({
      reason_code,
      count,
      share: misses > 0 ? Number((count / misses).toFixed(4)) : 0,
      contract_rewrite: ARENA_OVERRIDE_REASON_REGISTRY[reason_code].contract_rewrite,
      prompt_rewrite: ARENA_OVERRIDE_REASON_REGISTRY[reason_code].prompt_rewrite,
    }));

  const weightUpdateSuggestions = missReasonBreakdown
    .map((entry) => {
      const suggestion = ARENA_BACKTEST_WEIGHT_SUGGESTIONS[entry.reason_code];
      return {
        reason_code: entry.reason_code,
        priority_score: Number((entry.count * ARENA_OVERRIDE_REASON_REGISTRY[entry.reason_code].weight).toFixed(4)),
        count: entry.count,
        share: entry.share,
        recommended_weight_delta: suggestion.delta,
        rationale: suggestion.rationale,
      };
    })
    .sort((a, b) => b.priority_score - a.priority_score);

  return jsonResponse(
    {
      schema_version: 'arena_backtesting.v1',
      computed_at: new Date().toISOString(),
      task_fingerprint: taskFingerprintFilter,
      totals: {
        runs_considered: runs.length,
        evaluated_runs: evaluatedRecords.length,
        hits,
        misses,
        hit_rate: evaluatedRecords.length > 0 ? Number((hits / evaluatedRecords.length).toFixed(4)) : 0,
        miss_rate: evaluatedRecords.length > 0 ? Number((misses / evaluatedRecords.length).toFixed(4)) : 0,
      },
      calibration_drift: {
        avg_absolute_drift: Number(avgDrift.toFixed(4)),
      },
      top_miss_reasons: missReasonBreakdown,
      weight_update_suggestions: weightUpdateSuggestions,
      runs: records,
    },
    200,
    version,
  );
}

async function handleArenaManagerRoute(
  request: Request,
  env: Env,
  version: string,
  mode: 'route' | 'coach' = 'route',
): Promise<Response> {
  const adminError = requireAdmin(request, env, version);
  if (adminError) return adminError;

  const body = await parseJsonBody(request);
  if (!isRecord(body)) {
    return errorResponse('INVALID_REQUEST', 'Invalid JSON body', 400, undefined, version);
  }

  const taskFingerprint = d1String(body.task_fingerprint)?.trim();
  if (!taskFingerprint || taskFingerprint.length > 256) {
    return errorResponse('INVALID_REQUEST', 'task_fingerprint is required (<=256 chars)', 400, { field: 'task_fingerprint' }, version);
  }

  const objectiveProfileName = d1String(body.objective_profile_name)?.trim() ?? null;
  const experimentIdFilter = d1String(body.experiment_id)?.trim() ?? null;
  const experimentArmFilter = d1String(body.experiment_arm)?.trim() ?? null;
  const environment = normalizeArenaPolicyOptimizerEnvironment(
    body.environment,
    env.ENVIRONMENT?.trim().toLowerCase() ?? 'production',
  );

  if (experimentIdFilter && experimentIdFilter.length > 128) {
    return errorResponse('INVALID_REQUEST', 'experiment_id must be <=128 chars', 400, { field: 'experiment_id' }, version);
  }

  if (experimentArmFilter && experimentArmFilter.length > 64) {
    return errorResponse('INVALID_REQUEST', 'experiment_arm must be <=64 chars', 400, { field: 'experiment_arm' }, version);
  }

  const maxRunsRaw = body.max_runs;
  let maxRuns = 50;
  if (maxRunsRaw !== undefined) {
    const parsed = d1Number(maxRunsRaw);
    if (parsed === null || !Number.isInteger(parsed) || parsed <= 0) {
      return errorResponse('INVALID_REQUEST', 'max_runs must be a positive integer', 400, { field: 'max_runs' }, version);
    }
    maxRuns = Math.min(parsed, 200);
  }

  const requireHardGatePass = body.require_hard_gate_pass !== false;
  const allowFallback = body.allow_fallback !== false;
  const useActivePolicy = body.use_active_policy !== false;

  const requiredSkills = parseStringList(body.required_skills, 40, 120, true);
  const requiredTools = parseStringList(body.required_tools, 40, 120, true);
  const maxFleetCostTier = body.max_fleet_cost_tier === undefined || body.max_fleet_cost_tier === null
    ? null
    : parseArenaFleetCostTier(body.max_fleet_cost_tier);
  const maxFleetRiskTier = body.max_fleet_risk_tier === undefined || body.max_fleet_risk_tier === null
    ? null
    : parseArenaFleetRiskTier(body.max_fleet_risk_tier);

  if (!requiredSkills || !requiredTools) {
    return errorResponse('INVALID_REQUEST', 'required_skills/required_tools must be string[]', 400, undefined, version);
  }

  if (body.max_fleet_cost_tier !== undefined && body.max_fleet_cost_tier !== null && !maxFleetCostTier) {
    return errorResponse('INVALID_REQUEST', 'max_fleet_cost_tier must be low|medium|high', 400, { field: 'max_fleet_cost_tier' }, version);
  }

  if (body.max_fleet_risk_tier !== undefined && body.max_fleet_risk_tier !== null && !maxFleetRiskTier) {
    return errorResponse('INVALID_REQUEST', 'max_fleet_risk_tier must be low|medium|high', 400, { field: 'max_fleet_risk_tier' }, version);
  }

  const runsRaw = await listCompletedArenaRunsByTaskFingerprint(env.BOUNTIES_DB, taskFingerprint, maxRuns);
  const runs = runsRaw
    .filter((run) => isArenaRunRoutingEligible(run))
    .filter((run) => (objectiveProfileName ? getArenaObjectiveProfileNameFromRun(run) === objectiveProfileName : true))
    .filter((run) => (experimentIdFilter ? run.experiment_id === experimentIdFilter : true))
    .filter((run) => (experimentArmFilter ? run.experiment_arm === experimentArmFilter : true));

  if (runs.length === 0) {
    return errorResponse(
      'ARENA_ROUTE_NOT_FOUND',
      'No completed arena runs matched the routing query',
      404,
      {
        task_fingerprint: taskFingerprint,
        objective_profile_name: objectiveProfileName,
        experiment_id: experimentIdFilter,
        experiment_arm: experimentArmFilter,
      },
      version,
    );
  }

  type RoutingAggregate = {
    contender_id: string;
    label: string;
    model: string;
    harness: string;
    appearances: number;
    wins: number;
    hard_gate_passes: number;
    avg_score_sum: number;
    avg_risk_sum: number;
    avg_quality_sum: number;
    latest_hard_gate_pass: boolean;
    last_seen_at: string;
    sample_run_ids: string[];
  };

  type OutcomeAggregate = {
    samples: number;
    accepted: number;
    overridden: number;
    rework: number;
    confidence_sum: number;
    override_weight_sum: number;
    override_reason_counts: Map<ArenaOverrideReasonCode, number>;
  };

  const aggregates = new Map<string, RoutingAggregate>();
  const outcomeAggregates = new Map<string, OutcomeAggregate>();

  const winnerCounts = new Map<string, number>();
  for (const run of runs) {
    if (run.winner_contender_id) {
      winnerCounts.set(run.winner_contender_id, (winnerCounts.get(run.winner_contender_id) ?? 0) + 1);
    }

    const contenderRows = await listArenaContendersByRunId(env.BOUNTIES_DB, run.run_id);
    for (const contenderRow of contenderRows) {
      const contender = parseArenaContenderResult(contenderRow);
      if (!contender) {
        return errorResponse('DATA_INTEGRITY_ERROR', 'Arena contender payload is invalid', 500, { run_id: run.run_id }, version);
      }

      const existing = aggregates.get(contender.contender_id);
      if (!existing) {
        aggregates.set(contender.contender_id, {
          contender_id: contender.contender_id,
          label: contender.label,
          model: contender.model,
          harness: contender.harness,
          appearances: 1,
          wins: run.winner_contender_id === contender.contender_id ? 1 : 0,
          hard_gate_passes: contender.hard_gate_pass ? 1 : 0,
          avg_score_sum: contender.score,
          avg_risk_sum: contender.metrics.risk_score,
          avg_quality_sum: contender.metrics.quality_score,
          latest_hard_gate_pass: contender.hard_gate_pass,
          last_seen_at: run.updated_at,
          sample_run_ids: [run.run_id],
        });
      } else {
        existing.appearances += 1;
        existing.wins += run.winner_contender_id === contender.contender_id ? 1 : 0;
        existing.hard_gate_passes += contender.hard_gate_pass ? 1 : 0;
        existing.avg_score_sum += contender.score;
        existing.avg_risk_sum += contender.metrics.risk_score;
        existing.avg_quality_sum += contender.metrics.quality_score;

        if (run.updated_at >= existing.last_seen_at) {
          existing.last_seen_at = run.updated_at;
          existing.latest_hard_gate_pass = contender.hard_gate_pass;
        }

        if (existing.sample_run_ids.length < 10) {
          existing.sample_run_ids.push(run.run_id);
        }
      }
    }

    const outcomeRows = await listArenaOutcomesByArenaId(env.BOUNTIES_DB, run.arena_id, 50);
    for (const outcome of outcomeRows) {
      const overrideReasonCode = normalizeArenaOverrideReasonCode(outcome.override_reason_code) ?? 'ARENA_OVERRIDE_OTHER';
      const overrideWeight = outcome.overridden
        ? ARENA_OVERRIDE_REASON_REGISTRY[overrideReasonCode].weight
        : 0;

      const existing = outcomeAggregates.get(outcome.contender_id);
      if (!existing) {
        const reasonCounts = new Map<ArenaOverrideReasonCode, number>();
        if (outcome.overridden) {
          reasonCounts.set(overrideReasonCode, 1);
        }

        outcomeAggregates.set(outcome.contender_id, {
          samples: 1,
          accepted: outcome.accepted ? 1 : 0,
          overridden: outcome.overridden ? 1 : 0,
          rework: outcome.rework_required ? 1 : 0,
          confidence_sum: outcome.predicted_confidence,
          override_weight_sum: overrideWeight,
          override_reason_counts: reasonCounts,
        });
      } else {
        existing.samples += 1;
        existing.accepted += outcome.accepted ? 1 : 0;
        existing.overridden += outcome.overridden ? 1 : 0;
        existing.rework += outcome.rework_required ? 1 : 0;
        existing.confidence_sum += outcome.predicted_confidence;
        existing.override_weight_sum += overrideWeight;

        if (outcome.overridden) {
          existing.override_reason_counts.set(
            overrideReasonCode,
            (existing.override_reason_counts.get(overrideReasonCode) ?? 0) + 1,
          );
        }
      }
    }
  }

  const ranked = [...aggregates.values()]
    .map((entry) => {
      const appearances = entry.appearances;
      const winRate = entry.wins / appearances;
      const hardGatePassRate = entry.hard_gate_passes / appearances;
      const avgScore = entry.avg_score_sum / appearances;
      const avgRisk = entry.avg_risk_sum / appearances;
      const avgQuality = entry.avg_quality_sum / appearances;

      const outcomes = outcomeAggregates.get(entry.contender_id);
      const outcomeSamples = outcomes?.samples ?? 0;
      const acceptRate = outcomeSamples > 0 ? (outcomes?.accepted ?? 0) / outcomeSamples : 0;
      const overrideRate = outcomeSamples > 0 ? (outcomes?.overridden ?? 0) / outcomeSamples : 0;
      const reworkRate = outcomeSamples > 0 ? (outcomes?.rework ?? 0) / outcomeSamples : 0;
      const avgPredictedConfidence = outcomeSamples > 0 ? (outcomes?.confidence_sum ?? 0) / outcomeSamples : 0;
      const calibrationGap = outcomeSamples > 0 ? avgPredictedConfidence - acceptRate : 0;
      const overrideReasonPenalty = outcomeSamples > 0 ? (outcomes?.override_weight_sum ?? 0) / outcomeSamples : 0;

      const overrideReasonBreakdown = [...(outcomes?.override_reason_counts ?? new Map<ArenaOverrideReasonCode, number>()).entries()]
        .sort((a, b) => b[1] - a[1])
        .map(([reason_code, count]) => ({
          reason_code,
          count,
          share: outcomeSamples > 0 ? Number((count / outcomeSamples).toFixed(4)) : 0,
          contract_rewrite: ARENA_OVERRIDE_REASON_REGISTRY[reason_code].contract_rewrite,
          prompt_rewrite: ARENA_OVERRIDE_REASON_REGISTRY[reason_code].prompt_rewrite,
        }));

      const topOverrideReasonCode = overrideReasonBreakdown[0]?.reason_code ?? null;

      const baseRoutingScore =
        (avgScore * 0.65) +
        (winRate * 25) +
        (hardGatePassRate * 10) -
        (avgRisk * 0.1);

      const outcomeAdjustment =
        (acceptRate * 12) -
        (overrideRate * 18) -
        (reworkRate * 12) -
        (Math.abs(calibrationGap) * 8) -
        (overrideReasonPenalty * 10);

      const routingScore = baseRoutingScore + outcomeAdjustment;

      const coachingRecommendations: string[] = [];
      if (overrideRate >= 0.3) coachingRecommendations.push('High override rate; add human checkpoint before auto-route.');
      if (reworkRate >= 0.25) coachingRecommendations.push('Frequent rework; tighten task decomposition and acceptance criteria.');
      if (calibrationGap >= 0.2) coachingRecommendations.push('Predicted confidence appears over-optimistic; down-weight autonomy claims.');
      if (calibrationGap <= -0.2) coachingRecommendations.push('Predicted confidence appears conservative; contender may be under-utilized.');
      if (avgRisk >= 40) coachingRecommendations.push('Risk profile elevated; enforce stricter safety gates and staged rollout.');
      if (hardGatePassRate < 1) coachingRecommendations.push('Mandatory checks not consistently passing; fix contract compliance first.');

      if (topOverrideReasonCode && overrideRate > 0) {
        const hint = ARENA_OVERRIDE_REASON_REGISTRY[topOverrideReasonCode];
        coachingRecommendations.push(`Top override reason (${topOverrideReasonCode}): ${hint.contract_rewrite}`);
        coachingRecommendations.push(`Prompt rewrite hint: ${hint.prompt_rewrite}`);
      }

      if (coachingRecommendations.length === 0) coachingRecommendations.push('Stable performer; keep as primary route for matching fingerprint.');

      return {
        contender_id: entry.contender_id,
        label: entry.label,
        model: entry.model,
        harness: entry.harness,
        appearances,
        wins: entry.wins,
        win_rate: Number(winRate.toFixed(4)),
        hard_gate_pass_rate: Number(hardGatePassRate.toFixed(4)),
        avg_score: Number(avgScore.toFixed(4)),
        avg_risk: Number(avgRisk.toFixed(4)),
        avg_quality: Number(avgQuality.toFixed(4)),
        latest_hard_gate_pass: entry.latest_hard_gate_pass,
        routing_score: Number(routingScore.toFixed(6)),
        outcome_samples: outcomeSamples,
        empirical_accept_rate: Number(acceptRate.toFixed(4)),
        override_rate: Number(overrideRate.toFixed(4)),
        rework_rate: Number(reworkRate.toFixed(4)),
        avg_predicted_confidence: Number(avgPredictedConfidence.toFixed(4)),
        calibration_gap: Number(calibrationGap.toFixed(4)),
        override_reason_penalty: Number(overrideReasonPenalty.toFixed(4)),
        top_override_reason_code: topOverrideReasonCode,
        override_reason_breakdown: overrideReasonBreakdown,
        coaching_recommendations: coachingRecommendations,
        last_seen_at: entry.last_seen_at,
        sample_run_ids: entry.sample_run_ids,
      };
    })
    .sort((a, b) => {
      if (b.routing_score !== a.routing_score) return b.routing_score - a.routing_score;
      if (b.avg_score !== a.avg_score) return b.avg_score - a.avg_score;
      return a.contender_id.localeCompare(b.contender_id);
    });

  const eligible = requireHardGatePass
    ? ranked.filter((entry) => entry.latest_hard_gate_pass)
    : ranked;

  if (eligible.length === 0 && !allowFallback) {
    return errorResponse(
      'ARENA_ROUTE_HARD_GATE_BLOCKED',
      'No contender satisfies hard gate routing policy',
      409,
      {
        task_fingerprint: taskFingerprint,
        objective_profile_name: objectiveProfileName,
        experiment_id: experimentIdFilter,
        experiment_arm: experimentArmFilter,
      },
      version,
    );
  }

  const selectedPool = eligible.length > 0 ? eligible : ranked;
  if (selectedPool.length === 0) {
    return errorResponse('ARENA_ROUTE_NOT_FOUND', 'No routing candidates available', 404, undefined, version);
  }

  let recommended = selectedPool[0];
  if (!recommended) {
    return errorResponse('ARENA_ROUTE_NOT_FOUND', 'No routing candidates available', 404, undefined, version);
  }

  let policyOptimizerState: ArenaRoutePolicyOptimizerStateRecord | null = null;
  const policyOptimizerReasonCodes: string[] = [];

  if (useActivePolicy) {
    policyOptimizerState = await getArenaRoutePolicyOptimizerState(env.BOUNTIES_DB, {
      taskFingerprint,
      environment,
      objectiveProfileName: normalizeArenaPolicyDimensionValue(objectiveProfileName),
      experimentId: normalizeArenaPolicyDimensionValue(experimentIdFilter),
      experimentArm: normalizeArenaPolicyDimensionValue(experimentArmFilter),
    });

    const activePolicy = parseArenaRoutePolicyJson(policyOptimizerState?.active_policy_json ?? null);
    const activeContenderId = d1String(activePolicy?.contender_id)?.trim() ?? null;

    if (activeContenderId) {
      const activeCandidate = selectedPool.find((entry) => entry.contender_id === activeContenderId) ?? null;
      if (activeCandidate) {
        recommended = activeCandidate;
        policyOptimizerReasonCodes.push('ARENA_ROUTING_ACTIVE_POLICY_APPLIED');
      } else {
        policyOptimizerReasonCodes.push('ARENA_ROUTING_ACTIVE_POLICY_MISS');
      }
    } else if (policyOptimizerState) {
      policyOptimizerReasonCodes.push('ARENA_ROUTING_ACTIVE_POLICY_EMPTY');
    }
  }

  const reasonCodes = [
    eligible.length > 0 ? 'ARENA_ROUTING_SELECTED' : 'ARENA_ROUTING_HARD_GATE_FALLBACK',
    objectiveProfileName ? 'ARENA_ROUTING_OBJECTIVE_MATCHED' : 'ARENA_ROUTING_OBJECTIVE_ANY',
    mode === 'coach' ? 'ARENA_ROUTING_COACH_MODE' : 'ARENA_ROUTING_STANDARD_MODE',
    ...policyOptimizerReasonCodes,
  ];

  const backups = selectedPool
    .filter((entry) => entry.contender_id !== recommended.contender_id)
    .slice(0, 3);

  const fleetMatch = await computeArenaFleetCapabilityMatch(env.BOUNTIES_DB, {
    objectiveProfileName,
    harness: recommended.harness,
    contenderId: recommended.contender_id,
    requiredSkills,
    requiredTools,
    maxCostTier: maxFleetCostTier,
    maxRiskTier: maxFleetRiskTier,
    limit: 5,
  });

  const fleetReasonCodes = Array.isArray(fleetMatch.reason_codes)
    ? fleetMatch.reason_codes.filter((entry): entry is string => typeof entry === 'string')
    : [];

  if (fleetReasonCodes.length > 0) {
    reasonCodes.push(...fleetReasonCodes);
  }

  if (fleetMatch.status === 'matched') {
    reasonCodes.push('ARENA_ROUTING_FLEET_MATCHED');
  } else {
    reasonCodes.push('ARENA_ROUTING_FLEET_UNAVAILABLE');
  }

  const topWinner = [...winnerCounts.entries()].sort((a, b) => b[1] - a[1])[0] ?? null;
  const winnerStabilityRatio = topWinner && runs.length > 0 ? topWinner[1] / runs.length : 0;

  const globalCoachRecommendations: string[] = [];
  if (winnerStabilityRatio < 0.6) {
    globalCoachRecommendations.push('Winner stability is low for this fingerprint; run arena more frequently before defaulting routes.');
  }
  if (recommended.override_rate >= 0.25) {
    globalCoachRecommendations.push('Primary route has elevated override rate; require manual approval until calibration improves.');
  }
  if (recommended.calibration_gap >= 0.2) {
    globalCoachRecommendations.push('Primary route is over-confident; cap auto-approval confidence thresholds.');
  }
  if (recommended.top_override_reason_code) {
    const topReasonCode = recommended.top_override_reason_code as ArenaOverrideReasonCode;
    const hint = ARENA_OVERRIDE_REASON_REGISTRY[topReasonCode];
    globalCoachRecommendations.push(`Policy-learning signal (${topReasonCode}): ${hint.contract_rewrite}`);
    globalCoachRecommendations.push(`Prompt-learning signal: ${hint.prompt_rewrite}`);
  }
  if (globalCoachRecommendations.length === 0) {
    globalCoachRecommendations.push('Routing profile appears stable; continue autonomous routing with periodic calibration checks.');
  }

  return jsonResponse(
    {
      schema_version: mode === 'coach' ? 'arena_manager_coach.v1' : 'arena_manager_route.v2',
      computed_at: new Date().toISOString(),
      mode,
      task_fingerprint: taskFingerprint,
      objective_profile_name: objectiveProfileName,
      experiment_id: experimentIdFilter,
      experiment_arm: experimentArmFilter,
      analyzed_runs: runs.length,
      winner_stability_ratio: Number(winnerStabilityRatio.toFixed(4)),
      policy: {
        require_hard_gate_pass: requireHardGatePass,
        allow_fallback: allowFallback,
        use_active_policy: useActivePolicy,
        environment,
        max_runs: maxRuns,
        experiment_id: experimentIdFilter,
        experiment_arm: experimentArmFilter,
        required_skills: requiredSkills,
        required_tools: requiredTools,
        max_fleet_cost_tier: maxFleetCostTier,
        max_fleet_risk_tier: maxFleetRiskTier,
      },
      recommended: {
        contender_id: recommended.contender_id,
        label: recommended.label,
        model: recommended.model,
        harness: recommended.harness,
        routing_score: recommended.routing_score,
        reason_codes: reasonCodes,
        rationale: `Selected ${recommended.contender_id} with routing_score=${recommended.routing_score} from ${recommended.appearances} matched runs (win_rate=${recommended.win_rate}, hard_gate_pass_rate=${recommended.hard_gate_pass_rate}, override_rate=${recommended.override_rate}, top_override_reason=${recommended.top_override_reason_code ?? 'none'}, calibration_gap=${recommended.calibration_gap}).`,
        evidence: {
          appearances: recommended.appearances,
          wins: recommended.wins,
          win_rate: recommended.win_rate,
          hard_gate_pass_rate: recommended.hard_gate_pass_rate,
          avg_score: recommended.avg_score,
          avg_risk: recommended.avg_risk,
          avg_quality: recommended.avg_quality,
          latest_hard_gate_pass: recommended.latest_hard_gate_pass,
          outcome_samples: recommended.outcome_samples,
          empirical_accept_rate: recommended.empirical_accept_rate,
          override_rate: recommended.override_rate,
          rework_rate: recommended.rework_rate,
          avg_predicted_confidence: recommended.avg_predicted_confidence,
          calibration_gap: recommended.calibration_gap,
          override_reason_penalty: recommended.override_reason_penalty,
          top_override_reason_code: recommended.top_override_reason_code,
          override_reason_breakdown: recommended.override_reason_breakdown,
          coaching_recommendations: recommended.coaching_recommendations,
          last_seen_at: recommended.last_seen_at,
          sample_run_ids: recommended.sample_run_ids,
        },
      },
      backups,
      contenders_ranked: ranked,
      policy_optimizer: policyOptimizerState
        ? buildArenaPolicyOptimizerPayloadFromState(policyOptimizerState)
        : null,
      fleet_match: fleetMatch,
      delegation_coach: {
        primary_contender_id: recommended.contender_id,
        backup_contenders: backups.map((entry) => entry.contender_id),
        global_recommendations: globalCoachRecommendations,
        contender_cards: selectedPool.slice(0, 3).map((entry) => ({
          contender_id: entry.contender_id,
          routing_score: entry.routing_score,
          override_rate: entry.override_rate,
          rework_rate: entry.rework_rate,
          calibration_gap: entry.calibration_gap,
          top_override_reason_code: entry.top_override_reason_code,
          override_reason_breakdown: entry.override_reason_breakdown,
          coaching_recommendations: entry.coaching_recommendations,
        })),
      },
    },
    200,
    version,
  );
}

async function buildArenaManagerAutopilotPayload(
  routePayload: Record<string, unknown>,
): Promise<Record<string, unknown> | null> {
  const recommended = isRecord(routePayload.recommended) ? routePayload.recommended : null;
  if (!recommended) return null;

  const defaultContenderId = d1String(recommended.contender_id)?.trim() ?? null;
  const evidence = isRecord(recommended.evidence) ? recommended.evidence : null;
  if (!defaultContenderId || !evidence) return null;

  const backupsRaw = Array.isArray(routePayload.backups) ? routePayload.backups : [];
  const backupContenders = backupsRaw
    .map((entry) => (isRecord(entry) ? d1String(entry.contender_id)?.trim() ?? null : null))
    .filter((entry): entry is string => Boolean(entry));

  const fleetMatch = isRecord(routePayload.fleet_match) ? routePayload.fleet_match : null;
  const fleetStatus = d1String(fleetMatch?.status)?.trim() ?? 'unavailable';
  const fleetCandidates = Array.isArray(fleetMatch?.candidates)
    ? fleetMatch.candidates.filter((entry): entry is Record<string, unknown> => isRecord(entry))
    : [];
  const fleetReasonCodes = Array.isArray(fleetMatch?.reason_codes)
    ? fleetMatch.reason_codes.filter((entry): entry is string => typeof entry === 'string')
    : [];

  const analyzedRuns = d1Number(routePayload.analyzed_runs) ?? 0;
  const winnerStabilityRatio = d1Number(routePayload.winner_stability_ratio) ?? 0;

  const winRate = d1Number(evidence.win_rate) ?? 0;
  const overrideRate = d1Number(evidence.override_rate) ?? 0;
  const reworkRate = d1Number(evidence.rework_rate) ?? 0;
  const calibrationGap = d1Number(evidence.calibration_gap) ?? 0;
  const latestHardGatePass = evidence.latest_hard_gate_pass === true;

  const guardrails = {
    min_runs: 2,
    min_winner_stability_ratio: 0.6,
    min_win_rate: 0.5,
    max_override_rate: 0.3,
    max_rework_rate: 0.2,
    max_abs_calibration_gap: 0.2,
    require_latest_hard_gate_pass: true,
  };

  const violations: Array<{ code: string; message: string; value: number | boolean; threshold: number | boolean }> = [];
  if (analyzedRuns < guardrails.min_runs) {
    violations.push({
      code: 'ARENA_AUTOPILOT_INSUFFICIENT_RUNS',
      message: 'Matched runs are below minimum threshold for autonomous default routing.',
      value: analyzedRuns,
      threshold: guardrails.min_runs,
    });
  }

  if (winnerStabilityRatio < guardrails.min_winner_stability_ratio) {
    violations.push({
      code: 'ARENA_AUTOPILOT_LOW_WINNER_STABILITY',
      message: 'Winner stability is below autopilot threshold.',
      value: Number(winnerStabilityRatio.toFixed(4)),
      threshold: guardrails.min_winner_stability_ratio,
    });
  }

  if (winRate < guardrails.min_win_rate) {
    violations.push({
      code: 'ARENA_AUTOPILOT_LOW_WIN_RATE',
      message: 'Recommended contender win rate is below threshold.',
      value: Number(winRate.toFixed(4)),
      threshold: guardrails.min_win_rate,
    });
  }

  if (overrideRate > guardrails.max_override_rate) {
    violations.push({
      code: 'ARENA_AUTOPILOT_HIGH_OVERRIDE_RATE',
      message: 'Override rate exceeds autopilot limit.',
      value: Number(overrideRate.toFixed(4)),
      threshold: guardrails.max_override_rate,
    });
  }

  if (reworkRate > guardrails.max_rework_rate) {
    violations.push({
      code: 'ARENA_AUTOPILOT_HIGH_REWORK_RATE',
      message: 'Rework rate exceeds autopilot limit.',
      value: Number(reworkRate.toFixed(4)),
      threshold: guardrails.max_rework_rate,
    });
  }

  if (Math.abs(calibrationGap) > guardrails.max_abs_calibration_gap) {
    violations.push({
      code: 'ARENA_AUTOPILOT_CALIBRATION_GAP_HIGH',
      message: 'Calibration gap exceeds allowed threshold.',
      value: Number(calibrationGap.toFixed(4)),
      threshold: guardrails.max_abs_calibration_gap,
    });
  }

  if (guardrails.require_latest_hard_gate_pass && !latestHardGatePass) {
    violations.push({
      code: 'ARENA_AUTOPILOT_HARD_GATE_NOT_STABLE',
      message: 'Latest recommended contender run did not pass hard-gate requirements.',
      value: latestHardGatePass,
      threshold: true,
    });
  }

  if (fleetStatus !== 'matched' || fleetCandidates.length === 0) {
    violations.push({
      code: 'ARENA_AUTOPILOT_NO_FLEET_WORKER',
      message: 'No online fleet worker matched the recommended contender capability profile.',
      value: fleetCandidates.length,
      threshold: 1,
    });
  }

  const status = violations.length === 0 ? 'auto_route_enabled' : 'manual_review_required';

  const globalRecommendations = (() => {
    const coach = isRecord(routePayload.delegation_coach) ? routePayload.delegation_coach : null;
    const recsRaw = coach && Array.isArray(coach.global_recommendations) ? coach.global_recommendations : [];
    return recsRaw.filter((entry): entry is string => typeof entry === 'string');
  })();

  const computedAt = new Date().toISOString();
  const routePolicyMaterial = stableStringify({
    task_fingerprint: routePayload.task_fingerprint ?? null,
    objective_profile_name: routePayload.objective_profile_name ?? null,
    experiment_id: routePayload.experiment_id ?? null,
    experiment_arm: routePayload.experiment_arm ?? null,
    default_contender_id: defaultContenderId,
    backup_contenders: backupContenders,
    status,
    computed_at: computedAt,
  });
  const routePolicyId = `arp_${(await sha256B64uUtf8(routePolicyMaterial)).slice(0, 32)}`;

  return {
    schema_version: 'arena_manager_autopilot.v1',
    computed_at: computedAt,
    mode: 'autopilot',
    task_fingerprint: d1String(routePayload.task_fingerprint) ?? null,
    objective_profile_name: d1String(routePayload.objective_profile_name) ?? null,
    experiment_id: d1String(routePayload.experiment_id) ?? null,
    experiment_arm: d1String(routePayload.experiment_arm) ?? null,
    analyzed_runs: analyzedRuns,
    winner_stability_ratio: Number(winnerStabilityRatio.toFixed(4)),
    route: {
      recommended,
      backups: backupsRaw,
      reason_codes: Array.isArray(routePayload.reason_codes)
        ? routePayload.reason_codes.filter((entry): entry is string => typeof entry === 'string')
        : [],
    },
    fleet_match: fleetMatch,
    autopilot: {
      status,
      default_contender_id: defaultContenderId,
      backup_contenders: backupContenders,
      guardrails,
      violations,
      reason_codes: status === 'auto_route_enabled'
        ? ['ARENA_AUTOPILOT_ENABLED', 'ARENA_AUTOPILOT_GUARDRAILS_PASSED', ...fleetReasonCodes]
        : ['ARENA_AUTOPILOT_MANUAL_REVIEW_REQUIRED', ...fleetReasonCodes],
      recommendations: globalRecommendations,
      policy_template: {
        route_policy_id: routePolicyId,
        task_fingerprint: d1String(routePayload.task_fingerprint) ?? null,
        default_contender_id: defaultContenderId,
        backup_contenders: backupContenders,
        require_manual_approval: status !== 'auto_route_enabled',
        generated_at: computedAt,
      },
    },
  };
}

async function handleArenaManagerAutopilot(
  request: Request,
  env: Env,
  version: string,
): Promise<Response> {
  const routeResponse = await handleArenaManagerRoute(request, env, version, 'route');
  if (routeResponse.status !== 200) {
    return routeResponse;
  }

  let routePayload: unknown;
  try {
    routePayload = await routeResponse.json();
  } catch {
    return errorResponse('INTERNAL_ERROR', 'Failed to parse manager route payload', 500, undefined, version);
  }

  if (!isRecord(routePayload)) {
    return errorResponse('DATA_INTEGRITY_ERROR', 'Manager route payload is invalid', 500, undefined, version);
  }

  const autopilot = await buildArenaManagerAutopilotPayload(routePayload);
  if (!autopilot) {
    return errorResponse('DATA_INTEGRITY_ERROR', 'Autopilot payload could not be computed', 500, undefined, version);
  }

  return jsonResponse(autopilot, 200, version);
}

function buildArenaAutopilotPreview(
  run: ArenaRunRecord,
  payload: Record<string, unknown>,
  calibration: Record<string, unknown>,
): Record<string, unknown> {
  const delegationInsights = isRecord(payload.delegation_insights) ? payload.delegation_insights : null;
  const managerRouting = delegationInsights && isRecord(delegationInsights.manager_routing)
    ? delegationInsights.manager_routing
    : null;

  const backupContenders = managerRouting && Array.isArray(managerRouting.backup_contenders)
    ? managerRouting.backup_contenders.filter((entry): entry is string => typeof entry === 'string')
    : [];

  const totals = isRecord(calibration.totals) ? calibration.totals : null;
  const winnerStability = Array.isArray(calibration.winner_stability)
    ? calibration.winner_stability.find((entry) => isRecord(entry) && d1String(entry.task_fingerprint) === run.task_fingerprint)
    : null;

  const overrideRate = totals ? d1Number(totals.override_rate) ?? 0 : 0;
  const reworkRate = totals ? d1Number(totals.rework_rate) ?? 0 : 0;
  const stabilityRatio = winnerStability && isRecord(winnerStability)
    ? d1Number(winnerStability.stability_ratio) ?? 0
    : 1;

  const guardrails = {
    max_override_rate: 0.3,
    max_rework_rate: 0.2,
    min_winner_stability_ratio: 0.6,
  };

  const violations: string[] = [];
  if (overrideRate > guardrails.max_override_rate) violations.push('ARENA_AUTOPILOT_HIGH_OVERRIDE_RATE');
  if (reworkRate > guardrails.max_rework_rate) violations.push('ARENA_AUTOPILOT_HIGH_REWORK_RATE');
  if (stabilityRatio < guardrails.min_winner_stability_ratio) violations.push('ARENA_AUTOPILOT_LOW_WINNER_STABILITY');

  const status = violations.length === 0 ? 'auto_route_enabled' : 'manual_review_required';

  return {
    schema_version: 'arena_autopilot_preview.v1',
    status,
    task_fingerprint: run.task_fingerprint,
    default_contender_id: run.winner_contender_id,
    backup_contenders: backupContenders,
    guardrails,
    metrics: {
      override_rate: Number(overrideRate.toFixed(4)),
      rework_rate: Number(reworkRate.toFixed(4)),
      winner_stability_ratio: Number(stabilityRatio.toFixed(4)),
    },
    reason_codes: status === 'auto_route_enabled'
      ? ['ARENA_AUTOPILOT_PREVIEW_ENABLED']
      : ['ARENA_AUTOPILOT_PREVIEW_MANUAL_REVIEW'],
    violations,
  };
}

async function buildArenaPolicyOptimizerPreview(
  db: D1Database,
  run: ArenaRunRecord,
  environmentFallback: string,
): Promise<Record<string, unknown>> {
  const state = await getArenaRoutePolicyOptimizerState(db, {
    taskFingerprint: run.task_fingerprint,
    environment: normalizeArenaPolicyOptimizerEnvironment(environmentFallback, 'production'),
    objectiveProfileName: normalizeArenaPolicyDimensionValue(getArenaObjectiveProfileNameFromRun(run)),
    experimentId: normalizeArenaPolicyDimensionValue(run.experiment_id),
    experimentArm: normalizeArenaPolicyDimensionValue(run.experiment_arm),
  });

  if (!state) {
    return {
      schema_version: 'arena_policy_optimizer_preview.v1',
      status: 'empty',
      task_fingerprint: run.task_fingerprint,
    };
  }

  return {
    schema_version: 'arena_policy_optimizer_preview.v1',
    status: 'available',
    ...buildArenaPolicyOptimizerPayloadFromState(state),
  };
}

async function handleGetBounty(bountyId: string, env: Env, version: string): Promise<Response> {
  const bounty = await getBountyById(env.BOUNTIES_DB, bountyId);
  if (!bounty) {
    return errorResponse('NOT_FOUND', 'Bounty not found', 404, undefined, version);
  }

  const run = await getLatestArenaRunByBountyId(env.BOUNTIES_DB, bountyId);
  let arena: Record<string, unknown> | null = null;
  if (run) {
    arena = await buildArenaPayloadFromRun(env.BOUNTIES_DB, run);
  }

  return jsonResponse({ ...bounty, arena_lifecycle: buildBountyArenaLifecycleSummary(bounty), arena }, 200, version);
}

async function handleListBountySubmissions(
  bountyId: string,
  request: Request,
  url: URL,
  env: Env,
  version: string
): Promise<Response> {
  const limitRaw = url.searchParams.get('limit');
  const defaultLimit = 50;
  const maxLimit = 200;

  let limit = defaultLimit;
  if (isNonEmptyString(limitRaw)) {
    const n = Number.parseInt(limitRaw.trim(), 10);
    if (!Number.isFinite(n) || n <= 0) {
      return errorResponse('INVALID_REQUEST', 'limit must be a positive integer', 400, undefined, version);
    }
    limit = Math.min(maxLimit, n);
  }

  const statusRaw = url.searchParams.get('status');
  let status: SubmissionStatus | undefined;
  if (statusRaw !== null) {
    const parsed = parseSubmissionStatus(statusRaw);
    if (!parsed) {
      return errorResponse('INVALID_REQUEST', 'status must be pending_review|invalid|approved|rejected', 400, undefined, version);
    }
    status = parsed;
  }

  const workerDidRaw = url.searchParams.get('worker_did');
  let workerDidFilter: string | undefined;
  if (workerDidRaw !== null) {
    if (!isNonEmptyString(workerDidRaw) || !workerDidRaw.trim().startsWith('did:')) {
      return errorResponse('INVALID_REQUEST', 'worker_did must be a DID string', 400, undefined, version);
    }
    workerDidFilter = workerDidRaw.trim();
  }

  let bounty: BountyV2 | null;
  try {
    bounty = await getBountyById(env.BOUNTIES_DB, bountyId);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('DB_READ_FAILED', message, 500, undefined, version);
  }

  if (!bounty) {
    return errorResponse('NOT_FOUND', 'Bounty not found', 404, { bounty_id: bountyId }, version);
  }

  const viewer = await resolveSubmissionViewerContext(request, env, version, {
    requester_did_hint: bounty.requester_did,
  });
  if (!viewer.ok) return viewer.error;

  if (viewer.context.kind === 'requester') {
    try {
      await insertRequesterAuthEvent(env.BOUNTIES_DB, {
        action: 'read_submission',
        bounty_id: bounty.bounty_id,
        submission_id: null,
        auth: viewer.context.auth,
        created_at: new Date().toISOString(),
        sensitive_transition: false,
        control_plane_check: null,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      return errorResponse('DB_WRITE_FAILED', message, 500, undefined, version);
    }
  }

  if (viewer.context.kind === 'worker') {
    const workerDid = viewer.context.worker.worker_did;
    if (workerDidFilter && workerDidFilter !== workerDid) {
      return errorResponse('FORBIDDEN', 'Workers may only view their own submissions', 403, undefined, version);
    }
    workerDidFilter = workerDid;
  }

  let submissions: SubmissionRecord[];
  try {
    submissions = await listSubmissionsByBounty(env.BOUNTIES_DB, {
      bounty_id: bounty.bounty_id,
      status,
      worker_did: workerDidFilter,
      limit,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('DB_READ_FAILED', message, 500, undefined, version);
  }

  const arenaExplorerBaseUrl = resolveArenaExplorerBaseUrl(env);
  let latestArenaRun: ArenaRunRecord | null = null;
  let latestArenaWinnerContender: ArenaContenderResult | null = null;
  let latestArenaThreadForWinner: ArenaReviewThreadEntry | null = null;
  let latestArenaSummary: ArenaInlineReviewSummaryView | null = null;
  try {
    latestArenaRun = await getLatestArenaRunByBountyId(env.BOUNTIES_DB, bounty.bounty_id);
    if (latestArenaRun) {
      const contenderRows = await listArenaContendersByRunId(env.BOUNTIES_DB, latestArenaRun.run_id);
      if (latestArenaRun.winner_contender_id) {
        const winnerRow = contenderRows.find((row) => row.contender_id === latestArenaRun?.winner_contender_id) ?? null;
        latestArenaWinnerContender = winnerRow ? parseArenaContenderResult(winnerRow) : null;
      }

      const winnerContenderId = latestArenaRun.winner_contender_id ?? latestArenaWinnerContender?.contender_id ?? null;
      if (winnerContenderId) {
        const threadEntries = await listArenaReviewThreadByArenaId(env.BOUNTIES_DB, latestArenaRun.arena_id, 50);
        latestArenaThreadForWinner = threadEntries.find((entry) => entry.contender_id === winnerContenderId) ?? null;
      }

      latestArenaSummary = buildArenaInlineReviewSummaryView(
        latestArenaRun,
        latestArenaWinnerContender,
        arenaExplorerBaseUrl,
      );
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('DB_READ_FAILED', message, 500, undefined, version);
  }

  const views: SubmissionSummaryView[] = [];
  for (const record of submissions) {
    try {
      const latest = await getLatestTestResultBySubmissionId(env.BOUNTIES_DB, record.submission_id);
      const decisionCapture = buildArenaDecisionCaptureView(
        record,
        latestArenaRun,
        latestArenaWinnerContender,
        latestArenaThreadForWinner,
      );
      const arenaReviewFlow = await buildBountyReviewArenaFlowView(bounty, record, latestArenaSummary, decisionCapture);
      views.push(toSubmissionSummaryView(record, latest, arenaReviewFlow));
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      return errorResponse('DB_READ_FAILED', message, 500, undefined, version);
    }
  }

  return jsonResponse(
    {
      bounty_id: bounty.bounty_id,
      submissions: views,
      filters: {
        status: status ?? null,
        worker_did: workerDidFilter ?? null,
        limit,
      },
    },
    200,
    version
  );
}

async function handleGetSubmissionDetail(
  submissionId: string,
  request: Request,
  env: Env,
  version: string
): Promise<Response> {
  const viewer = await resolveSubmissionViewerContext(request, env, version);
  if (!viewer.ok) return viewer.error;

  let submission: SubmissionRecord | null;
  try {
    submission = await getSubmissionById(env.BOUNTIES_DB, submissionId);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('DB_READ_FAILED', message, 500, undefined, version);
  }

  if (!submission) {
    return errorResponse('NOT_FOUND', 'Submission not found', 404, { submission_id: submissionId }, version);
  }

  let bounty: BountyV2 | null;
  try {
    bounty = await getBountyById(env.BOUNTIES_DB, submission.bounty_id);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('DB_READ_FAILED', message, 500, undefined, version);
  }

  if (!bounty) {
    return errorResponse('DATA_INTEGRITY_ERROR', 'Bounty for submission not found', 500, { submission_id: submissionId }, version);
  }

  if (viewer.context.kind === 'worker' && submission.worker_did !== viewer.context.worker.worker_did) {
    return errorResponse('FORBIDDEN', 'Workers may only view their own submissions', 403, undefined, version);
  }

  if (viewer.context.kind === 'requester') {
    if (bounty.requester_did !== viewer.context.requester_did) {
      return errorResponse('FORBIDDEN', 'Requester is not allowed to view this submission', 403, undefined, version);
    }

    try {
      await insertRequesterAuthEvent(env.BOUNTIES_DB, {
        action: 'read_submission',
        bounty_id: bounty.bounty_id,
        submission_id: submission.submission_id,
        auth: viewer.context.auth,
        created_at: new Date().toISOString(),
        sensitive_transition: false,
        control_plane_check: null,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      return errorResponse('DB_WRITE_FAILED', message, 500, undefined, version);
    }
  }

  let latestTest: TestResultRecord | null = null;
  try {
    latestTest = await getLatestTestResultBySubmissionId(env.BOUNTIES_DB, submission.submission_id);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('DB_READ_FAILED', message, 500, undefined, version);
  }

  const arenaExplorerBaseUrl = resolveArenaExplorerBaseUrl(env);
  let latestArenaPayload: Record<string, unknown> | null = null;
  let latestArenaSummary: ArenaInlineReviewSummaryView | null = null;
  let latestArenaRun: ArenaRunRecord | null = null;
  let latestArenaWinnerContender: ArenaContenderResult | null = null;
  let latestArenaThreadForWinner: ArenaReviewThreadEntry | null = null;

  try {
    latestArenaRun = await getLatestArenaRunByBountyId(env.BOUNTIES_DB, submission.bounty_id);
    if (latestArenaRun) {
      latestArenaPayload = await buildArenaPayloadFromRun(env.BOUNTIES_DB, latestArenaRun);

      const contenderRows = await listArenaContendersByRunId(env.BOUNTIES_DB, latestArenaRun.run_id);
      if (latestArenaRun.winner_contender_id) {
        const winnerRow = contenderRows.find((row) => row.contender_id === latestArenaRun?.winner_contender_id) ?? null;
        latestArenaWinnerContender = winnerRow ? parseArenaContenderResult(winnerRow) : null;
      }

      const winnerContenderId = latestArenaRun.winner_contender_id ?? latestArenaWinnerContender?.contender_id ?? null;
      if (winnerContenderId) {
        const threadEntries = await listArenaReviewThreadByArenaId(env.BOUNTIES_DB, latestArenaRun.arena_id, 50);
        latestArenaThreadForWinner = threadEntries.find((entry) => entry.contender_id === winnerContenderId) ?? null;
      }

      latestArenaSummary = buildArenaInlineReviewSummaryView(
        latestArenaRun,
        latestArenaWinnerContender,
        arenaExplorerBaseUrl,
      );
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('DB_READ_FAILED', message, 500, undefined, version);
  }

  let arenaReviewFlow: BountyReviewArenaFlowView;
  try {
    const decisionCapture = buildArenaDecisionCaptureView(
      submission,
      latestArenaRun,
      latestArenaWinnerContender,
      latestArenaThreadForWinner,
    );
    arenaReviewFlow = await buildBountyReviewArenaFlowView(bounty, submission, latestArenaSummary, decisionCapture);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('INTERNAL_ERROR', message, 500, undefined, version);
  }

  const view = toSubmissionDetailView(submission, latestTest, arenaReviewFlow);
  if (latestArenaPayload) {
    view.arena = latestArenaPayload;
  }

  return jsonResponse({ submission: view }, 200, version);
}

async function handleGetSubmissionTrustPulse(
  submissionId: string,
  request: Request,
  env: Env,
  version: string
): Promise<Response> {
  const admin = isAdminAuthorized(request, env);

  let worker: WorkerRecordV1 | null = null;
  if (!admin) {
    const auth = await requireWorker(request, env, version, {
      action: 'read_trust_pulse',
    });
    if ('error' in auth) return auth.error;
    worker = auth.worker;
  }

  const submission = await getSubmissionById(env.BOUNTIES_DB, submissionId);
  if (!submission) {
    return errorResponse('NOT_FOUND', 'Submission not found', 404, { submission_id: submissionId }, version);
  }

  if (worker && submission.worker_did !== worker.worker_did) {
    return errorResponse('FORBIDDEN', 'Not allowed to access this submission', 403, undefined, version);
  }

  const tpRow = await getSubmissionTrustPulseBySubmissionId(env.BOUNTIES_DB, submissionId);
  if (!tpRow) {
    return errorResponse(
      'TRUST_PULSE_NOT_FOUND',
      'Trust Pulse not found for submission',
      404,
      { submission_id: submissionId },
      version
    );
  }

  let trust_pulse: unknown;
  try {
    trust_pulse = JSON.parse(tpRow.trust_pulse_json);
  } catch {
    return errorResponse('TRUST_PULSE_CORRUPT', 'Stored Trust Pulse JSON could not be parsed', 500, undefined, version);
  }

  const headers = new Headers();
  headers.set('content-type', 'application/json; charset=utf-8');
  headers.set('cache-control', 'no-store');
  headers.set('X-Bounties-Version', version);

  return new Response(
    JSON.stringify(
      {
        submission_id: tpRow.submission_id,
        run_id: tpRow.run_id,
        agent_did: tpRow.agent_did,
        hash_b64u: tpRow.hash_b64u,
        status: tpRow.status,
        created_at: tpRow.created_at,
        trust_pulse,
      },
      null,
      2
    ),
    { status: 200, headers }
  );
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method.toUpperCase();

    const version = env.BOUNTIES_VERSION?.trim().length ? env.BOUNTIES_VERSION.trim() : '0.1.0';

    // Public endpoints
    if (method === 'GET' || method === 'HEAD') {
      const origin = url.origin;

      if (path === '/') return htmlResponse(landingPage(origin, env), 200, version);
      if (path === '/docs') return htmlResponse(docsPage(origin), 200, version);
      if (path === '/duel') {
        return htmlResponse(
          bountyUiDuelPage({
            origin,
            environment: env.ENVIRONMENT ?? 'unknown',
            version,
            defaultWorkerDid: ARENA_CONFORMANCE_AGENT_DID,
          }),
          200,
          version,
        );
      }
      if (path === '/trust-pulse') return htmlResponse(trustPulseViewerPage(origin), 200, version);
      if (path === '/skill.md') return textResponse(skillMarkdown(origin), 'text/markdown; charset=utf-8', 200, version);
      if (path === '/health') {
        return jsonResponse(
          {
            status: 'ok',
            service: 'clawbounties',
            version,
            environment: env.ENVIRONMENT ?? 'unknown',
          },
          200,
          version
        );
      }
      if (path === '/robots.txt') return textResponse(robotsTxt(origin), 'text/plain; charset=utf-8', 200, version);
      if (path === '/sitemap.xml') return textResponse(sitemapXml(origin), 'application/xml; charset=utf-8', 200, version);
      if (path === '/.well-known/security.txt') return textResponse(securityTxt(origin), 'text/plain; charset=utf-8', 200, version);
    }

    // API
    if (path.startsWith('/v1/')) {
      if (path === '/v1/risk/loss-events' && method === 'POST') {
        return handleRiskLossEvent(request, env, version);
      }

      if (path === '/v1/risk/loss-events/clear' && method === 'POST') {
        return handleRiskLossEventClear(request, env, version);
      }

      // Worker API (public)
      if (path === '/v1/workers/register' && method === 'POST') {
        return handleRegisterWorker(request, env, version);
      }

      if (path === '/v1/workers' && method === 'GET') {
        return handleListWorkers(url, env, version);
      }

      if (path === '/v1/workers/self' && method === 'GET') {
        return handleGetWorkerSelf(request, env, version);
      }

      if (path === '/v1/arena/fleet/workers/register' && method === 'POST') {
        return handlePostArenaFleetWorkerRegister(request, env, version);
      }

      if (path === '/v1/arena/fleet/workers/heartbeat' && method === 'POST') {
        return handlePostArenaFleetWorkerHeartbeat(request, env, version);
      }

      if (path === '/v1/arena/fleet/workers' && method === 'GET') {
        return handleListArenaFleetWorkers(request, url, env, version);
      }

      if (path === '/v1/arena/fleet/match' && method === 'POST') {
        return handlePostArenaFleetMatch(request, env, version);
      }

      if (path === '/v1/arena/manager/route' && method === 'POST') {
        return handleArenaManagerRoute(request, env, version, 'route');
      }

      if (path === '/v1/arena/manager/autopilot' && method === 'POST') {
        return handleArenaManagerAutopilot(request, env, version);
      }

      if (path === '/v1/arena/manager/coach' && method === 'POST') {
        return handleArenaManagerRoute(request, env, version, 'coach');
      }

      if (path === '/v1/arena/mission' && method === 'GET') {
        return handleGetArenaMission(url, env, version);
      }

      if (path === '/v1/arena/desk/discover-loop' && method === 'POST') {
        return handlePostArenaDeskDiscoverLoop(request, env, version);
      }

      if (path === '/v1/arena/desk/claims' && method === 'GET') {
        return handleGetArenaDeskClaimLocks(request, env, version);
      }

      if (path === '/v1/arena/desk/kpi-gate' && method === 'POST') {
        return handlePostArenaDeskKpiGate(request, env, version);
      }

      if (path === '/v1/arena/desk/self-tune-rollout' && method === 'POST') {
        return handlePostArenaDeskSelfTuneRollout(request, env, version);
      }

      if (path === '/v1/arena/desk/claim-loop' && method === 'POST') {
        return handlePostArenaDeskClaimLoop(request, env, version);
      }

      if (path === '/v1/arena/desk/submit-loop' && method === 'POST') {
        return handlePostArenaDeskSubmissionLoop(request, env, version);
      }

      if (path === '/v1/arena/desk/decision-loop' && method === 'POST') {
        return handlePostArenaDeskDecisionLoop(request, env, version);
      }

      if (path === '/v1/arena/desk/resolve-loop' && method === 'POST') {
        return handlePostArenaDeskResolveLoop(request, env, version);
      }

      if (path === '/v1/arena/calibration' && method === 'GET') {
        return handleListArenaCalibration(url, env, version);
      }

      if (path === '/v1/arena/policy-learning' && method === 'GET') {
        return handleArenaPolicyLearning(request, url, env, version);
      }

      if (path === '/v1/arena/roi-dashboard' && method === 'GET') {
        return handleGetArenaRoiDashboard(request, url, env, version);
      }

      if (path === '/v1/arena/policy-optimizer' && method === 'GET') {
        return handleGetArenaPolicyOptimizer(request, url, env, version);
      }

      if (path === '/v1/arena/policy-optimizer' && method === 'POST') {
        return handlePostArenaPolicyOptimizer(request, env, version);
      }

      if (path === '/v1/arena/contract-copilot' && method === 'GET') {
        return handleGetArenaContractCopilot(request, url, env, version);
      }

      if (path === '/v1/arena/contract-copilot/generate' && method === 'POST') {
        return handlePostArenaContractCopilot(request, env, version);
      }

      if (path === '/v1/arena/contract-language-optimizer' && method === 'GET') {
        return handleGetArenaContractLanguageOptimizer(request, url, env, version);
      }

      if (path === '/v1/arena/contract-language-optimizer' && method === 'POST') {
        return handlePostArenaContractLanguageOptimizer(request, env, version);
      }

      if (path === '/v1/arena/backtesting' && method === 'GET') {
        return handleArenaBacktesting(request, url, env, version);
      }

      if (path === '/v1/arena' && method === 'GET') {
        return handleListArena(url, env, version);
      }

      const arenaDelegationInsightsMatch = path.match(/^\/v1\/arena\/([^/]+)\/delegation-insights$/);
      if (arenaDelegationInsightsMatch && method === 'GET') {
        const arenaId = decodeURIComponent(arenaDelegationInsightsMatch[1] ?? '');
        if (!arenaId) {
          return errorResponse('NOT_FOUND', 'Not found', 404, { path, method }, version);
        }
        return handleGetArenaDelegationInsights(arenaId, env, version);
      }

      const arenaReviewThreadMatch = path.match(/^\/v1\/arena\/([^/]+)\/review-thread$/);
      if (arenaReviewThreadMatch && method === 'GET') {
        const arenaId = decodeURIComponent(arenaReviewThreadMatch[1] ?? '');
        if (!arenaId) {
          return errorResponse('NOT_FOUND', 'Not found', 404, { path, method }, version);
        }
        return handleGetArenaReviewThread(arenaId, url, env, version);
      }

      const arenaOutcomesMatch = path.match(/^\/v1\/arena\/([^/]+)\/outcomes$/);
      if (arenaOutcomesMatch && method === 'GET') {
        const arenaId = decodeURIComponent(arenaOutcomesMatch[1] ?? '');
        if (!arenaId) {
          return errorResponse('NOT_FOUND', 'Not found', 404, { path, method }, version);
        }
        return handleGetArenaOutcomeFeed(arenaId, url, env, version);
      }

      const arenaMatch = path.match(/^\/v1\/arena\/([^/]+)$/);
      if (arenaMatch && method === 'GET') {
        const arenaId = decodeURIComponent(arenaMatch[1] ?? '');
        if (!arenaId) {
          return errorResponse('NOT_FOUND', 'Not found', 404, { path, method }, version);
        }
        return handleGetArena(arenaId, env, version);
      }

      const bountyArenaStartMatch = path.match(/^\/v1\/bounties\/(bty_[a-f0-9-]+)\/arena\/start$/);
      if (bountyArenaStartMatch && method === 'POST') {
        const bountyId = bountyArenaStartMatch[1];
        if (!bountyId) {
          return errorResponse('NOT_FOUND', 'Not found', 404, { path, method }, version);
        }
        return handleStartBountyArena(bountyId, request, env, version);
      }

      const bountyArenaResultMatch = path.match(/^\/v1\/bounties\/(bty_[a-f0-9-]+)\/arena\/result$/);
      if (bountyArenaResultMatch && method === 'POST') {
        const bountyId = bountyArenaResultMatch[1];
        if (!bountyId) {
          return errorResponse('NOT_FOUND', 'Not found', 404, { path, method }, version);
        }
        return handleSubmitBountyArenaResult(bountyId, request, env, version);
      }

      const bountyArenaGetMatch = path.match(/^\/v1\/bounties\/(bty_[a-f0-9-]+)\/arena$/);
      if (bountyArenaGetMatch && method === 'GET') {
        const bountyId = bountyArenaGetMatch[1];
        if (!bountyId) {
          return errorResponse('NOT_FOUND', 'Not found', 404, { path, method }, version);
        }
        return handleGetBountyArena(bountyId, env, version);
      }

      const bountyArenaReviewThreadMatch = path.match(/^\/v1\/bounties\/(bty_[a-f0-9-]+)\/arena\/review-thread$/);
      if (bountyArenaReviewThreadMatch && method === 'POST') {
        const bountyId = bountyArenaReviewThreadMatch[1];
        if (!bountyId) {
          return errorResponse('NOT_FOUND', 'Not found', 404, { path, method }, version);
        }
        return handlePostArenaReviewThread(bountyId, request, env, version);
      }

      if (bountyArenaReviewThreadMatch && method === 'GET') {
        const bountyId = bountyArenaReviewThreadMatch[1];
        if (!bountyId) {
          return errorResponse('NOT_FOUND', 'Not found', 404, { path, method }, version);
        }
        return handleListArenaReviewThread(bountyId, request, url, env, version);
      }

      const bountyArenaOutcomeMatch = path.match(/^\/v1\/bounties\/(bty_[a-f0-9-]+)\/arena\/outcome$/);
      if (bountyArenaOutcomeMatch && method === 'POST') {
        const bountyId = bountyArenaOutcomeMatch[1];
        if (!bountyId) {
          return errorResponse('NOT_FOUND', 'Not found', 404, { path, method }, version);
        }
        return handlePostArenaOutcome(bountyId, request, env, version);
      }

      const acceptMatch = path.match(/^\/v1\/bounties\/(bty_[a-f0-9-]+)\/accept$/);
      if (acceptMatch && method === 'POST') {
        const bountyId = acceptMatch[1];
        if (!bountyId) {
          return errorResponse('NOT_FOUND', 'Not found', 404, { path, method }, version);
        }
        return handleAcceptBounty(bountyId, request, env, version);
      }

      const cstMatch = path.match(/^\/v1\/bounties\/(bty_[a-f0-9-]+)\/cst$/);
      if (cstMatch && method === 'POST') {
        const bountyId = cstMatch[1];
        if (!bountyId) {
          return errorResponse('NOT_FOUND', 'Not found', 404, { path, method }, version);
        }
        return handleIssueBountyCst(bountyId, request, env, version);
      }

      const submitMatch = path.match(/^\/v1\/bounties\/(bty_[a-f0-9-]+)\/submit$/);
      if (submitMatch && method === 'POST') {
        const bountyId = submitMatch[1];
        if (!bountyId) {
          return errorResponse('NOT_FOUND', 'Not found', 404, { path, method }, version);
        }
        return handleSubmitBounty(bountyId, request, env, version);
      }

      if (path === '/v1/bounties' && method === 'POST') {
        return handlePostBounty(request, env, version);
      }

      const approveMatch = path.match(/^\/v1\/bounties\/(bty_[a-f0-9-]+)\/approve$/);
      if (approveMatch && method === 'POST') {
        const bountyId = approveMatch[1];
        if (!bountyId) {
          return errorResponse('NOT_FOUND', 'Not found', 404, { path, method }, version);
        }
        return handleApproveBounty(bountyId, request, env, version);
      }

      const rejectMatch = path.match(/^\/v1\/bounties\/(bty_[a-f0-9-]+)\/reject$/);
      if (rejectMatch && method === 'POST') {
        const bountyId = rejectMatch[1];
        if (!bountyId) {
          return errorResponse('NOT_FOUND', 'Not found', 404, { path, method }, version);
        }
        return handleRejectBounty(bountyId, request, env, version);
      }

      const bountySubmissionsMatch = path.match(/^\/v1\/bounties\/(bty_[a-f0-9-]+)\/submissions$/);
      if (bountySubmissionsMatch && method === 'GET') {
        const bountyId = bountySubmissionsMatch[1];
        if (!bountyId) {
          return errorResponse('NOT_FOUND', 'Not found', 404, { path, method }, version);
        }
        return handleListBountySubmissions(bountyId, request, url, env, version);
      }

      if (path === '/v1/bounties' && method === 'GET') {
        if (isAdminAuthorized(request, env)) {
          return handleListBounties(url, env, version);
        }
        return handleListBountiesForWorker(request, url, env, version);
      }

      const submissionTrustPulseMatch = path.match(/^\/v1\/submissions\/(sub_[a-f0-9-]+)\/trust-pulse$/);
      if (submissionTrustPulseMatch && method === 'GET') {
        const submissionId = submissionTrustPulseMatch[1];
        if (!submissionId) {
          return errorResponse('NOT_FOUND', 'Not found', 404, { path, method }, version);
        }
        return handleGetSubmissionTrustPulse(submissionId, request, env, version);
      }

      const submissionMatch = path.match(/^\/v1\/submissions\/(sub_[a-f0-9-]+)$/);
      if (submissionMatch && method === 'GET') {
        const submissionId = submissionMatch[1];
        if (!submissionId) {
          return errorResponse('NOT_FOUND', 'Not found', 404, { path, method }, version);
        }
        return handleGetSubmissionDetail(submissionId, request, env, version);
      }

      // Bounties API (admin)
      const adminError = requireAdmin(request, env, version);
      if (adminError) return adminError;

      const bountyMatch = path.match(/^\/v1\/bounties\/(bty_[a-f0-9-]+)$/);
      if (bountyMatch && method === 'GET') {
        const bountyId = bountyMatch[1];
        if (!bountyId) {
          return errorResponse('NOT_FOUND', 'Not found', 404, { path, method }, version);
        }
        return handleGetBounty(bountyId, env, version);
      }

      return errorResponse('NOT_FOUND', 'Not found', 404, { path, method }, version);
    }

    return errorResponse('NOT_FOUND', 'Not found', 404, { path, method }, version);
  },
};
