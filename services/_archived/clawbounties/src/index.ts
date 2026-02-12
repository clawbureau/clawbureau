/**
 * clawbounties.com worker
 *
 * - Public discovery endpoints (landing/docs/skill/health/robots/sitemap/security)
 * - Scoped requester-token + worker-token marketplace API (schema v2 aligned)
 */

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

function toSubmissionSummaryView(
  record: SubmissionRecord,
  latestTest: TestResultRecord | null
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
  };
}

function toSubmissionDetailView(
  record: SubmissionRecord,
  latestTest: TestResultRecord | null
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

async function handleSubmitBounty(bountyId: string, request: Request, env: Env, version: string): Promise<Response> {
  const auth = await requireWorker(request, env, version, {
    action: 'submit_bounty',
  });
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

async function handleApproveBounty(bountyId: string, request: Request, env: Env, version: string): Promise<Response> {
  const bodyRaw = await parseJsonBody(request);
  if (!isRecord(bodyRaw)) {
    return errorResponse('INVALID_REQUEST', 'Invalid JSON body', 400, undefined, version);
  }

  const requester_did_raw = bodyRaw.requester_did;
  const submission_id_raw = bodyRaw.submission_id;
  const idempotency_key_raw = bodyRaw.idempotency_key;

  if (!isNonEmptyString(requester_did_raw) || !requester_did_raw.trim().startsWith('did:')) {
    return errorResponse('INVALID_REQUEST', 'requester_did must be a DID string', 400, undefined, version);
  }

  const requester_did = requester_did_raw.trim();
  const requesterAuthResult = await requireRequesterAuth(request, env, version, {
    action: 'approve_bounty',
    requester_did_hint: requester_did,
  });
  if ('error' in requesterAuthResult) return requesterAuthResult.error;

  const requesterAuth = requesterAuthResult.auth;

  const transitionAuthCheck = await validateRequesterSensitiveTransition(env, version, {
    auth: requesterAuth,
    transition: 'approve_bounty',
  });
  if ('error' in transitionAuthCheck) return transitionAuthCheck.error;

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
      control_plane_check: transitionAuthCheck.evidence,
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

async function handleRejectBounty(bountyId: string, request: Request, env: Env, version: string): Promise<Response> {
  const bodyRaw = await parseJsonBody(request);
  if (!isRecord(bodyRaw)) {
    return errorResponse('INVALID_REQUEST', 'Invalid JSON body', 400, undefined, version);
  }

  const requester_did_raw = bodyRaw.requester_did;
  const submission_id_raw = bodyRaw.submission_id;
  const idempotency_key_raw = bodyRaw.idempotency_key;
  const reason_raw = bodyRaw.reason;

  if (!isNonEmptyString(requester_did_raw) || !requester_did_raw.trim().startsWith('did:')) {
    return errorResponse('INVALID_REQUEST', 'requester_did must be a DID string', 400, undefined, version);
  }

  const requester_did = requester_did_raw.trim();
  const requesterAuthResult = await requireRequesterAuth(request, env, version, {
    action: 'reject_bounty',
    requester_did_hint: requester_did,
  });
  if ('error' in requesterAuthResult) return requesterAuthResult.error;

  const requesterAuth = requesterAuthResult.auth;

  const transitionAuthCheck = await validateRequesterSensitiveTransition(env, version, {
    auth: requesterAuth,
    transition: 'reject_bounty',
  });
  if ('error' in transitionAuthCheck) return transitionAuthCheck.error;

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
      control_plane_check: transitionAuthCheck.evidence,
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

async function handlePostBounty(request: Request, env: Env, version: string): Promise<Response> {
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
  const requesterAuthResult = await requireRequesterAuth(request, env, version, {
    action: 'post_bounty',
    requester_did_hint,
  });
  if ('error' in requesterAuthResult) return requesterAuthResult.error;

  const requesterAuth = requesterAuthResult.auth;

  const transitionAuthCheck = await validateRequesterSensitiveTransition(env, version, {
    auth: requesterAuth,
    transition: 'post_bounty',
  });
  if ('error' in transitionAuthCheck) return transitionAuthCheck.error;

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
        control_plane_check: transitionAuthCheck.evidence,
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
      control_plane_check: transitionAuthCheck.evidence,
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

async function handleGetBounty(bountyId: string, env: Env, version: string): Promise<Response> {
  const bounty = await getBountyById(env.BOUNTIES_DB, bountyId);
  if (!bounty) {
    return errorResponse('NOT_FOUND', 'Bounty not found', 404, undefined, version);
  }

  return jsonResponse(bounty, 200, version);
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

  const views: SubmissionSummaryView[] = [];
  for (const record of submissions) {
    try {
      const latest = await getLatestTestResultBySubmissionId(env.BOUNTIES_DB, record.submission_id);
      views.push(toSubmissionSummaryView(record, latest));
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

  return jsonResponse({ submission: toSubmissionDetailView(submission, latestTest) }, 200, version);
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
