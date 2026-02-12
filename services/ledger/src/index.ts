/**
 * ClawLedger - Event-sourced ledger for balances, holds, and transfers
 * Cloudflare Worker entry point
 */

import { AccountRepository, AccountService, isValidDid } from './accounts';
import { ReserveAttestationService } from './attestation';
import { ReserveAssetService } from './reserve-assets';
import { ComputeReserveService } from './compute-reserves';
import { ClearingAccountRepository, ClearingService } from './clearing';
import { EventRepository, EventService, computeEventHash, isValidEventType, isValidBucket } from './events';
import { HoldService } from './holds';
import { ReconciliationService } from './reconciliation';
import { PaymentSettlementError, PaymentSettlementService } from './payment-settlements';
import { StakeFeeService } from './stake-fee';
import { TransferService, WebhookService } from './transfer';
import type {
  BucketName,
  ClearingDepositRequest,
  ClearingWithdrawRequest,
  CreateAccountRequest,
  CreateClearingAccountRequest,
  CreateEventRequest,
  CreateHoldRequest,
  Env,
  ErrorResponse,
  FeeBurnRequest,
  FeeTransferRequest,
  PromoBurnRequest,
  PromoMintRequest,
  PaymentSettlementDirection,
  PaymentSettlementIngestRequest,
  PaymentSettlementListQuery,
  ReleaseHoldRequest,
  ReserveAssetUpsertRequest,
  ComputeReservesUpsertRequest,
  SettlementRequest,
  StakeLockRequest,
  StakeSlashRequest,
  TransferRequest,
} from './types';

/**
 * JSON response helper
 */
function jsonResponse<T>(data: T, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'X-Ledger-Version': '1.0.0',
    },
  });
}

function escapeHtml(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function escapeXml(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function textResponse(body: string, contentType: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: {
      'Content-Type': contentType,
      'X-Ledger-Version': '1.0.0',
    },
  });
}

function htmlResponse(html: string, status = 200): Response {
  return textResponse(html, 'text/html; charset=utf-8', status);
}

/**
 * Error response helper
 */
function errorResponse(
  error: string,
  code: string,
  status: number,
  details?: Record<string, unknown>
): Response {
  const body: ErrorResponse = { error, code, details };
  return jsonResponse(body, status);
}

/**
 * Parse JSON body safely
 */
async function parseJsonBody<T>(request: Request): Promise<T | null> {
  try {
    return (await request.json()) as T;
  } catch {
    return null;
  }
}

function getIdempotencyKey(request: Request): string | null {
  const raw =
    request.headers.get('Idempotency-Key') ??
    request.headers.get('idempotency-key') ??
    request.headers.get('x-idempotency-key') ??
    request.headers.get('X-Idempotency-Key');

  if (!raw) {
    return null;
  }

  const trimmed = raw.trim();
  return trimmed.length > 0 ? trimmed : null;
}

/**
 * Handle POST /accounts - Create or get account
 */
async function handleCreateAccount(
  request: Request,
  env: Env
): Promise<Response> {
  const body = await parseJsonBody<CreateAccountRequest>(request);

  if (!body || !body.did) {
    return errorResponse(
      'Missing required field: did',
      'INVALID_REQUEST',
      400
    );
  }

  if (!isValidDid(body.did)) {
    return errorResponse(
      'Invalid DID format. Expected: did:method:identifier',
      'INVALID_DID',
      400
    );
  }

  const service = new AccountService(env);

  try {
    const account = await service.createAccount(body);
    return jsonResponse(account, 201);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse(message, 'CREATE_FAILED', 500);
  }
}

/**
 * Handle GET /accounts/:did - Get account by DID
 */
async function handleGetAccount(
  did: string,
  env: Env
): Promise<Response> {
  if (!isValidDid(did)) {
    return errorResponse(
      'Invalid DID format. Expected: did:method:identifier',
      'INVALID_DID',
      400
    );
  }

  const service = new AccountService(env);
  const account = await service.getAccount(did);

  if (!account) {
    return errorResponse('Account not found', 'NOT_FOUND', 404);
  }

  return jsonResponse(account);
}

/**
 * Handle GET /accounts/id/:id - Get account by account ID
 */
async function handleGetAccountById(
  id: string,
  env: Env
): Promise<Response> {
  const service = new AccountService(env);
  const account = await service.getAccountById(id);

  if (!account) {
    return errorResponse('Account not found', 'NOT_FOUND', 404);
  }

  return jsonResponse(account);
}

/**
 * Handle POST /events - Create a new ledger event
 */
async function handleCreateEvent(
  request: Request,
  env: Env
): Promise<Response> {
  const body = await parseJsonBody<CreateEventRequest>(request);

  if (!body) {
    return errorResponse('Invalid JSON body', 'INVALID_REQUEST', 400);
  }

  // Validate required fields
  if (!body.idempotencyKey) {
    return errorResponse(
      'Missing required field: idempotencyKey',
      'INVALID_REQUEST',
      400
    );
  }

  if (!body.eventType) {
    return errorResponse(
      'Missing required field: eventType',
      'INVALID_REQUEST',
      400
    );
  }

  if (!isValidEventType(body.eventType)) {
    return errorResponse(
      `Invalid eventType: ${body.eventType}. Must be a supported ledger event type`,
      'INVALID_EVENT_TYPE',
      400
    );
  }

  if (!body.accountId) {
    return errorResponse(
      'Missing required field: accountId',
      'INVALID_REQUEST',
      400
    );
  }

  if (!body.amount) {
    return errorResponse(
      'Missing required field: amount',
      'INVALID_REQUEST',
      400
    );
  }

  // Validate bucket if provided
  if (body.bucket && !isValidBucket(body.bucket)) {
    return errorResponse(
      `Invalid bucket: ${body.bucket}. Must be one of: available, held, bonded, feePool, promo`,
      'INVALID_BUCKET',
      400
    );
  }

  // Transfer requires toAccountId
  if (body.eventType === 'transfer' && !body.toAccountId) {
    return errorResponse(
      'Transfer events require toAccountId',
      'INVALID_REQUEST',
      400
    );
  }

  const service = new EventService(env);

  try {
    const event = await service.createEvent(body);
    return jsonResponse(event, 201);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse(message, 'CREATE_FAILED', 500);
  }
}

/**
 * Handle GET /events/:id - Get event by ID
 */
async function handleGetEvent(id: string, env: Env): Promise<Response> {
  const service = new EventService(env);
  const event = await service.getEvent(id);

  if (!event) {
    return errorResponse('Event not found', 'NOT_FOUND', 404);
  }

  return jsonResponse(event);
}

/**
 * Handle GET /events/idempotency/:key - Get event by idempotency key
 */
async function handleGetEventByIdempotencyKey(
  key: string,
  env: Env
): Promise<Response> {
  const service = new EventService(env);
  const event = await service.getEventByIdempotencyKey(key);

  if (!event) {
    return errorResponse('Event not found', 'NOT_FOUND', 404);
  }

  return jsonResponse(event);
}

/**
 * Handle GET /accounts/:accountId/events - Get events for an account
 */
async function handleGetAccountEvents(
  accountId: string,
  env: Env,
  url: URL
): Promise<Response> {
  const limitParam = url.searchParams.get('limit');
  const limit = limitParam ? Math.min(parseInt(limitParam, 10), 1000) : 100;

  const service = new EventService(env);
  const events = await service.getAccountEvents(accountId, limit);

  return jsonResponse({ events });
}

/**
 * Handle GET /events/verify - Verify hash chain integrity
 */
async function handleVerifyHashChain(env: Env): Promise<Response> {
  const service = new EventService(env);
  const result = await service.verifyHashChain();

  return jsonResponse(result);
}

/**
 * Handle POST /holds - Create a new hold
 */
async function handleCreateHold(
  request: Request,
  env: Env
): Promise<Response> {
  const body = await parseJsonBody<CreateHoldRequest>(request);

  if (!body) {
    return errorResponse('Invalid JSON body', 'INVALID_REQUEST', 400);
  }

  // Validate required fields
  if (!body.idempotencyKey) {
    return errorResponse(
      'Missing required field: idempotencyKey',
      'INVALID_REQUEST',
      400
    );
  }

  if (!body.accountId) {
    return errorResponse(
      'Missing required field: accountId',
      'INVALID_REQUEST',
      400
    );
  }

  if (!body.amount) {
    return errorResponse(
      'Missing required field: amount',
      'INVALID_REQUEST',
      400
    );
  }

  const service = new HoldService(env);

  try {
    const hold = await service.createHold(body);
    return jsonResponse(hold, 201);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    // Check for insufficient funds error
    if (message.includes('Insufficient funds')) {
      return errorResponse(message, 'INSUFFICIENT_FUNDS', 400);
    }
    return errorResponse(message, 'CREATE_FAILED', 500);
  }
}

/**
 * Handle GET /holds/:id - Get hold by ID
 */
async function handleGetHold(id: string, env: Env): Promise<Response> {
  const service = new HoldService(env);
  const hold = await service.getHold(id);

  if (!hold) {
    return errorResponse('Hold not found', 'NOT_FOUND', 404);
  }

  return jsonResponse(hold);
}

/**
 * Handle POST /holds/:id/release - Release a hold
 */
async function handleReleaseHold(
  holdId: string,
  request: Request,
  env: Env
): Promise<Response> {
  const body = await parseJsonBody<ReleaseHoldRequest>(request);

  if (!body) {
    return errorResponse('Invalid JSON body', 'INVALID_REQUEST', 400);
  }

  // Validate required fields
  if (!body.idempotencyKey) {
    return errorResponse(
      'Missing required field: idempotencyKey',
      'INVALID_REQUEST',
      400
    );
  }

  if (!body.releaseType) {
    return errorResponse(
      'Missing required field: releaseType',
      'INVALID_REQUEST',
      400
    );
  }

  if (body.releaseType !== 'complete' && body.releaseType !== 'cancel') {
    return errorResponse(
      `Invalid releaseType: ${body.releaseType}. Must be 'complete' or 'cancel'`,
      'INVALID_REQUEST',
      400
    );
  }

  if (body.releaseType === 'complete' && !body.toAccountId) {
    return errorResponse(
      'Complete release requires toAccountId',
      'INVALID_REQUEST',
      400
    );
  }

  const service = new HoldService(env);

  try {
    const result = await service.releaseHold(holdId, body);
    return jsonResponse(result);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    if (message.includes('not found')) {
      return errorResponse(message, 'NOT_FOUND', 404);
    }
    if (message.includes('already')) {
      return errorResponse(message, 'ALREADY_RELEASED', 400);
    }
    return errorResponse(message, 'RELEASE_FAILED', 500);
  }
}

/**
 * Handle GET /accounts/:accountId/holds - Get active holds for an account
 */
async function handleGetAccountHolds(
  accountId: string,
  env: Env
): Promise<Response> {
  const service = new HoldService(env);
  const holds = await service.getActiveHolds(accountId);

  return jsonResponse({ holds });
}

/**
 * Handle POST /reconciliation/run - Trigger a reconciliation job
 */
async function handleRunReconciliation(env: Env): Promise<Response> {
  const service = new ReconciliationService(env);

  try {
    const report = await service.runReconciliation();
    return jsonResponse(report, report.status === 'success' ? 200 : 200);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse(message, 'RECONCILIATION_FAILED', 500);
  }
}

/**
 * Handle GET /reconciliation/reports - Get recent reconciliation reports
 */
async function handleGetReconciliationReports(
  env: Env,
  url: URL
): Promise<Response> {
  const limitParam = url.searchParams.get('limit');
  const limit = limitParam ? Math.min(parseInt(limitParam, 10), 100) : 10;

  const service = new ReconciliationService(env);
  const reports = await service.getRecentReports(limit);

  return jsonResponse({ reports });
}

/**
 * Handle GET /reconciliation/reports/latest - Get the most recent report
 */
async function handleGetLatestReport(env: Env): Promise<Response> {
  const service = new ReconciliationService(env);
  const report = await service.getLatestReport();

  if (!report) {
    return errorResponse('No reconciliation reports found', 'NOT_FOUND', 404);
  }

  return jsonResponse(report);
}

/**
 * Handle GET /reconciliation/reports/:id - Get a specific report
 */
async function handleGetReconciliationReport(
  id: string,
  env: Env
): Promise<Response> {
  const service = new ReconciliationService(env);
  const report = await service.getReport(id);

  if (!report) {
    return errorResponse('Report not found', 'NOT_FOUND', 404);
  }

  return jsonResponse(report);
}

/**
 * Handle GET /reconciliation/export/:id - Export a report in a downloadable format
 */
async function handleExportReport(id: string, env: Env): Promise<Response> {
  const service = new ReconciliationService(env);
  const report = await service.getReport(id);

  if (!report) {
    return errorResponse('Report not found', 'NOT_FOUND', 404);
  }

  // Format as a detailed export
  const exportData = {
    report,
    exportedAt: new Date().toISOString(),
    format: 'json',
    version: '1.0.0',
  };

  return new Response(JSON.stringify(exportData, null, 2), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Content-Disposition': `attachment; filename="reconciliation-${id}.json"`,
      'X-Ledger-Version': '1.0.0',
    },
  });
}

/**
 * Handle GET /attestation/reserve - Generate reserve attestation
 * Public endpoint for auditors to verify reserve coverage
 */
async function handleReserveAttestation(env: Env): Promise<Response> {
  const service = new ReserveAttestationService(env);

  try {
    const response = await service.generateAttestation();
    return jsonResponse(response);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse(message, 'ATTESTATION_FAILED', 500);
  }
}

/**
 * Handle POST /reserve/compute - Upsert compute reserve assets (Gemini/FAL)
 * CLD-US-011
 */
async function handleUpsertComputeReserves(
  request: Request,
  env: Env
): Promise<Response> {
  const body = await parseJsonBody<ComputeReservesUpsertRequest>(request);

  if (!body) {
    return errorResponse('Invalid JSON body', 'INVALID_REQUEST', 400);
  }

  if (!body.gemini_amount) {
    return errorResponse('Missing required field: gemini_amount', 'INVALID_REQUEST', 400);
  }

  if (!body.fal_amount) {
    return errorResponse('Missing required field: fal_amount', 'INVALID_REQUEST', 400);
  }

  const service = new ComputeReserveService(env);

  try {
    const response = await service.upsertComputeReserves(body);
    return jsonResponse(response, 200);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse(message, 'COMPUTE_RESERVES_UPSERT_FAILED', 400);
  }
}

/**
 * Handle POST /reserve/assets - Upsert a reserve asset (operator endpoint)
 */
async function handleUpsertReserveAsset(
  request: Request,
  env: Env
): Promise<Response> {
  const body = await parseJsonBody<ReserveAssetUpsertRequest>(request);

  if (!body) {
    return errorResponse('Invalid JSON body', 'INVALID_REQUEST', 400);
  }

  if (!body.provider) {
    return errorResponse('Missing required field: provider', 'INVALID_REQUEST', 400);
  }

  if (!body.asset_type) {
    return errorResponse('Missing required field: asset_type', 'INVALID_REQUEST', 400);
  }

  if (!body.currency) {
    return errorResponse('Missing required field: currency', 'INVALID_REQUEST', 400);
  }

  if (!body.amount) {
    return errorResponse('Missing required field: amount', 'INVALID_REQUEST', 400);
  }

  const service = new ReserveAssetService(env);

  try {
    const response = await service.upsertAsset(body);
    return jsonResponse(response, 200);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse(message, 'RESERVE_ASSET_UPSERT_FAILED', 400);
  }
}

/**
 * Handle GET /reserve/assets - List reserve assets
 */
async function handleListReserveAssets(env: Env): Promise<Response> {
  const service = new ReserveAssetService(env);

  try {
    const response = await service.listAssets();
    return jsonResponse(response, 200);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse(message, 'RESERVE_ASSET_LIST_FAILED', 500);
  }
}

/**
 * Handle GET /balances - List account balances
 * Supports optional filtering by account IDs and pagination
 */
async function handleListBalances(env: Env, url: URL): Promise<Response> {
  const accountIdsParam = url.searchParams.get('accountIds');
  const limitParam = url.searchParams.get('limit');
  const offsetParam = url.searchParams.get('offset');

  const accountIds = accountIdsParam
    ? accountIdsParam.split(',').map((id) => id.trim()).filter(Boolean)
    : undefined;
  const limit = limitParam ? Math.min(parseInt(limitParam, 10), 1000) : 100;
  const offset = offsetParam ? Math.max(parseInt(offsetParam, 10), 0) : 0;

  const service = new AccountService(env);

  try {
    const result = await service.listBalances(accountIds, limit, offset);
    return jsonResponse(result);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse(message, 'LIST_BALANCES_FAILED', 500);
  }
}

type V1Bucket = 'A' | 'H' | 'B' | 'F' | 'P';

type V1TransferStatus = 'applied';

type DelegationSpendOperation = 'reserve' | 'consume' | 'release';

const DELEGATION_ID_RE = /^dlg_[a-f0-9-]+$/;
const SHA256_HEX_RE = /^[a-f0-9]{64}$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

function isV1Bucket(value: unknown): value is V1Bucket {
  return value === 'A' || value === 'H' || value === 'B' || value === 'F' || value === 'P';
}

function v1BucketToBucketName(bucket: V1Bucket): BucketName {
  switch (bucket) {
    case 'A':
      return 'available';
    case 'H':
      return 'held';
    case 'B':
      return 'bonded';
    case 'F':
      return 'feePool';
    case 'P':
      return 'promo';
  }
}

function bucketNameToV1Bucket(bucket: BucketName): V1Bucket {
  switch (bucket) {
    case 'available':
      return 'A';
    case 'held':
      return 'H';
    case 'bonded':
      return 'B';
    case 'feePool':
      return 'F';
    case 'promo':
      return 'P';
  }
}

function parsePositiveBigInt(value: unknown): bigint | null {
  if (typeof value !== 'string') return null;
  const s = value.trim();
  if (!/^[0-9]+$/.test(s)) return null;
  try {
    const n = BigInt(s);
    if (n <= 0n) return null;
    return n;
  } catch {
    return null;
  }
}

function isDelegationSpendOperation(value: unknown): value is DelegationSpendOperation {
  return value === 'reserve' || value === 'consume' || value === 'release';
}

interface V1BalancesResponse {
  did: string;
  currency: 'USD';
  buckets: Record<V1Bucket, string>;
  as_of: string;
}

async function handleV1GetBalances(env: Env, url: URL): Promise<Response> {
  const did = url.searchParams.get('did');

  if (!isNonEmptyString(did)) {
    return errorResponse('Missing required query param: did', 'INVALID_REQUEST', 400);
  }

  const didTrimmed = did.trim();
  if (!isValidDid(didTrimmed)) {
    return errorResponse('Invalid DID format. Expected: did:method:identifier', 'INVALID_DID', 400);
  }

  const service = new AccountService(env);

  try {
    // Spec-aligned behavior: create on first use.
    const account = await service.createAccount({ did: didTrimmed });

    const response: V1BalancesResponse = {
      did: account.did,
      currency: 'USD',
      buckets: {
        A: account.balances.available,
        H: account.balances.held,
        B: account.balances.bonded,
        F: account.balances.feePool,
        P: account.balances.promo,
      },
      as_of: new Date().toISOString(),
    };

    return jsonResponse(response);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse(message, 'BALANCES_FAILED', 500);
  }
}

interface V1TransferResponseBody {
  event_id: string;
  status: V1TransferStatus;
}

type V1AccountKind = 'user' | 'clearing';

interface V1ResolvedAccount {
  kind: V1AccountKind;
  id: string;
  display: string;
}

async function ensureClearingMirrorUserAccount(
  env: Env,
  params: { clearingAccountId: string; domain: string }
): Promise<void> {
  const accountRepo = new AccountRepository(env.DB);
  const existing = await accountRepo.findById(params.clearingAccountId);
  if (existing) {
    return;
  }

  const now = new Date().toISOString();
  const mirrorDid = `did:internal:clearing:${params.domain}`;

  try {
    await env.DB
      .prepare(
        `INSERT INTO accounts (
           id,
           did,
           balance_available,
           balance_held,
           balance_bonded,
           balance_fee_pool,
           balance_promo,
           created_at,
           updated_at,
           version
         ) VALUES (?, ?, '0', '0', '0', '0', '0', ?, ?, 1)`
      )
      .bind(params.clearingAccountId, mirrorDid, now, now)
      .run();
  } catch {
    // Best-effort mirror creation for legacy events FK compatibility.
    // If a concurrent writer created the mirror row first, we can safely continue.
  }
}

async function resolveV1AccountRef(account: string, env: Env): Promise<V1ResolvedAccount> {
  const input = account.trim();

  if (input.startsWith('did:')) {
    if (!isValidDid(input)) {
      throw new Error('INVALID_DID');
    }

    const accountService = new AccountService(env);
    const resolved = await accountService.createAccount({ did: input });
    return { kind: 'user', id: resolved.id, display: input };
  }

  if (input.startsWith('clearing:')) {
    const domain = input.slice('clearing:'.length).trim();
    if (!domain) {
      throw new Error('INVALID_CLEARING_DOMAIN');
    }

    const clearingService = new ClearingService(env);
    let clearing = await clearingService.getClearingAccountByDomain(domain);
    if (!clearing) {
      clearing = await clearingService.createClearingAccount({ domain, name: domain });
    }

    await ensureClearingMirrorUserAccount(env, {
      clearingAccountId: clearing.id,
      domain,
    });

    return { kind: 'clearing', id: clearing.id, display: input };
  }

  throw new Error('UNSUPPORTED_ACCOUNT');
}

async function debitV1Account(
  account: V1ResolvedAccount,
  bucket: BucketName,
  amount: bigint,
  repositories: {
    users: AccountRepository;
    clearing: ClearingAccountRepository;
  }
): Promise<void> {
  if (account.kind === 'user') {
    await repositories.users.debitBucket(account.id, bucket, amount);
    return;
  }

  await repositories.clearing.debitBucket(account.id, bucket, amount);
}

async function creditV1Account(
  account: V1ResolvedAccount,
  bucket: BucketName,
  amount: bigint,
  repositories: {
    users: AccountRepository;
    clearing: ClearingAccountRepository;
  }
): Promise<void> {
  if (account.kind === 'user') {
    await repositories.users.creditBucket(account.id, bucket, amount);
    return;
  }

  await repositories.clearing.creditBucket(account.id, bucket, amount);
}

/**
 * Handle GET /v1/balances - Spec-compatible balances endpoint.
 */
async function handleV1Balances(env: Env, url: URL): Promise<Response> {
  return handleV1GetBalances(env, url);
}

/**
 * Handle POST /v1/transfers - Spec-compatible transfer endpoint (supports bucket moves).
 */
async function handleV1Transfers(request: Request, env: Env): Promise<Response> {
  const bodyRaw = await parseJsonBody<unknown>(request);

  if (!isRecord(bodyRaw)) {
    return errorResponse('Invalid JSON body', 'INVALID_REQUEST', 400);
  }

  const idempotency_key = bodyRaw.idempotency_key;
  const currency = bodyRaw.currency;
  const from = bodyRaw.from;
  const to = bodyRaw.to;
  const amount_minor = bodyRaw.amount_minor;
  const metadataRaw = bodyRaw.metadata;

  if (!isNonEmptyString(idempotency_key)) {
    return errorResponse('Missing required field: idempotency_key', 'INVALID_REQUEST', 400);
  }

  if (!isNonEmptyString(currency) || currency.trim().toUpperCase() !== 'USD') {
    return errorResponse('Only USD is supported', 'UNSUPPORTED_CURRENCY', 400);
  }

  if (!isRecord(from)) {
    return errorResponse('Missing required object: from', 'INVALID_REQUEST', 400);
  }

  if (!isRecord(to)) {
    return errorResponse('Missing required object: to', 'INVALID_REQUEST', 400);
  }

  const fromAccount = from.account;
  const fromBucket = from.bucket;
  const toAccount = to.account;
  const toBucket = to.bucket;

  if (!isNonEmptyString(fromAccount)) {
    return errorResponse('Missing required field: from.account', 'INVALID_REQUEST', 400);
  }
  if (!isV1Bucket(fromBucket)) {
    return errorResponse('from.bucket must be one of A|H|B|F|P', 'INVALID_REQUEST', 400);
  }
  if (!isNonEmptyString(toAccount)) {
    return errorResponse('Missing required field: to.account', 'INVALID_REQUEST', 400);
  }
  if (!isV1Bucket(toBucket)) {
    return errorResponse('to.bucket must be one of A|H|B|F|P', 'INVALID_REQUEST', 400);
  }

  const amount = parsePositiveBigInt(amount_minor);
  if (amount === null) {
    return errorResponse('amount_minor must be a positive integer string', 'INVALID_REQUEST', 400);
  }

  let metadata: Record<string, unknown> | undefined;
  if (metadataRaw !== undefined) {
    if (!isRecord(metadataRaw)) {
      return errorResponse('metadata must be an object', 'INVALID_REQUEST', 400);
    }
    metadata = metadataRaw;
  }

  const eventRepo = new EventRepository(env.DB);

  // Idempotency: return existing event if present.
  const existing = await eventRepo.findByIdempotencyKey(idempotency_key.trim());
  if (existing) {
    const response: V1TransferResponseBody = { event_id: existing.id, status: 'applied' };
    return jsonResponse(response);
  }

  let resolvedFrom: V1ResolvedAccount;
  let resolvedTo: V1ResolvedAccount;

  try {
    resolvedFrom = await resolveV1AccountRef(fromAccount, env);
    resolvedTo = await resolveV1AccountRef(toAccount, env);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    if (message === 'INVALID_DID') {
      return errorResponse('Invalid DID account format', 'INVALID_ACCOUNT', 400);
    }
    if (message === 'INVALID_CLEARING_DOMAIN') {
      return errorResponse('Invalid clearing account domain', 'INVALID_ACCOUNT', 400);
    }
    if (message === 'UNSUPPORTED_ACCOUNT') {
      return errorResponse('Unsupported account identifier', 'INVALID_ACCOUNT', 400);
    }
    return errorResponse('Failed to resolve account', 'ACCOUNT_RESOLUTION_FAILED', 500);
  }

  const fromBucketName = v1BucketToBucketName(fromBucket);
  const toBucketName = v1BucketToBucketName(toBucket);

  if (resolvedFrom.id === resolvedTo.id && fromBucketName === toBucketName) {
    return errorResponse('from and to must not be identical', 'INVALID_REQUEST', 400);
  }

  const repositories = {
    users: new AccountRepository(env.DB),
    clearing: new ClearingAccountRepository(env.DB),
  };

  try {
    if (resolvedFrom.id === resolvedTo.id) {
      // Same account, bucket move.
      if (resolvedFrom.kind === 'user') {
        await repositories.users.moveBetweenBuckets(resolvedFrom.id, fromBucketName, toBucketName, amount);
      } else {
        await repositories.clearing.moveBetweenBuckets(resolvedFrom.id, fromBucketName, toBucketName, amount);
      }
    } else {
      // Cross-account transfer (supports any buckets).
      await debitV1Account(resolvedFrom, fromBucketName, amount, repositories);
      await creditV1Account(resolvedTo, toBucketName, amount, repositories);
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    if (message.includes('Insufficient funds')) {
      return errorResponse(message, 'INSUFFICIENT_FUNDS', 400);
    }
    if (message.includes('not found')) {
      return errorResponse(message, 'NOT_FOUND', 404);
    }
    return errorResponse(message, 'TRANSFER_FAILED', 500);
  }

  try {
    const previousHash = await eventRepo.getLastEventHash();
    const now = new Date().toISOString();

    const enrichedMetadata: Record<string, unknown> = {
      ...(metadata ?? {}),
      spec_v1: {
        currency: 'USD',
        from: { account: resolvedFrom.display, bucket: fromBucket },
        to: { account: resolvedTo.display, bucket: toBucket },
        amount_minor: amount.toString(),
      },
      from_bucket: bucketNameToV1Bucket(fromBucketName),
      to_bucket: bucketNameToV1Bucket(toBucketName),
    };

    const eventHash = await computeEventHash(
      previousHash,
      'transfer',
      resolvedFrom.id,
      resolvedTo.id,
      amount,
      fromBucketName,
      idempotency_key.trim(),
      now
    );

    const event = await eventRepo.create(
      idempotency_key.trim(),
      'transfer',
      resolvedFrom.id,
      amount,
      fromBucketName,
      previousHash,
      eventHash,
      resolvedTo.id,
      enrichedMetadata
    );

    const response: V1TransferResponseBody = { event_id: event.id, status: 'applied' };
    return jsonResponse(response);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse(message, 'EVENT_WRITE_FAILED', 500);
  }
}

/**
 * Handle POST /v1/delegations/spend/:operation
 *
 * Deterministic hook endpoint for delegation spend reserve/consume/release operations.
 * This endpoint is idempotent by idempotency_key.
 */
async function handleDelegationSpendHook(
  operation: DelegationSpendOperation,
  request: Request,
  env: Env
): Promise<Response> {
  const bodyRaw = await parseJsonBody<unknown>(request);
  if (!isRecord(bodyRaw)) {
    return errorResponse('Invalid JSON body', 'INVALID_REQUEST', 400);
  }

  const idempotencyKey = isNonEmptyString(bodyRaw.idempotency_key)
    ? bodyRaw.idempotency_key.trim()
    : null;
  if (!idempotencyKey) {
    return errorResponse('idempotency_key is required', 'INVALID_REQUEST', 400);
  }

  const delegationId = isNonEmptyString(bodyRaw.delegation_id)
    ? bodyRaw.delegation_id.trim()
    : null;
  if (!delegationId || !DELEGATION_ID_RE.test(delegationId)) {
    return errorResponse('delegation_id is invalid', 'INVALID_REQUEST', 400);
  }

  const delegatorDid = isNonEmptyString(bodyRaw.delegator_did)
    ? bodyRaw.delegator_did.trim()
    : null;
  if (!delegatorDid || !isValidDid(delegatorDid)) {
    return errorResponse('delegator_did must be a DID', 'INVALID_REQUEST', 400);
  }

  const actorDid = isNonEmptyString(bodyRaw.actor_did) ? bodyRaw.actor_did.trim() : null;
  if (!actorDid || !isValidDid(actorDid)) {
    return errorResponse('actor_did must be a DID', 'INVALID_REQUEST', 400);
  }

  const amountMinor = parsePositiveBigInt(bodyRaw.amount_minor);
  if (amountMinor === null) {
    return errorResponse('amount_minor must be a positive integer string', 'INVALID_REQUEST', 400);
  }

  const tokenHash = isNonEmptyString(bodyRaw.token_hash) ? bodyRaw.token_hash.trim().toLowerCase() : null;
  if (tokenHash && !SHA256_HEX_RE.test(tokenHash)) {
    return errorResponse('token_hash must be a lowercase hex sha256', 'INVALID_REQUEST', 400);
  }

  const requestFingerprint = JSON.stringify({
    operation,
    delegation_id: delegationId,
    idempotency_key: idempotencyKey,
    delegator_did: delegatorDid,
    actor_did: actorDid,
    amount_minor: amountMinor.toString(),
    token_hash: tokenHash,
  });

  const existing = await env.DB
    .prepare(
      `SELECT event_id, operation, delegation_id, request_fingerprint, response_json
       FROM delegation_spend_hooks
       WHERE idempotency_key = ?
       LIMIT 1`
    )
    .bind(idempotencyKey)
    .first<Record<string, unknown>>();

  if (existing) {
    const existingOperation = isNonEmptyString(existing.operation) ? existing.operation.trim() : null;
    const existingDelegationId = isNonEmptyString(existing.delegation_id) ? existing.delegation_id.trim() : null;
    const existingFingerprint = isNonEmptyString(existing.request_fingerprint)
      ? existing.request_fingerprint
      : null;

    if (
      existingOperation !== operation ||
      existingDelegationId !== delegationId ||
      existingFingerprint !== requestFingerprint
    ) {
      return errorResponse(
        'idempotency_key is already used with a different delegation spend payload',
        'IDEMPOTENCY_KEY_REUSED',
        409
      );
    }

    try {
      const parsed = isNonEmptyString(existing.response_json)
        ? JSON.parse(existing.response_json)
        : null;
      if (!parsed || typeof parsed !== 'object') {
        return errorResponse('Stored idempotency payload is invalid', 'INTERNAL_ERROR', 500);
      }
      return jsonResponse(parsed, 200);
    } catch {
      return errorResponse('Stored idempotency payload is invalid', 'INTERNAL_ERROR', 500);
    }
  }

  const createdAt = new Date().toISOString();
  const eventId = `ldg_dsp_${crypto.randomUUID()}`;

  const responseBody = {
    schema_version: '1',
    event_id: eventId,
    status: 'applied' as const,
    operation,
    delegation_id: delegationId,
    idempotency_key: idempotencyKey,
    delegator_did: delegatorDid,
    actor_did: actorDid,
    amount_minor: amountMinor.toString(),
    token_hash: tokenHash,
    created_at: createdAt,
  };

  await env.DB
    .prepare(
      `INSERT OR IGNORE INTO delegation_spend_hooks (
         event_id,
         idempotency_key,
         delegation_id,
         operation,
         delegator_did,
         actor_did,
         amount_minor,
         token_hash,
         request_fingerprint,
         response_json,
         created_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      eventId,
      idempotencyKey,
      delegationId,
      operation,
      delegatorDid,
      actorDid,
      amountMinor.toString(),
      tokenHash,
      requestFingerprint,
      JSON.stringify(responseBody),
      createdAt
    )
    .run();

  const stored = await env.DB
    .prepare(
      `SELECT event_id, operation, delegation_id, request_fingerprint, response_json
       FROM delegation_spend_hooks
       WHERE idempotency_key = ?
       LIMIT 1`
    )
    .bind(idempotencyKey)
    .first<Record<string, unknown>>();

  if (!stored || !isNonEmptyString(stored.response_json)) {
    return errorResponse('Failed to persist delegation spend hook result', 'INTERNAL_ERROR', 500);
  }

  const storedOperation = isNonEmptyString(stored.operation) ? stored.operation.trim() : null;
  const storedDelegationId = isNonEmptyString(stored.delegation_id) ? stored.delegation_id.trim() : null;
  const storedFingerprint = isNonEmptyString(stored.request_fingerprint)
    ? stored.request_fingerprint
    : null;

  if (
    storedOperation !== operation ||
    storedDelegationId !== delegationId ||
    storedFingerprint !== requestFingerprint
  ) {
    return errorResponse(
      'idempotency_key is already used with a different delegation spend payload',
      'IDEMPOTENCY_KEY_REUSED',
      409
    );
  }

  try {
    const parsed = JSON.parse(stored.response_json);
    const replay = isNonEmptyString(stored.event_id) && stored.event_id !== eventId;
    return jsonResponse(parsed, replay ? 200 : 201);
  } catch {
    return errorResponse('Stored idempotency payload is invalid', 'INTERNAL_ERROR', 500);
  }
}

/**
 * Handle POST /transfers - Execute a transfer between accounts
 */
async function handleTransfer(
  request: Request,
  env: Env,
  ctx: ExecutionContext
): Promise<Response> {
  const body = await parseJsonBody<TransferRequest>(request);

  if (!body) {
    return errorResponse('Invalid JSON body', 'INVALID_REQUEST', 400);
  }

  // Validate required fields
  if (!body.idempotencyKey) {
    return errorResponse(
      'Missing required field: idempotencyKey',
      'INVALID_REQUEST',
      400
    );
  }

  if (!body.fromAccountId) {
    return errorResponse(
      'Missing required field: fromAccountId',
      'INVALID_REQUEST',
      400
    );
  }

  if (!body.toAccountId) {
    return errorResponse(
      'Missing required field: toAccountId',
      'INVALID_REQUEST',
      400
    );
  }

  if (!body.amount) {
    return errorResponse(
      'Missing required field: amount',
      'INVALID_REQUEST',
      400
    );
  }

  const service = new TransferService(env);

  try {
    const result = await service.transfer(body);

    // Send webhook notification in the background
    const webhookService = new WebhookService(env);
    if (webhookService.isConfigured()) {
      ctx.waitUntil(
        webhookService.sendEventWebhook({
          id: result.eventId,
          idempotencyKey: result.idempotencyKey,
          eventType: 'transfer',
          accountId: result.fromAccountId,
          toAccountId: result.toAccountId,
          amount: result.amount,
          bucket: 'available',
          previousHash: '',
          eventHash: result.eventHash,
          metadata: body.metadata,
          createdAt: result.createdAt,
        })
      );
    }

    return jsonResponse(result, 201);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    // Check for insufficient funds error
    if (message.includes('Insufficient funds')) {
      return errorResponse(message, 'INSUFFICIENT_FUNDS', 400);
    }
    // Check for not found errors
    if (message.includes('not found')) {
      return errorResponse(message, 'NOT_FOUND', 404);
    }
    // Check for same account error
    if (message.includes('same account')) {
      return errorResponse(message, 'INVALID_REQUEST', 400);
    }
    return errorResponse(message, 'TRANSFER_FAILED', 500);
  }
}

/**
 * Handle GET /webhooks/status - Get webhook configuration status
 */
function handleWebhookStatus(env: Env): Response {
  const webhookService = new WebhookService(env);
  return jsonResponse({
    configured: webhookService.isConfigured(),
    types: ['ledger.event.created'],
  });
}

/**
 * Handle POST /stake/lock - Lock funds in bonded bucket
 */
async function handleStakeLock(
  request: Request,
  env: Env
): Promise<Response> {
  const body = await parseJsonBody<StakeLockRequest>(request);

  if (!body) {
    return errorResponse('Invalid JSON body', 'INVALID_REQUEST', 400);
  }

  // Validate required fields
  if (!body.idempotencyKey) {
    return errorResponse(
      'Missing required field: idempotencyKey',
      'INVALID_REQUEST',
      400
    );
  }

  if (!body.accountId) {
    return errorResponse(
      'Missing required field: accountId',
      'INVALID_REQUEST',
      400
    );
  }

  if (!body.amount) {
    return errorResponse(
      'Missing required field: amount',
      'INVALID_REQUEST',
      400
    );
  }

  const service = new StakeFeeService(env);

  try {
    const result = await service.stakeLock(body);
    return jsonResponse(result, 201);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    if (message.includes('Insufficient funds')) {
      return errorResponse(message, 'INSUFFICIENT_FUNDS', 400);
    }
    if (message.includes('not found')) {
      return errorResponse(message, 'NOT_FOUND', 404);
    }
    return errorResponse(message, 'STAKE_LOCK_FAILED', 500);
  }
}

/**
 * Handle POST /stake/slash - Slash bonded funds
 */
async function handleStakeSlash(
  request: Request,
  env: Env
): Promise<Response> {
  const body = await parseJsonBody<StakeSlashRequest>(request);

  if (!body) {
    return errorResponse('Invalid JSON body', 'INVALID_REQUEST', 400);
  }

  // Validate required fields
  if (!body.idempotencyKey) {
    return errorResponse(
      'Missing required field: idempotencyKey',
      'INVALID_REQUEST',
      400
    );
  }

  if (!body.accountId) {
    return errorResponse(
      'Missing required field: accountId',
      'INVALID_REQUEST',
      400
    );
  }

  if (!body.amount) {
    return errorResponse(
      'Missing required field: amount',
      'INVALID_REQUEST',
      400
    );
  }

  const service = new StakeFeeService(env);

  try {
    const result = await service.stakeSlash(body);
    return jsonResponse(result, 201);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    if (message.includes('Insufficient funds')) {
      return errorResponse(message, 'INSUFFICIENT_FUNDS', 400);
    }
    if (message.includes('not found')) {
      return errorResponse(message, 'NOT_FOUND', 404);
    }
    return errorResponse(message, 'STAKE_SLASH_FAILED', 500);
  }
}

/**
 * Handle POST /fees/burn - Burn funds from fee pool
 */
async function handleFeeBurn(
  request: Request,
  env: Env
): Promise<Response> {
  const body = await parseJsonBody<FeeBurnRequest>(request);

  if (!body) {
    return errorResponse('Invalid JSON body', 'INVALID_REQUEST', 400);
  }

  // Validate required fields
  if (!body.idempotencyKey) {
    return errorResponse(
      'Missing required field: idempotencyKey',
      'INVALID_REQUEST',
      400
    );
  }

  if (!body.accountId) {
    return errorResponse(
      'Missing required field: accountId',
      'INVALID_REQUEST',
      400
    );
  }

  if (!body.amount) {
    return errorResponse(
      'Missing required field: amount',
      'INVALID_REQUEST',
      400
    );
  }

  const service = new StakeFeeService(env);

  try {
    const result = await service.feeBurn(body);
    return jsonResponse(result, 201);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    if (message.includes('Insufficient funds')) {
      return errorResponse(message, 'INSUFFICIENT_FUNDS', 400);
    }
    if (message.includes('not found')) {
      return errorResponse(message, 'NOT_FOUND', 404);
    }
    return errorResponse(message, 'FEE_BURN_FAILED', 500);
  }
}

/**
 * Handle POST /fees/transfer - Transfer funds to fee pool
 */
async function handleFeeTransfer(
  request: Request,
  env: Env
): Promise<Response> {
  const body = await parseJsonBody<FeeTransferRequest>(request);

  if (!body) {
    return errorResponse('Invalid JSON body', 'INVALID_REQUEST', 400);
  }

  // Validate required fields
  if (!body.idempotencyKey) {
    return errorResponse(
      'Missing required field: idempotencyKey',
      'INVALID_REQUEST',
      400
    );
  }

  if (!body.accountId) {
    return errorResponse(
      'Missing required field: accountId',
      'INVALID_REQUEST',
      400
    );
  }

  if (!body.amount) {
    return errorResponse(
      'Missing required field: amount',
      'INVALID_REQUEST',
      400
    );
  }

  // Validate bucket if provided
  if (body.fromBucket && !isValidBucket(body.fromBucket)) {
    return errorResponse(
      `Invalid fromBucket: ${body.fromBucket}. Must be one of: available, held, bonded, feePool, promo`,
      'INVALID_BUCKET',
      400
    );
  }

  const service = new StakeFeeService(env);

  try {
    const result = await service.feeTransfer(body);
    return jsonResponse(result, 201);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    if (message.includes('Insufficient funds')) {
      return errorResponse(message, 'INSUFFICIENT_FUNDS', 400);
    }
    if (message.includes('not found')) {
      return errorResponse(message, 'NOT_FOUND', 404);
    }
    return errorResponse(message, 'FEE_TRANSFER_FAILED', 500);
  }
}

/**
 * Handle POST /promo/mint - Mint promotional credits
 */
async function handlePromoMint(
  request: Request,
  env: Env
): Promise<Response> {
  const body = await parseJsonBody<PromoMintRequest>(request);

  if (!body) {
    return errorResponse('Invalid JSON body', 'INVALID_REQUEST', 400);
  }

  // Validate required fields
  if (!body.idempotencyKey) {
    return errorResponse(
      'Missing required field: idempotencyKey',
      'INVALID_REQUEST',
      400
    );
  }

  if (!body.accountId) {
    return errorResponse(
      'Missing required field: accountId',
      'INVALID_REQUEST',
      400
    );
  }

  if (!body.amount) {
    return errorResponse(
      'Missing required field: amount',
      'INVALID_REQUEST',
      400
    );
  }

  const service = new StakeFeeService(env);

  try {
    const result = await service.promoMint(body);
    return jsonResponse(result, 201);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    if (message.includes('not found')) {
      return errorResponse(message, 'NOT_FOUND', 404);
    }
    return errorResponse(message, 'PROMO_MINT_FAILED', 500);
  }
}

/**
 * Handle POST /promo/burn - Burn promotional credits
 */
async function handlePromoBurn(
  request: Request,
  env: Env
): Promise<Response> {
  const body = await parseJsonBody<PromoBurnRequest>(request);

  if (!body) {
    return errorResponse('Invalid JSON body', 'INVALID_REQUEST', 400);
  }

  // Validate required fields
  if (!body.idempotencyKey) {
    return errorResponse(
      'Missing required field: idempotencyKey',
      'INVALID_REQUEST',
      400
    );
  }

  if (!body.accountId) {
    return errorResponse(
      'Missing required field: accountId',
      'INVALID_REQUEST',
      400
    );
  }

  if (!body.amount) {
    return errorResponse(
      'Missing required field: amount',
      'INVALID_REQUEST',
      400
    );
  }

  const service = new StakeFeeService(env);

  try {
    const result = await service.promoBurn(body);
    return jsonResponse(result, 201);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    if (message.includes('Insufficient funds')) {
      return errorResponse(message, 'INSUFFICIENT_FUNDS', 400);
    }
    if (message.includes('not found')) {
      return errorResponse(message, 'NOT_FOUND', 404);
    }
    return errorResponse(message, 'PROMO_BURN_FAILED', 500);
  }
}

/**
 * Handle POST /clearing/accounts - Create a clearing account
 */
async function handleCreateClearingAccount(
  request: Request,
  env: Env
): Promise<Response> {
  const body = await parseJsonBody<CreateClearingAccountRequest>(request);

  if (!body) {
    return errorResponse('Invalid JSON body', 'INVALID_REQUEST', 400);
  }

  if (!body.domain) {
    return errorResponse(
      'Missing required field: domain',
      'INVALID_REQUEST',
      400
    );
  }

  if (!body.name) {
    return errorResponse(
      'Missing required field: name',
      'INVALID_REQUEST',
      400
    );
  }

  const service = new ClearingService(env);

  try {
    const result = await service.createClearingAccount(body);
    return jsonResponse(result, 201);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse(message, 'CREATE_CLEARING_ACCOUNT_FAILED', 500);
  }
}

/**
 * Handle GET /clearing/accounts - List all clearing accounts
 */
async function handleListClearingAccounts(env: Env): Promise<Response> {
  const service = new ClearingService(env);

  try {
    const accounts = await service.listClearingAccounts();
    return jsonResponse({ accounts });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse(message, 'LIST_CLEARING_ACCOUNTS_FAILED', 500);
  }
}

/**
 * Handle GET /clearing/accounts/:id - Get clearing account by ID
 */
async function handleGetClearingAccountById(
  id: string,
  env: Env
): Promise<Response> {
  const service = new ClearingService(env);
  const account = await service.getClearingAccountById(id);

  if (!account) {
    return errorResponse('Clearing account not found', 'NOT_FOUND', 404);
  }

  return jsonResponse(account);
}

/**
 * Handle GET /clearing/accounts/domain/:domain - Get clearing account by domain
 */
async function handleGetClearingAccountByDomain(
  domain: string,
  env: Env
): Promise<Response> {
  const service = new ClearingService(env);
  const account = await service.getClearingAccountByDomain(domain);

  if (!account) {
    return errorResponse('Clearing account not found for domain', 'NOT_FOUND', 404);
  }

  return jsonResponse(account);
}

/**
 * Handle POST /clearing/deposit - Deposit funds to clearing account
 */
async function handleClearingDeposit(
  request: Request,
  env: Env
): Promise<Response> {
  const body = await parseJsonBody<ClearingDepositRequest>(request);

  if (!body) {
    return errorResponse('Invalid JSON body', 'INVALID_REQUEST', 400);
  }

  if (!body.idempotencyKey) {
    return errorResponse(
      'Missing required field: idempotencyKey',
      'INVALID_REQUEST',
      400
    );
  }

  if (!body.fromAccountId) {
    return errorResponse(
      'Missing required field: fromAccountId',
      'INVALID_REQUEST',
      400
    );
  }

  if (!body.amount) {
    return errorResponse(
      'Missing required field: amount',
      'INVALID_REQUEST',
      400
    );
  }

  if (!body.batchId) {
    return errorResponse(
      'Missing required field: batchId',
      'INVALID_REQUEST',
      400
    );
  }

  if (!body.clearingAccountId && !body.domain) {
    return errorResponse(
      'Either clearingAccountId or domain is required',
      'INVALID_REQUEST',
      400
    );
  }

  const service = new ClearingService(env);

  try {
    const result = await service.deposit(body);
    return jsonResponse(result, 201);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    if (message.includes('Insufficient funds')) {
      return errorResponse(message, 'INSUFFICIENT_FUNDS', 400);
    }
    if (message.includes('not found')) {
      return errorResponse(message, 'NOT_FOUND', 404);
    }
    return errorResponse(message, 'CLEARING_DEPOSIT_FAILED', 500);
  }
}

/**
 * Handle POST /clearing/withdraw - Withdraw funds from clearing account
 */
async function handleClearingWithdraw(
  request: Request,
  env: Env
): Promise<Response> {
  const body = await parseJsonBody<ClearingWithdrawRequest>(request);

  if (!body) {
    return errorResponse('Invalid JSON body', 'INVALID_REQUEST', 400);
  }

  if (!body.idempotencyKey) {
    return errorResponse(
      'Missing required field: idempotencyKey',
      'INVALID_REQUEST',
      400
    );
  }

  if (!body.toAccountId) {
    return errorResponse(
      'Missing required field: toAccountId',
      'INVALID_REQUEST',
      400
    );
  }

  if (!body.amount) {
    return errorResponse(
      'Missing required field: amount',
      'INVALID_REQUEST',
      400
    );
  }

  if (!body.batchId) {
    return errorResponse(
      'Missing required field: batchId',
      'INVALID_REQUEST',
      400
    );
  }

  if (!body.clearingAccountId && !body.domain) {
    return errorResponse(
      'Either clearingAccountId or domain is required',
      'INVALID_REQUEST',
      400
    );
  }

  const service = new ClearingService(env);

  try {
    const result = await service.withdraw(body);
    return jsonResponse(result, 201);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    if (message.includes('Insufficient funds')) {
      return errorResponse(message, 'INSUFFICIENT_FUNDS', 400);
    }
    if (message.includes('not found')) {
      return errorResponse(message, 'NOT_FOUND', 404);
    }
    return errorResponse(message, 'CLEARING_WITHDRAW_FAILED', 500);
  }
}

/**
 * Handle POST /settlements - Execute a settlement with batch reference
 */
async function handleSettlement(
  request: Request,
  env: Env
): Promise<Response> {
  const body = await parseJsonBody<SettlementRequest>(request);

  if (!body) {
    return errorResponse('Invalid JSON body', 'INVALID_REQUEST', 400);
  }

  if (!body.idempotencyKey) {
    return errorResponse(
      'Missing required field: idempotencyKey',
      'INVALID_REQUEST',
      400
    );
  }

  if (!body.fromAccountId) {
    return errorResponse(
      'Missing required field: fromAccountId',
      'INVALID_REQUEST',
      400
    );
  }

  if (!body.toAccountId) {
    return errorResponse(
      'Missing required field: toAccountId',
      'INVALID_REQUEST',
      400
    );
  }

  if (!body.amount) {
    return errorResponse(
      'Missing required field: amount',
      'INVALID_REQUEST',
      400
    );
  }

  if (!body.batchId) {
    return errorResponse(
      'Missing required field: batchId',
      'INVALID_REQUEST',
      400
    );
  }

  const service = new ClearingService(env);

  try {
    const result = await service.settle(body);
    return jsonResponse(result, 201);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    if (message.includes('Insufficient funds')) {
      return errorResponse(message, 'INSUFFICIENT_FUNDS', 400);
    }
    if (message.includes('not found')) {
      return errorResponse(message, 'NOT_FOUND', 404);
    }
    if (message.includes('same account')) {
      return errorResponse(message, 'INVALID_REQUEST', 400);
    }
    return errorResponse(message, 'SETTLEMENT_FAILED', 500);
  }
}

/**
 * Handle POST /v1/payments/settlements/ingest
 */
async function handleIngestPaymentSettlement(
  request: Request,
  env: Env
): Promise<Response> {
  const idempotencyKey = getIdempotencyKey(request);
  if (!idempotencyKey) {
    return errorResponse(
      'Missing required header: Idempotency-Key',
      'MISSING_IDEMPOTENCY_KEY',
      400
    );
  }

  const body = await parseJsonBody<PaymentSettlementIngestRequest>(request);
  if (!body) {
    return errorResponse('Invalid JSON body', 'INVALID_REQUEST', 400);
  }

  const service = new PaymentSettlementService(env);

  try {
    const response = await service.ingest(body, idempotencyKey);
    const status = response.idempotency.replayed || response.idempotency.deduped ? 200 : 201;
    return jsonResponse(response, status);
  } catch (err) {
    if (err instanceof PaymentSettlementError) {
      return errorResponse(err.message, err.code, err.status, err.details);
    }

    const message = err instanceof Error ? err.message : 'Unknown error';
    if (message.includes('Insufficient funds')) {
      return errorResponse(message, 'INSUFFICIENT_FUNDS', 422);
    }
    return errorResponse(message, 'PAYMENT_SETTLEMENT_INGEST_FAILED', 500);
  }
}

function parseDirectionQuery(
  value: string | null
): PaymentSettlementDirection | undefined {
  if (!value) {
    return undefined;
  }

  const trimmed = value.trim();
  if (trimmed === 'payin' || trimmed === 'refund' || trimmed === 'payout') {
    return trimmed;
  }

  return undefined;
}

/**
 * Handle GET /v1/payments/settlements/:provider/:external_payment_id
 */
async function handleGetPaymentSettlementByExternal(
  provider: string,
  externalPaymentId: string,
  env: Env,
  url: URL
): Promise<Response> {
  const service = new PaymentSettlementService(env);

  const rawDirection = url.searchParams.get('direction');
  const direction = parseDirectionQuery(rawDirection);

  if (rawDirection && !direction) {
    return errorResponse(
      'direction must be one of: payin|refund|payout',
      'INVALID_REQUEST',
      400
    );
  }

  try {
    const settlements = await service.getByProviderExternal(
      decodeURIComponent(provider),
      decodeURIComponent(externalPaymentId),
      direction
    );

    if (settlements.length === 0) {
      return errorResponse('Settlement not found', 'NOT_FOUND', 404);
    }

    return jsonResponse({ settlements });
  } catch (err) {
    if (err instanceof PaymentSettlementError) {
      return errorResponse(err.message, err.code, err.status, err.details);
    }

    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse(message, 'PAYMENT_SETTLEMENT_LOOKUP_FAILED', 500);
  }
}

/**
 * Handle GET /v1/payments/settlements
 */
async function handleListPaymentSettlements(
  env: Env,
  url: URL
): Promise<Response> {
  const service = new PaymentSettlementService(env);

  const rawDirection = url.searchParams.get('direction');
  const direction = parseDirectionQuery(rawDirection);
  if (rawDirection && !direction) {
    return errorResponse(
      'direction must be one of: payin|refund|payout',
      'INVALID_REQUEST',
      400
    );
  }

  const query: PaymentSettlementListQuery = {
    account_id: url.searchParams.get('account_id') ?? undefined,
    status: (url.searchParams.get('status') as PaymentSettlementListQuery['status']) ?? undefined,
    provider: url.searchParams.get('provider') ?? undefined,
    direction,
    limit: url.searchParams.get('limit')
      ? Number.parseInt(url.searchParams.get('limit') as string, 10)
      : undefined,
    cursor: url.searchParams.get('cursor') ?? undefined,
  };

  try {
    const response = await service.list(query);
    return jsonResponse(response);
  } catch (err) {
    if (err instanceof PaymentSettlementError) {
      return errorResponse(err.message, err.code, err.status, err.details);
    }

    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse(message, 'PAYMENT_SETTLEMENT_LIST_FAILED', 500);
  }
}

export function isSettlementVerificationReadRequest(method: string, path: string): boolean {
  if (method !== 'GET') return false;

  if (path === '/v1/payments/settlements') return true;

  if (/^\/v1\/payments\/settlements\/[^/]+\/[^/]+$/.test(path)) {
    return true;
  }

  if (/^\/accounts\/id\/[^/]+$/.test(path)) {
    return true;
  }

  return false;
}

export function parseAuthCandidates(request: Request): string[] {
  const authHeader =
    request.headers.get('authorization') ??
    request.headers.get('Authorization');
  const bearerMatch = authHeader ? authHeader.match(/^Bearer\s+(.+)$/i) : null;
  const bearer = bearerMatch?.[1]?.trim() ?? null;

  const xAdminKeyRaw =
    request.headers.get('x-admin-key') ?? request.headers.get('X-Admin-Key');
  const xAdminKey = xAdminKeyRaw?.trim() || null;

  return [bearer, xAdminKey].filter((value): value is string => Boolean(value));
}

function resolveLedgerAdminKeys(env: Env): { ok: true; keys: Set<string> } | { ok: false; code: string; message: string } {
  const keys = new Set<string>();

  if (env.LEDGER_ADMIN_KEY?.trim()) {
    keys.add(env.LEDGER_ADMIN_KEY.trim());
  }

  const additionalRaw = env.LEDGER_ADMIN_KEYS_JSON?.trim();
  if (additionalRaw) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(additionalRaw);
    } catch {
      return {
        ok: false,
        code: 'LEDGER_ADMIN_KEY_CONFIG_INVALID',
        message: 'LEDGER_ADMIN_KEYS_JSON must be valid JSON',
      };
    }

    if (!Array.isArray(parsed)) {
      return {
        ok: false,
        code: 'LEDGER_ADMIN_KEY_CONFIG_INVALID',
        message: 'LEDGER_ADMIN_KEYS_JSON must be a JSON array',
      };
    }

    for (const raw of parsed) {
      if (typeof raw !== 'string' || raw.trim().length === 0) {
        return {
          ok: false,
          code: 'LEDGER_ADMIN_KEY_CONFIG_INVALID',
          message: 'LEDGER_ADMIN_KEYS_JSON entries must be non-empty strings',
        };
      }
      keys.add(raw.trim());
    }
  }

  return { ok: true, keys };
}

export function evaluateLedgerAuth(params: {
  request: Request;
  env: Env;
  method: string;
  path: string;
}):
  | { ok: true }
  | { ok: false; status: number; code: string; message: string } {
  const resolvedAdminKeys = resolveLedgerAdminKeys(params.env);
  if (!resolvedAdminKeys.ok) {
    return {
      ok: false,
      status: 503,
      code: resolvedAdminKeys.code,
      message: resolvedAdminKeys.message,
    };
  }

  const settlementVerifyToken =
    params.env.LEDGER_SETTLEMENT_VERIFY_TOKEN?.trim() || null;
  const allowSettlementVerifyToken = isSettlementVerificationReadRequest(
    params.method,
    params.path
  );

  if (resolvedAdminKeys.keys.size === 0 && !(allowSettlementVerifyToken && settlementVerifyToken)) {
    return {
      ok: false,
      status: 503,
      code: 'LEDGER_ADMIN_KEY_MISSING',
      message: 'Ledger admin key not configured',
    };
  }

  const authCandidates = parseAuthCandidates(params.request);

  const adminAuthorized = authCandidates.some((candidate) => resolvedAdminKeys.keys.has(candidate));

  const verifyAuthorized =
    Boolean(settlementVerifyToken) &&
    allowSettlementVerifyToken &&
    authCandidates.some((candidate) => candidate === settlementVerifyToken);

  if (!adminAuthorized && !verifyAuthorized) {
    return {
      ok: false,
      status: 401,
      code: 'UNAUTHORIZED',
      message: 'Unauthorized',
    };
  }

  return { ok: true };
}

/**
 * Router for handling requests
 */
async function router(
  request: Request,
  env: Env,
  ctx: ExecutionContext
): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  // Fail-closed auth: require LEDGER_ADMIN_KEY for all non-public endpoints.
  const isPublicGet =
    method === 'GET' &&
    (path === '/' ||
      path === '/docs' ||
      path === '/skill.md' ||
      path === '/robots.txt' ||
      path === '/sitemap.xml' ||
      path === '/.well-known/security.txt' ||
      path === '/health' ||
      path === '/attestation/reserve');

  if (!isPublicGet) {
    const auth = evaluateLedgerAuth({
      request,
      env,
      method,
      path,
    });

    if (!auth.ok) {
      return errorResponse(auth.message, auth.code, auth.status);
    }
  }

  // CLD-US-012: Public landing + skill docs
  if (method === 'GET') {
    if (path === '/') {
      return htmlResponse(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>clawledger</title>
  </head>
  <body>
    <main style="max-width: 820px; margin: 2rem auto; font-family: ui-sans-serif, system-ui; line-height: 1.5;">
      <h1>clawledger</h1>
      <p>Event-sourced ledger for balances, holds, and transfers.</p>
      <ul>
        <li><a href="/docs">Docs</a></li>
        <li><a href="/skill.md">OpenClaw skill</a></li>
        <li><a href="/attestation/reserve">Reserve attestation</a></li>
      </ul>
      <p><small>Version: 1.0.0</small></p>
    </main>
  </body>
</html>`);
    }

    if (path === '/docs') {
      const origin = url.origin;
      return htmlResponse(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>clawledger docs</title>
  </head>
  <body>
    <main style="max-width: 820px; margin: 2rem auto; font-family: ui-sans-serif, system-ui; line-height: 1.5;">
      <h1>clawledger docs</h1>
      <p>Minimal HTTP API documentation.</p>

      <h2>Common endpoints</h2>
      <ul>
        <li><code>POST /accounts</code> — Create an account (idempotent by DID).</li>
        <li><code>GET /balances</code> — List balances (internal format).</li>
        <li><code>GET /v1/balances?did=&lt;did&gt;</code> — Spec-compatible balances (buckets A/H/B/F/P).</li>
        <li><code>POST /transfers</code> — Execute transfers between accounts (internal format).</li>
        <li><code>POST /v1/transfers</code> — Spec-compatible transfers (bucket moves, clearing accounts).</li>
        <li><code>POST /v1/payments/settlements/ingest</code> — Ingest provider-agnostic settlement updates (admin + idempotency required).</li>
        <li><code>GET /v1/payments/settlements/:provider/:external_payment_id</code> — Lookup settlement(s) by provider external id.</li>
        <li><code>GET /v1/payments/settlements</code> — List settlements (deterministic cursor pagination).</li>
        <li><code>GET /attestation/reserve</code> — Signed reserve coverage attestation (public).</li>
        <li><code>POST /reserve/compute</code> — Upsert compute reserve assets (Gemini/FAL credits).</li>
      </ul>

      <h2>Quick start</h2>
      <pre>curl -sS -X POST "${escapeHtml(origin)}/accounts" \\
  -H "Content-Type: application/json" \\
  -d '{"did":"did:key:example"}'</pre>

      <p>See also: <a href="/skill.md">/skill.md</a></p>
    </main>
  </body>
</html>`);
    }

    if (path === '/skill.md') {
      const metadata = {
        name: 'clawledger',
        version: '1',
        description:
          'Event-sourced ledger for balances, holds, transfers, and reserve attestations.',
        endpoints: [
          { method: 'POST', path: '/accounts' },
          { method: 'GET', path: '/balances' },
          { method: 'GET', path: '/v1/balances' },
          { method: 'POST', path: '/transfers' },
          { method: 'POST', path: '/v1/transfers' },
          { method: 'POST', path: '/v1/payments/settlements/ingest' },
          { method: 'GET', path: '/v1/payments/settlements/:provider/:external_payment_id' },
          { method: 'GET', path: '/v1/payments/settlements' },
          { method: 'GET', path: '/attestation/reserve' },
          { method: 'POST', path: '/reserve/compute' },
        ],
      };

      const md = `---
metadata: '${JSON.stringify(metadata)}'
---

# clawledger

Event-sourced ledger for balances, holds, and transfers.

## Create an account

\`POST /accounts\`

Example:

\`\`\`bash
curl -sS -X POST "${url.origin}/accounts" \\
  -H "Content-Type: application/json" \\
  -d '{"did":"did:key:z..."}'
\`\`\`

## List balances

\`GET /balances\`

\`\`\`bash
curl -sS "${url.origin}/balances"
\`\`\`

## Spec balances (Agent Economy MVP)

\`GET /v1/balances?did=<did>\`

\`\`\`bash
curl -sS "${url.origin}/v1/balances?did=did:key:z..."
\`\`\`

## Transfers

\`POST /transfers\`

\`\`\`bash
curl -sS -X POST "${url.origin}/transfers" \\
  -H "Content-Type: application/json" \\
  -d '{"idempotencyKey":"idem_123","fromAccountId":"acc_...","toAccountId":"acc_...","amount":"100"}'
\`\`\`

## Spec transfers (Agent Economy MVP)

\`POST /v1/transfers\`

\`\`\`bash
curl -sS -X POST "${url.origin}/v1/transfers" \\
  -H "Content-Type: application/json" \\
  -d '{"idempotency_key":"escrow:esc_123:hold","currency":"USD","from":{"account":"did:key:zBuyer","bucket":"A"},"to":{"account":"did:key:zBuyer","bucket":"H"},"amount_minor":"5000","metadata":{"reason":"escrow_hold"}}'
\`\`\`

## Machine payment settlement ingest

\`POST /v1/payments/settlements/ingest\`

Requires:
- admin auth header (Authorization Bearer / X-Admin-Key)
- \`Idempotency-Key\` header

\`\`\`bash
curl -sS -X POST "${url.origin}/v1/payments/settlements/ingest" \\
  -H "Content-Type: application/json" \\
  -H "Idempotency-Key: payset:example:1" \\
  -d '{"provider":"provider_sim","external_payment_id":"pay_123","direction":"payin","status":"confirmed","account_id":"acc_...","amount_minor":"2500","currency":"USD"}'
\`\`\`

## Settlement lookup + list

\`GET /v1/payments/settlements/:provider/:external_payment_id\`

\`\`\`bash
curl -sS "${url.origin}/v1/payments/settlements/provider_sim/pay_123"
\`\`\`

\`GET /v1/payments/settlements?account_id=...&status=...&provider=...&limit=...\`

\`\`\`bash
curl -sS "${url.origin}/v1/payments/settlements?provider=provider_sim&limit=20"
\`\`\`

## Reserve attestation (public)

\`GET /attestation/reserve\`

\`\`\`bash
curl -sS "${url.origin}/attestation/reserve"
\`\`\`

## Compute reserves

\`POST /reserve/compute\`

\`\`\`bash
curl -sS -X POST "${url.origin}/reserve/compute" \\
  -H "Content-Type: application/json" \\
  -d '{"gemini_amount":"0","fal_amount":"0"}'
\`\`\`
`;

      return textResponse(md, 'text/markdown; charset=utf-8', 200);
    }

    if (path === '/robots.txt') {
      const txt = `User-agent: *
Allow: /
Sitemap: ${url.origin}/sitemap.xml
`;
      return textResponse(txt, 'text/plain; charset=utf-8', 200);
    }

    if (path === '/sitemap.xml') {
      const base = url.origin;
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>${escapeXml(base)}/</loc></url>
  <url><loc>${escapeXml(base)}/docs</loc></url>
  <url><loc>${escapeXml(base)}/skill.md</loc></url>
</urlset>
`;
      return textResponse(xml, 'application/xml; charset=utf-8', 200);
    }

    if (path === '/.well-known/security.txt') {
      const expires = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();
      const txt = `Contact: mailto:security@clawledger.com
Preferred-Languages: en
Expires: ${expires}
Canonical: ${url.origin}/.well-known/security.txt
`;
      return textResponse(txt, 'text/plain; charset=utf-8', 200);
    }
  }

  // Health check
  if (path === '/health' && method === 'GET') {
    return jsonResponse({ status: 'ok', service: 'ledger' });
  }

  // Spec-compatible endpoints
  if (path === '/v1/balances' && method === 'GET') {
    return handleV1Balances(env, url);
  }

  if (path === '/v1/transfers' && method === 'POST') {
    return handleV1Transfers(request, env);
  }

  const delegationSpendMatch = path.match(/^\/v1\/delegations\/spend\/(reserve|consume|release)$/);
  if (delegationSpendMatch && method === 'POST') {
    const operation = delegationSpendMatch[1];
    if (!isDelegationSpendOperation(operation)) {
      return errorResponse('Unsupported delegation spend operation', 'INVALID_REQUEST', 400);
    }
    return handleDelegationSpendHook(operation, request, env);
  }

  // POST /v1/payments/settlements/ingest
  if (path === '/v1/payments/settlements/ingest' && method === 'POST') {
    return handleIngestPaymentSettlement(request, env);
  }

  // GET /v1/payments/settlements/:provider/:external_payment_id
  const paymentSettlementByExternalMatch = path.match(
    /^\/v1\/payments\/settlements\/([^/]+)\/([^/]+)$/
  );
  if (paymentSettlementByExternalMatch && method === 'GET') {
    return handleGetPaymentSettlementByExternal(
      paymentSettlementByExternalMatch[1],
      paymentSettlementByExternalMatch[2],
      env,
      url
    );
  }

  // GET /v1/payments/settlements
  if (path === '/v1/payments/settlements' && method === 'GET') {
    return handleListPaymentSettlements(env, url);
  }

  // GET /balances - List account balances
  if (path === '/balances' && method === 'GET') {
    return handleListBalances(env, url);
  }

  // POST /transfers - Execute transfer
  if (path === '/transfers' && method === 'POST') {
    return handleTransfer(request, env, ctx);
  }

  // GET /webhooks/status - Get webhook status
  if (path === '/webhooks/status' && method === 'GET') {
    return handleWebhookStatus(env);
  }

  // POST /stake/lock - Lock funds in bonded bucket
  if (path === '/stake/lock' && method === 'POST') {
    return handleStakeLock(request, env);
  }

  // POST /stake/slash - Slash bonded funds
  if (path === '/stake/slash' && method === 'POST') {
    return handleStakeSlash(request, env);
  }

  // POST /fees/burn - Burn funds from fee pool
  if (path === '/fees/burn' && method === 'POST') {
    return handleFeeBurn(request, env);
  }

  // POST /fees/transfer - Transfer funds to fee pool
  if (path === '/fees/transfer' && method === 'POST') {
    return handleFeeTransfer(request, env);
  }

  // POST /promo/mint - Mint promotional credits
  if (path === '/promo/mint' && method === 'POST') {
    return handlePromoMint(request, env);
  }

  // POST /promo/burn - Burn promotional credits
  if (path === '/promo/burn' && method === 'POST') {
    return handlePromoBurn(request, env);
  }

  // === Clearing Accounts & Settlements ===

  // POST /clearing/accounts - Create clearing account
  if (path === '/clearing/accounts' && method === 'POST') {
    return handleCreateClearingAccount(request, env);
  }

  // GET /clearing/accounts - List all clearing accounts
  if (path === '/clearing/accounts' && method === 'GET') {
    return handleListClearingAccounts(env);
  }

  // GET /clearing/accounts/domain/:domain - Get clearing account by domain
  const clearingByDomainMatch = path.match(/^\/clearing\/accounts\/domain\/([^/]+)$/);
  if (clearingByDomainMatch && method === 'GET') {
    return handleGetClearingAccountByDomain(decodeURIComponent(clearingByDomainMatch[1]), env);
  }

  // GET /clearing/accounts/:id - Get clearing account by ID
  const clearingByIdMatch = path.match(/^\/clearing\/accounts\/([^/]+)$/);
  if (clearingByIdMatch && method === 'GET') {
    return handleGetClearingAccountById(clearingByIdMatch[1], env);
  }

  // POST /clearing/deposit - Deposit funds to clearing account
  if (path === '/clearing/deposit' && method === 'POST') {
    return handleClearingDeposit(request, env);
  }

  // POST /clearing/withdraw - Withdraw funds from clearing account
  if (path === '/clearing/withdraw' && method === 'POST') {
    return handleClearingWithdraw(request, env);
  }

  // POST /settlements - Execute settlement with batch reference
  if (path === '/settlements' && method === 'POST') {
    return handleSettlement(request, env);
  }

  // POST /accounts - Create account
  if (path === '/accounts' && method === 'POST') {
    return handleCreateAccount(request, env);
  }

  // GET /accounts/id/:id - Get account by ID
  const accountByIdMatch = path.match(/^\/accounts\/id\/([^/]+)$/);
  if (accountByIdMatch && method === 'GET') {
    return handleGetAccountById(accountByIdMatch[1], env);
  }

  // GET /accounts/:did - Get account by DID
  // Note: DID format is did:method:identifier, so we need to capture the whole thing
  const accountByDidMatch = path.match(/^\/accounts\/(did:[^/]+)$/);
  if (accountByDidMatch && method === 'GET') {
    return handleGetAccount(decodeURIComponent(accountByDidMatch[1]), env);
  }

  // POST /events - Create event
  if (path === '/events' && method === 'POST') {
    return handleCreateEvent(request, env);
  }

  // GET /events/verify - Verify hash chain
  if (path === '/events/verify' && method === 'GET') {
    return handleVerifyHashChain(env);
  }

  // GET /events/idempotency/:key - Get event by idempotency key
  const eventByIdempotencyMatch = path.match(/^\/events\/idempotency\/([^/]+)$/);
  if (eventByIdempotencyMatch && method === 'GET') {
    return handleGetEventByIdempotencyKey(
      decodeURIComponent(eventByIdempotencyMatch[1]),
      env
    );
  }

  // GET /events/:id - Get event by ID
  const eventByIdMatch = path.match(/^\/events\/([^/]+)$/);
  if (eventByIdMatch && method === 'GET') {
    return handleGetEvent(eventByIdMatch[1], env);
  }

  // GET /accounts/:accountId/events - Get events for an account
  const accountEventsMatch = path.match(/^\/accounts\/([^/]+)\/events$/);
  if (accountEventsMatch && method === 'GET') {
    return handleGetAccountEvents(accountEventsMatch[1], env, url);
  }

  // POST /holds - Create hold
  if (path === '/holds' && method === 'POST') {
    return handleCreateHold(request, env);
  }

  // POST /holds/:id/release - Release hold
  const releaseHoldMatch = path.match(/^\/holds\/([^/]+)\/release$/);
  if (releaseHoldMatch && method === 'POST') {
    return handleReleaseHold(releaseHoldMatch[1], request, env);
  }

  // GET /holds/:id - Get hold by ID
  const holdByIdMatch = path.match(/^\/holds\/([^/]+)$/);
  if (holdByIdMatch && method === 'GET') {
    return handleGetHold(holdByIdMatch[1], env);
  }

  // GET /accounts/:accountId/holds - Get active holds for an account
  const accountHoldsMatch = path.match(/^\/accounts\/([^/]+)\/holds$/);
  if (accountHoldsMatch && method === 'GET') {
    return handleGetAccountHolds(accountHoldsMatch[1], env);
  }

  // POST /reconciliation/run - Trigger reconciliation
  if (path === '/reconciliation/run' && method === 'POST') {
    return handleRunReconciliation(env);
  }

  // GET /reconciliation/reports - Get recent reports
  if (path === '/reconciliation/reports' && method === 'GET') {
    return handleGetReconciliationReports(env, url);
  }

  // GET /reconciliation/reports/latest - Get the most recent report
  if (path === '/reconciliation/reports/latest' && method === 'GET') {
    return handleGetLatestReport(env);
  }

  // GET /reconciliation/export/:id - Export a report
  const exportReportMatch = path.match(/^\/reconciliation\/export\/([^/]+)$/);
  if (exportReportMatch && method === 'GET') {
    return handleExportReport(exportReportMatch[1], env);
  }

  // GET /reconciliation/reports/:id - Get a specific report
  const reportByIdMatch = path.match(/^\/reconciliation\/reports\/([^/]+)$/);
  if (reportByIdMatch && method === 'GET') {
    return handleGetReconciliationReport(reportByIdMatch[1], env);
  }

  // GET /reserve/assets - List reserve assets
  if (path === '/reserve/assets' && method === 'GET') {
    return handleListReserveAssets(env);
  }

  // POST /reserve/compute - Upsert compute reserve assets (Gemini/FAL)
  if (path === '/reserve/compute' && method === 'POST') {
    return handleUpsertComputeReserves(request, env);
  }

  // POST /reserve/assets - Upsert reserve asset
  if (path === '/reserve/assets' && method === 'POST') {
    return handleUpsertReserveAsset(request, env);
  }

  // GET /attestation/reserve - Generate reserve attestation (public endpoint)
  if (path === '/attestation/reserve' && method === 'GET') {
    return handleReserveAttestation(env);
  }

  // 404 for unknown routes
  return errorResponse('Not found', 'NOT_FOUND', 404);
}

/**
 * Main worker export
 */
export default {
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext
  ): Promise<Response> {
    try {
      return await router(request, env, ctx);
    } catch (err) {
      console.error('Unhandled error:', err);
      const message = err instanceof Error ? err.message : 'Internal server error';
      return errorResponse(message, 'INTERNAL_ERROR', 500);
    }
  },

  /**
   * Scheduled handler for nightly reconciliation job
   * Configured via wrangler.toml cron triggers
   */
  async scheduled(
    _event: ScheduledEvent,
    env: Env,
    ctx: ExecutionContext
  ): Promise<void> {
    console.log('Starting scheduled reconciliation job');

    const service = new ReconciliationService(env);

    // Use waitUntil to ensure the reconciliation completes even after the handler returns
    ctx.waitUntil(
      service.runReconciliation().then((report) => {
        console.log(`Reconciliation completed: ${report.status}`, {
          reportId: report.id,
          eventsReplayed: report.eventsReplayed,
          accountsChecked: report.accountsChecked,
          mismatchCount: report.mismatchCount,
          hashChainValid: report.hashChainValid,
        });
      }).catch((err) => {
        console.error('Reconciliation job failed:', err);
      })
    );
  },
};
