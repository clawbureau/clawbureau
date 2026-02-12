/**
 * Stake, Fee, and Promo event management for ClawLedger
 * Handles stake_lock, stake_slash, fee_burn, fee_transfer, promo_mint, promo_burn events
 * Links events to originating escrow/trial IDs for audit determinism
 */

import { AccountRepository } from './accounts';
import { computeEventHash, EventRepository, toEventResponse } from './events';
import type {
  BucketName,
  Env,
  EventResponse,
  EventType,
  FeeBurnRequest,
  FeeTransferRequest,
  PromoBurnRequest,
  PromoMintRequest,
  StakeFeeEventResponse,
  StakeLockRequest,
  StakeSlashRequest,
} from './types';

/**
 * Build stake event metadata with escrow/trial links
 */
function buildStakeMetadata(
  escrowId?: string,
  trialId?: string,
  reason?: string,
  extraMetadata?: Record<string, unknown>
): Record<string, unknown> {
  const metadata: Record<string, unknown> = {};
  if (escrowId) metadata.escrowId = escrowId;
  if (trialId) metadata.trialId = trialId;
  if (reason) metadata.reason = reason;
  if (extraMetadata) metadata.context = extraMetadata;
  return metadata;
}

/**
 * Build fee event metadata with escrow/transaction links
 */
function buildFeeMetadata(
  escrowId?: string,
  transactionId?: string,
  feeType?: string,
  reason?: string,
  extraMetadata?: Record<string, unknown>
): Record<string, unknown> {
  const metadata: Record<string, unknown> = {};
  if (escrowId) metadata.escrowId = escrowId;
  if (transactionId) metadata.transactionId = transactionId;
  if (feeType) metadata.feeType = feeType;
  if (reason) metadata.reason = reason;
  if (extraMetadata) metadata.context = extraMetadata;
  return metadata;
}

/**
 * Build promo event metadata with campaign links
 */
function buildPromoMetadata(
  campaignId?: string,
  promoCode?: string,
  reason?: string,
  expiresAt?: string,
  extraMetadata?: Record<string, unknown>
): Record<string, unknown> {
  const metadata: Record<string, unknown> = {};
  if (campaignId) metadata.campaignId = campaignId;
  if (promoCode) metadata.promoCode = promoCode;
  if (reason) metadata.reason = reason;
  if (expiresAt) metadata.expiresAt = expiresAt;
  if (extraMetadata) metadata.context = extraMetadata;
  return metadata;
}

/**
 * Convert event response to stake/fee event response
 */
function toStakeFeeEventResponse(
  event: EventResponse,
  eventType: EventType
): StakeFeeEventResponse {
  return {
    eventId: event.id,
    idempotencyKey: event.idempotencyKey,
    eventType,
    accountId: event.accountId,
    amount: event.amount,
    bucket: event.bucket,
    eventHash: event.eventHash,
    createdAt: event.createdAt,
    metadata: event.metadata,
  };
}

/**
 * Service for stake, fee, and promo events
 */
export class StakeFeeService {
  private eventRepository: EventRepository;
  private accountRepository: AccountRepository;

  constructor(env: Env) {
    this.eventRepository = new EventRepository(env.DB);
    this.accountRepository = new AccountRepository(env.DB);
  }

  /**
   * Create a stake_lock event
   * Moves funds from available to bonded bucket
   */
  async stakeLock(request: StakeLockRequest): Promise<StakeFeeEventResponse> {
    const eventType: EventType = 'stake_lock';
    const bucket: BucketName = 'bonded';

    // Check for existing event with same idempotency key
    const existing = await this.eventRepository.findByIdempotencyKey(
      request.idempotencyKey
    );
    if (existing) {
      return toStakeFeeEventResponse(toEventResponse(existing), eventType);
    }

    // Validate amount
    const amount = BigInt(request.amount);
    if (amount <= 0n) {
      throw new Error('Amount must be positive');
    }

    // Move funds from available to bonded
    await this.accountRepository.moveBetweenBuckets(
      request.accountId,
      'available',
      'bonded',
      amount
    );

    // Build metadata with escrow/trial links
    const metadata = buildStakeMetadata(
      request.escrowId,
      request.trialId,
      request.reason,
      request.metadata
    );

    // Get previous hash for chain
    const previousHash = await this.eventRepository.getLastEventHash();
    const now = new Date().toISOString();

    // Compute event hash
    const eventHash = await computeEventHash(
      previousHash,
      eventType,
      request.accountId,
      undefined,
      amount,
      bucket,
      request.idempotencyKey,
      now
    );

    // Create the event
    const event = await this.eventRepository.create(
      request.idempotencyKey,
      eventType,
      request.accountId,
      amount,
      bucket,
      previousHash,
      eventHash,
      undefined,
      metadata
    );

    return toStakeFeeEventResponse(toEventResponse(event), eventType);
  }

  /**
   * Create a stake_slash event
   * Removes funds from bonded bucket (penalty)
   */
  async stakeSlash(request: StakeSlashRequest): Promise<StakeFeeEventResponse> {
    const eventType: EventType = 'stake_slash';
    const bucket: BucketName = 'bonded';

    // Check for existing event with same idempotency key
    const existing = await this.eventRepository.findByIdempotencyKey(
      request.idempotencyKey
    );
    if (existing) {
      return toStakeFeeEventResponse(toEventResponse(existing), eventType);
    }

    // Validate amount
    const amount = BigInt(request.amount);
    if (amount <= 0n) {
      throw new Error('Amount must be positive');
    }

    // Debit bonded bucket (slash)
    await this.accountRepository.debitBonded(request.accountId, amount);

    // Build metadata with escrow/trial links
    const metadata = buildStakeMetadata(
      request.escrowId,
      request.trialId,
      request.reason,
      request.metadata
    );

    // Get previous hash for chain
    const previousHash = await this.eventRepository.getLastEventHash();
    const now = new Date().toISOString();

    // Compute event hash
    const eventHash = await computeEventHash(
      previousHash,
      eventType,
      request.accountId,
      undefined,
      amount,
      bucket,
      request.idempotencyKey,
      now
    );

    // Create the event
    const event = await this.eventRepository.create(
      request.idempotencyKey,
      eventType,
      request.accountId,
      amount,
      bucket,
      previousHash,
      eventHash,
      undefined,
      metadata
    );

    return toStakeFeeEventResponse(toEventResponse(event), eventType);
  }

  /**
   * Create a fee_burn event
   * Burns funds from fee pool bucket
   */
  async feeBurn(request: FeeBurnRequest): Promise<StakeFeeEventResponse> {
    const eventType: EventType = 'fee_burn';
    const bucket: BucketName = 'feePool';

    // Check for existing event with same idempotency key
    const existing = await this.eventRepository.findByIdempotencyKey(
      request.idempotencyKey
    );
    if (existing) {
      return toStakeFeeEventResponse(toEventResponse(existing), eventType);
    }

    // Validate amount
    const amount = BigInt(request.amount);
    if (amount <= 0n) {
      throw new Error('Amount must be positive');
    }

    // Debit fee pool bucket (burn)
    await this.accountRepository.debitFeePool(request.accountId, amount);

    // Build metadata with escrow/transaction links
    const metadata = buildFeeMetadata(
      request.escrowId,
      request.transactionId,
      request.feeType,
      request.reason,
      request.metadata
    );

    // Get previous hash for chain
    const previousHash = await this.eventRepository.getLastEventHash();
    const now = new Date().toISOString();

    // Compute event hash
    const eventHash = await computeEventHash(
      previousHash,
      eventType,
      request.accountId,
      undefined,
      amount,
      bucket,
      request.idempotencyKey,
      now
    );

    // Create the event
    const event = await this.eventRepository.create(
      request.idempotencyKey,
      eventType,
      request.accountId,
      amount,
      bucket,
      previousHash,
      eventHash,
      undefined,
      metadata
    );

    return toStakeFeeEventResponse(toEventResponse(event), eventType);
  }

  /**
   * Create a fee_transfer event
   * Transfers funds from a source bucket to fee pool
   */
  async feeTransfer(request: FeeTransferRequest): Promise<StakeFeeEventResponse> {
    const eventType: EventType = 'fee_transfer';
    const bucket: BucketName = 'feePool';
    const fromBucket = request.fromBucket ?? 'available';

    // Check for existing event with same idempotency key
    const existing = await this.eventRepository.findByIdempotencyKey(
      request.idempotencyKey
    );
    if (existing) {
      return toStakeFeeEventResponse(toEventResponse(existing), eventType);
    }

    // Validate amount
    const amount = BigInt(request.amount);
    if (amount <= 0n) {
      throw new Error('Amount must be positive');
    }

    // Move funds from source bucket to fee pool
    await this.accountRepository.moveBetweenBuckets(
      request.accountId,
      fromBucket,
      'feePool',
      amount
    );

    // Build metadata with escrow/transaction links and source bucket info
    const metadata = buildFeeMetadata(
      request.escrowId,
      request.transactionId,
      request.feeType,
      request.reason,
      { ...request.metadata, fromBucket }
    );

    // Get previous hash for chain
    const previousHash = await this.eventRepository.getLastEventHash();
    const now = new Date().toISOString();

    // Compute event hash
    const eventHash = await computeEventHash(
      previousHash,
      eventType,
      request.accountId,
      undefined,
      amount,
      bucket,
      request.idempotencyKey,
      now
    );

    // Create the event
    const event = await this.eventRepository.create(
      request.idempotencyKey,
      eventType,
      request.accountId,
      amount,
      bucket,
      previousHash,
      eventHash,
      undefined,
      metadata
    );

    return toStakeFeeEventResponse(toEventResponse(event), eventType);
  }

  /**
   * Create a promo_mint event
   * Mints credits directly to promo bucket
   */
  async promoMint(request: PromoMintRequest): Promise<StakeFeeEventResponse> {
    const eventType: EventType = 'promo_mint';
    const bucket: BucketName = 'promo';

    // Check for existing event with same idempotency key
    const existing = await this.eventRepository.findByIdempotencyKey(
      request.idempotencyKey
    );
    if (existing) {
      return toStakeFeeEventResponse(toEventResponse(existing), eventType);
    }

    // Validate amount
    const amount = BigInt(request.amount);
    if (amount <= 0n) {
      throw new Error('Amount must be positive');
    }

    // Credit promo bucket
    await this.accountRepository.creditPromo(request.accountId, amount);

    // Build metadata with campaign links
    const metadata = buildPromoMetadata(
      request.campaignId,
      request.promoCode,
      request.reason,
      request.expiresAt,
      request.metadata
    );

    // Get previous hash for chain
    const previousHash = await this.eventRepository.getLastEventHash();
    const now = new Date().toISOString();

    // Compute event hash
    const eventHash = await computeEventHash(
      previousHash,
      eventType,
      request.accountId,
      undefined,
      amount,
      bucket,
      request.idempotencyKey,
      now
    );

    // Create the event
    const event = await this.eventRepository.create(
      request.idempotencyKey,
      eventType,
      request.accountId,
      amount,
      bucket,
      previousHash,
      eventHash,
      undefined,
      metadata
    );

    return toStakeFeeEventResponse(toEventResponse(event), eventType);
  }

  /**
   * Create a promo_burn event
   * Burns credits from promo bucket
   */
  async promoBurn(request: PromoBurnRequest): Promise<StakeFeeEventResponse> {
    const eventType: EventType = 'promo_burn';
    const bucket: BucketName = 'promo';

    // Check for existing event with same idempotency key
    const existing = await this.eventRepository.findByIdempotencyKey(
      request.idempotencyKey
    );
    if (existing) {
      return toStakeFeeEventResponse(toEventResponse(existing), eventType);
    }

    // Validate amount
    const amount = BigInt(request.amount);
    if (amount <= 0n) {
      throw new Error('Amount must be positive');
    }

    // Debit promo bucket (burn)
    await this.accountRepository.debitPromo(request.accountId, amount);

    // Build metadata with campaign links
    const metadata = buildPromoMetadata(
      request.campaignId,
      undefined,
      request.reason,
      undefined,
      request.metadata
    );

    // Get previous hash for chain
    const previousHash = await this.eventRepository.getLastEventHash();
    const now = new Date().toISOString();

    // Compute event hash
    const eventHash = await computeEventHash(
      previousHash,
      eventType,
      request.accountId,
      undefined,
      amount,
      bucket,
      request.idempotencyKey,
      now
    );

    // Create the event
    const event = await this.eventRepository.create(
      request.idempotencyKey,
      eventType,
      request.accountId,
      amount,
      bucket,
      previousHash,
      eventHash,
      undefined,
      metadata
    );

    return toStakeFeeEventResponse(toEventResponse(event), eventType);
  }
}
