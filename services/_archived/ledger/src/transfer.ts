/**
 * Transfer service for ClawLedger
 * Handles fund transfers between accounts with webhook notifications
 */

import { AccountRepository, InsufficientFundsError } from './accounts';
import { EventRepository, computeEventHash } from './events';
import type {
  Env,
  EventResponse,
  TransferRequest,
  TransferResponse,
  WebhookEventPayload,
} from './types';

/**
 * Generate unique webhook ID for deduplication
 */
function generateWebhookId(): string {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 10);
  return `whk_${timestamp}_${random}`;
}

/**
 * Send webhook notification for an event
 * Non-blocking, logs errors but doesn't throw
 */
async function sendEventWebhook(
  webhookUrl: string,
  event: EventResponse
): Promise<void> {
  const payload: WebhookEventPayload = {
    webhookType: 'ledger.event.created',
    event,
    sentAt: new Date().toISOString(),
    webhookId: generateWebhookId(),
  };

  try {
    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Webhook-Type': 'ledger.event.created',
        'X-Webhook-Id': payload.webhookId,
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      console.error(
        `Webhook delivery failed: ${response.status} ${response.statusText}`
      );
    }
  } catch (error) {
    console.error('Webhook delivery error:', error);
  }
}

/**
 * Transfer service for executing transfers between accounts
 */
export class TransferService {
  private accountRepository: AccountRepository;
  private eventRepository: EventRepository;
  private webhookUrl?: string;

  constructor(env: Env) {
    this.accountRepository = new AccountRepository(env.DB);
    this.eventRepository = new EventRepository(env.DB);
    this.webhookUrl = env.EVENT_WEBHOOK_URL;
  }

  /**
   * Execute a transfer between two accounts
   * - Validates sufficient funds
   * - Debits source account
   * - Credits target account
   * - Creates transfer event
   * - Sends webhook notification
   */
  async transfer(request: TransferRequest): Promise<TransferResponse> {
    // Validate amount
    let amount: bigint;
    try {
      amount = BigInt(request.amount);
      if (amount <= 0n) {
        throw new Error('Amount must be positive');
      }
    } catch {
      throw new Error(
        `Invalid amount: ${request.amount}. Must be a valid positive integer string`
      );
    }

    // Check for existing event with same idempotency key
    const existing = await this.eventRepository.findByIdempotencyKey(
      request.idempotencyKey
    );
    if (existing) {
      // Return cached result for idempotent retry
      return {
        eventId: existing.id,
        idempotencyKey: existing.idempotencyKey,
        fromAccountId: existing.accountId,
        toAccountId: existing.toAccountId!,
        amount: existing.amount.toString(),
        eventHash: existing.eventHash,
        createdAt: existing.createdAt,
      };
    }

    // Verify source account exists and has sufficient funds
    const sourceAccount = await this.accountRepository.findById(
      request.fromAccountId
    );
    if (!sourceAccount) {
      throw new Error(`Source account not found: ${request.fromAccountId}`);
    }

    if (sourceAccount.balances.available < amount) {
      throw new InsufficientFundsError(
        request.fromAccountId,
        'available',
        amount,
        sourceAccount.balances.available
      );
    }

    // Verify target account exists
    const targetAccount = await this.accountRepository.findById(
      request.toAccountId
    );
    if (!targetAccount) {
      throw new Error(`Target account not found: ${request.toAccountId}`);
    }

    // Prevent self-transfer
    if (request.fromAccountId === request.toAccountId) {
      throw new Error('Cannot transfer to the same account');
    }

    // Debit source account
    await this.accountRepository.debitAvailable(request.fromAccountId, amount);

    // Credit target account
    await this.accountRepository.creditAvailable(request.toAccountId, amount);

    // Create transfer event
    const previousHash = await this.eventRepository.getLastEventHash();
    const now = new Date().toISOString();

    const eventHash = await computeEventHash(
      previousHash,
      'transfer',
      request.fromAccountId,
      request.toAccountId,
      amount,
      'available',
      request.idempotencyKey,
      now
    );

    const event = await this.eventRepository.create(
      request.idempotencyKey,
      'transfer',
      request.fromAccountId,
      amount,
      'available',
      previousHash,
      eventHash,
      request.toAccountId,
      request.metadata
    );

    const response: TransferResponse = {
      eventId: event.id,
      idempotencyKey: event.idempotencyKey,
      fromAccountId: event.accountId,
      toAccountId: event.toAccountId!,
      amount: event.amount.toString(),
      eventHash: event.eventHash,
      createdAt: event.createdAt,
    };

    // Send webhook notification (non-blocking)
    if (this.webhookUrl) {
      // Fire and forget - use ctx.waitUntil in the handler if needed
      sendEventWebhook(this.webhookUrl, {
        id: event.id,
        idempotencyKey: event.idempotencyKey,
        eventType: event.eventType,
        accountId: event.accountId,
        toAccountId: event.toAccountId,
        amount: event.amount.toString(),
        bucket: event.bucket,
        previousHash: event.previousHash,
        eventHash: event.eventHash,
        metadata: event.metadata,
        createdAt: event.createdAt,
      }).catch((err) => console.error('Failed to send webhook:', err));
    }

    return response;
  }
}

/**
 * Webhook service for sending event notifications
 */
export class WebhookService {
  private webhookUrl?: string;

  constructor(env: Env) {
    this.webhookUrl = env.EVENT_WEBHOOK_URL;
  }

  /**
   * Check if webhooks are configured
   */
  isConfigured(): boolean {
    return !!this.webhookUrl;
  }

  /**
   * Send webhook for an event
   */
  async sendEventWebhook(event: EventResponse): Promise<void> {
    if (!this.webhookUrl) {
      return;
    }
    await sendEventWebhook(this.webhookUrl, event);
  }
}

export { sendEventWebhook };
