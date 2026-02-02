/**
 * Receipt generation for proxied LLM requests
 */

import type { Provider, Receipt } from './types';
import { sha256 } from './crypto';

export interface ReceiptInput {
  provider: Provider;
  model?: string;
  requestBody: string;
  responseBody: string;
  startTime: number;
}

/**
 * Generate a receipt for a proxied request
 * Receipt contains hashes (not content) for privacy-preserving verification
 */
export async function generateReceipt(input: ReceiptInput): Promise<Receipt> {
  const { provider, model, requestBody, responseBody, startTime } = input;

  const [requestHash, responseHash] = await Promise.all([
    sha256(requestBody),
    sha256(responseBody),
  ]);

  const receipt: Receipt = {
    version: '1.0',
    provider,
    model,
    requestHash,
    responseHash,
    timestamp: new Date().toISOString(),
    latencyMs: Date.now() - startTime,
  };

  return receipt;
}

/**
 * Attach receipt to a response object
 * Returns a new object with _receipt field added
 */
export function attachReceipt<T extends object>(
  response: T,
  receipt: Receipt
): T & { _receipt: Receipt } {
  return {
    ...response,
    _receipt: receipt,
  };
}
