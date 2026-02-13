/**
 * MCP JSON-RPC Interceptor.
 *
 * Parses MCP protocol messages (JSON-RPC 2.0) from a byte stream,
 * intercepts `tools/call` requests and their responses, and injects
 * Clawsig tool_receipts into the `_meta` field of responses.
 *
 * MCP transports:
 * - stdio: JSON-RPC messages delimited by newlines on stdin/stdout
 * - SSE: JSON-RPC over Server-Sent Events (future)
 *
 * We wrap the MCP **server** transport (not the client) because we
 * trust the host environment executing the tool, not the agent.
 *
 * An LLM-layer tool_receipt proves "the model asked to use a tool."
 * An MCP-layer tool_receipt proves "the host actually executed the tool."
 * Reconciling both proves causal integrity.
 */

import { createHash, randomUUID } from 'node:crypto';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** A pending MCP tool call awaiting its result. */
export interface PendingToolCall {
  /** JSON-RPC request ID. */
  rpcId: string | number;
  /** MCP tool name. */
  toolName: string;
  /** SHA-256 hash of the tool arguments. */
  argsHashB64u: string;
  /** Timestamp when the request was intercepted. */
  requestedAt: string;
}

/** A synthesized MCP tool receipt. */
export interface McpToolReceipt {
  receipt_version: '1';
  receipt_id: string;
  receipt_source: 'mcp';
  tool_name: string;
  args_hash_b64u: string;
  result_hash_b64u: string;
  result_status: 'success' | 'error';
  latency_ms: number;
  timestamp: string;
  mcp_request_id: string | number;
}

/** Options for the MCP interceptor. */
export interface InterceptorOptions {
  /** Callback when a tool receipt is synthesized. */
  onReceipt?: (receipt: McpToolReceipt) => void;
  /** Callback when a suspicious tool call is detected. */
  onSuspicious?: (toolName: string, args: unknown) => void;
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

export class McpInterceptor {
  private pending = new Map<string | number, PendingToolCall>();
  private receipts: McpToolReceipt[] = [];
  private options: InterceptorOptions;

  constructor(options: InterceptorOptions = {}) {
    this.options = options;
  }

  /** Get all collected receipts. */
  getReceipts(): McpToolReceipt[] {
    return [...this.receipts];
  }

  /** Get receipt count. */
  get receiptCount(): number {
    return this.receipts.length;
  }

  /**
   * Process an incoming JSON-RPC message (client → server).
   * Intercepts `tools/call` requests.
   *
   * @returns The original message (unmodified). We only observe, not mutate requests.
   */
  processRequest(message: string): string {
    try {
      const parsed = JSON.parse(message);

      // JSON-RPC request with method "tools/call"
      if (parsed.method === 'tools/call' && parsed.id !== undefined) {
        const params = parsed.params;
        const toolName = params?.name ?? 'unknown';
        const args = params?.arguments ?? {};

        const argsHash = sha256B64u(JSON.stringify(args));

        this.pending.set(parsed.id, {
          rpcId: parsed.id,
          toolName,
          argsHashB64u: argsHash,
          requestedAt: new Date().toISOString(),
        });
      }
    } catch {
      // Not valid JSON — pass through
    }

    return message;
  }

  /**
   * Process an outgoing JSON-RPC message (server → client).
   * Matches responses to pending `tools/call` requests and synthesizes receipts.
   *
   * @returns The message with an injected `_meta.clawsig_receipt` if applicable.
   */
  processResponse(message: string): string {
    try {
      const parsed = JSON.parse(message);

      // JSON-RPC response (has id, has result or error)
      if (parsed.id !== undefined && (parsed.result !== undefined || parsed.error !== undefined)) {
        const pending = this.pending.get(parsed.id);
        if (pending) {
          this.pending.delete(parsed.id);

          const isError = parsed.error !== undefined;
          const resultPayload = isError ? parsed.error : parsed.result;
          const resultHash = sha256B64u(JSON.stringify(resultPayload));

          const requestTime = new Date(pending.requestedAt).getTime();
          const latencyMs = Math.max(0, Date.now() - requestTime);

          const receipt: McpToolReceipt = {
            receipt_version: '1',
            receipt_id: `mcp_${randomUUID()}`,
            receipt_source: 'mcp',
            tool_name: pending.toolName,
            args_hash_b64u: pending.argsHashB64u,
            result_hash_b64u: resultHash,
            result_status: isError ? 'error' : 'success',
            latency_ms: latencyMs,
            timestamp: new Date().toISOString(),
            mcp_request_id: pending.rpcId,
          };

          this.receipts.push(receipt);
          this.options.onReceipt?.(receipt);

          // Inject receipt into the response _meta
          if (!isError && parsed.result && typeof parsed.result === 'object') {
            if (!parsed.result._meta) {
              parsed.result._meta = {};
            }
            parsed.result._meta.clawsig_receipt = receipt;
            return JSON.stringify(parsed);
          }
        }
      }
    } catch {
      // Not valid JSON — pass through
    }

    return message;
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** SHA-256 base64url digest (synchronous, no padding). */
function sha256B64u(input: string): string {
  return createHash('sha256')
    .update(input)
    .digest('base64url');
}
