/**
 * Receipt noise filter — removes null-field receipts that bloat proof bundles.
 *
 * The interpose sentinel on macOS generates thousands of execution receipts
 * where every actionable field is null (fork/exec syscalls from the Node.js
 * process tree). Similarly, network receipts with null remote_host/port are
 * Node.js internal connections, not agent API calls.
 *
 * Filtering happens at bundle compilation time, not capture time. Full data
 * is preserved for --verbose diagnostics; only the bundle output is filtered.
 */

import type {
  ExecutionReceiptPayload,
  NetworkReceiptPayload,
} from './types.js';

/**
 * Returns true if an execution receipt has no useful actionable data.
 * These are typically fork/exec syscalls from the Node.js process tree
 * on macOS where all fields come through as null/empty.
 */
export function isNoiseExecutionReceipt(receipt: ExecutionReceiptPayload): boolean {
  return (
    !receipt.command_hash_b64u &&
    !receipt.target_hash_b64u &&
    receipt.command_type === 'execution'
  );
}

/**
 * Returns true if a network receipt has no useful connection data.
 * These are typically Node.js internal connections where both
 * remote address and classification are absent or meaningless.
 */
export function isNoiseNetworkReceipt(receipt: NetworkReceiptPayload): boolean {
  return (
    !receipt.remote_address_hash_b64u &&
    receipt.pid === null &&
    receipt.process_name === null
  );
}

/**
 * Filter execution receipts, removing noise entries.
 * Returns only receipts that carry actionable data.
 */
export function filterExecutionReceipts(
  receipts: ExecutionReceiptPayload[],
): ExecutionReceiptPayload[] {
  return receipts.filter((r) => !isNoiseExecutionReceipt(r));
}

/**
 * Filter network receipts, removing noise entries.
 * Returns only receipts that carry actionable data.
 */
export function filterNetworkReceipts(
  receipts: NetworkReceiptPayload[],
): NetworkReceiptPayload[] {
  return receipts.filter((r) => !isNoiseNetworkReceipt(r));
}

/**
 * Summary statistics for a compiled proof bundle.
 * Powers the summary box output and --json mode.
 */
export interface BundleSummaryStats {
  /** Receipt counts by type. */
  receiptCounts: {
    gateway: number;
    tool_call: number;
    execution: number;
    side_effect: number;
    network: number;
    human_approval: number;
    other: number;
  };
  /** Total number of receipts across all types. */
  totalReceipts: number;
  /** Total bundle size in bytes (JSON serialized). */
  bundleSizeBytes: number;
  /** Human-readable bundle size (e.g. "26 KB"). */
  bundleSizeHuman: string;
  /** Coverage tier based on receipt types present. */
  coverageTier: 'Self' | 'Gateway' | 'Gateway + Tools' | 'Gateway + Tools + Side-Effects';
  /** Number of receipts filtered out as noise. */
  filteredOut: {
    execution: number;
    network: number;
  };
}

/**
 * Compute summary statistics from a proof bundle payload and its
 * pre-filter counts.
 */
export function computeBundleSummary(args: {
  bundleJson: string;
  gatewayCount: number;
  toolCallCount: number;
  executionCount: number;
  sideEffectCount: number;
  networkCount: number;
  humanApprovalCount: number;
  otherCount: number;
  filteredExecution: number;
  filteredNetwork: number;
}): BundleSummaryStats {
  const bytes = Buffer.byteLength(args.bundleJson, 'utf-8');
  const totalReceipts =
    args.gatewayCount +
    args.toolCallCount +
    args.executionCount +
    args.sideEffectCount +
    args.networkCount +
    args.humanApprovalCount +
    args.otherCount;

  let coverageTier: BundleSummaryStats['coverageTier'] = 'Self';
  if (args.gatewayCount > 0) coverageTier = 'Gateway';
  if (args.gatewayCount > 0 && args.toolCallCount > 0) coverageTier = 'Gateway + Tools';
  if (args.gatewayCount > 0 && args.toolCallCount > 0 && args.sideEffectCount > 0) {
    coverageTier = 'Gateway + Tools + Side-Effects';
  }

  return {
    receiptCounts: {
      gateway: args.gatewayCount,
      tool_call: args.toolCallCount,
      execution: args.executionCount,
      side_effect: args.sideEffectCount,
      network: args.networkCount,
      human_approval: args.humanApprovalCount,
      other: args.otherCount,
    },
    totalReceipts,
    bundleSizeBytes: bytes,
    bundleSizeHuman: formatBytes(bytes),
    coverageTier,
    filteredOut: {
      execution: args.filteredExecution,
      network: args.filteredNetwork,
    },
  };
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const kb = bytes / 1024;
  if (kb < 1024) return `${Math.round(kb)} KB`;
  const mb = kb / 1024;
  return `${mb.toFixed(1)} MB`;
}
