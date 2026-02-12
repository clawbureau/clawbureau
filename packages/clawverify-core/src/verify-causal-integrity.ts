/**
 * TOCTOU Causal Integrity Verification (Red Team Fix #11 / Bonus).
 *
 * Detects Time-of-Check-to-Time-of-Use violations in proof bundles.
 *
 * Attack vector: Agent reads auth.ts, gets a tool_receipt with
 * result_hash_b64u of the safe version. While the LLM is thinking,
 * an attacker modifies auth.ts on disk. The agent commits the
 * malicious version.
 *
 * Defense: For each side_effect_receipt of type filesystem_write that
 * references files, verify that each file's hash matches the
 * result_hash_b64u of the most recent preceding tool_receipt that
 * read that file.
 *
 * This is a WARNING-tier finding, not a hard FAIL.
 */

import type { EventChainEntry } from './types.js';

// ---------------------------------------------------------------------------
// Local receipt interfaces (present in actual bundle JSON per SDK types)
// ---------------------------------------------------------------------------

interface ToolReceipt {
  receipt_id: string;
  tool_name: string;
  tool_version?: string;
  args_hash_b64u?: string;
  args_digest?: string;
  result_hash_b64u?: string;
  result_digest?: string;
  result_status?: string;
  timestamp: string;
  binding?: Record<string, unknown>;
}

interface SideEffectReceipt {
  receipt_id: string;
  effect_class: string;
  timestamp: string;
  binding?: Record<string, unknown>;
}

export interface CausalIntegrityBundleInput {
  event_chain?: EventChainEntry[];
  tool_receipts?: ToolReceipt[];
  side_effect_receipts?: SideEffectReceipt[];
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type CausalIntegritySeverity = 'warning' | 'info';

export interface CausalIntegrityFinding {
  severity: CausalIntegritySeverity;
  code: 'TOCTOU_INTEGRITY_VIOLATION' | 'TOCTOU_UNVERIFIABLE';
  message: string;
  file_path?: string;
  read_hash_b64u?: string;
  commit_hash_b64u?: string;
  read_receipt_id?: string;
  commit_receipt_id?: string;
}

export interface CausalIntegrityResult {
  has_violations: boolean;
  files_checked: number;
  files_passed: number;
  findings: CausalIntegrityFinding[];
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

const FILE_TOOLS = new Set([
  'read_file', 'write_file', 'edit_file', 'cat', 'read',
  'file_read', 'file_write', 'file_edit',
]);

function extractFilePathFromToolReceipt(receipt: ToolReceipt): string | undefined {
  if (!FILE_TOOLS.has(receipt.tool_name)) return undefined;

  const binding = receipt.binding;
  if (binding?.['file_path'] && typeof binding['file_path'] === 'string') {
    return binding['file_path'];
  }

  if (receipt.args_digest && typeof receipt.args_digest === 'string') {
    const pathMatch = receipt.args_digest.match(/path=([^\s,]+)/);
    if (pathMatch?.[1]) return pathMatch[1];
  }

  return undefined;
}

function extractCommitFiles(receipt: SideEffectReceipt): Array<{
  path: string;
  hash_b64u: string;
}> {
  const files: Array<{ path: string; hash_b64u: string }> = [];
  const binding = receipt.binding;
  const committedFiles = binding?.['committed_files'];

  if (Array.isArray(committedFiles)) {
    for (const f of committedFiles) {
      if (
        f &&
        typeof f === 'object' &&
        'path' in f &&
        typeof (f as Record<string, unknown>)['path'] === 'string' &&
        'hash_b64u' in f &&
        typeof (f as Record<string, unknown>)['hash_b64u'] === 'string'
      ) {
        files.push({
          path: (f as Record<string, string>)['path'],
          hash_b64u: (f as Record<string, string>)['hash_b64u'],
        });
      }
    }
  }

  return files;
}

function buildReceiptOrderMap(
  eventChain: EventChainEntry[] | undefined,
  toolReceipts: ToolReceipt[],
  sideEffectReceipts: SideEffectReceipt[],
): Map<string, number> {
  const orderMap = new Map<string, number>();

  const allReceipts = [
    ...toolReceipts.map(r => ({ id: r.receipt_id, ts: r.timestamp, binding: r.binding })),
    ...sideEffectReceipts.map(r => ({ id: r.receipt_id, ts: r.timestamp, binding: r.binding })),
  ];

  if (eventChain && eventChain.length > 0) {
    const eventHashToPosition = new Map<string, number>();
    for (let i = 0; i < eventChain.length; i++) {
      eventHashToPosition.set(eventChain[i].event_hash_b64u, i);
    }

    for (const r of allReceipts) {
      const eventHash = r.binding?.['event_hash_b64u'];
      if (typeof eventHash === 'string' && eventHashToPosition.has(eventHash)) {
        orderMap.set(r.id, eventHashToPosition.get(eventHash)!);
      }
    }
  }

  const timestampSorted = [...allReceipts].sort(
    (a, b) => new Date(a.ts).getTime() - new Date(b.ts).getTime(),
  );
  for (let i = 0; i < timestampSorted.length; i++) {
    if (!orderMap.has(timestampSorted[i].id)) {
      orderMap.set(timestampSorted[i].id, 1_000_000 + i);
    }
  }

  return orderMap;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Verify causal integrity of a proof bundle.
 *
 * Checks that files referenced in side_effect_receipts of type
 * filesystem_write match the result_hash_b64u of the most recent
 * preceding tool_receipt that read those files.
 */
export function verifyCausalIntegrity(
  bundle: CausalIntegrityBundleInput,
): CausalIntegrityResult {
  const findings: CausalIntegrityFinding[] = [];
  let filesChecked = 0;
  let filesPassed = 0;

  const toolReceipts = bundle.tool_receipts ?? [];
  const sideEffectReceipts = bundle.side_effect_receipts ?? [];

  const orderMap = buildReceiptOrderMap(bundle.event_chain, toolReceipts, sideEffectReceipts);

  const fileReadMap = new Map<string, {
    receipt_id: string;
    result_hash_b64u: string | undefined;
    order: number;
  }>();

  for (const tr of toolReceipts) {
    const filePath = extractFilePathFromToolReceipt(tr);
    if (!filePath) continue;

    const order = orderMap.get(tr.receipt_id) ?? Infinity;
    const existing = fileReadMap.get(filePath);

    if (!existing || order > existing.order) {
      fileReadMap.set(filePath, {
        receipt_id: tr.receipt_id,
        result_hash_b64u: tr.result_hash_b64u,
        order,
      });
    }
  }

  for (const ser of sideEffectReceipts) {
    if (ser.effect_class !== 'filesystem_write') continue;

    const committedFiles = extractCommitFiles(ser);
    if (committedFiles.length === 0) continue;

    const commitOrder = orderMap.get(ser.receipt_id) ?? Infinity;

    for (const file of committedFiles) {
      filesChecked++;
      const lastRead = fileReadMap.get(file.path);

      if (!lastRead) {
        findings.push({
          severity: 'info',
          code: 'TOCTOU_UNVERIFIABLE',
          message: `File "${file.path}" was committed but has no preceding read receipt.`,
          file_path: file.path,
          commit_hash_b64u: file.hash_b64u,
          commit_receipt_id: ser.receipt_id,
        });
        continue;
      }

      if (lastRead.order >= commitOrder) {
        findings.push({
          severity: 'info',
          code: 'TOCTOU_UNVERIFIABLE',
          message: `File "${file.path}" read receipt not ordered before commit receipt.`,
          file_path: file.path,
          read_receipt_id: lastRead.receipt_id,
          commit_receipt_id: ser.receipt_id,
        });
        continue;
      }

      if (!lastRead.result_hash_b64u) {
        findings.push({
          severity: 'info',
          code: 'TOCTOU_UNVERIFIABLE',
          message: `File "${file.path}" read receipt has no result_hash_b64u.`,
          file_path: file.path,
          read_receipt_id: lastRead.receipt_id,
          commit_receipt_id: ser.receipt_id,
        });
        continue;
      }

      if (lastRead.result_hash_b64u !== file.hash_b64u) {
        findings.push({
          severity: 'warning',
          code: 'TOCTOU_INTEGRITY_VIOLATION',
          message: `File "${file.path}" modified between read and commit. ` +
            `Read: ${lastRead.result_hash_b64u}, Commit: ${file.hash_b64u}.`,
          file_path: file.path,
          read_hash_b64u: lastRead.result_hash_b64u,
          commit_hash_b64u: file.hash_b64u,
          read_receipt_id: lastRead.receipt_id,
          commit_receipt_id: ser.receipt_id,
        });
      } else {
        filesPassed++;
      }
    }
  }

  return {
    has_violations: findings.some(f => f.code === 'TOCTOU_INTEGRITY_VIOLATION'),
    files_checked: filesChecked,
    files_passed: filesPassed,
    findings,
  };
}
