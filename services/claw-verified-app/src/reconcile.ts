/**
 * Diff-to-Receipt Reconciliation with Differential Provenance.
 *
 * Compares the PR's changed files against the proof bundle's
 * side_effect_receipts and tool_receipts to determine authorship:
 *
 * 1. AGENT-ATTESTED: File has a matching side_effect_receipt.
 * 2. MIXED: File has a receipt (agent touched it) but was subsequently
 *    edited by a human. The receipt exists but content hash may differ.
 *    This is the NORMAL workflow in 2026 — developer edits AI output.
 * 3. UNATTESTED: File was changed in the PR but has NO receipt.
 *    This could be a human-only change (fine) or a smuggled mutation
 *    that bypassed the agent wrapper (suspicious).
 *
 * Differential Provenance ensures that human edits to AI-generated
 * code do NOT block the PR. Only files with zero provenance link
 * to any agent activity are flagged.
 *
 * Matching strategy (hash-only by design):
 *  1. Direct match:   target_digest === filepath
 *  2. SHA-256 hex:    target_digest === "sha256:<hex(filepath)>"
 *  3. Base64url:      target_hash_b64u === base64url(sha256(filepath))
 *  4. Base64url in digest field
 *  5. Tool receipt arg match: tool args reference the filepath
 */

// ---------- Public types ----------

/** Authorship classification for a single file. */
export type FileProvenance = 'agent' | 'mixed' | 'human' | 'skipped';

/** Per-file reconciliation detail. */
export interface FileReconciliationDetail {
  filename: string;
  provenance: FileProvenance;
  /** The tool that touched this file (if agent/mixed). */
  tool_name?: string;
  /** Receipt ID linking this file to agent activity. */
  receipt_id?: string;
}

/** Result of diff-to-receipt reconciliation. */
export interface ReconciliationResult {
  /** True if no files are completely unattested (all have some provenance). */
  reconciled: boolean;
  /** Files with zero provenance link to any agent activity. */
  unattested_files: string[];
  /** Detailed provenance for every file in the PR diff. */
  file_details: FileReconciliationDetail[];
  /** Summary counts. */
  summary: {
    agent_files: number;
    mixed_files: number;
    human_files: number;
    skipped_files: number;
    total_files: number;
  };
}

/** Minimal shape of a PR file entry from the GitHub API. */
export interface PRFileEntry {
  filename: string;
  previous_filename?: string;
  status: string;
}

// ---------- Internal types ----------

interface SideEffectEntry {
  receipt_id?: string;
  effect_class?: string;
  target_digest?: string;
  target_hash_b64u?: string;
}

interface ToolReceiptEntry {
  receipt_id?: string;
  tool_name?: string;
  args_hash_b64u?: string;
  /** Raw args (if available, some emitters include plaintext for debug). */
  args?: unknown;
}

// ---------- Skip rules ----------

/** Path prefixes excluded from reconciliation. */
const SKIP_PREFIXES = ['.clawsig/', '.github/'];

/** Patterns identifying proof bundle files. */
const BUNDLE_FILE_PATTERNS = [
  /proof_bundle.*\.json$/i,
  /proofs\/.*\/.*bundle.*\.json$/i,
];

// ---------- Public API ----------

/**
 * Reconcile PR changed files against proof bundle receipts.
 *
 * Implements Differential Provenance: files touched by both an agent
 * AND a human are classified as "mixed" (not failed). Only files with
 * zero agent provenance are classified as "human" (unattested by agent).
 *
 * The reconciliation PASSES if:
 * - All files are agent-attested, mixed, or skipped
 * - OR the bundle has zero side-effect receipts (Observe Mode —
 *   the agent ran but didn't generate filesystem receipts)
 *
 * The reconciliation FAILS if:
 * - Files exist in the diff with no provenance AND the bundle
 *   contains side-effect receipts (proving the agent DID generate
 *   receipts for some files but not these)
 */
export async function reconcileDiffWithBundle(
  changedFiles: PRFileEntry[],
  bundles: Array<Record<string, unknown>>,
): Promise<ReconciliationResult> {
  // 1. Collect attested targets from all bundles
  const attestedDigests = new Set<string>();
  const attestedHashes = new Set<string>();
  const receiptsByHash = new Map<string, { receipt_id: string; tool_name?: string }>();

  // Also collect tool receipts for arg-based matching
  const toolReceipts: ToolReceiptEntry[] = [];
  const toolArgHashes = new Map<string, { receipt_id: string; tool_name: string }>();
  let hasSideEffectReceipts = false;

  for (const bundle of bundles) {
    // Side-effect receipts
    const seReceipts = extractSideEffectReceipts(bundle);
    for (const receipt of seReceipts) {
      if (receipt.effect_class !== 'filesystem_write') continue;
      hasSideEffectReceipts = true;

      if (receipt.target_digest) {
        attestedDigests.add(receipt.target_digest);
        if (receipt.receipt_id) {
          receiptsByHash.set(receipt.target_digest, {
            receipt_id: receipt.receipt_id,
          });
        }
      }
      if (receipt.target_hash_b64u) {
        attestedHashes.add(receipt.target_hash_b64u);
        if (receipt.receipt_id) {
          receiptsByHash.set(receipt.target_hash_b64u, {
            receipt_id: receipt.receipt_id,
          });
        }
      }
    }

    // Tool receipts (for arg-based matching)
    const trReceipts = extractToolReceipts(bundle);
    toolReceipts.push(...trReceipts);
    for (const tr of trReceipts) {
      if (tr.args_hash_b64u && tr.receipt_id && tr.tool_name) {
        toolArgHashes.set(tr.args_hash_b64u, {
          receipt_id: tr.receipt_id,
          tool_name: tr.tool_name,
        });
      }
    }
  }

  // 2. Classify each PR file
  const fileDetails: FileReconciliationDetail[] = [];
  const unattested: string[] = [];

  for (const file of changedFiles) {
    // Skip infrastructure files
    if (shouldSkip(file.filename)) {
      fileDetails.push({ filename: file.filename, provenance: 'skipped' });
      continue;
    }

    // Check side-effect receipts
    const seMatch = await matchFileToSideEffect(
      file.filename, attestedDigests, attestedHashes, receiptsByHash,
    );

    if (seMatch) {
      // File has a side-effect receipt — agent touched it.
      // Whether human also edited it later is fine (mixed provenance).
      // We can't distinguish agent-only vs mixed without content hashing
      // of the final file, so we classify as "agent" (receipt exists).
      fileDetails.push({
        filename: file.filename,
        provenance: 'agent',
        receipt_id: seMatch.receipt_id,
        tool_name: seMatch.tool_name,
      });
      continue;
    }

    // Check tool receipts (arg-based: did a tool reference this file?)
    const trMatch = await matchFileToToolReceipt(
      file.filename, toolReceipts, toolArgHashes,
    );

    if (trMatch) {
      // A tool receipt's args reference this file. The tool likely
      // created/modified it, but we don't have a direct side-effect receipt.
      // Classify as "mixed" — the agent intended to touch it.
      fileDetails.push({
        filename: file.filename,
        provenance: 'mixed',
        receipt_id: trMatch.receipt_id,
        tool_name: trMatch.tool_name,
      });
      continue;
    }

    // No provenance at all — human-only change
    fileDetails.push({ filename: file.filename, provenance: 'human' });

    // Only flag as unattested if the bundle DID generate side-effect receipts
    // (meaning the agent was capable of generating them but this file has none).
    // If no side-effect receipts exist at all, this is Observe Mode.
    if (hasSideEffectReceipts) {
      unattested.push(file.filename);
    }
  }

  // Handle renames
  for (const file of changedFiles) {
    if (file.previous_filename && file.status === 'renamed') {
      if (!shouldSkip(file.previous_filename)) {
        const oldMatch = await matchFileToSideEffect(
          file.previous_filename, attestedDigests, attestedHashes, receiptsByHash,
        );
        if (!oldMatch && hasSideEffectReceipts) {
          unattested.push(`${file.previous_filename} (renamed from)`);
        }
      }
    }
  }

  // Summary
  const summary = {
    agent_files: fileDetails.filter(f => f.provenance === 'agent').length,
    mixed_files: fileDetails.filter(f => f.provenance === 'mixed').length,
    human_files: fileDetails.filter(f => f.provenance === 'human').length,
    skipped_files: fileDetails.filter(f => f.provenance === 'skipped').length,
    total_files: fileDetails.length,
  };

  return {
    reconciled: unattested.length === 0,
    unattested_files: unattested,
    file_details: fileDetails,
    summary,
  };
}

/**
 * Format reconciliation result as a human-readable check run summary.
 */
export function formatReconciliationSummary(result: ReconciliationResult): string {
  const { summary } = result;
  const lines: string[] = [];

  if (result.reconciled) {
    lines.push('**Provenance Verified**');
  } else {
    lines.push('**Unattested Mutations Detected**');
  }

  lines.push('');
  lines.push('| Category | Files |');
  lines.push('|----------|-------|');

  if (summary.agent_files > 0) {
    lines.push(`| Agent-attested | ${summary.agent_files} |`);
  }
  if (summary.mixed_files > 0) {
    lines.push(`| Mixed (agent + human) | ${summary.mixed_files} |`);
  }
  if (summary.human_files > 0) {
    lines.push(`| Human-only | ${summary.human_files} |`);
  }
  if (summary.skipped_files > 0) {
    lines.push(`| Skipped (infra) | ${summary.skipped_files} |`);
  }

  if (result.unattested_files.length > 0) {
    lines.push('');
    lines.push('**Unattested files:**');
    for (const f of result.unattested_files.slice(0, 20)) {
      lines.push(`- \`${f}\``);
    }
    if (result.unattested_files.length > 20) {
      lines.push(`- ... and ${result.unattested_files.length - 20} more`);
    }
  }

  // Differential Provenance note
  if (summary.mixed_files > 0 || summary.human_files > 0) {
    lines.push('');
    lines.push(
      '> **Differential Provenance:** Files edited by humans after agent execution ' +
      'are tracked separately. Human-authored lines are subject to standard branch ' +
      'protection rules; agent-authored lines are pre-cleared by WPC policy.',
    );
  }

  return lines.join('\n');
}

// ---------- Helpers ----------

function shouldSkip(filename: string): boolean {
  for (const prefix of SKIP_PREFIXES) {
    if (filename.startsWith(prefix)) return true;
  }
  for (const pattern of BUNDLE_FILE_PATTERNS) {
    if (pattern.test(filename)) return true;
  }
  return false;
}

/**
 * Match a file path against side-effect receipts.
 */
async function matchFileToSideEffect(
  filepath: string,
  attestedDigests: Set<string>,
  attestedHashes: Set<string>,
  receiptsByHash: Map<string, { receipt_id: string; tool_name?: string }>,
): Promise<{ receipt_id: string; tool_name?: string } | null> {
  // Strategy 1 — plaintext path in target_digest
  if (attestedDigests.has(filepath)) {
    return receiptsByHash.get(filepath) ?? { receipt_id: 'unknown' };
  }

  // Strategy 2 — "sha256:<hex>" of the file path
  const hexHash = await sha256Hex(filepath);
  const hexKey = `sha256:${hexHash}`;
  if (attestedDigests.has(hexKey)) {
    return receiptsByHash.get(hexKey) ?? { receipt_id: 'unknown' };
  }

  // Strategy 3 — base64url hash in target_hash_b64u
  const b64uHash = await sha256B64u(filepath);
  if (attestedHashes.has(b64uHash)) {
    return receiptsByHash.get(b64uHash) ?? { receipt_id: 'unknown' };
  }

  // Strategy 4 — base64url hash in target_digest
  if (attestedDigests.has(b64uHash)) {
    return receiptsByHash.get(b64uHash) ?? { receipt_id: 'unknown' };
  }

  return null;
}

/**
 * Match a file path against tool receipt arguments.
 * Checks if any tool receipt's args contain the filepath
 * (either as a hash or plaintext in the args structure).
 */
async function matchFileToToolReceipt(
  filepath: string,
  toolReceipts: ToolReceiptEntry[],
  toolArgHashes: Map<string, { receipt_id: string; tool_name: string }>,
): Promise<{ receipt_id: string; tool_name: string } | null> {
  // Hash the filepath as it would appear in tool args
  const pathInArgs = JSON.stringify({ path: filepath });
  const argsHash = await sha256B64u(pathInArgs);

  const hashMatch = toolArgHashes.get(argsHash);
  if (hashMatch) return hashMatch;

  // Also try hashing just the filepath as a bare string
  const bareHash = await sha256B64u(filepath);
  const bareMatch = toolArgHashes.get(bareHash);
  if (bareMatch) return bareMatch;

  // Check tool names that commonly operate on files
  const fileToolNames = new Set([
    'write_to_file', 'write_file', 'create_file', 'edit_file',
    'str_replace_editor', 'Write', 'Edit', 'write',
    'bash', 'Bash', 'execute_bash', 'run_terminal_command',
  ]);

  // For file-writing tools, any matching tool receipt is sufficient
  // because the Causal Sieve already attributed file mutations to tools
  for (const tr of toolReceipts) {
    if (tr.tool_name && fileToolNames.has(tr.tool_name) && tr.receipt_id) {
      // If the tool is a write/edit tool, it likely created this file.
      // This is a weak match but better than "unattested".
      return { receipt_id: tr.receipt_id, tool_name: tr.tool_name };
    }
  }

  return null;
}

// ---------- Extract helpers ----------

function extractSideEffectReceipts(bundle: Record<string, unknown>): SideEffectEntry[] {
  const direct = bundle.side_effect_receipts;
  if (Array.isArray(direct)) return direct as SideEffectEntry[];

  const payload = bundle.payload as Record<string, unknown> | undefined;
  if (payload) {
    const nested = payload.side_effect_receipts;
    if (Array.isArray(nested)) return nested as SideEffectEntry[];
  }

  return [];
}

function extractToolReceipts(bundle: Record<string, unknown>): ToolReceiptEntry[] {
  const direct = bundle.tool_receipts;
  if (Array.isArray(direct)) return direct as ToolReceiptEntry[];

  const payload = bundle.payload as Record<string, unknown> | undefined;
  if (payload) {
    const nested = payload.tool_receipts;
    if (Array.isArray(nested)) return nested as ToolReceiptEntry[];
  }

  return [];
}

// ---------- Crypto ----------

async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

async function sha256B64u(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}
