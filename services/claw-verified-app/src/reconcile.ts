/**
 * Diff-to-Receipt Reconciliation.
 *
 * Compares the PR's changed files against the proof bundle's
 * side_effect_receipts to ensure every file mutation in the PR
 * is cryptographically attested. Files changed in the PR but
 * NOT in the receipt log trigger UNATTESTED_FILE_MUTATION.
 *
 * Matching strategy (the Clawsig protocol is hash-only by design):
 *  1. Direct match:   target_digest === filepath  (plaintext fallback)
 *  2. SHA-256 hex:    target_digest === "sha256:<hex(filepath)>"
 *  3. Base64url:      target_hash_b64u === base64url(sha256(filepath))
 *  4. Base64url in digest field (some emitters store b64u there)
 */

// ---------- Public types ----------

/** Result of diff-to-receipt reconciliation. */
export interface ReconciliationResult {
  reconciled: boolean;
  unattested_files: string[];
}

/** Minimal shape of a PR file entry from the GitHub API. */
export interface PRFileEntry {
  filename: string;
  previous_filename?: string;
  status: string;
}

// ---------- Internal types ----------

interface SideEffectEntry {
  effect_class?: string;
  target_digest?: string;
  target_hash_b64u?: string;
}

// ---------- Skip rules ----------

/** Path prefixes excluded from reconciliation (not agent-generated content). */
const SKIP_PREFIXES = ['.clawsig/', '.github/'];

/** Patterns identifying proof bundle files (excluded — they are proof artifacts). */
const BUNDLE_FILE_PATTERNS = [
  /proof_bundle.*\.json$/i,
  /proofs\/.*\/.*bundle.*\.json$/i,
];

// ---------- Public API ----------

/**
 * Reconcile PR changed files against proof bundle side-effect receipts.
 *
 * Every file in the PR diff (excluding skip-listed paths) must be attested
 * by a `filesystem_write` side-effect receipt in at least one of the
 * provided bundles.  Files without attestation are returned as
 * `unattested_files` and trigger a fail-closed UNATTESTED_FILE_MUTATION.
 */
export async function reconcileDiffWithBundle(
  changedFiles: PRFileEntry[],
  bundles: Array<Record<string, unknown>>,
): Promise<ReconciliationResult> {
  // 1. Collect every attested target from all bundles
  const attestedDigests = new Set<string>();
  const attestedHashes = new Set<string>();

  for (const bundle of bundles) {
    const receipts = extractSideEffectReceipts(bundle);
    for (const receipt of receipts) {
      if (receipt.effect_class !== 'filesystem_write') continue;
      if (receipt.target_digest) attestedDigests.add(receipt.target_digest);
      if (receipt.target_hash_b64u) attestedHashes.add(receipt.target_hash_b64u);
    }
  }

  // 2. Check each PR file
  const unattested: string[] = [];

  for (const file of changedFiles) {
    if (shouldSkip(file.filename)) continue;

    const matched = await isFileAttested(file.filename, attestedDigests, attestedHashes);
    if (!matched) {
      unattested.push(file.filename);
    }

    // Renames: the old path must also be attested (it was a filesystem mutation)
    if (file.previous_filename && file.status === 'renamed') {
      if (!shouldSkip(file.previous_filename)) {
        const oldMatched = await isFileAttested(
          file.previous_filename,
          attestedDigests,
          attestedHashes,
        );
        if (!oldMatched) {
          unattested.push(`${file.previous_filename} (renamed from)`);
        }
      }
    }
  }

  return {
    reconciled: unattested.length === 0,
    unattested_files: unattested,
  };
}

// ---------- Helpers ----------

/** Determine whether a file path should be skipped during reconciliation. */
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
 * Check if a file path is attested by any receipt target.
 * Tries direct-path, SHA-256 hex-prefixed, and base64url representations.
 */
async function isFileAttested(
  filepath: string,
  attestedDigests: Set<string>,
  attestedHashes: Set<string>,
): Promise<boolean> {
  // Strategy 1 — plaintext path in target_digest
  if (attestedDigests.has(filepath)) return true;

  // Strategy 2 — "sha256:<hex>" of the file path
  const hexHash = await sha256Hex(filepath);
  if (attestedDigests.has(`sha256:${hexHash}`)) return true;

  // Strategy 3 — base64url hash in target_hash_b64u
  const b64uHash = await sha256B64u(filepath);
  if (attestedHashes.has(b64uHash)) return true;

  // Strategy 4 — base64url hash stored in target_digest
  if (attestedDigests.has(b64uHash)) return true;

  return false;
}

/**
 * Extract side-effect receipt entries from a bundle.
 * Handles both top-level and signed-envelope-wrapped payloads.
 */
function extractSideEffectReceipts(bundle: Record<string, unknown>): SideEffectEntry[] {
  // Top-level field
  const direct = bundle.side_effect_receipts;
  if (Array.isArray(direct)) return direct as SideEffectEntry[];

  // Nested inside signed envelope payload
  const payload = bundle.payload as Record<string, unknown> | undefined;
  if (payload) {
    const nested = payload.side_effect_receipts;
    if (Array.isArray(nested)) return nested as SideEffectEntry[];
  }

  return [];
}

// ---------- Crypto ----------

/** SHA-256 hex digest of a UTF-8 string. */
async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/** SHA-256 base64url digest (no padding) of a UTF-8 string. */
async function sha256B64u(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}
