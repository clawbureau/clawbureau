/**
 * Audit log for verification provenance
 * CVF-US-005: Hash-chained audit log for compliance traceability
 */

import { base64UrlEncode } from './crypto';
import type {
  AuditLogEntry,
  AuditLogReceipt,
  ProvenanceResponse,
  EnvelopeType,
  VerificationStatus,
} from './types';

/**
 * D1 database interface for audit log
 */
export interface AuditLogDB {
  prepare(query: string): D1PreparedStatement;
  exec(query: string): Promise<D1ExecResult>;
}

interface D1PreparedStatement {
  bind(...values: unknown[]): D1PreparedStatement;
  first<T = unknown>(): Promise<T | null>;
  run(): Promise<D1Result>;
  all<T = unknown>(): Promise<D1Result<T>>;
}

interface D1Result<T = unknown> {
  results: T[];
  success: boolean;
  meta: unknown;
}

interface D1ExecResult {
  count: number;
  duration: number;
}

/**
 * SQL schema for the audit log table
 * Should be run once during database setup
 */
export const AUDIT_LOG_SCHEMA = `
CREATE TABLE IF NOT EXISTS audit_log (
  receipt_id TEXT PRIMARY KEY,
  request_hash_b64u TEXT NOT NULL,
  envelope_type TEXT NOT NULL,
  status TEXT NOT NULL,
  signer_did TEXT NOT NULL,
  verified_at TEXT NOT NULL,
  prev_hash_b64u TEXT,
  entry_hash_b64u TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_log_verified_at ON audit_log(verified_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_signer_did ON audit_log(signer_did);
CREATE INDEX IF NOT EXISTS idx_audit_log_entry_hash ON audit_log(entry_hash_b64u);
`;

/**
 * Generate a unique receipt ID for audit entries
 */
export function generateReceiptId(): string {
  const timestamp = Date.now().toString(36);
  const random = crypto.randomUUID().split('-').slice(0, 2).join('');
  return `avr_${timestamp}_${random}`;
}

/**
 * Compute hash for an audit log entry
 * Includes all entry fields + previous hash for chaining
 */
export async function computeEntryHash(
  requestHash: string,
  envelopeType: EnvelopeType,
  status: VerificationStatus,
  signerDid: string,
  verifiedAt: string,
  prevHash: string | null
): Promise<string> {
  const data = JSON.stringify({
    request_hash_b64u: requestHash,
    envelope_type: envelopeType,
    status,
    signer_did: signerDid,
    verified_at: verifiedAt,
    prev_hash_b64u: prevHash,
  });

  const encoder = new TextEncoder();
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(data));
  return base64UrlEncode(new Uint8Array(hashBuffer));
}

/**
 * Compute hash of a verification request for audit purposes
 */
export async function computeRequestHash(request: unknown): Promise<string> {
  const data = JSON.stringify(request);
  const encoder = new TextEncoder();
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(data));
  return base64UrlEncode(new Uint8Array(hashBuffer));
}

/**
 * Get the most recent entry hash for chaining
 */
async function getLatestEntryHash(db: AuditLogDB): Promise<string | null> {
  const result = await db
    .prepare(
      'SELECT entry_hash_b64u FROM audit_log ORDER BY created_at DESC LIMIT 1'
    )
    .first<{ entry_hash_b64u: string }>();

  return result?.entry_hash_b64u ?? null;
}

/**
 * Write an audit log entry with hash chaining
 */
export async function writeAuditLogEntry(
  db: AuditLogDB,
  requestHash: string,
  envelopeType: EnvelopeType,
  status: VerificationStatus,
  signerDid: string
): Promise<AuditLogReceipt> {
  const receiptId = generateReceiptId();
  const verifiedAt = new Date().toISOString();

  // Get the previous entry hash for chaining
  const prevHash = await getLatestEntryHash(db);

  // Compute this entry's hash
  const entryHash = await computeEntryHash(
    requestHash,
    envelopeType,
    status,
    signerDid,
    verifiedAt,
    prevHash
  );

  // Insert the entry
  await db
    .prepare(
      `INSERT INTO audit_log
       (receipt_id, request_hash_b64u, envelope_type, status, signer_did, verified_at, prev_hash_b64u, entry_hash_b64u)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      receiptId,
      requestHash,
      envelopeType,
      status,
      signerDid,
      verifiedAt,
      prevHash,
      entryHash
    )
    .run();

  return {
    receipt_id: receiptId,
    entry_hash_b64u: entryHash,
    prev_hash_b64u: prevHash,
    verified_at: verifiedAt,
  };
}

/**
 * Retrieve an audit log entry by receipt ID
 */
export async function getAuditLogEntry(
  db: AuditLogDB,
  receiptId: string
): Promise<ProvenanceResponse> {
  const entry = await db
    .prepare(
      `SELECT receipt_id, request_hash_b64u, envelope_type, status, signer_did,
              verified_at, prev_hash_b64u, entry_hash_b64u
       FROM audit_log WHERE receipt_id = ?`
    )
    .bind(receiptId)
    .first<AuditLogEntry>();

  if (!entry) {
    return { found: false };
  }

  // Verify the entry hash is correct
  const expectedHash = await computeEntryHash(
    entry.request_hash_b64u,
    entry.envelope_type,
    entry.status,
    entry.signer_did,
    entry.verified_at,
    entry.prev_hash_b64u
  );

  const chainValid = expectedHash === entry.entry_hash_b64u;

  return {
    found: true,
    entry,
    chain_valid: chainValid,
  };
}

/**
 * Verify the entire audit chain from a given entry back to the root
 */
export async function verifyAuditChain(
  db: AuditLogDB,
  receiptId: string
): Promise<{ valid: boolean; entries_checked: number; error?: string }> {
  let entriesChecked = 0;
  let currentReceiptId: string | null = receiptId;

  // Walk back through the chain
  while (currentReceiptId) {
    const result = await getAuditLogEntry(db, currentReceiptId);

    if (!result.found || !result.entry) {
      return {
        valid: false,
        entries_checked: entriesChecked,
        error: `Entry not found: ${currentReceiptId}`,
      };
    }

    if (!result.chain_valid) {
      return {
        valid: false,
        entries_checked: entriesChecked,
        error: `Hash mismatch at entry: ${currentReceiptId}`,
      };
    }

    entriesChecked++;

    // If no previous hash, we've reached the root
    if (!result.entry.prev_hash_b64u) {
      break;
    }

    // Find the entry with this hash
    const prevEntry = await db
      .prepare('SELECT receipt_id FROM audit_log WHERE entry_hash_b64u = ?')
      .bind(result.entry.prev_hash_b64u)
      .first<{ receipt_id: string }>();

    currentReceiptId = prevEntry?.receipt_id ?? null;

    if (!currentReceiptId) {
      return {
        valid: false,
        entries_checked: entriesChecked,
        error: `Previous entry not found for hash: ${result.entry.prev_hash_b64u}`,
      };
    }
  }

  return { valid: true, entries_checked: entriesChecked };
}

/**
 * Initialize the audit log database schema
 * Call this during worker startup or as a separate setup step
 */
export async function initAuditLogSchema(db: AuditLogDB): Promise<void> {
  // D1 exec() may reject multi-statement SQL strings.
  // Split on ';' and run statements one-by-one.
  const statements = AUDIT_LOG_SCHEMA
    .split(';')
    .map((s) => s.trim())
    .filter(Boolean);

  for (const stmt of statements) {
    await db.exec(stmt);
  }
}
