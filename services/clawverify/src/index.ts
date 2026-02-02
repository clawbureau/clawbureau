/**
 * Clawverify - Universal Signature Verification API
 * Cloudflare Worker entry point
 */

import { verifyArtifact } from './verify-artifact';
import { verifyMessage } from './verify-message';
import { verifyReceipt } from './verify-receipt';
import { verifyBatch } from './verify-batch';
import {
  writeAuditLogEntry,
  getAuditLogEntry,
  verifyAuditChain,
  computeRequestHash,
  initAuditLogSchema,
  type AuditLogDB,
} from './audit-log';
import { getSchemaRegistry, getSchemaById } from './schema-docs';
import type {
  VerifyArtifactResponse,
  VerifyMessageResponse,
  VerifyReceiptResponse,
  VerifyBatchResponse,
  EnvelopeType,
  AuditLogReceipt,
} from './types';

export interface Env {
  ENVIRONMENT: string;
  AUDIT_LOG_DB: AuditLogDB;
}

/**
 * Create a JSON response with proper headers
 */
function jsonResponse(data: unknown, status: number = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'X-Clawverify-Version': '1',
    },
  });
}

/**
 * Create an error response
 */
function errorResponse(message: string, status: number = 400): Response {
  return jsonResponse({ error: message }, status);
}

/**
 * Handle POST /v1/verify - Verify artifact signatures
 */
async function handleVerifyArtifact(
  request: Request,
  env: Env
): Promise<Response> {
  // Parse request body
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON in request body', 400);
  }

  // Validate request structure
  if (typeof body !== 'object' || body === null || !('envelope' in body)) {
    return errorResponse('Request must contain an "envelope" field', 400);
  }

  const { envelope } = body as { envelope: unknown };

  // Verify the artifact
  const verification = await verifyArtifact(envelope);

  // Write audit log entry
  let auditReceipt: AuditLogReceipt | undefined;
  if (env.AUDIT_LOG_DB && verification.result.signer_did) {
    const requestHash = await computeRequestHash(body);
    auditReceipt = await writeAuditLogEntry(
      env.AUDIT_LOG_DB,
      requestHash,
      'artifact_signature' as EnvelopeType,
      verification.result.status,
      verification.result.signer_did
    );
  }

  const response: VerifyArtifactResponse & { audit_receipt?: AuditLogReceipt } =
    {
      ...verification,
      audit_receipt: auditReceipt,
    };

  // Return 200 for valid, 422 for invalid (signature verification is not a 4xx error)
  const status = verification.result.status === 'VALID' ? 200 : 422;

  return jsonResponse(response, status);
}

/**
 * Handle POST /v1/verify/message - Verify message signatures
 */
async function handleVerifyMessage(
  request: Request,
  env: Env
): Promise<Response> {
  // Parse request body
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON in request body', 400);
  }

  // Validate request structure
  if (typeof body !== 'object' || body === null || !('envelope' in body)) {
    return errorResponse('Request must contain an "envelope" field', 400);
  }

  const { envelope } = body as { envelope: unknown };

  // Verify the message signature
  const verification = await verifyMessage(envelope);

  // Write audit log entry
  let auditReceipt: AuditLogReceipt | undefined;
  if (env.AUDIT_LOG_DB && verification.signer_did) {
    const requestHash = await computeRequestHash(body);
    auditReceipt = await writeAuditLogEntry(
      env.AUDIT_LOG_DB,
      requestHash,
      'message_signature' as EnvelopeType,
      verification.result.status,
      verification.signer_did
    );
  }

  const response: VerifyMessageResponse & { audit_receipt?: AuditLogReceipt } =
    {
      ...verification,
      audit_receipt: auditReceipt,
    };

  // Return 200 for valid, 422 for invalid
  const status = verification.result.status === 'VALID' ? 200 : 422;

  return jsonResponse(response, status);
}

/**
 * Handle POST /v1/verify/receipt - Verify gateway receipt signatures
 */
async function handleVerifyReceipt(
  request: Request,
  env: Env
): Promise<Response> {
  // Parse request body
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON in request body', 400);
  }

  // Validate request structure
  if (typeof body !== 'object' || body === null || !('envelope' in body)) {
    return errorResponse('Request must contain an "envelope" field', 400);
  }

  const { envelope } = body as { envelope: unknown };

  // Verify the receipt signature
  const verification = await verifyReceipt(envelope);

  // Write audit log entry
  let auditReceipt: AuditLogReceipt | undefined;
  if (env.AUDIT_LOG_DB && verification.result.signer_did) {
    const requestHash = await computeRequestHash(body);
    auditReceipt = await writeAuditLogEntry(
      env.AUDIT_LOG_DB,
      requestHash,
      'gateway_receipt' as EnvelopeType,
      verification.result.status,
      verification.result.signer_did
    );
  }

  const response: VerifyReceiptResponse & { audit_receipt?: AuditLogReceipt } =
    {
      ...verification,
      audit_receipt: auditReceipt,
    };

  // Return 200 for valid, 422 for invalid
  const status = verification.result.status === 'VALID' ? 200 : 422;

  return jsonResponse(response, status);
}

/**
 * Handle POST /v1/verify/batch - Batch verify multiple envelopes
 */
async function handleVerifyBatch(
  request: Request,
  env: Env
): Promise<Response> {
  // Parse request body
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON in request body', 400);
  }

  // Verify the batch
  const result = await verifyBatch(body);

  // If validation error, return 400
  if ('error' in result && typeof result.error === 'string') {
    return errorResponse(result.error, 400);
  }

  const response = result as VerifyBatchResponse;

  // Write audit log entries for each item in the batch
  const auditReceipts: AuditLogReceipt[] = [];
  if (env.AUDIT_LOG_DB) {
    for (const item of response.results) {
      if (item.signer_did && item.envelope_type) {
        const requestHash = await computeRequestHash({
          id: item.id,
          envelope_type: item.envelope_type,
        });
        const receipt = await writeAuditLogEntry(
          env.AUDIT_LOG_DB,
          requestHash,
          item.envelope_type,
          item.result.status,
          item.signer_did
        );
        auditReceipts.push(receipt);
      }
    }
  }

  const responseWithAudit: VerifyBatchResponse & {
    audit_receipts?: AuditLogReceipt[];
  } = {
    ...response,
    audit_receipts: auditReceipts.length > 0 ? auditReceipts : undefined,
  };

  // Return 200 for all valid, 207 for mixed results, 422 for all invalid
  let status: number;
  if (response.invalid_count === 0) {
    status = 200; // All valid
  } else if (response.valid_count === 0) {
    status = 422; // All invalid
  } else {
    status = 207; // Multi-status (mixed results)
  }

  return jsonResponse(responseWithAudit, status);
}

/**
 * Handle GET /v1/provenance/:receipt_id - Retrieve audit log entry by receipt ID
 */
async function handleGetProvenance(
  receiptId: string,
  env: Env
): Promise<Response> {
  if (!env.AUDIT_LOG_DB) {
    return errorResponse('Audit log not configured', 503);
  }

  const provenance = await getAuditLogEntry(env.AUDIT_LOG_DB, receiptId);

  if (!provenance.found) {
    return errorResponse('Receipt not found', 404);
  }

  return jsonResponse(provenance, 200);
}

/**
 * Handle GET /v1/provenance/:receipt_id/chain - Verify audit chain integrity
 */
async function handleVerifyChain(
  receiptId: string,
  env: Env
): Promise<Response> {
  if (!env.AUDIT_LOG_DB) {
    return errorResponse('Audit log not configured', 503);
  }

  const chainResult = await verifyAuditChain(env.AUDIT_LOG_DB, receiptId);

  return jsonResponse(chainResult, chainResult.valid ? 200 : 422);
}

/**
 * Handle POST /v1/provenance/init - Initialize audit log schema
 */
async function handleInitAuditLog(env: Env): Promise<Response> {
  if (!env.AUDIT_LOG_DB) {
    return errorResponse('Audit log not configured', 503);
  }

  await initAuditLogSchema(env.AUDIT_LOG_DB);

  return jsonResponse({ status: 'initialized' }, 200);
}

/**
 * Handle GET /v1/schemas - Get schema registry
 */
function handleGetSchemas(): Response {
  const registry = getSchemaRegistry();
  return jsonResponse(registry, 200);
}

/**
 * Handle GET /v1/schemas/:schema_id - Get individual schema details
 */
function handleGetSchemaById(schemaId: string): Response {
  const result = getSchemaById(schemaId);
  if (!result.found) {
    return errorResponse(`Schema '${schemaId}' not found`, 404);
  }
  return jsonResponse(result, 200);
}

/**
 * Handle health check
 */
function handleHealth(): Response {
  return jsonResponse({
    status: 'ok',
    service: 'clawverify',
    version: '1',
  });
}

/**
 * Main fetch handler
 */
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const method = request.method;

    // Health check
    if (url.pathname === '/health' && method === 'GET') {
      return handleHealth();
    }

    // POST /v1/verify - Artifact signature verification
    if (url.pathname === '/v1/verify' && method === 'POST') {
      return handleVerifyArtifact(request, env);
    }

    // POST /v1/verify/message - Message signature verification
    if (url.pathname === '/v1/verify/message' && method === 'POST') {
      return handleVerifyMessage(request, env);
    }

    // POST /v1/verify/receipt - Gateway receipt verification
    if (url.pathname === '/v1/verify/receipt' && method === 'POST') {
      return handleVerifyReceipt(request, env);
    }

    // POST /v1/verify/batch - Batch verification
    if (url.pathname === '/v1/verify/batch' && method === 'POST') {
      return handleVerifyBatch(request, env);
    }

    // GET /v1/provenance/:receipt_id - Retrieve audit log entry
    const provenanceMatch = url.pathname.match(/^\/v1\/provenance\/([^/]+)$/);
    if (provenanceMatch && method === 'GET') {
      return handleGetProvenance(provenanceMatch[1], env);
    }

    // GET /v1/provenance/:receipt_id/chain - Verify audit chain
    const chainMatch = url.pathname.match(
      /^\/v1\/provenance\/([^/]+)\/chain$/
    );
    if (chainMatch && method === 'GET') {
      return handleVerifyChain(chainMatch[1], env);
    }

    // POST /v1/provenance/init - Initialize audit log schema
    if (url.pathname === '/v1/provenance/init' && method === 'POST') {
      return handleInitAuditLog(env);
    }

    // GET /v1/schemas - Get schema registry
    if (url.pathname === '/v1/schemas' && method === 'GET') {
      return handleGetSchemas();
    }

    // GET /v1/schemas/:schema_id - Get individual schema details
    const schemaMatch = url.pathname.match(/^\/v1\/schemas\/([^/]+)$/);
    if (schemaMatch && method === 'GET') {
      return handleGetSchemaById(schemaMatch[1]);
    }

    // 404 for unknown routes
    return errorResponse('Not found', 404);
  },
};
