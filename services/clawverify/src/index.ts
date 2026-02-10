/**
 * Clawverify - Universal Signature Verification API
 * Cloudflare Worker entry point
 */

import { verifyArtifact } from './verify-artifact';
import { verifyMessage } from './verify-message';
import { verifyReceipt } from './verify-receipt';
import { verifyBatch } from './verify-batch';
import { verifyProofBundle } from './verify-proof-bundle';
import { verifyEventChain } from './verify-event-chain';
import { verifyOwnerAttestation } from './verify-owner-attestation';
import { verifyDidRotation } from './verify-did-rotation';
import { verifyCommitProof } from './verify-commit-proof';
import { verifyAgent } from './verify-agent';
import { verifyScopedToken } from './verify-scoped-token';
import {
  writeAuditLogEntry,
  getAuditLogEntry,
  verifyAuditChain,
  computeRequestHash,
  initAuditLogSchema,
  type AuditLogDB,
} from './audit-log';
import { getSchemaRegistry, getSchemaById, getSchemaAllowlist, getSchemaExample } from './schema-docs';
import { validateSchemaAllowlist, getAllowlistedSchemaIds } from './schema-registry';
import type {
  VerifyArtifactResponse,
  VerifyMessageResponse,
  VerifyReceiptResponse,
  VerifyBatchResponse,
  VerifyBundleResponse,
  VerifyEventChainResponse,
  VerifyOwnerAttestationResponse,
  VerifyDidRotationResponse,
  VerifyCommitProofResponse,
  VerifyAgentResponse,
  IntrospectScopedTokenResponse,
  EnvelopeType,
  AuditLogReceipt,
} from './types';

export interface Env {
  ENVIRONMENT: string;
  AUDIT_LOG_DB: AuditLogDB;

  /**
   * Comma-separated list of trusted gateway receipt signer DIDs (did:key:...).
   * Used for fail-closed receipt verification (POH gateway tier).
   */
  GATEWAY_RECEIPT_SIGNER_DIDS?: string;

  /**
   * Comma-separated list of repo claim IDs that exist in clawclaim.
   * Used for CVF-US-011 commit proof verification.
   */
  CLAWCLAIM_REPO_CLAIM_ALLOWLIST?: string;

  /**
   * Comma-separated list of trusted attester DIDs (did:key:...) that are
   * allowed to sign proof bundle attestations.
   *
   * CVF-US-023: Attestations do not uplift trust tiers unless the attester is
   * allowlisted and the signature verifies.
   */
  ATTESTATION_SIGNER_DIDS?: string;
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

function escapeHtml(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function escapeXml(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function textResponse(
  body: string,
  contentType: string,
  status = 200
): Response {
  return new Response(body, {
    status,
    headers: {
      'Content-Type': contentType,
      'X-Clawverify-Version': '1',
    },
  });
}

function htmlResponse(html: string, status = 200): Response {
  return textResponse(html, 'text/html; charset=utf-8', status);
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

  const gatewaySignerAllowlist = parseCommaSeparatedAllowlist(
    env.GATEWAY_RECEIPT_SIGNER_DIDS
  );

  // Verify the receipt signature
  const verification = await verifyReceipt(envelope, {
    allowlistedSignerDids: gatewaySignerAllowlist,
  });

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
 * Handle POST /v1/verify/owner-attestation - Verify owner attestation envelopes
 */
async function handleVerifyOwnerAttestation(
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

  // Verify the owner attestation
  const verification = await verifyOwnerAttestation(envelope);

  // Write audit log entry
  let auditReceipt: AuditLogReceipt | undefined;
  if (env.AUDIT_LOG_DB && verification.result.signer_did) {
    const requestHash = await computeRequestHash(body);
    auditReceipt = await writeAuditLogEntry(
      env.AUDIT_LOG_DB,
      requestHash,
      'owner_attestation' as EnvelopeType,
      verification.result.status,
      verification.result.signer_did
    );
  }

  const response: VerifyOwnerAttestationResponse & {
    audit_receipt?: AuditLogReceipt;
  } = {
    ...verification,
    audit_receipt: auditReceipt,
  };

  // Return 200 for valid, 422 for invalid
  const status = verification.result.status === 'VALID' ? 200 : 422;

  return jsonResponse(response, status);
}

/**
 * Handle POST /v1/verify/did-rotation - Verify DID rotation certificates
 */
async function handleVerifyDidRotation(
  request: Request,
  _env: Env
): Promise<Response> {
  // Parse request body
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON in request body', 400);
  }

  // Validate request structure
  if (typeof body !== 'object' || body === null || !('certificate' in body)) {
    return errorResponse('Request must contain a "certificate" field', 400);
  }

  const { certificate } = body as { certificate: unknown };

  const verification = await verifyDidRotation(certificate);

  const response: VerifyDidRotationResponse = {
    ...verification,
  };

  const status = verification.result.status === 'VALID' ? 200 : 422;
  return jsonResponse(response, status);
}

function parseCommaSeparatedAllowlist(value: string | undefined): string[] {
  if (!value) return [];
  return value
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

/**
 * Handle POST /v1/introspect/scoped-token - Scoped token introspection
 */
async function handleIntrospectScopedToken(
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

  const verification = await verifyScopedToken(envelope);

  // Token hash logging (clawlogs-style structured log)
  if (verification.token_hash_b64u) {
    console.log(
      '[TOKEN_HASH]',
      JSON.stringify({
        event: 'SCOPED_TOKEN_INTROSPECTED',
        token_hash_b64u: verification.token_hash_b64u,
        status: verification.result.status,
        signer_did: verification.result.signer_did,
        audience: verification.audience,
        scope: verification.scope,
        owner_ref: verification.owner_ref,
        verified_at: verification.result.verified_at,
      })
    );
  }

  // Write audit log entry (best-effort). For tokens, we anchor the audit request hash
  // to the token hash for easy correlation.
  let auditReceipt: AuditLogReceipt | undefined;
  if (env.AUDIT_LOG_DB && verification.result.signer_did) {
    const requestHash =
      verification.token_hash_b64u ?? (await computeRequestHash(body));

    auditReceipt = await writeAuditLogEntry(
      env.AUDIT_LOG_DB,
      requestHash,
      'scoped_token' as EnvelopeType,
      verification.result.status,
      verification.result.signer_did
    );
  }

  const response: IntrospectScopedTokenResponse & { audit_receipt?: AuditLogReceipt } = {
    ...verification,
    audit_receipt: auditReceipt,
  };

  const status = verification.result.status === 'VALID' ? 200 : 422;
  return jsonResponse(response, status);
}

/**
 * Handle POST /v1/verify/agent - One-call agent verification
 */
async function handleVerifyAgent(request: Request, env: Env): Promise<Response> {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON in request body', 400);
  }

  if (typeof body !== 'object' || body === null) {
    return errorResponse('Request must be an object', 400);
  }

  const gatewaySignerAllowlist = parseCommaSeparatedAllowlist(
    env.GATEWAY_RECEIPT_SIGNER_DIDS
  );

  const attesterAllowlist = parseCommaSeparatedAllowlist(
    env.ATTESTATION_SIGNER_DIDS
  );

  const verification = await verifyAgent(body, {
    allowlistedReceiptSignerDids: gatewaySignerAllowlist,
    allowlistedAttesterDids: attesterAllowlist,
  });
  const status = verification.result.status === 'VALID' ? 200 : 422;
  return jsonResponse(verification as VerifyAgentResponse, status);
}

/**
 * Handle POST /v1/verify/commit-proof - Verify commit proof envelopes
 */
async function handleVerifyCommitProof(
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

  const repoClaimAllowlist = parseCommaSeparatedAllowlist(
    env.CLAWCLAIM_REPO_CLAIM_ALLOWLIST
  );

  // Verify the commit proof
  const verification = await verifyCommitProof(envelope, {
    allowlistedRepoClaimIds: repoClaimAllowlist,
  });

  // Write audit log entry
  let auditReceipt: AuditLogReceipt | undefined;
  if (env.AUDIT_LOG_DB && verification.result.signer_did) {
    const requestHash = await computeRequestHash(body);
    auditReceipt = await writeAuditLogEntry(
      env.AUDIT_LOG_DB,
      requestHash,
      'commit_proof' as EnvelopeType,
      verification.result.status,
      verification.result.signer_did
    );
  }

  const response: VerifyCommitProofResponse & { audit_receipt?: AuditLogReceipt } = {
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

  const gatewaySignerAllowlist = parseCommaSeparatedAllowlist(
    env.GATEWAY_RECEIPT_SIGNER_DIDS
  );

  // Verify the batch
  const result = await verifyBatch(body, {
    allowlistedReceiptSignerDids: gatewaySignerAllowlist,
  });

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
 * Handle POST /v1/verify/bundle - Verify proof bundle envelopes
 */
async function handleVerifyBundle(
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

  const { envelope, urm } = body as { envelope: unknown; urm?: unknown };

  // Verify the proof bundle
  const gatewaySignerAllowlist = parseCommaSeparatedAllowlist(
    env.GATEWAY_RECEIPT_SIGNER_DIDS
  );

  const attesterAllowlist = parseCommaSeparatedAllowlist(
    env.ATTESTATION_SIGNER_DIDS
  );

  const verification = await verifyProofBundle(envelope, {
    allowlistedReceiptSignerDids: gatewaySignerAllowlist,
    allowlistedAttesterDids: attesterAllowlist,
    urm,
  });

  // Write audit log entry
  let auditReceipt: AuditLogReceipt | undefined;
  if (env.AUDIT_LOG_DB && verification.result.agent_did) {
    const requestHash = await computeRequestHash(body);
    auditReceipt = await writeAuditLogEntry(
      env.AUDIT_LOG_DB,
      requestHash,
      'proof_bundle' as EnvelopeType,
      verification.result.status,
      verification.result.agent_did
    );
  }

  const response: VerifyBundleResponse & { audit_receipt?: AuditLogReceipt } = {
    ...verification,
    trust_tier: verification.result.trust_tier,
    proof_tier: verification.result.proof_tier,
    model_identity_tier: verification.result.model_identity_tier,
    risk_flags: verification.result.risk_flags,
    audit_receipt: auditReceipt,
  };

  // Return 200 for valid, 422 for invalid
  const status = verification.result.status === 'VALID' ? 200 : 422;

  return jsonResponse(response, status);
}

/**
 * Handle POST /v1/verify/event-chain - Verify event chain envelopes
 */
async function handleVerifyEventChain(
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

  // Verify the event chain
  const verification = await verifyEventChain(envelope);

  // Write audit log entry
  let auditReceipt: AuditLogReceipt | undefined;
  if (env.AUDIT_LOG_DB && verification.result.signer_did) {
    const requestHash = await computeRequestHash(body);
    auditReceipt = await writeAuditLogEntry(
      env.AUDIT_LOG_DB,
      requestHash,
      'event_chain' as EnvelopeType,
      verification.result.status,
      verification.result.signer_did
    );
  }

  const response: VerifyEventChainResponse & { audit_receipt?: AuditLogReceipt } = {
    ...verification,
    chain_root_hash: verification.result.chain_root_hash,
    run_id: verification.result.run_id,
    audit_receipt: auditReceipt,
  };

  // Return 200 for valid, 422 for invalid
  const status = verification.result.status === 'VALID' ? 200 : 422;

  return jsonResponse(response, status);
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

  try {
    await initAuditLogSchema(env.AUDIT_LOG_DB);
    return jsonResponse({ status: 'initialized' }, 200);
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    // Avoid crashing the worker (1101) when D1 isn't ready / schema SQL fails.
    // We still want the caller to get a debuggable error.
    console.error('audit_log_init_failed', message);
    return jsonResponse({ error: 'audit_log_init_failed', message }, 500);
  }
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
 * Handle GET /v1/schemas/allowlist - Get schema allowlist with examples
 * CVF-US-009: Schema registry allowlist for deterministic validation
 */
function handleGetSchemaAllowlist(): Response {
  const allowlist = getSchemaAllowlist();
  return jsonResponse(allowlist, 200);
}

/**
 * Handle GET /v1/schemas/:schema_id/example - Get example payload for a schema
 */
function handleGetSchemaExample(schemaId: string): Response {
  // Validate schema ID against allowlist (fail-closed)
  const validation = validateSchemaAllowlist(schemaId);
  if (!validation.valid) {
    return jsonResponse({
      error: validation.error_message,
      code: validation.error_code,
      allowlisted_schemas: getAllowlistedSchemaIds(),
    }, 404);
  }

  const example = getSchemaExample(schemaId);
  if (!example) {
    return errorResponse(`No example available for schema '${schemaId}'`, 404);
  }

  return jsonResponse({
    schema_id: schemaId,
    version: validation.version,
    example: example,
    deprecated: validation.error_code === 'DEPRECATED_SCHEMA',
    deprecation_warning: validation.error_code === 'DEPRECATED_SCHEMA' ? validation.error_message : undefined,
  }, 200);
}

/**
 * Handle POST /v1/schemas/validate - Validate a schema ID against the allowlist
 * CVF-US-009: Reject unknown IDs by default
 */
async function handleValidateSchema(request: Request): Promise<Response> {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON in request body', 400);
  }

  if (typeof body !== 'object' || body === null) {
    return errorResponse('Request must be an object', 400);
  }

  const { schema_id, version } = body as { schema_id?: unknown; version?: unknown };

  if (typeof schema_id !== 'string') {
    return errorResponse('schema_id is required and must be a string', 400);
  }

  const validation = validateSchemaAllowlist(
    schema_id,
    typeof version === 'string' ? version : undefined
  );

  if (!validation.valid) {
    return jsonResponse({
      valid: false,
      schema_id: schema_id,
      version: version,
      error: validation.error_message,
      code: validation.error_code,
      allowlisted_schemas: getAllowlistedSchemaIds(),
    }, 422);
  }

  return jsonResponse({
    valid: true,
    schema_id: validation.schema_id,
    version: validation.version,
    deprecated: validation.error_code === 'DEPRECATED_SCHEMA',
    deprecation_warning: validation.error_code === 'DEPRECATED_SCHEMA' ? validation.error_message : undefined,
  }, 200);
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

    // CVF-US-014: Public landing + skill docs
    if (method === 'GET') {
      if (url.pathname === '/') {
        return htmlResponse(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>clawverify</title>
  </head>
  <body>
    <main style="max-width: 820px; margin: 2rem auto; font-family: ui-sans-serif, system-ui; line-height: 1.5;">
      <h1>clawverify</h1>
      <p>Universal signature verification API for artifacts, messages, receipts, and attestations.</p>
      <ul>
        <li><a href="/docs">Docs</a></li>
        <li><a href="/skill.md">OpenClaw skill</a></li>
        <li><a href="/v1/schemas">Schema registry</a></li>
        <li><a href="/v1/schemas/allowlist">Schema allowlist</a></li>
      </ul>
      <p><small>Environment: ${escapeHtml(env.ENVIRONMENT)}</small></p>
    </main>
  </body>
</html>`);
      }

      if (url.pathname === '/docs') {
        const origin = url.origin;
        return htmlResponse(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>clawverify docs</title>
  </head>
  <body>
    <main style="max-width: 820px; margin: 2rem auto; font-family: ui-sans-serif, system-ui; line-height: 1.5;">
      <h1>clawverify docs</h1>
      <p>Minimal HTTP API documentation.</p>

      <h2>Core endpoints</h2>
      <ul>
        <li><code>POST /v1/verify</code> — artifact_signature verification</li>
        <li><code>POST /v1/verify/message</code> — message_signature verification</li>
        <li><code>POST /v1/verify/receipt</code> — gateway_receipt verification</li>
        <li><code>POST /v1/verify/owner-attestation</code> — owner_attestation verification</li>
        <li><code>POST /v1/verify/did-rotation</code> — did_rotation certificate verification</li>
        <li><code>POST /v1/verify/commit-proof</code> — commit_proof verification</li>
        <li><code>POST /v1/verify/batch</code> — batch verification</li>
        <li><code>POST /v1/verify/bundle</code> — proof bundle verification (trust tier)</li>
        <li><code>POST /v1/verify/event-chain</code> — event chain verification</li>
        <li><code>POST /v1/verify/agent</code> — one-call agent verification</li>
        <li><code>POST /v1/introspect/scoped-token</code> — scoped token introspection</li>
      </ul>

      <h2>Schema registry</h2>
      <ul>
        <li><code>GET /v1/schemas</code></li>
        <li><code>GET /v1/schemas/allowlist</code></li>
        <li><code>GET /v1/schemas/:id</code></li>
        <li><code>GET /v1/schemas/:id/example</code></li>
      </ul>

      <h2>Quick start</h2>
      <pre>curl -sS -X POST "${escapeHtml(origin)}/v1/verify/message" \
  -H "Content-Type: application/json" \
  -d '{"envelope":{}}'</pre>

      <p>See also: <a href="/skill.md">/skill.md</a></p>
    </main>
  </body>
</html>`);
      }

      if (url.pathname === '/skill.md') {
        const metadata = {
          name: 'clawverify',
          version: '1',
          description:
            'Universal signature verification API for artifacts, messages, receipts, and attestations.',
          endpoints: [
            { method: 'POST', path: '/v1/verify' },
            { method: 'POST', path: '/v1/verify/message' },
            { method: 'POST', path: '/v1/verify/receipt' },
            { method: 'POST', path: '/v1/verify/owner-attestation' },
            { method: 'POST', path: '/v1/verify/did-rotation' },
            { method: 'POST', path: '/v1/verify/commit-proof' },
            { method: 'POST', path: '/v1/verify/batch' },
            { method: 'POST', path: '/v1/verify/bundle' },
            { method: 'POST', path: '/v1/verify/event-chain' },
            { method: 'POST', path: '/v1/verify/agent' },
            { method: 'POST', path: '/v1/introspect/scoped-token' },
            { method: 'GET', path: '/v1/schemas' },
            { method: 'GET', path: '/v1/schemas/allowlist' },
          ],
        };

        const md = `---
metadata: '${JSON.stringify(metadata)}'
---

# clawverify

Verification API for signed envelopes.

## Example: verify a message envelope

\`POST /v1/verify/message\`

\`\`\`bash
curl -sS -X POST "${url.origin}/v1/verify/message" \\
  -H "Content-Type: application/json" \\
  -d '{"envelope":{}}'
\`\`\`

## Schema registry

Use the schema registry to discover allowlisted schema IDs and example payloads:

- GET /v1/schemas
- GET /v1/schemas/allowlist
- GET /v1/schemas/:id/example
`;

        return textResponse(md, 'text/markdown; charset=utf-8', 200);
      }

      if (url.pathname === '/robots.txt') {
        const txt = `User-agent: *
Allow: /
Sitemap: ${url.origin}/sitemap.xml
`;
        return textResponse(txt, 'text/plain; charset=utf-8', 200);
      }

      if (url.pathname === '/sitemap.xml') {
        const base = url.origin;
        const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>${escapeXml(base)}/</loc></url>
  <url><loc>${escapeXml(base)}/docs</loc></url>
  <url><loc>${escapeXml(base)}/skill.md</loc></url>
</urlset>
`;
        return textResponse(xml, 'application/xml; charset=utf-8', 200);
      }

      if (url.pathname === '/.well-known/security.txt') {
        const expires = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();
        const txt = `Contact: mailto:security@clawverify.com
Preferred-Languages: en
Expires: ${expires}
Canonical: ${url.origin}/.well-known/security.txt
`;
        return textResponse(txt, 'text/plain; charset=utf-8', 200);
      }
    }

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

    // POST /v1/verify/owner-attestation - Owner attestation verification
    if (url.pathname === '/v1/verify/owner-attestation' && method === 'POST') {
      return handleVerifyOwnerAttestation(request, env);
    }

    // POST /v1/verify/did-rotation - DID rotation certificate verification
    if (url.pathname === '/v1/verify/did-rotation' && method === 'POST') {
      return handleVerifyDidRotation(request, env);
    }

    // POST /v1/introspect/scoped-token - Scoped token introspection
    if (url.pathname === '/v1/introspect/scoped-token' && method === 'POST') {
      return handleIntrospectScopedToken(request, env);
    }

    // POST /v1/verify/agent - One-call agent verification
    if (url.pathname === '/v1/verify/agent' && method === 'POST') {
      return handleVerifyAgent(request, env);
    }

    // POST /v1/verify/commit-proof - Commit proof verification
    if (url.pathname === '/v1/verify/commit-proof' && method === 'POST') {
      return handleVerifyCommitProof(request, env);
    }

    // POST /v1/verify/batch - Batch verification
    if (url.pathname === '/v1/verify/batch' && method === 'POST') {
      return handleVerifyBatch(request, env);
    }

    // POST /v1/verify/bundle - Proof bundle verification
    if (url.pathname === '/v1/verify/bundle' && method === 'POST') {
      return handleVerifyBundle(request, env);
    }

    // POST /v1/verify/event-chain - Event chain verification
    if (url.pathname === '/v1/verify/event-chain' && method === 'POST') {
      return handleVerifyEventChain(request, env);
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

    // GET /v1/schemas/allowlist - Get schema allowlist with examples
    if (url.pathname === '/v1/schemas/allowlist' && method === 'GET') {
      return handleGetSchemaAllowlist();
    }

    // POST /v1/schemas/validate - Validate schema ID against allowlist
    if (url.pathname === '/v1/schemas/validate' && method === 'POST') {
      return handleValidateSchema(request);
    }

    // GET /v1/schemas/:schema_id/example - Get example payload for a schema
    const schemaExampleMatch = url.pathname.match(/^\/v1\/schemas\/([^/]+)\/example$/);
    if (schemaExampleMatch && method === 'GET') {
      return handleGetSchemaExample(schemaExampleMatch[1]);
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
