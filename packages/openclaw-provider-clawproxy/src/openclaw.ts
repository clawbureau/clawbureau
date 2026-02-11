/**
 * OpenClaw plugin: provider-clawproxy
 *
 * Goal:
 * - Without modifying OpenClaw core, route supported provider HTTP calls
 *   through clawproxy (POST /v1/proxy/:provider)
 * - Inject PoH binding headers per call (X-Run-Id, X-Event-Hash, X-Idempotency-Key)
 * - Capture canonical gateway receipts (_receipt_envelope or SSE trailer)
 * - Emit signed proof bundle + URM + Trust Pulse (+ prompt commitments when available)
 *
 * This plugin patches global fetch() and uses AsyncLocalStorage to associate
 * outbound LLM calls with the active OpenClaw agent run.
 */

import { mkdir, readFile, writeFile, chmod } from 'node:fs/promises';
import path from 'node:path';
import { AsyncLocalStorage } from 'node:async_hooks';

import {
  base64UrlDecode,
  didFromPublicKey,
  generateKeyPair,
  hashJsonB64u,
  sha256B64u,
} from './crypto.js';

import { createRecorder, type HarnessRecorder } from './recorder.js';

import type {
  ClawproxyReceipt,
  Ed25519KeyPair,
  HarnessConfig,
  PromptPackEntry,
  ReceiptArtifact,
  SignedEnvelope,
  GatewayReceiptPayload,
} from './types.js';

// ---------------------------------------------------------------------------
// Plugin config + defaults
// ---------------------------------------------------------------------------

type PluginMode = 'enforce' | 'best_effort';

type AirlockConfig = {
  enabled?: boolean;
  identityRoots?: string[];
  jobRoots?: string[];
  /**
   * Fail-closed if bootstrap files are discovered outside identityRoots
   * (including files under jobRoots).
   */
  requireTrustedBootstrap?: boolean;
};

type PluginConfig = {
  baseUrl: string;
  token?: string;

  /** Optional pinned WPC hash (policy_hash_b64u). */
  policyHashB64u?: string;

  /** If true, send X-Confidential-Mode: true on all proxied calls. */
  confidentialMode?: boolean;

  /** Optional receipt privacy mode override (X-Receipt-Privacy-Mode). */
  receiptPrivacyMode?: 'hash_only' | 'encrypted';

  outputDir?: string;
  keyFile?: string;
  mode?: PluginMode;
  intercept?: {
    openai?: boolean;
    anthropic?: boolean;
    google?: boolean;
  };
  includePromptPack?: boolean;
  includeToolEvents?: boolean;
  airlock?: AirlockConfig;
};

function asObject(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function asBoolean(value: unknown): boolean | undefined {
  return typeof value === 'boolean' ? value : undefined;
}

function asString(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim().length > 0 ? value.trim() : undefined;
}

function asStringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined;

  const out = value
    .map((v) => asString(v))
    .filter((v): v is string => typeof v === 'string');

  return out.length > 0 ? out : undefined;
}

function parsePluginConfig(raw: unknown): PluginConfig | null {
  const obj = asObject(raw);
  if (!obj) return null;

  const baseUrl = asString(obj.baseUrl);
  if (!baseUrl) return null;

  const interceptObj = asObject(obj.intercept);

  const mode = asString(obj.mode);
  const parsedMode: PluginMode | undefined = mode === 'enforce' || mode === 'best_effort' ? mode : undefined;

  const receiptPrivacyModeRaw = asString(obj.receiptPrivacyMode);
  const receiptPrivacyMode: PluginConfig['receiptPrivacyMode'] =
    receiptPrivacyModeRaw === 'hash_only' || receiptPrivacyModeRaw === 'encrypted'
      ? receiptPrivacyModeRaw
      : undefined;

  const airlockObj = asObject(obj.airlock);

  return {
    baseUrl,
    token: asString(obj.token),
    policyHashB64u: asString(obj.policyHashB64u),
    confidentialMode: asBoolean(obj.confidentialMode),
    receiptPrivacyMode,
    outputDir: asString(obj.outputDir),
    keyFile: asString(obj.keyFile),
    mode: parsedMode,
    intercept: interceptObj
      ? {
          openai: asBoolean(interceptObj.openai),
          anthropic: asBoolean(interceptObj.anthropic),
          google: asBoolean(interceptObj.google),
        }
      : undefined,
    includePromptPack: asBoolean(obj.includePromptPack),
    includeToolEvents: asBoolean(obj.includeToolEvents),
    airlock: airlockObj
      ? {
          enabled: asBoolean(airlockObj.enabled),
          identityRoots: asStringArray(airlockObj.identityRoots),
          jobRoots: asStringArray(airlockObj.jobRoots),
          requireTrustedBootstrap: asBoolean(airlockObj.requireTrustedBootstrap),
        }
      : undefined,
  };
}

function normalizeBaseUrl(value: string): string {
  return value.trim().replace(/\/+$/, '');
}

export type AirlockBootstrapFileInput = {
  name: string | undefined;
  path: string | undefined;
  content: string | undefined;
  missing: boolean | undefined;
};

export type AirlockPathClassification = 'trusted' | 'untrusted' | 'unknown';

export type AirlockPartitionResult = {
  trustedFiles: AirlockBootstrapFileInput[];
  untrustedFiles: AirlockBootstrapFileInput[];
  unknownFiles: AirlockBootstrapFileInput[];
};

function normalizePathForAirlock(value: string): string {
  // Normalize separators + collapse relative segments.
  const withForwardSlashes = value.replace(/\\/g, '/');
  const normalized = path.posix.normalize(withForwardSlashes);

  // Keep roots canonical without trailing slash (except '/').
  if (normalized === '/') return normalized;
  return normalized.replace(/\/+$/, '');
}

function pathWithinRoot(targetPath: string, rootPath: string): boolean {
  if (rootPath === '/') return true;
  return targetPath === rootPath || targetPath.startsWith(`${rootPath}/`);
}

export function classifyAirlockPath(
  filePath: string | undefined,
  identityRoots: readonly string[],
  jobRoots: readonly string[],
): AirlockPathClassification {
  if (!filePath) return 'unknown';

  const normalizedFilePath = normalizePathForAirlock(filePath);

  const normalizedIdentityRoots = identityRoots.map((r) => normalizePathForAirlock(r));
  const normalizedJobRoots = jobRoots.map((r) => normalizePathForAirlock(r));

  for (const root of normalizedIdentityRoots) {
    if (pathWithinRoot(normalizedFilePath, root)) return 'trusted';
  }

  for (const root of normalizedJobRoots) {
    if (pathWithinRoot(normalizedFilePath, root)) return 'untrusted';
  }

  return 'unknown';
}

export function partitionBootstrapFilesForAirlock(
  files: AirlockBootstrapFileInput[],
  airlock: AirlockConfig,
): AirlockPartitionResult {
  const identityRoots = airlock.identityRoots ?? [];
  const jobRoots = airlock.jobRoots ?? [];

  const trustedFiles: AirlockBootstrapFileInput[] = [];
  const untrustedFiles: AirlockBootstrapFileInput[] = [];
  const unknownFiles: AirlockBootstrapFileInput[] = [];

  for (const file of files) {
    const classification = classifyAirlockPath(file.path, identityRoots, jobRoots);
    if (classification === 'trusted') {
      trustedFiles.push(file);
    } else if (classification === 'untrusted') {
      untrustedFiles.push(file);
    } else {
      unknownFiles.push(file);
    }
  }

  return { trustedFiles, untrustedFiles, unknownFiles };
}

// ---------------------------------------------------------------------------
// Key management (persistent Ed25519 JWK)
// ---------------------------------------------------------------------------

type StoredJwkKeyPair = { publicKey: JsonWebKey; privateKey: JsonWebKey };

async function exportKeyPairJwk(kp: Ed25519KeyPair): Promise<StoredJwkKeyPair> {
  const publicKey = (await crypto.subtle.exportKey('jwk', kp.publicKey)) as JsonWebKey;
  const privateKey = (await crypto.subtle.exportKey('jwk', kp.privateKey)) as JsonWebKey;
  return { publicKey, privateKey };
}

async function importKeyPairJwk(stored: StoredJwkKeyPair): Promise<Ed25519KeyPair> {
  const publicKey = await crypto.subtle.importKey(
    'jwk',
    stored.publicKey,
    'Ed25519',
    true,
    ['verify'],
  );
  const privateKey = await crypto.subtle.importKey(
    'jwk',
    stored.privateKey,
    'Ed25519',
    true,
    ['sign'],
  );
  return { publicKey, privateKey };
}

async function loadOrGenerateKeyPair(params: {
  keyFile: string;
  logger: { info: (msg: string) => void; warn: (msg: string) => void };
}): Promise<Ed25519KeyPair> {
  try {
    const raw = await readFile(params.keyFile, 'utf-8');
    const parsed = JSON.parse(raw) as StoredJwkKeyPair;
    return await importKeyPairJwk(parsed);
  } catch {
    // Generate
    await mkdir(path.dirname(params.keyFile), { recursive: true });

    const kp = await generateKeyPair();
    const stored = await exportKeyPairJwk(kp);
    await writeFile(params.keyFile, JSON.stringify(stored, null, 2), {
      encoding: 'utf-8',
      mode: 0o600,
    });

    // Best-effort hardening.
    try {
      await chmod(params.keyFile, 0o600);
    } catch {
      // ignore
    }

    const did = await didFromPublicKey(kp.publicKey);
    params.logger.info(`provider-clawproxy: generated new agent key → ${did}`);
    params.logger.info(`provider-clawproxy: saved key to ${params.keyFile}`);
    return kp;
  }
}

// ---------------------------------------------------------------------------
// Prompt pack capture (agent:bootstrap internal hook)
// ---------------------------------------------------------------------------

type BootstrapFileLike = {
  name?: string;
  path?: string;
  content?: string;
  missing?: boolean;
};

async function promptPackEntriesFromBootstrapFiles(files: BootstrapFileLike[]): Promise<PromptPackEntry[]> {
  const entries: PromptPackEntry[] = [];

  for (const f of files) {
    const content = typeof f.content === 'string' ? f.content : undefined;
    if (!content) continue;

    const entryIdBase = typeof f.name === 'string' && f.name.trim() ? f.name.trim() : typeof f.path === 'string' ? f.path.trim() : 'bootstrap';
    const entry_id = `bootstrap:${entryIdBase}`.slice(0, 256);

    const bytes = new TextEncoder().encode(content);
    const content_hash_b64u = await sha256B64u(bytes);

    entries.push({
      entry_id,
      content_hash_b64u,
      content_type: 'text/plain; charset=utf-8',
      size_bytes: bytes.byteLength,
    });
  }

  // Deduplicate by entry_id (last-write wins).
  const map = new Map<string, PromptPackEntry>();
  for (const e of entries) map.set(e.entry_id, e);
  return [...map.values()].sort((a, b) => a.entry_id.localeCompare(b.entry_id));
}

// ---------------------------------------------------------------------------
// LLM request interception + clawproxy bridging
// ---------------------------------------------------------------------------

type InterceptProvider = 'openai' | 'anthropic' | 'google';

function inferProviderFromUrl(url: URL): InterceptProvider | null {
  const host = url.hostname.toLowerCase();
  const pathLower = url.pathname.toLowerCase();

  // Strict host allowlist by default (avoid accidentally proxying openai-compatible endpoints).
  if (
    host === 'api.openai.com' &&
    (pathLower.endsWith('/chat/completions') || pathLower.endsWith('/responses'))
  ) {
    return 'openai';
  }
  if (host === 'api.anthropic.com' && pathLower.endsWith('/v1/messages')) return 'anthropic';
  if (host === 'generativelanguage.googleapis.com' && pathLower.includes(':generatecontent')) return 'google';

  return null;
}

type OpenAiApi = 'chat_completions' | 'responses';

function inferOpenAiApiFromUrl(url: URL): OpenAiApi | null {
  const host = url.hostname.toLowerCase();
  if (host !== 'api.openai.com') return null;

  const p = url.pathname.toLowerCase();
  if (p.endsWith('/responses')) return 'responses';
  if (p.endsWith('/chat/completions')) return 'chat_completions';
  return null;
}

function cleanProviderResponse(status: number, body: unknown): unknown {
  if (!body || typeof body !== 'object') return body;
  const obj = body as Record<string, unknown>;

  const cleaned: Record<string, unknown> = { ...obj };
  delete cleaned._receipt;
  delete cleaned._receipt_envelope;

  if (status >= 400 && 'error' in cleaned && 'status' in cleaned) {
    const s = cleaned.status;
    if (typeof s === 'number' && s === status) {
      return cleaned.error;
    }
  }

  return cleaned;
}

function stripBearer(value: string | null | undefined): string | undefined {
  if (!value) return undefined;
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  const m = trimmed.match(/^Bearer\s+/i);
  return m ? trimmed.slice(m[0].length).trim() : trimmed;
}

function extractUpstreamKey(provider: InterceptProvider, headers: Headers): string | undefined {
  if (provider === 'openai') {
    return stripBearer(headers.get('authorization'));
  }
  if (provider === 'anthropic') {
    return headers.get('x-api-key')?.trim() || headers.get('anthropic-api-key')?.trim() || stripBearer(headers.get('authorization'));
  }
  if (provider === 'google') {
    return headers.get('x-goog-api-key')?.trim() || stripBearer(headers.get('authorization'));
  }
  return undefined;
}

function isStreamingRequest(parsedBody: Record<string, unknown> | null, headers: Headers): boolean {
  if (parsedBody && parsedBody.stream === true) return true;
  const accept = headers.get('accept');
  return typeof accept === 'string' && accept.toLowerCase().includes('text/event-stream');
}

function decodeB64uJson(value: string): unknown {
  const bytes = base64UrlDecode(value);
  const text = new TextDecoder().decode(bytes);
  return JSON.parse(text) as unknown;
}

function extractOpenAiTextContent(content: unknown): string | undefined {
  if (typeof content === 'string') {
    const out = content;
    return out.length > 0 ? out : undefined;
  }

  if (Array.isArray(content)) {
    // OpenAI content parts:
    // - Chat Completions: [{type:'text', text:'...'}, {type:'image_url', image_url:{url:'...'}}]
    // - Responses API: [{type:'input_text', text:'...'}, ...]
    const textParts: string[] = [];
    for (const p of content) {
      const po = asObject(p);
      if (!po) continue;

      const type = typeof po.type === 'string' ? po.type : undefined;
      if ((type === 'text' || type === 'input_text' || type === 'output_text') && typeof po.text === 'string') {
        textParts.push(po.text);
      }
    }
    const out = textParts.join('');
    return out.length > 0 ? out : undefined;
  }

  const po = asObject(content);
  if (po) {
    const type = typeof po.type === 'string' ? po.type : undefined;
    if ((type === 'text' || type === 'input_text' || type === 'output_text') && typeof po.text === 'string') {
      const out = po.text;
      return out.length > 0 ? out : undefined;
    }
  }

  return undefined;
}

function extractOpenAiSystemPrompt(body: Record<string, unknown>): string | undefined {
  // OpenAI Responses API: prefer explicit instructions field if present.
  const instructions = body.instructions;
  if (typeof instructions === 'string' && instructions.trim().length > 0) {
    return instructions;
  }

  const extractFromItems = (items: unknown[]): string | undefined => {
    const parts: string[] = [];

    for (const msg of items) {
      const m = asObject(msg);
      if (!m) continue;
      const role = typeof m.role === 'string' ? m.role : undefined;
      if (role !== 'system' && role !== 'developer') continue;

      const text = extractOpenAiTextContent(m.content);
      if (text) parts.push(text);
    }

    const out = parts.join('\n\n');
    return out.length > 0 ? out : undefined;
  };

  // OpenAI Chat Completions API: messages array.
  const messages = body.messages;
  if (Array.isArray(messages)) {
    const out = extractFromItems(messages);
    if (out) return out;
  }

  // OpenAI Responses API: input array of messages.
  const input = body.input;
  if (Array.isArray(input)) {
    return extractFromItems(input);
  }

  const inputObj = asObject(input);
  if (inputObj) {
    return extractFromItems([inputObj]);
  }

  return undefined;
}

function extractAnthropicSystemPrompt(body: Record<string, unknown>): string | undefined {
  const system = body.system;
  if (typeof system === 'string') return system;

  if (Array.isArray(system)) {
    const textParts: string[] = [];
    for (const block of system) {
      const b = asObject(block);
      if (!b) continue;
      if (b.type === 'text' && typeof b.text === 'string') {
        textParts.push(b.text);
      }
    }
    const out = textParts.join('');
    return out.length > 0 ? out : undefined;
  }

  return undefined;
}

function extractRenderedSystemPrompt(provider: InterceptProvider, body: Record<string, unknown>): string | undefined {
  switch (provider) {
    case 'openai':
      return extractOpenAiSystemPrompt(body);
    case 'anthropic':
      return extractAnthropicSystemPrompt(body);
    case 'google': {
      // Best-effort: Gemini systemInstruction is often shaped as { systemInstruction: { parts: [{text:"..."}] } }
      const si = asObject(body.systemInstruction);
      const parts = si ? si.parts : undefined;
      if (Array.isArray(parts)) {
        const texts: string[] = [];
        for (const p of parts) {
          const po = asObject(p);
          if (po && typeof po.text === 'string') texts.push(po.text);
        }
        const out = texts.join('');
        return out.length > 0 ? out : undefined;
      }
      return undefined;
    }
    default:
      return undefined;
  }
}

function extractModelFromBody(body: Record<string, unknown>): string | undefined {
  return typeof body.model === 'string' && body.model.trim().length > 0 ? body.model.trim() : undefined;
}

function hasReceiptEnvelope(value: unknown): value is SignedEnvelope<GatewayReceiptPayload> {
  if (!value || typeof value !== 'object') return false;
  const obj = value as Record<string, unknown>;
  return obj.envelope_version === '1' && obj.envelope_type === 'gateway_receipt' && typeof obj.payload_hash_b64u === 'string';
}

function hasLegacyReceipt(value: unknown): value is ClawproxyReceipt {
  if (!value || typeof value !== 'object') return false;
  const obj = value as Record<string, unknown>;
  return obj.version === '1.0' && typeof obj.requestHash === 'string' && typeof obj.responseHash === 'string';
}

class ReceiptTrailerStripper {
  receiptB64u: string | null = null;
  receiptEnvelopeB64u: string | null = null;

  private decoder = new TextDecoder();
  private encoder = new TextEncoder();
  private pending = '';
  private suppressNextBlank = false;

  private processPending(opts: { emit: boolean }): string {
    let out = '';

    while (true) {
      const idx = this.pending.indexOf('\n');
      if (idx === -1) break;

      const line = this.pending.slice(0, idx);
      this.pending = this.pending.slice(idx + 1);

      const clean = line.endsWith('\r') ? line.slice(0, -1) : line;

      if (clean.startsWith(':')) {
        const comment = clean.slice(1).trimStart();

        if (comment.startsWith('clawproxy_receipt_envelope_b64u=')) {
          this.receiptEnvelopeB64u = comment.slice('clawproxy_receipt_envelope_b64u='.length).trim();
          this.suppressNextBlank = true;
          continue;
        }

        if (comment.startsWith('clawproxy_receipt_b64u=')) {
          this.receiptB64u = comment.slice('clawproxy_receipt_b64u='.length).trim();
          this.suppressNextBlank = true;
          continue;
        }
      }

      if (this.suppressNextBlank && clean === '') {
        this.suppressNextBlank = false;
        continue;
      }
      this.suppressNextBlank = false;

      if (opts.emit) out += line + '\n';
    }

    return out;
  }

  scan(chunk: Uint8Array): void {
    this.pending += this.decoder.decode(chunk, { stream: true });
    this.processPending({ emit: false });
  }

  transform(chunk: Uint8Array): Uint8Array {
    this.pending += this.decoder.decode(chunk, { stream: true });
    const out = this.processPending({ emit: true });
    return this.encoder.encode(out);
  }

  private finalizePending(): void {
    // Finalize decoder state and process any remaining pending bytes.
    this.pending += this.decoder.decode();

    // Ensure the last line is processed even if the stream didn't end with \n.
    if (!this.pending.endsWith('\n')) {
      this.pending += '\n';
    }
  }

  flushScan(): void {
    this.finalizePending();
    this.processPending({ emit: false });
  }

  flush(): Uint8Array {
    this.finalizePending();
    const out = this.processPending({ emit: true });
    return this.encoder.encode(out);
  }
}

function buildReceiptArtifact(params: {
  provider: InterceptProvider;
  model: string;
  receiptLegacy: unknown | undefined;
  receiptEnvelope: unknown | undefined;
}): ReceiptArtifact | null {
  if (params.receiptLegacy && hasLegacyReceipt(params.receiptLegacy)) {
    return {
      type: 'clawproxy_receipt',
      collectedAt: new Date().toISOString(),
      model: params.model,
      receipt: params.receiptLegacy,
      receiptEnvelope: params.receiptEnvelope && hasReceiptEnvelope(params.receiptEnvelope)
        ? params.receiptEnvelope
        : undefined,
    };
  }

  if (params.receiptEnvelope && hasReceiptEnvelope(params.receiptEnvelope)) {
    // If the legacy receipt is missing, fabricate a minimal stub.
    const stub: ClawproxyReceipt = {
      version: '1.0',
      provider: params.provider,
      model: params.model,
      requestHash: 'unknown',
      responseHash: 'unknown',
      timestamp: new Date().toISOString(),
      latencyMs: 0,
    };

    return {
      type: 'clawproxy_receipt',
      collectedAt: new Date().toISOString(),
      model: params.model,
      receipt: stub,
      receiptEnvelope: params.receiptEnvelope,
    };
  }

  return null;
}

async function readReceiptTrailersFromStream(stream: ReadableStream<Uint8Array>): Promise<{
  receiptLegacy: unknown | undefined;
  receiptEnvelope: unknown | undefined;
}> {
  const stripper = new ReceiptTrailerStripper();
  const reader = stream.getReader();

  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      if (value) stripper.scan(value);
    }
  } finally {
    try {
      reader.releaseLock();
    } catch {
      // ignore
    }
  }

  stripper.flushScan();

  let receiptLegacy: unknown | undefined;
  let receiptEnvelope: unknown | undefined;

  try {
    if (stripper.receiptB64u) {
      receiptLegacy = decodeB64uJson(stripper.receiptB64u);
    }
  } catch {
    // ignore
  }

  try {
    if (stripper.receiptEnvelopeB64u) {
      receiptEnvelope = decodeB64uJson(stripper.receiptEnvelopeB64u);
    }
  } catch {
    // ignore
  }

  return { receiptLegacy, receiptEnvelope };
}

async function captureStreamingReceipt(params: {
  stream: ReadableStream<Uint8Array>;
  provider: InterceptProvider;
  model: string;
  proxyUrl: string;
  proxyHeaders: Headers;
  baseFetch: typeof fetch;
  recorder: HarnessRecorder;
  logger: Logger;
}): Promise<void> {
  let receiptLegacy: unknown | undefined;
  let receiptEnvelope: unknown | undefined;

  try {
    const res = await readReceiptTrailersFromStream(params.stream);
    receiptLegacy = res.receiptLegacy;
    receiptEnvelope = res.receiptEnvelope;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    params.logger.warn(`provider-clawproxy: stream receipt parse failed: ${msg}`);
  }

  if (!receiptLegacy || !receiptEnvelope) {
    // Deterministic fallback: fetch stored receipts by nonce (no full-body replay).
    const nonce = params.proxyHeaders.get('X-Idempotency-Key')?.trim();
    const runId = params.proxyHeaders.get('X-Run-Id')?.trim();
    const eventHash = params.proxyHeaders.get('X-Event-Hash')?.trim();

    if (nonce) {
      try {
        const proxyUrl = new URL(params.proxyUrl);
        const idx = proxyUrl.pathname.indexOf('/v1/');
        const prefix = idx >= 0 ? proxyUrl.pathname.slice(0, idx) : '';

        const receiptUrl = new URL(
          `${prefix}/v1/receipt/${encodeURIComponent(nonce)}`,
          proxyUrl.origin,
        );

        if (runId) receiptUrl.searchParams.set('run_id', runId);
        if (eventHash) receiptUrl.searchParams.set('event_hash_b64u', eventHash);

        const lookupHeaders = new Headers({ accept: 'application/json' });

        const cst =
          params.proxyHeaders.get('X-CST') ??
          params.proxyHeaders.get('X-Scoped-Token') ??
          null;

        if (cst) {
          // Prefer X-CST so receipt lookup works under STRICT_AUTH_HEADERS deployments.
          lookupHeaders.set('X-CST', cst);
        } else {
          const auth = params.proxyHeaders.get('Authorization');
          if (auth) lookupHeaders.set('Authorization', auth);
        }

        for (let attempt = 0; attempt < 5 && (!receiptLegacy || !receiptEnvelope); attempt++) {
          const res = await params.baseFetch(receiptUrl.toString(), {
            method: 'GET',
            headers: lookupHeaders,
          });

          if (res.ok) {
            const data = await res.json().catch(() => null);
            if (data && typeof data === 'object') {
              const obj = data as Record<string, unknown>;
              receiptLegacy = obj['receipt'];
              receiptEnvelope = obj['receipt_envelope'];
            }
            break;
          }

          // Inflight: retry briefly.
          if (res.status === 409) {
            await new Promise((r) => setTimeout(r, 50 * (attempt + 1)));
            continue;
          }

          break;
        }
      } catch {
        // ignore
      }
    }
  }

  const artifact = buildReceiptArtifact({
    provider: params.provider,
    model: params.model,
    receiptLegacy,
    receiptEnvelope,
  });

  if (!artifact) {
    params.logger.warn('provider-clawproxy: missing receipt for streaming call (tier may degrade)');
    return;
  }

  params.recorder.addReceipt(artifact);
}

// ---------------------------------------------------------------------------
// Run context storage
// ---------------------------------------------------------------------------

type RunContext = {
  recorder: HarnessRecorder;
  promptPackEntries?: PromptPackEntry[];
  prompt?: string;
  sessionKey?: string;

  // Serialization for recordEvent() to ensure a linear event chain.
  chainLock: Promise<void>;
  withChainLock: <T>(fn: () => Promise<T>) => Promise<T>;

  // In-flight background receipt capture tasks (streaming).
  inflightReceiptTasks: Set<Promise<void>>;
};

const runStorage = new AsyncLocalStorage<RunContext>();

// sessionKey → prompt pack entries (computed at agent:bootstrap)
const promptPackBySession = new Map<string, PromptPackEntry[]>();

// sessionKey → airlock violation summary (computed at agent:bootstrap)
const airlockViolationsBySession = new Map<
  string,
  {
    untrustedCount: number;
    unknownCount: number;
  }
>();

// agentId → keyPair promise
const keyPairsByAgent = new Map<string, Promise<Ed25519KeyPair>>();

// ---------------------------------------------------------------------------
// fetch() patching (global)
// ---------------------------------------------------------------------------

type Logger = {
  info: (msg: string) => void;
  warn: (msg: string) => void;
  error: (msg: string) => void;
  debug: (msg: string) => void;
};

const FETCH_PATCH_KEY = Symbol.for('clawproxy-poh.fetch-patch');

type FetchPatchState = {
  patched: boolean;
  originalFetch: typeof fetch;
};

function getFetchPatchState(): FetchPatchState {
  const g = globalThis as any;
  if (!g[FETCH_PATCH_KEY]) {
    g[FETCH_PATCH_KEY] = { patched: false, originalFetch: globalThis.fetch } satisfies FetchPatchState;
  }
  return g[FETCH_PATCH_KEY] as FetchPatchState;
}

function patchFetch(params: {
  proxyBaseUrl: string;
  proxyToken?: string;

  // Optional WPC / confidential-mode headers
  policyHashB64u?: string;
  confidentialMode?: boolean;
  receiptPrivacyMode?: 'hash_only' | 'encrypted';

  mode: PluginMode;
  intercept: Required<NonNullable<PluginConfig['intercept']>>;
  logger: Logger;
}): void {
  const state = getFetchPatchState();
  if (state.patched) return;

  const baseFetch = state.originalFetch;

  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const store = runStorage.getStore();
    if (!store) {
      return baseFetch(input as any, init as any);
    }

    // If the store is provisional (recorder not yet initialized), do not intercept.
    if (!(store as any).recorder || typeof (store as any).recorder.recordEvent !== 'function') {
      return baseFetch(input as any, init as any);
    }

    let url: URL;
    try {
      if (typeof input === 'string') url = new URL(input);
      else if (input instanceof URL) url = input;
      else if (input instanceof Request) url = new URL(input.url);
      else return baseFetch(input as any, init as any);
    } catch {
      return baseFetch(input as any, init as any);
    }

    const provider = inferProviderFromUrl(url);
    if (!provider) {
      return baseFetch(input as any, init as any);
    }

    if (!params.intercept[provider]) {
      return baseFetch(input as any, init as any);
    }

    // Build a normalized Request so we can read headers/body safely.
    const req = input instanceof Request ? new Request(input, init) : new Request(input, init);
    const fallbackReq = req.clone();

    if (req.method.toUpperCase() !== 'POST') {
      return baseFetch(input as any, init as any);
    }

    let bodyText: string;
    try {
      bodyText = await req.text();
    } catch (err) {
      if (params.mode === 'best_effort') {
        return baseFetch(fallbackReq);
      }
      throw err;
    }

    let parsedBody: Record<string, unknown> | null = null;
    try {
      const rawParsed = JSON.parse(bodyText) as unknown;
      parsedBody = asObject(rawParsed);
    } catch {
      parsedBody = null;
    }

    const upstreamKey = extractUpstreamKey(provider, req.headers);
    if (!upstreamKey && params.mode === 'best_effort') {
      return baseFetch(fallbackReq);
    }
    if (!upstreamKey) {
      return new Response(
        JSON.stringify({ error: { message: 'provider api key missing (clawproxy PoH enforce mode)' } }),
        { status: 401, headers: { 'Content-Type': 'application/json; charset=utf-8' } },
      );
    }

    const model = parsedBody ? extractModelFromBody(parsedBody) : undefined;
    const renderedSystemPrompt = parsedBody ? extractRenderedSystemPrompt(provider, parsedBody) : undefined;

    const isStreaming = isStreamingRequest(parsedBody, req.headers);

    // Record llm_call to obtain binding context.
    const { binding } = await store.withChainLock(() =>
      store.recorder.recordEvent({
        eventType: 'llm_call',
        payload: {
          provider,
          model,
          stream: isStreaming,
          rendered_system_prompt: renderedSystemPrompt,
        },
      }),
    );

    const proxyUrl = `${params.proxyBaseUrl}/v1/proxy/${provider}`;

    const headers = new Headers();
    headers.set('Content-Type', 'application/json');

    // Preserve Accept for streaming.
    const accept = req.headers.get('accept');
    if (accept) headers.set('accept', accept);

    // Provider key (always via X-Provider-API-Key so Authorization isn't overloaded; CST uses X-CST).
    headers.set('X-Provider-API-Key', upstreamKey);

    // PoH binding
    headers.set('X-Run-Id', binding.runId);
    if (binding.eventHash) headers.set('X-Event-Hash', binding.eventHash);
    if (binding.nonce) headers.set('X-Idempotency-Key', binding.nonce);

    // WPC / confidential-mode headers
    if (params.policyHashB64u) headers.set('X-Policy-Hash', params.policyHashB64u);
    if (params.confidentialMode) headers.set('X-Confidential-Mode', 'true');
    if (params.receiptPrivacyMode) headers.set('X-Receipt-Privacy-Mode', params.receiptPrivacyMode);

    // OpenAI upstream endpoint selection (chat completions vs responses)
    if (provider === 'openai') {
      const api = inferOpenAiApiFromUrl(url);
      if (api) {
        headers.set('X-OpenAI-API', api === 'responses' ? 'responses' : 'chat_completions');
      }
    }

    // Proxy auth (CST)
    if (params.proxyToken) {
      const token = stripBearer(params.proxyToken);
      if (token) headers.set('X-CST', token);
    }

    // Forward relevant provider headers
    // Anthropic version/betas
    if (provider === 'anthropic') {
      const av = req.headers.get('anthropic-version');
      if (av) headers.set('anthropic-version', av);
      const ab = req.headers.get('anthropic-beta');
      if (ab) headers.set('anthropic-beta', ab);
    }

    let proxyRes: Response;
    try {
      proxyRes = await baseFetch(proxyUrl, {
        method: 'POST',
        headers,
        body: bodyText,
        signal: req.signal,
      });
    } catch (err) {
      if (params.mode === 'best_effort') {
        return baseFetch(fallbackReq);
      }
      const msg = err instanceof Error ? err.message : String(err);
      params.logger.error(`provider-clawproxy: proxy fetch failed: ${msg}`);
      return new Response(
        JSON.stringify({ error: { message: `clawproxy proxy fetch failed: ${msg}` } }),
        { status: 502, headers: { 'Content-Type': 'application/json; charset=utf-8' } },
      );
    }

    // Streaming responses: strip trailer comments and capture receipt(s).
    const contentType = proxyRes.headers.get('content-type') ?? '';
    const proxyIsStream = isStreaming && contentType.toLowerCase().includes('text/event-stream');

    if (proxyIsStream && proxyRes.body) {
      // tee() so we can keep reading in the background even if the consumer cancels early.
      const [consumer, monitor] = proxyRes.body.tee();

      const captureTask = captureStreamingReceipt({
        stream: monitor,
        provider,
        model: model ?? 'unknown',
        proxyUrl,
        proxyHeaders: new Headers(headers),
        baseFetch,
        recorder: store.recorder,
        logger: params.logger,
      }).catch((err) => {
        const msg = err instanceof Error ? err.message : String(err);
        params.logger.warn(`provider-clawproxy: receipt capture task failed: ${msg}`);
      });

      store.inflightReceiptTasks.add(captureTask);
      captureTask.finally(() => {
        store.inflightReceiptTasks.delete(captureTask);
      });

      const stripper = new ReceiptTrailerStripper();
      const ts = new TransformStream({
        transform(chunk: Uint8Array, controller: TransformStreamDefaultController<Uint8Array>) {
          controller.enqueue(stripper.transform(chunk));
        },
        flush(controller: TransformStreamDefaultController<Uint8Array>) {
          const tail = stripper.flush();
          if (tail.byteLength > 0) controller.enqueue(tail);
        },
      });

      const strippedStream = consumer.pipeThrough(ts);

      const outHeaders = new Headers(proxyRes.headers);
      outHeaders.set('content-type', contentType);

      return new Response(strippedStream, {
        status: proxyRes.status,
        headers: outHeaders,
      });
    }

    // Non-streaming JSON response
    let json: any;
    try {
      json = await proxyRes.json();
    } catch {
      // Unexpected: pass-through
      return proxyRes;
    }

    const receipt = json?._receipt;
    const receiptEnvelope = json?._receipt_envelope;

    if (hasLegacyReceipt(receipt)) {
      const artifact: ReceiptArtifact = {
        type: 'clawproxy_receipt',
        collectedAt: new Date().toISOString(),
        model: model ?? (receipt.model ?? 'unknown'),
        receipt,
        receiptEnvelope: hasReceiptEnvelope(receiptEnvelope) ? receiptEnvelope : undefined,
      };
      store.recorder.addReceipt(artifact);
    } else if (hasReceiptEnvelope(receiptEnvelope)) {
      const stub: ClawproxyReceipt = {
        version: '1.0',
        provider,
        model,
        requestHash: 'unknown',
        responseHash: 'unknown',
        timestamp: new Date().toISOString(),
        latencyMs: 0,
      };
      store.recorder.addReceipt({
        type: 'clawproxy_receipt',
        collectedAt: new Date().toISOString(),
        model: model ?? 'unknown',
        receipt: stub,
        receiptEnvelope,
      });
    }

    const cleaned = cleanProviderResponse(proxyRes.status, json);

    const outHeaders = new Headers(proxyRes.headers);
    outHeaders.set('content-type', 'application/json; charset=utf-8');

    // We re-serialize JSON after stripping receipts; drop any headers that could mismatch.
    outHeaders.delete('content-length');
    outHeaders.delete('content-encoding');

    return new Response(JSON.stringify(cleaned), {
      status: proxyRes.status,
      headers: outHeaders,
    });
  }) as any;

  state.patched = true;
  params.logger.info('provider-clawproxy: patched global fetch() for PoH proxying');
}

// ---------------------------------------------------------------------------
// OpenClaw plugin definition
// ---------------------------------------------------------------------------

export default {
  id: 'provider-clawproxy',
  name: 'Clawproxy PoH',
  description: 'Routes LLM calls through clawproxy and emits Proof-of-Harness artifacts.',

  register(api: any) {
    const logger: Logger = {
      info: (msg) => api.logger?.info?.(msg) ?? console.log(msg),
      warn: (msg) => api.logger?.warn?.(msg) ?? console.warn(msg),
      error: (msg) => api.logger?.error?.(msg) ?? console.error(msg),
      debug: (msg) => api.logger?.debug?.(msg),
    };

    const cfg = parsePluginConfig(api.pluginConfig) ?? parsePluginConfig(api.config?.plugins?.entries?.['provider-clawproxy']?.config) ?? null;
    if (!cfg) {
      logger.error('provider-clawproxy: missing/invalid plugin config (baseUrl required)');
      return;
    }

    const proxyBaseUrl = normalizeBaseUrl(cfg.baseUrl);
    const proxyToken = cfg.token;
    const mode: PluginMode = cfg.mode ?? 'enforce';
    const intercept = {
      openai: cfg.intercept?.openai ?? true,
      anthropic: cfg.intercept?.anthropic ?? true,
      google: cfg.intercept?.google ?? false,
    };

    const includePromptPack = cfg.includePromptPack ?? true;
    const includeToolEvents = cfg.includeToolEvents ?? true;

    const airlockEnabled = cfg.airlock?.enabled ?? false;
    const airlockRequireTrustedBootstrap = cfg.airlock?.requireTrustedBootstrap ?? true;
    const airlockIdentityRoots = cfg.airlock?.identityRoots ?? [];
    const airlockJobRoots = cfg.airlock?.jobRoots ?? [];

    // Patch fetch once for this process.
    patchFetch({
      proxyBaseUrl,
      proxyToken,
      policyHashB64u: cfg.policyHashB64u,
      confidentialMode: cfg.confidentialMode,
      receiptPrivacyMode: cfg.receiptPrivacyMode,
      mode,
      intercept,
      logger,
    });

    // Internal hook: agent:bootstrap (capture bootstrap file prompt pack entries)
    api.registerHook('agent:bootstrap', async (event: any) => {
      try {
        const type = event?.type;
        const action = event?.action;
        if (type !== 'agent' || action !== 'bootstrap') return;

        const ctx = asObject(event.context) ?? {};
        const sessionKey = asString(ctx.sessionKey) ?? asString(event.sessionKey);
        if (!sessionKey) return;

        if (!includePromptPack) return;

        const filesRaw = ctx.bootstrapFiles;
        if (!Array.isArray(filesRaw)) return;

        const files = filesRaw
          .map((f: unknown) => asObject(f) ?? null)
          .filter((f): f is Record<string, unknown> => !!f)
          .map((f) => ({
            name: asString(f.name),
            path: asString(f.path),
            content: typeof f.content === 'string' ? f.content : undefined,
            missing: typeof f.missing === 'boolean' ? f.missing : undefined,
          }));

        let filesForPromptPack = files;

        if (airlockEnabled) {
          const partition = partitionBootstrapFilesForAirlock(files, {
            enabled: true,
            identityRoots: airlockIdentityRoots,
            jobRoots: airlockJobRoots,
            requireTrustedBootstrap: airlockRequireTrustedBootstrap,
          });

          filesForPromptPack = partition.trustedFiles;

          const untrustedCount = partition.untrustedFiles.length;
          const unknownCount = partition.unknownFiles.length;

          if (untrustedCount > 0 || unknownCount > 0) {
            logger.warn(
              `provider-clawproxy: AIRLOCK bootstrap partition detected non-trusted bootstrap files (session=${sessionKey}, untrusted=${untrustedCount}, unknown=${unknownCount})`,
            );

            if (airlockRequireTrustedBootstrap) {
              airlockViolationsBySession.set(sessionKey, {
                untrustedCount,
                unknownCount,
              });
            }
          }
        }

        const entries = await promptPackEntriesFromBootstrapFiles(filesForPromptPack);
        if (entries.length > 0) {
          promptPackBySession.set(sessionKey, entries);
        }
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        logger.warn(`provider-clawproxy: agent:bootstrap hook failed: ${msg}`);
      }
    });

    // Plugin hook: before_agent_start (initialize recorder + ALS context)
    api.on('before_agent_start', async (event: any, ctx: any) => {
      const agentId = asString(ctx?.agentId) ?? 'default';
      const sessionKey = asString(ctx?.sessionKey) ?? asString(ctx?.sessionId) ?? undefined;
      const workspaceDir = asString(ctx?.workspaceDir) ?? process.cwd();

      if (airlockEnabled && airlockRequireTrustedBootstrap && sessionKey) {
        const violation = airlockViolationsBySession.get(sessionKey);
        if (violation) {
          airlockViolationsBySession.delete(sessionKey);
          throw new Error(
            `AIRLOCK_BOOTSTRAP_VIOLATION: non-trusted bootstrap files detected for session ${sessionKey} (untrusted=${violation.untrustedCount}, unknown=${violation.unknownCount})`,
          );
        }
      }

      // Serialize all recordEvent calls (tool hooks + llm_call via fetch).
      // IMPORTANT: runStorage.enterWith() MUST run before the first await in this handler,
      // otherwise the AsyncLocalStorage context may not propagate to subsequent model calls.
      let chainLock: Promise<void> = Promise.resolve();
      const withChainLock = async <T,>(fn: () => Promise<T>): Promise<T> => {
        const run = chainLock.then(fn, fn);
        chainLock = run.then(
          () => undefined,
          () => undefined,
        );
        return run;
      };

      const prompt = asString(event?.prompt);
      const promptPackEntries = sessionKey ? promptPackBySession.get(sessionKey) : undefined;

      // Provisional store (recorder is populated later in this hook).
      const store: RunContext = {
        recorder: null as any,
        promptPackEntries,
        prompt,
        sessionKey,
        chainLock,
        withChainLock,
        inflightReceiptTasks: new Set(),
      };

      runStorage.enterWith(store);

      // Resolve default keyFile/outputDir
      const stateDir = typeof api.runtime?.state?.resolveStateDir === 'function'
        ? api.runtime.state.resolveStateDir()
        : path.join(process.env.HOME ?? process.cwd(), '.openclaw');

      const keyFile = cfg.keyFile
        ? api.resolvePath?.(cfg.keyFile) ?? cfg.keyFile
        : path.join(stateDir, 'clawproof', 'keys', `${agentId}.jwk.json`);

      const outputDirRel = cfg.outputDir ?? path.join('.clawproof', 'openclaw');
      const outputDir = path.isAbsolute(outputDirRel)
        ? outputDirRel
        : path.join(workspaceDir, outputDirRel);

      if (!keyPairsByAgent.has(agentId)) {
        keyPairsByAgent.set(
          agentId,
          loadOrGenerateKeyPair({
            keyFile,
            logger: { info: logger.info, warn: logger.warn },
          }),
        );
      }

      const keyPair = await keyPairsByAgent.get(agentId)!;
      const agentDid = await didFromPublicKey(keyPair.publicKey);

      const harness: HarnessConfig = {
        id: 'openclaw',
        version: typeof api.runtime?.version === 'string' ? api.runtime.version : 'unknown',
        runtime: 'openclaw',
      };

      const recorder = await createRecorder(
        {
          keyPair,
          agentDid,
          harness,
        },
        {
          logger,
          configDir: stateDir,
          workspaceDir,
          rpc: { send: async () => undefined },
        },
      );

      // Publish the recorder into ALS store.
      store.recorder = recorder;

      // Record run_start
      await withChainLock(() =>
        recorder.recordEvent({
          eventType: 'run_start',
          payload: {
            openclaw: {
              agentId,
              sessionKey,
              workspaceDir,
              plugin: { id: api.id, version: api.version },
              proxyBaseUrl,
              mode,
            },
          },
        }).then(() => undefined),
      );

      // Ensure output directory exists early (best-effort)
      try {
        await mkdir(outputDir, { recursive: true });
      } catch {
        // ignore
      }

      logger.info(
        `provider-clawproxy: run started (runId=${recorder.runId}, did=${agentDid}, agent=${agentId})`,
      );

      // No modifications to prompt.
      return {};
    });

    if (includeToolEvents) {
      // Plugin hook: before_tool_call
      api.on('before_tool_call', async (event: any, _toolCtx: any) => {
        const store = runStorage.getStore();
        if (!store) return;

        const toolName = asString(event?.toolName) ?? asString(event?.name);
        const params = asObject(event?.params) ?? {};

        await store.withChainLock(() =>
          store.recorder.recordEvent({
            eventType: 'tool_call',
            payload: {
              tool: toolName ?? 'unknown',
              params,
            },
          }).then(() => undefined),
        );

        return undefined;
      });
    }

    // Plugin hook: agent_end (finalize + write artifacts)
    api.on('agent_end', async (event: any, ctx: any) => {
      const store = runStorage.getStore();
      if (!store) return;

      const agentId = asString(ctx?.agentId) ?? 'default';
      const sessionKey = store.sessionKey ?? asString(ctx?.sessionKey);
      const workspaceDir = asString(ctx?.workspaceDir) ?? process.cwd();

      const outputDirRel = cfg.outputDir ?? path.join('.clawproof', 'openclaw');
      const outputDir = path.isAbsolute(outputDirRel)
        ? outputDirRel
        : path.join(workspaceDir, outputDirRel);

      const success = typeof event?.success === 'boolean' ? event.success : false;
      const error = asString(event?.error);
      const durationMs = typeof event?.durationMs === 'number' ? event.durationMs : undefined;

      // Wait for any background streaming receipt capture tasks before finalizing.
      if (store.inflightReceiptTasks.size > 0) {
        await Promise.allSettled([...store.inflightReceiptTasks]);
      }

      await store.withChainLock(() =>
        store.recorder.recordEvent({
          eventType: 'run_end',
          payload: {
            success,
            error,
            durationMs,
          },
        }).then(() => undefined),
      );

      const promptHash = store.prompt ? await hashJsonB64u(store.prompt) : await hashJsonB64u('');
      const endHash = await hashJsonB64u({ success, error: error ?? null, durationMs: durationMs ?? null });

      const result = await store.recorder.finalize({
        inputs: [
          {
            type: 'openclaw_prompt',
            hashB64u: promptHash,
            contentType: 'text/plain; charset=utf-8',
            metadata: {
              session_key: sessionKey,
              agent_id: agentId,
            },
          },
        ],
        outputs: [
          {
            type: 'openclaw_agent_end',
            hashB64u: endHash,
            contentType: 'application/json',
            metadata: { success },
          },
        ],
        urmMetadata: {
          openclaw: {
            agentId,
            sessionKey,
            workspaceDir,
            success,
          },
        },
        promptPackEntries: includePromptPack ? store.promptPackEntries : undefined,
      });

      await mkdir(outputDir, { recursive: true });

      const bundlePath = path.join(outputDir, `${store.recorder.runId}-bundle.json`);
      const urmPath = path.join(outputDir, `${store.recorder.runId}-urm.json`);
      const trustPulsePath = path.join(outputDir, `${store.recorder.runId}-trust-pulse.json`);

      await writeFile(bundlePath, JSON.stringify(result.envelope, null, 2), 'utf-8');
      await writeFile(urmPath, JSON.stringify(result.urm, null, 2), 'utf-8');
      await writeFile(trustPulsePath, JSON.stringify(result.trustPulse, null, 2), 'utf-8');

      logger.info(
        `provider-clawproxy: finalized run ${store.recorder.runId} → ${bundlePath}`,
      );

      if (sessionKey) {
        promptPackBySession.delete(sessionKey);
        airlockViolationsBySession.delete(sessionKey);
      }
    });
  },
};
