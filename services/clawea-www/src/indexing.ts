/**
 * Indexing: IndexNow, Google Indexing API, durable queue system.
 * Extracted from index.ts for maintainability.
 */

import type { Env, Article, ManifestEntry, SearchDocument, SearchDocumentKind, SearchResult } from "./index";
import { layout } from "./layout";
import { faqSchema, serviceSchema, canonical, definedTermSchema, breadcrumbSchema } from "./seo";
import { apiJson, apiError, apiHeaders, checkAutomationAuth } from "./index";

function esc(s: string): string { return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"); }

const INDEXABLE_HOSTS = new Set(["clawea.com", "www.clawea.com"]);

function normalizeIndexingUrl(input: string): string | null {
  try {
    const u = new URL(input);
    if (u.protocol !== "https:") return null;
    const host = u.hostname.toLowerCase();
    if (!INDEXABLE_HOSTS.has(host)) return null;

    u.hash = "";
    return u.toString();
  } catch {
    return null;
  }
}

export function normalizeUrlList(input: unknown, maxUrls = 500): { accepted: string[]; rejected: string[] } {
  const accepted: string[] = [];
  const rejected: string[] = [];

  if (!Array.isArray(input)) {
    return { accepted, rejected: ["urls_must_be_array"] };
  }

  for (const raw of input) {
    if (accepted.length >= maxUrls) break;
    if (typeof raw !== "string") {
      rejected.push(String(raw));
      continue;
    }

    const normalized = normalizeIndexingUrl(raw.trim());
    if (!normalized) {
      rejected.push(raw);
      continue;
    }

    if (!accepted.includes(normalized)) accepted.push(normalized);
  }

  return { accepted, rejected };
}

type IndexNowAttempt = {
  attempt: number;
  status: number;
  ok: boolean;
  retryable: boolean;
  waitMs?: number;
};

type IndexNowResult = {
  ok: boolean;
  submitted: number;
  status: number;
  body?: unknown;
  error?: string;
  attempts: number;
  retried: number;
  retryableFailures: number;
  attemptLog: IndexNowAttempt[];
};

const RETRYABLE_HTTP_STATUS = new Set([429, 500, 502, 503, 504]);

function isRetryableStatus(status: number): boolean {
  return RETRYABLE_HTTP_STATUS.has(status);
}

function parseRetryAfterMs(value: string | null): number | null {
  if (!value) return null;

  const asNum = Number(value);
  if (Number.isFinite(asNum) && asNum >= 0) {
    return Math.floor(asNum * 1000);
  }

  const asDate = Date.parse(value);
  if (Number.isNaN(asDate)) return null;

  const delta = asDate - Date.now();
  return delta > 0 ? delta : 0;
}

function backoffMs(attempt: number, baseMs = 900, maxMs = 30000): number {
  const exp = Math.min(maxMs, baseMs * 2 ** Math.max(0, attempt - 1));
  const jitter = Math.floor(exp * 0.2 * Math.random());
  return Math.min(maxMs, exp + jitter);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function submitIndexNow(urls: string[], env: Env): Promise<IndexNowResult> {
  const key = env.INDEXNOW_KEY?.trim();
  if (!key) {
    return {
      ok: false,
      submitted: 0,
      status: 503,
      error: "INDEXNOW_KEY_NOT_CONFIGURED",
      attempts: 0,
      retried: 0,
      retryableFailures: 0,
      attemptLog: [],
    };
  }

  const maxAttempts = Math.max(1, Number(env.INDEXNOW_MAX_ATTEMPTS ?? "4"));
  const baseBackoffMs = Math.max(250, Number(env.INDEXNOW_RETRY_BASE_MS ?? "900"));
  const maxBackoffMs = Math.max(baseBackoffMs, Number(env.INDEXNOW_RETRY_MAX_MS ?? "30000"));

  const payload = {
    host: "clawea.com",
    key,
    keyLocation: `https://clawea.com/${key}.txt`,
    urlList: urls,
  };

  const attemptLog: IndexNowAttempt[] = [];
  let retried = 0;
  let retryableFailures = 0;
  let lastBody: unknown = null;
  let lastStatus = 502;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const res = await fetch("https://api.indexnow.org/IndexNow", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      });

      const raw = await res.text();
      let parsed: unknown = raw;
      try {
        parsed = raw ? JSON.parse(raw) : null;
      } catch {
        // keep raw text body
      }

      const retryable = isRetryableStatus(res.status);
      const nextAllowed = attempt < maxAttempts && retryable;

      let waitMs: number | undefined;
      if (nextAllowed) {
        const retryAfterMs = parseRetryAfterMs(res.headers.get("retry-after"));
        waitMs = retryAfterMs ?? backoffMs(attempt, baseBackoffMs, maxBackoffMs);
      }

      attemptLog.push({
        attempt,
        status: res.status,
        ok: res.ok,
        retryable,
        waitMs,
      });

      lastBody = parsed;
      lastStatus = res.status;

      if (res.ok) {
        return {
          ok: true,
          submitted: urls.length,
          status: res.status,
          body: parsed,
          attempts: attempt,
          retried,
          retryableFailures,
          attemptLog,
        };
      }

      if (!nextAllowed) {
        return {
          ok: false,
          submitted: 0,
          status: res.status,
          body: parsed,
          error: "INDEXNOW_REQUEST_FAILED",
          attempts: attempt,
          retried,
          retryableFailures,
          attemptLog,
        };
      }

      retryableFailures += 1;
      retried += 1;
      await sleep(waitMs ?? backoffMs(attempt, baseBackoffMs, maxBackoffMs));
    } catch (err: any) {
      const nextAllowed = attempt < maxAttempts;
      const waitMs = nextAllowed ? backoffMs(attempt, baseBackoffMs, maxBackoffMs) : undefined;

      attemptLog.push({
        attempt,
        status: 0,
        ok: false,
        retryable: nextAllowed,
        waitMs,
      });

      lastBody = { message: String(err?.message ?? err) };
      lastStatus = 502;

      if (!nextAllowed) {
        return {
          ok: false,
          submitted: 0,
          status: 502,
          body: lastBody,
          error: "INDEXNOW_FETCH_FAILED",
          attempts: attempt,
          retried,
          retryableFailures,
          attemptLog,
        };
      }

      retryableFailures += 1;
      retried += 1;
      await sleep(waitMs ?? backoffMs(attempt, baseBackoffMs, maxBackoffMs));
    }
  }

  return {
    ok: false,
    submitted: 0,
    status: lastStatus,
    body: lastBody,
    error: "INDEXNOW_REQUEST_FAILED",
    attempts: attemptLog.length,
    retried,
    retryableFailures,
    attemptLog,
  };
}

type GoogleServiceAccount = {
  client_email: string;
  private_key: string;
  token_uri?: string;
};

type GoogleAttempt = {
  attempt: number;
  status: number;
  ok: boolean;
  retryable: boolean;
  waitMs?: number;
};

type GoogleIndexDetail = {
  url: string;
  ok: boolean;
  status: number;
  body?: unknown;
  attempts: number;
  retried: number;
  retryableFailures: number;
  attemptLog: GoogleAttempt[];
};

type GoogleIndexResult = {
  ok: boolean;
  submitted: number;
  failed: number;
  status: number;
  details: GoogleIndexDetail[];
  error?: string;
};

function b64Url(input: string | Uint8Array): string {
  const str =
    typeof input === "string"
      ? input
      : String.fromCharCode(...input);
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function pemToPkcs8Bytes(pem: string): Uint8Array {
  const b64 = pem
    .replace(/-----BEGIN PRIVATE KEY-----/g, "")
    .replace(/-----END PRIVATE KEY-----/g, "")
    .replace(/\s+/g, "");

  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function buildGoogleAccessToken(env: Env): Promise<string> {
  const raw = env.GOOGLE_INDEXING_SERVICE_ACCOUNT_JSON?.trim();
  if (!raw) {
    throw new Error("GOOGLE_INDEXING_NOT_CONFIGURED");
  }

  let sa: GoogleServiceAccount;
  try {
    sa = JSON.parse(raw) as GoogleServiceAccount;
  } catch {
    throw new Error("GOOGLE_INDEXING_SERVICE_ACCOUNT_INVALID_JSON");
  }

  if (!sa.client_email || !sa.private_key) {
    throw new Error("GOOGLE_INDEXING_SERVICE_ACCOUNT_FIELDS_MISSING");
  }

  const tokenUri = sa.token_uri ?? "https://oauth2.googleapis.com/token";
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + 3600;

  const header = { alg: "RS256", typ: "JWT" };
  const claim = {
    iss: sa.client_email,
    scope: "https://www.googleapis.com/auth/indexing",
    aud: tokenUri,
    iat,
    exp,
  };

  const encodedHeader = b64Url(JSON.stringify(header));
  const encodedClaim = b64Url(JSON.stringify(claim));
  const signingInput = `${encodedHeader}.${encodedClaim}`;

  const key = await crypto.subtle.importKey(
    "pkcs8",
    pemToPkcs8Bytes(sa.private_key),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );

  const sig = await crypto.subtle.sign(
    { name: "RSASSA-PKCS1-v1_5" },
    key,
    new TextEncoder().encode(signingInput),
  );

  const jwt = `${signingInput}.${b64Url(new Uint8Array(sig))}`;

  const tokenRes = await fetch(tokenUri, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: jwt,
    }).toString(),
  });

  if (!tokenRes.ok) {
    const errBody = await tokenRes.text();
    throw new Error(`GOOGLE_OAUTH_FAILED:${tokenRes.status}:${errBody.slice(0, 400)}`);
  }

  const tokenJson = await tokenRes.json<any>();
  const accessToken = tokenJson?.access_token;
  if (!accessToken || typeof accessToken !== "string") {
    throw new Error("GOOGLE_OAUTH_NO_ACCESS_TOKEN");
  }

  return accessToken;
}

export async function submitGoogleIndexing(
  urls: string[],
  action: "URL_UPDATED" | "URL_DELETED",
  env: Env,
): Promise<GoogleIndexResult> {
  try {
    const accessToken = await buildGoogleAccessToken(env);

    const details: GoogleIndexResult["details"] = [];
    let submitted = 0;
    let failed = 0;

    const maxAttempts = Math.max(1, Number(env.GOOGLE_INDEX_MAX_ATTEMPTS ?? "4"));
    const baseBackoffMs = Math.max(250, Number(env.GOOGLE_INDEX_RETRY_BASE_MS ?? "1200"));
    const maxBackoffMs = Math.max(baseBackoffMs, Number(env.GOOGLE_INDEX_RETRY_MAX_MS ?? "45000"));

    for (const url of urls) {
      const attemptLog: GoogleAttempt[] = [];
      let retried = 0;
      let retryableFailures = 0;
      let finalOk = false;
      let finalStatus = 503;
      let finalBody: unknown = null;

      for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        try {
          const res = await fetch("https://indexing.googleapis.com/v3/urlNotifications:publish", {
            method: "POST",
            headers: {
              "content-type": "application/json",
              authorization: `Bearer ${accessToken}`,
            },
            body: JSON.stringify({
              url,
              type: action,
            }),
          });

          const raw = await res.text();
          let parsed: unknown = raw;
          try {
            parsed = raw ? JSON.parse(raw) : null;
          } catch {
            // leave as text
          }

          const retryable = isRetryableStatus(res.status);
          const shouldRetry = !res.ok && retryable && attempt < maxAttempts;
          const retryAfterMs = shouldRetry ? parseRetryAfterMs(res.headers.get("retry-after")) : null;
          const waitMs = shouldRetry ? (retryAfterMs ?? backoffMs(attempt, baseBackoffMs, maxBackoffMs)) : undefined;

          attemptLog.push({
            attempt,
            status: res.status,
            ok: res.ok,
            retryable,
            waitMs,
          });

          finalOk = res.ok;
          finalStatus = res.status;
          finalBody = parsed;

          if (res.ok) break;
          if (!shouldRetry) break;

          retryableFailures += 1;
          retried += 1;
          await sleep(waitMs ?? backoffMs(attempt, baseBackoffMs, maxBackoffMs));
        } catch (err: any) {
          const shouldRetry = attempt < maxAttempts;
          const waitMs = shouldRetry ? backoffMs(attempt, baseBackoffMs, maxBackoffMs) : undefined;

          attemptLog.push({
            attempt,
            status: 0,
            ok: false,
            retryable: shouldRetry,
            waitMs,
          });

          finalOk = false;
          finalStatus = 503;
          finalBody = { message: String(err?.message ?? err) };

          if (!shouldRetry) break;

          retryableFailures += 1;
          retried += 1;
          await sleep(waitMs ?? backoffMs(attempt, baseBackoffMs, maxBackoffMs));
        }
      }

      if (finalOk) submitted += 1;
      else failed += 1;

      details.push({
        url,
        ok: finalOk,
        status: finalStatus,
        body: finalBody,
        attempts: attemptLog.length,
        retried,
        retryableFailures,
        attemptLog,
      });
    }

    return {
      ok: failed === 0,
      submitted,
      failed,
      status: failed === 0 ? 200 : 207,
      details,
    };
  } catch (err: any) {
    return {
      ok: false,
      submitted: 0,
      failed: urls.length,
      status: 503,
      details: [],
      error: String(err?.message ?? err),
    };
  }
}

// ── Durable Indexing Queue ──────────────────────────────────────

export type IndexEngine = "indexnow" | "google";
export type IndexAction = "URL_UPDATED" | "URL_DELETED";
type IndexQueueEngineStatus = "queued" | "retry" | "done" | "failed";

const INDEX_ENGINES: IndexEngine[] = ["indexnow", "google"];
const INDEX_QUEUE_KEY = "articles/_indexing_queue.v1.json";
const INDEX_QUEUE_SUMMARY_KEY = "articles/_indexing_queue_summary.json";

interface IndexQueueEngineState {
  status: IndexQueueEngineStatus;
  attempts: number;
  maxAttempts: number;
  nextAttemptAt?: string;
  lastStatus?: number;
  lastError?: string;
  lastProcessedAt?: string;
}

interface IndexQueueEntry {
  id: string;
  url: string;
  action: IndexAction;
  engines: Partial<Record<IndexEngine, IndexQueueEngineState>>;
  createdAt: string;
  updatedAt: string;
  source?: string;
}

interface IndexQueueState {
  version: 1;
  updatedAt: string;
  entries: Record<string, IndexQueueEntry>;
}

interface IndexQueueRunEngineResult {
  engine: IndexEngine;
  ok: boolean;
  status: number;
  retryable: boolean;
  attempts: number;
  maxAttempts: number;
  nextAttemptAt?: string;
  error?: string;
}

interface IndexQueueRunItem {
  id: string;
  url: string;
  action: IndexAction;
  engineResults: IndexQueueRunEngineResult[];
}

interface IndexQueueRunArtifact {
  runId: string;
  source: string;
  startedAt: string;
  finishedAt: string;
  processedEntries: number;
  processedEngines: number;
  succeeded: number;
  scheduledRetry: number;
  failed: number;
  clearedEntries: number;
  simulate429: boolean;
  items: IndexQueueRunItem[];
  queueAfter: ReturnType<typeof summarizeIndexQueue>;
}

interface QueueStatusSummary {
  totalEntries: number;
  byEngine: Record<IndexEngine, { queued: number; retry: number; done: number; failed: number }>;
  nextAttemptAt?: string;
}

interface EnqueueQueueOptions {
  urls: string[];
  action: IndexAction;
  engines: IndexEngine[];
  force?: boolean;
  source?: string;
}

interface ProcessQueueOptions {
  source: string;
  maxEntries?: number;
  simulate429?: boolean;
}

interface ProcessQueueResult {
  run: IndexQueueRunArtifact;
  artifactKey: string;
}

function envInt(raw: string | undefined, fallback: number, min = 1): number {
  const n = Number(raw);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.floor(n));
}

export function queueEnabled(env: Env): boolean {
  return env.INDEX_QUEUE_ENABLED !== "0";
}

export function queueMaxEntriesPerRun(env: Env): number {
  return envInt(env.INDEX_QUEUE_MAX_ENTRIES_PER_RUN, 40, 1);
}

function queueMaxAttemptsForEngine(env: Env, engine: IndexEngine): number {
  if (engine === "indexnow") {
    return envInt(env.INDEX_QUEUE_INDEXNOW_MAX_ATTEMPTS, 8, 1);
  }
  return envInt(env.INDEX_QUEUE_GOOGLE_MAX_ATTEMPTS, 6, 1);
}

function deterministicJitter(seed: string, limit: number): number {
  if (limit <= 0) return 0;
  let h = 2166136261;
  for (let i = 0; i < seed.length; i++) {
    h ^= seed.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return Math.abs(h) % Math.max(1, limit);
}

function queueBackoffMs(env: Env, seed: string, attempt: number): number {
  const baseMs = envInt(env.INDEX_QUEUE_RETRY_BASE_MS, 60_000, 250);
  const maxMs = envInt(env.INDEX_QUEUE_RETRY_MAX_MS, 3_600_000, baseMs);
  const exp = Math.min(maxMs, baseMs * 2 ** Math.max(0, attempt - 1));
  const jitter = deterministicJitter(`${seed}:${attempt}`, Math.floor(exp * 0.25));
  return Math.min(maxMs, exp + jitter);
}

function parseDueMs(iso: string | undefined): number {
  if (!iso) return 0;
  const ms = Date.parse(iso);
  return Number.isNaN(ms) ? 0 : ms;
}

function isPendingState(status: IndexQueueEngineStatus): boolean {
  return status === "queued" || status === "retry";
}

async function queueEntryId(url: string, action: IndexAction): Promise<string> {
  const input = new TextEncoder().encode(`${action}|${url}`);
  const digest = await crypto.subtle.digest("SHA-256", input);
  return b64Url(new Uint8Array(digest));
}

export async function loadIndexQueue(env: Env): Promise<IndexQueueState> {
  const obj = await env.ARTICLES.get(INDEX_QUEUE_KEY);
  if (!obj) {
    return {
      version: 1,
      updatedAt: new Date().toISOString(),
      entries: {},
    };
  }

  try {
    const parsed = await obj.json<IndexQueueState>();
    if (!parsed || typeof parsed !== "object" || parsed.version !== 1 || typeof parsed.entries !== "object") {
      throw new Error("invalid_queue_shape");
    }

    return {
      version: 1,
      updatedAt: typeof parsed.updatedAt === "string" ? parsed.updatedAt : new Date().toISOString(),
      entries: parsed.entries ?? {},
    };
  } catch {
    return {
      version: 1,
      updatedAt: new Date().toISOString(),
      entries: {},
    };
  }
}

async function saveIndexQueue(env: Env, state: IndexQueueState): Promise<void> {
  state.updatedAt = new Date().toISOString();
  await env.ARTICLES.put(INDEX_QUEUE_KEY, JSON.stringify(state, null, 2), {
    httpMetadata: { contentType: "application/json" },
  });
}

export function summarizeIndexQueue(state: IndexQueueState): QueueStatusSummary {
  const byEngine: QueueStatusSummary["byEngine"] = {
    indexnow: { queued: 0, retry: 0, done: 0, failed: 0 },
    google: { queued: 0, retry: 0, done: 0, failed: 0 },
  };

  let nextAttemptMs = Number.POSITIVE_INFINITY;

  for (const entry of Object.values(state.entries)) {
    for (const engine of INDEX_ENGINES) {
      const s = entry.engines[engine];
      if (!s) continue;
      byEngine[engine][s.status] += 1;
      if (isPendingState(s.status)) {
        const due = parseDueMs(s.nextAttemptAt);
        if (due > 0 && due < nextAttemptMs) nextAttemptMs = due;
      }
    }
  }

  return {
    totalEntries: Object.keys(state.entries).length,
    byEngine,
    nextAttemptAt: Number.isFinite(nextAttemptMs) ? new Date(nextAttemptMs).toISOString() : undefined,
  };
}

export function summarizeQueueForResponse(state: IndexQueueState) {
  const summary = summarizeIndexQueue(state);
  const pending = Object.values(state.entries)
    .filter((entry) =>
      INDEX_ENGINES.some((engine) => {
        const s = entry.engines[engine];
        return s && isPendingState(s.status);
      }),
    )
    .sort((a, b) => a.updatedAt.localeCompare(b.updatedAt, "en"))
    .slice(0, 25)
    .map((entry) => ({
      id: entry.id,
      url: entry.url,
      action: entry.action,
      engines: entry.engines,
      updatedAt: entry.updatedAt,
    }));

  return { summary, pending };
}

export function parseIndexingEngines(input: unknown): IndexEngine[] {
  const raw = Array.isArray(input)
    ? input.map((x) => String(x).toLowerCase())
    : [String(input ?? "all").toLowerCase()];

  const useAll = raw.includes("all");
  const out: IndexEngine[] = [];
  if (useAll || raw.includes("indexnow")) out.push("indexnow");
  if (useAll || raw.includes("google")) out.push("google");
  return out;
}

export async function enqueueIndexQueue(
  env: Env,
  options: EnqueueQueueOptions,
): Promise<{ created: number; updated: number; deduped: number; state: IndexQueueState; summary: ReturnType<typeof summarizeQueueForResponse> }> {
  const state = await loadIndexQueue(env);

  const nowIso = new Date().toISOString();
  let created = 0;
  let updated = 0;
  let deduped = 0;

  for (const url of options.urls) {
    const id = await queueEntryId(url, options.action);
    let entry = state.entries[id];
    const wasExisting = Boolean(entry);
    let changed = false;

    if (!entry) {
      entry = {
        id,
        url,
        action: options.action,
        engines: {},
        createdAt: nowIso,
        updatedAt: nowIso,
        source: options.source,
      };
      state.entries[id] = entry;
      created += 1;
      changed = true;
    }

    for (const engine of options.engines) {
      const maxAttempts = queueMaxAttemptsForEngine(env, engine);
      const existing = entry.engines[engine];

      if (!existing) {
        entry.engines[engine] = {
          status: "queued",
          attempts: 0,
          maxAttempts,
          nextAttemptAt: nowIso,
        };
        changed = true;
        continue;
      }

      if (options.force) {
        entry.engines[engine] = {
          status: "queued",
          attempts: 0,
          maxAttempts,
          nextAttemptAt: nowIso,
        };
        changed = true;
        continue;
      }

      existing.maxAttempts = maxAttempts;

      if (existing.status === "done") {
        deduped += 1;
        continue;
      }

      if (existing.status === "failed" && existing.attempts >= existing.maxAttempts) {
        deduped += 1;
        continue;
      }

      if (existing.status === "failed" || existing.status === "retry") {
        existing.status = "queued";
        existing.nextAttemptAt = nowIso;
        existing.lastError = undefined;
        changed = true;
        continue;
      }

      deduped += 1;
    }

    if (changed) {
      entry.updatedAt = nowIso;
      entry.source = options.source ?? entry.source;
      if (!entry.createdAt) entry.createdAt = nowIso;
      if (wasExisting) updated += 1;
    }
  }

  await saveIndexQueue(env, state);
  return {
    created,
    updated,
    deduped,
    state,
    summary: summarizeQueueForResponse(state),
  };
}

export async function forceRequeueFailedEntries(env: Env): Promise<{ requeued: number; state: IndexQueueState }> {
  const state = await loadIndexQueue(env);
  const nowIso = new Date().toISOString();
  let requeued = 0;

  for (const entry of Object.values(state.entries)) {
    let changed = false;
    for (const engine of INDEX_ENGINES) {
      const s = entry.engines[engine];
      if (!s || s.status !== "failed") continue;
      s.status = "queued";
      s.nextAttemptAt = nowIso;
      s.lastError = undefined;
      changed = true;
      requeued += 1;
    }
    if (changed) entry.updatedAt = nowIso;
  }

  if (requeued > 0) await saveIndexQueue(env, state);
  return { requeued, state };
}

function googleFailureStatus(result: GoogleIndexResult, url: string): { status: number; retryable: boolean; error?: string } {
  const detail = result.details.find((d) => d.url === url) ?? result.details[0];
  if (detail) {
    return {
      status: detail.status,
      retryable: isRetryableStatus(detail.status),
      error: detail.ok ? undefined : "GOOGLE_INDEXING_REQUEST_FAILED",
    };
  }

  return {
    status: result.status,
    retryable: isRetryableStatus(result.status),
    error: result.error,
  };
}

export async function processIndexQueue(env: Env, options: ProcessQueueOptions): Promise<ProcessQueueResult> {
  const startedAt = new Date().toISOString();
  const runId = startedAt.replace(/[:.]/g, "-");

  if (!queueEnabled(env)) {
    const disabledRun: IndexQueueRunArtifact = {
      runId,
      source: options.source,
      startedAt,
      finishedAt: new Date().toISOString(),
      processedEntries: 0,
      processedEngines: 0,
      succeeded: 0,
      scheduledRetry: 0,
      failed: 0,
      clearedEntries: 0,
      simulate429: Boolean(options.simulate429),
      items: [],
      queueAfter: {
        totalEntries: 0,
        byEngine: {
          indexnow: { queued: 0, retry: 0, done: 0, failed: 0 },
          google: { queued: 0, retry: 0, done: 0, failed: 0 },
        },
      },
    };

    const disabledKey = `articles/_indexing_runs/queue-${runId}.json`;
    await env.ARTICLES.put(disabledKey, JSON.stringify(disabledRun, null, 2), {
      httpMetadata: { contentType: "application/json" },
    });

    return { run: disabledRun, artifactKey: disabledKey };
  }

  const state = await loadIndexQueue(env);
  const maxEntries = Math.max(1, options.maxEntries ?? queueMaxEntriesPerRun(env));
  const nowMs = Date.now();

  const candidates = Object.values(state.entries)
    .map((entry) => {
      const dueEngines = INDEX_ENGINES.filter((engine) => {
        const s = entry.engines[engine];
        if (!s || !isPendingState(s.status)) return false;
        return parseDueMs(s.nextAttemptAt) <= nowMs;
      });
      return { entry, dueEngines };
    })
    .filter((x) => x.dueEngines.length > 0)
    .sort((a, b) => a.entry.updatedAt.localeCompare(b.entry.updatedAt, "en"))
    .slice(0, maxEntries);

  const items: IndexQueueRunItem[] = [];
  let succeeded = 0;
  let scheduledRetry = 0;
  let failed = 0;
  let clearedEntries = 0;

  for (const candidate of candidates) {
    const entry = candidate.entry;
    const engineResults: IndexQueueRunEngineResult[] = [];

    for (const engine of candidate.dueEngines) {
      const stateForEngine = entry.engines[engine];
      if (!stateForEngine) continue;

      stateForEngine.attempts += 1;
      stateForEngine.lastProcessedAt = new Date().toISOString();

      let ok = false;
      let status = 503;
      let retryable = false;
      let error: string | undefined;

      if (options.simulate429) {
        status = 429;
        retryable = true;
        error = "SIMULATED_429";
      } else if (engine === "indexnow") {
        const result = await submitIndexNow([entry.url], env);
        ok = result.ok;
        status = result.status;
        retryable = isRetryableStatus(result.status);
        error = result.error;
      } else {
        const result = await submitGoogleIndexing([entry.url], entry.action, env);
        ok = result.ok;
        const failure = googleFailureStatus(result, entry.url);
        status = ok ? 200 : failure.status;
        retryable = !ok && failure.retryable;
        error = ok ? undefined : (failure.error ?? result.error);
      }

      if (ok) {
        stateForEngine.status = "done";
        stateForEngine.nextAttemptAt = undefined;
        stateForEngine.lastStatus = status;
        stateForEngine.lastError = undefined;
        succeeded += 1;
      } else if (retryable && stateForEngine.attempts < stateForEngine.maxAttempts) {
        stateForEngine.status = "retry";
        const waitMs = queueBackoffMs(env, `${entry.id}:${engine}`, stateForEngine.attempts);
        stateForEngine.nextAttemptAt = new Date(Date.now() + waitMs).toISOString();
        stateForEngine.lastStatus = status;
        stateForEngine.lastError = error ?? "INDEXING_RETRY_SCHEDULED";
        scheduledRetry += 1;
      } else {
        stateForEngine.status = "failed";
        stateForEngine.nextAttemptAt = undefined;
        stateForEngine.lastStatus = status;
        stateForEngine.lastError = error ?? "INDEXING_FAILED";
        failed += 1;
      }

      engineResults.push({
        engine,
        ok,
        status,
        retryable,
        attempts: stateForEngine.attempts,
        maxAttempts: stateForEngine.maxAttempts,
        nextAttemptAt: stateForEngine.nextAttemptAt,
        error: stateForEngine.lastError,
      });
    }

    entry.updatedAt = new Date().toISOString();
    items.push({
      id: entry.id,
      url: entry.url,
      action: entry.action,
      engineResults,
    });

    const allDone = INDEX_ENGINES.every((engine) => {
      const s = entry.engines[engine];
      return !s || s.status === "done";
    });

    if (allDone) {
      delete state.entries[entry.id];
      clearedEntries += 1;
    }
  }

  await saveIndexQueue(env, state);

  const run: IndexQueueRunArtifact = {
    runId,
    source: options.source,
    startedAt,
    finishedAt: new Date().toISOString(),
    processedEntries: items.length,
    processedEngines: items.reduce((sum, item) => sum + item.engineResults.length, 0),
    succeeded,
    scheduledRetry,
    failed,
    clearedEntries,
    simulate429: Boolean(options.simulate429),
    items,
    queueAfter: summarizeIndexQueue(state),
  };

  const artifactKey = `articles/_indexing_runs/queue-${runId}.json`;
  await env.ARTICLES.put(artifactKey, JSON.stringify(run, null, 2), {
    httpMetadata: { contentType: "application/json" },
  });
  await env.ARTICLES.put(INDEX_QUEUE_SUMMARY_KEY, JSON.stringify(run, null, 2), {
    httpMetadata: { contentType: "application/json" },
  });

  return { run, artifactKey };
}

export async function loadLastQueueRun(env: Env): Promise<IndexQueueRunArtifact | null> {
  const obj = await env.ARTICLES.get(INDEX_QUEUE_SUMMARY_KEY);
  if (!obj) return null;
  try {
    return await obj.json<IndexQueueRunArtifact>();
  } catch {
    return null;
  }
}

export async function loadArticle(env: Env, slug: string): Promise<Article | null> {
  const key = `articles/${slug}.json`;
  const obj = await env.ARTICLES.get(key);
  if (!obj) return null;
  const data = await obj.json<Article>();
  if ((data as any).error) return null;
  return data;
}

export async function loadManifest(env: Env): Promise<Record<string, ManifestEntry>> {
  const obj = await env.ARTICLES.get("articles/_manifest.json");
  if (!obj) return {};
  try {
    const parsed = await obj.json<Record<string, ManifestEntry>>();
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

export function slugFromPath(pathname: string): string {
  return pathname.replace(/^\//, "").replace(/\/$/, "");
}

export function normalizeSearchQuery(raw: string | null): string {
  return (raw ?? "")
    .trim()
    .toLowerCase()
    .replace(/\s+/g, " ")
    .slice(0, 120);
}

export function categoryLabel(category: string): string {
  return category.replace(/-/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

const STATIC_SEARCH_DOCS: SearchDocument[] = [
  {
    path: "/",
    title: "Claw EA | Enterprise AI Agents, Deployed and Verified",
    description: "Deploy managed AI agents for your enterprise with cryptographic attestation and policy controls.",
    category: "landing",
    kind: "static",
  },
  {
    path: "/pricing",
    title: "Pricing | Claw EA Enterprise AI Agents",
    description: "Pricing plans for enterprise AI agent infrastructure.",
    category: "pricing",
    kind: "static",
  },
  {
    path: "/assessment",
    title: "AI Readiness Assessment | Claw EA",
    description: "Two-minute assessment for enterprise AI readiness, expected ROI, and rollout risk posture.",
    category: "assessment",
    kind: "static",
  },
  {
    path: "/sources",
    title: "Citation Source Hub | Claw EA",
    description: "Citation routing hub for source-backed enterprise AI implementation pages.",
    category: "sources",
    kind: "static",
  },
  {
    path: "/contact",
    title: "Contact Sales | Claw EA Enterprise AI Agents",
    description: "Talk to Claw EA enterprise sales.",
    category: "contact",
    kind: "static",
  },
  {
    path: "/book",
    title: "Book a Rollout Session | Claw EA",
    description: "Book a deployment planning session with lead-context prefill and conversion tracking.",
    category: "book",
    kind: "static",
  },
  {
    path: "/trust",
    title: "Trust Layer | Verified AI Agent Execution | Claw EA",
    description: "Cryptographic proof of AI agent actions.",
    category: "trust",
    kind: "static",
  },
  {
    path: "/trust/security-review",
    title: "Security Review Pack | Claw EA Enterprise AI Agents",
    description: "Architecture, threat model, proof artifacts, and deployment integrity for security review.",
    category: "trust",
    kind: "static",
  },
  {
    path: "/secure-workers",
    title: "Secure AI Workers | Sandboxed Enterprise Agents | Claw EA",
    description: "Hardware-isolated secure AI workers with strict policy enforcement.",
    category: "trust",
    kind: "static",
  },
  {
    path: "/consulting",
    title: "Enterprise AI Consulting | Agent Strategy & Deployment | Claw EA",
    description: "Consulting services for deployment and governance of AI agent programs.",
    category: "consulting",
    kind: "static",
  },
  {
    path: "/compare/claw-vs-manual-audit",
    title: "Claw EA vs Manual Audit Evidence",
    description: "Automated proof bundles vs manual evidence collection for compliance.",
    category: "compare",
    kind: "static",
  },
  {
    path: "/compare/claw-vs-guardrails",
    title: "Claw EA vs Guardrails (NeMo, Guardrails AI)",
    description: "Protocol-level proof vs inference-time guardrails for agent governance.",
    category: "compare",
    kind: "static",
  },
  {
    path: "/compare/claw-vs-langfuse",
    title: "Claw EA vs Langfuse | Receipts vs Observability",
    description: "Cryptographic receipts with offline verification vs observability dashboards.",
    category: "compare",
    kind: "static",
  },
  {
    path: "/compare/claw-vs-custom-wrappers",
    title: "Claw EA vs Custom Wrappers",
    description: "Protocol-level receipts vs ad-hoc custom wrapper logging.",
    category: "compare",
    kind: "static",
  },
  {
    path: "/compare/agent-governance-platforms",
    title: "Agent Governance Platforms Landscape",
    description: "How guardrails, observability, custom wrappers, and protocol-first proof compare.",
    category: "compare",
    kind: "static",
  },
  {
    path: "/guides/github-actions-proof-pipeline",
    title: "GitHub Actions Proof Pipeline Guide",
    description: "Step-by-step setup for Claw Verified PR pipeline with GitHub Actions.",
    category: "guides",
    kind: "static",
  },
  {
    path: "/guides/okta-scoped-tokens",
    title: "Okta Scoped Tokens Guide",
    description: "Map Okta groups to CST scopes for policy-gated agent execution.",
    category: "guides",
    kind: "static",
  },
  {
    path: "/guides/compliance-evidence-export",
    title: "Compliance Evidence Export Guide",
    description: "Generate export bundles, verify offline, deliver SOX/SOC 2 evidence.",
    category: "guides",
    kind: "static",
  },
  {
    path: "/about",
    title: "About Claw Bureau | Enterprise AI Trust Infrastructure",
    description: "About Claw Bureau and the trust infrastructure approach for enterprise AI.",
    category: "about",
    kind: "static",
  },
  {
    path: "/proof-points",
    title: "Why Trust Claw EA | Protocol Proof Points",
    description: "Protocol adoption metrics, open source transparency, dogfooding evidence, and architecture credibility.",
    category: "trust",
    kind: "static",
  },
  {
    path: "/resources/protocol-whitepaper",
    title: "Download: Clawsig Protocol v0.1 Specification",
    description: "Five cryptographic primitives for verifiable AI agent execution.",
    category: "resources",
    kind: "static",
  },
  {
    path: "/resources/security-checklist",
    title: "Agent Security Checklist: 15 Controls",
    description: "Controls every enterprise needs before deploying AI agents.",
    category: "resources",
    kind: "static",
  },
  {
    path: "/resources/compliance-mapping",
    title: "Regulatory Mapping: SOX, HIPAA, FedRAMP → Controls",
    description: "Map regulations to specific AI agent controls and evidence.",
    category: "resources",
    kind: "static",
  },
  {
    path: "/pricing/starter",
    title: "Starter Plan | $49/mo | Claw EA",
    description: "1 AI agent, execution attestation, 90-day retention.",
    category: "pricing",
    kind: "static",
  },
  {
    path: "/pricing/team",
    title: "Team Plan | $249/mo | Claw EA",
    description: "5 agents, Work Policy Contracts, budget controls, 1-year retention.",
    category: "pricing",
    kind: "static",
  },
  {
    path: "/pricing/enterprise",
    title: "Enterprise Plan | Custom | Claw EA",
    description: "Unlimited agents, custom compliance mapping, 7-year retention, BAA/DPA.",
    category: "pricing",
    kind: "static",
  },
  {
    path: "/industries/financial-services",
    title: "AI Agent Compliance for Financial Services",
    description: "SOX-grade evidence, budget controls, approval gates for banks and fintechs.",
    category: "industries",
    kind: "static",
  },
  {
    path: "/industries/healthcare",
    title: "AI Agent HIPAA Compliance for Healthcare",
    description: "DLP redaction, secret boundaries, egress allowlists for healthcare organizations.",
    category: "industries",
    kind: "static",
  },
  {
    path: "/industries/government",
    title: "AI Agent FedRAMP & Government Compliance",
    description: "Two-person rule, kill switch, forced dry-run, tamper-evident logs for government.",
    category: "industries",
    kind: "static",
  },
  {
    path: "/industries/insurance",
    title: "AI Agent Insurance Underwriting Automation",
    description: "Approval gates, proof bundles, reconciliation controls for insurance carriers.",
    category: "industries",
    kind: "static",
  },
  {
    path: "/industries/legal",
    title: "AI Agent Legal Document Review Governance",
    description: "File path scopes, DLP, two-person rule, audit replay for law firms.",
    category: "industries",
    kind: "static",
  },
  {
    path: "/industries/technology",
    title: "AI Agent DevOps Governance for Technology",
    description: "Deploy approvals, GitHub Actions integration, credential rotation for engineering teams.",
    category: "industries",
    kind: "static",
  },
  {
    path: "/security",
    title: "Security | Claw EA",
    description: "Data handling, encryption, access controls, and infrastructure security.",
    category: "trust",
    kind: "static",
  },
  {
    path: "/privacy",
    title: "Privacy Policy | Claw EA",
    description: "How Claw EA handles personal data. Hash-only protocol, no PII in receipts, GDPR-compatible.",
    category: "legal",
    kind: "static",
  },
  {
    path: "/terms",
    title: "Terms of Service | Claw EA",
    description: "Terms of service for the Claw EA platform and website.",
    category: "legal",
    kind: "static",
  },
  {
    path: "/docs",
    title: "Documentation | Claw EA",
    description: "Developer, security team, and compliance team documentation hub.",
    category: "docs",
    kind: "static",
  },
  {
    path: "/changelog",
    title: "Changelog | Claw EA",
    description: "Product changelog with shipped features, dates, and PR numbers.",
    category: "docs",
    kind: "static",
  },
  {
    path: "/status",
    title: "System Status | Claw EA",
    description: "Live service health for Claw EA infrastructure.",
    category: "status",
    kind: "static",
  },
  {
    path: "/case-studies",
    title: "Case Studies | Claw EA",
    description: "How organizations use Claw EA for verifiable AI agent governance.",
    category: "case-studies",
    kind: "static",
  },
  {
    path: "/case-studies/dogfood-claw-bureau",
    title: "Dogfooding the Clawsig Protocol | Case Study",
    description: "3 autonomous agents, 190+ PRs with proof chains, 12 services in production.",
    category: "case-studies",
    kind: "static",
  },
  {
    path: "/glossary",
    title: "Glossary | Claw EA",
    description: "Glossary of enterprise AI policy, proof, and control terms.",
    category: "glossary",
    kind: "static",
  },
];

export function buildSearchCorpus(manifest: Record<string, ManifestEntry>): SearchDocument[] {
  const manifestDocs: SearchDocument[] = Object.entries(manifest)
    .filter(([, entry]) => Boolean(entry?.title))
    .map(([slug, entry]) => ({
      path: `/${slug}`,
      title: entry.title,
      description: entry.description,
      category: entry.category,
      kind: "article" as const,
    }));

  const map = new Map<string, SearchDocument>();
  for (const doc of [...manifestDocs, ...STATIC_SEARCH_DOCS]) {
    map.set(doc.path, doc);
  }
  return [...map.values()];
}

export function searchCorpus(corpus: SearchDocument[], query: string, limit = 30): SearchResult[] {
  if (!query) return [];
  const tokens = [...new Set(query.split(/[^a-z0-9]+/g).filter((t) => t.length >= 2))];
  const out: SearchResult[] = [];

  for (const doc of corpus) {
    const title = doc.title.toLowerCase();
    const desc = (doc.description ?? "").toLowerCase();
    const pathText = doc.path.toLowerCase().replace(/\//g, " ");
    const categoryText = doc.category.toLowerCase();

    let score = 0;
    if (title.includes(query)) score += 120;
    if (pathText.includes(query)) score += 95;
    if (desc.includes(query)) score += 45;
    if (categoryText.includes(query)) score += 30;

    for (const t of tokens) {
      if (title.startsWith(t)) score += 25;
      if (title.includes(t)) score += 18;
      if (pathText.includes(t)) score += 15;
      if (desc.includes(t)) score += 8;
      if (categoryText.includes(t)) score += 6;
    }

    if (doc.kind === "article") score += 6;
    if (score <= 0) continue;

    out.push({ ...doc, score });
  }

  return out
    .sort((a, b) => (b.score - a.score) || a.path.localeCompare(b.path, "en"))
    .slice(0, limit);
}

export function previewText(input: string, max = 220): string {
  const cleaned = input.replace(/\s+/g, " ").trim();
  if (cleaned.length <= max) return cleaned;
  return `${cleaned.slice(0, max - 1)}…`;
}

export function glossarySearchPage(query: string, results: SearchResult[]): string {
  const q = query.trim();
  const hasResults = results.length > 0;
  const body = hasResults
    ? `<div class="search-results">${results
        .map(
          (r) => `<a class="search-result-card" href="${r.path}">
            <div class="search-result-meta">
              <span class="badge badge-blue">${esc(categoryLabel(r.category))}</span>
              <span class="search-pill">${esc(r.path)}</span>
            </div>
            <div class="search-result-title">${esc(r.title.replace(/ \| Claw EA$/, ""))}</div>
            <p class="search-result-desc">${esc(previewText(r.description, 240))}</p>
          </a>`,
        )
        .join("")}</div>`
    : `<div class="search-empty">
        No exact matches for <strong>${esc(q)}</strong>. Try a tool name (e.g. <em>okta</em>), a control (e.g. <em>dlp</em>), or a workflow phrase (e.g. <em>approval gate</em>).
      </div>`;

  return layout({
    meta: {
      title: `Search: ${q} | Claw EA`,
      description: `Search Claw EA policy, workflow, tool, and glossary content for “${q}”.`,
      path: "/glossary",
      canonicalPath: "/glossary",
      noindex: true,
      ogImageAlt: `Search results for ${q}`,
    },
    breadcrumbs: [
      { name: "Home", path: "/" },
      { name: "Glossary", path: "/glossary" },
      { name: `Search: ${q}`, path: "/glossary" },
    ],
    body: `
    <section class="section content-page">
      <div class="wrap">
        <h1>Search results</h1>
        <p class="search-summary">
          <span class="search-pill">Query: ${esc(q)}</span>
          <span>${results.length} result${results.length === 1 ? "" : "s"}</span>
        </p>
        <form class="card" role="search" action="/glossary" method="get" style="max-width:780px;padding:1rem 1.2rem;display:flex;gap:.6rem;align-items:center;flex-wrap:wrap">
          <label for="glossary-search-input" class="sr-only">Refine search query</label>
          <input id="glossary-search-input" type="search" name="q" value="${esc(q)}" placeholder="Search controls, workflows, tools..." style="flex:1;min-width:200px;border:1px solid var(--border);background:var(--surface-2);color:var(--text);padding:.6rem .75rem;border-radius:.6rem">
          <button type="submit" class="cta-btn" data-cta="glossary-search-submit">Search</button>
        </form>
        ${body}
      </div>
    </section>`,
  });
}

export type TrackingEventType =
  | "cta_click"
  | "contact_intent_view"
  | "contact_email_click"
  | "contact_intent_submit"
  | "lead_submit"
  | "variant_assignment"
  | "search_query"
  | "search_result_click"
  | "search_clear"
  | "book_prompt_shown"
  | "booking_submit"
  | "booking_complete";

