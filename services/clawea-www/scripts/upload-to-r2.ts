#!/usr/bin/env npx tsx
/**
 * Upload generated articles to R2 for the clawea-www worker.
 *
 * Usage:
 *   npx tsx scripts/upload-to-r2.ts
 *   npx tsx scripts/upload-to-r2.ts --bucket clawea-www --auto-index
 *   npx tsx scripts/upload-to-r2.ts --replay-failures articles/_indexing_failures.json
 *   npx tsx scripts/upload-to-r2.ts --index-only --auto-index
 */

import * as fs from "fs";
import * as path from "path";
import { execSync } from "child_process";

const args = process.argv.slice(2);
const getArg = (name: string) => {
  const idx = args.indexOf(`--${name}`);
  return idx >= 0 && idx + 1 < args.length ? args[idx + 1] : undefined;
};
const hasFlag = (name: string) => args.includes(`--${name}`);

const ARTICLES_DIR = path.resolve(import.meta.dirname ?? ".", "../articles");
const BUCKET = getArg("bucket") ?? "clawea-www";
const DRY_RUN = hasFlag("dry-run");
const INDEX_ONLY = hasFlag("index-only");

const AUTO_INDEX = hasFlag("auto-index") || process.env.CLAWEA_AUTO_INDEX_ON_PUBLISH === "1";
const INDEX_ENDPOINT = getArg("index-endpoint") ?? process.env.CLAWEA_INDEX_ENDPOINT ?? "https://clawea.com/api/index-urls";
const INDEX_ENGINES = getArg("index-engines") ?? process.env.CLAWEA_INDEX_ENGINES ?? "all";
const INDEX_BATCH_SIZE = Math.max(1, Number(getArg("index-batch-size") ?? process.env.CLAWEA_INDEX_BATCH_SIZE ?? "20"));
const INDEX_TOKEN = process.env.INDEX_AUTOMATION_TOKEN ?? process.env.CLAWEA_INDEX_AUTOMATION_TOKEN;
const INDEX_MAX_ATTEMPTS = Math.max(1, Number(getArg("index-max-attempts") ?? process.env.CLAWEA_INDEX_MAX_ATTEMPTS ?? "4"));
const INDEX_RETRY_BASE_MS = Math.max(250, Number(getArg("index-retry-base-ms") ?? process.env.CLAWEA_INDEX_RETRY_BASE_MS ?? "1200"));
const INDEX_RETRY_MAX_MS = Math.max(INDEX_RETRY_BASE_MS, Number(getArg("index-retry-max-ms") ?? process.env.CLAWEA_INDEX_RETRY_MAX_MS ?? "45000"));
const INDEX_RUN_ID = getArg("index-run-id") ?? new Date().toISOString().replace(/[:.]/g, "-");
const INDEX_RUNS_DIR = path.resolve(getArg("index-run-dir") ?? path.join(ARTICLES_DIR, "_indexing_runs"));
const INDEX_FAILURE_QUEUE_PATH = path.resolve(
  getArg("index-failure-queue") ?? path.join(ARTICLES_DIR, "_indexing_failures.json"),
);
const REPLAY_FAILURES_PATH = getArg("replay-failures")
  ? path.resolve(getArg("replay-failures") as string)
  : undefined;

const RETRYABLE_STATUS = new Set([429, 500, 502, 503, 504]);

type BatchAttempt = {
  attempt: number;
  status: number;
  ok: boolean;
  retryable: boolean;
  waitMs?: number;
  body?: unknown;
  error?: string;
};

type BatchArtifact = {
  batch: number;
  urlCount: number;
  urls: string[];
  success: boolean;
  submitted: number;
  failed: number;
  attempts: BatchAttempt[];
};

type FailedUrl = {
  url: string;
  batch: number;
  attempts: number;
  lastStatus: number;
  reason: string;
  indexnowStatus?: number;
  googleStatus?: number;
};

type IndexRunArtifact = {
  runId: string;
  mode: "publish" | "replay" | "index-only";
  endpoint: string;
  engines: string[];
  requestedUrls: number;
  submittedUrls: number;
  failedUrls: number;
  batchSize: number;
  batchCount: number;
  retriedBatches: number;
  retryAttempts: number;
  batches: BatchArtifact[];
  failures: FailedUrl[];
  failureQueuePath: string;
  startedAt: string;
  finishedAt: string;
};

function getAllArticles(): string[] {
  const files: string[] = [];

  function walk(dir: string) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);

      if (entry.isDirectory()) {
        if (entry.name.startsWith("_")) continue;
        walk(full);
        continue;
      }

      if (entry.name.endsWith(".json") && !entry.name.startsWith("_")) files.push(full);
    }
  }

  walk(ARTICLES_DIR);
  return files;
}

function chunks<T>(arr: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < arr.length; i += size) {
    out.push(arr.slice(i, i + size));
  }
  return out;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function backoffMs(attempt: number): number {
  const exp = Math.min(INDEX_RETRY_MAX_MS, INDEX_RETRY_BASE_MS * 2 ** Math.max(0, attempt - 1));
  const jitter = Math.floor(exp * 0.2 * Math.random());
  return Math.min(INDEX_RETRY_MAX_MS, exp + jitter);
}

function parseRetryAfterMs(value: string | null): number | null {
  if (!value) return null;

  const n = Number(value);
  if (Number.isFinite(n) && n >= 0) return Math.floor(n * 1000);

  const asDate = Date.parse(value);
  if (Number.isNaN(asDate)) return null;
  const delta = asDate - Date.now();
  return delta > 0 ? delta : 0;
}

function parseBody(raw: string): unknown {
  try {
    return raw ? JSON.parse(raw) : null;
  } catch {
    return raw;
  }
}

function summarizeBody(body: unknown): unknown {
  if (typeof body === "string") return body.slice(0, 400);
  if (!body || typeof body !== "object") return body ?? null;

  const root = body as Record<string, any>;
  const summary: Record<string, unknown> = {};

  if (typeof root.ok === "boolean") summary.ok = root.ok;
  if (Number.isFinite(Number(root.requested))) summary.requested = Number(root.requested);
  if (Array.isArray(root.rejected)) summary.rejectedCount = root.rejected.length;
  if (typeof root.action === "string") summary.action = root.action;

  if (root.indexnow && typeof root.indexnow === "object") {
    const i = root.indexnow as Record<string, any>;
    summary.indexnow = {
      ok: i.ok,
      submitted: Number(i.submitted ?? 0),
      status: Number(i.status ?? 0),
      attempts: Number(i.attempts ?? 0),
      retried: Number(i.retried ?? 0),
      retryableFailures: Number(i.retryableFailures ?? 0),
      error: i.error,
      body: typeof i.body === "object" && i.body !== null
        ? {
            code: (i.body as Record<string, unknown>).code,
            message: (i.body as Record<string, unknown>).message,
          }
        : i.body,
    };
  }

  if (root.google && typeof root.google === "object") {
    const g = root.google as Record<string, any>;
    const details = Array.isArray(g.details) ? g.details : [];
    const failedDetails = details
      .filter((x: any) => x && x.ok === false)
      .slice(0, 5)
      .map((x: any) => ({
        url: x.url,
        status: x.status,
      }));

    summary.google = {
      ok: g.ok,
      submitted: Number(g.submitted ?? 0),
      failed: Number(g.failed ?? 0),
      status: Number(g.status ?? 0),
      error: g.error,
      detailsCount: details.length,
      failedDetails,
    };
  }

  return summary;
}

function nestedEngineStatus(body: unknown, engine: "indexnow" | "google"): number | undefined {
  if (!body || typeof body !== "object") return undefined;
  const root = body as Record<string, unknown>;
  const e = root[engine];
  if (!e || typeof e !== "object") return undefined;
  const status = Number((e as Record<string, unknown>).status);
  return Number.isFinite(status) ? status : undefined;
}

function isResponseOk(status: number, body: unknown): boolean {
  const httpOk = status >= 200 && status < 300;
  if (!httpOk) return false;

  if (body && typeof body === "object" && "ok" in (body as Record<string, unknown>)) {
    return (body as Record<string, unknown>).ok !== false;
  }

  return true;
}

function extractStatusCandidates(status: number, body: unknown): number[] {
  const out = [status];

  if (!body || typeof body !== "object") return out;

  const root = body as Record<string, unknown>;
  const nested = [root.indexnow, root.google];

  for (const n of nested) {
    if (!n || typeof n !== "object") continue;
    const s = Number((n as Record<string, unknown>).status);
    if (Number.isFinite(s)) out.push(s);
  }

  return out;
}

function isRetryableFailure(status: number, body: unknown): boolean {
  const statuses = extractStatusCandidates(status, body);
  return statuses.some((s) => RETRYABLE_STATUS.has(s));
}

function loadReplayUrls(filePath: string): string[] {
  if (!fs.existsSync(filePath)) return [];

  try {
    const parsed = JSON.parse(fs.readFileSync(filePath, "utf-8")) as any;

    const fromPending = Array.isArray(parsed?.pending)
      ? parsed.pending.map((x: any) => (typeof x?.url === "string" ? x.url : null)).filter(Boolean)
      : [];

    const fromFailures = Array.isArray(parsed?.failures)
      ? parsed.failures.map((x: any) => (typeof x?.url === "string" ? x.url : null)).filter(Boolean)
      : [];

    const fromUrls = Array.isArray(parsed?.urls)
      ? parsed.urls.filter((x: unknown) => typeof x === "string")
      : [];

    return [...new Set([...fromPending, ...fromFailures, ...fromUrls])];
  } catch {
    return [];
  }
}

function loadIndexableUrlsFromCoreSitemap(): string[] {
  const sitemapCorePath = path.resolve(ARTICLES_DIR, "_sitemap_core.json");
  if (!fs.existsSync(sitemapCorePath)) return ["https://clawea.com/"];

  const core = JSON.parse(fs.readFileSync(sitemapCorePath, "utf-8")) as Array<{ slug: string }>;
  return [
    "https://clawea.com/",
    ...core.map((x) => `https://clawea.com/${x.slug}`),
  ];
}

function writeJson(filePath: string, data: unknown): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

async function pushIndexing(urls: string[], mode: IndexRunArtifact["mode"]): Promise<IndexRunArtifact | null> {
  if (!AUTO_INDEX) return null;

  if (!INDEX_TOKEN) {
    console.warn("Auto-index skipped: INDEX_AUTOMATION_TOKEN (or CLAWEA_INDEX_AUTOMATION_TOKEN) not set");
    return null;
  }

  const engines =
    INDEX_ENGINES === "all"
      ? ["all"]
      : INDEX_ENGINES.split(",").map((x) => x.trim()).filter(Boolean);

  const startedAt = new Date().toISOString();

  const batchUrls = chunks(urls, INDEX_BATCH_SIZE);
  const batches: BatchArtifact[] = [];
  const failures: FailedUrl[] = [];

  let submittedUrls = 0;
  let retriedBatches = 0;
  let retryAttempts = 0;

  for (let i = 0; i < batchUrls.length; i++) {
    const urlsInBatch = batchUrls[i];
    const attempts: BatchAttempt[] = [];

    for (let attempt = 1; attempt <= INDEX_MAX_ATTEMPTS; attempt++) {
      try {
        const res = await fetch(INDEX_ENDPOINT, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            authorization: `Bearer ${INDEX_TOKEN}`,
          },
          body: JSON.stringify({
            urls: urlsInBatch,
            engines,
            action: "URL_UPDATED",
          }),
        });

        const raw = await res.text();
        const body = parseBody(raw);
        const ok = isResponseOk(res.status, body);
        const retryable = !ok && isRetryableFailure(res.status, body);
        const shouldRetry = retryable && attempt < INDEX_MAX_ATTEMPTS;
        const retryAfterMs = shouldRetry ? parseRetryAfterMs(res.headers.get("retry-after")) : null;
        const waitMs = shouldRetry ? (retryAfterMs ?? backoffMs(attempt)) : undefined;

        attempts.push({
          attempt,
          status: res.status,
          ok,
          retryable,
          waitMs,
          body: summarizeBody(body),
        });

        if (ok) {
          submittedUrls += urlsInBatch.length;
          break;
        }

        if (!shouldRetry) break;

        await sleep(waitMs ?? backoffMs(attempt));
      } catch (err: any) {
        const shouldRetry = attempt < INDEX_MAX_ATTEMPTS;
        const waitMs = shouldRetry ? backoffMs(attempt) : undefined;

        attempts.push({
          attempt,
          status: 0,
          ok: false,
          retryable: shouldRetry,
          waitMs,
          error: String(err?.message ?? err),
        });

        if (!shouldRetry) break;
        await sleep(waitMs ?? backoffMs(attempt));
      }
    }

    const last = attempts[attempts.length - 1];
    const success = Boolean(last?.ok);

    if (attempts.length > 1) {
      retriedBatches += 1;
      retryAttempts += attempts.length - 1;
    }

    if (!success) {
      const indexnowStatus = nestedEngineStatus(last?.body, "indexnow");
      const googleStatus = nestedEngineStatus(last?.body, "google");

      for (const url of urlsInBatch) {
        failures.push({
          url,
          batch: i + 1,
          attempts: attempts.length,
          lastStatus: last?.status ?? 0,
          reason: last?.error ?? "INDEXING_BATCH_FAILED",
          indexnowStatus,
          googleStatus,
        });
      }
    }

    batches.push({
      batch: i + 1,
      urlCount: urlsInBatch.length,
      urls: urlsInBatch,
      success,
      submitted: success ? urlsInBatch.length : 0,
      failed: success ? 0 : urlsInBatch.length,
      attempts,
    });

    if (success) {
      console.log(`Indexed batch ${i + 1}/${batchUrls.length} (${urlsInBatch.length} URLs)`);
    } else {
      console.error(`Indexing batch ${i + 1}/${batchUrls.length} failed after ${attempts.length} attempt(s)`);
    }
  }

  const finishedAt = new Date().toISOString();

  const runArtifact: IndexRunArtifact = {
    runId: INDEX_RUN_ID,
    mode,
    endpoint: INDEX_ENDPOINT,
    engines,
    requestedUrls: urls.length,
    submittedUrls,
    failedUrls: failures.length,
    batchSize: INDEX_BATCH_SIZE,
    batchCount: batches.length,
    retriedBatches,
    retryAttempts,
    batches,
    failures,
    failureQueuePath: INDEX_FAILURE_QUEUE_PATH,
    startedAt,
    finishedAt,
  };

  const queueArtifact = {
    runId: INDEX_RUN_ID,
    generatedAt: finishedAt,
    endpoint: INDEX_ENDPOINT,
    engines,
    pendingCount: failures.length,
    pending: failures,
  };

  writeJson(INDEX_FAILURE_QUEUE_PATH, queueArtifact);

  const runArtifactPath = path.join(INDEX_RUNS_DIR, `${INDEX_RUN_ID}.json`);
  writeJson(runArtifactPath, runArtifact);

  const latestPath = path.resolve(ARTICLES_DIR, "_indexing_push.json");
  writeJson(latestPath, runArtifact);

  if (mode === "replay") {
    const replayLatest = path.resolve(ARTICLES_DIR, "_indexing_replay.json");
    writeJson(replayLatest, runArtifact);
  }

  console.log(`Indexing run artifact: ${runArtifactPath}`);
  console.log(`Failure queue artifact: ${INDEX_FAILURE_QUEUE_PATH} (${failures.length} pending)`);

  return runArtifact;
}

async function uploadArticlesAndManifests(): Promise<string[]> {
  const files = getAllArticles();
  console.log(`Found ${files.length} article files`);
  console.log(`Target bucket: ${BUCKET}`);

  if (DRY_RUN) {
    console.log("(dry run)");
    files.slice(0, 10).forEach((f) => {
      const rel = path.relative(ARTICLES_DIR, f);
      console.log(`  articles/${rel}`);
    });
    return [];
  }

  const manifest: Record<string, { title: string; category: string; description: string; indexable: boolean }> = {};

  let uploaded = 0;
  for (const file of files) {
    const rel = path.relative(ARTICLES_DIR, file);
    const key = `articles/${rel}`;

    try {
      const data = JSON.parse(fs.readFileSync(file, "utf-8"));
      if (data.error) continue;

      if (
        typeof data.slug !== "string" ||
        typeof data.title !== "string" ||
        typeof data.category !== "string" ||
        typeof data.description !== "string"
      ) {
        console.warn(`Skipping non-article JSON: ${rel}`);
        continue;
      }

      const indexable = data.indexable === true;

      manifest[data.slug] = {
        title: data.title,
        category: data.category,
        description: data.description,
        indexable,
      };

      execSync(
        `wrangler r2 object put "${BUCKET}/${key}" --file "${file}" --content-type "application/json"`,
        { stdio: "pipe" },
      );

      uploaded++;
      if (uploaded % 100 === 0) {
        console.log(`Uploaded ${uploaded}/${files.length}...`);
      }
    } catch (err: any) {
      console.error(`Failed to upload ${rel}: ${err.message?.slice(0, 140)}`);
    }
  }

  const manifestPath = path.resolve(ARTICLES_DIR, "_manifest.json");
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
  execSync(
    `wrangler r2 object put "${BUCKET}/articles/_manifest.json" --file "${manifestPath}" --content-type "application/json"`,
    { stdio: "pipe" },
  );

  const allEntries = Object.entries(manifest).map(([slug, meta]) => ({
    slug,
    title: meta.title,
    category: meta.category,
    indexable: meta.indexable,
  }));

  const coreEntries = allEntries.filter((e) => e.indexable);

  const sitemapAllPath = path.resolve(ARTICLES_DIR, "_sitemap_all.json");
  fs.writeFileSync(sitemapAllPath, JSON.stringify(allEntries));
  execSync(
    `wrangler r2 object put "${BUCKET}/articles/_sitemap_all.json" --file "${sitemapAllPath}" --content-type "application/json"`,
    { stdio: "pipe" },
  );

  const sitemapCorePath = path.resolve(ARTICLES_DIR, "_sitemap_core.json");
  fs.writeFileSync(sitemapCorePath, JSON.stringify(coreEntries));
  execSync(
    `wrangler r2 object put "${BUCKET}/articles/_sitemap_core.json" --file "${sitemapCorePath}" --content-type "application/json"`,
    { stdio: "pipe" },
  );

  const sitemapCompatPath = path.resolve(ARTICLES_DIR, "_sitemap.json");
  fs.writeFileSync(sitemapCompatPath, JSON.stringify(coreEntries));
  execSync(
    `wrangler r2 object put "${BUCKET}/articles/_sitemap.json" --file "${sitemapCompatPath}" --content-type "application/json"`,
    { stdio: "pipe" },
  );

  console.log(`\nDone! Uploaded ${uploaded} articles + manifest + core sitemap (${coreEntries.length}) to ${BUCKET}`);

  return [
    "https://clawea.com/",
    ...coreEntries.map((e) => `https://clawea.com/${e.slug}`),
  ];
}

async function main() {
  if (DRY_RUN) {
    await uploadArticlesAndManifests();
    return;
  }

  if (REPLAY_FAILURES_PATH) {
    const replayUrls = loadReplayUrls(REPLAY_FAILURES_PATH);
    if (replayUrls.length === 0) {
      console.log(`No replay URLs found in ${REPLAY_FAILURES_PATH}`);
      return;
    }

    console.log(`Replaying ${replayUrls.length} failed URLs from ${REPLAY_FAILURES_PATH}`);
    await pushIndexing(replayUrls, "replay");
    return;
  }

  let indexableUrls: string[] = [];

  if (INDEX_ONLY) {
    indexableUrls = loadIndexableUrlsFromCoreSitemap();
    console.log(`Index-only mode: ${indexableUrls.length} URLs from core sitemap`);
  } else {
    indexableUrls = await uploadArticlesAndManifests();
  }

  await pushIndexing(indexableUrls, INDEX_ONLY ? "index-only" : "publish");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
