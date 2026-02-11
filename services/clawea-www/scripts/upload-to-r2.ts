#!/usr/bin/env npx tsx
/**
 * Upload generated articles to R2 for the clawea-www worker.
 *
 * Usage:
 *   npx tsx scripts/upload-to-r2.ts                        # upload all
 *   npx tsx scripts/upload-to-r2.ts --bucket clawea-www   # specify bucket
 *   npx tsx scripts/upload-to-r2.ts --dry-run             # preview only
 *   npx tsx scripts/upload-to-r2.ts --auto-index          # push URLs to /api/index-urls after upload
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

const AUTO_INDEX = hasFlag("auto-index") || process.env.CLAWEA_AUTO_INDEX_ON_PUBLISH === "1";
const INDEX_ENDPOINT = getArg("index-endpoint") ?? process.env.CLAWEA_INDEX_ENDPOINT ?? "https://clawea.com/api/index-urls";
const INDEX_ENGINES = getArg("index-engines") ?? process.env.CLAWEA_INDEX_ENGINES ?? "all";
const INDEX_BATCH_SIZE = Math.max(1, Number(getArg("index-batch-size") ?? process.env.CLAWEA_INDEX_BATCH_SIZE ?? "100"));
const INDEX_TOKEN = process.env.INDEX_AUTOMATION_TOKEN ?? process.env.CLAWEA_INDEX_AUTOMATION_TOKEN;

function getAllArticles(): string[] {
  const files: string[] = [];
  function walk(dir: string) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name.endsWith(".json") && !entry.name.startsWith("_")) {
        files.push(full);
      }
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

async function pushIndexing(urls: string[]): Promise<void> {
  if (!AUTO_INDEX) return;

  if (!INDEX_TOKEN) {
    console.warn("Auto-index skipped: INDEX_AUTOMATION_TOKEN (or CLAWEA_INDEX_AUTOMATION_TOKEN) not set");
    return;
  }

  const engines =
    INDEX_ENGINES === "all"
      ? ["all"]
      : INDEX_ENGINES.split(",")
          .map((x) => x.trim())
          .filter(Boolean);

  const batches = chunks(urls, INDEX_BATCH_SIZE);
  const responses: Array<{ batch: number; status: number; ok: boolean; body: unknown }> = [];

  for (let i = 0; i < batches.length; i++) {
    const batch = batches[i];
    const res = await fetch(INDEX_ENDPOINT, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${INDEX_TOKEN}`,
      },
      body: JSON.stringify({
        urls: batch,
        engines,
        action: "URL_UPDATED",
      }),
    });

    const raw = await res.text();
    let parsed: unknown = raw;
    try {
      parsed = raw ? JSON.parse(raw) : null;
    } catch {
      // keep text
    }

    const bodyOk =
      typeof parsed === "object" &&
      parsed !== null &&
      "ok" in (parsed as Record<string, unknown>)
        ? (parsed as Record<string, unknown>).ok !== false
        : true;

    responses.push({ batch: i + 1, status: res.status, ok: res.ok && bodyOk, body: parsed });

    if (!res.ok || !bodyOk) {
      console.error(`Indexing batch ${i + 1}/${batches.length} failed with ${res.status}`);
      console.error(typeof parsed === "string" ? parsed.slice(0, 400) : JSON.stringify(parsed).slice(0, 400));
      break;
    }

    console.log(`Indexed batch ${i + 1}/${batches.length} (${batch.length} URLs)`);
  }

  const artifactPath = path.resolve(ARTICLES_DIR, "_indexing_push.json");
  fs.writeFileSync(
    artifactPath,
    JSON.stringify(
      {
        endpoint: INDEX_ENDPOINT,
        engines,
        requestedUrls: urls.length,
        batchSize: INDEX_BATCH_SIZE,
        batches: responses,
        generatedAt: new Date().toISOString(),
      },
      null,
      2,
    ),
  );

  console.log(`Indexing push artifact: ${artifactPath}`);
}

async function main() {
  const files = getAllArticles();
  console.log(`Found ${files.length} article files`);
  console.log(`Target bucket: ${BUCKET}`);

  if (DRY_RUN) {
    console.log("(dry run)");
    files.slice(0, 10).forEach((f) => {
      const rel = path.relative(ARTICLES_DIR, f);
      console.log(`  articles/${rel}`);
    });
    return;
  }

  // Also generate a manifest for the worker
  // NOTE: indexable=true pages are included in the core sitemap (Plan A).
  const manifest: Record<
    string,
    { title: string; category: string; description: string; indexable: boolean }
  > = {};

  let uploaded = 0;
  for (const file of files) {
    const rel = path.relative(ARTICLES_DIR, file);
    const key = `articles/${rel}`;

    try {
      const data = JSON.parse(fs.readFileSync(file, "utf-8"));
      if (data.error) continue; // skip failed articles

      const indexable = data.indexable === true;

      manifest[data.slug] = {
        title: data.title,
        category: data.category,
        description: data.description,
        indexable,
      };

      execSync(
        `wrangler r2 object put "${BUCKET}/${key}" --file "${file}" --content-type "application/json"`,
        { stdio: "pipe" }
      );

      uploaded++;
      if (uploaded % 100 === 0) {
        console.log(`Uploaded ${uploaded}/${files.length}...`);
      }
    } catch (err: any) {
      console.error(`Failed to upload ${rel}: ${err.message?.slice(0, 100)}`);
    }
  }

  // Upload manifest
  const manifestPath = path.resolve(ARTICLES_DIR, "_manifest.json");
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
  execSync(
    `wrangler r2 object put "${BUCKET}/articles/_manifest.json" --file "${manifestPath}" --content-type "application/json"`,
    { stdio: "pipe" }
  );

  // Upload sitemap data (Plan A: only index core pages initially)
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
    { stdio: "pipe" }
  );

  const sitemapCorePath = path.resolve(ARTICLES_DIR, "_sitemap_core.json");
  fs.writeFileSync(sitemapCorePath, JSON.stringify(coreEntries));
  execSync(
    `wrangler r2 object put "${BUCKET}/articles/_sitemap_core.json" --file "${sitemapCorePath}" --content-type "application/json"`,
    { stdio: "pipe" }
  );

  // Backwards compatibility (old path): keep _sitemap.json as core.
  const sitemapCompatPath = path.resolve(ARTICLES_DIR, "_sitemap.json");
  fs.writeFileSync(sitemapCompatPath, JSON.stringify(coreEntries));
  execSync(
    `wrangler r2 object put "${BUCKET}/articles/_sitemap.json" --file "${sitemapCompatPath}" --content-type "application/json"`,
    { stdio: "pipe" }
  );

  const indexableUrls = [
    "https://clawea.com/",
    ...coreEntries.map((e) => `https://clawea.com/${e.slug}`),
  ];
  await pushIndexing(indexableUrls);

  console.log(`\nDone! Uploaded ${uploaded} articles + manifest + core sitemap (${coreEntries.length}) to ${BUCKET}`);
}

main().catch(console.error);
