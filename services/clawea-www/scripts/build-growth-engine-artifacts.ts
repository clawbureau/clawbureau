#!/usr/bin/env npx tsx
/**
 * Build deterministic ops artifacts for AEO-PIPE-003.
 *
 * Writes under artifacts/ops/clawea-www/<timestamp>/:
 * - search-smoke.json
 * - indexing-queue-summary.json
 * - indexing-replay-result.json
 * - conversion-summary.json
 * - seo-metadata-smoke.json
 * - deploy-summary.json
 */

import * as fs from "node:fs";
import * as path from "node:path";

const args = process.argv.slice(2);
const getArg = (name: string) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 && i + 1 < args.length ? args[i + 1] : undefined;
};

const stagingBase = (getArg("staging-base") ?? "https://staging-www.clawea.com").replace(/\/+$/, "");
const prodBase = (getArg("prod-base") ?? "https://clawea.com").replace(/\/+$/, "");
const token = process.env.INDEX_AUTOMATION_TOKEN ?? process.env.CLAWEA_INDEX_AUTOMATION_TOKEN;

if (!token) {
  console.error("Missing INDEX_AUTOMATION_TOKEN (or CLAWEA_INDEX_AUTOMATION_TOKEN)");
  process.exit(1);
}

const stamp = getArg("stamp") ?? new Date().toISOString().replace(/[:.]/g, "-");
const outDir = path.resolve(getArg("out-dir") ?? path.resolve(import.meta.dirname ?? ".", `../artifacts/ops/clawea-www/${stamp}`));

const mergeSha = getArg("merge-sha") ?? "";
const stagingVersion = getArg("staging-version") ?? "";
const prodVersion = getArg("prod-version") ?? "";

fs.mkdirSync(outDir, { recursive: true });

async function fetchText(url: string): Promise<string> {
  const res = await fetch(url, { method: "GET" });
  if (!res.ok) {
    throw new Error(`GET ${url} failed (${res.status})`);
  }
  return await res.text();
}

async function authJson(url: string, method: "GET" | "POST", body?: unknown): Promise<any> {
  const res = await fetch(url, {
    method,
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${token}`,
    },
    body: method === "POST" ? JSON.stringify(body ?? {}) : undefined,
  });

  const raw = await res.text();
  let parsed: any = raw;
  try {
    parsed = raw ? JSON.parse(raw) : null;
  } catch {
    // keep text
  }

  if (!res.ok) {
    throw new Error(`${method} ${url} failed (${res.status}): ${typeof parsed === "string" ? parsed : JSON.stringify(parsed)}`);
  }

  return parsed;
}

function has(html: string, pattern: RegExp): boolean {
  return pattern.test(html);
}

function write(fileName: string, data: unknown): void {
  fs.writeFileSync(path.join(outDir, fileName), JSON.stringify(data, null, 2));
}

async function searchSmoke(base: string) {
  const api = await fetch(`${base}/api/search?q=okta&limit=8`).then(async (res) => {
    const raw = await res.text();
    let parsed: any = raw;
    try {
      parsed = raw ? JSON.parse(raw) : null;
    } catch {
      // keep string
    }
    return {
      status: res.status,
      ok: res.ok,
      body: parsed,
    };
  });

  const html = await fetchText(`${base}/glossary?q=okta`);

  return {
    apiStatus: api.status,
    apiOk: api.ok,
    apiResultCount: Number(api?.body?.count ?? 0),
    apiHasResultsArray: Array.isArray(api?.body?.results),
    htmlHasSearchHeader: has(html, /<h1>Search results<\/h1>/i),
    htmlHasQueryPill: has(html, /Query:\s*okta/i),
    htmlHasResultCards: has(html, /class="search-result-card"/i),
  };
}

async function seoSmoke(base: string) {
  const toolsHtml = await fetchText(`${base}/tools/okta`);
  const workflowsHtml = await fetchText(`${base}/workflows/contract-review-approval`);
  const searchHtml = await fetchText(`${base}/glossary?q=okta`);

  return {
    tools: {
      hasOgImageAlt: has(toolsHtml, /property="og:image:alt"/i),
      hasTwitterSite: has(toolsHtml, /name="twitter:site"/i),
      hasTwitterImageAlt: has(toolsHtml, /name="twitter:image:alt"/i),
      hasArticleSection: has(toolsHtml, /property="article:section"/i),
      hasTechArticleSchema: has(toolsHtml, /"@type":"TechArticle"/i),
      hasMetaStrip: has(toolsHtml, /class="article-meta-strip"/i),
    },
    workflows: {
      hasOgImageAlt: has(workflowsHtml, /property="og:image:alt"/i),
      hasTwitterSite: has(workflowsHtml, /name="twitter:site"/i),
      hasArticleSection: has(workflowsHtml, /property="article:section"/i),
      hasTechArticleSchema: has(workflowsHtml, /"@type":"TechArticle"/i),
      hasMetaStrip: has(workflowsHtml, /class="article-meta-strip"/i),
    },
    searchPage: {
      hasNoindexFollow: has(searchHtml, /meta name="robots" content="noindex,follow"/i),
      hasCanonicalGlossary: has(searchHtml, /link rel="canonical" href="https:\/\/www\.clawea\.com\/glossary"/i),
    },
  };
}

async function main() {
  const search = {
    generatedAt: new Date().toISOString(),
    staging: await searchSmoke(stagingBase),
    production: await searchSmoke(prodBase),
  };
  write("search-smoke.json", search);

  const queueStatusStagingBefore = await authJson(`${stagingBase}/api/index-queue/status`, "GET");
  const queueStatusProd = await authJson(`${prodBase}/api/index-queue/status`, "GET");

  const replaySeedUrls = [
    `${stagingBase}/tools/okta`,
    `${stagingBase}/workflows/contract-review-approval`,
  ];

  const enqueue = await authJson(`${stagingBase}/api/index-queue/enqueue`, "POST", {
    urls: replaySeedUrls,
    action: "URL_UPDATED",
    engines: ["all"],
    force: true,
  });

  const replayOne = await authJson(`${stagingBase}/api/index-queue/replay`, "POST", {
    maxEntries: 8,
    simulate429: true,
  });

  const replayTwo = await authJson(`${stagingBase}/api/index-queue/replay`, "POST", {
    maxEntries: 8,
    simulate429: true,
  });

  const queueStatusStagingAfter = await authJson(`${stagingBase}/api/index-queue/status`, "GET");

  write("indexing-replay-result.json", {
    generatedAt: new Date().toISOString(),
    staging: {
      enqueue,
      replayOne,
      replayTwo,
      notes: {
        expected: "replayTwo should process fewer or zero entries due to backoff nextAttemptAt scheduling",
      },
    },
  });

  write("indexing-queue-summary.json", {
    generatedAt: new Date().toISOString(),
    staging: {
      before: queueStatusStagingBefore,
      after: queueStatusStagingAfter,
    },
    production: queueStatusProd,
  });

  const now = new Date();
  const from = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);

  const conversionStaging = await authJson(`${stagingBase}/api/events/summary`, "POST", {
    from: from.toISOString(),
    to: now.toISOString(),
    days: 7,
  });

  const conversionProd = await authJson(`${prodBase}/api/events/summary`, "POST", {
    from: from.toISOString(),
    to: now.toISOString(),
    days: 7,
  });

  write("conversion-summary.json", {
    generatedAt: new Date().toISOString(),
    staging: conversionStaging,
    production: conversionProd,
  });

  write("seo-metadata-smoke.json", {
    generatedAt: new Date().toISOString(),
    staging: await seoSmoke(stagingBase),
    production: await seoSmoke(prodBase),
  });

  write("deploy-summary.json", {
    generatedAt: new Date().toISOString(),
    mergeSha,
    staging: {
      baseUrl: stagingBase,
      versionId: stagingVersion,
    },
    production: {
      baseUrl: prodBase,
      versionId: prodVersion,
    },
  });

  console.log(`Artifacts written to ${outDir}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
