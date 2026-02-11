#!/usr/bin/env npx tsx
/**
 * Parallel Gemini content generator for clawea.com programmatic SEO.
 *
 * Uses gemini-2.5-flash with Google Search grounding to generate
 * 10k+ articles from the taxonomy. Writes JSON files to ./articles/.
 *
 * Usage:
 *   npx tsx scripts/generate.ts                    # generate all
 *   npx tsx scripts/generate.ts --category deploy  # generate one category
 *   npx tsx scripts/generate.ts --limit 100        # generate first 100
 *   npx tsx scripts/generate.ts --dry-run          # show stats only
 *   npx tsx scripts/generate.ts --concurrency 30   # parallel workers
 *   npx tsx scripts/generate.ts --resume            # skip existing articles
 */

import { generateAllTopics, taxonomyStats, type Topic } from "./taxonomy";
import * as fs from "fs";
import * as path from "path";

// ── Config ────────────────────────────────────────────────────────

const API_KEY = process.env.GOOGLE_API_KEY;
if (!API_KEY) {
  console.error("GOOGLE_API_KEY not set");
  process.exit(1);
}

// gemini-3-flash-preview is the fast default for bulk generation
// gemini-3-pro-preview for higher quality on landing pages
const FAST_MODEL = "gemini-3-flash-preview";
const QUALITY_MODEL = "gemini-3-pro-preview";
const API_BASE = "https://generativelanguage.googleapis.com/v1beta";

const ARTICLES_DIR = path.resolve(
  process.env.CLAWEA_ARTICLES_DIR ?? path.resolve(import.meta.dirname ?? ".", "../articles"),
);
const PROGRESS_FILE = path.resolve(ARTICLES_DIR, "_progress.json");

const TEMPERATURE = Number(process.env.CLAWEA_TEMPERATURE ?? "0.7");
const MAX_OUTPUT_TOKENS_FAST = Number(process.env.CLAWEA_MAX_OUTPUT_TOKENS_FAST ?? "8192");
const MAX_OUTPUT_TOKENS_QUALITY = Number(process.env.CLAWEA_MAX_OUTPUT_TOKENS_QUALITY ?? "16384");

// ── CLI Args ──────────────────────────────────────────────────────

const args = process.argv.slice(2);
const getFlag = (name: string) => args.includes(`--${name}`);
const getArg = (name: string) => {
  const idx = args.indexOf(`--${name}`);
  return idx >= 0 && idx + 1 < args.length ? args[idx + 1] : undefined;
};

const DRY_RUN = getFlag("dry-run");
const RESUME = getFlag("resume");
const CATEGORY = getArg("category");
const SLUGS = getArg("slugs");
const LIMIT = parseInt(getArg("limit") ?? "0", 10) || 0;
const CONCURRENCY = parseInt(getArg("concurrency") ?? "25", 10);

// Use the quality model only for the highest-priority pages (to keep cost sane).
// Override if you want more quality pages:
//   CLAWEA_QUALITY_PRIORITY=0.65 npx tsx scripts/generate.ts ...
const QUALITY_PRIORITY = Number(process.env.CLAWEA_QUALITY_PRIORITY ?? "0.7");

// ── Types ─────────────────────────────────────────────────────────

interface Article {
  slug: string;
  title: string;
  category: string;
  html: string;
  description: string;
  faqs: { q: string; a: string }[];
  sources: { title: string; uri: string }[];
  model: string;
  generatedAt: string;
  tokens: { prompt: number; completion: number; total: number };
  /** Plan A: only index selected categories initially */
  indexable: boolean;
}

interface Progress {
  completed: string[];    // slugs
  failed: string[];       // slugs
  startedAt: string;
  lastUpdatedAt: string;
}

// ── Gemini API ────────────────────────────────────────────────────

async function callGemini(prompt: string, model: string, retries = 3): Promise<{
  text: string;
  sources: { title: string; uri: string }[];
  tokens: { prompt: number; completion: number; total: number };
}> {
  const url = `${API_BASE}/models/${model}:generateContent?key=${API_KEY}`;

  const body = {
    contents: [{ parts: [{ text: prompt }] }],
    tools: [{ google_search: {} }],
    generationConfig: {
      maxOutputTokens: model === QUALITY_MODEL ? MAX_OUTPUT_TOKENS_QUALITY : MAX_OUTPUT_TOKENS_FAST,
      temperature: TEMPERATURE,
    },
  };

  for (let attempt = 0; attempt < retries; attempt++) {
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });

      if (res.status === 429) {
        const wait = Math.min(2 ** attempt * 5000, 60000);
        console.log(`  [429] Rate limited, waiting ${wait / 1000}s...`);
        await sleep(wait);
        continue;
      }

      if (res.status === 503 || res.status === 500) {
        const wait = Math.min(2 ** attempt * 3000, 30000);
        console.log(`  [${res.status}] Server error, retrying in ${wait / 1000}s...`);
        await sleep(wait);
        continue;
      }

      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`Gemini API ${res.status}: ${errText.slice(0, 200)}`);
      }

      const data = await res.json() as any;
      const candidate = data.candidates?.[0];
      if (!candidate?.content?.parts) {
        throw new Error("No candidate content in response");
      }

      const text = candidate.content.parts
        .filter((p: any) => p.text)
        .map((p: any) => p.text)
        .join("");

      const grounding = candidate.groundingMetadata ?? {};
      const sources = (grounding.groundingChunks ?? [])
        .filter((c: any) => c.web)
        .map((c: any) => ({ title: c.web.title ?? "", uri: c.web.uri ?? "" }));

      const usage = data.usageMetadata ?? {};

      return {
        text,
        sources,
        tokens: {
          prompt: usage.promptTokenCount ?? 0,
          completion: usage.candidatesTokenCount ?? 0,
          total: usage.totalTokenCount ?? 0,
        },
      };
    } catch (err: any) {
      if (attempt === retries - 1) throw err;
      const wait = Math.min(2 ** attempt * 2000, 15000);
      console.log(`  [error] ${err.message?.slice(0, 100)}, retrying in ${wait / 1000}s...`);
      await sleep(wait);
    }
  }

  throw new Error("Exhausted retries");
}

// ── Article Generation ────────────────────────────────────────────

function extractMeta(html: string, title: string): { description: string; faqs: { q: string; a: string }[] } {
  const stripTags = (s: string) => s.replace(/<[^>]*>/g, " ");
  const decodeEntities = (s: string) =>
    s
      .replace(/&nbsp;/g, " ")
      .replace(/&amp;/g, "&")
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">")
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'");
  const normalize = (s: string) => decodeEntities(stripTags(s)).replace(/\s+/g, " ").trim();

  // Extract first paragraph as description (strip inline tags like <code> safely)
  const pMatch = html.match(/<p[^>]*>([\s\S]*?)<\/p>/i);
  const pText = pMatch ? normalize(pMatch[1]).slice(0, 220) : "";
  const description = pText.length >= 50 ? pText : title;

  // Extract FAQ Q&A pairs (capture full <p> content, not just text up to first tag)
  const faqs: { q: string; a: string }[] = [];
  const faqRegex = /<h[34][^>]*>([^<]*\?)<\/h[34]>\s*<p[^>]*>([\s\S]*?)<\/p>/gi;
  let match: RegExpExecArray | null;
  while ((match = faqRegex.exec(html)) !== null) {
    const q = normalize(match[1]);
    const a = normalize(match[2]);
    if (q && a) faqs.push({ q, a });
  }

  return { description, faqs };
}

async function generateArticle(topic: Topic): Promise<Article> {
  const model = topic.priority >= QUALITY_PRIORITY ? QUALITY_MODEL : FAST_MODEL;

  const result = await callGemini(topic.prompt, model);

  let html = result.text;

  // Clean up common Gemini artifacts
  html = html.replace(/```html\n?/g, "").replace(/```\n?$/g, "");

  // Add source citations if grounded
  if (result.sources.length > 0) {
    html += `\n<div class="sources" style="margin-top:2rem;padding-top:1rem;border-top:1px solid var(--border)">
<p style="font-size:.75rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:.5rem">Sources</p>
<ul style="list-style:none;padding:0">
${result.sources.slice(0, 5).map((s) => `<li style="font-size:.8rem;color:var(--text-muted);margin-bottom:.25rem"><a href="${escHtml(s.uri)}" target="_blank" rel="noopener" style="color:var(--text-secondary)">${escHtml(s.title || s.uri)}</a></li>`).join("\n")}
</ul></div>`;
  }

  // Add deploy CTA
  html += `\n<div class="cta-banner">
<h2>Ready to Deploy?</h2>
<p>Get a verified AI agent running for your team in under 10 minutes.</p>
<a href="/contact" class="cta-btn cta-btn-lg">Talk to Sales</a>
<a href="/pricing" class="cta-btn cta-btn-outline cta-btn-lg" style="margin-left:.75rem">View Pricing</a>
</div>`;

  const { description, faqs } = extractMeta(html, topic.title);

  return {
    slug: topic.slug,
    title: topic.title,
    category: topic.category,
    html,
    description,
    faqs,
    sources: result.sources,
    model,
    generatedAt: new Date().toISOString(),
    tokens: result.tokens,
    indexable: topic.indexable === true,
  };
}

// ── Progress Tracking ─────────────────────────────────────────────

function loadProgress(): Progress {
  if (fs.existsSync(PROGRESS_FILE)) {
    return JSON.parse(fs.readFileSync(PROGRESS_FILE, "utf-8"));
  }
  return { completed: [], failed: [], startedAt: new Date().toISOString(), lastUpdatedAt: new Date().toISOString() };
}

function saveProgress(progress: Progress): void {
  progress.lastUpdatedAt = new Date().toISOString();
  fs.writeFileSync(PROGRESS_FILE, JSON.stringify(progress, null, 2));
}

// ── Parallel Executor ─────────────────────────────────────────────

async function processQueue(topics: Topic[], concurrency: number): Promise<void> {
  fs.mkdirSync(ARTICLES_DIR, { recursive: true });

  const progress = loadProgress();
  const completedSet = new Set(progress.completed);

  let queue = topics;
  if (RESUME) {
    queue = topics.filter((t) => !completedSet.has(t.slug));
    console.log(`Resuming: ${topics.length - queue.length} already done, ${queue.length} remaining`);
  }

  let completed = 0;
  let failed = 0;
  let totalTokens = 0;
  const startTime = Date.now();

  const semaphore = new Array(concurrency).fill(null);

  async function worker(id: number): Promise<void> {
    while (true) {
      const topic = queue.shift();
      if (!topic) break;

      const articlePath = path.resolve(ARTICLES_DIR, topic.slug + ".json");
      const articleDir = path.dirname(articlePath);
      fs.mkdirSync(articleDir, { recursive: true });

      try {
        const article = await generateArticle(topic);
        fs.writeFileSync(articlePath, JSON.stringify(article, null, 2));

        completed++;
        totalTokens += article.tokens.total;
        progress.completed.push(topic.slug);

        const elapsed = (Date.now() - startTime) / 1000;
        const rate = completed / elapsed;
        const eta = queue.length / rate;
        const pct = ((completed / (completed + queue.length + failed)) * 100).toFixed(1);

        if (completed % 10 === 0 || completed <= 5) {
          console.log(
            `[${pct}%] ${completed}/${completed + queue.length} | ${article.model} | ${article.tokens.total}tok | ` +
            `${rate.toFixed(1)}/s | ETA ${formatTime(eta)} | ${topic.slug.slice(0, 60)}`
          );
          saveProgress(progress);
        }

        // Small delay to avoid hammering the API
        await sleep(100 + Math.random() * 200);
      } catch (err: any) {
        failed++;
        progress.failed.push(topic.slug);
        console.error(`[FAIL] ${topic.slug}: ${err.message?.slice(0, 100)}`);

        // Write error marker
        fs.writeFileSync(articlePath, JSON.stringify({ error: err.message, slug: topic.slug }, null, 2));
      }
    }
  }

  console.log(`Starting ${concurrency} workers for ${queue.length} topics...`);
  console.log(`Articles dir: ${ARTICLES_DIR}`);
  console.log(`Models: ${FAST_MODEL} (bulk), ${QUALITY_MODEL} (priority>=${QUALITY_PRIORITY})`);
  console.log(
    `Generation: temperature=${TEMPERATURE}, maxOutputTokens fast=${MAX_OUTPUT_TOKENS_FAST}, quality=${MAX_OUTPUT_TOKENS_QUALITY}`,
  );
  console.log();

  await Promise.all(semaphore.map((_, i) => worker(i)));

  saveProgress(progress);

  const elapsed = (Date.now() - startTime) / 1000;
  console.log();
  console.log("═══════════════════════════════════════════════════");
  console.log(`Done! ${completed} articles generated, ${failed} failed`);
  console.log(`Total time: ${formatTime(elapsed)}`);
  console.log(`Total tokens: ${(totalTokens / 1000).toFixed(0)}k`);
  console.log(`Avg rate: ${(completed / elapsed).toFixed(1)} articles/sec`);
  console.log(`Articles saved to: ${ARTICLES_DIR}`);
  console.log("═══════════════════════════════════════════════════");
}

// ── Helpers ───────────────────────────────────────────────────────

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function formatTime(seconds: number): string {
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
}

function escHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// ── Main ──────────────────────────────────────────────────────────

async function main(): Promise<void> {
  console.log("🔍 Claw EA Programmatic SEO Generator");
  console.log("════════════════════════════════════════\n");

  const stats = taxonomyStats();
  console.log(`Total topics in taxonomy: ${stats.total}`);
  console.log(`Indexable at launch (core sitemap): ${stats.indexable}`);
  console.log("Breakdown (total / indexable):");
  for (const [cat, count] of Object.entries(stats.breakdown).sort((a, b) => b[1] - a[1])) {
    const idx = stats.indexableBreakdown[cat] ?? 0;
    console.log(`  ${cat}: ${count} / ${idx}`);
  }
  console.log();

  if (DRY_RUN) {
    console.log("(dry run, exiting)");
    return;
  }

  let topics = generateAllTopics();

  if (CATEGORY) {
    topics = topics.filter((t) => t.category === CATEGORY);
    console.log(`Filtered to category "${CATEGORY}": ${topics.length} topics`);
  }

  if (SLUGS) {
    const wanted = new Set(
      SLUGS.split(",")
        .map((s) => s.trim())
        .filter(Boolean),
    );
    const before = topics.length;
    topics = topics.filter((t) => wanted.has(t.slug));

    const found = new Set(topics.map((t) => t.slug));
    const missing = [...wanted].filter((s) => !found.has(s));

    console.log(`Filtered to --slugs: ${topics.length}/${before} topics`);
    if (missing.length) {
      console.log(
        `Missing slugs (ignored): ${missing.slice(0, 20).join(", ")}${missing.length > 20 ? " ..." : ""}`,
      );
    }
  }

  // Sort: highest priority first
  topics.sort((a, b) => b.priority - a.priority);

  if (LIMIT > 0) {
    topics = topics.slice(0, LIMIT);
    console.log(`Limited to first ${LIMIT} topics`);
  }

  await processQueue(topics, CONCURRENCY);
}

main().catch((err) => {
  console.error("Fatal:", err);
  process.exit(1);
});
