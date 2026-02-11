#!/usr/bin/env npx tsx
/**
 * Promote writeoff outputs into production article JSON files.
 *
 * Deterministic source set:
 *  - spec.json
 *  - candidates/<candidate>.html
 *  - candidates/<candidate>.report.json
 *  - sources.json
 *
 * Usage:
 *   npx tsx scripts/promote-writeoff-run.ts --run sample-output/model-writeoff/<runId>
 *   npx tsx scripts/promote-writeoff-run.ts --run ... --candidate candidate-01
 *   npx tsx scripts/promote-writeoff-run.ts --run ... --no-clean
 */

import * as fs from "fs";
import * as path from "path";

import { generateAllTopics } from "./taxonomy";

type SourceInput = { title?: string; url?: string; uri?: string; text?: string };

type CandidateReport = {
  kind?: string;
  truncated?: boolean;
  sanitizer_failed_reason?: string | null;
  lint?: { ok?: boolean };
  structure?: {
    missingH2?: string[];
    orderOk?: boolean;
    faqCountOk?: boolean;
  };
  citations?: {
    violations?: string[];
  };
  claim_state_violations?: string[];
  endpoint_invention_violations?: string[];
  shipped_planned_mismatch?: string[];
  generatedAt?: string;
};

type ArticleOut = {
  slug: string;
  title: string;
  category: string;
  html: string;
  description: string;
  faqs: { q: string; a: string }[];
  sources: { title: string; uri: string }[];
  model: string;
  generatedAt: string;
  indexable: boolean;
};

type SkipReason =
  | "missing_spec"
  | "missing_report"
  | "missing_html"
  | "invalid_json"
  | "not_article"
  | "lint_not_ok"
  | "truncated"
  | "sanitizer_failed"
  | "citation_violations"
  | "claim_state_violations"
  | "endpoint_invention_violations"
  | "shipped_planned_mismatch"
  | "missing_h2"
  | "heading_order_invalid"
  | "faq_count_invalid"
  | "empty_html";

type SkipEntry = {
  slug: string;
  reasons: string[];
};

const args = process.argv.slice(2);
const getArg = (name: string) => {
  const idx = args.indexOf(`--${name}`);
  return idx >= 0 && idx + 1 < args.length ? args[idx + 1] : undefined;
};
const hasFlag = (name: string) => args.includes(`--${name}`);

const runArg = getArg("run");
if (!runArg) {
  console.error("Missing required --run <run-folder>");
  process.exit(1);
}

const runRoot = path.resolve(runArg);
const candidate = getArg("candidate") ?? "candidate-01";
const cleanMode = !hasFlag("--no-clean");
const articlesDir = path.resolve(getArg("articles-dir") ?? path.resolve(import.meta.dirname ?? ".", "../articles"));
const summaryPath = path.resolve(getArg("summary") ?? path.join(runRoot, "PUBLISH_SUMMARY.json"));

const topicBySlug = new Map(generateAllTopics().map((t) => [t.slug, t] as const));

function readJson<T>(file: string): T {
  return JSON.parse(fs.readFileSync(file, "utf-8")) as T;
}

function ensureDir(dir: string): void {
  fs.mkdirSync(dir, { recursive: true });
}

function removeNonInternalJsonFiles(root: string): void {
  if (!fs.existsSync(root)) return;

  const walk = (dir: string) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full);
        const remain = fs.readdirSync(full);
        if (remain.length === 0) fs.rmdirSync(full);
        continue;
      }

      if (entry.isFile() && entry.name.endsWith(".json") && !entry.name.startsWith("_")) {
        fs.unlinkSync(full);
      }
    }
  };

  walk(root);
}

function listTargetDirs(root: string): string[] {
  return fs
    .readdirSync(root, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => path.join(root, d.name))
    .filter((d) => fs.existsSync(path.join(d, "spec.json")))
    .sort((a, b) => a.localeCompare(b, "en"));
}

function decodeEntities(s: string): string {
  return s
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'");
}

function stripTags(s: string): string {
  return s.replace(/<[^>]*>/g, " ");
}

function normalizeText(s: string): string {
  return decodeEntities(stripTags(s)).replace(/\s+/g, " ").trim();
}

function extractMeta(html: string, fallbackTitle: string): { description: string; faqs: { q: string; a: string }[] } {
  const firstP = html.match(/<p[^>]*>([\s\S]*?)<\/p>/i);
  const pText = firstP ? normalizeText(firstP[1]).slice(0, 220) : "";
  const description = pText.length >= 50 ? pText : fallbackTitle;

  const faqs: { q: string; a: string }[] = [];
  const faqRegex = /<h[34][^>]*>([^<]*\?)<\/h[34]>\s*<p[^>]*>([\s\S]*?)<\/p>/gi;
  let m: RegExpExecArray | null;
  while ((m = faqRegex.exec(html)) !== null) {
    const q = normalizeText(m[1]);
    const a = normalizeText(m[2]);
    if (q && a) faqs.push({ q, a });
  }

  return { description, faqs };
}

function mapSources(src: SourceInput[]): { title: string; uri: string }[] {
  const out: { title: string; uri: string }[] = [];
  const seen = new Set<string>();

  for (const s of src) {
    const uri = String(s?.url ?? s?.uri ?? "").trim();
    if (!uri || seen.has(uri)) continue;
    seen.add(uri);

    const title = String(s?.title ?? uri).trim() || uri;
    out.push({ title, uri });
  }

  return out;
}

function reasonCounts(skipped: SkipEntry[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const s of skipped) {
    for (const r of s.reasons) {
      counts[r] = (counts[r] ?? 0) + 1;
    }
  }
  return counts;
}

function main(): void {
  if (!fs.existsSync(runRoot) || !fs.statSync(runRoot).isDirectory()) {
    console.error(`Run folder not found: ${runRoot}`);
    process.exit(1);
  }

  ensureDir(articlesDir);

  if (cleanMode) {
    removeNonInternalJsonFiles(articlesDir);
  }

  const targets = listTargetDirs(runRoot);
  const published: string[] = [];
  const skipped: SkipEntry[] = [];

  for (const targetDir of targets) {
    const specPath = path.join(targetDir, "spec.json");
    const reportPath = path.join(targetDir, "candidates", `${candidate}.report.json`);
    const htmlPath = path.join(targetDir, "candidates", `${candidate}.html`);
    const sourcesPath = path.join(targetDir, "sources.json");

    if (!fs.existsSync(specPath)) {
      skipped.push({ slug: path.basename(targetDir), reasons: ["missing_spec"] });
      continue;
    }

    let spec: any;
    try {
      spec = readJson<any>(specPath);
    } catch {
      skipped.push({ slug: path.basename(targetDir), reasons: ["invalid_json"] });
      continue;
    }

    const slug = String(spec?.slug ?? path.basename(targetDir).replace(/__/g, "/"));

    if (!fs.existsSync(reportPath)) {
      skipped.push({ slug, reasons: ["missing_report"] });
      continue;
    }
    if (!fs.existsSync(htmlPath)) {
      skipped.push({ slug, reasons: ["missing_html"] });
      continue;
    }

    let report: CandidateReport;
    try {
      report = readJson<CandidateReport>(reportPath);
    } catch {
      skipped.push({ slug, reasons: ["invalid_json"] });
      continue;
    }

    const reasons: string[] = [];

    if ((report.kind ?? "article") !== "article") reasons.push("not_article");
    if (report.lint?.ok !== true) reasons.push("lint_not_ok");
    if (report.truncated === true) reasons.push("truncated");
    if (report.sanitizer_failed_reason) reasons.push("sanitizer_failed");

    if (Array.isArray(report.citations?.violations) && report.citations!.violations!.length > 0) {
      reasons.push("citation_violations");
    }

    if (Array.isArray(report.claim_state_violations) && report.claim_state_violations.length > 0) {
      reasons.push("claim_state_violations");
    }

    if (Array.isArray(report.endpoint_invention_violations) && report.endpoint_invention_violations.length > 0) {
      reasons.push("endpoint_invention_violations");
    }

    if (Array.isArray(report.shipped_planned_mismatch) && report.shipped_planned_mismatch.length > 0) {
      reasons.push("shipped_planned_mismatch");
    }

    if (Array.isArray(report.structure?.missingH2) && report.structure!.missingH2!.length > 0) {
      reasons.push("missing_h2");
    }
    if (report.structure?.orderOk !== true) reasons.push("heading_order_invalid");
    if (report.structure?.faqCountOk !== true) reasons.push("faq_count_invalid");

    const html = fs.readFileSync(htmlPath, "utf-8").trim();
    if (!html) reasons.push("empty_html");

    if (reasons.length > 0) {
      skipped.push({ slug, reasons: [...new Set(reasons)] });
      continue;
    }

    const topic = topicBySlug.get(slug);
    const category = topic?.category ?? (slug.includes("/") ? slug.split("/")[0] : "pillars");
    const title = String(spec?.title ?? topic?.title ?? slug);

    const sourceRows = fs.existsSync(sourcesPath) ? readJson<SourceInput[]>(sourcesPath) : [];
    const sources = mapSources(sourceRows);
    const meta = extractMeta(html, title);

    const article: ArticleOut = {
      slug,
      title,
      category,
      html,
      description: meta.description,
      faqs: meta.faqs,
      sources,
      model: candidate,
      generatedAt: report.generatedAt ?? new Date(0).toISOString(),
      indexable: true,
    };

    const outPath = path.join(articlesDir, `${slug}.json`);
    ensureDir(path.dirname(outPath));
    fs.writeFileSync(outPath, JSON.stringify(article, null, 2));
    published.push(slug);
  }

  published.sort((a, b) => a.localeCompare(b, "en"));
  skipped.sort((a, b) => a.slug.localeCompare(b.slug, "en"));

  const summary = {
    runId: path.basename(runRoot),
    runRoot,
    candidate,
    cleanMode,
    totalTargets: targets.length,
    publishedCount: published.length,
    skippedCount: skipped.length,
    publishedSlugs: published,
    skipped,
    reasonCounts: reasonCounts(skipped),
    generatedAt: new Date().toISOString(),
  };

  fs.writeFileSync(summaryPath, JSON.stringify(summary, null, 2));
  fs.writeFileSync(path.join(articlesDir, "_publish_summary.json"), JSON.stringify(summary, null, 2));

  console.log(`Promoted ${published.length}/${targets.length} targets from ${path.basename(runRoot)} using ${candidate}`);
  console.log(`Summary: ${summaryPath}`);
}

main();
