#!/usr/bin/env npx tsx
/**
 * Human-tone lint gate for published article corpus.
 *
 * Scans article JSON files recursively under articles/, lints html + description with scripts/quality.ts,
 * writes a machine-readable report, and fails on error-level lint findings.
 */

import * as fs from "node:fs";
import * as path from "node:path";

import { lintText } from "./quality";

type ArticleRecord = {
  slug?: string;
  title?: string;
  html?: string;
  description?: string;
  indexable?: boolean;
};

const args = process.argv.slice(2);
const getArg = (name: string): string | undefined => {
  const idx = args.indexOf(`--${name}`);
  return idx >= 0 && idx + 1 < args.length ? args[idx + 1] : undefined;
};
const hasFlag = (name: string): boolean => args.includes(`--${name}`);

const root = path.resolve(getArg("dir") ?? path.resolve(import.meta.dirname ?? ".", "../articles"));
const strict = !hasFlag("no-strict");
const output = path.resolve(
  getArg("output")
    ?? path.resolve(import.meta.dirname ?? ".", `../artifacts/ops/clawea-www/human-tone-lint-${new Date().toISOString().slice(0, 10)}.json`),
);

function walkJson(dir: string): string[] {
  const out: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name.startsWith(".")) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...walkJson(full));
      continue;
    }
    if (entry.isFile() && entry.name.endsWith(".json")) {
      out.push(full);
    }
  }
  return out;
}

function safeJson(filePath: string): ArticleRecord | null {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf-8")) as ArticleRecord;
  } catch {
    return null;
  }
}

if (!fs.existsSync(root)) {
  console.error(`Directory not found: ${root}`);
  process.exit(1);
}

const files = walkJson(root);
const rows: Array<{
  file: string;
  slug: string;
  title: string;
  indexable: boolean;
  ok: boolean;
  humanToneScore: number | null;
  errors: string[];
  warns: string[];
}> = [];

for (const filePath of files) {
  const rel = path.relative(root, filePath);
  const rec = safeJson(filePath);
  if (!rec) {
    rows.push({
      file: rel,
      slug: "",
      title: "",
      indexable: false,
      ok: false,
      humanToneScore: null,
      errors: ["invalid_json"],
      warns: [],
    });
    continue;
  }

  if (typeof rec.html !== "string" || rec.html.trim().length === 0) {
    continue;
  }

  const text = `${rec.html}\n\n${rec.description ?? ""}`;
  const lint = lintText(text);
  rows.push({
    file: rel,
    slug: String(rec.slug ?? ""),
    title: String(rec.title ?? ""),
    indexable: rec.indexable !== false,
    ok: lint.ok,
    humanToneScore: typeof lint.humanTone?.score === "number" ? lint.humanTone.score : null,
    errors: lint.issues.filter((i) => i.level === "error").map((i) => i.code),
    warns: lint.issues.filter((i) => i.level === "warn").map((i) => i.code),
  });
}

const errors = rows.filter((r) => !r.ok);
const issueCounts = new Map<string, number>();
for (const row of rows) {
  for (const code of [...row.errors, ...row.warns]) {
    issueCounts.set(code, (issueCounts.get(code) ?? 0) + 1);
  }
}

const summary = {
  generatedAt: new Date().toISOString(),
  root,
  strict,
  totals: {
    scanned: rows.length,
    failed: errors.length,
    indexableScanned: rows.filter((r) => r.indexable).length,
    indexableFailed: rows.filter((r) => r.indexable && !r.ok).length,
  },
  topIssues: [...issueCounts.entries()]
    .sort((a, b) => (b[1] - a[1]) || a[0].localeCompare(b[0], "en"))
    .slice(0, 30)
    .map(([code, count]) => ({ code, count })),
  failures: errors.slice(0, 300),
};

fs.mkdirSync(path.dirname(output), { recursive: true });
fs.writeFileSync(output, JSON.stringify(summary, null, 2));

console.log(`Scanned ${rows.length} article JSON files`);
console.log(`Failures: ${errors.length}`);
console.log(`Report: ${output}`);

if (strict && errors.length > 0) {
  process.exit(1);
}
