#!/usr/bin/env npx tsx
/**
 * Create a WINNERS/ folder for a write-off run by copying the council-selected
 * winner candidate per target.
 *
 * - Reads council summaries (prefers council/aggregate.blind.json).
 * - Copies winning candidate HTML/JSON into WINNERS/<slug>.html|.json
 * - Writes WINNERS/index.md linking to each page.
 * - Keeps outputs anonymized: includes candidate IDs, not model IDs.
 *
 * Usage:
 *   npx tsx scripts/make-winners.ts --run sample-output/model-writeoff/<runId>
 */

import * as fs from "fs";
import * as path from "path";

const args = process.argv.slice(2);
const getArg = (name: string) => {
  const idx = args.indexOf(`--${name}`);
  return idx >= 0 && idx + 1 < args.length ? args[idx + 1] : undefined;
};

const runArg = getArg("run");
if (!runArg) {
  console.error("Missing --run <run-folder>");
  process.exit(1);
}

const runRoot = path.resolve(runArg);
if (!fs.existsSync(runRoot) || !fs.statSync(runRoot).isDirectory()) {
  console.error(`Run folder not found: ${runRoot}`);
  process.exit(1);
}

function ensureDir(p: string): void {
  fs.mkdirSync(p, { recursive: true });
}

function safeFolderFromSlug(slug: string): string {
  return slug.replace(/\//g, "__");
}

function normalizeSlug(s: string): string {
  return s.replace(/^\//, "");
}

type WinnerRow = { slug: string; winnerCandidate: string };

function loadWinnersFromAggregate(councilRoot: string): WinnerRow[] | null {
  const agg = path.join(councilRoot, "aggregate.blind.json");
  if (!fs.existsSync(agg)) return null;
  const data = JSON.parse(fs.readFileSync(agg, "utf-8")) as any;
  const targets = Array.isArray(data?.targets) ? data.targets : [];
  const rows: WinnerRow[] = [];
  for (const t of targets) {
    const slug = normalizeSlug(String(t?.slug ?? ""));
    const winnerCandidate = String(t?.winnerCandidate ?? "");
    if (!slug || !winnerCandidate) continue;
    rows.push({ slug, winnerCandidate });
  }
  return rows.length ? rows : null;
}

function loadWinnersFromSummaries(councilRoot: string): WinnerRow[] {
  const rows: WinnerRow[] = [];
  for (const ent of fs.readdirSync(councilRoot, { withFileTypes: true })) {
    if (!ent.isDirectory()) continue;
    const summaryPath = path.join(councilRoot, ent.name, "summary.json");
    if (!fs.existsSync(summaryPath)) continue;
    const sum = JSON.parse(fs.readFileSync(summaryPath, "utf-8")) as any;
    const slug = normalizeSlug(String(sum?.target?.slug ?? ""));
    const winner = String(sum?.consensus?.ranking?.[0] ?? "");
    if (!slug || !winner) continue;
    rows.push({ slug, winnerCandidate: winner });
  }
  return rows;
}

async function main(): Promise<void> {
  const councilRoot = path.join(runRoot, "council");
  if (!fs.existsSync(councilRoot)) {
    console.error(`No council folder found at: ${councilRoot}`);
    process.exit(1);
  }

  const winners = loadWinnersFromAggregate(councilRoot) ?? loadWinnersFromSummaries(councilRoot);
  if (!winners.length) {
    console.error("No winners found in council outputs.");
    process.exit(1);
  }

  winners.sort((a, b) => a.slug.localeCompare(b.slug, "en"));

  const winnersRoot = path.join(runRoot, "WINNERS");
  ensureDir(winnersRoot);

  const indexLines: string[] = [];
  indexLines.push("# WINNERS (blind)\n");
  indexLines.push(`Run: ${path.basename(runRoot)}\n`);
  indexLines.push("Each file is the council-selected winning candidate for that slug.\n");

  for (const w of winners) {
    const slug = normalizeSlug(w.slug);
    const targetDir = path.join(runRoot, safeFolderFromSlug(slug));
    const specPath = path.join(targetDir, "spec.json");
    if (!fs.existsSync(specPath)) {
      console.error(`Missing spec.json for target ${slug}: ${specPath}`);
      continue;
    }

    const spec = JSON.parse(fs.readFileSync(specPath, "utf-8")) as any;
    const kind = String(spec?.kind ?? "article");

    const ext = kind === "wizard" ? "json" : "html";
    const src = path.join(targetDir, "candidates", `${w.winnerCandidate}.${ext}`);
    if (!fs.existsSync(src)) {
      console.error(`Missing winner candidate file for ${slug}: ${src}`);
      continue;
    }

    const dest = path.join(winnersRoot, `${slug}.${ext}`);
    ensureDir(path.dirname(dest));
    fs.copyFileSync(src, dest);

    const rel = path.relative(winnersRoot, dest);
    indexLines.push(`- [/${slug}](${rel})  (winner: ${w.winnerCandidate})`);
  }

  fs.writeFileSync(path.join(winnersRoot, "index.md"), indexLines.join("\n") + "\n");

  console.log(`Wrote winners folder: ${winnersRoot}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
