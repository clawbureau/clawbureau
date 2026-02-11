#!/usr/bin/env npx tsx
/**
 * Aggregate council-review results across a run folder.
 *
 * Usage:
 *   npx tsx scripts/council-aggregate.ts --run sample-output/model-writeoff/<runId>
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

const runId = path.basename(runRoot);

const councilRoot = path.join(runRoot, "council");
if (!fs.existsSync(councilRoot)) {
  console.error(`No council folder at: ${councilRoot}`);
  process.exit(1);
}

const privateMapPath = path.join(
  process.env.HOME ?? "~",
  ".clawbureau-secrets",
  `clawea-model-writeoff-map.${runId}.json`,
);

const privateMap = fs.existsSync(privateMapPath)
  ? JSON.parse(fs.readFileSync(privateMapPath, "utf-8"))
  : null;

function average(nums: number[]): number {
  if (!nums.length) return 0;
  return nums.reduce((a, b) => a + b, 0) / nums.length;
}

function safeFolderNameFromSlug(slug: string): string {
  return slug.replace(/\//g, "__");
}

type TargetAgg = {
  slug: string;
  winnerCandidate: string;
  winnerMeanOverall: number | null;
  candidates: Array<{ candidate: string; meanOverall: number | null; model?: string }>;
};

const targets: TargetAgg[] = [];

for (const ent of fs.readdirSync(councilRoot, { withFileTypes: true })) {
  if (!ent.isDirectory()) continue;
  const summaryPath = path.join(councilRoot, ent.name, "summary.json");
  if (!fs.existsSync(summaryPath)) continue;

  const sum = JSON.parse(fs.readFileSync(summaryPath, "utf-8")) as any;
  const slug = String(sum?.target?.slug ?? "");
  const winner = String(sum?.consensus?.ranking?.[0] ?? "");
  if (!slug || !winner) continue;

  const byCand = sum?.consensus?.byCandidate ?? {};

  const modelsByCandidate = privateMap?.articles?.[slug]?.candidates ?? {};

  const candidates = Object.keys(byCand)
    .sort((a, b) => a.localeCompare(b, "en"))
    .map((candidate) => ({
      candidate,
      meanOverall: typeof byCand[candidate]?.meanOverall === "number" ? byCand[candidate].meanOverall : null,
      model: modelsByCandidate[candidate] ? String(modelsByCandidate[candidate]) : undefined,
    }));

  targets.push({
    slug,
    winnerCandidate: winner,
    winnerMeanOverall: typeof byCand[winner]?.meanOverall === "number" ? byCand[winner].meanOverall : null,
    candidates,
  });
}

targets.sort((a, b) => a.slug.localeCompare(b.slug, "en"));

// Aggregate win counts by model if private map is available.
const winCounts: Record<string, number> = {};
const meanScoresByModel: Record<string, number[]> = {};

for (const t of targets) {
  const winnerModel = t.candidates.find((c) => c.candidate === t.winnerCandidate)?.model;
  if (winnerModel) winCounts[winnerModel] = (winCounts[winnerModel] ?? 0) + 1;

  for (const c of t.candidates) {
    if (!c.model || typeof c.meanOverall !== "number") continue;
    meanScoresByModel[c.model] ??= [];
    meanScoresByModel[c.model].push(c.meanOverall);
  }
}

const modelMeans = Object.fromEntries(
  Object.entries(meanScoresByModel)
    .map(([model, scores]) => [model, average(scores)])
    .sort((a, b) => (b[1] as number) - (a[1] as number)),
);

const out = {
  runId,
  targetCount: targets.length,
  winCounts: privateMap ? winCounts : undefined,
  meanOverallByModel: privateMap ? modelMeans : undefined,
  targets: targets.map((t) => ({
    slug: t.slug,
    winnerCandidate: t.winnerCandidate,
    winnerModel: privateMap ? t.candidates.find((c) => c.candidate === t.winnerCandidate)?.model ?? null : undefined,
    winnerMeanOverall: t.winnerMeanOverall,
    candidates: t.candidates.map((c) => ({
      candidate: c.candidate,
      meanOverall: c.meanOverall,
      model: privateMap ? c.model ?? null : undefined,
    })),
  })),
};

const outDir = path.join(councilRoot);
fs.writeFileSync(path.join(outDir, "aggregate.internal.json"), JSON.stringify(out, null, 2));

const mdLines: string[] = [];
mdLines.push(`# Council aggregate (internal)`);
mdLines.push("");
mdLines.push(`Run: ${runId}`);
mdLines.push(`Targets: ${targets.length}`);
mdLines.push("");

if (privateMap) {
  mdLines.push("Win counts by writer model:");
  for (const [m, n] of Object.entries(winCounts).sort((a, b) => b[1] - a[1])) {
    mdLines.push(`- ${m}: ${n}/${targets.length}`);
  }
  mdLines.push("");

  mdLines.push("Mean overall score by writer model (across all candidates):");
  for (const [m, mean] of Object.entries(modelMeans)) {
    mdLines.push(`- ${m}: ${mean.toFixed(3)}`);
  }
  mdLines.push("");
}

mdLines.push("Per-target winners:");
for (const t of targets) {
  const winnerModel = privateMap ? (t.candidates.find((c) => c.candidate === t.winnerCandidate)?.model ?? "(unknown)") : "(hidden)";
  mdLines.push(`- /${t.slug}: ${t.winnerCandidate} ${privateMap ? `(${winnerModel})` : ""}`);
}

fs.writeFileSync(path.join(outDir, "aggregate.internal.md"), mdLines.join("\n") + "\n");

// Blind aggregate (no model names)
const blind = {
  runId,
  targetCount: targets.length,
  targets: targets.map((t) => ({
    slug: t.slug,
    winnerCandidate: t.winnerCandidate,
    winnerMeanOverall: t.winnerMeanOverall,
  })),
};

fs.writeFileSync(path.join(outDir, "aggregate.blind.json"), JSON.stringify(blind, null, 2));
fs.writeFileSync(
  path.join(outDir, "aggregate.blind.md"),
  `# Council aggregate (blind)\n\nRun: ${runId}\nTargets: ${targets.length}\n\nPer-target winners:\n${targets
    .map((t) => `- /${t.slug}: ${t.winnerCandidate}`)
    .join("\n")}\n`,
);

console.log(`Wrote:\n- ${path.join(outDir, "aggregate.internal.md")}\n- ${path.join(outDir, "aggregate.blind.md")}`);
console.log(`Private map used: ${privateMap ? privateMapPath : "(not found)"}`);
