#!/usr/bin/env npx tsx
/**
 * Pull weekly conversion telemetry from clawea-www and write local artifacts.
 *
 * Usage:
 *   npx tsx scripts/weekly-conversion-summary.ts
 *   INDEX_AUTOMATION_TOKEN=... npx tsx scripts/weekly-conversion-summary.ts --days 7
 *   npx tsx scripts/weekly-conversion-summary.ts --output reports/conversion/2026-02-11.json
 */

import * as fs from "fs";
import * as path from "path";

const args = process.argv.slice(2);
const getArg = (name: string) => {
  const idx = args.indexOf(`--${name}`);
  return idx >= 0 && idx + 1 < args.length ? args[idx + 1] : undefined;
};

const ENDPOINT = getArg("endpoint") ?? process.env.CLAWEA_EVENTS_SUMMARY_ENDPOINT ?? "https://clawea.com/api/events/summary";
const DAYS = Math.max(1, Math.min(56, Number(getArg("days") ?? process.env.CLAWEA_CONVERSION_DAYS ?? "7")));
const TOKEN = process.env.INDEX_AUTOMATION_TOKEN ?? process.env.CLAWEA_INDEX_AUTOMATION_TOKEN;

if (!TOKEN) {
  console.error("Missing INDEX_AUTOMATION_TOKEN (or CLAWEA_INDEX_AUTOMATION_TOKEN)");
  process.exit(1);
}

const stamp = new Date().toISOString().slice(0, 10);
const outJson = path.resolve(
  getArg("output") ?? path.resolve(import.meta.dirname ?? ".", `../reports/conversion/weekly-${stamp}.json`),
);
const outMd = path.resolve(
  getArg("markdown") ?? path.resolve(import.meta.dirname ?? ".", `../reports/conversion/weekly-${stamp}.md`),
);

function writeJson(filePath: string, data: unknown): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

function pickTopRows(rows: any[] | undefined, limit = 8): Array<{ key: string; count: number }> {
  if (!Array.isArray(rows)) return [];
  return rows
    .filter((r) => typeof r?.key === "string" && Number.isFinite(Number(r?.count)))
    .slice(0, limit)
    .map((r) => ({ key: String(r.key), count: Number(r.count) }));
}

function toBullet(rows: Array<{ key: string; count: number }>, fallback = "- none"): string {
  if (!rows.length) return fallback;
  return rows.map((r) => `- ${r.key}: ${r.count}`).join("\n");
}

async function main() {
  const res = await fetch(ENDPOINT, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${TOKEN}`,
    },
    body: JSON.stringify({ days: DAYS }),
  });

  const raw = await res.text();
  let parsed: any = raw;
  try {
    parsed = raw ? JSON.parse(raw) : null;
  } catch {
    // keep text
  }

  if (!res.ok || !parsed || parsed.ok !== true) {
    console.error(`Failed conversion summary (${res.status})`);
    console.error(typeof parsed === "string" ? parsed : JSON.stringify(parsed, null, 2));
    process.exit(1);
  }

  writeJson(outJson, parsed);

  const totals = parsed.totals ?? {};
  const md = `# clawea.com Weekly Conversion Summary\n\n` +
    `- generatedAt: ${parsed.generatedAt ?? new Date().toISOString()}\n` +
    `- periodDays: ${parsed.days ?? DAYS}\n` +
    `- totalEvents: ${Number(totals.events ?? 0)}\n` +
    `- contactIntentViews: ${Number(totals.contactIntentViews ?? 0)}\n` +
    `- contactIntentActions: ${Number(totals.contactIntentActions ?? 0)}\n` +
    `- intentToActionRate: ${Number(totals.intentToActionRate ?? 0)}\n\n` +
    `## Top Sources\n${toBullet(pickTopRows(parsed.breakdown?.bySource))}\n\n` +
    `## Top Pages\n${toBullet(pickTopRows(parsed.breakdown?.topPages))}\n\n` +
    `## Top CTAs\n${toBullet(pickTopRows(parsed.breakdown?.topCtas))}\n`;

  fs.mkdirSync(path.dirname(outMd), { recursive: true });
  fs.writeFileSync(outMd, md);

  console.log(`Wrote ${outJson}`);
  console.log(`Wrote ${outMd}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
