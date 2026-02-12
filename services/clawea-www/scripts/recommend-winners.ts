#!/usr/bin/env npx tsx
/**
 * Run guardrailed experiment winner recommendation and persist local artifact.
 */

import * as fs from "node:fs";
import * as path from "node:path";

const args = process.argv.slice(2);
const getArg = (name: string): string | undefined => {
  const idx = args.indexOf(`--${name}`);
  return idx >= 0 && idx + 1 < args.length ? args[idx + 1] : undefined;
};

const TOKEN = process.env.LEADS_API_TOKEN
  ?? process.env.INDEX_AUTOMATION_TOKEN
  ?? process.env.CLAWEA_INDEX_AUTOMATION_TOKEN;

if (!TOKEN) {
  console.error("Missing LEADS_API_TOKEN or INDEX_AUTOMATION_TOKEN");
  process.exit(1);
}

const base = (getArg("base") ?? process.env.CLAWEA_BASE_URL ?? "https://www.clawea.com").replace(/\/+$/, "");
const endpoint = getArg("endpoint") ?? `${base}/api/experiments/recommend`;
const days = Math.max(1, Math.min(90, Number(getArg("days") ?? "7")));

const outFile = path.resolve(
  getArg("output")
    ?? path.resolve(import.meta.dirname ?? ".", `../artifacts/ops/clawea-www/experiment-recommend-${new Date().toISOString().replace(/[:]/g, "-")}.json`),
);

async function main(): Promise<void> {
  const res = await fetch(endpoint, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${TOKEN}`,
    },
    body: JSON.stringify({ days }),
  });

  const raw = await res.text();
  let parsed: any = raw;
  try {
    parsed = raw ? JSON.parse(raw) : null;
  } catch {
    // raw fallback
  }

  if (!res.ok) {
    console.error(`Recommendation request failed (${res.status})`);
    console.error(typeof parsed === "string" ? parsed : JSON.stringify(parsed, null, 2));
    process.exit(1);
  }

  fs.mkdirSync(path.dirname(outFile), { recursive: true });
  fs.writeFileSync(outFile, JSON.stringify(parsed, null, 2));

  console.log(`Recommendation response written: ${outFile}`);
  console.log(JSON.stringify(parsed, null, 2));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
