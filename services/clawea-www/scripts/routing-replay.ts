#!/usr/bin/env npx tsx
/**
 * Replay dead-lettered lead routing jobs.
 *
 * Usage:
 *   LEADS_API_TOKEN=... npx tsx scripts/routing-replay.ts --base https://www.clawea.com --limit 10
 *   LEADS_API_TOKEN=... npx tsx scripts/routing-replay.ts --job-id route_job_abc --job-id route_job_def --execute --force
 */

import * as fs from "node:fs";
import * as path from "node:path";

const args = process.argv.slice(2);

const getArg = (name: string): string | undefined => {
  const idx = args.indexOf(`--${name}`);
  return idx >= 0 && idx + 1 < args.length ? args[idx + 1] : undefined;
};

const getArgs = (name: string): string[] => {
  const out: string[] = [];
  for (let i = 0; i < args.length; i += 1) {
    if (args[i] === `--${name}` && i + 1 < args.length) {
      out.push(args[i + 1]);
      i += 1;
    }
  }
  return out;
};

const hasFlag = (name: string): boolean => args.includes(`--${name}`);

const TOKEN = process.env.LEADS_API_TOKEN
  ?? process.env.INDEX_AUTOMATION_TOKEN
  ?? process.env.CLAWEA_INDEX_AUTOMATION_TOKEN;

if (!TOKEN) {
  console.error("Missing LEADS_API_TOKEN or INDEX_AUTOMATION_TOKEN");
  process.exit(1);
}

const base = (getArg("base") ?? process.env.CLAWEA_BASE_URL ?? "https://www.clawea.com").replace(/\/+$/, "");
const endpoint = getArg("endpoint") ?? `${base}/api/routing/replay`;
const limit = Math.max(1, Math.min(100, Number(getArg("limit") ?? "10")));
const maxAgeHours = Math.max(1, Math.min(24 * 30, Number(getArg("max-age-hours") ?? "336")));
const jobIds = getArgs("job-id").map((v) => v.trim()).filter(Boolean);
const execute = hasFlag("execute");
const force = hasFlag("force");
const includeReplayed = hasFlag("include-replayed");

const outFile = path.resolve(
  getArg("output")
    ?? path.resolve(import.meta.dirname ?? ".", `../artifacts/ops/clawea-www/routing-replay-${new Date().toISOString().replace(/[:]/g, "-")}.json`),
);

async function main(): Promise<void> {
  const body: Record<string, unknown> = {
    limit,
    maxAgeHours,
    dryRun: !execute,
    includeReplayed,
  };
  if (execute) body.confirm = "replay";
  if (force) body.force = true;
  if (jobIds.length > 0) body.jobIds = jobIds;

  const res = await fetch(endpoint, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${TOKEN}`,
    },
    body: JSON.stringify(body),
  });

  const raw = await res.text();
  let parsed: any = raw;
  try {
    parsed = raw ? JSON.parse(raw) : null;
  } catch {
    // raw text fallback
  }

  if (!res.ok) {
    console.error(`Routing replay failed (${res.status})`);
    console.error(typeof parsed === "string" ? parsed : JSON.stringify(parsed, null, 2));
    process.exit(1);
  }

  fs.mkdirSync(path.dirname(outFile), { recursive: true });
  fs.writeFileSync(outFile, JSON.stringify(parsed, null, 2));

  console.log(`Routing replay response written: ${outFile}`);
  console.log(JSON.stringify(parsed, null, 2));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
