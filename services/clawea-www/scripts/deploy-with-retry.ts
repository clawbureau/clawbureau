#!/usr/bin/env npx tsx
/*
 * Deploy wrapper with retry for transient Cloudflare API failures.
 * Records deploy attempts to an artifact JSON file.
 */

import { spawn } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";

type DeployAttempt = {
  attempt: number;
  startedAt: string;
  finishedAt: string;
  durationMs: number;
  exitCode: number | null;
  ok: boolean;
  retryableErrorCodes: number[];
  versionId?: string;
  worker?: string;
  outputTail: string;
};

type DeployArtifact = {
  generatedAt: string;
  cwd: string;
  env?: string;
  command: string;
  maxAttempts: number;
  retryCodes: number[];
  attempts: DeployAttempt[];
  result: {
    ok: boolean;
    versionId?: string;
    worker?: string;
    attempts: number;
  };
};

const args = process.argv.slice(2);
const getArg = (name: string): string | undefined => {
  const idx = args.indexOf(`--${name}`);
  return idx >= 0 && idx + 1 < args.length ? args[idx + 1] : undefined;
};

const envName = getArg("env");
const outFile = getArg("artifact") ?? "";
const maxAttempts = Math.max(1, Math.min(8, Number(getArg("max-attempts") ?? "4")));
const retryCodes = String(getArg("retry-codes") ?? "10013")
  .split(",")
  .map((s) => Number(s.trim()))
  .filter((n) => Number.isFinite(n));

function nowIso(): string {
  return new Date().toISOString();
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function parseRetryableCodes(output: string, allow: number[]): number[] {
  const found = new Set<number>();
  for (const code of allow) {
    if (!Number.isFinite(code)) continue;
    const re = new RegExp(`\\b${code}\\b`);
    if (re.test(output)) found.add(code);
  }
  return [...found.values()].sort((a, b) => a - b);
}

function parseVersionId(output: string): string | undefined {
  const m = output.match(/Version ID:\s*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/i);
  return m?.[1];
}

function parseWorkerName(output: string): string | undefined {
  // Wrangler output varies; try a couple patterns.
  const m1 = output.match(/Uploaded\s+([^\s]+)\s+\(/i);
  if (m1?.[1]) return m1[1];

  const m2 = output.match(/Deploying\s+([^\s]+)\s+\(/i);
  if (m2?.[1]) return m2[1];

  return undefined;
}

async function runOnce(command: string): Promise<{ exitCode: number | null; output: string }> {
  return await new Promise((resolve) => {
    const child = spawn(command, {
      shell: true,
      stdio: ["ignore", "pipe", "pipe"],
      env: process.env,
    });

    let buf = "";
    child.stdout.on("data", (chunk) => {
      const s = String(chunk);
      process.stdout.write(s);
      buf += s;
    });
    child.stderr.on("data", (chunk) => {
      const s = String(chunk);
      process.stderr.write(s);
      buf += s;
    });

    child.on("close", (code) => {
      resolve({ exitCode: code, output: buf });
    });
  });
}

async function main(): Promise<void> {
  if (!outFile) {
    console.error("Missing --artifact <path>");
    process.exit(2);
  }

  const wranglerArgs = ["deploy"];
  if (envName) wranglerArgs.push("--env", envName);
  const command = `npx wrangler ${wranglerArgs.join(" ")}`;

  const artifact: DeployArtifact = {
    generatedAt: nowIso(),
    cwd: process.cwd(),
    env: envName,
    command,
    maxAttempts,
    retryCodes,
    attempts: [],
    result: { ok: false, attempts: 0 },
  };

  let lastVersionId: string | undefined;
  let lastWorker: string | undefined;

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    const started = Date.now();
    const startedAt = nowIso();

    const { exitCode, output } = await runOnce(command);

    const finished = Date.now();
    const finishedAt = nowIso();

    const versionId = parseVersionId(output);
    const worker = parseWorkerName(output);
    const retryableErrorCodes = parseRetryableCodes(output, retryCodes);
    const ok = exitCode === 0;

    if (versionId) lastVersionId = versionId;
    if (worker) lastWorker = worker;

    artifact.attempts.push({
      attempt,
      startedAt,
      finishedAt,
      durationMs: finished - started,
      exitCode,
      ok,
      retryableErrorCodes,
      versionId,
      worker,
      outputTail: output.slice(-6000),
    });

    if (ok) {
      artifact.result = { ok: true, versionId, worker, attempts: attempt };
      break;
    }

    if (retryableErrorCodes.length > 0 && attempt < maxAttempts) {
      const backoffMs = Math.min(30_000, 2_000 * Math.pow(2, attempt - 1));
      console.error(`Deploy attempt ${attempt} failed with retryable codes ${retryableErrorCodes.join(",")} — retrying in ${backoffMs}ms...`);
      await sleep(backoffMs);
      continue;
    }

    artifact.result = { ok: false, versionId: lastVersionId, worker: lastWorker, attempts: attempt };
    break;
  }

  fs.mkdirSync(path.dirname(outFile), { recursive: true });
  fs.writeFileSync(outFile, JSON.stringify(artifact, null, 2));

  if (!artifact.result.ok) {
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
