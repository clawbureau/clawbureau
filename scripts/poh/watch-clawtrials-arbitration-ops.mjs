#!/usr/bin/env node

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

function parseArgs(argv) {
  const out = new Map();
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith('--')) continue;
    const key = token.slice(2);
    const next = argv[i + 1];
    if (!next || next.startsWith('--')) {
      out.set(key, 'true');
      continue;
    }
    out.set(key, next);
    i += 1;
  }
  return out;
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(`ASSERT_FAILED: ${message}`);
  }
}

function nowIso() {
  return new Date().toISOString();
}

function baseUrlForEnv(envName) {
  return envName === 'prod' ? 'https://clawtrials.com' : 'https://staging.clawtrials.com';
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function classifyErrorBucket(result) {
  if (result.status >= 500) return 'server_error';
  if (!result.expected_ok) return 'contract_drift';
  if (result.error_code === 'UNAUTHORIZED') return 'unauthorized_expected';
  return 'ok';
}

async function requestJson(url, init = {}) {
  const startedAt = Date.now();
  let response;
  try {
    response = await fetch(url, init);
  } catch (err) {
    return {
      ok: false,
      status: 0,
      elapsed_ms: Date.now() - startedAt,
      text: String(err instanceof Error ? err.message : err),
      json: null,
      network_error: true,
    };
  }

  const text = await response.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }

  return {
    ok: response.ok,
    status: response.status,
    elapsed_ms: Date.now() - startedAt,
    text,
    json,
    network_error: false,
  };
}

function buildChecks(baseUrl, trialsAdminKey) {
  const checks = [
    {
      id: 'health',
      method: 'GET',
      url: `${baseUrl}/health`,
      init: {},
      expect: (res) => res.status === 200,
      contract: '200',
    },
    {
      id: 'cases_list_unauthorized',
      method: 'GET',
      url: `${baseUrl}/v1/trials/cases`,
      init: {},
      expect: (res) => res.status === 401,
      contract: '401',
    },
    {
      id: 'cases_create_unauthorized',
      method: 'POST',
      url: `${baseUrl}/v1/trials/cases`,
      init: {
        headers: {
          'content-type': 'application/json; charset=utf-8',
        },
        body: JSON.stringify({
          idempotency_key: `watch:unauth:${crypto.randomUUID()}`,
        }),
      },
      expect: (res) => res.status === 401,
      contract: '401',
    },
    {
      id: 'reports_unauthorized',
      method: 'GET',
      url: `${baseUrl}/v1/trials/reports/disputes`,
      init: {},
      expect: (res) => res.status === 401,
      contract: '401',
    },
  ];

  if (trialsAdminKey && trialsAdminKey.trim().length > 0) {
    checks.push({
      id: 'reports_authorized',
      method: 'GET',
      url: `${baseUrl}/v1/trials/reports/disputes`,
      init: {
        headers: {
          authorization: `Bearer ${trialsAdminKey.trim()}`,
        },
      },
      expect: (res) => res.status === 200 && typeof res.json?.totals?.total_cases === 'number',
      contract: '200 + totals.total_cases',
    });
  }

  return checks;
}

function aggregateResults(rows) {
  const byCheck = {};
  const errorBuckets = {
    ok: 0,
    unauthorized_expected: 0,
    contract_drift: 0,
    server_error: 0,
    network_error: 0,
  };

  let serverErrors = 0;
  let contractDrift = 0;

  for (const row of rows) {
    if (!byCheck[row.check_id]) {
      byCheck[row.check_id] = {
        count: 0,
        status_counts: {},
        p95_ms: 0,
        avg_ms: 0,
        expected_contract: row.expected_contract,
      };
    }

    const ref = byCheck[row.check_id];
    ref.count += 1;
    ref.status_counts[String(row.status)] = (ref.status_counts[String(row.status)] ?? 0) + 1;

    if (row.status >= 500 || row.network_error) {
      serverErrors += 1;
    }
    if (!row.expected_ok) {
      contractDrift += 1;
    }

    if (row.network_error) {
      errorBuckets.network_error += 1;
      continue;
    }

    const bucket = classifyErrorBucket(row);
    errorBuckets[bucket] = (errorBuckets[bucket] ?? 0) + 1;
  }

  for (const [checkId, ref] of Object.entries(byCheck)) {
    const latencies = rows
      .filter((row) => row.check_id === checkId)
      .map((row) => row.elapsed_ms)
      .filter((n) => Number.isFinite(n))
      .sort((a, b) => a - b);

    if (latencies.length > 0) {
      const p95Index = Math.min(latencies.length - 1, Math.floor(latencies.length * 0.95));
      const avg = latencies.reduce((acc, n) => acc + n, 0) / latencies.length;
      ref.p95_ms = latencies[p95Index];
      ref.avg_ms = Math.round(avg);
    }
  }

  const total = rows.length;
  return {
    total_requests: total,
    server_errors: serverErrors,
    contract_drift_count: contractDrift,
    server_error_rate_percent: total > 0 ? Math.round((serverErrors / total) * 10_000) / 100 : 0,
    error_buckets: errorBuckets,
    checks: byCheck,
  };
}

async function runEnvWatch(params) {
  const {
    envName,
    iterations,
    pauseMs,
    trialsAdminKey,
  } = params;

  const baseUrl = baseUrlForEnv(envName);
  const checks = buildChecks(baseUrl, trialsAdminKey);
  const rows = [];

  for (let i = 0; i < iterations; i += 1) {
    for (const check of checks) {
      const res = await requestJson(check.url, {
        method: check.method,
        ...check.init,
      });

      const errorCode = typeof res.json?.error === 'string' ? res.json.error : null;
      const expectedOk = check.expect(res);

      rows.push({
        env: envName,
        iteration: i + 1,
        check_id: check.id,
        method: check.method,
        path: new URL(check.url).pathname,
        status: res.status,
        elapsed_ms: res.elapsed_ms,
        expected_contract: check.contract,
        expected_ok: expectedOk,
        error_code: errorCode,
        network_error: res.network_error,
        checked_at: nowIso(),
      });
    }

    if (pauseMs > 0 && i < iterations - 1) {
      await sleep(pauseMs);
    }
  }

  return {
    env: envName,
    base_url: baseUrl,
    generated_at: nowIso(),
    iterations,
    checks: checks.map((check) => ({
      id: check.id,
      method: check.method,
      path: new URL(check.url).pathname,
      expected_contract: check.contract,
    })),
    summary: aggregateResults(rows),
    samples: rows,
  };
}

async function writeJson(filePath, payload) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
}

function makeArtifactDir(label) {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const __dirname = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.resolve(__dirname, '../..');
  const dir = path.resolve(repoRoot, 'artifacts', 'ops', 'clawtrials', `${timestamp}-${label}`);
  return { timestamp, dir };
}

async function runOnce({
  iterations,
  pauseMs,
  trialsAdminKey,
  label,
}) {
  const artifact = makeArtifactDir(label);
  const staging = await runEnvWatch({ envName: 'staging', iterations, pauseMs, trialsAdminKey });
  const prod = await runEnvWatch({ envName: 'prod', iterations, pauseMs, trialsAdminKey });

  const summary = {
    generated_at: nowIso(),
    label,
    out_dir: artifact.dir,
    staging: {
      total_requests: staging.summary.total_requests,
      server_errors: staging.summary.server_errors,
      contract_drift_count: staging.summary.contract_drift_count,
      server_error_rate_percent: staging.summary.server_error_rate_percent,
      error_buckets: staging.summary.error_buckets,
    },
    prod: {
      total_requests: prod.summary.total_requests,
      server_errors: prod.summary.server_errors,
      contract_drift_count: prod.summary.contract_drift_count,
      server_error_rate_percent: prod.summary.server_error_rate_percent,
      error_buckets: prod.summary.error_buckets,
    },
  };

  await writeJson(path.resolve(artifact.dir, 'staging.json'), staging);
  await writeJson(path.resolve(artifact.dir, 'prod.json'), prod);
  await writeJson(path.resolve(artifact.dir, 'error-buckets.json'), {
    generated_at: nowIso(),
    staging: staging.summary.error_buckets,
    prod: prod.summary.error_buckets,
  });
  await writeJson(path.resolve(artifact.dir, 'summary.json'), summary);

  return {
    ...summary,
    artifact_dir: artifact.dir,
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const mode = String(args.get('mode') || 'once').trim();
  const iterations = Number.parseInt(String(args.get('iterations') || '12'), 10);
  const pauseMs = Number.parseInt(String(args.get('pause-ms') || '200'), 10);
  const label = String(args.get('label') || '72h-watch-day1').trim();
  const durationHours = Number.parseInt(String(args.get('duration-hours') || '72'), 10);
  const intervalMinutes = Number.parseInt(String(args.get('interval-minutes') || '60'), 10);
  const trialsAdminKey = String(args.get('trials-admin-key') || process.env.TRIALS_ADMIN_KEY || '').trim();

  assert(Number.isFinite(iterations) && iterations > 0, 'iterations must be > 0');
  assert(Number.isFinite(pauseMs) && pauseMs >= 0, 'pause-ms must be >= 0');

  if (mode === 'once') {
    const out = await runOnce({
      iterations,
      pauseMs,
      trialsAdminKey,
      label,
    });
    console.log(JSON.stringify(out, null, 2));
    return;
  }

  assert(mode === 'daemon', 'mode must be once or daemon');
  assert(Number.isFinite(durationHours) && durationHours > 0, 'duration-hours must be > 0');
  assert(Number.isFinite(intervalMinutes) && intervalMinutes > 0, 'interval-minutes must be > 0');

  const startedAt = Date.now();
  const durationMs = durationHours * 60 * 60 * 1000;
  let runCount = 0;

  while (Date.now() - startedAt < durationMs) {
    runCount += 1;
    const dailyLabel = `${label}-run${String(runCount).padStart(3, '0')}`;
    const out = await runOnce({
      iterations,
      pauseMs,
      trialsAdminKey,
      label: dailyLabel,
    });
    console.log(JSON.stringify({ mode: 'daemon', run: runCount, ...out }, null, 2));

    if (Date.now() - startedAt >= durationMs) break;
    await sleep(intervalMinutes * 60 * 1000);
  }
}

main().catch((err) => {
  const message = err instanceof Error ? err.message : String(err);
  console.error(JSON.stringify({ ok: false, error: message }, null, 2));
  process.exit(1);
});
