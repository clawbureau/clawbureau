#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const DEFAULT_OUTPUT_ROOT = 'artifacts/ops/clawsig-canary-seed';
const FIXTURE_PATH = 'packages/schema/fixtures/protocol-conformance/proof_bundle_pass.v1.json';

const ENV_CONFIG = {
  staging: {
    ledgerHost: 'staging-api.clawverify.com',
    d1Name: 'clawsig-public-ledger-staging',
    bucketName: 'clawsig-public-bundles-staging',
    wranglerEnvArgs: ['--env', 'staging'],
  },
  prod: {
    ledgerHost: 'api.clawverify.com',
    d1Name: 'clawsig-public-ledger',
    bucketName: 'clawsig-public-bundles',
    wranglerEnvArgs: [],
  },
};

function parseArgs(argv) {
  const args = {
    env: 'all',
    outputRoot: DEFAULT_OUTPUT_ROOT,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--env') {
      args.env = argv[i + 1] ?? 'all';
      i += 1;
      continue;
    }
    if (arg === '--output-root') {
      args.outputRoot = argv[i + 1] ?? DEFAULT_OUTPUT_ROOT;
      i += 1;
      continue;
    }
  }

  if (!['all', 'staging', 'prod'].includes(args.env)) {
    throw new Error(`Invalid --env value: ${args.env}`);
  }

  return args;
}

function run(cmd, args, options = {}) {
  return execFileSync(cmd, args, {
    encoding: 'utf8',
    stdio: ['pipe', 'pipe', 'pipe'],
    ...options,
  }).trim();
}

function tryRun(cmd, args, options = {}) {
  try {
    return { ok: true, out: run(cmd, args, options) };
  } catch (error) {
    return {
      ok: false,
      out: String(error?.stdout ?? ''),
      err: String(error?.stderr ?? error?.message ?? error),
    };
  }
}

function toBase64Url(input) {
  return Buffer.from(input)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function resolveA(host) {
  const res = tryRun('dig', ['@1.1.1.1', '+short', host, 'A']);
  if (!res.ok) return [];
  return res.out.split('\n').map((x) => x.trim()).filter(Boolean);
}

function curlJsonWithResolvedHost(host, pathName) {
  const aRecords = resolveA(host);
  if (aRecords.length === 0) {
    return {
      ok: false,
      code: 'DNS_A_MISSING',
      status: null,
      body: null,
    };
  }

  const ip = aRecords[0];
  const url = `https://${host}${pathName}`;
  const res = tryRun('curl', ['-sS', '--resolve', `${host}:443:${ip}`, '-w', '\n%{http_code}', url]);
  if (!res.ok) {
    return {
      ok: false,
      code: 'CURL_FAILED',
      status: null,
      body: null,
      detail: res.err,
    };
  }

  const lines = res.out.split('\n');
  const statusRaw = lines.pop() ?? '';
  const body = lines.join('\n');
  const status = Number(statusRaw);
  if (!Number.isFinite(status)) {
    return {
      ok: false,
      code: 'HTTP_STATUS_PARSE_FAILED',
      status: null,
      body,
    };
  }

  return {
    ok: status >= 200 && status < 300,
    code: status >= 200 && status < 300 ? 'OK' : 'HTTP_NON_2XX',
    status,
    body,
  };
}

function escapeSql(value) {
  return `'${String(value).replace(/'/g, "''")}'`;
}

function nowLabel() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

function loadFixture() {
  const raw = readFileSync(FIXTURE_PATH, 'utf8');
  const parsed = JSON.parse(raw);
  return parsed;
}

function computeBundleHash(bundle) {
  const serialized = JSON.stringify(bundle);
  const digest = createHash('sha256').update(serialized).digest();
  return toBase64Url(digest);
}

function runCanarySeed(targetEnv, outputDir) {
  const config = ENV_CONFIG[targetEnv];
  if (!config) {
    throw new Error(`Unknown environment: ${targetEnv}`);
  }

  const fixture = loadFixture();
  const bundleHash = computeBundleHash(fixture);
  const runId = `run_${bundleHash.slice(0, 24)}`;
  const agentDid = String(fixture?.payload?.agent_did ?? 'did:key:unknown');
  const nowIso = new Date().toISOString();
  const modelsJson = JSON.stringify(['canary-seed']);

  const tempDir = mkdtempSync(path.join(os.tmpdir(), `clawsig-canary-${targetEnv}-`));
  const bundlePath = path.join(tempDir, `${runId}.json`);
  writeFileSync(bundlePath, JSON.stringify(fixture, null, 2));

  const insertAgentSql = `
    INSERT INTO agents (did, first_seen_at, verified_runs, gateway_tier_runs, policy_violations)
    VALUES (${escapeSql(agentDid)}, datetime('now'), 1, 0, 0)
    ON CONFLICT(did) DO UPDATE SET
      verified_runs = CASE WHEN agents.verified_runs < 1 THEN 1 ELSE agents.verified_runs END
  `;

  const upsertRunSql = `
    INSERT INTO runs (
      run_id,
      bundle_hash_b64u,
      agent_did,
      proof_tier,
      status,
      reason_code,
      failure_class,
      verification_source,
      auth_mode,
      wpc_hash_b64u,
      rt_leaf_index,
      models_json,
      created_at
    ) VALUES (
      ${escapeSql(runId)},
      ${escapeSql(bundleHash)},
      ${escapeSql(agentDid)},
      'self',
      'PASS',
      'OK',
      'none',
      'canary_seed',
      'canary',
      NULL,
      NULL,
      ${escapeSql(modelsJson)},
      datetime('now')
    )
    ON CONFLICT(run_id) DO UPDATE SET
      created_at = datetime('now'),
      status = 'PASS',
      reason_code = 'OK',
      failure_class = 'none',
      verification_source = 'canary_seed',
      auth_mode = 'canary',
      proof_tier = 'self',
      models_json = ${escapeSql(modelsJson)}
  `;

  const d1AgentArgs = ['d1', 'execute', config.d1Name, '--remote', '--command', insertAgentSql, ...config.wranglerEnvArgs];
  const d1RunArgs = ['d1', 'execute', config.d1Name, '--remote', '--command', upsertRunSql, ...config.wranglerEnvArgs];

  const d1AgentRes = tryRun('npx', ['wrangler', ...d1AgentArgs], {
    cwd: 'services/clawsig-ledger',
  });
  const d1RunRes = tryRun('npx', ['wrangler', ...d1RunArgs], {
    cwd: 'services/clawsig-ledger',
  });

  const r2Res = tryRun('npx', ['wrangler', 'r2', 'object', 'put', `${config.bucketName}/bundles/${runId}.json`, '--file', bundlePath], {
    cwd: 'services/clawsig-ledger',
  });

  const healthRes = curlJsonWithResolvedHost(config.ledgerHost, '/health');
  const latestRunRes = curlJsonWithResolvedHost(config.ledgerHost, '/v1/ledger/runs?limit=1');

  let latestRun = null;
  let latestRunValid = false;
  if (latestRunRes.ok && latestRunRes.body) {
    try {
      const parsed = JSON.parse(latestRunRes.body);
      latestRun = Array.isArray(parsed?.runs) ? parsed.runs[0] ?? null : null;
      latestRunValid = Boolean(latestRun?.run_id === runId && latestRun?.agent_did === agentDid);
    } catch {
      latestRun = null;
      latestRunValid = false;
    }
  }

  const checks = [
    {
      name: `${targetEnv}:d1-agent-upsert`,
      ok: d1AgentRes.ok,
      reason_code: d1AgentRes.ok ? 'OK' : 'D1_AGENT_UPSERT_FAILED',
    },
    {
      name: `${targetEnv}:d1-run-upsert`,
      ok: d1RunRes.ok,
      reason_code: d1RunRes.ok ? 'OK' : 'D1_RUN_UPSERT_FAILED',
    },
    {
      name: `${targetEnv}:r2-upload`,
      ok: r2Res.ok,
      reason_code: r2Res.ok ? 'OK' : 'R2_UPLOAD_FAILED',
    },
    {
      name: `${targetEnv}:health`,
      ok: healthRes.ok && healthRes.status === 200,
      reason_code: healthRes.ok ? 'OK' : healthRes.code,
      http_status: healthRes.status,
    },
    {
      name: `${targetEnv}:latest-run-reference`,
      ok: latestRunValid,
      reason_code: latestRunRes.ok ? (latestRunValid ? 'OK' : 'LATEST_RUN_REFERENCE_MISMATCH') : latestRunRes.code,
      http_status: latestRunRes.status,
    },
  ];

  const details = {
    target_env: targetEnv,
    host: config.ledgerHost,
    run_id: runId,
    agent_did: agentDid,
    bundle_hash_b64u: bundleHash,
    seeded_at: nowIso,
    d1_agent_stdout: d1AgentRes.out,
    d1_agent_stderr: d1AgentRes.err ?? null,
    d1_run_stdout: d1RunRes.out,
    d1_run_stderr: d1RunRes.err ?? null,
    r2_stdout: r2Res.out,
    r2_stderr: r2Res.err ?? null,
    latest_run: latestRun,
  };

  writeFileSync(path.join(outputDir, `${targetEnv}.details.json`), JSON.stringify(details, null, 2));

  rmSync(tempDir, { recursive: true, force: true });

  return {
    checks,
    details,
  };
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const ts = nowLabel();
  const outputDir = path.join(args.outputRoot, ts);
  mkdirSync(outputDir, { recursive: true });

  const envs = args.env === 'all' ? ['staging', 'prod'] : [args.env];

  const allChecks = [];
  const summaryEnvs = [];

  for (const envName of envs) {
    const result = runCanarySeed(envName, outputDir);
    allChecks.push(...result.checks);
    summaryEnvs.push({
      env: envName,
      run_id: result.details.run_id,
      agent_did: result.details.agent_did,
      bundle_hash_b64u: result.details.bundle_hash_b64u,
    });
  }

  const failed = allChecks.filter((check) => !check.ok);
  const summary = {
    ok: failed.length === 0,
    generated_at: new Date().toISOString(),
    output_dir: outputDir,
    environments: summaryEnvs,
    total_checks: allChecks.length,
    passed_checks: allChecks.length - failed.length,
    failed_checks: failed.length,
    failures: failed.map((check) => ({ name: check.name, reason_code: check.reason_code })),
  };

  writeFileSync(path.join(outputDir, 'checks.json'), JSON.stringify({ checks: allChecks }, null, 2));
  writeFileSync(path.join(outputDir, 'summary.json'), JSON.stringify(summary, null, 2));

  console.log(JSON.stringify(summary, null, 2));

  if (!summary.ok) {
    process.exitCode = 1;
  }
}

main();
