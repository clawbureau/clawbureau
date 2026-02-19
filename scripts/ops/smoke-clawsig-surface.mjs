#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';

const OUTPUT_ROOT_DEFAULT = 'artifacts/ops/clawsig-synthetic';
const DEFAULT_MAX_RUN_REF_AGE_MINUTES = 180;

const SLO_TARGET_SUCCESS_RATE = 0.99;
const SLO_ERROR_BUDGET = 1 - SLO_TARGET_SUCCESS_RATE;
const SLO_WARN_BURN_RATE_24H = 1;
const SLO_WARN_BURN_RATE_7D = 1;
const SLO_CRITICAL_BURN_RATE_24H = 2;
const SLO_CRITICAL_BURN_RATE_7D = 1.5;

function parseArgs(argv) {
  const args = {
    outputRoot: OUTPUT_ROOT_DEFAULT,
    maxRunRefAgeMinutes: DEFAULT_MAX_RUN_REF_AGE_MINUTES,
    env: 'all',
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--output-root') {
      args.outputRoot = argv[i + 1] ?? OUTPUT_ROOT_DEFAULT;
      i += 1;
      continue;
    }

    if (arg === '--max-run-ref-age-minutes') {
      const parsed = Number.parseInt(argv[i + 1] ?? '', 10);
      if (!Number.isFinite(parsed) || parsed <= 0) {
        throw new Error('Invalid --max-run-ref-age-minutes value');
      }
      args.maxRunRefAgeMinutes = parsed;
      i += 1;
      continue;
    }

    if (arg === '--env') {
      args.env = (argv[i + 1] ?? 'all').trim().toLowerCase();
      i += 1;
      continue;
    }
  }

  if (!['all', 'staging', 'prod'].includes(args.env)) {
    throw new Error('Invalid --env value: expected all, staging, or prod');
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
    const out = run(cmd, args, options);
    return { ok: true, out };
  } catch (error) {
    return {
      ok: false,
      out: String(error?.stdout ?? ''),
      err: String(error?.stderr ?? error?.message ?? error),
    };
  }
}

function resolveRecords(host, type) {
  const res = tryRun('dig', ['@1.1.1.1', '+short', host, type]);
  if (!res.ok) return [];
  return res.out.split('\n').map((x) => x.trim()).filter(Boolean);
}

function curlViaResolvedHost(host, pathName) {
  const aRecords = resolveRecords(host, 'A');
  if (aRecords.length === 0) {
    return {
      ok: false,
      code: 'DNS_A_MISSING',
      status: null,
      body: null,
      ip: null,
      url: `https://${host}${pathName}`,
    };
  }

  const ip = aRecords[0];
  const url = `https://${host}${pathName}`;
  const result = tryRun('curl', [
    '-sS',
    '--resolve', `${host}:443:${ip}`,
    '-w', '\n%{http_code}',
    url,
  ]);

  if (!result.ok) {
    return {
      ok: false,
      code: 'CURL_FAILED',
      status: null,
      body: null,
      ip,
      url,
      detail: result.err,
    };
  }

  const lines = result.out.split('\n');
  const statusRaw = lines.pop() ?? '';
  const body = lines.join('\n');
  const status = Number(statusRaw);
  if (!Number.isFinite(status)) {
    return {
      ok: false,
      code: 'HTTP_STATUS_PARSE_FAILED',
      status: null,
      body,
      ip,
      url,
    };
  }

  return {
    ok: status >= 200 && status < 300,
    code: status >= 200 && status < 300 ? 'OK' : 'HTTP_NON_2XX',
    status,
    body,
    ip,
    url,
  };
}

function tlsCheck(host) {
  const aRecords = resolveRecords(host, 'A');
  if (aRecords.length === 0) {
    return {
      ok: false,
      code: 'DNS_A_MISSING',
      cert: null,
    };
  }

  const ip = aRecords[0];
  const script = `echo | openssl s_client -servername ${host} -connect ${ip}:443 2>/dev/null | openssl x509 -noout -subject -issuer -dates`;
  const res = tryRun('bash', ['-lc', script]);
  if (!res.ok) {
    return {
      ok: false,
      code: 'TLS_HANDSHAKE_FAILED',
      cert: null,
      detail: res.err,
    };
  }

  return {
    ok: true,
    code: 'OK',
    cert: res.out,
  };
}

function nowTimestamp() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

function markerForPage(pathName) {
  if (pathName === '/') return 'Clawsig Explorer';
  if (pathName === '/runs') return 'Runs Feed';
  if (pathName === '/stats') return 'Network Statistics';
  if (pathName === '/run/:id') return 'Verification Run';
  if (pathName === '/agent/:did') return 'Agent Profile';
  return null;
}

function pushCheck(checks, data) {
  checks.push({
    ...data,
    checked_at: new Date().toISOString(),
  });
}

function parseRunTimestamp(rawTimestamp) {
  if (typeof rawTimestamp !== 'string' || rawTimestamp.trim().length === 0) {
    return null;
  }

  const trimmed = rawTimestamp.trim();
  const isoLike = trimmed.includes('T') ? trimmed : `${trimmed.replace(' ', 'T')}Z`;
  const parsed = new Date(isoLike);
  if (Number.isNaN(parsed.getTime())) {
    return null;
  }

  return parsed;
}

function toFiniteNumber(value, fallback = 0) {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string') {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return fallback;
}

function computeSloSeverity(window24hBurnRate, window7dBurnRate, degradedHosts, failingWorkflows) {
  if (Array.isArray(degradedHosts) && degradedHosts.length > 0) {
    return { severity: 'critical', reason_code: 'SLO_CRITICAL_DOMAIN_HEALTH_DEGRADED' };
  }

  if (Array.isArray(failingWorkflows) && failingWorkflows.length > 0) {
    return { severity: 'critical', reason_code: 'SLO_CRITICAL_SYNTHETIC_FAILURE' };
  }

  const critical24h = window24hBurnRate >= SLO_CRITICAL_BURN_RATE_24H;
  const critical7d = window7dBurnRate >= SLO_CRITICAL_BURN_RATE_7D;
  const warn24h = window24hBurnRate >= SLO_WARN_BURN_RATE_24H;
  const warn7d = window7dBurnRate >= SLO_WARN_BURN_RATE_7D;

  if (critical24h && critical7d) {
    return { severity: 'critical', reason_code: 'SLO_CRITICAL_BURNRATE_MULTIWINDOW' };
  }
  if (critical24h) {
    return { severity: 'critical', reason_code: 'SLO_CRITICAL_BURNRATE_24H' };
  }
  if (critical7d) {
    return { severity: 'critical', reason_code: 'SLO_CRITICAL_BURNRATE_7D' };
  }
  if (warn24h && warn7d) {
    return { severity: 'warn', reason_code: 'SLO_WARN_BURNRATE_MULTIWINDOW' };
  }
  if (warn24h) {
    return { severity: 'warn', reason_code: 'SLO_WARN_BURNRATE_24H' };
  }
  if (warn7d) {
    return { severity: 'warn', reason_code: 'SLO_WARN_BURNRATE_7D' };
  }

  return { severity: 'ok', reason_code: 'SLO_HEALTHY' };
}

function fetchSloSnapshot(apiHost) {
  const stats = curlViaResolvedHost(apiHost, '/v1/ledger/stats');
  if (!stats.ok || !stats.body) {
    return {
      check: {
        name: `api:slo:${apiHost}`,
        ok: false,
        reason_code: stats.code,
        http_status: stats.status,
        host: apiHost,
        path: '/v1/ledger/stats',
      },
      snapshot: null,
    };
  }

  try {
    const payload = JSON.parse(stats.body);
    const runs24h = Math.max(0, toFiniteNumber(payload?.runs_24h, 0));
    const failRuns24h = Math.max(0, toFiniteNumber(payload?.fail_runs_24h, 0));
    const failRate24h = Math.max(0, toFiniteNumber(payload?.fail_rate_24h, runs24h > 0 ? failRuns24h / runs24h : 0));

    const runs7d = Math.max(0, toFiniteNumber(payload?.diagnostics_7d?.runs_7d, 0));
    const failRuns7d = Math.max(0, toFiniteNumber(payload?.diagnostics_7d?.fail_runs_7d, 0));
    const failRate7d = Math.max(0, toFiniteNumber(payload?.diagnostics_7d?.fail_rate_7d, runs7d > 0 ? failRuns7d / runs7d : 0));

    const burnRate24h = Number((failRate24h / SLO_ERROR_BUDGET).toFixed(6));
    const burnRate7d = Number((failRate7d / SLO_ERROR_BUDGET).toFixed(6));
    const health = computeSloSeverity(burnRate24h, burnRate7d, [], []);

    const snapshot = {
      host: apiHost,
      target_success_rate: SLO_TARGET_SUCCESS_RATE,
      error_budget_fraction: SLO_ERROR_BUDGET,
      runs_24h: runs24h,
      fail_runs_24h: failRuns24h,
      fail_rate_24h: failRate24h,
      burn_rate_24h: burnRate24h,
      runs_7d: runs7d,
      fail_runs_7d: failRuns7d,
      fail_rate_7d: failRate7d,
      burn_rate_7d: burnRate7d,
      severity: health.severity,
      reason_code: health.reason_code,
      thresholds: {
        warn_burn_rate_24h: SLO_WARN_BURN_RATE_24H,
        warn_burn_rate_7d: SLO_WARN_BURN_RATE_7D,
        critical_burn_rate_24h: SLO_CRITICAL_BURN_RATE_24H,
        critical_burn_rate_7d: SLO_CRITICAL_BURN_RATE_7D,
      },
    };

    return {
      check: {
        name: `api:slo:${apiHost}`,
        ok: health.severity !== 'critical',
        reason_code: health.reason_code,
        http_status: stats.status,
        host: apiHost,
        path: '/v1/ledger/stats',
        severity: health.severity,
        burn_rate_24h: burnRate24h,
        burn_rate_7d: burnRate7d,
      },
      snapshot,
    };
  } catch {
    return {
      check: {
        name: `api:slo:${apiHost}`,
        ok: false,
        reason_code: 'SLO_STATS_PARSE_FAILED',
        http_status: stats.status,
        host: apiHost,
        path: '/v1/ledger/stats',
      },
      snapshot: null,
    };
  }
}

function latestRunRef(apiHost, maxRunRefAgeMinutes) {
  const response = curlViaResolvedHost(apiHost, '/v1/ledger/runs?limit=1');
  if (!response.ok || !response.body) {
    return {
      runId: null,
      agentDid: null,
      createdAt: null,
      ageMinutes: null,
      check: {
        name: `api:runs-feed:${apiHost}`,
        ok: false,
        reason_code: response.code,
        http_status: response.status,
        host: apiHost,
        path: '/v1/ledger/runs?limit=1',
      },
    };
  }

  try {
    const parsed = JSON.parse(response.body);
    const run = Array.isArray(parsed?.runs) ? parsed.runs[0] : null;
    const runId = typeof run?.run_id === 'string' ? run.run_id : null;
    const agentDid = typeof run?.agent_did === 'string' ? run.agent_did : null;
    const createdAt = typeof run?.created_at === 'string' ? run.created_at : null;

    if (!runId || !agentDid || !createdAt) {
      return {
        runId,
        agentDid,
        createdAt,
        ageMinutes: null,
        check: {
          name: `api:runs-feed:${apiHost}`,
          ok: false,
          reason_code: 'NO_RUN_REFERENCE_AVAILABLE',
          http_status: response.status,
          host: apiHost,
          path: '/v1/ledger/runs?limit=1',
        },
      };
    }

    const parsedCreatedAt = parseRunTimestamp(createdAt);
    if (!parsedCreatedAt) {
      return {
        runId,
        agentDid,
        createdAt,
        ageMinutes: null,
        check: {
          name: `api:runs-feed:${apiHost}`,
          ok: false,
          reason_code: 'RUN_REFERENCE_TIMESTAMP_INVALID',
          http_status: response.status,
          host: apiHost,
          path: '/v1/ledger/runs?limit=1',
        },
      };
    }

    const ageMinutes = (Date.now() - parsedCreatedAt.getTime()) / 60000;
    const fresh = ageMinutes <= maxRunRefAgeMinutes;

    return {
      runId,
      agentDid,
      createdAt,
      ageMinutes,
      check: {
        name: `api:runs-feed:${apiHost}`,
        ok: fresh,
        reason_code: fresh ? 'OK' : 'RUN_REFERENCE_STALE',
        http_status: response.status,
        host: apiHost,
        path: '/v1/ledger/runs?limit=1',
        run_id: runId,
        agent_did: agentDid,
        created_at: createdAt,
        age_minutes: Number(ageMinutes.toFixed(3)),
        max_age_minutes: maxRunRefAgeMinutes,
      },
    };
  } catch {
    return {
      runId: null,
      agentDid: null,
      createdAt: null,
      ageMinutes: null,
      check: {
        name: `api:runs-feed:${apiHost}`,
        ok: false,
        reason_code: 'API_JSON_PARSE_FAILED',
        http_status: response.status,
        host: apiHost,
        path: '/v1/ledger/runs?limit=1',
      },
    };
  }
}

function pageCheck(explorerHost, pathName, markerPathName = pathName) {
  const page = curlViaResolvedHost(explorerHost, pathName);
  const marker = markerForPage(markerPathName);
  const hasMarker = marker ? (page.body ?? '').includes(marker) : true;

  return {
    ok: page.ok && hasMarker,
    reason_code: page.ok ? (hasMarker ? 'OK' : 'MARKER_MISSING') : page.code,
    http_status: page.status,
    host: explorerHost,
    path: pathName,
    marker,
  };
}

function runSmoke() {
  const args = parseArgs(process.argv.slice(2));
  const ts = nowTimestamp();
  const outDir = path.join(args.outputRoot, ts);
  mkdirSync(outDir, { recursive: true });

  const hosts = {
    staging_api: 'staging-api.clawverify.com',
    prod_api: 'api.clawverify.com',
    staging_explorer: 'staging-explorer.clawsig.com',
    prod_explorer: 'explorer.clawsig.com',
  };

  const envTargets = args.env === 'all'
    ? [
      ['staging', hosts.staging_api, hosts.staging_explorer],
      ['prod', hosts.prod_api, hosts.prod_explorer],
    ]
    : args.env === 'staging'
      ? [['staging', hosts.staging_api, hosts.staging_explorer]]
      : [['prod', hosts.prod_api, hosts.prod_explorer]];

  const targetHostEntries = envTargets.flatMap(([envLabel, apiHost, explorerHost]) => [
    [`${envLabel}_api`, apiHost],
    [`${envLabel}_explorer`, explorerHost],
  ]);

  const checks = [];
  const context = {
    hosts,
    target_env: args.env,
    dns: {},
    tls: {},
    refs: {},
    slo: {},
    options: args,
  };

  for (const [name, host] of targetHostEntries) {
    const a = resolveRecords(host, 'A');
    const aaaa = resolveRecords(host, 'AAAA');

    context.dns[name] = { a, aaaa };

    pushCheck(checks, {
      name: `dns:${host}`,
      ok: a.length > 0 || aaaa.length > 0,
      reason_code: a.length > 0 || aaaa.length > 0 ? 'OK' : 'DNS_EMPTY',
      host,
      a_count: a.length,
      aaaa_count: aaaa.length,
    });

    const tls = tlsCheck(host);
    context.tls[name] = tls;

    pushCheck(checks, {
      name: `tls:${host}`,
      ok: tls.ok,
      reason_code: tls.code,
      host,
    });
  }

  for (const [, host] of targetHostEntries) {
    const health = curlViaResolvedHost(host, '/health');
    pushCheck(checks, {
      name: `health:${host}`,
      ok: health.ok,
      reason_code: health.code,
      http_status: health.status,
      host,
      path: '/health',
    });
  }

  for (const [envLabel, apiHost, explorerHost] of envTargets) {
    const refs = latestRunRef(apiHost, args.maxRunRefAgeMinutes);
    context.refs[envLabel] = {
      run_id: refs.runId,
      agent_did: refs.agentDid,
      created_at: refs.createdAt,
      age_minutes: refs.ageMinutes,
    };
    pushCheck(checks, refs.check);

    const slo = fetchSloSnapshot(apiHost);
    context.slo[envLabel] = slo.snapshot;
    pushCheck(checks, slo.check);

    for (const pathName of ['/', '/runs', '/stats']) {
      const check = pageCheck(explorerHost, pathName);
      pushCheck(checks, {
        name: `page:${explorerHost}${pathName}`,
        ...check,
      });
    }

    if (refs.runId) {
      const runPath = `/run/${encodeURIComponent(refs.runId)}`;
      const runCheck = pageCheck(explorerHost, runPath, '/run/:id');
      pushCheck(checks, {
        name: `page:${explorerHost}/run/:id`,
        ...runCheck,
      });
    } else {
      pushCheck(checks, {
        name: `page:${explorerHost}/run/:id`,
        ok: false,
        reason_code: 'NO_RUN_REFERENCE_AVAILABLE',
        http_status: null,
        host: explorerHost,
        path: '/run/:id',
      });
    }

    if (refs.agentDid) {
      const agentPath = `/agent/${encodeURIComponent(refs.agentDid)}`;
      const agentCheck = pageCheck(explorerHost, agentPath, '/agent/:did');
      pushCheck(checks, {
        name: `page:${explorerHost}/agent/:did`,
        ...agentCheck,
      });
    } else {
      pushCheck(checks, {
        name: `page:${explorerHost}/agent/:did`,
        ok: false,
        reason_code: 'NO_AGENT_REFERENCE_AVAILABLE',
        http_status: null,
        host: explorerHost,
        path: '/agent/:did',
      });
    }
  }

  const failed = checks.filter((c) => !c.ok);
  const degradedHosts = checks
    .filter((c) => c.name.startsWith('health:') && c.ok === false)
    .map((c) => c.host)
    .filter(Boolean);

  const sloSnapshots = Object.values(context.slo).filter((snapshot) => snapshot && typeof snapshot === 'object');
  const burnRate24h = sloSnapshots.length > 0
    ? Math.max(...sloSnapshots.map((snapshot) => toFiniteNumber(snapshot.burn_rate_24h, 0)))
    : 0;
  const burnRate7d = sloSnapshots.length > 0
    ? Math.max(...sloSnapshots.map((snapshot) => toFiniteNumber(snapshot.burn_rate_7d, 0)))
    : 0;

  const sloHealth = computeSloSeverity(burnRate24h, burnRate7d, degradedHosts, []);

  let alertSeverity = 'ok';
  let alertReasonCode = 'SLO_HEALTHY';

  if (failed.length > 0) {
    alertSeverity = 'critical';
    alertReasonCode = sloHealth.reason_code !== 'SLO_HEALTHY'
      ? sloHealth.reason_code
      : 'SYNTHETIC_SURFACE_FAILURE';
  } else if (sloHealth.severity !== 'ok') {
    alertSeverity = sloHealth.severity;
    alertReasonCode = sloHealth.reason_code;
  }

  const summary = {
    ok: failed.length === 0,
    generated_at: new Date().toISOString(),
    output_dir: outDir,
    target_env: args.env,
    total_checks: checks.length,
    passed_checks: checks.length - failed.length,
    failed_checks: failed.length,
    failure_reason_codes: [...new Set(failed.map((f) => f.reason_code))],
    failures: failed.map((f) => ({
      name: f.name,
      reason_code: f.reason_code,
      http_status: f.http_status ?? null,
    })),
    slo_health: {
      severity: sloHealth.severity,
      reason_code: sloHealth.reason_code,
      burn_rate_24h: Number(burnRate24h.toFixed(6)),
      burn_rate_7d: Number(burnRate7d.toFixed(6)),
      degraded_hosts: degradedHosts,
      per_env: context.slo,
      thresholds: {
        warn_burn_rate_24h: SLO_WARN_BURN_RATE_24H,
        warn_burn_rate_7d: SLO_WARN_BURN_RATE_7D,
        critical_burn_rate_24h: SLO_CRITICAL_BURN_RATE_24H,
        critical_burn_rate_7d: SLO_CRITICAL_BURN_RATE_7D,
      },
      target_success_rate: SLO_TARGET_SUCCESS_RATE,
      error_budget_fraction: SLO_ERROR_BUDGET,
    },
    alert: {
      severity: alertSeverity,
      reason_code: alertReasonCode,
    },
  };

  writeFileSync(path.join(outDir, 'checks.json'), JSON.stringify({ checks, context }, null, 2));
  writeFileSync(path.join(outDir, 'summary.json'), JSON.stringify(summary, null, 2));

  console.log(JSON.stringify(summary, null, 2));

  if (!summary.ok) {
    process.exitCode = 1;
  }
}

runSmoke();
