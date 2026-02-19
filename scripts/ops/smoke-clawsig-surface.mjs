#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';

const OUTPUT_ROOT_DEFAULT = 'artifacts/ops/clawsig-synthetic';

function parseArgs(argv) {
  const args = {
    outputRoot: OUTPUT_ROOT_DEFAULT,
    requireRunRefs: true,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--output-root') {
      args.outputRoot = argv[i + 1] ?? OUTPUT_ROOT_DEFAULT;
      i += 1;
      continue;
    }

    if (arg === '--allow-missing-run-refs') {
      args.requireRunRefs = false;
      continue;
    }
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
  return null;
}

function pushCheck(checks, data) {
  checks.push({
    ...data,
    checked_at: new Date().toISOString(),
  });
}

function latestRunRef(apiHost) {
  const response = curlViaResolvedHost(apiHost, '/v1/ledger/runs?limit=1');
  if (!response.ok || !response.body) {
    return {
      runId: null,
      agentDid: null,
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

    return {
      runId,
      agentDid,
      check: {
        name: `api:runs-feed:${apiHost}`,
        ok: true,
        reason_code: runId && agentDid ? 'OK' : 'NO_RUN_REFERENCE_AVAILABLE',
        http_status: response.status,
        host: apiHost,
        path: '/v1/ledger/runs?limit=1',
        has_run_reference: Boolean(runId && agentDid),
      },
    };
  } catch {
    return {
      runId: null,
      agentDid: null,
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

  const checks = [];
  const context = {
    hosts,
    dns: {},
    tls: {},
    refs: {},
    options: args,
  };

  for (const [name, host] of Object.entries(hosts)) {
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

  for (const host of [hosts.staging_api, hosts.prod_api, hosts.staging_explorer, hosts.prod_explorer]) {
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

  for (const [envLabel, apiHost, explorerHost] of [
    ['staging', hosts.staging_api, hosts.staging_explorer],
    ['prod', hosts.prod_api, hosts.prod_explorer],
  ]) {
    const refs = latestRunRef(apiHost);
    context.refs[envLabel] = { run_id: refs.runId, agent_did: refs.agentDid };
    pushCheck(checks, refs.check);

    for (const pathName of ['/', '/runs', '/stats']) {
      const page = curlViaResolvedHost(explorerHost, pathName);
      const marker = markerForPage(pathName);
      const hasMarker = marker ? (page.body ?? '').includes(marker) : true;
      pushCheck(checks, {
        name: `page:${explorerHost}${pathName}`,
        ok: page.ok && hasMarker,
        reason_code: page.ok ? (hasMarker ? 'OK' : 'MARKER_MISSING') : page.code,
        http_status: page.status,
        host: explorerHost,
        path: pathName,
      });
    }

    if (refs.runId) {
      const runPage = curlViaResolvedHost(explorerHost, `/run/${encodeURIComponent(refs.runId)}`);
      pushCheck(checks, {
        name: `page:${explorerHost}/run/:id`,
        ok: runPage.ok,
        reason_code: runPage.code,
        http_status: runPage.status,
        host: explorerHost,
        path: `/run/${refs.runId}`,
      });
    } else {
      pushCheck(checks, {
        name: `page:${explorerHost}/run/:id`,
        ok: !args.requireRunRefs,
        reason_code: 'NO_RUN_REFERENCE_AVAILABLE',
        http_status: null,
        host: explorerHost,
        path: '/run/:id',
      });
    }

    if (refs.agentDid) {
      const agentPath = `/agent/${encodeURIComponent(refs.agentDid)}`;
      const agentPage = curlViaResolvedHost(explorerHost, agentPath);
      pushCheck(checks, {
        name: `page:${explorerHost}/agent/:did`,
        ok: agentPage.ok,
        reason_code: agentPage.code,
        http_status: agentPage.status,
        host: explorerHost,
        path: agentPath,
      });
    } else {
      pushCheck(checks, {
        name: `page:${explorerHost}/agent/:did`,
        ok: !args.requireRunRefs,
        reason_code: 'NO_AGENT_REFERENCE_AVAILABLE',
        http_status: null,
        host: explorerHost,
        path: '/agent/:did',
      });
    }
  }

  const failed = checks.filter((c) => !c.ok);
  const summary = {
    ok: failed.length === 0,
    generated_at: new Date().toISOString(),
    output_dir: outDir,
    total_checks: checks.length,
    passed_checks: checks.length - failed.length,
    failed_checks: failed.length,
    failure_reason_codes: [...new Set(failed.map((f) => f.reason_code))],
    failures: failed.map((f) => ({
      name: f.name,
      reason_code: f.reason_code,
      http_status: f.http_status ?? null,
    })),
  };

  writeFileSync(path.join(outDir, 'checks.json'), JSON.stringify({ checks, context }, null, 2));
  writeFileSync(path.join(outDir, 'summary.json'), JSON.stringify(summary, null, 2));

  console.log(JSON.stringify(summary, null, 2));

  if (!summary.ok) {
    process.exitCode = 1;
  }
}

runSmoke();
