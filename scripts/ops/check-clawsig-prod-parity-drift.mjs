#!/usr/bin/env node
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const OUTPUT_ROOT_DEFAULT = 'artifacts/ops/clawsig-parity-drift';
const DEFAULT_MAX_DRIFT_COUNT = 0;

function parseArgs(argv) {
  const args = {
    outputRoot: OUTPUT_ROOT_DEFAULT,
    maxDriftCount: DEFAULT_MAX_DRIFT_COUNT,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];

    if (arg === '--output-root') {
      args.outputRoot = argv[i + 1] ?? OUTPUT_ROOT_DEFAULT;
      i += 1;
      continue;
    }

    if (arg === '--max-drift-count') {
      const parsed = Number.parseInt(argv[i + 1] ?? '', 10);
      if (!Number.isFinite(parsed) || parsed < 0) {
        throw new Error('Invalid --max-drift-count value');
      }
      args.maxDriftCount = parsed;
      i += 1;
      continue;
    }
  }

  return args;
}

function nowLabel() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

function curlJson(url) {
  try {
    const out = execFileSync('curl', ['-sS', '-w', '\n%{http_code}', url], {
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    const lines = out.split('\n');
    const statusRaw = lines.pop() ?? '';
    const status = Number(statusRaw.trim());
    const body = lines.join('\n');

    return {
      ok: Number.isFinite(status),
      status: Number.isFinite(status) ? status : null,
      body,
      error: null,
    };
  } catch (error) {
    return {
      ok: false,
      status: null,
      body: '',
      error: String(error?.stderr ?? error?.message ?? error),
    };
  }
}

function valueType(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  return typeof value;
}

function collectShape(value, prefix = '', acc = new Map()) {
  const kind = valueType(value);

  if (kind === 'array') {
    const nextPrefix = prefix.length > 0 ? prefix : '$';
    acc.set(nextPrefix, 'array');

    if (value.length > 0) {
      collectShape(value[0], `${nextPrefix}[]`, acc);
    }

    return acc;
  }

  if (kind === 'object') {
    const nextPrefix = prefix.length > 0 ? prefix : '$';
    acc.set(nextPrefix, 'object');

    for (const [key, nested] of Object.entries(value)) {
      const childPrefix = nextPrefix === '$' ? `$.${key}` : `${nextPrefix}.${key}`;
      collectShape(nested, childPrefix, acc);
    }

    return acc;
  }

  const nextPrefix = prefix.length > 0 ? prefix : '$';
  acc.set(nextPrefix, kind);
  return acc;
}

function compareShapes(stagingPayload, prodPayload) {
  const stagingShape = collectShape(stagingPayload);
  const prodShape = collectShape(prodPayload);

  const missingInProd = [];
  const missingInStaging = [];
  const typeMismatch = [];

  for (const [key, stagingType] of stagingShape.entries()) {
    if (!prodShape.has(key)) {
      missingInProd.push(key);
      continue;
    }

    const prodType = prodShape.get(key);
    if (stagingType !== prodType) {
      typeMismatch.push({ key, staging_type: stagingType, prod_type: prodType });
    }
  }

  for (const key of prodShape.keys()) {
    if (!stagingShape.has(key)) {
      missingInStaging.push(key);
    }
  }

  return {
    missing_in_prod: missingInProd,
    missing_in_staging: missingInStaging,
    type_mismatch: typeMismatch,
    has_drift: missingInProd.length > 0 || missingInStaging.length > 0 || typeMismatch.length > 0,
  };
}

function endpointChecks() {
  return [
    {
      name: 'ledger-health',
      mode: 'json',
      staging_url: 'https://staging-api.clawverify.com/health',
      prod_url: 'https://api.clawverify.com/health',
    },
    {
      name: 'ledger-runs-contract',
      mode: 'json',
      staging_url: 'https://staging-api.clawverify.com/v1/ledger/runs?limit=1',
      prod_url: 'https://api.clawverify.com/v1/ledger/runs?limit=1',
    },
    {
      name: 'ledger-stats-contract',
      mode: 'json',
      staging_url: 'https://staging-api.clawverify.com/v1/ledger/stats',
      prod_url: 'https://api.clawverify.com/v1/ledger/stats',
    },
    {
      name: 'explorer-health',
      mode: 'json',
      staging_url: 'https://staging-explorer.clawsig.com/health',
      prod_url: 'https://explorer.clawsig.com/health',
    },
    {
      name: 'explorer-ops-page',
      mode: 'html-marker',
      marker: 'Operations Dashboard',
      staging_url: 'https://staging-explorer.clawsig.com/ops',
      prod_url: 'https://explorer.clawsig.com/ops',
    },
    {
      name: 'explorer-slo-contract',
      mode: 'json',
      staging_url: 'https://staging-explorer.clawsig.com/ops/slo-health.json',
      prod_url: 'https://explorer.clawsig.com/ops/slo-health.json',
    },
  ];
}

function runCheck(target) {
  const staging = curlJson(target.staging_url);
  const prod = curlJson(target.prod_url);

  const base = {
    name: target.name,
    mode: target.mode,
    staging_url: target.staging_url,
    prod_url: target.prod_url,
    staging_status: staging.status,
    prod_status: prod.status,
    ok: true,
    reason_code: 'OK',
    drift: null,
  };

  if (!staging.ok || !prod.ok) {
    return {
      ...base,
      ok: false,
      reason_code: 'PARITY_FETCH_FAILED',
      drift: {
        staging_error: staging.error,
        prod_error: prod.error,
      },
    };
  }

  if (staging.status !== prod.status) {
    return {
      ...base,
      ok: false,
      reason_code: 'PARITY_HTTP_STATUS_MISMATCH',
      drift: {
        staging_status: staging.status,
        prod_status: prod.status,
      },
    };
  }

  if ((staging.status ?? 0) < 200 || (staging.status ?? 0) >= 300) {
    return {
      ...base,
      ok: true,
      reason_code: 'PARITY_SHARED_NON_2XX',
      drift: {
        staging_status: staging.status,
        prod_status: prod.status,
      },
    };
  }

  if (target.mode === 'html-marker') {
    const marker = target.marker ?? '';
    const stagingHasMarker = staging.body.includes(marker);
    const prodHasMarker = prod.body.includes(marker);

    if (!stagingHasMarker || !prodHasMarker) {
      return {
        ...base,
        ok: false,
        reason_code: 'PARITY_HTML_MARKER_MISSING',
        drift: {
          marker,
          staging_marker_present: stagingHasMarker,
          prod_marker_present: prodHasMarker,
        },
      };
    }

    return base;
  }

  try {
    const stagingJson = JSON.parse(staging.body);
    const prodJson = JSON.parse(prod.body);
    const shapeDiff = compareShapes(stagingJson, prodJson);

    if (shapeDiff.has_drift) {
      return {
        ...base,
        ok: false,
        reason_code: 'PARITY_JSON_SHAPE_DRIFT',
        drift: shapeDiff,
      };
    }

    return base;
  } catch {
    return {
      ...base,
      ok: false,
      reason_code: 'PARITY_JSON_PARSE_FAILED',
      drift: null,
    };
  }
}

function toMarkdown(summary, checks) {
  const failed = checks.filter((row) => !row.ok);

  const lines = [
    '# Clawsig Staging/Prod Parity Drift Report',
    '',
    `- generated_at: ${summary.generated_at}`,
    `- ok: ${summary.ok}`,
    `- drift_count: ${summary.drift_count}`,
    `- max_drift_count: ${summary.max_drift_count}`,
    `- threshold_reason_code: ${summary.threshold_reason_code}`,
    '',
    '## Endpoint checks',
    '',
  ];

  for (const check of checks) {
    lines.push(`- ${check.ok ? 'PASS' : 'FAIL'} ${check.name} :: ${check.reason_code}`);
  }

  if (failed.length > 0) {
    lines.push('', '## Drift details', '');
    for (const row of failed) {
      lines.push(`### ${row.name}`, '');
      lines.push('```json');
      lines.push(JSON.stringify(row.drift ?? {}, null, 2));
      lines.push('```', '');
    }
  }

  return lines.join('\n');
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const outDir = path.join(args.outputRoot, nowLabel());
  mkdirSync(outDir, { recursive: true });

  const checks = endpointChecks().map((target) => runCheck(target));
  const failed = checks.filter((row) => !row.ok);
  const driftReasonCodes = [...new Set(failed.map((row) => row.reason_code))];

  const thresholdExceeded = failed.length > args.maxDriftCount;

  const summary = {
    ok: !thresholdExceeded,
    generated_at: new Date().toISOString(),
    output_dir: outDir,
    total_checks: checks.length,
    passed_checks: checks.length - failed.length,
    drift_count: failed.length,
    max_drift_count: args.maxDriftCount,
    drift_reason_codes: driftReasonCodes,
    threshold_reason_code: thresholdExceeded ? 'PARITY_DRIFT_THRESHOLD_EXCEEDED' : 'OK',
  };

  writeFileSync(path.join(outDir, 'checks.json'), JSON.stringify({ checks }, null, 2));
  writeFileSync(path.join(outDir, 'parity-diff-report.json'), JSON.stringify({ summary, checks }, null, 2));
  writeFileSync(path.join(outDir, 'parity-diff-report.md'), toMarkdown(summary, checks));
  writeFileSync(path.join(outDir, 'summary.json'), JSON.stringify(summary, null, 2));

  console.log(JSON.stringify(summary, null, 2));

  if (thresholdExceeded) {
    process.exitCode = 1;
  }
}

main();
