#!/usr/bin/env node
import { readFileSync } from 'node:fs';

function parseArgs(argv) {
  const args = {
    summaryPath: '',
    checksPath: '',
    workflowFile: 'clawsig-surface-synthetic-smoke.yml',
    dedupeWindowMinutes: 240,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];

    if (arg === '--summary') {
      args.summaryPath = argv[i + 1] ?? '';
      i += 1;
      continue;
    }

    if (arg === '--checks') {
      args.checksPath = argv[i + 1] ?? '';
      i += 1;
      continue;
    }

    if (arg === '--workflow-file') {
      args.workflowFile = argv[i + 1] ?? args.workflowFile;
      i += 1;
      continue;
    }

    if (arg === '--dedupe-window-minutes') {
      const parsed = Number.parseInt(argv[i + 1] ?? '', 10);
      if (!Number.isFinite(parsed) || parsed <= 0) {
        throw new Error('Invalid --dedupe-window-minutes value');
      }
      args.dedupeWindowMinutes = parsed;
      i += 1;
      continue;
    }
  }

  if (!args.summaryPath) {
    throw new Error('Missing required --summary path');
  }

  if (!args.checksPath) {
    throw new Error('Missing required --checks path');
  }

  return args;
}

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function normalizeFailures(summary, checksPayload) {
  const checks = Array.isArray(checksPayload?.checks) ? checksPayload.checks : [];
  const failedChecks = checks.filter((check) => check && check.ok === false);

  const byKey = new Map();
  for (const check of failedChecks) {
    const reasonCode = typeof check.reason_code === 'string' ? check.reason_code : 'UNKNOWN_REASON';
    const host = typeof check.host === 'string' ? check.host : 'n/a';
    const route = typeof check.path === 'string' ? check.path : 'n/a';
    const key = `${reasonCode}|${host}|${route}`;

    if (!byKey.has(key)) {
      byKey.set(key, {
        reason_code: reasonCode,
        host,
        route,
      });
    }
  }

  const deduped = [...byKey.values()];

  if (deduped.length > 0) return deduped;

  const fallback = Array.isArray(summary?.failures) ? summary.failures : [];
  return fallback.map((failure) => ({
    reason_code: typeof failure?.reason_code === 'string' ? failure.reason_code : 'UNKNOWN_REASON',
    host: typeof failure?.host === 'string' ? failure.host : 'n/a',
    route: typeof failure?.path === 'string' ? failure.path : (typeof failure?.name === 'string' ? failure.name : 'n/a'),
  }));
}

function normalizeSeverity(raw) {
  if (raw === 'critical' || raw === 'warn' || raw === 'ok') return raw;
  return 'ok';
}

function deriveAlertSignal(summary) {
  const summaryAlertSeverity = normalizeSeverity(summary?.alert?.severity);
  const summaryAlertReason = typeof summary?.alert?.reason_code === 'string'
    ? summary.alert.reason_code
    : null;

  const sloSeverity = normalizeSeverity(summary?.slo_health?.severity);
  const sloReason = typeof summary?.slo_health?.reason_code === 'string'
    ? summary.slo_health.reason_code
    : null;

  if (summary?.ok === false) {
    return {
      severity: 'critical',
      reason_code: summaryAlertReason ?? sloReason ?? 'SYNTHETIC_SURFACE_FAILURE',
      shouldRoute: true,
    };
  }

  if (summaryAlertSeverity !== 'ok') {
    return {
      severity: summaryAlertSeverity,
      reason_code: summaryAlertReason ?? sloReason ?? 'SYNTHETIC_ALERT_DEGRADED',
      shouldRoute: true,
    };
  }

  if (sloSeverity !== 'ok') {
    return {
      severity: sloSeverity,
      reason_code: sloReason ?? 'SLO_DEGRADED',
      shouldRoute: true,
    };
  }

  return {
    severity: 'ok',
    reason_code: 'SLO_HEALTHY',
    shouldRoute: false,
  };
}

async function fetchRecentRuns(workflowFile, token) {
  const repo = process.env.GITHUB_REPOSITORY;
  if (!repo) return [];

  const url = `https://api.github.com/repos/${repo}/actions/workflows/${encodeURIComponent(workflowFile)}/runs?per_page=20`;
  const res = await fetch(url, {
    headers: {
      Accept: 'application/vnd.github+json',
      'User-Agent': 'clawsig-synthetic-alert-router',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });

  if (!res.ok) {
    return [];
  }

  const payload = await res.json();
  return Array.isArray(payload?.workflow_runs) ? payload.workflow_runs : [];
}

function shouldSuppressAsDuplicate(runs, dedupeWindowMinutes, severity) {
  const currentRunId = Number.parseInt(process.env.GITHUB_RUN_ID ?? '', 10);
  const currentSha = process.env.GITHUB_SHA ?? '';

  if (!Number.isFinite(currentRunId) || !currentSha) return false;

  const nowMs = Date.now();

  for (const run of runs) {
    const runId = typeof run?.id === 'number' ? run.id : null;
    const runSha = typeof run?.head_sha === 'string' ? run.head_sha : null;
    const runConclusion = typeof run?.conclusion === 'string' ? run.conclusion : null;
    const runStatus = typeof run?.status === 'string' ? run.status : null;
    const runCreatedAt = typeof run?.created_at === 'string' ? run.created_at : null;

    if (!runId || runId === currentRunId) continue;
    if (runSha !== currentSha) continue;

    if (severity === 'critical') {
      if (runConclusion !== 'failure') continue;
    } else if (severity === 'warn') {
      if (runStatus !== 'completed') continue;
    }

    if (!runCreatedAt) continue;

    const createdMs = Date.parse(runCreatedAt);
    if (!Number.isFinite(createdMs)) continue;

    const ageMinutes = (nowMs - createdMs) / 60000;
    if (ageMinutes <= dedupeWindowMinutes) {
      return true;
    }
  }

  return false;
}

function buildAlertMessage(summary, failures, alertSignal) {
  const repo = process.env.GITHUB_REPOSITORY ?? 'unknown-repo';
  const sha = process.env.GITHUB_SHA ?? 'unknown-sha';
  const runId = process.env.GITHUB_RUN_ID ?? 'unknown-run';
  const server = process.env.GITHUB_SERVER_URL ?? 'https://github.com';
  const workflowUrl = `${server}/${repo}/actions/runs/${runId}`;

  const severityIcon = alertSignal.severity === 'critical'
    ? '🚨'
    : (alertSignal.severity === 'warn' ? '⚠️' : '✅');

  const failureLines = failures
    .slice(0, 20)
    .map((failure) => `- ${failure.reason_code} | ${failure.host} | ${failure.route}`)
    .join('\n');

  const totalChecks = Number(summary?.total_checks ?? 0);
  const failedChecks = Number(summary?.failed_checks ?? failures.length);
  const targetEnv = typeof summary?.target_env === 'string' ? summary.target_env : 'all';

  const text = [
    `${severityIcon} Clawsig synthetic signal (${targetEnv})`,
    `severity: ${alertSignal.severity}`,
    `reason_code: ${alertSignal.reason_code}`,
    `repo: ${repo}`,
    `commit: ${sha}`,
    `workflow: ${workflowUrl}`,
    `checks: ${Math.max(0, totalChecks - failedChecks)}/${totalChecks} passed`,
    'failures:',
    failureLines || '- no structured failures reported',
  ].join('\n');

  return {
    text,
    workflowUrl,
    sha,
    repo,
    targetEnv,
    failedChecks,
    totalChecks,
    severity: alertSignal.severity,
    reason_code: alertSignal.reason_code,
  };
}

async function postJson(url, payload) {
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  });

  return {
    ok: res.ok,
    status: res.status,
  };
}

async function routeAlerts(alertMessage) {
  const slackWebhook = process.env.SYNTHETIC_ALERT_SLACK_WEBHOOK;
  const discordWebhook = process.env.SYNTHETIC_ALERT_DISCORD_WEBHOOK;

  const attempts = [];

  if (slackWebhook) {
    const slackPayload = {
      text: alertMessage.text,
      blocks: [
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: `*Clawsig synthetic signal*\n*severity:* ${alertMessage.severity}\n*reason_code:* ${alertMessage.reason_code}\n*repo:* ${alertMessage.repo}\n*commit:* ${alertMessage.sha}\n*env:* ${alertMessage.targetEnv}\n*workflow:* <${alertMessage.workflowUrl}|open run>`
          }
        },
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: alertMessage.text.split('\n').slice(5).join('\n')
          }
        }
      ],
    };

    const result = await postJson(slackWebhook, slackPayload);
    attempts.push({ channel: 'slack', ...result });
  }

  if (discordWebhook) {
    const discordPayload = {
      content: alertMessage.text,
    };

    const result = await postJson(discordWebhook, discordPayload);
    attempts.push({ channel: 'discord', ...result });
  }

  return attempts;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const summary = readJson(args.summaryPath);
  const checksPayload = readJson(args.checksPath);

  const alertSignal = deriveAlertSignal(summary);
  if (!alertSignal.shouldRoute) {
    console.log(JSON.stringify({ ok: true, skipped: true, reason: 'NO_ALERT_SIGNAL' }, null, 2));
    return;
  }

  const failures = normalizeFailures(summary, checksPayload);
  const token = process.env.GITHUB_TOKEN ?? process.env.GH_TOKEN ?? '';
  const runs = await fetchRecentRuns(args.workflowFile, token);
  const deduped = shouldSuppressAsDuplicate(runs, args.dedupeWindowMinutes, alertSignal.severity);

  if (deduped) {
    console.log(JSON.stringify({ ok: true, skipped: true, reason: 'DUPLICATE_FAILURE_SUPPRESSED' }, null, 2));
    return;
  }

  const message = buildAlertMessage(summary, failures, alertSignal);
  const attempts = await routeAlerts(message);

  const routedChannels = attempts.filter((attempt) => attempt.ok).map((attempt) => attempt.channel);

  const result = {
    ok: routedChannels.length > 0,
    routed_channels: routedChannels,
    attempts,
    severity: message.severity,
    reason_code: message.reason_code,
    failure_count: failures.length,
  };

  console.log(JSON.stringify(result, null, 2));

  if (attempts.length > 0 && routedChannels.length === 0) {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
