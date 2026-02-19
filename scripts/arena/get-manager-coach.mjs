#!/usr/bin/env node

const DEFAULT_BOUNTIES_BASE = 'https://staging.clawbounties.com';

function parseArgs(argv) {
  const args = {
    taskFingerprint: null,
    objectiveProfileName: null,
    maxRuns: 50,
    requireHardGatePass: true,
    allowFallback: true,
    bountiesBase: DEFAULT_BOUNTIES_BASE,
    adminKey: process.env.BOUNTIES_ADMIN_KEY ?? '',
    mode: 'coach',
    dryRun: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--task-fingerprint') {
      args.taskFingerprint = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--objective-profile-name') {
      args.objectiveProfileName = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--max-runs') {
      args.maxRuns = Number(argv[i + 1] ?? 50);
      i += 1;
      continue;
    }
    if (arg === '--require-hard-gate-pass') {
      args.requireHardGatePass = argv[i + 1] !== 'false';
      i += 1;
      continue;
    }
    if (arg === '--allow-fallback') {
      args.allowFallback = argv[i + 1] !== 'false';
      i += 1;
      continue;
    }
    if (arg === '--bounties-base') {
      args.bountiesBase = argv[i + 1] ?? DEFAULT_BOUNTIES_BASE;
      i += 1;
      continue;
    }
    if (arg === '--admin-key') {
      args.adminKey = argv[i + 1] ?? '';
      i += 1;
      continue;
    }
    if (arg === '--mode') {
      args.mode = argv[i + 1] === 'route' ? 'route' : 'coach';
      i += 1;
      continue;
    }
    if (arg === '--dry-run') {
      args.dryRun = true;
      continue;
    }
  }

  if (!args.taskFingerprint) {
    throw new Error('Usage: node scripts/arena/get-manager-coach.mjs --task-fingerprint <fingerprint> [--objective-profile-name <name>] [--mode coach|route] [--bounties-base <url>] [--admin-key <key>] [--dry-run]');
  }

  if (!args.dryRun && !args.adminKey.trim()) {
    throw new Error('admin key is required (provide --admin-key or BOUNTIES_ADMIN_KEY env)');
  }

  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  const endpoint = args.mode === 'route'
    ? '/v1/arena/manager/route'
    : '/v1/arena/manager/coach';

  const payload = {
    task_fingerprint: args.taskFingerprint,
    objective_profile_name: args.objectiveProfileName,
    max_runs: args.maxRuns,
    require_hard_gate_pass: args.requireHardGatePass,
    allow_fallback: args.allowFallback,
  };

  if (args.dryRun) {
    console.log(JSON.stringify({ ok: true, mode: 'dry-run', endpoint, payload }, null, 2));
    return;
  }

  const res = await fetch(`${args.bountiesBase.replace(/\/$/, '')}${endpoint}`, {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'content-type': 'application/json',
      'x-admin-key': args.adminKey.trim(),
    },
    body: JSON.stringify(payload),
  });

  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = { raw: text };
  }

  if (!res.ok) {
    console.error(JSON.stringify({ ok: false, status: res.status, error: json }, null, 2));
    process.exit(1);
  }

  console.log(JSON.stringify({ ok: true, endpoint, payload, response: json }, null, 2));
}

main().catch((err) => {
  console.error(JSON.stringify({ ok: false, error: err instanceof Error ? err.message : String(err) }, null, 2));
  process.exit(1);
});
