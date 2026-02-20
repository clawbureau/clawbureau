#!/usr/bin/env node

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

const DEFAULT_OUTPUT_ROOT = 'artifacts/ops/arena-productization';

function parseArgs(argv) {
  const args = {
    workersPath: null,
    bountiesBase: 'https://staging.clawbounties.com',
    adminKey: process.env.BOUNTIES_ADMIN_KEY ?? '',
    outputRoot: DEFAULT_OUTPUT_ROOT,
    envLabel: 'staging',
    dryRun: false,
    heartbeat: true,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];

    if (arg === '--workers') {
      args.workersPath = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--bounties-base') {
      args.bountiesBase = argv[i + 1] ?? args.bountiesBase;
      i += 1;
      continue;
    }
    if (arg === '--admin-key') {
      args.adminKey = argv[i + 1] ?? '';
      i += 1;
      continue;
    }
    if (arg === '--output-root') {
      args.outputRoot = argv[i + 1] ?? DEFAULT_OUTPUT_ROOT;
      i += 1;
      continue;
    }
    if (arg === '--env-label') {
      args.envLabel = argv[i + 1] ?? 'staging';
      i += 1;
      continue;
    }
    if (arg === '--dry-run') {
      args.dryRun = true;
      continue;
    }
    if (arg === '--no-heartbeat') {
      args.heartbeat = false;
      continue;
    }
  }

  if (!args.workersPath) {
    throw new Error('Usage: node scripts/arena/register-harness-fleet-workers.mjs --workers <json> [--bounties-base <url>] [--admin-key <key>] [--env-label <staging|prod>] [--dry-run]');
  }

  if (!args.dryRun && !args.adminKey) {
    throw new Error('Missing admin key. Provide --admin-key or BOUNTIES_ADMIN_KEY.');
  }

  return args;
}

function loadWorkers(filePath) {
  const input = JSON.parse(readFileSync(filePath, 'utf8'));
  if (!Array.isArray(input) || input.length === 0) {
    throw new Error('workers file must be a non-empty JSON array');
  }

  return input.map((row, index) => {
    if (!row || typeof row !== 'object' || Array.isArray(row)) {
      throw new Error(`workers[${index}] must be an object`);
    }

    const workerDid = String(row.worker_did ?? '').trim();
    const harness = String(row.harness ?? '').trim();
    const model = String(row.model ?? '').trim();
    const skills = Array.isArray(row.skills) ? row.skills.map((entry) => String(entry).trim()).filter(Boolean) : [];
    const tools = Array.isArray(row.tools) ? row.tools.map((entry) => String(entry).trim()).filter(Boolean) : [];
    const objectiveProfiles = Array.isArray(row.objective_profiles)
      ? row.objective_profiles.map((entry) => String(entry).trim()).filter(Boolean)
      : [];
    const costTier = String(row.cost_tier ?? 'medium').trim().toLowerCase();
    const riskTier = String(row.risk_tier ?? 'medium').trim().toLowerCase();
    const availabilityStatus = String(row.availability_status ?? 'online').trim().toLowerCase();

    if (!workerDid.startsWith('did:')) throw new Error(`workers[${index}].worker_did must be a DID`);
    if (!harness) throw new Error(`workers[${index}].harness is required`);
    if (!model) throw new Error(`workers[${index}].model is required`);
    if (!['low', 'medium', 'high'].includes(costTier)) throw new Error(`workers[${index}].cost_tier must be low|medium|high`);
    if (!['low', 'medium', 'high'].includes(riskTier)) throw new Error(`workers[${index}].risk_tier must be low|medium|high`);
    if (!['online', 'offline', 'paused'].includes(availabilityStatus)) throw new Error(`workers[${index}].availability_status must be online|offline|paused`);

    return {
      worker_did: workerDid,
      harness,
      model,
      skills,
      tools,
      objective_profiles: objectiveProfiles,
      cost_tier: costTier,
      risk_tier: riskTier,
      availability_status: availabilityStatus,
      metadata: row.metadata && typeof row.metadata === 'object' && !Array.isArray(row.metadata) ? row.metadata : null,
    };
  });
}

function nowLabel() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

function toSummaryPath(outputRoot, envLabel) {
  const dir = path.join(outputRoot, `${nowLabel()}-agp-us-058-fleet-register-${envLabel}`);
  mkdirSync(dir, { recursive: true });
  return {
    dir,
    summary: path.join(dir, 'summary.json'),
    workers: path.join(dir, 'workers.json'),
    roster: path.join(dir, 'roster.json'),
  };
}

async function requestJson(url, init) {
  const res = await fetch(url, init);
  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }

  return {
    ok: res.ok,
    status: res.status,
    json,
    text,
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const workers = loadWorkers(args.workersPath);
  const out = toSummaryPath(args.outputRoot, args.envLabel);

  const registerEndpoint = `${args.bountiesBase.replace(/\/$/, '')}/v1/arena/fleet/workers/register`;
  const heartbeatEndpoint = `${args.bountiesBase.replace(/\/$/, '')}/v1/arena/fleet/workers/heartbeat`;
  const listEndpoint = `${args.bountiesBase.replace(/\/$/, '')}/v1/arena/fleet/workers?availability_status=online&limit=200`;

  const events = [];

  for (const worker of workers) {
    const registerPayload = {
      ...worker,
      touch_heartbeat: args.heartbeat,
    };

    if (args.dryRun) {
      events.push({ action: 'register', endpoint: registerEndpoint, worker_did: worker.worker_did, payload: registerPayload });
      if (args.heartbeat) {
        events.push({
          action: 'heartbeat',
          endpoint: heartbeatEndpoint,
          worker_did: worker.worker_did,
          payload: { worker_did: worker.worker_did, availability_status: worker.availability_status, metadata: worker.metadata },
        });
      }
      continue;
    }

    const registerRes = await requestJson(registerEndpoint, {
      method: 'POST',
      headers: {
        'content-type': 'application/json; charset=utf-8',
        'x-admin-key': args.adminKey,
      },
      body: JSON.stringify(registerPayload),
    });

    events.push({
      action: 'register',
      worker_did: worker.worker_did,
      status: registerRes.status,
      ok: registerRes.ok,
      response: registerRes.json,
    });

    if (!registerRes.ok) {
      throw new Error(`fleet register failed for ${worker.worker_did}: HTTP ${registerRes.status}`);
    }

    if (args.heartbeat) {
      const heartbeatRes = await requestJson(heartbeatEndpoint, {
        method: 'POST',
        headers: {
          'content-type': 'application/json; charset=utf-8',
          'x-admin-key': args.adminKey,
        },
        body: JSON.stringify({
          worker_did: worker.worker_did,
          availability_status: worker.availability_status,
          metadata: worker.metadata,
        }),
      });

      events.push({
        action: 'heartbeat',
        worker_did: worker.worker_did,
        status: heartbeatRes.status,
        ok: heartbeatRes.ok,
        response: heartbeatRes.json,
      });

      if (!heartbeatRes.ok) {
        throw new Error(`fleet heartbeat failed for ${worker.worker_did}: HTTP ${heartbeatRes.status}`);
      }
    }
  }

  let roster = null;
  if (!args.dryRun) {
    const rosterRes = await requestJson(listEndpoint, {
      method: 'GET',
      headers: {
        'x-admin-key': args.adminKey,
      },
    });

    if (!rosterRes.ok) {
      throw new Error(`fleet list failed: HTTP ${rosterRes.status}`);
    }

    roster = rosterRes.json;
    writeFileSync(out.roster, JSON.stringify(roster, null, 2) + '\n');
  }

  const discoveredWorkers = Array.isArray(roster?.workers)
    ? roster.workers.filter((row) => workers.some((entry) => entry.worker_did === row.worker_did))
    : [];

  const summary = {
    ok: true,
    generated_at: new Date().toISOString(),
    story: 'AGP-US-058',
    endpoint_base: args.bountiesBase,
    env: args.envLabel,
    dry_run: args.dryRun,
    totals: {
      requested_workers: workers.length,
      discovered_workers: discoveredWorkers.length,
      minimum_target_met: args.envLabel === 'production'
        ? discoveredWorkers.length >= 3
        : discoveredWorkers.length >= 5,
    },
    endpoints: {
      register: registerEndpoint,
      heartbeat: heartbeatEndpoint,
      list: listEndpoint,
    },
    artifacts: {
      workers: out.workers,
      roster: args.dryRun ? null : out.roster,
      summary: out.summary,
    },
  };

  writeFileSync(out.workers, JSON.stringify(workers, null, 2) + '\n');
  writeFileSync(out.summary, JSON.stringify(summary, null, 2) + '\n');

  console.log(JSON.stringify({
    ...summary,
    events,
  }, null, 2));
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
