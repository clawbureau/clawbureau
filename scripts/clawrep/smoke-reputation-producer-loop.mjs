#!/usr/bin/env node

import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

function parseArgs(argv) {
  const out = {
    env: 'staging',
    clawtrialsBaseUrl: '',
    clawrepBaseUrl: '',
    repAdminKey: process.env.CLAWREP_ADMIN_KEY ?? '',
    outDir: '',
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--env' && argv[i + 1]) out.env = String(argv[++i]);
    else if (arg === '--clawtrials-base-url' && argv[i + 1]) out.clawtrialsBaseUrl = String(argv[++i]);
    else if (arg === '--clawrep-base-url' && argv[i + 1]) out.clawrepBaseUrl = String(argv[++i]);
    else if (arg === '--admin-key' && argv[i + 1]) out.repAdminKey = String(argv[++i]);
    else if (arg === '--out-dir' && argv[i + 1]) out.outDir = String(argv[++i]);
  }

  return out;
}

function timestampForPath(date = new Date()) {
  return date.toISOString().replace(/:/g, '-').replace(/\./g, '-');
}

function jsonText(value) {
  return JSON.stringify(value, null, 2);
}

function makeDid(seed) {
  return `did:key:z6Mktrial${seed}`;
}

async function sleep(ms) {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

async function requestJson(url, { method = 'GET', headers = {}, body } = {}) {
  const response = await fetch(url, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  const text = await response.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = { raw: text };
  }

  return {
    status: response.status,
    ok: response.ok,
    json,
    text,
  };
}

function assertStatus(label, response, expected) {
  if (response.status !== expected) {
    throw new Error(`${label} expected HTTP ${expected}, got ${response.status}: ${JSON.stringify(response.json)}`);
  }
}

function assertCondition(label, condition, context) {
  if (!condition) {
    throw new Error(`${label} assertion failed: ${JSON.stringify(context)}`);
  }
}

async function waitForRep(baseUrl, did, predicate, { attempts = 30, delayMs = 1000 } = {}) {
  let last = null;
  for (let i = 0; i < attempts; i += 1) {
    const rep = await requestJson(`${baseUrl}/v1/rep/${encodeURIComponent(did)}`);
    if (rep.status === 200) {
      last = rep;
      if (predicate(rep.json)) return rep;
    }
    if (i < attempts - 1) await sleep(delayMs);
  }
  return last;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.env !== 'staging' && args.env !== 'prod') {
    throw new Error('--env must be staging or prod');
  }
  if (!args.repAdminKey) {
    throw new Error('CLAWREP_ADMIN_KEY is required (or pass --admin-key)');
  }

  const clawtrialsBaseUrl =
    args.clawtrialsBaseUrl ||
    (args.env === 'prod' ? 'https://clawtrials.com' : 'https://clawtrials-staging.generaite.workers.dev');
  const clawrepBaseUrl =
    args.clawrepBaseUrl ||
    (args.env === 'prod' ? 'https://clawrep.com' : 'https://clawrep-staging.generaite.workers.dev');

  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
  const ts = timestampForPath();
  const outDir = args.outDir || path.join(root, 'artifacts', 'smoke', 'clawrep-producer-loop', `${ts}-${args.env}`);
  mkdirSync(outDir, { recursive: true });

  const now = Date.now();
  const did = makeDid(now);
  const bountyId = `bty_trial_${now}`;
  const submissionPass = `sub_trial_pass_${now}`;
  const submissionFail = `sub_trial_fail_${now}`;

  const basePayload = {
    schema_version: '1',
    test_harness_id: 'th_policy_summary_v1',
    bounty_id: bountyId,
    proof_bundle_hash: `hash_${now}`,
  };

  const passRun = await requestJson(`${clawtrialsBaseUrl}/v1/harness/run`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: {
      ...basePayload,
      submission_id: submissionPass,
      output: {
        worker_did: did,
        result_summary: 'trial pass baseline',
      },
    },
  });
  assertStatus('clawtrials.pass', passRun, 200);
  assertCondition('clawtrials.pass.true', passRun.json?.passed === true, passRun.json);

  const failRun = await requestJson(`${clawtrialsBaseUrl}/v1/harness/run`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: {
      ...basePayload,
      submission_id: submissionFail,
      output: {
        worker_did: did,
        result_summary: '[force_fail] trial fail baseline',
      },
    },
  });
  assertStatus('clawtrials.fail', failRun, 200);
  assertCondition('clawtrials.fail.false', failRun.json?.passed === false, failRun.json);

  const repAfter = await waitForRep(
    clawrepBaseUrl,
    did,
    (rep) => Number(rep?.events_count ?? 0) >= 2 && Number(rep?.penalties_count ?? 0) >= 1,
    { attempts: 40, delayMs: 1000 }
  );

  assertCondition('clawrep.rep.available', repAfter?.status === 200, repAfter);
  assertCondition('clawrep.rep.events_count', Number(repAfter?.json?.events_count ?? 0) >= 2, repAfter?.json);
  assertCondition('clawrep.rep.penalties_count', Number(repAfter?.json?.penalties_count ?? 0) >= 1, repAfter?.json);

  const auditEvents = await requestJson(`${clawrepBaseUrl}/v1/audit/events?limit=50`, {
    method: 'GET',
    headers: {
      authorization: `Bearer ${args.repAdminKey}`,
    },
  });
  assertStatus('clawrep.audit.events', auditEvents, 200);

  const trialAuditHits = (auditEvents.json?.events ?? []).filter((event) => {
    const details = event?.details;
    if (!details || typeof details !== 'object') return false;
    return details.source_service === 'clawtrials';
  });

  const result = {
    env: args.env,
    generated_at: new Date().toISOString(),
    clawtrials_base_url: clawtrialsBaseUrl,
    clawrep_base_url: clawrepBaseUrl,
    did,
    bounty_id: bountyId,
    pass_run: passRun.json,
    fail_run: failRun.json,
    rep_after: repAfter?.json ?? null,
    trial_audit_hits: trialAuditHits,
    assertions: {
      pass_run_passed: passRun.json?.passed === true,
      fail_run_failed: failRun.json?.passed === false,
      rep_events_count_at_least_two: Number(repAfter?.json?.events_count ?? 0) >= 2,
      rep_penalties_count_at_least_one: Number(repAfter?.json?.penalties_count ?? 0) >= 1,
      audit_has_clawtrials_source: trialAuditHits.length > 0,
    },
  };

  writeFileSync(path.join(outDir, 'result.json'), jsonText(result));

  const summary = [
    `clawrep producer-loop smoke (${args.env})`,
    `generated_at=${result.generated_at}`,
    `did=${did}`,
    `pass=${Object.values(result.assertions).every(Boolean) ? 'true' : 'false'}`,
  ];
  writeFileSync(path.join(outDir, 'summary.txt'), `${summary.join('\n')}\n`);
  process.stdout.write(`${summary.join('\n')}\n`);

  if (!Object.values(result.assertions).every(Boolean)) {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack || error.message : String(error));
  process.exitCode = 1;
});
