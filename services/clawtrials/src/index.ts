interface Env {
  ENVIRONMENT?: string;
  CLAWTRIALS_VERSION?: string;
  CLAWREP_BASE_URL?: string;
  CLAWREP_INGEST_KEY?: string;
  REP_EVENTS?: Queue;
}

interface HarnessRunRequest {
  schema_version: '1';
  test_harness_id: string;
  submission_id: string;
  bounty_id: string;
  output: Record<string, unknown>;
  proof_bundle_hash: string;
  timeout_ms?: number;
}

interface HarnessRunResponse {
  schema_version: '1';
  test_harness_id: string;
  submission_id: string;
  bounty_id: string;
  passed: boolean;
  total_tests: number;
  passed_tests: number;
  failed_tests: number;
  execution_time_ms: number;
  completed_at: string;
  error?: string;
  test_results: Array<Record<string, unknown>>;
}

interface HarnessDefinition {
  id: string;
  description: string;
  evaluate: (request: HarnessRunRequest) => {
    passed: boolean;
    test_results: Array<Record<string, unknown>>;
    error?: string;
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

function isDidString(value: unknown): value is string {
  return isNonEmptyString(value) && value.trim().startsWith('did:');
}

type ClawrepLoopEnvelope = {
  schema_version: '1';
  source_event_id: string;
  source_service: 'clawtrials';
  kind: 'penalty' | 'recovery';
  did: string;
  occurred_at: string;
  penalty?: {
    penalty_type:
      | 'dispute_upheld_against_reviewer'
      | 'dispute_upheld_against_worker'
      | 'fraud_confirmed'
      | 'spam_review'
      | 'policy_violation';
    severity?: number;
    reason?: string;
  };
  recovery?: {
    recovery_type: 'appeal_upheld_for_reviewer' | 'appeal_upheld_for_worker';
    severity?: number;
    reason?: string;
  };
  metadata?: Record<string, unknown>;
};

function resolveClawrepBaseUrl(env: Env): string {
  const base = env.CLAWREP_BASE_URL?.trim();
  if (base && base.length > 0) return base;
  return 'https://clawrep.com';
}

async function emitTrialOutcomeToClawrep(env: Env, envelope: ClawrepLoopEnvelope): Promise<void> {
  try {
    if (env.REP_EVENTS) {
      await env.REP_EVENTS.send(envelope, { contentType: 'json' });
      return;
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`[clawtrials] clawrep queue send failed source_event_id=${envelope.source_event_id}: ${message}`);
  }

  if (!env.CLAWREP_INGEST_KEY || env.CLAWREP_INGEST_KEY.trim().length === 0) return;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);

  try {
    const response = await fetch(`${resolveClawrepBaseUrl(env)}/v1/events/ingest-loop`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json; charset=utf-8',
        authorization: `Bearer ${env.CLAWREP_INGEST_KEY}`,
      },
      body: JSON.stringify(envelope),
      signal: controller.signal,
    });

    if (!response.ok && response.status !== 409) {
      const text = await response.text();
      console.error(
        `[clawtrials] clawrep ingest-loop failed status=${response.status} source_event_id=${envelope.source_event_id} body=${text.slice(0, 240)}`
      );
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`[clawtrials] clawrep ingest-loop error source_event_id=${envelope.source_event_id}: ${message}`);
  } finally {
    clearTimeout(timeout);
  }
}

function jsonResponse(payload: unknown, status = 200, version = '0.1.0'): Response {
  return new Response(JSON.stringify(payload, null, 2), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'x-clawtrials-version': version,
    },
  });
}

function textResponse(text: string, status = 200, version = '0.1.0'): Response {
  return new Response(text, {
    status,
    headers: {
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': 'no-store',
      'x-clawtrials-version': version,
    },
  });
}

function errorResponse(code: string, message: string, status: number, version: string, details?: Record<string, unknown>): Response {
  return jsonResponse(
    {
      error: code,
      message,
      ...(details ? { details } : {}),
    },
    status,
    version
  );
}

function deterministicInt(seed: string, min: number, max: number): number {
  let acc = 0;
  for (let i = 0; i < seed.length; i += 1) {
    acc = (acc + seed.charCodeAt(i) * (i + 17)) % 1_000_000_007;
  }
  const span = Math.max(1, max - min + 1);
  return min + (acc % span);
}

function summarizeOutput(output: Record<string, unknown>): string {
  const raw = output.result_summary;
  if (!isNonEmptyString(raw)) return '';
  return raw.trim().toLowerCase();
}

const HARNESSES: HarnessDefinition[] = [
  {
    id: 'th_smoke_pass_v1',
    description: 'Always passes with deterministic smoke assertions',
    evaluate: (request) => ({
      passed: true,
      test_results: [
        {
          name: 'proof_bundle_hash_present',
          status: 'passed',
          details: { proof_bundle_hash: request.proof_bundle_hash },
        },
        {
          name: 'submission_id_format',
          status: request.submission_id.startsWith('sub_') ? 'passed' : 'failed',
        },
        {
          name: 'output_payload_present',
          status: Object.keys(request.output).length > 0 ? 'passed' : 'failed',
        },
      ],
    }),
  },
  {
    id: 'th_smoke_fail_v1',
    description: 'Always fails with deterministic rejection for negative-path testing',
    evaluate: () => ({
      passed: false,
      test_results: [
        {
          name: 'intentional_failure',
          status: 'failed',
          reason: 'Harness configured for deterministic fail-path tests',
        },
      ],
    }),
  },
  {
    id: 'th_policy_summary_v1',
    description: 'Pass/fail derived deterministically from output.result_summary markers',
    evaluate: (request) => {
      const summary = summarizeOutput(request.output);

      if (summary.includes('[force_harness_error]')) {
        return {
          passed: false,
          error: 'HARNESS_RULE_ERROR:force_harness_error',
          test_results: [
            {
              name: 'policy_summary_markers',
              status: 'failed',
              reason: 'force_harness_error marker present',
            },
          ],
        };
      }

      if (summary.includes('[force_fail]')) {
        return {
          passed: false,
          test_results: [
            {
              name: 'policy_summary_markers',
              status: 'failed',
              reason: 'force_fail marker present',
            },
          ],
        };
      }

      if (summary.length === 0) {
        return {
          passed: false,
          test_results: [
            {
              name: 'summary_required',
              status: 'failed',
              reason: 'result_summary must be non-empty',
            },
          ],
        };
      }

      return {
        passed: true,
        test_results: [
          {
            name: 'summary_required',
            status: 'passed',
          },
          {
            name: 'summary_marker_guard',
            status: 'passed',
          },
        ],
      };
    },
  },
];

const HARNESS_MAP = new Map(HARNESSES.map((h) => [h.id, h]));

function validateHarnessRunRequest(body: unknown): { ok: true; request: HarnessRunRequest } | { ok: false; response: Response } {
  if (!isRecord(body)) {
    return {
      ok: false,
      response: jsonResponse({ error: 'INVALID_REQUEST', message: 'Body must be a JSON object' }, 400),
    };
  }

  const schemaVersion = body.schema_version;
  const testHarnessId = body.test_harness_id;
  const submissionId = body.submission_id;
  const bountyId = body.bounty_id;
  const output = body.output;
  const proofBundleHash = body.proof_bundle_hash;
  const timeoutMs = body.timeout_ms;

  if (schemaVersion !== '1') {
    return {
      ok: false,
      response: jsonResponse({ error: 'INVALID_REQUEST', message: 'schema_version must be "1"' }, 400),
    };
  }

  if (!isNonEmptyString(testHarnessId)) {
    return {
      ok: false,
      response: jsonResponse({ error: 'INVALID_REQUEST', message: 'test_harness_id is required' }, 400),
    };
  }

  if (!isNonEmptyString(submissionId)) {
    return {
      ok: false,
      response: jsonResponse({ error: 'INVALID_REQUEST', message: 'submission_id is required' }, 400),
    };
  }

  if (!isNonEmptyString(bountyId)) {
    return {
      ok: false,
      response: jsonResponse({ error: 'INVALID_REQUEST', message: 'bounty_id is required' }, 400),
    };
  }

  if (!isRecord(output)) {
    return {
      ok: false,
      response: jsonResponse({ error: 'INVALID_REQUEST', message: 'output must be an object' }, 400),
    };
  }

  if (!isNonEmptyString(proofBundleHash)) {
    return {
      ok: false,
      response: jsonResponse({ error: 'INVALID_REQUEST', message: 'proof_bundle_hash is required' }, 400),
    };
  }

  if (timeoutMs !== undefined && timeoutMs !== null) {
    if (typeof timeoutMs !== 'number' || !Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > 300_000) {
      return {
        ok: false,
        response: jsonResponse({ error: 'INVALID_REQUEST', message: 'timeout_ms must be a number between 1 and 300000' }, 400),
      };
    }
  }

  return {
    ok: true,
    request: {
      schema_version: '1',
      test_harness_id: testHarnessId.trim(),
      submission_id: submissionId.trim(),
      bounty_id: bountyId.trim(),
      output,
      proof_bundle_hash: proofBundleHash.trim(),
      timeout_ms: typeof timeoutMs === 'number' ? timeoutMs : undefined,
    },
  };
}

function buildHarnessResponse(request: HarnessRunRequest, result: { passed: boolean; test_results: Array<Record<string, unknown>>; error?: string }): HarnessRunResponse {
  const normalized = result.test_results.map((row, index) => {
    const base = isRecord(row) ? row : {};
    const statusRaw = base.status;
    const status = isNonEmptyString(statusRaw) && (statusRaw === 'passed' || statusRaw === 'failed') ? statusRaw : result.passed ? 'passed' : 'failed';
    return {
      test_id: `test_${index + 1}`,
      ...base,
      status,
    };
  });

  const failedCount = normalized.filter((row) => row.status === 'failed').length;
  const passedCount = normalized.length - failedCount;
  const executionTime = deterministicInt(`${request.submission_id}:${request.proof_bundle_hash}`, 80, 320);

  return {
    schema_version: '1',
    test_harness_id: request.test_harness_id,
    submission_id: request.submission_id,
    bounty_id: request.bounty_id,
    passed: result.error ? false : result.passed,
    total_tests: normalized.length,
    passed_tests: passedCount,
    failed_tests: failedCount,
    execution_time_ms: executionTime,
    completed_at: new Date().toISOString(),
    ...(result.error ? { error: result.error } : {}),
    test_results: normalized,
  };
}

function docsPage(origin: string): string {
  const harnessRows = HARNESSES.map((h) => `<li><code>${h.id}</code> — ${h.description}</li>`).join('');
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>clawtrials harness API</title>
    <style>
      body { font-family: ui-sans-serif, system-ui, -apple-system; max-width: 860px; margin: 2rem auto; padding: 0 1rem; line-height: 1.5; }
      code, pre { background: #f4f4f5; border-radius: 6px; padding: 0.2rem 0.35rem; }
      pre { overflow-x: auto; padding: 0.75rem; }
    </style>
  </head>
  <body>
    <h1>clawtrials — harness lane</h1>
    <p>Deterministic staging harness runner for clawbounties test closure.</p>
    <ul>
      <li><code>GET ${origin}/health</code></li>
      <li><code>GET ${origin}/v1/harness/catalog</code></li>
      <li><code>POST ${origin}/v1/harness/run</code></li>
    </ul>
    <h2>Harness IDs</h2>
    <ul>${harnessRows}</ul>
    <h2>Example</h2>
    <pre>curl -sS -X POST "${origin}/v1/harness/run" \\
  -H "content-type: application/json" \\
  --data '{
    "schema_version": "1",
    "test_harness_id": "th_smoke_pass_v1",
    "submission_id": "sub_example",
    "bounty_id": "bty_example",
    "proof_bundle_hash": "abc123",
    "output": { "result_summary": "hello" }
  }'</pre>
  </body>
</html>`;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method.toUpperCase();
    const version = env.CLAWTRIALS_VERSION?.trim() || '0.1.0';

    if (method === 'GET' || method === 'HEAD') {
      if (path === '/' || path === '/docs') {
        return new Response(docsPage(url.origin), {
          status: 200,
          headers: {
            'content-type': 'text/html; charset=utf-8',
            'cache-control': 'no-store',
            'x-clawtrials-version': version,
          },
        });
      }

      if (path === '/health') {
        return jsonResponse(
          {
            status: 'ok',
            service: 'clawtrials',
            version,
            environment: env.ENVIRONMENT ?? 'unknown',
            harness_count: HARNESSES.length,
          },
          200,
          version
        );
      }

      if (path === '/v1/harness/catalog') {
        return jsonResponse(
          {
            schema_version: '1',
            harnesses: HARNESSES.map((h) => ({ id: h.id, description: h.description })),
          },
          200,
          version
        );
      }
    }

    if (path === '/v1/harness/run' && method === 'POST') {
      let parsedBody: unknown;
      try {
        parsedBody = await request.json();
      } catch {
        return errorResponse('INVALID_REQUEST', 'Body must be valid JSON', 400, version);
      }

      const validated = validateHarnessRunRequest(parsedBody);
      if (!validated.ok) return validated.response;

      const runRequest = validated.request;
      const harness = HARNESS_MAP.get(runRequest.test_harness_id);
      if (!harness) {
        const response = buildHarnessResponse(runRequest, {
          passed: false,
          error: `HARNESS_NOT_FOUND:${runRequest.test_harness_id}`,
          test_results: [],
        });
        return jsonResponse(response, 200, version);
      }

      try {
        const result = harness.evaluate(runRequest);
        const response = buildHarnessResponse(runRequest, result);

        const workerDid = isRecord(runRequest.output) ? runRequest.output.worker_did : null;
        if (isDidString(workerDid)) {
          const sourceEventId = `clawtrials:harness:${runRequest.submission_id}:${runRequest.test_harness_id}:${response.passed ? 'pass' : 'fail'}`;
          if (response.passed) {
            await emitTrialOutcomeToClawrep(env, {
              schema_version: '1',
              source_event_id: sourceEventId,
              source_service: 'clawtrials',
              kind: 'recovery',
              did: workerDid.trim(),
              occurred_at: response.completed_at,
              recovery: {
                recovery_type: 'appeal_upheld_for_worker',
                severity: 1,
                reason: 'Trial harness passed',
              },
              metadata: {
                bounty_id: runRequest.bounty_id,
                submission_id: runRequest.submission_id,
                test_harness_id: runRequest.test_harness_id,
                total_tests: response.total_tests,
                failed_tests: response.failed_tests,
              },
            });
          } else {
            await emitTrialOutcomeToClawrep(env, {
              schema_version: '1',
              source_event_id: sourceEventId,
              source_service: 'clawtrials',
              kind: 'penalty',
              did: workerDid.trim(),
              occurred_at: response.completed_at,
              penalty: {
                penalty_type: 'policy_violation',
                severity: 1,
                reason: 'Trial harness failed',
              },
              metadata: {
                bounty_id: runRequest.bounty_id,
                submission_id: runRequest.submission_id,
                test_harness_id: runRequest.test_harness_id,
                total_tests: response.total_tests,
                failed_tests: response.failed_tests,
              },
            });
          }
        }

        return jsonResponse(response, 200, version);
      } catch (err) {
        const reason = err instanceof Error ? err.message : 'Unknown error';
        const response = buildHarnessResponse(runRequest, {
          passed: false,
          error: `HARNESS_EXECUTION_FAILED:${reason}`,
          test_results: [],
        });

        const workerDid = isRecord(runRequest.output) ? runRequest.output.worker_did : null;
        if (isDidString(workerDid)) {
          await emitTrialOutcomeToClawrep(env, {
            schema_version: '1',
            source_event_id: `clawtrials:harness:${runRequest.submission_id}:${runRequest.test_harness_id}:error`,
            source_service: 'clawtrials',
            kind: 'penalty',
            did: workerDid.trim(),
            occurred_at: response.completed_at,
            penalty: {
              penalty_type: 'policy_violation',
              severity: 1,
              reason: 'Trial harness execution failed',
            },
            metadata: {
              bounty_id: runRequest.bounty_id,
              submission_id: runRequest.submission_id,
              test_harness_id: runRequest.test_harness_id,
            },
          });
        }

        return jsonResponse(response, 200, version);
      }
    }

    if (path === '/robots.txt') return textResponse('User-agent: *\nAllow: /\n', 200, version);

    return errorResponse('NOT_FOUND', 'Not found', 404, version, { path, method });
  },
};
