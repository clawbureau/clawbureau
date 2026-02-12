/**
 * Claw Verified GitHub App — Cloudflare Worker
 *
 * Receives GitHub webhook events for PRs, discovers proof bundles,
 * runs offline verification, and posts "Claw Verified" check runs.
 *
 * Trust model per Gemini Deep Think decisions:
 * - Repo-Anchored TOFU (WPC unsigned, branch protection = trust)
 * - Gateway DID Allowlist (hardcoded trusted signers)
 * - Agent identity informational only
 */

import type { Env, WebhookEvent } from './types';
import { getInstallationToken, createCheckRun } from './github';
import { loadPolicy } from './policy';
import { verifyPR } from './verify';

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // Health check
    if (url.pathname === '/health') {
      return Response.json({ status: 'ok', service: 'claw-verified-app' });
    }

    // Webhook endpoint
    if (url.pathname === '/webhook' && request.method === 'POST') {
      return handleWebhook(request, env);
    }

    return new Response('Claw Verified GitHub App', { status: 200 });
  },
};

// ---------- Webhook Handler ----------

async function handleWebhook(request: Request, env: Env): Promise<Response> {
  // 1. Verify webhook signature FIRST (fail-closed)
  const signature = request.headers.get('x-hub-signature-256');
  if (!signature) {
    return Response.json({ error: 'missing_signature' }, { status: 401 });
  }

  const body = await request.text();

  const valid = await verifyWebhookSignature(body, signature, env.GITHUB_WEBHOOK_SECRET);
  if (!valid) {
    return Response.json({ error: 'invalid_signature' }, { status: 401 });
  }

  // 2. Parse event
  const event = request.headers.get('x-github-event');
  let payload: WebhookEvent;
  try {
    payload = JSON.parse(body) as WebhookEvent;
  } catch {
    return Response.json({ error: 'invalid_json' }, { status: 400 });
  }

  // 3. Route to handler
  if (event === 'pull_request' && (payload.action === 'opened' || payload.action === 'synchronize')) {
    await handlePullRequest(payload, env);
    return Response.json({ ok: true });
  }

  if (event === 'check_suite' && (payload.action === 'requested' || payload.action === 'rerequested')) {
    await handleCheckSuite(payload, env);
    return Response.json({ ok: true });
  }

  // Acknowledge other events without processing
  return Response.json({ ok: true, skipped: true });
}

// ---------- Event Handlers ----------

async function handlePullRequest(payload: WebhookEvent, env: Env): Promise<void> {
  const { installation, repository, pull_request: pr } = payload;
  if (!installation || !repository || !pr) return;

  const token = await getInstallationToken(env, installation.id);

  // Load policy from default branch
  const { policy, source } = await loadPolicy(
    token,
    repository.full_name,
    repository.default_branch,
  );

  // Run verification
  const result = await verifyPR(
    token,
    repository.full_name,
    pr.number,
    pr.head.sha,
    policy,
    source,
  );

  // Post check run
  await createCheckRun(
    token,
    repository.full_name,
    pr.head.sha,
    result.conclusion,
    result.output,
  );
}

async function handleCheckSuite(payload: WebhookEvent, env: Env): Promise<void> {
  const { installation, repository, check_suite: suite } = payload;
  if (!installation || !repository || !suite) return;
  if (!suite.pull_requests || suite.pull_requests.length === 0) return;

  const token = await getInstallationToken(env, installation.id);

  const { policy, source } = await loadPolicy(
    token,
    repository.full_name,
    repository.default_branch,
  );

  // Process each associated PR
  for (const pr of suite.pull_requests) {
    const result = await verifyPR(
      token,
      repository.full_name,
      pr.number,
      suite.head_sha,
      policy,
      source,
    );

    await createCheckRun(
      token,
      repository.full_name,
      suite.head_sha,
      result.conclusion,
      result.output,
    );
  }
}

// ---------- Webhook Signature Verification ----------

/**
 * Verify GitHub webhook HMAC-SHA256 signature.
 * MUST be called before any processing (fail-closed).
 */
async function verifyWebhookSignature(
  body: string,
  signature: string,
  secret: string,
): Promise<boolean> {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );

  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(body));
  const expected = 'sha256=' + Array.from(new Uint8Array(sig))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

  // Constant-time comparison
  if (expected.length !== signature.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) {
    diff |= expected.charCodeAt(i) ^ signature.charCodeAt(i);
  }
  return diff === 0;
}
