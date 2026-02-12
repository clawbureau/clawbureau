/**
 * Claw Verified GitHub App — Cloudflare Worker Entry Point
 *
 * Receives GitHub webhook events (pull_request, check_suite) and runs
 * Clawsig proof bundle verification. Posts Check Runs with PASS/FAIL
 * results and detailed reason codes.
 *
 * Security: Webhook signature verification (HMAC SHA-256) MUST pass
 * before any other processing (fail-closed).
 */

import type {
  Env,
  PullRequestEvent,
  CheckSuiteEvent,
} from './types.js';
import { GitHubClient } from './github.js';
import { verifyPullRequest } from './verify.js';

const CHECK_NAME = 'Claw Verified';

// ---------------------------------------------------------------------------
// Webhook signature verification (HMAC SHA-256)
// ---------------------------------------------------------------------------

/**
 * Verify the GitHub webhook HMAC-SHA256 signature.
 * Fail-closed: returns false on any error.
 */
async function verifyWebhookSignature(
  secret: string,
  payload: string,
  signatureHeader: string | null,
): Promise<boolean> {
  if (!signatureHeader) return false;

  // GitHub sends: sha256=<hex>
  const prefix = 'sha256=';
  if (!signatureHeader.startsWith(prefix)) return false;
  const expectedHex = signatureHeader.slice(prefix.length);

  try {
    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    );

    const signature = await crypto.subtle.sign(
      'HMAC',
      key,
      new TextEncoder().encode(payload),
    );

    const computedHex = Array.from(new Uint8Array(signature))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');

    // Constant-time comparison
    if (computedHex.length !== expectedHex.length) return false;

    let mismatch = 0;
    for (let i = 0; i < computedHex.length; i++) {
      mismatch |= computedHex.charCodeAt(i) ^ expectedHex.charCodeAt(i);
    }
    return mismatch === 0;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Event handlers
// ---------------------------------------------------------------------------

async function handlePullRequestEvent(
  event: PullRequestEvent,
  env: Env,
): Promise<Response> {
  // Only process opened and synchronize (new commits pushed)
  if (event.action !== 'opened' && event.action !== 'synchronize') {
    return new Response('Ignored PR action', { status: 200 });
  }

  const client = await GitHubClient.fromInstallation(
    env,
    event.installation.id,
  );

  // Post initial "in_progress" check run
  const startedAt = new Date().toISOString();
  await client.createCheckRun({
    owner: event.repository.owner.login,
    repo: event.repository.name,
    name: CHECK_NAME,
    head_sha: event.pull_request.head.sha,
    status: 'in_progress',
    started_at: startedAt,
  });

  // Run verification
  const output = await verifyPullRequest(
    client,
    event.repository,
    event.pull_request,
  );

  // Post completed check run
  await client.createCheckRun({
    owner: event.repository.owner.login,
    repo: event.repository.name,
    name: CHECK_NAME,
    head_sha: event.pull_request.head.sha,
    status: 'completed',
    conclusion: output.conclusion,
    started_at: startedAt,
    completed_at: new Date().toISOString(),
    output: {
      title: output.title,
      summary: output.summary,
      text: output.text,
    },
  });

  return new Response(
    JSON.stringify({
      status: 'ok',
      conclusion: output.conclusion,
      bundles_found: output.bundles_found,
    }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  );
}

async function handleCheckSuiteEvent(
  event: CheckSuiteEvent,
  env: Env,
): Promise<Response> {
  // Only process requested and rerequested
  if (event.action !== 'requested' && event.action !== 'rerequested') {
    return new Response('Ignored check_suite action', { status: 200 });
  }

  // check_suite events include associated PRs
  const pullRequests = event.check_suite.pull_requests;
  if (pullRequests.length === 0) {
    return new Response('No pull requests in check suite', { status: 200 });
  }

  const client = await GitHubClient.fromInstallation(
    env,
    event.installation.id,
  );

  // Process the first associated PR
  const pr = pullRequests[0];
  const startedAt = new Date().toISOString();

  await client.createCheckRun({
    owner: event.repository.owner.login,
    repo: event.repository.name,
    name: CHECK_NAME,
    head_sha: event.check_suite.head_sha,
    status: 'in_progress',
    started_at: startedAt,
  });

  const output = await verifyPullRequest(client, event.repository, pr);

  await client.createCheckRun({
    owner: event.repository.owner.login,
    repo: event.repository.name,
    name: CHECK_NAME,
    head_sha: event.check_suite.head_sha,
    status: 'completed',
    conclusion: output.conclusion,
    started_at: startedAt,
    completed_at: new Date().toISOString(),
    output: {
      title: output.title,
      summary: output.summary,
      text: output.text,
    },
  });

  return new Response(
    JSON.stringify({
      status: 'ok',
      conclusion: output.conclusion,
    }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  );
}

// ---------------------------------------------------------------------------
// Worker entry
// ---------------------------------------------------------------------------

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // Health check
    if (url.pathname === '/health') {
      return new Response(
        JSON.stringify({ status: 'ok', service: 'claw-verified-app' }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      );
    }

    // Only accept POST to webhook endpoint
    if (request.method !== 'POST' || url.pathname !== '/webhook') {
      return new Response('Not Found', { status: 404 });
    }

    // -----------------------------------------------------------------------
    // WEBHOOK SIGNATURE VERIFICATION (FAIL-CLOSED — before ANY processing)
    // -----------------------------------------------------------------------
    const body = await request.text();
    const signatureHeader = request.headers.get('x-hub-signature-256');

    const signatureValid = await verifyWebhookSignature(
      env.GITHUB_WEBHOOK_SECRET,
      body,
      signatureHeader,
    );

    if (!signatureValid) {
      return new Response('Unauthorized: Invalid webhook signature', {
        status: 401,
      });
    }

    // -----------------------------------------------------------------------
    // Route by event type
    // -----------------------------------------------------------------------
    const eventType = request.headers.get('x-github-event');

    try {
      if (eventType === 'pull_request') {
        const event = JSON.parse(body) as PullRequestEvent;
        return await handlePullRequestEvent(event, env);
      }

      if (eventType === 'check_suite') {
        const event = JSON.parse(body) as CheckSuiteEvent;
        return await handleCheckSuiteEvent(event, env);
      }

      // Ping event (app installation verification)
      if (eventType === 'ping') {
        return new Response(JSON.stringify({ status: 'pong' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      return new Response(`Unhandled event: ${eventType}`, { status: 200 });
    } catch (err) {
      const message =
        err instanceof Error ? err.message : 'Internal server error';
      console.error(`Webhook handler error: ${message}`);

      return new Response(
        JSON.stringify({ error: message }),
        { status: 500, headers: { 'Content-Type': 'application/json' } },
      );
    }
  },
};
