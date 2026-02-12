/**
 * GitHub API client for the Claw Verified App.
 * Handles JWT auth, installation tokens, check runs, and file content.
 */

import type { Env, CheckRunOutput } from './types';

const GITHUB_API = 'https://api.github.com';

// ---------- JWT Generation ----------

/**
 * Generate a GitHub App JWT for authentication.
 * JWT is signed with the App's private key and valid for 10 minutes.
 */
export async function generateAppJWT(env: Env): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT' };
  const payload = {
    iat: now - 60, // clock skew
    exp: now + 600, // 10 minutes
    iss: env.GITHUB_APP_ID,
  };

  const headerB64 = btoa(JSON.stringify(header)).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
  const payloadB64 = btoa(JSON.stringify(payload)).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
  const signingInput = `${headerB64}.${payloadB64}`;

  // Import the PEM private key
  const key = await importPKCS8Key(env.GITHUB_PRIVATE_KEY);
  const signature = await crypto.subtle.sign(
    { name: 'RSASSA-PKCS1-v1_5' },
    key,
    new TextEncoder().encode(signingInput),
  );

  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');

  return `${signingInput}.${sigB64}`;
}

/**
 * Import a PEM-encoded PKCS#8 private key for RS256 signing.
 */
async function importPKCS8Key(pem: string): Promise<CryptoKey> {
  const pemBody = pem
    .replace(/-----BEGIN.*?-----/g, '')
    .replace(/-----END.*?-----/g, '')
    .replace(/\s/g, '');
  const binary = Uint8Array.from(atob(pemBody), c => c.charCodeAt(0));

  return crypto.subtle.importKey(
    'pkcs8',
    binary.buffer,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign'],
  );
}

// ---------- Installation Token ----------

/**
 * Get an installation access token for API calls.
 */
export async function getInstallationToken(
  env: Env,
  installationId: number,
): Promise<string> {
  const jwt = await generateAppJWT(env);
  const resp = await fetch(
    `${GITHUB_API}/app/installations/${installationId}/access_tokens`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${jwt}`,
        Accept: 'application/vnd.github+json',
        'User-Agent': 'claw-verified-app',
        'X-GitHub-Api-Version': '2022-11-28',
      },
    },
  );

  if (!resp.ok) {
    const body = await resp.text();
    throw new Error(`Failed to get installation token: ${resp.status} ${body}`);
  }

  const data = await resp.json() as { token: string };
  return data.token;
}

// ---------- Check Runs ----------

/**
 * Create a check run on a commit.
 */
export async function createCheckRun(
  token: string,
  repo: string,
  headSha: string,
  conclusion: 'success' | 'failure' | 'neutral' | 'action_required',
  output: CheckRunOutput,
): Promise<void> {
  const resp = await fetch(`${GITHUB_API}/repos/${repo}/check-runs`, {
    method: 'POST',
    headers: {
      Authorization: `token ${token}`,
      Accept: 'application/vnd.github+json',
      'Content-Type': 'application/json',
      'User-Agent': 'claw-verified-app',
      'X-GitHub-Api-Version': '2022-11-28',
    },
    body: JSON.stringify({
      name: 'Claw Verified',
      head_sha: headSha,
      status: 'completed',
      conclusion,
      output,
    }),
  });

  if (!resp.ok) {
    const body = await resp.text();
    throw new Error(`Failed to create check run: ${resp.status} ${body}`);
  }
}

// ---------- File Content ----------

/**
 * Get file content from a repo at a specific ref.
 */
export async function getFileContent(
  token: string,
  repo: string,
  path: string,
  ref: string,
): Promise<string | null> {
  const resp = await fetch(
    `${GITHUB_API}/repos/${repo}/contents/${encodeURIComponent(path)}?ref=${ref}`,
    {
      headers: {
        Authorization: `token ${token}`,
        Accept: 'application/vnd.github.raw+json',
        'User-Agent': 'claw-verified-app',
        'X-GitHub-Api-Version': '2022-11-28',
      },
    },
  );

  if (resp.status === 404) return null;
  if (!resp.ok) return null;
  return resp.text();
}

// ---------- PR Files ----------

/**
 * List files changed in a PR.
 */
export async function getPRFiles(
  token: string,
  repo: string,
  prNumber: number,
): Promise<Array<{ filename: string; sha: string; status: string }>> {
  const resp = await fetch(
    `${GITHUB_API}/repos/${repo}/pulls/${prNumber}/files?per_page=100`,
    {
      headers: {
        Authorization: `token ${token}`,
        Accept: 'application/vnd.github+json',
        'User-Agent': 'claw-verified-app',
        'X-GitHub-Api-Version': '2022-11-28',
      },
    },
  );

  if (!resp.ok) return [];
  return resp.json() as Promise<Array<{ filename: string; sha: string; status: string }>>;
}
