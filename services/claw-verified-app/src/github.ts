/**
 * GitHub API Client — JWT Auth, Installation Tokens, Check Runs
 *
 * Handles:
 * - GitHub App JWT generation (RS256 via Web Crypto)
 * - Installation token acquisition
 * - Check Run creation/updates
 * - File content fetching (for policy + bundle download)
 * - PR file listing
 *
 * All calls use fail-closed error handling.
 */

import type {
  Env,
  CreateCheckRunParams,
  PRFile,
} from './types.js';

const GITHUB_API = 'https://api.github.com';

// ---------------------------------------------------------------------------
// JWT generation for GitHub App authentication (RS256)
// ---------------------------------------------------------------------------

function base64UrlEncodeString(str: string): string {
  const bytes = new TextEncoder().encode(str);
  return base64UrlEncodeBytes(bytes);
}

function base64UrlEncodeBytes(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Import a PEM-encoded PKCS#8 private key for RS256.
 * GitHub App private keys are RSA 2048-bit in PEM PKCS#8 format.
 */
async function importPrivateKey(pem: string): Promise<CryptoKey> {
  // Normalize: strip PEM headers, whitespace, and convert to binary
  const pemBody = pem
    .replace(/-----BEGIN RSA PRIVATE KEY-----/g, '')
    .replace(/-----END RSA PRIVATE KEY-----/g, '')
    .replace(/-----BEGIN PRIVATE KEY-----/g, '')
    .replace(/-----END PRIVATE KEY-----/g, '')
    .replace(/[\n\r\s]/g, '');

  const binaryString = atob(pemBody);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }

  // Try PKCS#8 first, fall back to pkcs8 with different header detection
  try {
    return await crypto.subtle.importKey(
      'pkcs8',
      bytes.buffer as ArrayBuffer,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['sign'],
    );
  } catch {
    // If the PEM was an RSA PRIVATE KEY (PKCS#1), we need to wrap it.
    // For now, throw — GitHub App keys should be PKCS#8.
    throw new Error('Failed to import GitHub App private key. Ensure it is in PKCS#8 PEM format.');
  }
}

/**
 * Generate a GitHub App JWT (RS256, 10-minute expiry).
 */
async function generateAppJwt(env: Env): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT' };
  const payload = {
    iat: now - 60, // clock skew tolerance
    exp: now + 600, // 10 minutes
    iss: env.GITHUB_APP_ID,
  };

  const headerB64 = base64UrlEncodeString(JSON.stringify(header));
  const payloadB64 = base64UrlEncodeString(JSON.stringify(payload));
  const signingInput = `${headerB64}.${payloadB64}`;

  const key = await importPrivateKey(env.GITHUB_PRIVATE_KEY);
  const signature = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    key,
    new TextEncoder().encode(signingInput),
  );

  const signatureB64 = base64UrlEncodeBytes(new Uint8Array(signature));
  return `${signingInput}.${signatureB64}`;
}

// ---------------------------------------------------------------------------
// Installation token
// ---------------------------------------------------------------------------

interface InstallationToken {
  token: string;
  expires_at: string;
}

/**
 * Exchange App JWT for an installation access token.
 */
async function getInstallationToken(
  env: Env,
  installationId: number,
): Promise<InstallationToken> {
  const jwt = await generateAppJwt(env);

  const response = await fetch(
    `${GITHUB_API}/app/installations/${installationId}/access_tokens`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${jwt}`,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'ClawVerified/0.1.0',
      },
    },
  );

  if (!response.ok) {
    const body = await response.text();
    throw new Error(
      `Failed to get installation token (${response.status}): ${body}`,
    );
  }

  return (await response.json()) as InstallationToken;
}

// ---------------------------------------------------------------------------
// GitHub API client class
// ---------------------------------------------------------------------------

export class GitHubClient {
  private token: string;

  constructor(token: string) {
    this.token = token;
  }

  /**
   * Create a GitHubClient from an installation ID.
   * Handles JWT creation and token exchange.
   */
  static async fromInstallation(
    env: Env,
    installationId: number,
  ): Promise<GitHubClient> {
    const tokenData = await getInstallationToken(env, installationId);
    return new GitHubClient(tokenData.token);
  }

  private headers(): Record<string, string> {
    return {
      Authorization: `token ${this.token}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'ClawVerified/0.1.0',
    };
  }

  /**
   * Create a Check Run on a commit.
   */
  async createCheckRun(params: CreateCheckRunParams): Promise<void> {
    const body: Record<string, unknown> = {
      name: params.name,
      head_sha: params.head_sha,
      status: params.status,
    };

    if (params.conclusion) body.conclusion = params.conclusion;
    if (params.output) body.output = params.output;
    if (params.started_at) body.started_at = params.started_at;
    if (params.completed_at) body.completed_at = params.completed_at;

    const response = await fetch(
      `${GITHUB_API}/repos/${params.owner}/${params.repo}/check-runs`,
      {
        method: 'POST',
        headers: { ...this.headers(), 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      },
    );

    if (!response.ok) {
      const errBody = await response.text();
      throw new Error(
        `Failed to create check run (${response.status}): ${errBody}`,
      );
    }
  }

  /**
   * List files changed in a pull request.
   */
  async listPRFiles(
    owner: string,
    repo: string,
    prNumber: number,
  ): Promise<PRFile[]> {
    const allFiles: PRFile[] = [];
    let page = 1;
    const perPage = 100;

    // Paginate — PRs can have many files
    while (true) {
      const response = await fetch(
        `${GITHUB_API}/repos/${owner}/${repo}/pulls/${prNumber}/files?per_page=${perPage}&page=${page}`,
        { headers: this.headers() },
      );

      if (!response.ok) {
        const errBody = await response.text();
        throw new Error(
          `Failed to list PR files (${response.status}): ${errBody}`,
        );
      }

      const files = (await response.json()) as PRFile[];
      allFiles.push(...files);

      if (files.length < perPage) break;
      page++;

      // Safety: cap at 1000 files
      if (allFiles.length >= 1000) break;
    }

    return allFiles;
  }

  /**
   * Download raw file content from a specific ref.
   * Returns null if file does not exist (404).
   */
  async getFileContent(
    owner: string,
    repo: string,
    path: string,
    ref: string,
  ): Promise<string | null> {
    const response = await fetch(
      `${GITHUB_API}/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}?ref=${encodeURIComponent(ref)}`,
      {
        headers: {
          ...this.headers(),
          Accept: 'application/vnd.github.raw+json',
        },
      },
    );

    if (response.status === 404) return null;

    if (!response.ok) {
      const errBody = await response.text();
      throw new Error(
        `Failed to get file content (${response.status}): ${errBody}`,
      );
    }

    return response.text();
  }

  /**
   * Download raw file content from the PR head ref (the branch being merged).
   */
  async getFileContentFromPRHead(
    owner: string,
    repo: string,
    path: string,
    headSha: string,
  ): Promise<string | null> {
    return this.getFileContent(owner, repo, path, headSha);
  }
}
