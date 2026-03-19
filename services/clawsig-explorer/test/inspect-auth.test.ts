import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  beginGithubOauth,
  completeGithubOauth,
} from '../src/inspect-auth.js';

function b64Url(input: string): string {
  return Buffer.from(input, 'utf-8')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('inspect auth flow', () => {
  it('redirects to inspect with oauth_not_configured when client config is missing', () => {
    const request = new Request('https://explorer.clawsig.test/auth/github/login');
    const response = beginGithubOauth(request, {});

    expect(response.status).toBe(302);
    expect(response.headers.get('Location')).toBe('https://explorer.clawsig.test/inspect?auth=oauth_not_configured');
  });

  it('handles denied OAuth callback with explicit auth status', async () => {
    const request = new Request(
      'https://explorer.clawsig.test/auth/github/callback?error=access_denied',
    );

    const response = await completeGithubOauth(request, {});

    expect(response.status).toBe(302);
    expect(response.headers.get('Location')).toBe('https://explorer.clawsig.test/inspect?auth=access_denied');
  });

  it('handles token exchange network failures', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('network down')));

    const state = 'state123';
    const returnTo = '/inspect?bundle=https://example.com/proof_bundle.v2.json';
    const cookieValue = `${state}|${b64Url(returnTo)}`;

    const request = new Request(
      `https://explorer.clawsig.test/auth/github/callback?code=abc123&state=${state}`,
      {
        headers: {
          cookie: `clawsig_explorer_oauth_state=${cookieValue}`,
        },
      },
    );

    const response = await completeGithubOauth(request, {
      GITHUB_OAUTH_CLIENT_ID: 'cid',
      GITHUB_OAUTH_CLIENT_SECRET: 'secret',
      EXPLORER_SESSION_SECRET: 'session-secret',
    });

    expect(response.status).toBe(302);
    expect(response.headers.get('Location')).toBe('https://explorer.clawsig.test/inspect?auth=oauth_network_error');
  });
});
