import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm, readFile, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { generateIdentity } from '../src/identity.js';
import {
  __setFetch,
  __setOpenUrl,
  defaultGithubBindingPath,
  isGithubBindingStore,
  linkGithubIdentity,
  showGithubIdentity,
} from '../src/identity-github.js';

let tmpDir: string;
let originalHome: string | undefined;
let restoreFetch: (() => void) | undefined;
let restoreOpenUrl: (() => void) | undefined;

function jsonResponse(status: number, payload: unknown): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

async function homeOverrideWorks(): Promise<boolean> {
  const { homedir } = await import('node:os');
  return homedir() === process.env['HOME'];
}

function installFetchQueue(queue: Array<Response | Error>): void {
  restoreFetch?.();
  restoreFetch = __setFetch(async () => {
    const next = queue.shift();
    if (!next) throw new Error('No more mocked responses');
    if (next instanceof Error) throw next;
    return next;
  });
}

function queueDeviceFlow(login: string, id: number, htmlUrl?: string): Response[] {
  return [
    jsonResponse(200, {
      device_code: `device_${login}`,
      user_code: 'ABCD-EFGH',
      verification_uri: 'https://github.com/login/device',
      verification_uri_complete: 'https://github.com/login/device?user_code=ABCD-EFGH',
      expires_in: 900,
      interval: 0,
    }),
    jsonResponse(200, {
      access_token: `token_${login}`,
      token_type: 'bearer',
      scope: 'read:user',
    }),
    jsonResponse(200, {
      login,
      id,
      html_url: htmlUrl,
    }),
  ];
}

beforeEach(async () => {
  tmpDir = await mkdtemp(join(tmpdir(), 'clawsig-github-binding-test-'));
  originalHome = process.env['HOME'];
  process.env['HOME'] = join(tmpDir, 'home');

  delete process.env['CLAWSIG_IDENTITY'];
  delete process.env['CLAWSIG_GITHUB_OAUTH_CLIENT_ID'];
  delete process.env['CLAWSIG_GITHUB_BINDING_LEDGER_URL'];
  delete process.env['CLAWSIG_GITHUB_BINDING_LEDGER_TOKEN'];

  restoreFetch = undefined;
  restoreOpenUrl = undefined;
});

afterEach(async () => {
  restoreFetch?.();
  restoreOpenUrl?.();
  process.env['HOME'] = originalHome;

  delete process.env['CLAWSIG_IDENTITY'];
  delete process.env['CLAWSIG_GITHUB_OAUTH_CLIENT_ID'];
  delete process.env['CLAWSIG_GITHUB_BINDING_LEDGER_URL'];
  delete process.env['CLAWSIG_GITHUB_BINDING_LEDGER_TOKEN'];

  await rm(tmpDir, { recursive: true, force: true });
});

describe('identity github binding', () => {
  it('links GitHub identity to current DID and writes ~/.clawsig/github-binding.json', async () => {
    if (!(await homeOverrideWorks())) return;

    const identityPath = join(tmpDir, 'id1.jwk.json');
    const identity = await generateIdentity(identityPath);
    process.env['CLAWSIG_IDENTITY'] = identityPath;
    process.env['CLAWSIG_GITHUB_OAUTH_CLIENT_ID'] = 'client_123';

    installFetchQueue(queueDeviceFlow('octocat', 1, 'https://github.com/octocat'));
    restoreOpenUrl = __setOpenUrl(() => true);

    const result = await linkGithubIdentity({
      githubUsername: 'octocat',
      json: true,
      openBrowser: false,
    });

    expect(result.status).toBe('ok');
    expect(result.github_username).toBe('octocat');
    expect(result.github_user_id).toBe(1);
    expect(result.did).toBe(identity.did);
    expect(result.linked_dids).toEqual([identity.did]);
    expect(result.attestation.payload.statement).toBe(`GitHub user octocat controls DID ${identity.did}`);

    const bindingPath = defaultGithubBindingPath();
    expect(result.binding_path).toBe(bindingPath);

    const raw = await readFile(bindingPath, 'utf-8');
    const parsed: unknown = JSON.parse(raw);
    expect(isGithubBindingStore(parsed)).toBe(true);

    if (!isGithubBindingStore(parsed)) {
      throw new Error('Parsed store is not valid');
    }

    expect(parsed.github.username).toBe('octocat');
    expect(parsed.github.linked_dids).toEqual([identity.did]);
    expect(parsed.attestations).toHaveLength(1);

    if (process.platform !== 'win32') {
      const dirMode = (await stat(join(tmpDir, 'home', '.clawsig'))).mode & 0o777;
      const fileMode = (await stat(bindingPath)).mode & 0o777;
      expect(dirMode).toBe(0o700);
      expect(fileMode).toBe(0o600);
    }

    const shown = await showGithubIdentity();
    expect(shown.status).toBe('ok');
    expect(shown.identity_did).toBe(identity.did);
    expect(shown.github_binding?.github_username).toBe('octocat');
    expect(shown.github_binding?.linked_dids).toEqual([identity.did]);
  });

  it('fails closed when authenticated GitHub login does not match --github', async () => {
    if (!(await homeOverrideWorks())) return;

    const identityPath = join(tmpDir, 'id1.jwk.json');
    await generateIdentity(identityPath);
    process.env['CLAWSIG_IDENTITY'] = identityPath;
    process.env['CLAWSIG_GITHUB_OAUTH_CLIENT_ID'] = 'client_123';

    installFetchQueue(queueDeviceFlow('someoneelse', 9, 'https://github.com/someoneelse'));
    restoreOpenUrl = __setOpenUrl(() => true);

    await expect(
      linkGithubIdentity({
        githubUsername: 'octocat',
        json: true,
        openBrowser: false,
      }),
    ).rejects.toMatchObject({ code: 'USERNAME_MISMATCH' });

    await expect(readFile(defaultGithubBindingPath(), 'utf-8')).rejects.toMatchObject({
      code: 'ENOENT',
    });
  });

  it('supports multiple DIDs bound to the same GitHub user', async () => {
    if (!(await homeOverrideWorks())) return;

    const identityPath1 = join(tmpDir, 'id1.jwk.json');
    const identityPath2 = join(tmpDir, 'id2.jwk.json');
    const id1 = await generateIdentity(identityPath1);
    const id2 = await generateIdentity(identityPath2);

    process.env['CLAWSIG_GITHUB_OAUTH_CLIENT_ID'] = 'client_123';

    installFetchQueue([
      ...queueDeviceFlow('octocat', 1, 'https://github.com/octocat'),
      ...queueDeviceFlow('octocat', 1, 'https://github.com/octocat'),
    ]);
    restoreOpenUrl = __setOpenUrl(() => true);

    process.env['CLAWSIG_IDENTITY'] = identityPath1;
    await linkGithubIdentity({ githubUsername: 'octocat', json: true, openBrowser: false });

    process.env['CLAWSIG_IDENTITY'] = identityPath2;
    await linkGithubIdentity({ githubUsername: 'octocat', json: true, openBrowser: false });

    const raw = await readFile(defaultGithubBindingPath(), 'utf-8');
    const parsed: unknown = JSON.parse(raw);

    if (!isGithubBindingStore(parsed)) {
      throw new Error('Parsed store is not valid');
    }

    expect(parsed.github.username).toBe('octocat');
    expect(parsed.github.user_id).toBe(1);
    expect(parsed.github.linked_dids).toHaveLength(2);
    expect(parsed.github.linked_dids).toContain(id1.did);
    expect(parsed.github.linked_dids).toContain(id2.did);
    expect(parsed.attestations).toHaveLength(2);
  });

  it('relinking the same DID is idempotent and does not append duplicate attestations', async () => {
    if (!(await homeOverrideWorks())) return;

    const identityPath = join(tmpDir, 'id1.jwk.json');
    const identity = await generateIdentity(identityPath);

    process.env['CLAWSIG_IDENTITY'] = identityPath;
    process.env['CLAWSIG_GITHUB_OAUTH_CLIENT_ID'] = 'client_123';

    installFetchQueue([
      ...queueDeviceFlow('octocat', 1, 'https://github.com/octocat'),
      ...queueDeviceFlow('octocat', 1, 'https://github.com/octocat'),
    ]);

    await linkGithubIdentity({ githubUsername: 'octocat', json: true, openBrowser: false });
    await linkGithubIdentity({ githubUsername: 'octocat', json: true, openBrowser: false });

    const raw = await readFile(defaultGithubBindingPath(), 'utf-8');
    const parsed: unknown = JSON.parse(raw);

    if (!isGithubBindingStore(parsed)) {
      throw new Error('Parsed store is not valid');
    }

    expect(parsed.github.linked_dids).toEqual([identity.did]);
    expect(parsed.attestations).toHaveLength(1);
  });

  it('updates stored GitHub username/profile when user id matches', async () => {
    if (!(await homeOverrideWorks())) return;

    const identityPath1 = join(tmpDir, 'id1.jwk.json');
    const identityPath2 = join(tmpDir, 'id2.jwk.json');
    await generateIdentity(identityPath1);
    await generateIdentity(identityPath2);

    process.env['CLAWSIG_GITHUB_OAUTH_CLIENT_ID'] = 'client_123';

    installFetchQueue([
      ...queueDeviceFlow('octocat', 1, 'https://github.com/octocat'),
      ...queueDeviceFlow('octo-renamed', 1, 'https://github.com/octo-renamed'),
    ]);

    process.env['CLAWSIG_IDENTITY'] = identityPath1;
    await linkGithubIdentity({ githubUsername: 'octocat', json: true, openBrowser: false });

    process.env['CLAWSIG_IDENTITY'] = identityPath2;
    await linkGithubIdentity({ githubUsername: 'octo-renamed', json: true, openBrowser: false });

    const raw = await readFile(defaultGithubBindingPath(), 'utf-8');
    const parsed: unknown = JSON.parse(raw);

    if (!isGithubBindingStore(parsed)) {
      throw new Error('Parsed store is not valid');
    }

    expect(parsed.github.user_id).toBe(1);
    expect(parsed.github.username).toBe('octo-renamed');
    expect(parsed.github.profile_url).toBe('https://github.com/octo-renamed');
  });

  it('maps fetch failures to GithubBindingError codes', async () => {
    if (!(await homeOverrideWorks())) return;

    const identityPath = join(tmpDir, 'id1.jwk.json');
    await generateIdentity(identityPath);

    process.env['CLAWSIG_IDENTITY'] = identityPath;
    process.env['CLAWSIG_GITHUB_OAUTH_CLIENT_ID'] = 'client_123';

    installFetchQueue([new Error('device flow offline')]);
    await expect(
      linkGithubIdentity({ githubUsername: 'octocat', json: true, openBrowser: false }),
    ).rejects.toMatchObject({ code: 'GITHUB_DEVICE_CODE_REQUEST_FAILED' });

    installFetchQueue([
      jsonResponse(200, {
        device_code: 'device_1',
        user_code: 'ABCD-EFGH',
        verification_uri: 'https://github.com/login/device',
        verification_uri_complete: 'https://github.com/login/device?user_code=ABCD-EFGH',
        expires_in: 900,
        interval: 0,
      }),
      new Error('token endpoint offline'),
    ]);
    await expect(
      linkGithubIdentity({ githubUsername: 'octocat', json: true, openBrowser: false }),
    ).rejects.toMatchObject({ code: 'GITHUB_TOKEN_REQUEST_FAILED' });

    installFetchQueue([
      jsonResponse(200, {
        device_code: 'device_2',
        user_code: 'ABCD-EFGH',
        verification_uri: 'https://github.com/login/device',
        verification_uri_complete: 'https://github.com/login/device?user_code=ABCD-EFGH',
        expires_in: 900,
        interval: 0,
      }),
      jsonResponse(200, {
        access_token: 'token_ok',
        token_type: 'bearer',
        scope: 'read:user',
      }),
      new Error('user endpoint offline'),
    ]);
    await expect(
      linkGithubIdentity({ githubUsername: 'octocat', json: true, openBrowser: false }),
    ).rejects.toMatchObject({ code: 'GITHUB_USER_REQUEST_FAILED' });
  });

  it('shows empty binding when none exists', async () => {
    if (!(await homeOverrideWorks())) return;

    const shown = await showGithubIdentity();
    expect(shown.status).toBe('ok');
    expect(shown.identity_did).toBeNull();
    expect(shown.github_binding).toBeNull();
  });
});
