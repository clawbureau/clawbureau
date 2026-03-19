import { mkdir, readFile, writeFile, chmod, stat } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { homedir } from 'node:os';
import { spawn } from 'node:child_process';
import { setTimeout as sleep } from 'node:timers/promises';
import crypto from 'node:crypto';
import { hashJsonB64u } from '@clawbureau/clawsig-sdk';
import { loadIdentity, identityToAgentDid } from './identity.js';

const CLAWSIG_DIR = '.clawsig';
const GITHUB_BINDING_FILENAME = 'github-binding.json';
const GITHUB_DEVICE_CODE_URL = 'https://github.com/login/device/code';
const GITHUB_ACCESS_TOKEN_URL = 'https://github.com/login/oauth/access_token';
const GITHUB_USER_URL = 'https://api.github.com/user';

const ENV_GITHUB_CLIENT_ID = 'CLAWSIG_GITHUB_OAUTH_CLIENT_ID';
const ENV_GITHUB_BINDING_LEDGER_URL = 'CLAWSIG_GITHUB_BINDING_LEDGER_URL';
const ENV_GITHUB_BINDING_LEDGER_TOKEN = 'CLAWSIG_GITHUB_BINDING_LEDGER_TOKEN';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface GithubDidBindingAttestationPayload {
  attestation_version: '1';
  attestation_type: 'github_did_binding';
  attestation_id: string;
  github_username: string;
  github_user_id: number;
  did: string;
  statement: string;
  issued_at: string;
}

export interface GithubDidBindingAttestationEnvelope {
  envelope_version: '1';
  envelope_type: 'github_did_binding';
  payload: GithubDidBindingAttestationPayload;
  payload_hash_b64u: string;
  hash_algorithm: 'SHA-256';
  signature_b64u: string;
  algorithm: 'Ed25519';
  signer_did: string;
  issued_at: string;
}

export interface GithubBindingStore {
  schema_version: '1';
  github: {
    username: string;
    user_id: number;
    profile_url: string;
    linked_dids: string[];
  };
  attestations: GithubDidBindingAttestationEnvelope[];
  updated_at: string;
}

export interface LinkGithubOptions {
  githubUsername: string;
  projectDir?: string;
  json?: boolean;
  openBrowser?: boolean;
}

export interface LinkGithubResult {
  status: 'ok';
  github_username: string;
  github_user_id: number;
  did: string;
  binding_path: string;
  linked_dids: string[];
  attestation: GithubDidBindingAttestationEnvelope;
  published: boolean;
  ledger_url?: string;
  publish_error?: { code: string; message: string };
}

export interface ShowGithubIdentityResult {
  status: 'ok';
  identity_did: string | null;
  github_binding: {
    github_username: string;
    github_user_id: number;
    profile_url: string;
    linked_dids: string[];
    attestations_count: number;
    binding_path: string;
    updated_at: string;
  } | null;
}

interface JsonHttpRequest {
  url: string;
  init: RequestInit;
  networkErrorCode: string;
}

interface GithubDeviceCodeResponse {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete?: string;
  expires_in: number;
  interval?: number;
}

interface GithubTokenPollResponse {
  access_token?: string;
  token_type?: string;
  scope?: string;
  error?: string;
  error_description?: string;
}

interface GithubUserProfile {
  login: string;
  id: number;
  html_url?: string;
}

interface PublishGithubBindingResult {
  attempted: boolean;
  published: boolean;
  ledgerUrl?: string;
  error?: { code: string; message: string };
}

// ---------------------------------------------------------------------------
// Test seams
// ---------------------------------------------------------------------------

type FetchFn = typeof globalThis.fetch;
let _fetch: FetchFn = globalThis.fetch;

export function __setFetch(fn: FetchFn): () => void {
  const prev = _fetch;
  _fetch = fn;
  return () => {
    _fetch = prev;
  };
}

export type OpenUrlFn = (url: string) => Promise<boolean> | boolean;
let _openUrl: OpenUrlFn = defaultOpenUrl;

export function __setOpenUrl(fn: OpenUrlFn): () => void {
  const prev = _openUrl;
  _openUrl = fn;
  return () => {
    _openUrl = prev;
  };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function defaultGithubBindingPath(): string {
  return join(homedir(), CLAWSIG_DIR, GITHUB_BINDING_FILENAME);
}

export function isGithubBindingStore(value: unknown): value is GithubBindingStore {
  if (!isRecord(value)) return false;
  if (value['schema_version'] !== '1') return false;

  const github = value['github'];
  if (!isRecord(github)) return false;

  const username = github['username'];
  const userId = github['user_id'];
  const profileUrl = github['profile_url'];
  const linkedDids = github['linked_dids'];

  if (typeof username !== 'string' || username.length === 0) return false;
  if (typeof userId !== 'number' || !Number.isInteger(userId) || userId <= 0) return false;
  if (typeof profileUrl !== 'string' || profileUrl.length === 0) return false;
  if (!Array.isArray(linkedDids) || !linkedDids.every((d) => typeof d === 'string' && d.startsWith('did:'))) {
    return false;
  }

  const attestations = value['attestations'];
  if (!Array.isArray(attestations) || !attestations.every(isGithubDidBindingAttestationEnvelope)) {
    return false;
  }

  const updatedAt = value['updated_at'];
  if (typeof updatedAt !== 'string' || Number.isNaN(Date.parse(updatedAt))) return false;

  return true;
}

export async function showGithubIdentity(options: { projectDir?: string } = {}): Promise<ShowGithubIdentityResult> {
  const identity = await loadIdentity(options.projectDir);
  const bindingPath = defaultGithubBindingPath();
  const store = await loadGithubBindingStore(bindingPath);

  if (!store) {
    return {
      status: 'ok',
      identity_did: identity?.did ?? null,
      github_binding: null,
    };
  }

  return {
    status: 'ok',
    identity_did: identity?.did ?? null,
    github_binding: {
      github_username: store.github.username,
      github_user_id: store.github.user_id,
      profile_url: store.github.profile_url,
      linked_dids: [...store.github.linked_dids],
      attestations_count: store.attestations.length,
      binding_path: bindingPath,
      updated_at: store.updated_at,
    },
  };
}

export async function linkGithubIdentity(options: LinkGithubOptions): Promise<LinkGithubResult> {
  const expectedGithubUsername = normalizeGithubUsername(options.githubUsername);
  const jsonMode = !!options.json;
  const shouldOpenBrowser = options.openBrowser ?? true;

  const identity = await loadIdentity(options.projectDir);
  if (!identity) {
    throw new GithubBindingError(
      'IDENTITY_MISSING',
      'No persistent identity found. Run `clawsig init` first.',
    );
  }

  const githubClientId = process.env[ENV_GITHUB_CLIENT_ID]?.trim();
  if (!githubClientId) {
    throw new GithubBindingError(
      'GITHUB_CLIENT_ID_MISSING',
      `Missing ${ENV_GITHUB_CLIENT_ID}. Configure a GitHub OAuth App client ID for device flow.`,
    );
  }

  const deviceCode = await requestGithubDeviceCode(githubClientId);

  if (!jsonMode) {
    process.stdout.write('Authenticate GitHub account via device flow:\n');
    process.stdout.write(`  GitHub username (expected): ${expectedGithubUsername}\n`);
    process.stdout.write(`  Verification URL: ${deviceCode.verification_uri}\n`);
    process.stdout.write(`  User code: ${deviceCode.user_code}\n`);

    if (shouldOpenBrowser) {
      const openTarget = deviceCode.verification_uri_complete ?? deviceCode.verification_uri;
      const opened = await tryOpenUrl(openTarget);
      if (opened) {
        process.stdout.write('  Browser: opened automatically\n');
      } else {
        process.stdout.write('  Browser: could not open automatically (open URL manually)\n');
      }
    }

    process.stdout.write('\nWaiting for GitHub authorization...\n');
  }

  const accessToken = await pollGithubDeviceToken({
    clientId: githubClientId,
    deviceCode: deviceCode.device_code,
    expiresInSec: deviceCode.expires_in,
    intervalSec: deviceCode.interval ?? 5,
  });

  const githubUser = await fetchAuthenticatedGithubUser(accessToken);
  const authenticatedUsername = normalizeGithubUsername(githubUser.login);

  if (authenticatedUsername !== expectedGithubUsername) {
    throw new GithubBindingError(
      'USERNAME_MISMATCH',
      `Authenticated GitHub user '${githubUser.login}' does not match --github '${expectedGithubUsername}'.`,
    );
  }

  const nowIso = new Date().toISOString();
  const attestation = await createGithubDidBindingAttestation({
    did: identity.did,
    githubUsername: githubUser.login,
    githubUserId: githubUser.id,
    issuedAt: nowIso,
    identity,
  });

  const bindingPath = defaultGithubBindingPath();
  const existingStore = await loadGithubBindingStore(bindingPath);
  const updatedStore = mergeGithubBindingStore({
    existingStore,
    githubUsername: githubUser.login,
    githubUserId: githubUser.id,
    profileUrl: githubUser.html_url ?? `https://github.com/${githubUser.login}`,
    did: identity.did,
    attestation,
    updatedAt: nowIso,
  });

  await saveGithubBindingStore(bindingPath, updatedStore);

  const publishResult = await maybePublishGithubBinding(attestation);

  return {
    status: 'ok',
    github_username: githubUser.login,
    github_user_id: githubUser.id,
    did: identity.did,
    binding_path: bindingPath,
    linked_dids: [...updatedStore.github.linked_dids],
    attestation,
    published: publishResult.published,
    ...(publishResult.ledgerUrl ? { ledger_url: publishResult.ledgerUrl } : {}),
    ...(publishResult.error ? { publish_error: publishResult.error } : {}),
  };
}

// ---------------------------------------------------------------------------
// OAuth
// ---------------------------------------------------------------------------

async function requestGithubDeviceCode(clientId: string): Promise<GithubDeviceCodeResponse> {
  const body = new URLSearchParams({
    client_id: clientId,
    scope: 'read:user',
  });

  const response = await requestJsonWithNetworkMapping({
    url: GITHUB_DEVICE_CODE_URL,
    init: {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: body.toString(),
    },
    networkErrorCode: 'GITHUB_DEVICE_CODE_REQUEST_FAILED',
  });

  const data = await parseJsonResponse(response, 'GITHUB_DEVICE_CODE_REQUEST_FAILED');

  if (!isRecord(data)) {
    throw new GithubBindingError('GITHUB_DEVICE_CODE_INVALID_RESPONSE', 'Invalid GitHub device-code response.');
  }

  const deviceCode = data['device_code'];
  const userCode = data['user_code'];
  const verificationUri = data['verification_uri'];
  const verificationUriComplete = data['verification_uri_complete'];
  const expiresIn = data['expires_in'];
  const interval = data['interval'];

  if (
    typeof deviceCode !== 'string' ||
    typeof userCode !== 'string' ||
    typeof verificationUri !== 'string' ||
    typeof expiresIn !== 'number'
  ) {
    throw new GithubBindingError('GITHUB_DEVICE_CODE_INVALID_RESPONSE', 'Missing required fields in GitHub device-code response.');
  }

  return {
    device_code: deviceCode,
    user_code: userCode,
    verification_uri: verificationUri,
    verification_uri_complete: typeof verificationUriComplete === 'string' ? verificationUriComplete : undefined,
    expires_in: expiresIn,
    interval: typeof interval === 'number' ? interval : undefined,
  };
}

async function pollGithubDeviceToken(args: {
  clientId: string;
  deviceCode: string;
  expiresInSec: number;
  intervalSec: number;
}): Promise<string> {
  let pollIntervalMs = Math.max(0, Math.floor(args.intervalSec * 1000));
  const deadline = Date.now() + Math.max(1000, Math.floor(args.expiresInSec * 1000));
  let firstPoll = true;

  while (Date.now() < deadline) {
    if (firstPoll) {
      firstPoll = false;
      await sleep(pollIntervalMs);
    }

    const body = new URLSearchParams({
      client_id: args.clientId,
      device_code: args.deviceCode,
      grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
    });

    const response = await requestJsonWithNetworkMapping({
      url: GITHUB_ACCESS_TOKEN_URL,
      init: {
        method: 'POST',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: body.toString(),
      },
      networkErrorCode: 'GITHUB_TOKEN_REQUEST_FAILED',
    });

    const tokenResponse = await parseJsonResponse(response, 'GITHUB_TOKEN_REQUEST_FAILED');

    if (!isRecord(tokenResponse)) {
      throw new GithubBindingError('GITHUB_TOKEN_INVALID_RESPONSE', 'Invalid GitHub token response.');
    }

    const parsed: GithubTokenPollResponse = {
      access_token: typeof tokenResponse['access_token'] === 'string' ? tokenResponse['access_token'] : undefined,
      token_type: typeof tokenResponse['token_type'] === 'string' ? tokenResponse['token_type'] : undefined,
      scope: typeof tokenResponse['scope'] === 'string' ? tokenResponse['scope'] : undefined,
      error: typeof tokenResponse['error'] === 'string' ? tokenResponse['error'] : undefined,
      error_description: typeof tokenResponse['error_description'] === 'string' ? tokenResponse['error_description'] : undefined,
    };

    if (parsed.access_token && parsed.access_token.length > 0) {
      return parsed.access_token;
    }

    switch (parsed.error) {
      case 'authorization_pending':
        await sleep(pollIntervalMs);
        break;
      case 'slow_down':
        pollIntervalMs += 5000;
        await sleep(pollIntervalMs);
        break;
      case 'expired_token':
        throw new GithubBindingError(
          'GITHUB_DEVICE_CODE_EXPIRED',
          parsed.error_description ?? 'GitHub device code expired before authorization completed.',
        );
      case 'access_denied':
        throw new GithubBindingError(
          'GITHUB_ACCESS_DENIED',
          parsed.error_description ?? 'GitHub authorization was denied by user.',
        );
      default:
        throw new GithubBindingError(
          'GITHUB_TOKEN_REQUEST_FAILED',
          parsed.error_description ?? parsed.error ?? 'Failed to obtain GitHub OAuth token.',
        );
    }
  }

  throw new GithubBindingError(
    'GITHUB_DEVICE_CODE_TIMEOUT',
    'Timed out waiting for GitHub device authorization.',
  );
}

async function fetchAuthenticatedGithubUser(accessToken: string): Promise<GithubUserProfile> {
  const response = await requestJsonWithNetworkMapping({
    url: GITHUB_USER_URL,
    init: {
      method: 'GET',
      headers: {
        Accept: 'application/vnd.github+json',
        Authorization: `Bearer ${accessToken}`,
        'X-GitHub-Api-Version': '2022-11-28',
      },
    },
    networkErrorCode: 'GITHUB_USER_REQUEST_FAILED',
  });

  const data = await parseJsonResponse(response, 'GITHUB_USER_REQUEST_FAILED');
  if (!isRecord(data)) {
    throw new GithubBindingError('GITHUB_USER_INVALID_RESPONSE', 'Invalid GitHub user response.');
  }

  const login = data['login'];
  const id = data['id'];
  const htmlUrl = data['html_url'];

  if (typeof login !== 'string' || typeof id !== 'number' || !Number.isInteger(id)) {
    throw new GithubBindingError('GITHUB_USER_INVALID_RESPONSE', 'GitHub user response missing login/id fields.');
  }

  return {
    login,
    id,
    html_url: typeof htmlUrl === 'string' ? htmlUrl : undefined,
  };
}

// ---------------------------------------------------------------------------
// Attestation + storage
// ---------------------------------------------------------------------------

async function createGithubDidBindingAttestation(args: {
  did: string;
  githubUsername: string;
  githubUserId: number;
  issuedAt: string;
  identity: Awaited<ReturnType<typeof loadIdentity>>;
}): Promise<GithubDidBindingAttestationEnvelope> {
  if (!args.identity) {
    throw new GithubBindingError('IDENTITY_MISSING', 'Persistent identity is required for signing attestation.');
  }

  const attestationId = `ghbind_${crypto.randomUUID()}`;
  const statement = `GitHub user ${args.githubUsername} controls DID ${args.did}`;

  const payload: GithubDidBindingAttestationPayload = {
    attestation_version: '1',
    attestation_type: 'github_did_binding',
    attestation_id: attestationId,
    github_username: args.githubUsername,
    github_user_id: args.githubUserId,
    did: args.did,
    statement,
    issued_at: args.issuedAt,
  };

  const payloadHashB64u = await hashJsonB64u(payload);
  const signer = await identityToAgentDid(args.identity);
  const signature = await signer.sign(new TextEncoder().encode(payloadHashB64u));

  return {
    envelope_version: '1',
    envelope_type: 'github_did_binding',
    payload,
    payload_hash_b64u: payloadHashB64u,
    hash_algorithm: 'SHA-256',
    signature_b64u: signature,
    algorithm: 'Ed25519',
    signer_did: args.did,
    issued_at: args.issuedAt,
  };
}

function mergeGithubBindingStore(args: {
  existingStore: GithubBindingStore | null;
  githubUsername: string;
  githubUserId: number;
  profileUrl: string;
  did: string;
  attestation: GithubDidBindingAttestationEnvelope;
  updatedAt: string;
}): GithubBindingStore {
  const existing = args.existingStore;

  if (existing) {
    if (existing.github.user_id !== args.githubUserId) {
      throw new GithubBindingError(
        'GITHUB_BINDING_CONFLICT',
        `Existing binding user ID (${existing.github.user_id}) does not match authenticated GitHub user ID (${args.githubUserId}).`,
      );
    }

    const linkedDidSet = new Set(existing.github.linked_dids);
    const hasDid = linkedDidSet.has(args.did);
    linkedDidSet.add(args.did);

    return {
      schema_version: '1',
      github: {
        username: args.githubUsername,
        user_id: existing.github.user_id,
        profile_url: args.profileUrl,
        linked_dids: Array.from(linkedDidSet).sort(),
      },
      attestations: hasDid ? [...existing.attestations] : [...existing.attestations, args.attestation],
      updated_at: args.updatedAt,
    };
  }

  return {
    schema_version: '1',
    github: {
      username: args.githubUsername,
      user_id: args.githubUserId,
      profile_url: args.profileUrl,
      linked_dids: [args.did],
    },
    attestations: [args.attestation],
    updated_at: args.updatedAt,
  };
}

async function loadGithubBindingStore(path: string): Promise<GithubBindingStore | null> {
  try {
    const raw = await readFile(path, 'utf-8');
    const parsed: unknown = JSON.parse(raw);

    if (!isGithubBindingStore(parsed)) {
      throw new GithubBindingError(
        'GITHUB_BINDING_INVALID',
        `GitHub binding file is malformed: ${path}`,
      );
    }

    validateStoreConsistency(parsed, path);
    return parsed;
  } catch (err) {
    if (isErrnoException(err) && err.code === 'ENOENT') {
      return null;
    }
    throw err;
  }
}

async function saveGithubBindingStore(path: string, store: GithubBindingStore): Promise<void> {
  const parentDir = dirname(path);
  await mkdir(parentDir, { recursive: true });
  await enforceDirectoryPermissions(parentDir);
  await writeFile(path, JSON.stringify(store, null, 2) + '\n', {
    encoding: 'utf-8',
    mode: 0o600,
  });

  try {
    const fileStat = await stat(path);
    const mode = fileStat.mode & 0o777;
    if (mode !== 0o600) {
      await chmod(path, 0o600);
    }
  } catch {
    // Best-effort for platforms where permissions may not map 1:1.
  }
}

async function maybePublishGithubBinding(
  envelope: GithubDidBindingAttestationEnvelope,
): Promise<PublishGithubBindingResult> {
  const publishUrl = process.env[ENV_GITHUB_BINDING_LEDGER_URL]?.trim();
  if (!publishUrl) {
    return { attempted: false, published: false };
  }

  const token = process.env[ENV_GITHUB_BINDING_LEDGER_TOKEN]?.trim();

  try {
    const response = await _fetch(publishUrl, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify({ github_binding_envelope: envelope }),
    });

    if (!response.ok) {
      const body = await response.text().catch(() => '');
      return {
        attempted: true,
        published: false,
        error: {
          code: 'GITHUB_BINDING_PUBLISH_FAILED',
          message: `Ledger publish failed (HTTP ${response.status})${body ? `: ${body.slice(0, 200)}` : ''}`,
        },
      };
    }

    let ledgerUrl: string | undefined;
    try {
      const parsed = await response.json() as unknown;
      if (isRecord(parsed)) {
        if (typeof parsed['ledger_url'] === 'string') {
          ledgerUrl = parsed['ledger_url'];
        }

        const urls = parsed['urls'];
        if (!ledgerUrl && isRecord(urls) && typeof urls['ledger'] === 'string') {
          ledgerUrl = urls['ledger'];
        }
      }
    } catch {
      // Ignore JSON parse errors on publish success.
    }

    return {
      attempted: true,
      published: true,
      ...(ledgerUrl ? { ledgerUrl } : {}),
    };
  } catch (err) {
    return {
      attempted: true,
      published: false,
      error: {
        code: 'GITHUB_BINDING_PUBLISH_FAILED',
        message: err instanceof Error ? err.message : 'Ledger publish request failed.',
      },
    };
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function normalizeGithubUsername(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length === 0) {
    throw new GithubBindingError('INVALID_GITHUB_USERNAME', 'GitHub username cannot be empty.');
  }

  const withoutAt = trimmed.startsWith('@') ? trimmed.slice(1) : trimmed;
  if (withoutAt.length === 0) {
    throw new GithubBindingError('INVALID_GITHUB_USERNAME', 'GitHub username cannot be empty.');
  }

  return withoutAt.toLowerCase();
}

async function tryOpenUrl(url: string): Promise<boolean> {
  try {
    return await Promise.resolve(_openUrl(url));
  } catch {
    return false;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isErrnoException(err: unknown): err is NodeJS.ErrnoException {
  return isRecord(err) && typeof err['code'] === 'string';
}

function isGithubDidBindingAttestationEnvelope(value: unknown): value is GithubDidBindingAttestationEnvelope {
  if (!isRecord(value)) return false;
  if (value['envelope_version'] !== '1') return false;
  if (value['envelope_type'] !== 'github_did_binding') return false;
  if (value['hash_algorithm'] !== 'SHA-256') return false;
  if (value['algorithm'] !== 'Ed25519') return false;
  if (typeof value['payload_hash_b64u'] !== 'string' || value['payload_hash_b64u'].length < 8) return false;
  if (typeof value['signature_b64u'] !== 'string' || value['signature_b64u'].length < 8) return false;
  if (typeof value['signer_did'] !== 'string' || !value['signer_did'].startsWith('did:')) return false;
  if (typeof value['issued_at'] !== 'string' || Number.isNaN(Date.parse(value['issued_at']))) return false;

  const payload = value['payload'];
  if (!isRecord(payload)) return false;

  return (
    payload['attestation_version'] === '1' &&
    payload['attestation_type'] === 'github_did_binding' &&
    typeof payload['attestation_id'] === 'string' &&
    payload['attestation_id'].length > 0 &&
    typeof payload['github_username'] === 'string' &&
    payload['github_username'].length > 0 &&
    typeof payload['github_user_id'] === 'number' &&
    Number.isInteger(payload['github_user_id']) &&
    (payload['github_user_id'] as number) > 0 &&
    typeof payload['did'] === 'string' &&
    payload['did'].startsWith('did:') &&
    typeof payload['statement'] === 'string' &&
    payload['statement'].length > 0 &&
    typeof payload['issued_at'] === 'string' &&
    !Number.isNaN(Date.parse(payload['issued_at']))
  );
}

async function parseJsonResponse(response: Response, errorCode: string): Promise<unknown> {
  let text = '';
  try {
    text = await response.text();
  } catch (err) {
    throw new GithubBindingError(
      errorCode,
      err instanceof Error ? err.message : 'Failed to read GitHub response body.',
    );
  }

  let data: unknown = null;

  if (text.length > 0) {
    try {
      data = JSON.parse(text);
    } catch {
      throw new GithubBindingError(errorCode, `Expected JSON response (HTTP ${response.status}).`);
    }
  }

  if (!response.ok) {
    let message = `GitHub request failed with HTTP ${response.status}.`;

    if (isRecord(data) && typeof data['error_description'] === 'string' && data['error_description'].length > 0) {
      message = data['error_description'];
    } else if (isRecord(data) && typeof data['message'] === 'string' && data['message'].length > 0) {
      message = data['message'];
    } else if (typeof text === 'string' && text.length > 0) {
      message = `${message} ${text.slice(0, 200)}`;
    }

    throw new GithubBindingError(errorCode, message);
  }

  return data;
}

async function requestJsonWithNetworkMapping(args: JsonHttpRequest): Promise<Response> {
  try {
    return await _fetch(args.url, args.init);
  } catch (err) {
    throw new GithubBindingError(
      args.networkErrorCode,
      err instanceof Error ? err.message : 'GitHub request failed.',
    );
  }
}

function validateStoreConsistency(store: GithubBindingStore, path: string): void {
  const linkedDidSet = new Set(store.github.linked_dids);
  const seenDidAttestations = new Set<string>();

  for (const envelope of store.attestations) {
    const did = envelope.payload.did;
    if (envelope.signer_did !== did) {
      throw new GithubBindingError(
        'GITHUB_BINDING_INVALID',
        `GitHub binding file has signer DID mismatch: ${path}`,
      );
    }
    if (!linkedDidSet.has(did)) {
      throw new GithubBindingError(
        'GITHUB_BINDING_INVALID',
        `GitHub binding file has attestation DID not present in linked_dids: ${path}`,
      );
    }
    if (envelope.payload.github_user_id !== store.github.user_id) {
      throw new GithubBindingError(
        'GITHUB_BINDING_INVALID',
        `GitHub binding file has mixed github_user_id values: ${path}`,
      );
    }
    seenDidAttestations.add(did);
  }

  for (const did of linkedDidSet) {
    if (!seenDidAttestations.has(did)) {
      throw new GithubBindingError(
        'GITHUB_BINDING_INVALID',
        `GitHub binding file has linked_did without attestation: ${path}`,
      );
    }
  }
}

async function enforceDirectoryPermissions(path: string): Promise<void> {
  try {
    const directoryStat = await stat(path);
    const mode = directoryStat.mode & 0o777;
    if (mode !== 0o700) {
      await chmod(path, 0o700);
    }
  } catch {
    // Best-effort for platforms where permissions may not map 1:1.
  }
}

function defaultOpenUrl(url: string): Promise<boolean> {
  if (process.platform === 'darwin') {
    return spawnDetached('open', [url]);
  }

  if (process.platform === 'win32') {
    return spawnDetached('cmd', ['/c', 'start', '', url]);
  }

  return spawnDetached('xdg-open', [url]);
}

function spawnDetached(command: string, args: string[]): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    let settled = false;
    const finalize = (value: boolean) => {
      if (settled) return;
      settled = true;
      resolve(value);
    };

    try {
      const child = spawn(command, args, {
        detached: true,
        stdio: 'ignore',
      });
      child.once('error', () => finalize(false));
      child.once('spawn', () => {
        child.unref();
        finalize(true);
      });
    } catch {
      finalize(false);
    }
  });
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

export class GithubBindingError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}
