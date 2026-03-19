const SESSION_COOKIE = 'clawsig_explorer_session';
const OAUTH_STATE_COOKIE = 'clawsig_explorer_oauth_state';
const SESSION_TTL_SECONDS = 7 * 24 * 60 * 60;
const OAUTH_STATE_TTL_SECONDS = 10 * 60;

export interface AuthEnv {
  GITHUB_OAUTH_CLIENT_ID?: string;
  GITHUB_OAUTH_CLIENT_SECRET?: string;
  GITHUB_OAUTH_REDIRECT_URI?: string;
  EXPLORER_SESSION_SECRET?: string;
}

interface SessionClaims {
  sub: string;
  login: string;
  github_id: number;
  name?: string;
  avatar_url?: string;
  iat: number;
  exp: number;
}

interface GithubUser {
  id: number;
  login: string;
  name?: string | null;
  avatar_url?: string | null;
}

export interface ExplorerSession {
  login: string;
  githubId: number;
  name: string | null;
  avatarUrl: string | null;
  logoutCsrfToken: string;
}

interface ValidatedSession {
  secret: string;
  token: string;
  claims: SessionClaims;
}

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  const base64 = btoa(binary);
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64UrlDecode(input: string): Uint8Array {
  const base64 = input.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

function utf8Encode(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function utf8Decode(value: Uint8Array): string {
  return new TextDecoder().decode(value);
}

function parseCookieHeader(header: string | null): Map<string, string> {
  const out = new Map<string, string>();
  if (!header) return out;

  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx <= 0) continue;
    const key = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (!key) continue;
    out.set(key, value);
  }

  return out;
}

function serializeCookie(params: {
  name: string;
  value: string;
  maxAgeSeconds?: number;
  path?: string;
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: 'Lax' | 'Strict' | 'None';
}): string {
  const parts = [`${params.name}=${params.value}`];

  parts.push(`Path=${params.path ?? '/'}`);
  parts.push(`SameSite=${params.sameSite ?? 'Lax'}`);

  if (typeof params.maxAgeSeconds === 'number') {
    parts.push(`Max-Age=${Math.max(0, Math.floor(params.maxAgeSeconds))}`);
  }
  if (params.httpOnly !== false) {
    parts.push('HttpOnly');
  }
  if (params.secure !== false) {
    parts.push('Secure');
  }

  return parts.join('; ');
}

function randomBase64Url(size = 16): string {
  const bytes = new Uint8Array(size);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

function normalizeReturnPath(raw: string | null): string {
  if (!raw) return '/inspect';

  const trimmed = raw.trim();
  if (!trimmed.startsWith('/')) {
    return '/inspect';
  }

  if (trimmed.startsWith('//')) {
    return '/inspect';
  }

  try {
    const parsed = new URL(trimmed, 'https://explorer.clawsig.local');
    return `${parsed.pathname}${parsed.search}`;
  } catch {
    return '/inspect';
  }
}

function addQueryParam(pathAndQuery: string, key: string, value: string): string {
  const parsed = new URL(pathAndQuery, 'https://explorer.clawsig.local');
  parsed.searchParams.set(key, value);
  return `${parsed.pathname}${parsed.search}`;
}

function buildInspectAuthRedirect(request: Request, code: string): string {
  const url = new URL(request.url);
  const path = addQueryParam('/inspect', 'auth', code);
  return `${url.origin}${path}`;
}

function buildGithubRedirectUri(request: Request, env: AuthEnv): string {
  if (env.GITHUB_OAUTH_REDIRECT_URI && env.GITHUB_OAUTH_REDIRECT_URI.trim().length > 0) {
    return env.GITHUB_OAUTH_REDIRECT_URI.trim();
  }

  const url = new URL(request.url);
  return `${url.origin}/auth/github/callback`;
}

async function signHs256(input: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    utf8Encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );

  const signature = await crypto.subtle.sign('HMAC', key, utf8Encode(input));
  return base64UrlEncode(new Uint8Array(signature));
}

async function verifyHs256(input: string, signatureB64u: string, secret: string): Promise<boolean> {
  const key = await crypto.subtle.importKey(
    'raw',
    utf8Encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify'],
  );

  return crypto.subtle.verify('HMAC', key, base64UrlDecode(signatureB64u), utf8Encode(input));
}

async function encodeSessionToken(claims: SessionClaims, secret: string): Promise<string> {
  const headerB64u = base64UrlEncode(utf8Encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
  const payloadB64u = base64UrlEncode(utf8Encode(JSON.stringify(claims)));
  const signingInput = `${headerB64u}.${payloadB64u}`;
  const signature = await signHs256(signingInput, secret);
  return `${signingInput}.${signature}`;
}

async function decodeSessionToken(token: string, secret: string): Promise<SessionClaims | null> {
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  const [headerB64u, payloadB64u, signatureB64u] = parts;
  if (!headerB64u || !payloadB64u || !signatureB64u) return null;

  let header: { alg?: string };
  let payload: SessionClaims;

  try {
    header = JSON.parse(utf8Decode(base64UrlDecode(headerB64u))) as { alg?: string };
    payload = JSON.parse(utf8Decode(base64UrlDecode(payloadB64u))) as SessionClaims;
  } catch {
    return null;
  }

  if (header.alg !== 'HS256') return null;

  const validSig = await verifyHs256(`${headerB64u}.${payloadB64u}`, signatureB64u, secret);
  if (!validSig) return null;

  const now = Math.floor(Date.now() / 1000);
  if (!Number.isFinite(payload.exp) || payload.exp < now) return null;
  if (!Number.isFinite(payload.iat) || payload.iat > now + 60) return null;
  if (typeof payload.login !== 'string' || payload.login.trim().length === 0) return null;
  if (!Number.isFinite(payload.github_id)) return null;

  return payload;
}

function appendSetCookie(headers: Headers, cookie: string): void {
  headers.append('Set-Cookie', cookie);
}

function redirectWithCookies(location: string, cookies: string[]): Response {
  const headers = new Headers({ Location: location });
  for (const cookie of cookies) {
    appendSetCookie(headers, cookie);
  }
  return new Response(null, { status: 302, headers });
}

function clearCookie(name: string, secure: boolean): string {
  return serializeCookie({
    name,
    value: '',
    maxAgeSeconds: 0,
    secure,
  });
}

function getOAuthStateCookieValue(state: string, returnToPath: string): string {
  const payload = `${state}|${base64UrlEncode(utf8Encode(returnToPath))}`;
  return payload;
}

function parseOAuthStateCookieValue(cookieValue: string): { state: string; returnTo: string } | null {
  const sep = cookieValue.indexOf('|');
  if (sep <= 0) return null;
  const state = cookieValue.slice(0, sep);
  const encodedReturnTo = cookieValue.slice(sep + 1);
  if (!state || !encodedReturnTo) return null;

  try {
    const returnTo = utf8Decode(base64UrlDecode(encodedReturnTo));
    return { state, returnTo: normalizeReturnPath(returnTo) };
  } catch {
    return null;
  }
}

async function exchangeGithubCodeForToken(
  request: Request,
  env: AuthEnv,
  code: string,
): Promise<string> {
  const clientId = env.GITHUB_OAUTH_CLIENT_ID?.trim();
  const clientSecret = env.GITHUB_OAUTH_CLIENT_SECRET?.trim();

  if (!clientId || !clientSecret) {
    throw new Error('OAUTH_NOT_CONFIGURED');
  }

  const tokenResp = await fetch('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      'User-Agent': 'clawsig-explorer',
    },
    body: JSON.stringify({
      client_id: clientId,
      client_secret: clientSecret,
      code,
      redirect_uri: buildGithubRedirectUri(request, env),
    }),
  });

  const tokenJson = (await tokenResp.json().catch(() => null)) as {
    access_token?: string;
    token_type?: string;
    error?: string;
  } | null;

  if (!tokenResp.ok || !tokenJson || typeof tokenJson.access_token !== 'string') {
    const code = tokenJson?.error && tokenJson.error.trim().length > 0
      ? tokenJson.error
      : 'token_exchange_failed';
    throw new Error(`TOKEN_EXCHANGE:${code}`);
  }

  return tokenJson.access_token;
}

async function fetchGithubUser(accessToken: string): Promise<GithubUser> {
  const resp = await fetch('https://api.github.com/user', {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/vnd.github+json',
      'User-Agent': 'clawsig-explorer',
      'X-GitHub-Api-Version': '2022-11-28',
    },
  });

  if (!resp.ok) {
    throw new Error(`GITHUB_USER_FETCH:${resp.status}`);
  }

  const json = (await resp.json()) as {
    id?: number;
    login?: string;
    name?: string | null;
    avatar_url?: string | null;
  };

  if (!Number.isFinite(json.id) || typeof json.login !== 'string' || json.login.trim().length === 0) {
    throw new Error('GITHUB_USER_INVALID');
  }

  return {
    id: Number(json.id),
    login: json.login.trim(),
    name: typeof json.name === 'string' ? json.name : null,
    avatar_url: typeof json.avatar_url === 'string' ? json.avatar_url : null,
  };
}

function makeSessionCookie(token: string, secure: boolean): string {
  return serializeCookie({
    name: SESSION_COOKIE,
    value: token,
    maxAgeSeconds: SESSION_TTL_SECONDS,
    secure,
    httpOnly: true,
    sameSite: 'Lax',
    path: '/',
  });
}

function makeOAuthStateCookie(value: string, secure: boolean): string {
  return serializeCookie({
    name: OAUTH_STATE_COOKIE,
    value,
    maxAgeSeconds: OAUTH_STATE_TTL_SECONDS,
    secure,
    httpOnly: true,
    sameSite: 'Lax',
    path: '/',
  });
}

function isSecureRequest(request: Request): boolean {
  return new URL(request.url).protocol === 'https:';
}

async function readValidatedSession(request: Request, env: AuthEnv): Promise<ValidatedSession | null> {
  const secret = env.EXPLORER_SESSION_SECRET?.trim();
  if (!secret) return null;

  const cookies = parseCookieHeader(request.headers.get('cookie'));
  const token = cookies.get(SESSION_COOKIE);
  if (!token) return null;

  const claims = await decodeSessionToken(token, secret);
  if (!claims) return null;

  return { secret, token, claims };
}

async function buildLogoutCsrfToken(sessionToken: string, secret: string): Promise<string> {
  return signHs256(`logout:${sessionToken}`, secret);
}

function readFormString(formData: FormData | null, key: string): string | null {
  if (!formData) return null;
  const value = formData.get(key);
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

export async function readExplorerSession(request: Request, env: AuthEnv): Promise<ExplorerSession | null> {
  const session = await readValidatedSession(request, env);
  if (!session) return null;
  const logoutCsrfToken = await buildLogoutCsrfToken(session.token, session.secret);

  return {
    login: session.claims.login,
    githubId: session.claims.github_id,
    name: session.claims.name ?? null,
    avatarUrl: session.claims.avatar_url ?? null,
    logoutCsrfToken,
  };
}

export function beginGithubOauth(request: Request, env: AuthEnv): Response {
  const clientId = env.GITHUB_OAUTH_CLIENT_ID?.trim();
  const clientSecret = env.GITHUB_OAUTH_CLIENT_SECRET?.trim();

  if (!clientId || !clientSecret) {
    return Response.redirect(buildInspectAuthRedirect(request, 'oauth_not_configured'), 302);
  }

  const requestUrl = new URL(request.url);
  const returnTo = normalizeReturnPath(requestUrl.searchParams.get('return_to'));

  const state = randomBase64Url(20);
  const secure = isSecureRequest(request);
  const oauthStateCookie = makeOAuthStateCookie(getOAuthStateCookieValue(state, returnTo), secure);

  const authorizeUrl = new URL('https://github.com/login/oauth/authorize');
  authorizeUrl.searchParams.set('client_id', clientId);
  authorizeUrl.searchParams.set('redirect_uri', buildGithubRedirectUri(request, env));
  authorizeUrl.searchParams.set('scope', 'read:user');
  authorizeUrl.searchParams.set('state', state);
  authorizeUrl.searchParams.set('allow_signup', 'true');

  return redirectWithCookies(authorizeUrl.toString(), [oauthStateCookie]);
}

export async function completeGithubOauth(request: Request, env: AuthEnv): Promise<Response> {
  const url = new URL(request.url);
  const secure = isSecureRequest(request);
  const clearStateCookie = clearCookie(OAUTH_STATE_COOKIE, secure);

  const oauthError = url.searchParams.get('error');
  if (oauthError) {
    return redirectWithCookies(buildInspectAuthRedirect(request, oauthError), [clearStateCookie]);
  }

  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  if (!code || !state) {
    return redirectWithCookies(buildInspectAuthRedirect(request, 'oauth_missing_code'), [clearStateCookie]);
  }

  const cookies = parseCookieHeader(request.headers.get('cookie'));
  const stateCookie = cookies.get(OAUTH_STATE_COOKIE);
  const parsedStateCookie = stateCookie ? parseOAuthStateCookieValue(stateCookie) : null;

  if (!parsedStateCookie || parsedStateCookie.state !== state) {
    return redirectWithCookies(buildInspectAuthRedirect(request, 'oauth_state_mismatch'), [clearStateCookie]);
  }

  const sessionSecret = env.EXPLORER_SESSION_SECRET?.trim();
  if (!sessionSecret) {
    return redirectWithCookies(buildInspectAuthRedirect(request, 'session_not_configured'), [clearStateCookie]);
  }

  let user: GithubUser;
  try {
    const token = await exchangeGithubCodeForToken(request, env, code);
    user = await fetchGithubUser(token);
  } catch (error) {
    const msg = error instanceof Error ? error.message : 'oauth_unknown';
    const code = msg.startsWith('TOKEN_EXCHANGE:')
      ? msg.replace('TOKEN_EXCHANGE:', '')
      : msg.startsWith('GITHUB_USER_')
        ? 'github_user_fetch_failed'
        : msg === 'OAUTH_NOT_CONFIGURED'
          ? 'oauth_not_configured'
          : 'oauth_network_error';

    const location = buildInspectAuthRedirect(request, code);
    return redirectWithCookies(location, [clearStateCookie]);
  }

  const now = Math.floor(Date.now() / 1000);
  const claims: SessionClaims = {
    sub: `github:${user.id}`,
    login: user.login,
    github_id: user.id,
    name: user.name ?? undefined,
    avatar_url: user.avatar_url ?? undefined,
    iat: now,
    exp: now + SESSION_TTL_SECONDS,
  };

  const token = await encodeSessionToken(claims, sessionSecret);
  const sessionCookie = makeSessionCookie(token, secure);

  const returnToWithAuth = addQueryParam(parsedStateCookie.returnTo, 'auth', 'ok');
  const requestOrigin = new URL(request.url).origin;
  return redirectWithCookies(`${requestOrigin}${returnToWithAuth}`, [clearStateCookie, sessionCookie]);
}

export async function logoutGithubSession(request: Request, env: AuthEnv): Promise<Response> {
  const formData = await request.formData().catch(() => null);
  const activeSession = await readValidatedSession(request, env);
  if (activeSession) {
    const submittedCsrfToken = readFormString(formData, 'csrf_token');
    const expectedCsrfToken = await buildLogoutCsrfToken(activeSession.token, activeSession.secret);
    if (!submittedCsrfToken || submittedCsrfToken !== expectedCsrfToken) {
      return new Response('Forbidden', {
        status: 403,
        headers: {
          'Cache-Control': 'private, no-store, no-cache, must-revalidate',
        },
      });
    }
  }

  const secure = isSecureRequest(request);
  const clearSession = clearCookie(SESSION_COOKIE, secure);
  const clearState = clearCookie(OAUTH_STATE_COOKIE, secure);
  const requestUrl = new URL(request.url);

  const returnTo = normalizeReturnPath(readFormString(formData, 'return_to') ?? requestUrl.searchParams.get('return_to'));
  const location = `${requestUrl.origin}${addQueryParam(returnTo, 'auth', 'logged_out')}`;
  return redirectWithCookies(location, [clearSession, clearState]);
}
