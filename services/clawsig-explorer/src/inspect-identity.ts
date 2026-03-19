const DEFAULT_CLAWCLAIM_BASE_URL = 'https://clawclaim.com';
const CLAIM_LOOKUP_TIMEOUT_MS = 7000;

export interface IdentityEnv {
  CLAWCLAIM_BASE_URL?: string;
  GITHUB_DID_KEYRING_JSON?: string;
}

export interface ViewerIdentity {
  did: string;
  publicKeyJwk: JsonWebKey;
  privateKeyJwk: JsonWebKey;
}

interface OwnerAttestationLookupResponse {
  attestations?: Array<Record<string, unknown>>;
}

interface KeyringEntry {
  did: string;
  githubLogin?: string;
  providerRef?: string;
  publicKeyJwk: JsonWebKey;
  privateKeyJwk: JsonWebKey;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function normalizeDid(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!trimmed.startsWith('did:')) return null;
  return trimmed;
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

function looksLikeEd25519PrivateJwk(value: unknown): value is JsonWebKey {
  if (!isObject(value)) return false;
  return value.kty === 'OKP' && value.crv === 'Ed25519' && typeof value.d === 'string' && typeof value.x === 'string';
}

function looksLikeEd25519PublicJwk(value: unknown): value is JsonWebKey {
  if (!isObject(value)) return false;
  return value.kty === 'OKP' && value.crv === 'Ed25519' && typeof value.x === 'string';
}

function normalizeGithubLogin(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  if (trimmed.length === 0) return undefined;
  return trimmed.toLowerCase();
}

function normalizeProviderRef(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  if (trimmed.length === 0) return undefined;
  return trimmed;
}

function normalizeKeyringEntry(raw: Record<string, unknown>): KeyringEntry | null {
  const did = normalizeDid(raw.did ?? raw.viewer_did ?? raw.subject_did ?? raw.owner_did);
  if (!did) return null;

  const publicKey = (raw.publicKeyJwk ?? raw.public_key_jwk ?? raw.public_key ?? raw.publicKey) as unknown;
  const privateKey = (raw.privateKeyJwk ?? raw.private_key_jwk ?? raw.private_key ?? raw.privateKey) as unknown;

  if (!looksLikeEd25519PublicJwk(publicKey) || !looksLikeEd25519PrivateJwk(privateKey)) {
    return null;
  }

  const githubLogin = normalizeGithubLogin(raw.githubLogin ?? raw.github_login ?? raw.login ?? raw.github_handle);
  const providerRef = normalizeProviderRef(raw.providerRef ?? raw.provider_ref);

  return {
    did,
    githubLogin,
    providerRef,
    publicKeyJwk: publicKey,
    privateKeyJwk: privateKey,
  };
}

function parseKeyringEntries(rawJson: string | undefined): KeyringEntry[] {
  if (!rawJson || rawJson.trim().length === 0) return [];

  let parsed: unknown;
  try {
    parsed = JSON.parse(rawJson);
  } catch {
    return [];
  }

  const out: KeyringEntry[] = [];

  if (Array.isArray(parsed)) {
    for (const item of parsed) {
      if (!isObject(item)) continue;
      const normalized = normalizeKeyringEntry(item);
      if (normalized) out.push(normalized);
    }
    return out;
  }

  if (!isObject(parsed)) {
    return [];
  }

  if (Array.isArray(parsed.bindings)) {
    for (const item of parsed.bindings) {
      if (!isObject(item)) continue;
      const normalized = normalizeKeyringEntry(item);
      if (normalized) out.push(normalized);
    }
  }

  if (isObject(parsed.identities)) {
    for (const [did, value] of Object.entries(parsed.identities)) {
      if (!isObject(value)) continue;
      const normalized = normalizeKeyringEntry({ did, ...value });
      if (normalized) out.push(normalized);
    }
  }

  for (const [did, value] of Object.entries(parsed)) {
    if (!did.startsWith('did:') || !isObject(value)) continue;
    const normalized = normalizeKeyringEntry({ did, ...value });
    if (normalized) out.push(normalized);
  }

  return out;
}

function dedupeDids(input: Iterable<string>): string[] {
  const seen = new Set<string>();
  for (const did of input) {
    seen.add(did);
  }
  return [...seen];
}

function isExpired(expiresAt: unknown): boolean {
  if (typeof expiresAt !== 'string' || expiresAt.trim().length === 0) return false;
  const ts = Date.parse(expiresAt);
  if (!Number.isFinite(ts)) return false;
  return ts <= Date.now();
}

async function fetchWithTimeout(url: string, timeoutMs: number): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await fetch(url, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        'User-Agent': 'clawsig-explorer',
      },
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }
}

async function lookupDidsFromOwnerAttestations(githubLogin: string, baseUrl: string): Promise<string[]> {
  const dids: string[] = [];
  const providerRefs = [
    `github.com/${githubLogin}`,
    `github:${githubLogin}`,
    githubLogin,
  ];
  const providers = ['oauth', 'github'];

  for (const ownerProvider of providers) {
    for (const providerRef of providerRefs) {
      const lookup = new URL('/v1/owner-attestations/lookup', baseUrl);
      lookup.searchParams.set('owner_provider', ownerProvider);
      lookup.searchParams.set('provider_ref', providerRef);

      let response: Response;
      try {
        response = await fetchWithTimeout(lookup.toString(), CLAIM_LOOKUP_TIMEOUT_MS);
      } catch {
        continue;
      }

      if (!response.ok) {
        continue;
      }

      const json = (await response.json().catch(() => null)) as OwnerAttestationLookupResponse | null;
      if (!json || !Array.isArray(json.attestations)) {
        continue;
      }

      for (const attestation of json.attestations) {
        if (!isObject(attestation)) continue;
        if (isExpired(attestation.expires_at)) continue;
        const did = normalizeDid(attestation.owner_did ?? attestation.subject_did);
        if (did) {
          dids.push(did);
        }
      }
    }
  }

  return dedupeDids(dids);
}

export async function resolveGithubViewerIdentities(
  githubLogin: string,
  env: IdentityEnv,
): Promise<ViewerIdentity[]> {
  const login = githubLogin.trim().toLowerCase();
  if (!login) return [];

  const clawclaimBase = (env.CLAWCLAIM_BASE_URL?.trim() || DEFAULT_CLAWCLAIM_BASE_URL).replace(/\/$/, '');

  let didsFromAttestation: string[] = [];
  try {
    didsFromAttestation = await lookupDidsFromOwnerAttestations(login, clawclaimBase);
  } catch {
    didsFromAttestation = [];
  }

  const keyring = parseKeyringEntries(env.GITHUB_DID_KEYRING_JSON);
  if (keyring.length === 0) return [];

  const didAllowlist = new Set(didsFromAttestation);
  const targetProviderRef = `github.com/${login}`;

  const matched: KeyringEntry[] = [];

  for (const entry of keyring) {
    if (didAllowlist.size > 0) {
      if (didAllowlist.has(entry.did)) {
        matched.push(entry);
      }
      continue;
    }

    if (entry.githubLogin && entry.githubLogin === login) {
      matched.push(entry);
      continue;
    }

    if (entry.providerRef && entry.providerRef.toLowerCase() === targetProviderRef) {
      matched.push(entry);
      continue;
    }
  }

  const dedupedByDid = new Map<string, ViewerIdentity>();
  for (const entry of matched) {
    if (dedupedByDid.has(entry.did)) continue;
    dedupedByDid.set(entry.did, {
      did: entry.did,
      publicKeyJwk: entry.publicKeyJwk,
      privateKeyJwk: entry.privateKeyJwk,
    });
  }

  return [...dedupedByDid.values()];
}
