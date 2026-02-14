import { reverse } from 'node:dns/promises';

export type Classification = 'llm_api' | 'infrastructure' | 'agent_tooling' | 'suspicious' | 'system_noise' | 'local';

const dnsCache = new Map<string, string[]>();

const LLM_DOMAINS = [
  /\.openai\.com$/, /\.anthropic\.com$/, /\.googleapis\.com$/,
  /\.groq\.com$/, /\.mistral\.ai$/, /\.cohere\.com$/,
];

const INFRA_DOMAINS = [
  /\.github\.com$/, /\.npmjs\.org$/, /\.pypi\.org$/, /\.docker\.io$/,
];

const NOISY_DAEMONS = [
  'rapportd', 'identityservicesd', 'sharingd', 'mDNSResponder',
  'trustd', 'nsurlsessiond', 'apsd', 'parsecd',
];

const LOCAL_PATTERNS = [
  /^127\./, /^0\.0\.0\./, /^::1/, /^localhost/, /^\[::1\]/,
];

export async function classifyConnection(
  ip: string,
  port: number,
  processName: string | null,
  _pid: number | null,
  isAgentPid: boolean = false,
): Promise<Classification> {
  // 1. Local loopback
  if (LOCAL_PATTERNS.some(p => p.test(ip))) {
    return 'local';
  }

  // 2. macOS System Daemons
  if (processName && NOISY_DAEMONS.some(d => processName.includes(d))) {
    return 'system_noise';
  }

  // 3. Resolve Hostnames
  let hostnames: string[] = [];
  if (dnsCache.has(ip)) {
    hostnames = dnsCache.get(ip)!;
  } else {
    try {
      hostnames = await reverse(ip);
      dnsCache.set(ip, hostnames);
    } catch {
      dnsCache.set(ip, []);
    }
  }

  // 4. Check Domains
  const checkDomains = [ip, ...hostnames];
  for (const host of checkDomains) {
    if (LLM_DOMAINS.some(pattern => pattern.test(host))) return 'llm_api';
    if (INFRA_DOMAINS.some(pattern => pattern.test(host))) return 'infrastructure';
  }

  // 5. Agent Tooling (Port 443/80 heuristic)
  if (isAgentPid && (port === 443 || port === 80)) {
    return 'agent_tooling';
  }

  // If not from our PID tree and didn't match anything else, consider it noise
  if (!isAgentPid) {
    return 'system_noise';
  }

  return 'suspicious';
}
