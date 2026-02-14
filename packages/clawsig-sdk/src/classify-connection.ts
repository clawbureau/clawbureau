import { reverse } from 'node:dns/promises';

export type Classification =
  | 'llm_api'
  | 'infrastructure'
  | 'agent_tooling'
  | 'agent_http'
  | 'suspicious'
  | 'system_noise'
  | 'local'
  | 'fd_inheritance';

// ---------------------------------------------------------------------------
// DNS cache with negative lookups + TTL
// ---------------------------------------------------------------------------
const dnsCache = new Map<string, { hostnames: string[]; ts: number }>();
const DNS_CACHE_TTL_MS = 300_000; // 5 minutes

async function fastReverseDns(ip: string): Promise<string[]> {
  const now = Date.now();
  const cached = dnsCache.get(ip);
  if (cached && now - cached.ts < DNS_CACHE_TTL_MS) return cached.hostnames;

  try {
    // Race against a 500ms timeout — PTR lookups on CDN IPs can stall for 5+ seconds
    const hostnames = await Promise.race([
      reverse(ip),
      new Promise<string[]>((_, reject) => setTimeout(() => reject(new Error('dns timeout')), 500)),
    ]);
    dnsCache.set(ip, { hostnames, ts: now });
    return hostnames;
  } catch {
    dnsCache.set(ip, { hostnames: [], ts: now });
    return [];
  }
}

// ---------------------------------------------------------------------------
// Process classification tables
// ---------------------------------------------------------------------------

/**
 * Text processing pipes that NEVER initiate network connections.
 * If lsof shows these with sockets, it's ALWAYS inherited FDs from parent bash.
 */
const NEVER_CONNECTS = new Set([
  // Text filters
  'tr', 'sed', 'head', 'tail', 'awk', 'gawk', 'mawk', 'nawk',
  'grep', 'egrep', 'fgrep', 'rg', 'sort', 'uniq', 'wc', 'cut',
  'tee', 'paste', 'join', 'comm', 'fold', 'fmt', 'column',
  'rev', 'tac', 'nl', 'expand', 'unexpand', 'pr',
  // I/O but not network
  'cat', 'echo', 'printf', 'yes', 'true', 'false', 'test', '[',
  // Math / string
  'expr', 'bc', 'dc', 'factor',
  // Info
  'date', 'env', 'printenv', 'id', 'whoami', 'hostname',
  'basename', 'dirname', 'realpath', 'readlink',
  // Control
  'sleep', 'timeout', 'watch', 'xargs', 'parallel',
  // Shells — inherit parent FDs across fork, never connect themselves
  'sh', 'bash', 'zsh', 'fish', 'dash',
  // Data processors
  'jq', 'yq',
]);

/**
 * CLI networking tools that the agent INTENTIONALLY runs.
 * If spawned by the agent's PID tree → agent_tooling, not suspicious.
 */
const AGENT_NET_TOOLS = new Set([
  // HTTP clients
  'curl', 'wget', 'httpie', 'http',
  // DNS
  'dig', 'nslookup', 'host', 'drill',
  // ICMP / routing
  'ping', 'ping6', 'traceroute', 'traceroute6', 'mtr', 'tracepath',
  // Raw sockets
  'nc', 'ncat', 'netcat', 'socat',
  // TLS / crypto
  'openssl',
  // Remote access
  'ssh', 'scp', 'sftp', 'rsync',
  // Lookup
  'whois', 'telnet',
  // Scanning
  'nmap', 'masscan',
  // VCS
  'git', 'git-remote-http', 'git-remote-https',
  'gh', 'hub',
  // Package managers
  'npm', 'npx', 'yarn', 'pnpm', 'bun',
  'pip', 'pip3', 'poetry', 'cargo', 'go',
]);

// ---------------------------------------------------------------------------
// Domain patterns
// ---------------------------------------------------------------------------
const LLM_DOMAINS = [
  /\.openai\.com$/,
  /\.anthropic\.com$/,
  /\.googleapis\.com$/,
  /\.groq\.com$/,
  /\.mistral\.ai$/,
  /\.cohere\.com$/,
  /\.deepseek\.com$/,
  /openrouter\.ai$/,
  /\.together\.xyz$/,
];

const INFRA_DOMAINS = [
  /\.github\.com$/,
  /\.githubusercontent\.com$/,
  /\.npmjs\.org$/,
  /\.npmjs\.com$/,
  /\.pypi\.org$/,
  /\.docker\.io$/,
  /\.docker\.com$/,
  /\.vercel\.app$/,
  /\.cloudflare\.com$/,
  /\.workers\.dev$/,
];

const NOISY_DAEMONS = [
  'rapportd', 'identityservicesd', 'sharingd', 'mDNSResponder',
  'trustd', 'nsurlsessiond', 'apsd', 'parsecd', 'cloudd',
  'CalendarAgent', 'accountsd', 'WiFiAgent',
];

const BROWSER_NAMES = [
  'Google Chrome', 'Brave Browser', 'Firefox', 'Safari',
  'Arc', 'Microsoft Edge', 'Opera', 'Vivaldi', 'Chromium',
];

const LOCAL_PATTERNS = [
  /^127\./, /^0\.0\.0\./, /^::1$/, /^localhost$/, /^\[::1\]$/,
];

// ---------------------------------------------------------------------------
// Main classifier
// ---------------------------------------------------------------------------
export async function classifyConnection(
  ip: string,
  port: number,
  processName: string | null,
  _pid: number | null,
  isAgentPid: boolean = false,
): Promise<Classification> {
  // 1. Local loopback
  if (LOCAL_PATTERNS.some(p => p.test(ip))) return 'local';

  if (processName) {
    // Extract base name (strip path prefix, leading dash)
    const baseName = processName.trim().split(' ')[0]!.split('/').pop()!.replace(/^-/, '');

    // 2. Text pipes — ALWAYS FD inheritance noise
    if (NEVER_CONNECTS.has(baseName)) return 'fd_inheritance';

    // 3. System daemons
    if (NOISY_DAEMONS.some(d => processName.includes(d))) return 'system_noise';

    // 4. Browsers
    if (BROWSER_NAMES.some(b => processName.includes(b))) return 'infrastructure';

    // 5. Known agent networking tools
    if (isAgentPid && AGENT_NET_TOOLS.has(baseName)) return 'agent_tooling';
  }

  // 6. Reverse DNS domain matching
  const hostnames = await fastReverseDns(ip);
  const checkDomains = [ip, ...hostnames];

  for (const host of checkDomains) {
    if (LLM_DOMAINS.some(p => p.test(host))) return 'llm_api';
    if (INFRA_DOMAINS.some(p => p.test(host))) return 'infrastructure';
  }

  // 7. Agent's Node process making HTTPS calls
  if (isAgentPid && processName === 'node' && (port === 443 || port === 80)) {
    return 'agent_http';
  }

  // 8. In agent PID tree but unknown purpose
  if (isAgentPid) return 'suspicious';

  // 9. Not in agent PID tree — external noise
  return 'system_noise';
}
