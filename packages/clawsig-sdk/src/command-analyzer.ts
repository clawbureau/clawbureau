/**
 * Semantic Shell Command Security Analyzer
 *
 * Parses shell commands to detect data exfiltration, remote code execution,
 * sensitive file access, and suspicious network behavior. Pure string analysis
 * with no shell execution. Handles pipes, subshells, redirections, chaining,
 * variables, and globs.
 *
 * Risk levels:
 *   safe     — Read-only inbound from trusted domain
 *   caution  — Outbound to unknown domain, or accessing non-sensitive files
 *   dangerous — Accessing sensitive files OR outbound with file data
 *   critical — Sensitive file + outbound to untrusted destination, or RCE
 */

export interface CommandAnalysis {
  command: string;
  risk: 'safe' | 'caution' | 'dangerous' | 'critical';
  dataFlow: 'inbound' | 'outbound' | 'bidirectional' | 'local' | 'unknown';
  sensitiveFiles: string[];
  destinations: Array<{
    host: string;
    trust: 'trusted' | 'expected' | 'unknown' | 'suspicious' | 'high_risk';
  }>;
  patterns: string[];
  explanation: string;
}

// ---------------------------------------------------------------------------
// Sensitive file patterns
// ---------------------------------------------------------------------------

const SENSITIVE_FILE_PATTERNS: RegExp[] = [
  /\.(env|pem|key|p12|pfx|netrc|npmrc|gitconfig)$/i,
  /\.(env\.(local|production|staging|development|test))$/i,
  /id_(rsa|ed25519|ecdsa|dsa)/i,
  /\/?\.(ssh|aws|gcloud|azure|kube|gnupg)\//i,
  /\/etc\/(passwd|shadow|sudoers)/i,
  /\.docker\/config\.json/i,
  /.*_history$/i,
  /\.clawsecrets\//i,
  /\.pypirc$/i,
];

// ---------------------------------------------------------------------------
// Exfiltration patterns
// ---------------------------------------------------------------------------

const EXFIL_PATTERNS: RegExp[] = [
  // curl/wget uploading files
  /(curl|wget)\s.*(-d\s*@|-T\s|--data-binary\s*@|--data\s*@|--upload-file\s)/i,
  // curl POST (might be sending data)
  /curl\s.*-X\s*(POST|PUT|PATCH)\s/i,
  // Piping into network commands
  /\|\s*(curl|wget|nc|netcat|ncat|socat)\s/i,
  // Command substitution in URLs (data in query params)
  /(curl|wget)\s.*[\$`].*\b(cat|base64|xxd|od)\b/i,
  // tar/zip piped to network
  /\b(tar|zip|gzip)\b.*\|\s*(curl|wget|nc|netcat|ncat|socat)\s/i,
  // DNS exfiltration: dig with command substitution
  /\bdig\b.*[\$`]/i,
  // netcat receiving file input
  /\b(nc|netcat|ncat)\b.*[<]/i,
  // scp/rsync TO remote (local path before remote path pattern user@host:)
  /\b(scp|rsync)\b\s+[^@:]+\s+\S+@\S+:/i,
];

// ---------------------------------------------------------------------------
// Remote Code Execution patterns
// ---------------------------------------------------------------------------

const RCE_PATTERNS: RegExp[] = [
  // curl/wget pipe to shell
  /(curl|wget)\s.*\|\s*(bash|sh|zsh|dash|ksh)/i,
  // eval with network command
  /\beval\b.*[\$`]\s*\(?\s*(curl|wget)/i,
  // python/ruby -c with embedded curl
  /\b(python3?|ruby|perl)\b\s+-[ce]\s*["']?\$?\(?\s*(curl|wget)/i,
  // wget -O - pipe to shell
  /wget\s.*-O\s*-.*\|\s*(bash|sh)/i,
  // Download and execute pattern
  /&&\s*(bash|sh|chmod\s+\+x)\s/i,
];

// ---------------------------------------------------------------------------
// Trusted domains (known safe destinations)
// ---------------------------------------------------------------------------

const TRUSTED_DOMAINS: string[] = [
  // Code hosting
  'github.com', 'gitlab.com', 'bitbucket.org', 'codeberg.org',
  // Package registries
  'npmjs.org', 'registry.npmjs.org', 'pypi.org', 'files.pythonhosted.org',
  'docker.io', 'docker.com', 'ghcr.io',
  'maven.org', 'jcenter.bintray.com', 'repo1.maven.org',
  'rubygems.org', 'crates.io', 'nuget.org',
  'pkg.go.dev', 'proxy.golang.org',
  // CDNs / infra
  'cdn.jsdelivr.net', 'unpkg.com', 'cdnjs.cloudflare.com',
  'dl.google.com', 'storage.googleapis.com',
  'amazonaws.com', 's3.amazonaws.com',
  // News / reference
  'bbc.co.uk', 'bbc.com', 'reuters.com', 'apnews.com',
  'theguardian.com', 'npr.org', 'aljazeera.com',
  'wikipedia.org', 'wikimedia.org',
  'techcrunch.com', 'arstechnica.com', 'hackernews.com',
  // API providers (LLM etc)
  'api.openai.com', 'api.anthropic.com', 'api.groq.com',
  'generativelanguage.googleapis.com', 'api.mistral.ai',
  'openrouter.ai', 'api.together.xyz', 'api.cohere.com',
  // Cloud
  'api.cloudflare.com', 'api.vercel.com',
  'api.stripe.com', 'api.github.com',
  // Search
  'api.search.brave.com', 'google.com', 'bing.com',
];

// ---------------------------------------------------------------------------
// High-risk domain patterns
// ---------------------------------------------------------------------------

const HIGH_RISK_DOMAINS: RegExp[] = [
  /\.onion$/i,
  /\.bit$/i,
  /\.ngrok\.(io|com|app)$/i,
  /\.duckdns\.org$/i,
  /\.loca\.lt$/i,
  /\.pinggy\.link$/i,
  /\.trycloudflare\.com$/i,
  /\.serveo\.net$/i,
  /\.localtunnel\.me$/i,
  /\.burpcollaborator\.net$/i,
  /\.oast\.(live|fun|pro|me|site|online)$/i,
  /\.interact\.sh$/i,
  /\.requestbin\.(com|net)$/i,
  /\.webhook\.site$/i,
  /\.pipedream\.(net|com)$/i,
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function extractUrlsAndHosts(cmd: string): string[] {
  const hosts: string[] = [];
  // HTTP(S) URLs
  const urlRegex = /https?:\/\/([^\/\s'"\\)>]+)/gi;
  let match: RegExpExecArray | null;
  while ((match = urlRegex.exec(cmd)) !== null) {
    if (match[1]) {
      // Strip port
      hosts.push(match[1].split(':')[0].toLowerCase());
    }
  }
  // scp/rsync user@host:path
  const sshRegex = /(?:scp|rsync)\s+.*?\s+([^@\s]+@)?([^:\s]+):/gi;
  while ((match = sshRegex.exec(cmd)) !== null) {
    if (match[2]) hosts.push(match[2].toLowerCase());
  }
  // nc/netcat host port
  const ncRegex = /\b(?:nc|netcat|ncat)\s+([a-zA-Z0-9.-]+)\s+\d+/gi;
  while ((match = ncRegex.exec(cmd)) !== null) {
    if (match[1]) hosts.push(match[1].toLowerCase());
  }
  return [...new Set(hosts)];
}

function evaluateTrust(host: string): CommandAnalysis['destinations'][0]['trust'] {
  // Check trusted domains (exact match or subdomain)
  if (TRUSTED_DOMAINS.some(d => host === d || host.endsWith('.' + d))) return 'trusted';
  // Check high-risk patterns
  if (HIGH_RISK_DOMAINS.some(r => r.test(host))) return 'high_risk';
  // Raw IP addresses
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) return 'suspicious';
  // IPv6
  if (host.startsWith('[') || host.includes('::')) return 'suspicious';
  // localhost / loopback
  if (host === 'localhost' || host === '127.0.0.1' || host === '::1') return 'trusted';
  // Everything else
  return 'unknown';
}

function extractSensitiveFiles(cmd: string): string[] {
  const found: string[] = [];
  // Tokenize respecting quotes
  const tokens = cmd.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g) || [];
  for (const raw of tokens) {
    const token = raw.replace(/^['"]|['"]$/g, '');
    if (SENSITIVE_FILE_PATTERNS.some(p => p.test(token))) {
      found.push(token);
    }
  }
  // Also check for expanded paths in the full command
  const pathPatterns = [
    /~\/\.ssh\/\S+/g,
    /~\/\.aws\/\S+/g,
    /~\/\.gnupg\/\S+/g,
    /~\/\.kube\/\S+/g,
    /\/etc\/(?:passwd|shadow|sudoers)/g,
  ];
  for (const p of pathPatterns) {
    let m: RegExpExecArray | null;
    while ((m = p.exec(cmd)) !== null) {
      if (!found.includes(m[0])) found.push(m[0]);
    }
  }
  return [...new Set(found)];
}

function determineDataFlow(cmd: string, hosts: string[]): CommandAnalysis['dataFlow'] {
  if (hosts.length === 0) return 'local';

  // Outbound: file upload indicators — check BEFORE bidirectional
  if (EXFIL_PATTERNS.some(p => p.test(cmd))) return 'outbound';

  // Bidirectional tools (only if no explicit exfil pattern detected)
  if (/\b(ssh|rsync)\b/i.test(cmd)) return 'bidirectional';

  // Outbound: pipe into network command
  if (/\|.*\b(curl|wget|nc|netcat|ncat|socat)\b/i.test(cmd)) return 'outbound';

  // Outbound: POST/PUT/PATCH without explicit file but with -d
  if (/curl\s.*-X\s*(POST|PUT|PATCH)/i.test(cmd) && /\s-d\s/i.test(cmd)) return 'outbound';

  // Default for commands with hosts: inbound (read/download)
  return 'inbound';
}

function detectPatterns(cmd: string, dataFlow: string, sensitiveFiles: string[]): string[] {
  const patterns: string[] = [];

  // Exfiltration: outbound + sensitive files
  if (dataFlow === 'outbound' && sensitiveFiles.length > 0) {
    patterns.push('sensitive_exfiltration');
  }

  // Remote code execution
  if (RCE_PATTERNS.some(p => p.test(cmd))) {
    patterns.push('remote_code_execution');
  }

  // DNS exfiltration
  if (/\bdig\b.*[\$`]/i.test(cmd)) {
    patterns.push('dns_exfiltration');
  }

  // File upload (even without sensitive files)
  if (/(curl|wget)\s.*(-T\s|--upload-file\s|--data-binary\s*@)/i.test(cmd)) {
    patterns.push('file_upload');
  }

  // Sensitive file read (even without network)
  if (sensitiveFiles.length > 0 && dataFlow === 'local') {
    patterns.push('sensitive_file_access');
  }

  // Sensitive file read + network (not necessarily outbound)
  if (sensitiveFiles.length > 0 && dataFlow !== 'local') {
    patterns.push('sensitive_file_with_network');
  }

  // Shell config modification
  if (/>>?\s*~\/\.(zshrc|bashrc|bash_profile|profile)/i.test(cmd)) {
    patterns.push('shell_config_modification');
  }

  // Env variable exfiltration
  if (/\benv\b|\bprintenv\b|\bset\b.*\|\s*(curl|wget|nc)/i.test(cmd)) {
    patterns.push('env_exfiltration');
  }

  return patterns;
}

function computeRisk(
  dataFlow: string,
  sensitiveFiles: string[],
  patterns: string[],
  destinations: CommandAnalysis['destinations'],
): { risk: CommandAnalysis['risk']; explanation: string } {
  let score = 0;

  // Sensitive files
  if (sensitiveFiles.length > 0) score += 2;

  // Outbound data flow
  if (dataFlow === 'outbound') score += 1;

  // Pattern-based scoring
  if (patterns.includes('remote_code_execution')) score += 3;
  if (patterns.includes('sensitive_exfiltration')) score += 4;
  if (patterns.includes('dns_exfiltration')) score += 3;
  if (patterns.includes('file_upload')) score += 1;

  // Destination trust scoring
  if (destinations.some(d => d.trust === 'high_risk')) score += 3;
  if (destinations.some(d => d.trust === 'suspicious')) score += 1;

  // Shell config modification
  if (patterns.includes('shell_config_modification')) score += 1;

  // Determine risk level
  let risk: CommandAnalysis['risk'];
  let explanation: string;

  if (score >= 4) {
    risk = 'critical';
    explanation = `Critical: ${patterns.join(', ') || 'suspicious command combination'}. ` +
      (sensitiveFiles.length > 0 ? `Sensitive files: ${sensitiveFiles.join(', ')}. ` : '') +
      (destinations.filter(d => d.trust !== 'trusted').map(d => `${d.host} (${d.trust})`).join(', ') || '');
  } else if (score >= 2) {
    risk = 'dangerous';
    explanation = `Dangerous: ${patterns.join(', ') || 'accesses sensitive files or suspicious network behavior'}. ` +
      (sensitiveFiles.length > 0 ? `Files: ${sensitiveFiles.join(', ')}. ` : '');
  } else if (score === 1) {
    risk = 'caution';
    explanation = `Caution: ${patterns.join(', ') || 'outbound network request or unknown domain'}.`;
  } else {
    risk = 'safe';
    explanation = 'Safe: benign local or inbound operation.';
  }

  // Override: inbound from all-trusted domains is always safe
  if (dataFlow === 'inbound' && destinations.length > 0 &&
      destinations.every(d => d.trust === 'trusted') &&
      sensitiveFiles.length === 0 &&
      !patterns.includes('remote_code_execution')) {
    risk = 'safe';
    explanation = 'Safe: inbound read from trusted domain.';
  }

  return { risk, explanation: explanation.trim() };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function analyzeCommand(command: string): CommandAnalysis {
  const hosts = extractUrlsAndHosts(command);
  const destinations = hosts.map(h => ({ host: h, trust: evaluateTrust(h) }));
  const sensitiveFiles = extractSensitiveFiles(command);
  const dataFlow = determineDataFlow(command, hosts);
  const patterns = detectPatterns(command, dataFlow, sensitiveFiles);
  const { risk, explanation } = computeRisk(dataFlow, sensitiveFiles, patterns, destinations);

  return {
    command,
    risk,
    dataFlow,
    sensitiveFiles,
    destinations,
    patterns,
    explanation,
  };
}
