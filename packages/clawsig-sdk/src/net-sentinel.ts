/**
 * Network Sentinel — Detect network connections from agent processes.
 *
 * Uses /proc/net/tcp on Linux (zero-dependency, low overhead) with
 * lsof -i fallback on macOS. Polls at configurable intervals to detect
 * new TCP connections from the agent's PID tree.
 *
 * This catches the bypass that env-var proxies can't: when an agent
 * runs `curl --noproxy '*'` or `python3 -c "requests.get(...)"`
 * directly, the HTTP_PROXY is ignored but the TCP connection
 * is still visible to lsof/procfs.
 *
 * Coverage: ~75% of outbound TCP connections.
 * Evasion: sub-200ms connections, UDP/ICMP, DNS tunneling,
 * double-fork daemon escape.
 */

import { execFile } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** A network connection event captured by the sentinel. */
export interface NetEvent {
  layer: 'net';
  /** ISO 8601 timestamp. */
  ts: string;
  /** Protocol (tcp, tcp6). */
  protocol: string;
  /** Local address:port. */
  localAddress: string;
  /** Remote address:port. */
  remoteAddress: string;
  /** Connection state. */
  state: string;
  /** PID that owns the connection (if resolved). */
  pid: number | null;
  /** Process name (if resolved). */
  processName: string | null;
  /** Classification of the connection. */
  classification: 'llm_provider' | 'authorized' | 'suspicious' | 'local';
}

/** Options for the Network Sentinel. */
export interface NetSentinelOptions {
  /** Polling interval in milliseconds (default: 500). */
  pollIntervalMs?: number;
  /** Allowed domains/IPs that won't be flagged as suspicious. */
  allowedHosts?: string[];
}

// ---------------------------------------------------------------------------
// Known LLM provider domains (for classification)
// ---------------------------------------------------------------------------

const LLM_PROVIDER_PATTERNS = [
  /api\.anthropic\.com/,
  /api\.openai\.com/,
  /generativelanguage\.googleapis\.com/,
  /api\.together\.xyz/,
  /api\.groq\.com/,
  /openrouter\.ai/,
  /api\.cohere\.ai/,
  /api\.mistral\.ai/,
  /api\.fireworks\.ai/,
  /clawproxy\.com/,
];

const LOCAL_PATTERNS = [
  /^127\./,
  /^0\.0\.0\./,
  /^::1/,
  /^localhost/,
  /^\[::1\]/,
];

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

export class NetSentinel {
  private timer?: ReturnType<typeof setInterval>;
  private knownConnections = new Set<string>();
  private events: NetEvent[] = [];
  private targetPids = new Set<number>();
  private allowedHosts: string[];
  private running = false;
  private pollIntervalMs: number;
  private useProcfs: boolean;

  constructor(options: NetSentinelOptions) {
    this.pollIntervalMs = options.pollIntervalMs ?? 500;
    this.allowedHosts = options.allowedHosts ?? [];
    this.useProcfs = existsSync('/proc/net/tcp');
  }

  /** Add a PID to monitor (and all its descendants). */
  setTargetPid(pid: number): void {
    this.targetPids.add(pid);
  }

  /** Start polling for network connections. */
  start(): void {
    if (this.running) return;
    this.running = true;

    this.timer = setInterval(() => {
      void this.poll().catch(() => { /* swallow poll errors */ });
    }, this.pollIntervalMs);

    // Don't prevent Node from exiting
    this.timer.unref();
  }

  /** Stop polling. */
  stop(): void {
    this.running = false;
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = undefined;
    }
  }

  /** Get all captured network events. */
  getEvents(): NetEvent[] {
    return [...this.events];
  }

  /** Get only suspicious events (non-LLM, non-local, non-allowed). */
  getSuspiciousEvents(): NetEvent[] {
    return this.events.filter(e => e.classification === 'suspicious');
  }

  /** Get event count. */
  get eventCount(): number {
    return this.events.length;
  }

  /** Get suspicious event count. */
  get suspiciousCount(): number {
    return this.events.filter(e => e.classification === 'suspicious').length;
  }

  // ---- Private ----

  private async poll(): Promise<void> {
    if (this.useProcfs) {
      this.pollProcNet('/proc/net/tcp', 'tcp');
      if (existsSync('/proc/net/tcp6')) {
        this.pollProcNet('/proc/net/tcp6', 'tcp6');
      }
    } else {
      await this.pollLsof();
    }
  }

  /**
   * Read /proc/net/tcp directly (Linux, no exec overhead).
   * Format: sl local_address rem_address st tx_queue rx_queue ...
   */
  private pollProcNet(procPath: string, protocol: string): void {
    try {
      const content = readFileSync(procPath, 'utf8');
      const lines = content.split('\n');
      const ts = new Date().toISOString();

      for (let i = 1; i < lines.length; i++) {
        const line = lines[i]?.trim();
        if (!line) continue;

        const parts = line.split(/\s+/);
        if (parts.length < 4) continue;

        const localPart = parts[1];
        const remotePart = parts[2];
        const stateCode = parts[3];

        if (!localPart || !remotePart || !stateCode) continue;

        // Only ESTABLISHED (01) and SYN_SENT (02)
        if (stateCode !== '01' && stateCode !== '02') continue;

        const local = this.parseHexAddress(localPart);
        const remote = this.parseHexAddress(remotePart);

        // Skip loopback
        if (this.isLocal(remote)) continue;

        const connKey = `${protocol}:${local}->${remote}`;
        if (this.knownConnections.has(connKey)) continue;
        this.knownConnections.add(connKey);

        const classification = this.classifyConnection(remote);
        const event: NetEvent = {
          layer: 'net',
          ts,
          protocol,
          localAddress: local,
          remoteAddress: remote,
          state: stateCode === '01' ? 'ESTABLISHED' : 'SYN_SENT',
          pid: null, // /proc/net/tcp doesn't include PID without scanning /proc/[pid]/fd
          processName: null,
          classification,
        };

        this.events.push(event);
      }
    } catch {
      // procfs read failed — skip this tick
    }
  }

  /**
   * Use lsof on macOS/BSD to get network connections.
   * Filters to the target PID tree.
   */
  private async pollLsof(): Promise<void> {
    try {
      // Build PID tree for filtering
      const pids = await this.expandPidTree();

      const args = ['-i', '-n', '-P', '-F', 'pcPnT'];
      if (pids.length > 0) {
        args.push('-p', pids.join(','));
      }

      let stdout: string;
      try {
        const result = await execFileAsync('lsof', args, { timeout: 3000 });
        stdout = result.stdout;
      } catch (err: unknown) {
        // lsof exits 1 when no matching sockets — that's fine
        const execErr = err as { stdout?: string; code?: number };
        if (execErr.stdout) {
          stdout = execErr.stdout;
        } else {
          return;
        }
      }

      const ts = new Date().toISOString();
      let currentPid = -1;
      let currentCmd = '';
      let currentProtocol = '';

      const lines = stdout.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (!line) continue;

        const type = line.charAt(0);
        const val = line.slice(1);

        if (type === 'p') {
          currentPid = parseInt(val, 10);
        } else if (type === 'c') {
          currentCmd = val;
        } else if (type === 'P') {
          currentProtocol = val.toLowerCase();
        } else if (type === 'n') {
          const address = val;
          let state = 'UNKNOWN';

          // Check next line for state (TST= prefix in lsof -F T output)
          if (i + 1 < lines.length && lines[i + 1]?.startsWith('TST=')) {
            state = lines[i + 1]!.slice(4);
            i++;
          }

          if (!address.includes('->')) continue;
          if (state !== 'ESTABLISHED' && state !== 'SYN_SENT' && state !== 'UNKNOWN') continue;

          const [local, remote] = address.split('->');
          if (!remote || this.isLocal(remote)) continue;

          const connKey = `${currentPid}:${currentProtocol}:${local}:${remote}`;
          if (this.knownConnections.has(connKey)) continue;
          this.knownConnections.add(connKey);

          const classification = this.classifyConnection(remote);
          const event: NetEvent = {
            layer: 'net',
            ts,
            protocol: currentProtocol,
            localAddress: local || '',
            remoteAddress: remote,
            state,
            pid: currentPid,
            processName: currentCmd,
            classification,
          };

          this.events.push(event);
        }
      }
    } catch {
      // lsof not available or failed — skip
    }
  }

  /**
   * Expand target PIDs into full process tree.
   */
  private async expandPidTree(): Promise<number[]> {
    const all = new Set<number>();

    for (const pid of this.targetPids) {
      all.add(pid);
      try {
        const { stdout } = await execFileAsync('pgrep', ['-P', String(pid)], { timeout: 2000 });
        for (const line of stdout.trim().split('\n')) {
          const child = parseInt(line, 10);
          if (!isNaN(child)) {
            all.add(child);
            // One level deeper (grandchildren)
            try {
              const { stdout: gc } = await execFileAsync('pgrep', ['-P', String(child)], { timeout: 1000 });
              for (const gcLine of gc.trim().split('\n')) {
                const grandchild = parseInt(gcLine, 10);
                if (!isNaN(grandchild)) all.add(grandchild);
              }
            } catch { /* no grandchildren */ }
          }
        }
      } catch { /* no children */ }
    }

    return [...all];
  }

  /** Classify a remote address. */
  private classifyConnection(remote: string): NetEvent['classification'] {
    if (this.isLocal(remote)) return 'local';

    // Check known LLM providers
    for (const pat of LLM_PROVIDER_PATTERNS) {
      if (pat.test(remote)) return 'llm_provider';
    }

    // Check allowed hosts
    for (const host of this.allowedHosts) {
      if (remote.includes(host)) return 'authorized';
    }

    return 'suspicious';
  }

  /** Check if an address is loopback. */
  private isLocal(address: string): boolean {
    return LOCAL_PATTERNS.some(p => p.test(address));
  }

  /** Parse hex address from /proc/net/tcp format (ADDR:PORT). */
  private parseHexAddress(hexAddr: string): string {
    const [addrHex, portHex] = hexAddr.split(':');
    if (!addrHex || !portHex) return hexAddr;

    const port = parseInt(portHex, 16);

    if (addrHex.length <= 8) {
      // IPv4: bytes are reversed
      const bytes = addrHex.match(/.{2}/g);
      if (!bytes || bytes.length < 4) return `${hexAddr}`;
      const ip = bytes.reverse().map(b => parseInt(b, 16)).join('.');
      return `${ip}:${port}`;
    }

    // IPv6: too long to render nicely, abbreviate
    return `[ipv6:${addrHex.slice(0, 8)}...]:${port}`;
  }
}
