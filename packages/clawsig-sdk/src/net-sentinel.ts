import { execFile } from 'node:child_process';
import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { promisify } from 'node:util';
import { classifyConnection, type Classification } from './classify-connection.js';

const execFileAsync = promisify(execFile);

export interface NetEvent {
  layer: 'net';
  ts: string;
  protocol: string;
  localAddress: string;
  remoteAddress: string;
  state: string;
  pid: number | null;
  processName: string | null;
  classification: Classification;
}

export interface NetSentinelOptions {
  pollIntervalMs?: number;
}

/**
 * Time-windowed dedup: same (pid, proto, local, remote) within this window → skip.
 * After the window expires, emit a fresh receipt (connection still alive = useful signal).
 */
const DEDUP_WINDOW_MS = 10_000;

/**
 * Shells that inherit parent FDs — exclude from lsof queries entirely.
 */
const SHELL_NAMES = new Set(['bash', 'sh', 'zsh', 'fish', 'dash', 'cmd.exe', 'powershell.exe', 'pwsh.exe']);

export class NetSentinel {
  private timer?: ReturnType<typeof setInterval>;
  private knownConnections = new Map<string, number>(); // connKey → last-seen timestamp
  private events: NetEvent[] = [];
  private targetPids = new Set<number>();
  private running = false;
  private pollIntervalMs: number;
  private isMac = process.platform === 'darwin';
  private isWin = process.platform === 'win32';

  constructor(options: NetSentinelOptions = {}) {
    this.pollIntervalMs = options.pollIntervalMs ?? 500;
  }

  setTargetPid(pid: number): void {
    this.targetPids.add(pid);
  }

  start(): void {
    if (this.running) return;
    this.running = true;

    this.timer = setInterval(() => {
      void this.poll().catch(() => {});
    }, this.pollIntervalMs);
    this.timer.unref();
  }

  stop(): void {
    this.running = false;
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = undefined;
    }
  }

  /** Returns only meaningful events (filters fd_inheritance + system_noise) */
  getEvents(): NetEvent[] {
    return this.events.filter(
      e => e.classification !== 'fd_inheritance' && e.classification !== 'system_noise',
    );
  }

  getSuspiciousEvents(): NetEvent[] {
    return this.events.filter(e => e.classification === 'suspicious');
  }

  get eventCount(): number {
    return this.getEvents().length;
  }

  get suspiciousCount(): number {
    return this.getSuspiciousEvents().length;
  }

  // -------------------------------------------------------------------------
  // Polling
  // -------------------------------------------------------------------------

  private async poll(): Promise<void> {
    const tree = await this.expandPidTree();
    if (tree.pids.length === 0) return;

    // Filter out shell PIDs from lsof query (prevents FD inheritance noise at source)
    const queryPids: number[] = [];
    for (const pid of tree.pids) {
      const name = tree.processNames.get(pid) || '';
      if (SHELL_NAMES.has(name)) continue;
      queryPids.push(pid);
    }

    // Always include root target PIDs
    for (const pid of this.targetPids) {
      if (!queryPids.includes(pid)) queryPids.push(pid);
    }

    if (queryPids.length === 0) return;

    if (this.isWin) {
      await this.pollNetstatWindows(queryPids, tree);
    } else if (this.isMac) {
      await this.pollLsof(queryPids, tree);
    } else {
      await this.pollProcNetTcp(queryPids, tree);
    }

    // Expire old dedup entries
    const now = Date.now();
    for (const [key, ts] of this.knownConnections) {
      if (now - ts > DEDUP_WINDOW_MS) {
        this.knownConnections.delete(key);
      }
    }
  }

  // -------------------------------------------------------------------------
  // PID tree expansion
  // -------------------------------------------------------------------------

  private async expandPidTree(): Promise<{
    pids: number[];
    isAgentMap: Map<number, boolean>;
    processNames: Map<number, string>;
  }> {
    const allPids = new Set<number>(this.targetPids);
    const isAgentMap = new Map<number, boolean>();
    const processNames = new Map<number, string>();

    for (const p of this.targetPids) isAgentMap.set(p, true);

    if (this.isWin) {
      // Windows: wmic process tree
      try {
        const { stdout } = await execFileAsync('wmic', ['process', 'get', 'Name,ParentProcessId,ProcessId'], { timeout: 3000 });
        const ppidMap = new Map<number, number[]>();
        for (const line of stdout.split('\n').slice(1)) {
          const trimmed = line.trim(); if (!trimmed) continue;
          const parts = trimmed.split(/\s+/);
          if (parts.length >= 3) {
            const pidStr = parts.pop()!, ppidStr = parts.pop()!, name = parts.join(' ');
            const pid = parseInt(pidStr, 10), ppid = parseInt(ppidStr, 10);
            if (!isNaN(pid) && !isNaN(ppid)) {
              processNames.set(pid, name);
              if (!ppidMap.has(ppid)) ppidMap.set(ppid, []);
              ppidMap.get(ppid)!.push(pid);
            }
          }
        }
        const queue = Array.from(this.targetPids);
        while (queue.length > 0) {
          const current = queue.shift()!;
          for (const child of ppidMap.get(current) || []) {
            if (!allPids.has(child)) { allPids.add(child); isAgentMap.set(child, true); queue.push(child); }
          }
        }
      } catch { /* degrade gracefully */ }
    } else if (this.isMac) {
      // Batched pgrep: comma-separated parent PIDs in one call
      let currentLevel = Array.from(this.targetPids);
      while (currentLevel.length > 0) {
        try {
          const { stdout } = await execFileAsync(
            'pgrep', ['-P', currentLevel.join(',')],
            { timeout: 2000 },
          );
          const childPids = stdout.trim().split('\n')
            .map(p => parseInt(p, 10))
            .filter(p => !isNaN(p));
          currentLevel = [];
          for (const childPid of childPids) {
            if (!allPids.has(childPid)) {
              allPids.add(childPid);
              isAgentMap.set(childPid, true);
              currentLevel.push(childPid);
            }
          }
        } catch {
          break; // No children or pgrep failed
        }
      }

      // Single ps call to get process names
      if (allPids.size > 0) {
        try {
          const pidList = Array.from(allPids).join(',');
          const { stdout } = await execFileAsync(
            'ps', ['-o', 'pid=,comm=', '-p', pidList],
            { timeout: 2000 },
          );
          for (const line of stdout.split('\n')) {
            const trimmed = line.trim();
            if (!trimmed) continue;
            const spaceIdx = trimmed.indexOf(' ');
            if (spaceIdx === -1) continue;
            const pid = parseInt(trimmed.slice(0, spaceIdx), 10);
            const comm = trimmed.slice(spaceIdx + 1).trim().split('/').pop()!.replace(/^-/, '');
            if (!isNaN(pid) && comm) processNames.set(pid, comm);
          }
        } catch { /* skip */ }
      }
    } else {
      // Linux: read /proc to build parent→children map
      try {
        const procDirs = readdirSync('/proc');
        const ppidMap = new Map<number, number[]>();
        for (const dir of procDirs) {
          const pid = parseInt(dir, 10);
          if (isNaN(pid)) continue;
          try {
            const statContent = readFileSync(`/proc/${pid}/stat`, 'utf8');
            const match = statContent.match(/^\d+\s+\(([^)]+)\)\s+[A-Z]\s+(\d+)/);
            if (match?.[1] && match?.[2]) {
              const ppid = parseInt(match[2], 10);
              processNames.set(pid, match[1]);
              if (!ppidMap.has(ppid)) ppidMap.set(ppid, []);
              ppidMap.get(ppid)!.push(pid);
            }
          } catch { /* skip */ }
        }

        const queue = Array.from(this.targetPids);
        while (queue.length > 0) {
          const pid = queue.shift()!;
          const children = ppidMap.get(pid) || [];
          for (const child of children) {
            if (!allPids.has(child)) {
              allPids.add(child);
              isAgentMap.set(child, true);
              queue.push(child);
            }
          }
        }
      } catch { /* skip */ }
    }

    return { pids: Array.from(allPids), isAgentMap, processNames };
  }

  // -------------------------------------------------------------------------
  // Windows: netstat -ano polling
  // -------------------------------------------------------------------------

  private async pollNetstatWindows(
    queryPids: number[],
    tree: { isAgentMap: Map<number, boolean>; processNames: Map<number, string> },
  ): Promise<void> {
    try {
      const { stdout } = await execFileAsync('netstat', ['-ano'], { timeout: 3000 });
      const ts = new Date().toISOString();
      const nowMs = Date.now();

      for (const line of stdout.split('\n')) {
        const parts = line.trim().split(/\s+/).filter(Boolean);
        if (parts.length < 5) continue;

        const protoStr = parts[0]!.toLowerCase();
        if (!protoStr.startsWith('tcp')) continue;

        const localPart = parts[1]!;
        const remotePart = parts[2]!;
        const stateCode = parts[3]!;
        const pidStr = parts[4]!;

        if (stateCode !== 'ESTABLISHED' && stateCode !== 'SYN_SENT') continue;

        const pid = parseInt(pidStr, 10);
        if (isNaN(pid) || !queryPids.includes(pid)) continue;

        const lastColon = remotePart.lastIndexOf(':');
        if (lastColon === -1) continue;

        const ip = remotePart.slice(0, lastColon).replace(/^\[|\]$/g, '');
        const port = parseInt(remotePart.slice(lastColon + 1) || '0', 10);
        if (!ip || isNaN(port)) continue;

        const proto = protoStr.includes('6') ? 'tcp6' : 'tcp';
        const connKey = `${pid}:${proto}:${localPart}:${remotePart}`;

        const lastSeen = this.knownConnections.get(connKey);
        if (lastSeen && (nowMs - lastSeen < DEDUP_WINDOW_MS)) {
          this.knownConnections.set(connKey, nowMs);
          continue;
        }
        this.knownConnections.set(connKey, nowMs);

        const resolvedCmd = tree.processNames.get(pid) || null;
        const isAgent = tree.isAgentMap.get(pid) ?? false;
        const classification = await classifyConnection(ip, port, resolvedCmd, pid, isAgent);
        if (classification === 'local' || classification === 'system_noise' || classification === 'fd_inheritance') continue;

        this.events.push({
          layer: 'net', ts, protocol: proto, localAddress: localPart,
          remoteAddress: remotePart, state: stateCode, pid,
          processName: resolvedCmd, classification,
        });
      }
    } catch { /* skip */ }
  }

  // -------------------------------------------------------------------------
  // macOS: lsof-based polling
  // -------------------------------------------------------------------------

  private async pollLsof(
    queryPids: number[],
    tree: { isAgentMap: Map<number, boolean>; processNames: Map<number, string> },
  ): Promise<void> {
    try {
      const args = ['-i', '-n', '-P', '-F', 'pcPnT', '-p', queryPids.join(',')];
      let stdout = '';
      try {
        const result = await execFileAsync('lsof', args, { timeout: 3000 });
        stdout = result.stdout;
      } catch (err: unknown) {
        const e = err as { stdout?: string };
        if (e.stdout) stdout = e.stdout;
        else return;
      }

      const ts = new Date().toISOString();
      const nowMs = Date.now();
      let currentPid = -1;
      let currentCmd = '';
      let currentProtocol = '';

      const lines = stdout.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (!line) continue;

        const type = line.charAt(0);
        const val = line.slice(1);

        if (type === 'p') currentPid = parseInt(val, 10);
        else if (type === 'c') currentCmd = val;
        else if (type === 'P') currentProtocol = val.toLowerCase();
        else if (type === 'n') {
          const address = val;
          let state = 'UNKNOWN';

          if (lines[i + 1]?.startsWith('TST=')) {
            state = lines[i + 1]!.slice(4);
            i++;
          }

          if (!address.includes('->')) continue;
          if (state !== 'ESTABLISHED' && state !== 'SYN_SENT' && state !== 'UNKNOWN') continue;

          const arrowIdx = address.indexOf('->');
          const local = address.slice(0, arrowIdx);
          const remote = address.slice(arrowIdx + 2);
          if (!remote) continue;

          // Time-windowed dedup
          const connKey = `${currentPid}:${currentProtocol}:${local}:${remote}`;
          const lastSeen = this.knownConnections.get(connKey);
          if (lastSeen && (nowMs - lastSeen < DEDUP_WINDOW_MS)) {
            this.knownConnections.set(connKey, nowMs); // Refresh timestamp
            continue;
          }
          this.knownConnections.set(connKey, nowMs);

          // Parse IP and port
          const lastColon = remote.lastIndexOf(':');
          const ip = remote.slice(0, lastColon).replace(/^\[|\]$/g, '');
          const port = parseInt(remote.slice(lastColon + 1) || '0', 10);

          const resolvedCmd = tree.processNames.get(currentPid) || currentCmd;
          const isAgent = tree.isAgentMap.get(currentPid) ?? false;

          const classification = await classifyConnection(ip, port, resolvedCmd, currentPid, isAgent);

          // Filter at capture time
          if (classification === 'local' || classification === 'system_noise' || classification === 'fd_inheritance') {
            continue;
          }

          this.events.push({
            layer: 'net',
            ts,
            protocol: currentProtocol,
            localAddress: local,
            remoteAddress: remote,
            state,
            pid: currentPid,
            processName: resolvedCmd,
            classification,
          });
        }
      }
    } catch { /* skip */ }
  }

  // -------------------------------------------------------------------------
  // Linux: /proc/net/tcp polling
  // -------------------------------------------------------------------------

  private async pollProcNetTcp(
    queryPids: number[],
    tree: { isAgentMap: Map<number, boolean>; processNames: Map<number, string> },
  ): Promise<void> {
    const inodeToPid = new Map<string, number>();

    for (const pid of queryPids) {
      try {
        const fdPath = `/proc/${pid}/fd`;
        if (!existsSync(fdPath)) continue;
        const fds = readdirSync(fdPath);
        for (const fd of fds) {
          try {
            const link = readFileSync(`${fdPath}/${fd}`, 'utf8');
            const match = link.match(/^socket:\[(\d+)\]$/);
            if (match?.[1]) inodeToPid.set(match[1], pid);
          } catch { /* skip */ }
        }
      } catch { /* skip */ }
    }

    const ts = new Date().toISOString();
    const nowMs = Date.now();

    for (const file of ['/proc/net/tcp', '/proc/net/tcp6']) {
      if (!existsSync(file)) continue;
      try {
        const content = readFileSync(file, 'utf8');
        const lines = content.split('\n');
        for (let i = 1; i < lines.length; i++) {
          const parts = lines[i]?.trim().split(/\s+/);
          if (!parts || parts.length < 10) continue;

          const localPart = parts[1];
          const remotePart = parts[2];
          const stateCode = parts[3];
          const inode = parts[9];

          if (!inode || !localPart || !remotePart || !stateCode) continue;
          if (stateCode !== '01' && stateCode !== '02') continue; // ESTABLISHED or SYN_SENT

          const pid = inodeToPid.get(inode);
          if (!pid) continue;

          const proto = file.includes('tcp6') ? 'tcp6' : 'tcp';
          const local = this.parseHexAddress(localPart);
          const remote = this.parseHexAddress(remotePart);

          const connKey = `${pid}:${proto}:${local}:${remote}`;
          const lastSeen = this.knownConnections.get(connKey);
          if (lastSeen && (nowMs - lastSeen < DEDUP_WINDOW_MS)) {
            this.knownConnections.set(connKey, nowMs);
            continue;
          }
          this.knownConnections.set(connKey, nowMs);

          const lastColon = remote.lastIndexOf(':');
          const ip = remote.slice(0, lastColon).replace(/^\[|\]$/g, '');
          const portStr = remote.slice(lastColon + 1);
          if (!ip || !portStr) continue;
          const port = parseInt(portStr, 10);

          const resolvedCmd = tree.processNames.get(pid) || null;
          const isAgent = tree.isAgentMap.get(pid) ?? false;

          const classification = await classifyConnection(ip, port, resolvedCmd, pid, isAgent);
          if (classification === 'local' || classification === 'system_noise' || classification === 'fd_inheritance') {
            continue;
          }

          this.events.push({
            layer: 'net',
            ts,
            protocol: proto,
            localAddress: local,
            remoteAddress: remote,
            state: stateCode === '01' ? 'ESTABLISHED' : 'SYN_SENT',
            pid,
            processName: resolvedCmd,
            classification,
          });
        }
      } catch { /* skip */ }
    }
  }

  // -------------------------------------------------------------------------
  // Hex address parsing (Linux /proc/net/tcp)
  // -------------------------------------------------------------------------

  private parseHexAddress(hexAddr: string): string {
    const [addrHex, portHex] = hexAddr.split(':');
    if (!addrHex || !portHex) return hexAddr;
    const port = parseInt(portHex, 16);
    if (addrHex.length <= 8) {
      const bytes = addrHex.match(/.{2}/g);
      if (!bytes || bytes.length < 4) return hexAddr;
      const ip = bytes.reverse().map(b => parseInt(b, 16)).join('.');
      return `${ip}:${port}`;
    }
    return `[ipv6:${addrHex.slice(0, 8)}...]:${port}`;
  }
}
