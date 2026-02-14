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
  allowedHosts?: string[];
}

export class NetSentinel {
  private timer?: ReturnType<typeof setInterval>;
  private knownConnections = new Set<string>();
  private events: NetEvent[] = [];
  private targetPids = new Set<number>();
  private running = false;
  private pollIntervalMs: number;
  private isMac = process.platform === 'darwin';

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

  getEvents(): NetEvent[] {
    return [...this.events];
  }

  getSuspiciousEvents(): NetEvent[] {
    return this.events.filter(e => e.classification === 'suspicious');
  }

  get eventCount(): number {
    return this.events.length;
  }

  get suspiciousCount(): number {
    return this.getSuspiciousEvents().length;
  }

  private async poll(): Promise<void> {
    const pids = await this.expandPidTree();
    if (pids.length === 0) return;

    if (this.isMac) {
      await this.pollLsof(pids);
    } else {
      await this.pollProcNetTcp(pids);
    }
  }

  private async expandPidTree(): Promise<number[]> {
    const allPids = new Set<number>(this.targetPids);
    if (this.isMac) {
      let currentLevel = Array.from(this.targetPids);
      while (currentLevel.length > 0) {
        const nextLevel: number[] = [];
        for (const pid of currentLevel) {
          try {
            const { stdout } = await execFileAsync('pgrep', ['-P', String(pid)], { timeout: 1000 });
            const childPids = stdout.trim().split('\n').map(p => parseInt(p, 10)).filter(p => !isNaN(p));
            for (const childPid of childPids) {
              if (!allPids.has(childPid)) {
                allPids.add(childPid);
                nextLevel.push(childPid);
              }
            }
          } catch {
            // Process exited or no children
          }
        }
        currentLevel = nextLevel;
      }
    } else {
      try {
        const procDirs = readdirSync('/proc');
        const ppidMap = new Map<number, number[]>();
        for (const dir of procDirs) {
          const pid = parseInt(dir, 10);
          if (isNaN(pid)) continue;
          try {
            const statContent = readFileSync(`/proc/${pid}/stat`, 'utf8');
            const match = statContent.match(/^\d+\s+\([^)]+\)\s+[A-Z]\s+(\d+)/);
            if (match?.[1]) {
              const ppid = parseInt(match[1], 10);
              const children = ppidMap.get(ppid) || [];
              children.push(pid);
              ppidMap.set(ppid, children);
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
              queue.push(child);
            }
          }
        }
      } catch { /* fallthrough */ }
    }

    return Array.from(allPids);
  }

  private async pollLsof(pids: number[]): Promise<void> {
    try {
      const args = ['-i', '-n', '-P', '-F', 'pcPnT', '-p', pids.join(',')];
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

          if (i + 1 < lines.length && lines[i + 1]?.startsWith('TST=')) {
            state = lines[i + 1]!.slice(4);
            i++;
          }

          if (!address.includes('->')) continue;
          if (state !== 'ESTABLISHED' && state !== 'SYN_SENT' && state !== 'UNKNOWN') continue;

          const parts = address.split('->');
          const local = parts[0] ?? '';
          const remote = parts[1] ?? '';
          if (!remote) continue;

          const connKey = `${currentPid}:${currentProtocol}:${local}:${remote}`;
          if (this.knownConnections.has(connKey)) continue;
          this.knownConnections.add(connKey);

          const lastColon = remote.lastIndexOf(':');
          const ip = remote.slice(0, lastColon);
          const port = parseInt(remote.slice(lastColon + 1) || '0', 10);

          let cleanIp = ip;
          if (cleanIp.startsWith('[') && cleanIp.endsWith(']')) {
            cleanIp = cleanIp.slice(1, -1);
          }

          const classification = await classifyConnection(
            cleanIp, port, currentCmd, currentPid, pids.includes(currentPid),
          );
          if (classification === 'local' || classification === 'system_noise') continue;

          this.events.push({
            layer: 'net',
            ts,
            protocol: currentProtocol,
            localAddress: local,
            remoteAddress: remote,
            state,
            pid: currentPid,
            processName: currentCmd,
            classification,
          });
        }
      }
    } catch {
      // lsof errors can be ignored
    }
  }

  private async pollProcNetTcp(pids: number[]): Promise<void> {
    const inodeToPid = new Map<string, number>();

    for (const pid of pids) {
      try {
        const fdPath = `/proc/${pid}/fd`;
        if (existsSync(fdPath)) {
          const fds = readdirSync(fdPath);
          for (const fd of fds) {
            try {
              const link = readFileSync(`${fdPath}/${fd}`, 'utf8');
              const match = link.match(/^socket:\[(\d+)\]$/);
              if (match?.[1]) {
                inodeToPid.set(match[1], pid);
              }
            } catch { /* skip */ }
          }
        }
      } catch { /* skip */ }
    }

    const ts = new Date().toISOString();
    for (const file of ['/proc/net/tcp', '/proc/net/tcp6']) {
      if (!existsSync(file)) continue;
      try {
        const content = readFileSync(file, 'utf8');
        const lines = content.split('\n');
        for (let i = 1; i < lines.length; i++) {
          const parts = lines[i]?.trim().split(/\s+/);
          if (!parts || parts.length < 10) continue;

          const remotePart = parts[2];
          const stateCode = parts[3];
          const inode = parts[9];

          if (!inode || !remotePart || !stateCode) continue;
          if (stateCode !== '01' && stateCode !== '02') continue;

          const pid = inodeToPid.get(inode);
          if (!pid) continue;

          const remote = this.parseHexAddress(remotePart);
          const connKey = `${file.includes('tcp6') ? 'tcp6' : 'tcp'}:${remote}`;
          if (this.knownConnections.has(connKey)) continue;
          this.knownConnections.add(connKey);

          const lastColon = remote.lastIndexOf(':');
          const ip = remote.slice(0, lastColon);
          const portStr = remote.slice(lastColon + 1);
          if (!ip || !portStr) continue;
          const port = parseInt(portStr, 10);

          const classification = await classifyConnection(ip, port, null, pid, true);
          if (classification === 'local' || classification === 'system_noise') continue;

          this.events.push({
            layer: 'net',
            ts,
            protocol: file.includes('tcp6') ? 'tcp6' : 'tcp',
            localAddress: '',
            remoteAddress: remote,
            state: stateCode === '01' ? 'ESTABLISHED' : 'SYN_SENT',
            pid,
            processName: null,
            classification,
          });
        }
      } catch { /* skip */ }
    }
  }

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
