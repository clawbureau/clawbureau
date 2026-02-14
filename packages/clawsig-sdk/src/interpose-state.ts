/**
 * InterposeState — Ground truth oracle from C interposition events.
 *
 * Ingests the JSONL trace produced by libclawsig_interpose.c and builds:
 * - Perfect process genealogy (fork/posix_spawn child PIDs)
 * - Server socket port registry (bind events)
 * - DNS hostname→IP cache (getaddrinfo with ALL resolved IPs)
 * - Environment audit trail (SHA-256 hashes of API keys)
 * - Credential leak alerts
 * - LLM recv() sampling data (SSE chunks, timing)
 *
 * This data is used by classify-connection.ts to eliminate false positives
 * that lsof-based polling cannot resolve (pgrep races, unknown server ports).
 */

import { readFile } from 'node:fs/promises';

export interface EnvAuditEvent {
  key: string;
  value_sha256: string;
  pid: number;
  ts: string;
  seq: number;
}

export interface CredLeakEvent {
  fd: number;
  pattern: string;
  pid: number;
  ts: string;
  seq: number;
}

export interface RecvLlmEvent {
  fd: number;
  bytes: number;
  sse: number;
  pid: number;
  ts: string;
  ns: number;
  seq: number;
}

export interface AgentNode {
  pid: number;
  parentPid: number;
  harness: string | null;
  path: string;
  argv: string[];
  children: number[];
  ts: string;
  seq: number;
}

export class InterposeState {
  /** PIDs known to be in the agent's process tree (ground truth from fork/spawn) */
  public pidTree = new Set<number>();

  /** Ports the agent has bound to (server sockets — DevTools, MCP, etc.) */
  public boundPorts = new Set<number>();

  /** IP → Set<hostname> from getaddrinfo (all resolved addresses) */
  public dnsCache = new Map<string, Set<string>>();

  /** Deduplicated env audit events (key+hash pairs) */
  public envAudits: EnvAuditEvent[] = [];

  /** Credential leak DLP alerts */
  public credLeaks: CredLeakEvent[] = [];

  /** LLM recv samples for kinematic fingerprinting */
  public recvSamples: RecvLlmEvent[] = [];

  /** Agent genealogy: PID → agent node with harness classification */
  public agentNodes = new Map<number, AgentNode>();

  /** Total events ingested */
  public totalEvents = 0;

  /** Max causal sequence number seen */
  public maxSeq = 0;

  constructor(public rootPid: number) {
    this.pidTree.add(rootPid);
  }

  /**
   * Ingest the full JSONL trace file. Events are sorted by causal sequence
   * number for correct happens-before ordering.
   */
  async ingestTrace(traceFile: string): Promise<void> {
    let content: string;
    try {
      content = await readFile(traceFile, 'utf-8');
    } catch {
      return; // File doesn't exist yet
    }

    const events = content
      .split('\n')
      .filter(l => l.trim())
      .map(l => { try { return JSON.parse(l); } catch { return null; } })
      .filter((e): e is Record<string, unknown> => e !== null && e.layer === 'interpose')
      .sort((a, b) => ((a.seq as number) ?? 0) - ((b.seq as number) ?? 0));

    this.totalEvents = events.length;

    // Dedup for env audits (same key+hash = same credential)
    const envSeen = new Set<string>();

    for (const ev of events) {
      const seq = (ev.seq as number) ?? 0;
      if (seq > this.maxSeq) this.maxSeq = seq;
      const syscall = ev.syscall as string;

      // 1. Process Genealogy — perfect PID tree from kernel events
      if (syscall === 'fork' || syscall === 'vfork' ||
          syscall === 'posix_spawn' || syscall === 'posix_spawnp') {
        const childPid = ev.child_pid as number;
        const parentPid = ev.pid as number;
        if (childPid > 0 && this.pidTree.has(parentPid)) {
          this.pidTree.add(childPid);

          // Build agent node for harness-detected processes
          const harness = (ev.harness as string) || null;
          const path = (ev.path as string) || '';
          const argv = (ev.argv as string[]) || [];

          const node: AgentNode = {
            pid: childPid,
            parentPid,
            harness,
            path,
            argv: Array.isArray(argv) ? argv : [],
            children: [],
            ts: ev.ts as string,
            seq,
          };
          this.agentNodes.set(childPid, node);

          // Link parent → child
          const parentNode = this.agentNodes.get(parentPid);
          if (parentNode) parentNode.children.push(childPid);
        }
      }

      // Also catch execve events for harness detection on the same PID
      if (syscall === 'execve' && ev.harness) {
        const pid = ev.pid as number;
        if (this.pidTree.has(pid)) {
          const existing = this.agentNodes.get(pid);
          if (existing) {
            existing.harness = ev.harness as string;
            existing.path = (ev.path as string) || existing.path;
          } else {
            this.agentNodes.set(pid, {
              pid,
              parentPid: 0,
              harness: ev.harness as string,
              path: (ev.path as string) || '',
              argv: (ev.argv as string[]) || [],
              children: [],
              ts: ev.ts as string,
              seq,
            });
          }
        }
      }

      // 2. Server Socket Registry — ports the agent binds to
      if (syscall === 'bind' && ev.rc === 0) {
        const port = ev.port as number;
        const pid = ev.pid as number;
        if (port > 0 && this.pidTree.has(pid)) {
          this.boundPorts.add(port);
        }
      }

      // 3. DNS Cache — hostname→IP from getaddrinfo (all IPs)
      if (syscall === 'getaddrinfo' && Array.isArray(ev.ips)) {
        const hostname = ev.hostname as string;
        for (const ip of ev.ips as string[]) {
          if (!this.dnsCache.has(ip)) this.dnsCache.set(ip, new Set());
          this.dnsCache.get(ip)!.add(hostname);
        }
      }

      // 4. Environment Auditing — deduplicated
      if (syscall === 'env_audit') {
        const key = ev.key as string;
        const hash = ev.value_sha256 as string;
        const dedupKey = `${key}:${hash}`;
        if (!envSeen.has(dedupKey)) {
          envSeen.add(dedupKey);
          this.envAudits.push({
            key,
            value_sha256: hash,
            pid: ev.pid as number,
            ts: ev.ts as string,
            seq,
          });
        }
      }

      // 5. Credential Leak DLP
      if (syscall === 'cred_leak') {
        this.credLeaks.push({
          fd: ev.fd as number,
          pattern: ev.pattern as string,
          pid: ev.pid as number,
          ts: ev.ts as string,
          seq,
        });
      }

      // 6. LLM recv() Samples
      if (syscall === 'recv_llm') {
        this.recvSamples.push({
          fd: ev.fd as number,
          bytes: ev.bytes as number,
          sse: ev.sse as number,
          pid: ev.pid as number,
          ts: ev.ts as string,
          ns: ev.ns as number,
          seq,
        });
      }
    }
  }

  /** Check if a PID is in the agent's process tree (ground truth) */
  isAgentPid(pid: number): boolean {
    return this.pidTree.has(pid);
  }

  /** Check if a port is bound by the agent (server socket) */
  isAgentServerPort(port: number): boolean {
    return this.boundPorts.has(port);
  }

  /** Look up hostname for an IP via DNS cache */
  getHostnames(ip: string): string[] {
    return Array.from(this.dnsCache.get(ip) ?? []);
  }

  /** Get all detected agent harnesses in the process tree */
  getDetectedHarnesses(): Array<{ pid: number; harness: string; path: string }> {
    const result: Array<{ pid: number; harness: string; path: string }> = [];
    for (const [, node] of this.agentNodes) {
      if (node.harness) {
        result.push({ pid: node.pid, harness: node.harness, path: node.path });
      }
    }
    return result;
  }

  /** Build agent delegation chain: root → sub-agent → sub-sub-agent */
  getAgentGenealogy(): Array<{
    pid: number;
    parentPid: number;
    harness: string | null;
    depth: number;
  }> {
    const result: Array<{
      pid: number; parentPid: number; harness: string | null; depth: number;
    }> = [];

    const visit = (pid: number, depth: number) => {
      const node = this.agentNodes.get(pid);
      if (node) {
        result.push({
          pid: node.pid,
          parentPid: node.parentPid,
          harness: node.harness,
          depth,
        });
        for (const childPid of node.children) {
          visit(childPid, depth + 1);
        }
      }
    };

    // Start from root
    visit(this.rootPid, 0);
    // Also visit any orphan agent nodes not reachable from root
    for (const [pid, node] of this.agentNodes) {
      if (!result.some(r => r.pid === pid) && node.harness) {
        visit(pid, 0);
      }
    }

    return result;
  }

  /** Summary for bundle metadata */
  getSummary() {
    const harnesses = this.getDetectedHarnesses();
    return {
      pid_tree_size: this.pidTree.size,
      bound_ports: Array.from(this.boundPorts),
      dns_entries: this.dnsCache.size,
      env_audits: this.envAudits.length,
      cred_leaks: this.credLeaks.length,
      recv_samples: this.recvSamples.length,
      total_events: this.totalEvents,
      max_seq: this.maxSeq,
      detected_harnesses: harnesses.length > 0 ? harnesses : undefined,
      agent_genealogy: this.getAgentGenealogy(),
    };
  }
}
