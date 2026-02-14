/**
 * InterposeState — Graph Attribution Oracle from C interposition events.
 *
 * Ingests the JSONL trace produced by libclawsig_interpose.c and builds:
 * - Perfect process genealogy with harness + role classification
 * - Per-agent activity attribution (LLM calls, file mutations, network)
 * - Server socket port registry (bind events)
 * - DNS hostname->IP cache
 * - Environment audit trail (SHA-256 hashes of API keys)
 * - Credential leak alerts
 * - LLM recv() sampling data
 * - Hierarchical genealogy tree with roll-up of mundane tools
 */

import { readFile } from 'node:fs/promises';

export type AgentRole = 'root_agent' | 'agent' | 'mcp_server' | 'browser' | 'shell' | 'utility' | 'process' | 'unknown';

export interface EnvAuditEvent { key: string; value_sha256: string; pid: number; ts: string; seq: number; }
export interface CredLeakEvent { fd: number; pattern: string; pid: number; ts: string; seq: number; }
export interface RecvLlmEvent { fd: number; bytes: number; sse: number; pid: number; ts: string; ns: number; seq: number; }

export interface AgentNode {
  pid: number;
  parentPid: number;
  harness: string | null;
  role: AgentRole;
  path: string;
  argv: string[];
  children: number[];
  ts: string;
  seq: number;

  stats: {
    llm_calls: number;
    files_opened: number;
    files_modified: number;
    network_connections: number;
  };

  /** @internal */
  _llmDomains: Set<string>;
  /** @internal */
  _filesOpened: Set<string>;
  /** @internal */
  _filesModified: Set<string>;
  /** @internal */
  _networkConns: Set<string>;
  /** @internal */
  _boundPorts: Set<number>;
}

export interface GenealogyReceiptNode {
  pid: number;
  role: string;
  harness: string | null;
  command: string;
  activity: {
    llm_calls: number;
    llm_domains: string[];
    files_opened: number;
    files_modified: number;
    network_connections: number;
    bound_ports: number[];
  };
  children: GenealogyReceiptNode[];
}

const LLM_DOMAIN_PATTERN = /openai|anthropic|googleapis|cohere|mistral|deepseek|groq|together|x\.ai|openrouter|github\.com/;

export class InterposeState {
  public pidTree = new Set<number>();
  public boundPorts = new Set<number>();
  public dnsCache = new Map<string, Set<string>>();

  public envAudits: EnvAuditEvent[] = [];
  public credLeaks: CredLeakEvent[] = [];
  public recvSamples: RecvLlmEvent[] = [];

  public agentNodes = new Map<number, AgentNode>();
  public totalEvents = 0;
  public maxSeq = 0;

  constructor(public rootPid: number) {
    this.pidTree.add(rootPid);
    this.getOrInitNode(rootPid, 0);
  }

  private getOrInitNode(pid: number, parentPid: number = 0): AgentNode {
    let node = this.agentNodes.get(pid);
    if (!node) {
      node = {
        pid, parentPid, harness: null, role: 'unknown',
        path: '', argv: [], children: [], ts: '', seq: 0,
        stats: { llm_calls: 0, files_opened: 0, files_modified: 0, network_connections: 0 },
        _llmDomains: new Set(), _filesOpened: new Set(),
        _filesModified: new Set(), _networkConns: new Set(), _boundPorts: new Set(),
      };
      this.agentNodes.set(pid, node);
      if (parentPid > 0) {
        const parent = this.agentNodes.get(parentPid);
        if (parent && !parent.children.includes(pid)) parent.children.push(pid);
      }
    }
    return node;
  }

  async ingestTrace(traceFile: string): Promise<void> {
    let content: string;
    try { content = await readFile(traceFile, 'utf-8'); } catch { return; }

    const events = content.split('\n')
      .filter(l => l.trim())
      .map(l => { try { return JSON.parse(l); } catch { return null; } })
      .filter((e): e is Record<string, unknown> => e !== null && e.layer === 'interpose')
      .sort((a, b) => ((a.seq as number) ?? 0) - ((b.seq as number) ?? 0));

    this.totalEvents = events.length;
    const envSeen = new Set<string>();

    for (const ev of events) {
      const seq = (ev.seq as number) ?? 0;
      if (seq > this.maxSeq) this.maxSeq = seq;
      const syscall = ev.syscall as string;
      const pid = ev.pid as number;

      // agent_init: self-identification of root process
      if (syscall === 'agent_init' && pid === this.rootPid) {
        const node = this.getOrInitNode(pid);
        node.role = 'root_agent';
        if (ev.harness && ev.harness !== 'unknown') node.harness = ev.harness as string;
        continue;
      }

      // 1. Process Genealogy (Graph Building)
      if (['fork', 'vfork', 'posix_spawn', 'posix_spawnp'].includes(syscall)) {
        const childPid = ev.child_pid as number;
        if (childPid > 0 && this.pidTree.has(pid)) {
          this.pidTree.add(childPid);
          const childNode = this.getOrInitNode(childPid, pid);
          if (ev.role) childNode.role = ev.role as AgentRole;
          if (ev.harness) childNode.harness = ev.harness as string;
          if (ev.path) childNode.path = ev.path as string;
          if (ev.argv) childNode.argv = ev.argv as string[];
          if (ev.ts) childNode.ts = ev.ts as string;
          childNode.seq = seq;
        }
      }

      // execve updates existing node (same PID replaces binary)
      if (syscall === 'execve' && this.pidTree.has(pid)) {
        const node = this.getOrInitNode(pid);
        if (ev.role && node.role === 'unknown') node.role = ev.role as AgentRole;
        if (ev.harness) node.harness = ev.harness as string;
        if (ev.path) node.path = ev.path as string;
        if (ev.argv) node.argv = ev.argv as string[];
        node.seq = seq;
      }

      // 2. DNS Resolution Cache
      if (syscall === 'getaddrinfo' && Array.isArray(ev.ips)) {
        for (const ip of ev.ips as string[]) {
          if (!this.dnsCache.has(ip)) this.dnsCache.set(ip, new Set());
          this.dnsCache.get(ip)!.add(ev.hostname as string);
        }
      }

      // 3. Per-PID Attributed Events
      if (this.pidTree.has(pid)) {
        const node = this.getOrInitNode(pid);

        // TLS SNI → LLM attribution
        if (syscall === 'tls_sni') {
          const host = ev.hostname as string;
          if (LLM_DOMAIN_PATTERN.test(host)) {
            node.stats.llm_calls++;
            node._llmDomains.add(host);
          }
          node._networkConns.add(`${ev.addr}:${ev.port}`);
          node.stats.network_connections = node._networkConns.size;
        }

        // File open with is_write classification
        if (['open', 'openat', 'open64', 'openat64'].includes(syscall)) {
          const path = ev.path as string;
          if (ev.rc !== -1 && path &&
              !path.startsWith('/dev/') && !path.startsWith('/tmp/') &&
              !path.startsWith('/proc/') && !path.startsWith('/private/var/')) {
            node._filesOpened.add(path);
            node.stats.files_opened = node._filesOpened.size;
            if (ev.is_write === 1) {
              node._filesModified.add(path);
              node.stats.files_modified = node._filesModified.size;
            }
          }
        }

        // Network connections
        if (syscall === 'connect') {
          node._networkConns.add(`${ev.addr}:${ev.port}`);
          node.stats.network_connections = node._networkConns.size;
        }

        // Server socket binding
        if (syscall === 'bind' && ev.rc === 0 && (ev.port as number) > 0) {
          const port = ev.port as number;
          this.boundPorts.add(port);
          node._boundPorts.add(port);
        }

        // Environment auditing (deduplicated)
        if (syscall === 'env_audit') {
          const key = ev.key as string, hash = ev.value_sha256 as string;
          const dedupKey = `${key}:${hash}`;
          if (!envSeen.has(dedupKey)) {
            envSeen.add(dedupKey);
            this.envAudits.push({ key, value_sha256: hash, pid, ts: ev.ts as string, seq });
          }
        }

        // Credential leak alerts
        if (syscall === 'cred_leak') {
          this.credLeaks.push({
            fd: ev.fd as number, pattern: ev.pattern as string,
            pid, ts: ev.ts as string, seq,
          });
        }

        // LLM recv samples
        if (syscall === 'recv_llm') {
          this.recvSamples.push({
            fd: ev.fd as number, bytes: ev.bytes as number,
            sse: ev.sse as number, pid, ts: ev.ts as string,
            ns: ev.ns as number, seq,
          });
        }
      }
    }
  }

  /**
   * Build hierarchical genealogy tree with roll-up.
   * Significant nodes (agents, MCP servers, browsers, PIDs with LLM calls)
   * get their own entry. Mundane tools (cat, grep, bash, git) roll up
   * into their parent agent's activity stats.
   */
  public getGenealogyTree(): GenealogyReceiptNode | null {
    const buildExportNode = (
      node: AgentNode,
      targetAggregator: AgentNode,
    ): GenealogyReceiptNode | null => {
      const isSignificant =
        node.pid === this.rootPid ||
        node.role === 'agent' || node.role === 'root_agent' ||
        node.role === 'mcp_server' ||
        node.role === 'browser' ||
        node.stats.llm_calls > 0;

      const currentTarget = isSignificant ? node : targetAggregator;

      // Roll up data of mundane tools into the parent aggregator
      if (!isSignificant && currentTarget !== node) {
        node._llmDomains.forEach(d => currentTarget._llmDomains.add(d));
        node._filesOpened.forEach(f => currentTarget._filesOpened.add(f));
        node._filesModified.forEach(f => currentTarget._filesModified.add(f));
        node._networkConns.forEach(c => currentTarget._networkConns.add(c));
        node._boundPorts.forEach(p => currentTarget._boundPorts.add(p));
        currentTarget.stats.llm_calls += node.stats.llm_calls;
      }

      const exportChildren: GenealogyReceiptNode[] = [];
      for (const childPid of node.children) {
        const childNode = this.agentNodes.get(childPid);
        if (childNode) {
          const childExport = buildExportNode(childNode, currentTarget);
          if (childExport) exportChildren.push(childExport);
        }
      }

      if (isSignificant) {
        let command = node.argv.length > 0 ? node.argv.join(' ') : node.path;
        if (command.length > 256) command = command.substring(0, 253) + '...';

        return {
          pid: node.pid,
          role: node.role,
          harness: node.harness,
          command,
          activity: {
            llm_calls: node.stats.llm_calls,
            llm_domains: Array.from(node._llmDomains),
            files_opened: node._filesOpened.size,
            files_modified: node._filesModified.size,
            network_connections: node._networkConns.size,
            bound_ports: Array.from(node._boundPorts),
          },
          children: exportChildren,
        };
      }
      return null;
    };

    const rootNode = this.agentNodes.get(this.rootPid);
    if (!rootNode) return null;
    return buildExportNode(rootNode, rootNode);
  }

  isAgentPid(pid: number): boolean { return this.pidTree.has(pid); }
  isAgentServerPort(port: number): boolean { return this.boundPorts.has(port); }
  getHostnames(ip: string): string[] { return Array.from(this.dnsCache.get(ip) ?? []); }

  getSummary() {
    const tree = this.getGenealogyTree();
    const harnesses: Array<{ pid: number; harness: string; role: string }> = [];
    for (const [, node] of this.agentNodes) {
      if (node.harness) {
        harnesses.push({ pid: node.pid, harness: node.harness, role: node.role });
      }
    }

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
      genealogy_tree: tree ?? undefined,
    };
  }
}
