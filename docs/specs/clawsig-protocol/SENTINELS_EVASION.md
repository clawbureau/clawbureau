# Causal Sieve Sentinels: Evasion Analysis and Coverage

The Clawsig Sentinels operate in user-space without root, eBPF, or containers.
This makes them highly deployable but introduces fundamental evasion vectors.

## Layer Coverage

### 1. Sentinel Shell (trap DEBUG via BASH_ENV)
- **Coverage**: ~85% of shell commands (bash -c, exec, execSync with shell:true)
- **Evasion Vectors**:
  - child_process.spawn() with no shell (bypasses BASH_ENV entirely)
  - Alternative shells: /bin/zsh, python -c, node -e
  - Trap unbinding: `trap - DEBUG` within the session
  - `env -i bash` strips BASH_ENV
  - Direct syscalls from compiled binaries

### 2. Filesystem Sentinel (fs.watch recursive)
- **Coverage**: ~90% of persistent file modifications in watched dirs
- **Evasion Vectors**:
  - Writes to /tmp, /dev/shm, or other dirs outside the workspace
  - memfd_create (Linux) for in-memory execution without VFS
  - TOCTOU races: create + delete in <5ms may miss stat()
  - Does NOT catch file reads (macOS FSEvents doesn't report reads)

### 3. Network Sentinel (lsof/procfs polling)
- **Coverage**: ~75% of outbound TCP connections
- **Evasion Vectors**:
  - Polling gap (500ms): fast connections open/exfil/close between ticks
  - UDP/ICMP: DNS tunneling, ICMP payloads
  - Double-fork daemon escaping the PID tree
  - IPv6 connections may be partially visible

### 4. Causal Sieve (HTTP stream parsing)
- **Coverage**: ~95% of LLM API tool calls
- **Evasion Vectors**:
  - Non-streaming custom protocols
  - Agent using a local LLM (no HTTP traffic)
  - Encrypted WebSocket channels

## Composite Coverage

With all layers active:

| Observable Class | macOS | Linux | Notes |
|---|---|---|---|
| LLM tool calls | 95% | 95% | HTTP stream parsing |
| Bash commands | 85% | 85% | BASH_ENV + trap DEBUG |
| File writes | 90% | 90% | fs.watch recursive |
| File reads | 0% | 50% | inotify IN_ACCESS (Linux only) |
| Network connections | 70% | 80% | lsof (macOS), procfs (Linux) |
| Subprocess spawning | 85% | 85% | Shell sentinel captures most |
| Env manipulation | 85% | 85% | Shell sentinel pattern matching |

**Aggregate: ~85% of agent behavior on macOS, ~88% on Linux.**

## Honest Assessment

The 15% blind spot consists of:
1. Compiled binaries making direct syscalls (no shell involved)
2. Fast network connections that complete between polling ticks
3. File reads (invisible without kernel-level hooks on macOS)
4. Operations in /tmp or other unwatched directories
5. Agents that actively disable observation (trap - DEBUG)

For the target use case (securing AI agent PRs from prompt injection),
the remaining 15% is acceptable because:
- The PR gate (GitHub App) catches unattested file mutations
- Sophisticated active evasion requires pre-existing malicious intent
  that goes beyond typical prompt injection capabilities
- The 85% coverage creates a "paper trail" that makes post-incident
  forensics viable even when real-time blocking isn't possible

Phase 4 (CEA-US-010) adds kernel-level eBPF probes for sys_execve,
sys_openat, and tcp_v4_connect, closing the gap to ~98%.
