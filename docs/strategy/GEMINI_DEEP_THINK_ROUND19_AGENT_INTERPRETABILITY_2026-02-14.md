# Gemini Deep Think Round 19: Deep Agent Interpretability (2026-02-14)

> **Context:** Full multi-agent genealogy with harness identification, per-agent activity attribution, MCP server detection.
> **Input:** 1273-line C library, InterposeState oracle, 20+ known harness signatures.
> **Decision:** Replace flat detect_harness() with identify_process() returning (harness, role). Add agent_init self-identification. Roll up utility PIDs into parent agents. Build genealogy receipt for proof bundle.

## Key Design Decisions

### 1. identify_process() replaces detect_harness()
Returns `proc_ident_t { harness, role }` instead of just a harness string. Roles: agent, mcp_server, browser, shell, utility, unknown. Enables tree pruning — shells and utilities roll up into their parent agent.

### 2. Deep Environment Scanning
Scans envp for framework markers: OPENCLAW_, AIDER_, CREWAI_, AUTOGEN_, LANGCHAIN_. Catches Python frameworks that don't have distinctive binary names.

### 3. MCP Server Detection from argv
Scans first 15 argv entries for @modelcontextprotocol/, mcp-server, mcp_server. Sub-classifies: mcp_browser, mcp_git, mcp_filesystem, mcp_sqlite, mcp_postgres, mcp_custom.

### 4. is_write Boolean on open Events
Every open/openat now emits is_write:0 or is_write:1 based on O_WRONLY, O_RDWR, O_CREAT, O_APPEND, O_TRUNC. TypeScript oracle knows which files were mutated vs read.

### 5. agent_init Event
Constructor emits agent_init with self-identification of the root process. Captures the harness/role of the process being wrapped before any child spawning.

### 6. Genealogy Tree with Roll-up
The InterposeState.getGenealogyTree() method builds a hierarchical GenealogyReceiptNode tree. "Significant" nodes (agents, MCP servers, browsers, any PID with LLM calls) get their own tree entry. Mundane tools (cat, grep, git, bash) roll up into their parent agent's activity stats.

### 7. Per-Agent Activity Attribution
Each AgentNode tracks: llm_calls (from tls_sni matching LLM domains), files_opened, files_modified (from is_write), network_connections (from connect/tls_sni), bound_ports (from bind).

## Execution Mandate
1. Replace libclawsig_interpose.c with new version (identify_process, agent_init, is_write, role field)
2. Replace interpose-state.ts with graph attribution oracle (AgentNode with stats, getGenealogyTree with roll-up)
3. Wire genealogy receipt + security receipts into wrap.ts proof bundle
4. Compile on macOS ARM64, verify zero crashes
5. Test with multi-process agent scenario
