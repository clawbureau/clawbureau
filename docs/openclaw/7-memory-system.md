Menu

## Memory System

Relevant source files
- [.npmrc](https://github.com/openclaw/openclaw/blob/bf6ec64f/.npmrc)
- [.prettierignore](https://github.com/openclaw/openclaw/blob/bf6ec64f/.prettierignore)
- [CHANGELOG.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/CHANGELOG.md)
- [README.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/README.md)
- [assets/avatar-placeholder.svg](https://github.com/openclaw/openclaw/blob/bf6ec64f/assets/avatar-placeholder.svg)
- [docs/cli/memory.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/cli/memory.md)
- [docs/concepts/memory.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/concepts/memory.md)
- [extensions/memory-core/package.json](https://github.com/openclaw/openclaw/blob/bf6ec64f/extensions/memory-core/package.json)
- [package.json](https://github.com/openclaw/openclaw/blob/bf6ec64f/package.json)
- [pnpm-lock.yaml](https://github.com/openclaw/openclaw/blob/bf6ec64f/pnpm-lock.yaml)
- [pnpm-workspace.yaml](https://github.com/openclaw/openclaw/blob/bf6ec64f/pnpm-workspace.yaml)
- [scripts/clawtributors-map.json](https://github.com/openclaw/openclaw/blob/bf6ec64f/scripts/clawtributors-map.json)
- [scripts/update-clawtributors.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/scripts/update-clawtributors.ts)
- [scripts/update-clawtributors.types.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/scripts/update-clawtributors.types.ts)
- [src/agents/memory-search.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/memory-search.test.ts)
- [src/agents/memory-search.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/memory-search.ts)
- [src/agents/pi-embedded-runner-extraparams.live.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-runner-extraparams.live.test.ts)
- [src/agents/pi-embedded-runner-extraparams.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-runner-extraparams.test.ts)
- [src/agents/tools/memory-tool.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/tools/memory-tool.ts)
- [src/auto-reply/reply/agent-runner.heartbeat-typing.runreplyagent-typing-heartbeat.retries-after-compaction-failure-by-resetting-session.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/auto-reply/reply/agent-runner.heartbeat-typing.runreplyagent-typing-heartbeat.retries-after-compaction-failure-by-resetting-session.test.ts)
- [src/cli/memory-cli.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/cli/memory-cli.test.ts)
- [src/cli/memory-cli.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/cli/memory-cli.ts)
- [src/config/schema.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/schema.ts)
- [src/config/types.tools.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/types.tools.ts)
- [src/config/zod-schema.agent-runtime.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/zod-schema.agent-runtime.ts)
- [src/index.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/index.ts)
- [src/memory/index.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/index.test.ts)
- [src/memory/internal.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/internal.test.ts)
- [src/memory/internal.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/internal.ts)
- [src/memory/manager-cache-key.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/manager-cache-key.ts)
- [src/memory/manager.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/manager.ts)
- [src/memory/sync-memory-files.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/sync-memory-files.ts)
- [ui/package.json](https://github.com/openclaw/openclaw/blob/bf6ec64f/ui/package.json)
- [ui/src/styles.css](https://github.com/openclaw/openclaw/blob/bf6ec64f/ui/src/styles.css)
- [ui/src/styles/layout.mobile.css](https://github.com/openclaw/openclaw/blob/bf6ec64f/ui/src/styles/layout.mobile.css)

The Memory System provides semantic search over workspace files and session transcripts using vector embeddings and hybrid retrieval. It indexes Markdown files from the agent workspace, generates embeddings via OpenAI/Gemini/local providers, stores them in SQLite with optional vector extensions, and exposes search capabilities to agents via the `memory_search` tool.

For workspace file layout and memory file conventions, see [Agent Workspace](https://deepwiki.com/openclaw/openclaw/5-agent-system). For configuration of embedding models and providers, see [Model Selection and Failover](https://deepwiki.com/openclaw/openclaw/5.4-model-selection-and-failover).

---

## Architecture Overview

```
Search PipelineStorage: SQLiteMemoryIndexManagerSourcesMemory Files
MEMORY.md, memory/*.mdSession Transcripts
~/.openclaw/agents/{agentId}/sessions/*.jsonlExtra Paths
config: extraPathslistMemoryFiles()
src/memory/internal.tschokidar FSWatcher
watch modeonSessionTranscriptUpdate
delta trackingchunkMarkdown()
token-based chunkingEmbeddingProvider
embedQuery/embedBatchBatch APIs
OpenAI/Geminichunks table
file_path, start_line, text, hashchunks_vec
vec_distance_cosine(embedding)chunks_fts
FTS5 full-text indexembedding_cache
hash → embedding blobmetadata
provider, model, dimssearchVector()
cosine similaritysearchKeyword()
BM25 via FTS5mergeHybridResults()
weighted scorememory_search tool
agent exposure
```

**Sources**: [src/memory/manager.ts 1-873](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/manager.ts#L1-L873) [src/memory/internal.ts 1-170](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/internal.ts#L1-L170) [src/agents/memory-search.ts 1-200](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/memory-search.ts#L1-L200)

---

## Core Components

### MemoryIndexManager Class

The `MemoryIndexManager` class ([src/memory/manager.ts 119-873](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/manager.ts#L119-L873)) is the central orchestrator. Key responsibilities:

| Responsibility | Implementation |
| --- | --- |
| **Database lifecycle** | Opens SQLite connection, loads sqlite-vec extension, ensures schema |
| **Provider management** | Creates `EmbeddingProvider` via `createEmbeddingProvider()`, handles fallback |
| **File monitoring** | Watches workspace files via `chokidar`, debounces changes |
| **Session tracking** | Subscribes to `onSessionTranscriptUpdate`, tracks deltas |
| **Indexing** | Chunks files, embeds text, writes to `chunks` / `chunks_vec` / `chunks_fts` |
| **Search** | Queries vector + FTS tables, merges results |
| **Caching** | Maintains `embedding_cache` table with LRU eviction |

Instance resolution is cached by agent ID and workspace directory via `MemoryIndexManager.get()` ([src/memory/manager.ts 176-206](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/manager.ts#L176-L206)).

**Sources**: [src/memory/manager.ts 119-250](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/manager.ts#L119-L250)

---

## Storage Schema

### SQLite Tables

```
1:11:1chunksTEXTfile_pathINTEGERstart_lineINTEGERend_lineTEXTtextTEXThashTEXTprovider_modelTEXTsourcechunks_vecBLOBembeddingINTEGERchunk_rowidFKchunks_ftsTEXTtextINTEGERchunk_rowidFKembedding_cacheTEXTprovider_modelTEXTtext_hashBLOBembeddingINTEGERtimestamp
```

**Table Details**:

- **`chunks`**: Core chunk storage with file path, line ranges, text content, hash, provider/model key, and source type (`"memory"` or `"sessions"`). Schema created by `ensureMemoryIndexSchema()` ([src/memory/memory-schema.ts 1-150](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/memory-schema.ts#L1-L150)).
- **`chunks_vec`**: Vector index using sqlite-vec extension. Stores `BLOB` embeddings with `vec_distance_cosine()` index. Only created when `store.vector.enabled = true` and extension loads successfully ([src/memory/manager.ts 470-520](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/manager.ts#L470-L520)).
- **`chunks_fts`**: FTS5 full-text index for BM25 keyword search. Uses `tokenize='porter unicode61'` and `content='chunks'` for external content ([src/memory/memory-schema.ts 60-80](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/memory-schema.ts#L60-L80)).
- **`embedding_cache`**: Deduplication cache keyed by `{provider}:{model}:{text_hash}`. Evicts oldest entries when `cache.maxEntries` is exceeded ([src/memory/manager.ts 650-700](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/manager.ts#L650-L700)).
- **`metadata`**: Key-value store for index metadata (`memory_index_meta_v1` holds model, dimensions, chunk config).

**Sources**: [src/memory/memory-schema.ts 1-150](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/memory-schema.ts#L1-L150) [src/memory/manager.ts 220-250](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/manager.ts#L220-L250) [src/memory/sqlite-vec.ts 1-50](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/sqlite-vec.ts#L1-L50)

---

## Embedding Providers

### Provider Selection

```
openaigeminilocalautolocal.modelPath existsOpenAI key availableGemini key availableno keysfailurefailurefailureopenai/gemini/localnonememorySearch.provider
config valueOpenAI Provider
text-embedding-3-smallGemini Provider
gemini-embedding-001Local Provider
node-llama-cppAuto SelectionMemory disabledmemorySearch.fallback
```

**Provider Implementations**:

| Provider | Module | Default Model | Authentication |
| --- | --- | --- | --- |
| **OpenAI** | [src/memory/embeddings-openai.ts 1-100](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/embeddings-openai.ts#L1-L100) | `text-embedding-3-small` | API key from auth profiles or `models.providers.openai.apiKey` |
| **Gemini** | [src/memory/embeddings-gemini.ts 1-80](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/embeddings-gemini.ts#L1-L80) | `gemini-embedding-001` | `GEMINI_API_KEY` or `models.providers.google.apiKey` |
| **Local** | [src/memory/embeddings-local.ts 1-120](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/embeddings-local.ts#L1-L120) | User-specified GGUF | Local file at `local.modelPath` |

Provider resolution happens in `createEmbeddingProvider()` ([src/memory/embeddings.ts 1-200](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/embeddings.ts#L1-L200)), which returns an `EmbeddingProvider` interface with `embedQuery()` and `embedBatch()` methods.

**Sources**: [src/memory/embeddings.ts 1-200](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/embeddings.ts#L1-L200) [src/agents/memory-search.ts 70-150](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/memory-search.ts#L70-L150)

---

## Indexing Pipeline

### File Discovery and Chunking

```
DB Writeembedding_cacheembedBatch()chunkMarkdown()buildFileEntry()listMemoryFiles()sync()DB Writeembedding_cacheembedBatch()chunkMarkdown()buildFileEntry()listMemoryFiles()sync()alt[File hash changed][File unchanged]loop[Each file]Scan workspace + extraPathsFile pathsRead file, compute hashMemoryFileEntrySplit by token limitsMemoryChunk[]Check cached embeddingsPartial hitsBatch uncached chunksFloat32Array[]Store new embeddingsINSERT chunks + chunks_vec + chunks_ftsSkip reindex
```

**Chunking Strategy**:

The `chunkMarkdown()` function ([src/memory/internal.ts 90-170](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/internal.ts#L90-L170)) splits Markdown by token budget:

1. Default: 400 tokens per chunk, 80 token overlap ([src/agents/memory-search.ts 76-77](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/memory-search.ts#L76-L77))
2. Respects paragraph boundaries (blank lines)
3. Never splits headings from their content
4. Tracks line numbers for snippet extraction

**Batch Embedding**:

When `remote.batch.enabled = true` (default), indexing uses batch APIs:

- **OpenAI Batch API**: `runOpenAiEmbeddingBatches()` ([src/memory/batch-openai.ts 1-300](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/batch-openai.ts#L1-L300)) creates batch jobs via `/v1/batches`, polls every `pollIntervalMs`, waits up to `timeoutMinutes`.
- **Gemini Batch API**: `runGeminiEmbeddingBatches()` ([src/memory/batch-gemini.ts 1-250](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/batch-gemini.ts#L1-L250)) uses similar flow with Gemini's batch endpoints.
- Concurrency controlled by `remote.batch.concurrency` (default: 2).

Failures are tracked with a failure counter. After `BATCH_FAILURE_LIMIT` (2) consecutive failures, batch mode disables and falls back to single embeddings ([src/memory/manager.ts 570-620](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/manager.ts#L570-L620)).

**Sources**: [src/memory/manager.ts 380-730](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/manager.ts#L380-L730) [src/memory/internal.ts 90-170](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/internal.ts#L90-L170) [src/memory/sync-memory-files.ts 1-100](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/sync-memory-files.ts#L1-L100)

---

## Session Transcript Indexing

### Delta Tracking

Session transcripts (`.jsonl` files) are incrementally indexed:

```
deltaBytes >= thresholddeltaMessages >= thresholdbelow thresholdsonSessionTranscriptUpdate
eventCheck session deltaRead new bytesParse JSONL linesExtract text from turnsEmbed textINSERT with source='sessions'Add to pending set
```

**Configuration**:

| Setting | Default | Description |
| --- | --- | --- |
| `sync.sessions.deltaBytes` | 100,000 | Minimum new bytes before reindex |
| `sync.sessions.deltaMessages` | 50 | Minimum new JSONL lines before reindex |
| `sources` | `["memory"]` | Must include `"sessions"` to enable |
| `experimental.sessionMemory` | `false` | Must be `true` to index sessions |

Delta state is tracked in `sessionDeltas` map ([src/memory/manager.ts 169-173](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/manager.ts#L169-L173)). When a transcript exceeds thresholds, `syncSessionFiles()` reads only the new tail ([src/memory/manager.ts 750-850](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/manager.ts#L750-L850)).

**Sources**: [src/memory/manager.ts 245-260](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/manager.ts#L245-L260) [src/memory/manager.ts 750-850](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/manager.ts#L750-L850) [src/sessions/transcript-events.ts 1-50](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/sessions/transcript-events.ts#L1-L50)

---

## Search Mechanics

```
search(query)searchVector()
cosine similaritysearchKeyword()
BM25 FTS5SELECT * FROM chunks_vec
ORDER BY vec_distance_cosine(embedding, ?)
LIMIT candidatesSELECT * FROM chunks_fts
WHERE chunks_fts MATCH buildFtsQuery(query)
ORDER BY bm25(chunks_fts)
LIMIT candidatesVector results
with distance scoresFTS results
with BM25 ranksmergeHybridResults()
weighted combinationApply minScore filterTake maxResultsMemorySearchResult[]
```

**Scoring Formula**:

```
final_score = (vector_score * vectorWeight) + (text_score * textWeight)
```

Where:

- `vector_score` = `1.0 - cosine_distance` (higher is better)
- `text_score` = `bm25RankToScore(rank)` ([src/memory/hybrid.ts 1-50](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/hybrid.ts#L1-L50))
- Default weights: `vectorWeight = 0.7`, `textWeight = 0.3` ([src/agents/memory-search.ts 84-85](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/memory-search.ts#L84-L85))

**Query Transformation**:

The `buildFtsQuery()` function ([src/memory/hybrid.ts 10-40](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/hybrid.ts#L10-L40)) converts natural language to FTS5 syntax:

- Tokenizes by whitespace
- Quotes each token to handle special chars
- Joins with `OR` for any-match semantics

**Candidate Pool**:

Both vector and keyword searches fetch `candidates = maxResults * candidateMultiplier` (default: 4x) entries before merging. This increases recall when weights favor one modality ([src/memory/manager.ts 280-308](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/manager.ts#L280-L308)).

**Sources**: [src/memory/manager.ts 262-381](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/manager.ts#L262-L381) [src/memory/manager-search.ts 1-200](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/manager-search.ts#L1-L200) [src/memory/hybrid.ts 1-120](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/hybrid.ts#L1-L120)

---

## Configuration Reference

### Key Settings

```
type MemorySearchConfig = {
  enabled?: boolean;                          // Default: true
  sources?: Array<"memory" | "sessions">;    // Default: ["memory"]
  extraPaths?: string[];                      // Additional directories/files
  provider?: "openai" | "gemini" | "local" | "auto"; // Default: "auto"
  fallback?: "openai" | "gemini" | "local" | "none"; // Default: "none"
  model?: string;                             // Provider-specific model ID
  
  remote?: {
    baseUrl?: string;                         // Custom endpoint
    apiKey?: string;                          // API key override
    headers?: Record<string, string>;         // Custom headers
    batch?: {
      enabled?: boolean;                      // Default: true
      wait?: boolean;                         // Default: true
      concurrency?: number;                   // Default: 2
      pollIntervalMs?: number;                // Default: 2000
      timeoutMinutes?: number;                // Default: 60
    };
  };
  
  local?: {
    modelPath?: string;                       // GGUF file path or hf: URI
    modelCacheDir?: string;                   // Download cache
  };
  
  store?: {
    path?: string;                            // SQLite file path
    vector?: {
      enabled?: boolean;                      // Default: true
      extensionPath?: string;                 // sqlite-vec override
    };
  };
  
  chunking?: {
    tokens?: number;                          // Default: 400
    overlap?: number;                         // Default: 80
  };
  
  sync?: {
    onSessionStart?: boolean;                 // Default: false
    onSearch?: boolean;                       // Default: false
    watch?: boolean;                          // Default: false
    watchDebounceMs?: number;                 // Default: 1500
    intervalMinutes?: number;                 // Default: 0 (off)
    sessions?: {
      deltaBytes?: number;                    // Default: 100000
      deltaMessages?: number;                 // Default: 50
    };
  };
  
  query?: {
    maxResults?: number;                      // Default: 6
    minScore?: number;                        // Default: 0.35
    hybrid?: {
      enabled?: boolean;                      // Default: true
      vectorWeight?: number;                  // Default: 0.7
      textWeight?: number;                    // Default: 0.3
      candidateMultiplier?: number;           // Default: 4
    };
  };
  
  cache?: {
    enabled?: boolean;                        // Default: true
    maxEntries?: number;                      // Default: undefined (no limit)
  };
};
```

Configuration resolution merges `agents.defaults.memorySearch` with per-agent `agents.list[].memorySearch` overrides via `resolveMemorySearchConfig()` ([src/agents/memory-search.ts 112-200](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/memory-search.ts#L112-L200)).

**Sources**: [src/config/types.tools.ts 224-324](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/types.tools.ts#L224-L324) [src/agents/memory-search.ts 1-200](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/memory-search.ts#L1-L200)

---

## CLI Commands

### openclaw memory status

Displays index status for all configured agents:

```
openclaw memory status
openclaw memory status --agent main
openclaw memory status --deep
openclaw memory status --deep --index --verbose
```

**Output includes**:

| Field | Description |
| --- | --- |
| **Agent** | Agent ID |
| **Workspace** | Workspace directory path |
| **Sources** | Active sources (`memory`, `sessions`) |
| **Provider** | Embedding provider (with fallback indicator) |
| **Model** | Embedding model ID |
| **Index** | SQLite database path |
| **Files** | Indexed file count |
| **Chunks** | Total chunk count |
| **Dirty** | Whether reindex is needed |
| **Vector** | sqlite-vec availability and dimensions |
| **FTS** | FTS5 availability |
| **Cache** | Embedding cache size |

With `--deep`, probes vector extension via `probeVectorAvailability()` (timeout: 30s). With `--index`, triggers full reindex if dirty.

**Sources**: [src/cli/memory-cli.ts 90-350](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/cli/memory-cli.ts#L90-L350)

---

### openclaw memory index

Forces reindexing:

```
openclaw memory index
openclaw memory index --agent main --verbose
```

With `--verbose`, emits:

- Provider and model selection
- Batch API activity (job IDs, status polling)
- Per-file progress with timing
- Final counts (files, chunks, embeddings)

**Sources**: [src/cli/memory-cli.ts 350-500](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/cli/memory-cli.ts#L350-L500)

---

### openclaw memory search

Performs semantic search from CLI:

```
openclaw memory search "deployment checklist"
openclaw memory search "rate limit handling" --agent main --json
```

Returns ranked snippets with paths, line ranges, scores, and source type. With `--json`, outputs structured `MemorySearchResult[]`.

**Sources**: [src/cli/memory-cli.ts 500-650](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/cli/memory-cli.ts#L500-L650)

---

## Agent Tool Integration

### memory\_search Tool

Agents invoke memory search via the `memory_search` tool ([src/agents/tools/memory-tool.ts 1-150](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/tools/memory-tool.ts#L1-L150)):

**Tool Schema**:

```
{
  name: "memory_search",
  description: "Search agent memory (workspace files + session history)",
  parameters: {
    query: string;           // Search query
    max_results?: number;    // Default: from config
    min_score?: number;      // Default: from config
  }
}
```

**Implementation**:

1. Resolve agent ID from session key ([src/agents/agent-scope.ts 50-100](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/agent-scope.ts#L50-L100))
2. Get or create `MemoryIndexManager` for agent
3. Call `manager.search(query, opts)`
4. Format results as JSON with paths, line ranges, snippets

The tool checks if memory search is enabled via `resolveMemorySearchConfig()`. If disabled, returns an error indicating memory is not configured ([src/agents/tools/memory-tool.ts 40-60](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/tools/memory-tool.ts#L40-L60)).

**Sources**: [src/agents/tools/memory-tool.ts 1-150](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/tools/memory-tool.ts#L1-L150) [src/agents/tool-registry.ts 200-250](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/tool-registry.ts#L200-L250)

---

### memory\_get Tool

The `memory_get` tool ([src/agents/tools/memory-tool.ts 150-250](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/tools/memory-tool.ts#L150-L250)) reads specific files:

**Tool Schema**:

```
{
  name: "memory_get",
  description: "Read a specific memory file by path",
  parameters: {
    path: string;           // Relative or absolute path
    from?: number;          // Optional start line (0-indexed)
    lines?: number;         // Optional line count
  }
}
```

**Security**:

- Resolves paths relative to workspace directory
- Rejects paths outside workspace (via `..` or absolute paths outside workspace)
- For `extraPaths`, allows read if path matches configured extra paths
- Returns error if path is not readable

**Sources**: [src/agents/tools/memory-tool.ts 150-250](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/tools/memory-tool.ts#L150-L250) [src/memory/manager.ts 394-450](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/manager.ts#L394-L450)

---

## Lifecycle and Caching

### Instance Lifecycle

```
MemoryIndexManager.get()Compute cache keyCache hitCache missOpen SQLiteLoad sqlite-vecCreate tableschokidar.watch()onSessionTranscriptUpdateINDEX_CACHE.set()Return managermanager.close()GetManagerCheckCacheExistingInstanceCreateNewOpenDBLoadExtensionEnsureSchemaStartWatcherSubscribeSessionStoreInCacheInUseClose
```

**Cache Key**:

Cache key includes agent ID, workspace directory, provider, model, chunking config, and header fingerprint. Computed by `computeMemoryManagerCacheKey()` ([src/memory/manager-cache-key.ts 1-50](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/manager-cache-key.ts#L1-L50)).

**Cleanup**:

`manager.close()` ([src/memory/manager.ts 860-873](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/manager.ts#L860-L873)):

1. Stops file watcher
2. Unsubscribes from session events
3. Clears interval timer
4. Closes SQLite connection
5. Removes from `INDEX_CACHE`

**Sources**: [src/memory/manager.ts 176-250](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/manager.ts#L176-L250) [src/memory/manager-cache-key.ts 1-50](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/manager-cache-key.ts#L1-L50) [src/memory/manager.ts 860-873](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/manager.ts#L860-L873)

---

## Sync Modes

### Sync Triggers

| Mode | Config Path | Behavior |
| --- | --- | --- |
| **Session start** | `sync.onSessionStart` | Sync before first agent turn |
| **On search** | `sync.onSearch` | Lazy sync when search is invoked |
| **File watch** | `sync.watch` | Debounced reindex on file changes |
| **Interval** | `sync.intervalMinutes` | Periodic full sync |
| **Session delta** | `sync.sessions.delta*` | Reindex transcripts after threshold |

Sync is skipped if already running (`this.syncing` lock, [src/memory/manager.ts 387-392](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/manager.ts#L387-L392)).

**Session Warmup**:

`warmSession(sessionKey)` ([src/memory/manager.ts 252-260](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/manager.ts#L252-L260)) ensures index is fresh before agent processing. Tracks warmed sessions to avoid duplicate syncs.

**Sources**: [src/memory/manager.ts 245-260](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/manager.ts#L245-L260) [src/memory/manager.ts 380-730](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/manager.ts#L380-L730)

---

## Extension Points

### Custom Embedding Providers

To add a new provider:

1. Implement `EmbeddingProvider` interface ([src/memory/embeddings.ts 50-80](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/embeddings.ts#L50-L80))
2. Add provider case to `createEmbeddingProvider()` ([src/memory/embeddings.ts 100-200](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/embeddings.ts#L100-L200))
3. Update `MemorySearchConfig.provider` union type ([src/config/types.tools.ts 237](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/types.tools.ts#L237-L237))

**Interface**:

```
interface EmbeddingProvider {
  id: string;
  model: string;
  embedQuery: (text: string) => Promise<number[]>;
  embedBatch: (texts: string[]) => Promise<number[][]>;
}
```

**Sources**: [src/memory/embeddings.ts 1-200](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/embeddings.ts#L1-L200)

---

### Plugin Integration

The memory system is exposed as a plugin slot ([docs/concepts/memory.md 11-13](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/concepts/memory.md#L11-L13)):

- Default plugin: `@openclaw/memory-core` ([extensions/memory-core/package.json 1-18](https://github.com/openclaw/openclaw/blob/bf6ec64f/extensions/memory-core/package.json#L1-L18))
- Disable with: `plugins.slots.memory = "none"`
- Plugin manifest provides `memory_search` and `memory_get` tools

Plugin registration happens in the plugin loader ([src/plugins/loader.ts 200-300](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/plugins/loader.ts#L200-L300)), which discovers `openclaw.extensions` in `package.json` and loads tool providers.

**Sources**: [extensions/memory-core/package.json 1-18](https://github.com/openclaw/openclaw/blob/bf6ec64f/extensions/memory-core/package.json#L1-L18) [extensions/memory-core/index.ts 1-50](https://github.com/openclaw/openclaw/blob/bf6ec64f/extensions/memory-core/index.ts#L1-L50) [src/plugins/loader.ts 200-300](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/plugins/loader.ts#L200-L300)

---

## Performance Considerations

### Batch API Efficiency

Batch APIs significantly reduce indexing time:

- **Single embeddings**: ~100-200ms per request, sequential
- **Batch API**: Submit 1000+ chunks in one job, parallel processing

Default concurrency (`remote.batch.concurrency = 2`) allows overlapping batch jobs. Polling interval (`pollIntervalMs = 2000`) balances latency vs. API load.

**Timeout Handling**:

| Operation | Timeout | Config Path |
| --- | --- | --- |
| Query embedding (remote) | 60s | `EMBEDDING_QUERY_TIMEOUT_REMOTE_MS` |
| Query embedding (local) | 5min | `EMBEDDING_QUERY_TIMEOUT_LOCAL_MS` |
| Batch indexing (remote) | 2min | `EMBEDDING_BATCH_TIMEOUT_REMOTE_MS` |
| Batch indexing (local) | 10min | `EMBEDDING_BATCH_TIMEOUT_LOCAL_MS` |
| Vector extension load | 30s | `VECTOR_LOAD_TIMEOUT_MS` |

**Sources**: [src/memory/manager.ts 106-111](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/manager.ts#L106-L111) [src/memory/batch-openai.ts 1-300](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/batch-openai.ts#L1-L300) [src/memory/batch-gemini.ts 1-250](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/batch-gemini.ts#L1-L250)

---

### Embedding Cache

The `embedding_cache` table deduplicates embeddings by text hash ([src/memory/manager.ts 650-700](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/manager.ts#L650-L700)):

- Cache key: `{provider}:{model}:{sha256(text)}`
- Eviction: LRU when `cache.maxEntries` exceeded
- Persistence: Survives index rebuilds if model unchanged

Cache hit rate is reported in `memory status --deep` output.

**Sources**: [src/memory/manager.ts 650-700](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/manager.ts#L650-L700) [src/memory/manager.ts 280-308](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/manager.ts#L280-L308)

---

### Fallback Chain

```
yesnoPrimary provider failsfallback != 'none'?Switch to fallback providerStore fallbackFrom + fallbackReasonReturn fallback provider
```

Fallback reason is exposed in `manager.status()` ([src/memory/manager.ts 750-800](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/manager.ts#L750-L800)) for debugging.

**Batch Failure Handling**:

After `BATCH_FAILURE_LIMIT` (2) consecutive batch failures:

1. Disable batch mode (`batchFailureCount >= 2`)
2. Fall back to single `embedQuery()` calls
3. Store failure reason in `batchFailureLastError`

**Sources**: [src/memory/embeddings.ts 100-200](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/embeddings.ts#L100-L200) [src/memory/manager.ts 570-620](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/manager.ts#L570-L620)

---

## Debugging

### Verbose Logging

Enable with `--verbose` flag or `setVerbose(true)`:

```
openclaw memory index --verbose
```

Logs include:

- Provider selection and fallback
- Batch job creation and polling
- Per-file indexing with timing
- Chunk counts and embedding cache hits
- SQL query execution (when diagnostics enabled)

**Sources**: [src/cli/memory-cli.ts 1-650](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/cli/memory-cli.ts#L1-L650) [src/logging/subsystem.ts 1-50](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/logging/subsystem.ts#L1-L50)

---

### Diagnostic Commands

```
# Check index status
openclaw memory status --deep

# Force reindex
openclaw memory index --agent main

# Test search
openclaw memory search "keyword" --json

# Verify vector extension
openclaw doctor  # includes sqlite-vec probe
```

**Sources**: [src/cli/memory-cli.ts 1-650](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/cli/memory-cli.ts#L1-L650) [src/commands/doctor.ts 500-600](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/commands/doctor.ts#L500-L600)

<svg id="mermaid-fu8dstus3vp" width="100%" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 2412 512" style="max-width: 512px;" role="graphics-document document" aria-roledescription="error"><g></g><g><path class="error-icon" d="m411.313,123.313c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32-9.375,9.375-20.688-20.688c-12.484-12.5-32.766-12.5-45.25,0l-16,16c-1.261,1.261-2.304,2.648-3.31,4.051-21.739-8.561-45.324-13.426-70.065-13.426-105.867,0-192,86.133-192,192s86.133,192 192,192 192-86.133 192-192c0-24.741-4.864-48.327-13.426-70.065 1.402-1.007 2.79-2.049 4.051-3.31l16-16c12.5-12.492 12.5-32.758 0-45.25l-20.688-20.688 9.375-9.375 32.001-31.999zm-219.313,100.687c-52.938,0-96,43.063-96,96 0,8.836-7.164,16-16,16s-16-7.164-16-16c0-70.578 57.422-128 128-128 8.836,0 16,7.164 16,16s-7.164,16-16,16z"></path><path class="error-icon" d="m459.02,148.98c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l16,16c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16.001-16z"></path><path class="error-icon" d="m340.395,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16-16c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l15.999,16z"></path><path class="error-icon" d="m400,64c8.844,0 16-7.164 16-16v-32c0-8.836-7.156-16-16-16-8.844,0-16,7.164-16,16v32c0,8.836 7.156,16 16,16z"></path><path class="error-icon" d="m496,96.586h-32c-8.844,0-16,7.164-16,16 0,8.836 7.156,16 16,16h32c8.844,0 16-7.164 16-16 0-8.836-7.156-16-16-16z"></path><path class="error-icon" d="m436.98,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688l32-32c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32c-6.251,6.25-6.251,16.375-0.001,22.625z"></path><text class="error-text" x="1440" y="250" font-size="150px" style="text-anchor: middle;">Syntax error in text</text> <text class="error-text" x="1250" y="400" font-size="100px" style="text-anchor: middle;">mermaid version 11.12.2</text></g></svg> <svg id="mermaid-7khuxtjp8f" width="100%" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 2412 512" style="max-width: 512px;" role="graphics-document document" aria-roledescription="error"><g></g><g><path class="error-icon" d="m411.313,123.313c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32-9.375,9.375-20.688-20.688c-12.484-12.5-32.766-12.5-45.25,0l-16,16c-1.261,1.261-2.304,2.648-3.31,4.051-21.739-8.561-45.324-13.426-70.065-13.426-105.867,0-192,86.133-192,192s86.133,192 192,192 192-86.133 192-192c0-24.741-4.864-48.327-13.426-70.065 1.402-1.007 2.79-2.049 4.051-3.31l16-16c12.5-12.492 12.5-32.758 0-45.25l-20.688-20.688 9.375-9.375 32.001-31.999zm-219.313,100.687c-52.938,0-96,43.063-96,96 0,8.836-7.164,16-16,16s-16-7.164-16-16c0-70.578 57.422-128 128-128 8.836,0 16,7.164 16,16s-7.164,16-16,16z"></path><path class="error-icon" d="m459.02,148.98c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l16,16c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16.001-16z"></path><path class="error-icon" d="m340.395,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16-16c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l15.999,16z"></path><path class="error-icon" d="m400,64c8.844,0 16-7.164 16-16v-32c0-8.836-7.156-16-16-16-8.844,0-16,7.164-16,16v32c0,8.836 7.156,16 16,16z"></path><path class="error-icon" d="m496,96.586h-32c-8.844,0-16,7.164-16,16 0,8.836 7.156,16 16,16h32c8.844,0 16-7.164 16-16 0-8.836-7.156-16-16-16z"></path><path class="error-icon" d="m436.98,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688l32-32c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32c-6.251,6.25-6.251,16.375-0.001,22.625z"></path><text class="error-text" x="1440" y="250" font-size="150px" style="text-anchor: middle;">Syntax error in text</text> <text class="error-text" x="1250" y="400" font-size="100px" style="text-anchor: middle;">mermaid version 11.12.2</text></g></svg>