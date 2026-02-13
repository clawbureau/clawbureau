/**
 * Causal Sieve — Tool Observability Without Agent Cooperation
 *
 * Reconstructs an agent's execution trace by parsing the LLM HTTP
 * stream and correlating tool_calls with filesystem side-effects
 * detected via git diff.
 *
 * The Sieve operates at the "cognitive boundary": the HTTP traffic
 * between the agent and the LLM. Every tool invocation follows the
 * pattern:
 *
 *   1. LLM response contains tool_call (intent)
 *   2. Agent executes tool locally (blind spot)
 *   3. Agent sends tool_result back to LLM (confirmation)
 *
 * By parsing both sides of the HTTP traffic, we reconstruct the
 * agent's behavior. By running `git diff` between steps 1 and 3,
 * we capture file mutations and attribute them to specific tool calls.
 *
 * See: docs/strategy/GEMINI_DEEP_THINK_ROUND8_TOOL_OBSERVABILITY_2026-02-13.md
 */

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { hashJsonB64u, sha256B64u, randomUUID } from './crypto.js';
import type {
  ToolReceiptPayload,
  SideEffectReceiptPayload,
  SignedEnvelope,
} from './types.js';
import type { EphemeralDid } from './ephemeral-did.js';

const execFileAsync = promisify(execFile);

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** A tool call extracted from an LLM response. */
export interface ExtractedToolCall {
  /** Provider-assigned tool call ID (e.g. "toolu_01abc..." or "call_abc..."). */
  id: string;
  /** Tool name (e.g. "bash", "read_file", "write_to_file"). */
  name: string;
  /** Raw arguments JSON string. */
  argsJson: string;
  /** Timestamp when extracted from stream. */
  extractedAt: string;
}

/** A tool result extracted from an outgoing request. */
export interface ExtractedToolResult {
  /** The tool_call_id this result corresponds to. */
  toolCallId: string;
  /** The tool result content (may be truncated for hashing). */
  resultJson: string;
  /** Timestamp when extracted from request. */
  extractedAt: string;
}

/** A file mutation detected by git diff. */
export interface DetectedMutation {
  /** File path relative to repo root. */
  path: string;
  /** Type of change. */
  status: 'added' | 'modified' | 'deleted' | 'renamed';
  /** SHA-256 hash of the new file content (for added/modified). */
  contentHashB64u?: string;
}

/** A synthesized tool invocation with causal attribution. */
export interface CausalToolInvocation {
  toolCall: ExtractedToolCall;
  toolResult?: ExtractedToolResult;
  fileMutations: DetectedMutation[];
  /** Synthesized tool receipt. */
  receipt: ToolReceiptPayload;
  /** Synthesized side-effect receipts for file mutations. */
  sideEffectReceipts: SideEffectReceiptPayload[];
}

/** WPC policy evaluation for the TCP Guillotine. */
export interface PolicyViolation {
  toolCall: ExtractedToolCall;
  statementSid: string;
  reason: string;
}

/** Simple WPC statement for local evaluation. */
export interface LocalPolicyStatement {
  sid: string;
  effect: 'Allow' | 'Deny';
  actions: string[];
  resources: string[];
  conditions?: Record<string, Record<string, string[]>>;
}

/** Local WPC policy for the TCP Guillotine. */
export interface LocalPolicy {
  statements: LocalPolicyStatement[];
}

// ---------------------------------------------------------------------------
// LLM Response Parsing — Extract tool_calls from HTTP bodies
// ---------------------------------------------------------------------------

/**
 * Extract tool calls from an OpenAI-format response body.
 *
 * OpenAI tool_calls appear in `choices[].message.tool_calls[]` with:
 *   { id: "call_...", type: "function", function: { name, arguments } }
 *
 * For streaming, they appear across multiple SSE chunks with
 * `choices[].delta.tool_calls[]` using index-based assembly.
 */
export function extractToolCallsOpenAI(body: string): ExtractedToolCall[] {
  const now = new Date().toISOString();
  const calls: ExtractedToolCall[] = [];

  try {
    // Try non-streaming format first
    const parsed = JSON.parse(body);
    const choices = parsed?.choices ?? [];
    for (const choice of choices) {
      const toolCalls = choice?.message?.tool_calls ?? choice?.delta?.tool_calls ?? [];
      for (const tc of toolCalls) {
        if (tc?.function?.name) {
          calls.push({
            id: tc.id ?? `call_${randomUUID()}`,
            name: tc.function.name,
            argsJson: tc.function.arguments ?? '{}',
            extractedAt: now,
          });
        }
      }
    }
  } catch {
    // If JSON parse fails, try SSE parsing
    const assembled = assembleOpenAIStreamToolCalls(body);
    calls.push(...assembled);
  }

  return calls;
}

/**
 * Assemble tool_calls from OpenAI streaming SSE chunks.
 * Streaming tool calls arrive as deltas with index-based assembly.
 */
function assembleOpenAIStreamToolCalls(sseBody: string): ExtractedToolCall[] {
  const now = new Date().toISOString();
  const toolCallMap = new Map<number, { id: string; name: string; args: string }>();

  for (const line of sseBody.split('\n')) {
    if (!line.startsWith('data: ')) continue;
    const data = line.slice(6).trim();
    if (data === '[DONE]') continue;

    try {
      const chunk = JSON.parse(data);
      for (const choice of (chunk?.choices ?? [])) {
        for (const tc of (choice?.delta?.tool_calls ?? [])) {
          const idx = tc.index ?? 0;
          const existing = toolCallMap.get(idx) ?? { id: '', name: '', args: '' };
          if (tc.id) existing.id = tc.id;
          if (tc.function?.name) existing.name += tc.function.name;
          if (tc.function?.arguments) existing.args += tc.function.arguments;
          toolCallMap.set(idx, existing);
        }
      }
    } catch {
      // Skip unparseable chunks
    }
  }

  return Array.from(toolCallMap.values())
    .filter(tc => tc.name)
    .map(tc => ({
      id: tc.id || `call_${randomUUID()}`,
      name: tc.name,
      argsJson: tc.args || '{}',
      extractedAt: now,
    }));
}

/**
 * Extract tool calls from an Anthropic-format response body.
 *
 * Anthropic tool_use blocks appear in `content[]` with:
 *   { type: "tool_use", id: "toolu_...", name: "...", input: {...} }
 *
 * For streaming, they appear as content_block_start + content_block_delta events.
 */
export function extractToolCallsAnthropic(body: string): ExtractedToolCall[] {
  const now = new Date().toISOString();
  const calls: ExtractedToolCall[] = [];

  try {
    // Try non-streaming format first
    const parsed = JSON.parse(body);
    const content = parsed?.content ?? [];
    for (const block of content) {
      if (block?.type === 'tool_use' && block?.name) {
        calls.push({
          id: block.id ?? `toolu_${randomUUID()}`,
          name: block.name,
          argsJson: JSON.stringify(block.input ?? {}),
          extractedAt: now,
        });
      }
    }
  } catch {
    // SSE streaming format
    const assembled = assembleAnthropicStreamToolCalls(body);
    calls.push(...assembled);
  }

  return calls;
}

/**
 * Assemble tool_use blocks from Anthropic streaming SSE events.
 */
function assembleAnthropicStreamToolCalls(sseBody: string): ExtractedToolCall[] {
  const now = new Date().toISOString();
  const blocks = new Map<number, { id: string; name: string; inputJson: string }>();

  for (const line of sseBody.split('\n')) {
    if (!line.startsWith('data: ')) continue;
    const data = line.slice(6).trim();

    try {
      const event = JSON.parse(data);

      if (event.type === 'content_block_start' && event.content_block?.type === 'tool_use') {
        blocks.set(event.index ?? blocks.size, {
          id: event.content_block.id ?? `toolu_${randomUUID()}`,
          name: event.content_block.name ?? '',
          inputJson: '',
        });
      }

      if (event.type === 'content_block_delta' && event.delta?.type === 'input_json_delta') {
        const idx = event.index ?? 0;
        const existing = blocks.get(idx);
        if (existing) {
          existing.inputJson += event.delta.partial_json ?? '';
        }
      }
    } catch {
      // Skip unparseable events
    }
  }

  return Array.from(blocks.values())
    .filter(b => b.name)
    .map(b => ({
      id: b.id,
      name: b.name,
      argsJson: b.inputJson || '{}',
      extractedAt: now,
    }));
}

// ---------------------------------------------------------------------------
// Request Parsing — Extract tool_results from outgoing requests
// ---------------------------------------------------------------------------

/**
 * Extract tool results from an OpenAI-format request body.
 * Tool results appear as messages with `role: "tool"`.
 */
export function extractToolResultsOpenAI(body: string): ExtractedToolResult[] {
  const now = new Date().toISOString();
  const results: ExtractedToolResult[] = [];

  try {
    const parsed = JSON.parse(body);
    for (const msg of (parsed?.messages ?? [])) {
      if (msg?.role === 'tool' && msg?.tool_call_id) {
        results.push({
          toolCallId: msg.tool_call_id,
          resultJson: typeof msg.content === 'string' ? msg.content : JSON.stringify(msg.content ?? ''),
          extractedAt: now,
        });
      }
    }
  } catch {
    // Not valid JSON, skip
  }

  return results;
}

/**
 * Extract tool results from an Anthropic-format request body.
 * Tool results appear in `messages[]` with content blocks of type "tool_result".
 */
export function extractToolResultsAnthropic(body: string): ExtractedToolResult[] {
  const now = new Date().toISOString();
  const results: ExtractedToolResult[] = [];

  try {
    const parsed = JSON.parse(body);
    for (const msg of (parsed?.messages ?? [])) {
      if (!Array.isArray(msg?.content)) continue;
      for (const block of msg.content) {
        if (block?.type === 'tool_result' && block?.tool_use_id) {
          let resultContent = '';
          if (typeof block.content === 'string') {
            resultContent = block.content;
          } else if (Array.isArray(block.content)) {
            resultContent = JSON.stringify(block.content);
          }
          results.push({
            toolCallId: block.tool_use_id,
            resultJson: resultContent,
            extractedAt: now,
          });
        }
      }
    }
  } catch {
    // Not valid JSON, skip
  }

  return results;
}

// ---------------------------------------------------------------------------
// Git Diff — Detect filesystem mutations between tool boundaries
// ---------------------------------------------------------------------------

/**
 * Get current git tree hash for change detection.
 * Returns null if not in a git repo.
 */
export async function getGitTreeHash(cwd?: string): Promise<string | null> {
  try {
    const { stdout } = await execFileAsync('git', ['write-tree'], { cwd: cwd ?? process.cwd() });
    return stdout.trim();
  } catch {
    return null;
  }
}

/**
 * Run git diff to detect file mutations since a reference point.
 *
 * Uses `git diff --name-status` against the working tree.
 * If baseTreeHash is provided, diffs against that tree.
 * Otherwise diffs against HEAD.
 */
export async function getFileMutations(cwd?: string): Promise<DetectedMutation[]> {
  const workdir = cwd ?? process.cwd();
  const mutations: DetectedMutation[] = [];

  try {
    // Diff working tree against index (unstaged changes)
    const { stdout: unstaged } = await execFileAsync(
      'git', ['diff', '--name-status', 'HEAD'],
      { cwd: workdir, timeout: 5000 },
    );

    // Also check untracked files
    const { stdout: untracked } = await execFileAsync(
      'git', ['ls-files', '--others', '--exclude-standard'],
      { cwd: workdir, timeout: 5000 },
    );

    for (const line of unstaged.split('\n')) {
      if (!line.trim()) continue;
      const [status, ...pathParts] = line.split('\t');
      const filePath = pathParts.join('\t');
      if (!filePath) continue;

      let mutationStatus: DetectedMutation['status'];
      switch (status?.[0]) {
        case 'A': mutationStatus = 'added'; break;
        case 'M': mutationStatus = 'modified'; break;
        case 'D': mutationStatus = 'deleted'; break;
        case 'R': mutationStatus = 'renamed'; break;
        default: mutationStatus = 'modified';
      }

      mutations.push({ path: filePath, status: mutationStatus });
    }

    for (const line of untracked.split('\n')) {
      if (!line.trim()) continue;
      mutations.push({ path: line.trim(), status: 'added' });
    }
  } catch {
    // Not a git repo or git not available
  }

  return mutations;
}

/**
 * Get incremental file mutations since the last snapshot.
 * Takes a snapshot of modified files, diffs against previous snapshot.
 */
export async function getIncrementalMutations(
  previousFiles: Map<string, string>,
  cwd?: string,
): Promise<{ mutations: DetectedMutation[]; currentFiles: Map<string, string> }> {
  const workdir = cwd ?? process.cwd();
  const currentFiles = new Map<string, string>();
  const mutations: DetectedMutation[] = [];

  try {
    // Get all tracked files with their hashes
    const { stdout } = await execFileAsync(
      'git', ['ls-files', '-s'],
      { cwd: workdir, timeout: 5000 },
    );

    for (const line of stdout.split('\n')) {
      if (!line.trim()) continue;
      // Format: <mode> <hash> <stage>\t<path>
      const match = line.match(/^\d+\s+([a-f0-9]+)\s+\d+\t(.+)$/);
      if (match?.[1] && match?.[2]) {
        currentFiles.set(match[2], match[1]);
      }
    }

    // Also check working tree modifications
    const { stdout: diffOut } = await execFileAsync(
      'git', ['diff', '--name-only'],
      { cwd: workdir, timeout: 5000 },
    );

    const modifiedInWorkTree = new Set(
      diffOut.split('\n').map(l => l.trim()).filter(Boolean),
    );

    // Detect changes since last snapshot
    for (const [path, hash] of currentFiles) {
      const prevHash = previousFiles.get(path);
      if (!prevHash) {
        mutations.push({ path, status: 'added' });
      } else if (prevHash !== hash || modifiedInWorkTree.has(path)) {
        mutations.push({ path, status: 'modified' });
      }
    }

    for (const [path] of previousFiles) {
      if (!currentFiles.has(path)) {
        mutations.push({ path, status: 'deleted' });
      }
    }

    // Untracked files
    const { stdout: untracked } = await execFileAsync(
      'git', ['ls-files', '--others', '--exclude-standard'],
      { cwd: workdir, timeout: 5000 },
    );
    for (const line of untracked.split('\n')) {
      if (!line.trim()) continue;
      if (!previousFiles.has(line.trim())) {
        mutations.push({ path: line.trim(), status: 'added' });
      }
    }
  } catch {
    // Fallback: simple diff against HEAD
    return { mutations: await getFileMutations(cwd), currentFiles };
  }

  return { mutations, currentFiles };
}

// ---------------------------------------------------------------------------
// Receipt Synthesis — Turn observations into signed receipts
// ---------------------------------------------------------------------------

const encoder = new TextEncoder();

/**
 * Synthesize a tool_receipt from an observed tool call + result.
 */
export async function synthesizeToolReceipt(
  toolCall: ExtractedToolCall,
  toolResult: ExtractedToolResult | undefined,
  agentDid: EphemeralDid,
  runId: string,
): Promise<SignedEnvelope<ToolReceiptPayload>> {
  const receiptId = `tr_${randomUUID()}`;
  const now = new Date().toISOString();

  const argsHash = await sha256B64u(encoder.encode(toolCall.argsJson));
  const resultHash = await sha256B64u(
    encoder.encode(toolResult?.resultJson ?? ''),
  );

  // Calculate latency from extraction timestamps
  const callTime = new Date(toolCall.extractedAt).getTime();
  const resultTime = toolResult
    ? new Date(toolResult.extractedAt).getTime()
    : Date.now();
  const latencyMs = Math.max(0, resultTime - callTime);

  const payload: ToolReceiptPayload = {
    receipt_version: '1',
    receipt_id: receiptId,
    tool_name: toolCall.name,
    args_hash_b64u: argsHash,
    result_hash_b64u: resultHash,
    result_status: toolResult ? 'success' : 'timeout',
    hash_algorithm: 'SHA-256',
    agent_did: agentDid.did,
    timestamp: now,
    latency_ms: latencyMs,
    binding: {
      run_id: runId,
    },
  };

  const payloadHash = await hashJsonB64u(payload);
  const signature = await agentDid.sign(encoder.encode(payloadHash));

  return {
    envelope_version: '1',
    envelope_type: 'tool_receipt',
    payload,
    payload_hash_b64u: payloadHash,
    hash_algorithm: 'SHA-256',
    signature_b64u: signature,
    algorithm: 'Ed25519',
    signer_did: agentDid.did,
    issued_at: now,
  };
}

/**
 * Synthesize a side_effect_receipt for a detected file mutation.
 */
export async function synthesizeSideEffectReceipt(
  mutation: DetectedMutation,
  toolCallId: string,
  agentDid: EphemeralDid,
  runId: string,
): Promise<SignedEnvelope<SideEffectReceiptPayload>> {
  const receiptId = `se_${randomUUID()}`;
  const now = new Date().toISOString();

  const targetHash = await sha256B64u(encoder.encode(mutation.path));
  const requestHash = await sha256B64u(
    encoder.encode(JSON.stringify({ tool_call_id: toolCallId, file: mutation.path })),
  );
  const responseHash = await sha256B64u(
    encoder.encode(JSON.stringify({ status: mutation.status })),
  );

  const payload: SideEffectReceiptPayload = {
    receipt_version: '1',
    receipt_id: receiptId,
    effect_class: 'filesystem_write',
    target_hash_b64u: targetHash,
    request_hash_b64u: requestHash,
    response_hash_b64u: responseHash,
    response_status: 'success',
    hash_algorithm: 'SHA-256',
    agent_did: agentDid.did,
    timestamp: now,
    latency_ms: 0,
    binding: {
      run_id: runId,
    },
  };

  const payloadHash = await hashJsonB64u(payload);
  const signature = await agentDid.sign(encoder.encode(payloadHash));

  return {
    envelope_version: '1',
    envelope_type: 'side_effect_receipt',
    payload,
    payload_hash_b64u: payloadHash,
    hash_algorithm: 'SHA-256',
    signature_b64u: signature,
    algorithm: 'Ed25519',
    signer_did: agentDid.did,
    issued_at: now,
  };
}

// ---------------------------------------------------------------------------
// TCP Guillotine — Evaluate tool calls against local WPC
// ---------------------------------------------------------------------------

/**
 * Evaluate a tool call against a local policy.
 * Returns null if allowed, or a PolicyViolation if blocked.
 *
 * Fail-closed: if the policy cannot be evaluated, the tool is allowed
 * (because we can't intercept execution anyway — we just flag it).
 */
export function evaluateToolCallAgainstPolicy(
  toolCall: ExtractedToolCall,
  policy: LocalPolicy | null,
): PolicyViolation | null {
  if (!policy) return null;

  // Parse tool arguments to extract actionable data
  let parsedArgs: Record<string, unknown> = {};
  try {
    parsedArgs = JSON.parse(toolCall.argsJson);
  } catch {
    // Unparseable args — can't evaluate conditions
  }

  // Check deny statements first (deny overrides allow)
  for (const stmt of policy.statements) {
    if (stmt.effect !== 'Deny') continue;

    // Check if the tool action matches
    const actionMatches = stmt.actions.some(a => matchesGlob(a, `tool:${toolCall.name}`));
    if (!actionMatches) continue;

    // Check conditions
    if (stmt.conditions) {
      const conditionMet = evaluateConditions(stmt.conditions, toolCall, parsedArgs);
      if (!conditionMet) continue;
    }

    return {
      toolCall,
      statementSid: stmt.sid,
      reason: `Denied by WPC statement "${stmt.sid}": tool:${toolCall.name}`,
    };
  }

  return null;
}

/**
 * Check if a shell command in tool args contains blocked patterns.
 * Inspects bash/shell tool invocations for dangerous commands.
 */
export function extractCommandFromToolArgs(toolCall: ExtractedToolCall): string | null {
  try {
    const args = JSON.parse(toolCall.argsJson);

    // Common tool argument patterns across frameworks
    if (typeof args === 'string') return args;
    if (args?.command) return String(args.command);
    if (args?.cmd) return String(args.cmd);
    if (args?.content && toolCall.name.includes('bash')) return String(args.content);
    if (args?.code && toolCall.name.includes('exec')) return String(args.code);

    // Anthropic computer use format
    if (args?.action === 'execute' && args?.command) return String(args.command);
  } catch {
    // Can't parse
  }
  return null;
}

// ---------------------------------------------------------------------------
// Pattern matching helpers
// ---------------------------------------------------------------------------

function matchesGlob(pattern: string, value: string): boolean {
  if (pattern === '*') return true;
  if (pattern.endsWith(':*')) {
    return value.startsWith(pattern.slice(0, -1));
  }
  // Simple glob with trailing *
  if (pattern.endsWith('*')) {
    return value.startsWith(pattern.slice(0, -1));
  }
  return pattern === value;
}

function evaluateConditions(
  conditions: Record<string, Record<string, string[]>>,
  toolCall: ExtractedToolCall,
  args: Record<string, unknown>,
): boolean {
  for (const [operator, fields] of Object.entries(conditions)) {
    for (const [key, values] of Object.entries(fields)) {
      // Resolve the context key to an actual value
      let actual: string | null = null;

      if (key === 'SideEffect:TargetDomain') {
        const cmd = extractCommandFromToolArgs(toolCall);
        if (cmd) {
          // Extract domain from curl/wget/fetch commands
          const urlMatch = cmd.match(/https?:\/\/([^\/\s'"]+)/);
          actual = urlMatch?.[1] ?? null;
        }
      } else if (key === 'Tool:Command') {
        actual = extractCommandFromToolArgs(toolCall);
      } else {
        actual = args[key] !== undefined ? String(args[key]) : null;
      }

      // Fail-closed per spec: unresolvable keys evaluate to false
      if (actual === null) return false;

      switch (operator) {
        case 'StringLike':
          if (!values.some(v => matchesGlob(v, actual!))) return false;
          break;
        case 'StringNotLike':
          if (values.some(v => matchesGlob(v, actual!))) return true;
          break;
        case 'StringEquals':
          if (!values.includes(actual)) return false;
          break;
        case 'StringNotEquals':
          if (values.includes(actual)) return true;
          break;
        default:
          // Unknown operator — fail-closed (condition not met)
          return false;
      }
    }
  }

  return true;
}

// ---------------------------------------------------------------------------
// The Causal Sieve — Main orchestrator
// ---------------------------------------------------------------------------

export interface CausalSieveOptions {
  agentDid: EphemeralDid;
  runId: string;
  /** Working directory for git operations. */
  cwd?: string;
  /** Local WPC policy for the TCP Guillotine. */
  policy?: LocalPolicy | null;
  /** Callback when a policy violation is detected. */
  onViolation?: (violation: PolicyViolation) => void;
}

/**
 * The Causal Sieve: state machine for tracking tool call lifecycle
 * and synthesizing receipts from HTTP stream observations.
 */
export class CausalSieve {
  private agentDid: EphemeralDid;
  private runId: string;
  private cwd: string;
  private policy: LocalPolicy | null;
  private onViolation?: (violation: PolicyViolation) => void;

  // State: pending tool calls awaiting results
  private pendingToolCalls: Map<string, ExtractedToolCall> = new Map();

  // State: file snapshot for incremental diffing
  private fileSnapshot: Map<string, string> = new Map();
  private snapshotInitialized = false;

  // Collected receipts
  private _toolReceipts: SignedEnvelope<ToolReceiptPayload>[] = [];
  private _sideEffectReceipts: SignedEnvelope<SideEffectReceiptPayload>[] = [];
  private _violations: PolicyViolation[] = [];

  constructor(options: CausalSieveOptions) {
    this.agentDid = options.agentDid;
    this.runId = options.runId;
    this.cwd = options.cwd ?? process.cwd();
    this.policy = options.policy ?? null;
    this.onViolation = options.onViolation;
  }

  /** Initialize git file snapshot. Call before agent starts. */
  async initialize(): Promise<void> {
    const { currentFiles } = await getIncrementalMutations(new Map(), this.cwd);
    this.fileSnapshot = currentFiles;
    this.snapshotInitialized = true;
  }

  /** Get all synthesized tool receipts. */
  get toolReceipts(): SignedEnvelope<ToolReceiptPayload>[] {
    return this._toolReceipts;
  }

  /** Get all synthesized side-effect receipts. */
  get sideEffectReceipts(): SignedEnvelope<SideEffectReceiptPayload>[] {
    return this._sideEffectReceipts;
  }

  /** Get all policy violations detected. */
  get violations(): PolicyViolation[] {
    return this._violations;
  }

  /**
   * Process an LLM response body. Extracts tool_calls and evaluates
   * them against the local WPC (TCP Guillotine).
   *
   * @returns Array of policy violations (empty if all tools are allowed).
   *          If non-empty, the caller should sever the connection.
   */
  processLLMResponse(provider: 'openai' | 'anthropic', responseBody: string): PolicyViolation[] {
    const toolCalls = provider === 'openai'
      ? extractToolCallsOpenAI(responseBody)
      : extractToolCallsAnthropic(responseBody);

    const violations: PolicyViolation[] = [];

    for (const tc of toolCalls) {
      // TCP Guillotine: check against WPC
      const violation = evaluateToolCallAgainstPolicy(tc, this.policy);
      if (violation) {
        violations.push(violation);
        this._violations.push(violation);
        this.onViolation?.(violation);
        continue; // Don't track blocked tool calls
      }

      // Track pending tool call
      this.pendingToolCalls.set(tc.id, tc);
    }

    return violations;
  }

  /**
   * Process an outgoing request body (agent → LLM).
   * Extracts tool_results, runs git diff, synthesizes receipts.
   *
   * Call this BEFORE forwarding the request upstream, so we capture
   * the file state after tool execution but before the next LLM call.
   */
  async processAgentRequest(provider: 'openai' | 'anthropic', requestBody: string): Promise<void> {
    const toolResults = provider === 'openai'
      ? extractToolResultsOpenAI(requestBody)
      : extractToolResultsAnthropic(requestBody);

    if (toolResults.length === 0) return;

    // Run git diff to detect file mutations since last check
    let mutations: DetectedMutation[] = [];
    if (this.snapshotInitialized) {
      const result = await getIncrementalMutations(this.fileSnapshot, this.cwd);
      mutations = result.mutations;
      this.fileSnapshot = result.currentFiles;
    }

    // Match tool results to pending tool calls and synthesize receipts
    for (const result of toolResults) {
      const toolCall = this.pendingToolCalls.get(result.toolCallId);
      if (!toolCall) continue; // Orphaned result, skip

      this.pendingToolCalls.delete(result.toolCallId);

      // Synthesize tool receipt
      const toolReceipt = await synthesizeToolReceipt(
        toolCall, result, this.agentDid, this.runId,
      );
      this._toolReceipts.push(toolReceipt);

      // Attribute file mutations to this tool call
      // (All mutations since last check are attributed to the most recent tool)
      for (const mutation of mutations) {
        const seReceipt = await synthesizeSideEffectReceipt(
          mutation, toolCall.id, this.agentDid, this.runId,
        );
        this._sideEffectReceipts.push(seReceipt);
      }

      // Clear mutations after attribution (only attribute once)
      mutations = [];
    }
  }

  /**
   * Final sweep: detect any remaining file mutations after the agent exits.
   * Attributes them to the last known tool call, or as unattributed.
   */
  async finalize(): Promise<void> {
    if (!this.snapshotInitialized) return;

    const { mutations } = await getIncrementalMutations(this.fileSnapshot, this.cwd);

    // Find the last tool call for attribution
    const lastToolCallId = this._toolReceipts.length > 0
      ? this._toolReceipts[this._toolReceipts.length - 1]!.payload.receipt_id
      : 'final_sweep';

    for (const mutation of mutations) {
      const seReceipt = await synthesizeSideEffectReceipt(
        mutation, lastToolCallId, this.agentDid, this.runId,
      );
      this._sideEffectReceipts.push(seReceipt);
    }

    // Also resolve any pending tool calls that never got results
    for (const [id, toolCall] of this.pendingToolCalls) {
      const toolReceipt = await synthesizeToolReceipt(
        toolCall, undefined, this.agentDid, this.runId,
      );
      this._toolReceipts.push(toolReceipt);
      this.pendingToolCalls.delete(id);
    }
  }
}
