This analysis determines how the local `agentlog` repo can serve as a semantic intelligence layer and verification aid for the Claw Bureau Trust Platform (Proof-of-Harness).

### 1. Repo Summary: `agentlog`

**Agentlog** is a Python-based local intelligence tool that normalizes, analyzes, and synthesizes session logs from disparate AI agents (Pi, Claude Code, Codex, OpenClaw).

*   **Architecture**: CLI-driven (`cli.py`) with a modular parsing backend. It runs post-hoc on local filesystem logs.
*   **Data Model**:
    *   **Input**: Ingests raw JSONL from `~/.pi`, `~/.claude`, `~/.codex`, `~/.openclaw`.
    *   **Internal**: Normalized `AgentEvent` dataclass (timestamp, harness, project, role, content, tool_calls).
    *   **Output**: Redacted Markdown reports, QMD-indexed memory notes, and "Pulse" signals.
*   **Ingestion Strategy**:
    *   **Parsers**: Specialized modules (`parsers/*.py`) map harness-specific JSON schemas to the canonical `AgentEvent`.
    *   **Logic**: Handles branching logic (Pi), sidechains (Claude), and receipt extraction (implied in JSON payloads).
*   **Key Components**:
    *   `parsers/`: Normalization logic.
    *   `redact.py`: Robust regex-based PII scrubbing.
    *   `memory.py` / `memory_pulse.py`: Semantic extraction (decisions, files touched) and content hashing.
    *   `synthesize.py`: LLM-based summarization of session content.

### 2. High-Leverage Intersections with PoH

**A. Correctness & Event Normalization**
PoH requires a canonical "Event Chain." `agentlog` has already solved the "Tower of Babel" problem of normalizing harness logs.
*   *Leverage*: The normalization logic in `agentlog/parsers/*.py` (mapping `toolCall` vs `function_call` vs `tool_use`) should enable `clawverify` to deterministically interpret the *semantics* of an Event Chain regardless of which harness produced it.

**B. Semantic Metadata for URM**
The `Universal Run Manifest` (URM) allows for a `metadata` field. `agentlog` extracts high-value signals that should be injected here:
*   **Pulse Signals**: `memory_pulse.py` extracts "Decisions", "Files Touched", and "Tools Used".
*   **Value**: Including these in the URM allows the generic Marketplace UI to display "What this agent actually did" (files modified, decisions made) without parsing the full, encrypted event chain.

**C. Redaction & PII Safety**
`agentlog/redact.py` contains a mature set of regexes for `Bearer`, `sk-ant-`, `jwt`, and natural language leaks.
*   *Learnings*: PoH adapters MUST run this specific logic *before* hashing the payload for the Event Chain. If a key leaks into the Event Chain, the entire proof bundle is toxic.
*   *Action*: Port `agentlog/redact.py` logic directly into `clawproof-adapters` TypeScript logic.

**D. Harness Shims**
The `shim.ts` in `clawproof-adapters` proxies traffic. `agentlog`'s parser logic can be used to *verify* that the referenced files in a tool call (e.g., `read_file "config.json"`) actually exist on the user's disk relative to the `cwd` defined in the session header, adding a layer of integrity check to "Self" tier proofs.

### 3. Trust Analysis

| Evidence Source | Trust Tier | Analysis |
| :--- | :--- | :--- |
| **Raw JSONL Logs** | **Self-Reported** | Mutable text files on disk. User can edit timestamps, prompts, or tool outputs. `agentlog` currently trusts these implicitly. |
| **Derived Memory** | **Self-Reported** | Since input is mutable, memory (`memory.py`) is mutable. Useful for context, not verification. |
| **Clawproxy Receipts** | **Verifiable** | `_receipt_envelope` found in logs (via `shim.ts`) contains an Ed25519 signature from the gateway. |
| **PoH Bundle** | **Verifiable** | If `agentlog` finds a PoH bundle, it can verify the `payload_hash` against the log content. |

**Risk of False Trust Uplift**:
`agentlog` currently reports "Activity" based on file existence. A malicious user could generate fake JSONL to inflate "Active Time" metrics.
*   *Mitigation*: `agentlog` CLI should distinguish between **Verified Sessions** (contain valid PoH `receipts` or `proof_bundle`) and **Unverified Sessions**.

### 4. Concrete Integration Proposals

#### 1. Port Redaction Logic to PoH Adapters
*   **Description**: Port `agentlog/redact.py` (Python) to `packages/clawproof-adapters` (TypeScript).
*   **Target**: `clawproof-adapters` library users (harness developers).
*   **Value**: Prevents PII/Keys from ever entering the immutable Event Chain, ensuring PoH bundles are safe to share/store.
*   **Location**: `packages/clawproof-adapters/src/redact.ts`.
*   **Complexity**: Low (Regex port).

#### 2. `agentlog verify` Command
*   **Description**: A local verification tool that cross-checks raw logs against local PoH bundles.
*   **Target**: OpenClaw users, Developers debugging PoH.
*   **Value**: "Trust but Verify" locally. Ensures that the `_receipt_envelope` embedded in the logs matches the parameters of the log entry (timestamp, model, prompt hash). failing-closed if tampered.
*   **Location**: New `agentlog` subcommand: `agentlog verify <session_path>`.
*   **Complexity**: Medium (Requires logic to recompute hashes Python-side).

#### 3. Semantic Metadata Injection (Pulse-to-URM)
*   **Description**: When `clawproof-adapters` finalizes a run, it should allow an optional `semantic_summary` input. `agentlog`'s logic (`memory_pulse.py`) extracts "Decisions" and "Files Modifed".
*   **Target**: Marketplace Users (Buyers).
*   **Value**: Buyers see a high-level summary of the run (e.g., "Modified 3 files in `src/`, decided to use `axios`") in the Explorer UI without needed to decrypt/parse the full chain.
*   **Location**: `packages/clawproof-adapters` (interface update) & `agentlog` (extractor).
*   **Complexity**: Low.

#### 4. Reference integrity Check (Git Commit Linkage)
*   **Description**: Modify `agentlog` parsers to look for `session_meta` (Codex/OpenClaw) containing git commit hashes. Correlate "Session Timestamp" with "Git Commit Timestamp" in `monthly_review.py`.
*   **Target**: Trust Platform / Auditors.
*   **Value**: Stronger "Self" tier signal. If a session claims to write code, and a signed Git commit exists exactly at that time authoring those lines, trust confidence increases.
*   **Location**: `agentlog/monthly_review.py` and `agentlog/parsers/base.py`.
*   **Complexity**: Medium.

#### 5. Retroactive "Self-Tier" Bundle Generation
*   **Description**: Use `agentlog` to parse *legacy* or *non-PoH* sessions (e.g. from standard Claude Code) and wrap them in a **strictly Self-Tier** PoH bundle format.
*   **Target**: Users wanting to archive/attest to past work.
*   **Value**: Brings standard harness logs into the PoH ecosystem formats (URM, Event Chain) for archival, explicitly marked as `tier: "self_retroactive"`.
*   **Location**: `agentlog bundle <session_path>`.
*   **Complexity**: High (Needs strict schema compliance).

### 5. Recommended Next Steps

**Phase 1: Safety & Consistency (Quick Wins - 1 Day)**
1.  **Port Redaction**: Copy regexes from `agentlog/redact.py` to `packages/clawproof-adapters/src/redact.ts` and use it in `recorder.ts` `recordEvent`.
2.  **Harmonize Schemas**: Ensure `agentlog/parsers/base.py` `AgentEvent` aligns with fields required by `packages/schema/poh/event_chain.v1.json`.

**Phase 2: Verifiability (1 Week)**
1.  Implement **Proposal 2**: `agentlog verify` to validate local `_receipt_envelope` signatures found in logs.
2.  Update `agentlog` reports (`cli.py`) to show a ✅ badge next to sessions that pass local verification.

**Phase 3: Semantic Trust (2 Weeks)**
1.  Implement **Proposal 3**: Update `recorder.finalise()` to accept rich metadata, and use `agentlog` logic to generate that metadata for OpenClaw runs.
