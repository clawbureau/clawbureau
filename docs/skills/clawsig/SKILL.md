---
name: clawsig
description: >-
  Clawsig Protocol CLI skill for agent harnesses.
  Covers identity setup, proof-bundle wrapping, offline verification,
  reason-code explanation, compliance reporting, and policy management.
  Use when the task involves proving agent work, verifying proof bundles,
  generating compliance reports, or managing clawsig identity/policy.
  Triggers on: "clawsig", "clawverify", "proof bundle", "verify bundle",
  "wrap agent", "agent proof", "compliance report", "reason code",
  "clawsig init", "DID identity".
---

# Clawsig Protocol — Agent Skill

CLI reference for `clawsig` (v0.4) / `clawverify` (v0.2).
All commands support `--json` for machine-parseable output.

Install:

```bash
npm install -g clawsig                      # provides `clawsig` bin
# or
npm install -g @clawbureau/clawverify-cli   # provides `clawverify` bin
```

Both bins resolve to the same CLI. Use `clawsig` for wrap, `clawverify` for verify/compliance/explain.

---

## 1. Identity — `clawsig init`

Scaffold a `.clawsig/` directory with a persistent Ed25519 identity and default policy.

### Usage

```bash
# Project-level (writes to .clawsig/ in cwd)
clawsig init --json

# Global identity (writes to ~/.clawsig/)
clawsig init --global --json

# Force-overwrite existing files
clawsig init --force --json

# Custom directory
clawsig init --dir /path/to/project --json
```

### JSON output

```jsonc
{
  "identity_created": true,        // false if already existed
  "identity_did": "did:key:z6Mk...",
  "identity_path": "/abs/path/.clawsig/identity.jwk.json",
  "policy_created": true,
  "policy_path": "/abs/path/.clawsig/policy.json",
  "dir": "/abs/path/.clawsig",
  "created": ["identity.jwk.json", "policy.json", "README.md"],
  "skipped": []
}
```

### Identity lookup order

1. `CLAWSIG_IDENTITY` env var (explicit path to JWK file)
2. `.clawsig/identity.jwk.json` (project-level)
3. `~/.clawsig/identity.jwk.json` (global)

If no persistent identity is found during `wrap`, an ephemeral DID is generated automatically.

### Check identity (no dedicated command — use init)

```bash
# If identity exists, init reports it in "skipped" + returns the DID
clawsig init --json | jq '.identity_did'
```

### Fail-closed behavior

- Identity JWK files are written with mode `0600`. Verify permissions:
  `stat -f '%Lp' .clawsig/identity.jwk.json` should return `600`.
- Never commit `identity.jwk.json` to version control. Add `.clawsig/identity.jwk.json` to `.gitignore`.

---

## 2. Wrap — `clawsig wrap`

One-line agent verification. Wraps any agent process, intercepts LLM calls, and compiles a signed proof bundle on exit.

### Usage

```bash
# Basic wrap (publishes bundle to VaaS)
clawsig wrap -- python my_agent.py

# JSON mode (machine output only, no ANSI)
clawsig wrap --json -- node agent.js

# Save bundle to specific path
clawsig wrap --output bundle.json -- node agent.js

# Skip VaaS publish (offline only)
clawsig wrap --no-publish -- npx my-agent

# Verbose diagnostics (sentinel status, receipt details)
clawsig wrap --verbose -- pi "fix the tests"

# Combine flags
clawsig wrap --json --no-publish --output ./proof.json -- claude "refactor module"
```

### Harness-specific adapters

```bash
# Pi
clawsig wrap -- pi "fix the tests"

# Claude Code
clawsig wrap -- claude "implement feature"

# Codex (note: base URL override disabled for OAuth compat)
clawsig wrap -- codex "build feature"

# OpenCode
clawsig wrap -- opencode "refactor module"
```

### JSON output (wrap --json)

```jsonc
{
  "status": "PASS",                    // "PASS" or "FAIL"
  "exit_code": 0,
  "agent_did": "did:key:z6Mk...",
  "bundle_path": ".clawsig/proof_bundle.json",
  "bundle_size_bytes": 4821,
  "coverage": "gateway",              // "gateway" or "self"
  "receipt_counts": {
    "gateway": 3,
    "tool_call": 12,
    "side_effect": 2,
    "execution": 45,
    "network": 8,
    "human_approval": 1
  },
  "duration_ms": 34521
}
```

### Bundle output location

The proof bundle is always written to `.clawsig/proof_bundle.json` in cwd, regardless of `--output` or `--no-publish`.

### Visibility: public vs private

By default, `wrap` publishes the proof bundle to the VaaS ledger (public). Use `--no-publish` for private/offline-only bundles. Published bundles get a verification badge URL printed to stdout.

### Environment variables (advanced)

| Variable | Effect |
|----------|--------|
| `CLAWSIG_IDENTITY` | Explicit path to identity JWK file |
| `CLAWSIG_USE_CLAWPROXY` | Set to route through clawproxy (gateway receipts) |
| `CLAWSIG_CLAWPROXY_URL` | Custom clawproxy URL |
| `CLAWSIG_DISABLE_INTERPOSE` | Set to `1` to disable syscall interposition |
| `CLAWSIG_FORCE_BASE_URL_OVERRIDE` | Set to `1` to force provider base URL override (e.g., for Codex) |

### What wrap captures (MTS coverage)

| Layer | What | Receipt type |
|-------|------|-------------|
| Local proxy (Causal Sieve) | LLM requests/responses, tool calls, side effects | `gateway`, `tool_call`, `side_effect` |
| Sentinel Shell (`BASH_ENV`) | Every bash subcommand the agent spawns | `execution` |
| FS Sentinel | File creates/writes/deletes | (metadata in bundle) |
| Net Sentinel | TCP connections + suspicious egress | `network` |
| Interpose Sentinel (`LD_PRELOAD`/`DYLD_INSERT`) | syscall-level connect, open, execve, sendto | `network`, `execution`, `gateway` |
| Node Preload | `fetch`/`https` intercepts in Node child processes | `gateway` |
| TLS SNI | Cross-runtime TLS connection domains | `gateway` |
| Human approval | Explicit approve/deny from operator | `human_approval` |

### Fail-closed behavior

- Unknown envelope types in receipts are rejected during verification.
- Policy violations during wrap are logged to stderr with `[clawsig:guillotine]` prefix and recorded in the bundle.
- If the child process is killed via SIGTERM/SIGHUP, the signal is forwarded to the child; the bundle is still compiled after child exit.

---

## 3. Verify — `clawverify verify`

Offline verification of proof bundles, export bundles, aggregate bundles, and commit signatures.

### Usage

```bash
# Verify a proof bundle
clawverify verify proof-bundle --input bundle.json --json

# Verify with config (trusted signer allowlist)
clawverify verify proof-bundle --input bundle.json --config clawverify.config.v1.json --json

# Verify with URM (User Rights Manifest)
clawverify verify proof-bundle --input bundle.json --urm urm.json --json

# Verify an export bundle
clawverify verify export-bundle --input export.json --json

# Verify an aggregate bundle
clawverify verify aggregate-bundle --input aggregate.json --json

# Verify a commit signature
clawverify verify commit-sig --input commit.sig.json --json
```

### JSON output — proof-bundle

```jsonc
{
  "result": "PASS",                     // "PASS" or "FAIL"
  "tier": "gateway",
  "schema_version": "proof_bundle.v1",
  "agent_did": "did:key:z6Mk...",
  "reason_codes": [],                   // empty on PASS; e.g. ["HASH_MISMATCH"] on FAIL
  "receipt_count": 12,
  "warnings": []
}
```

### JSON output — commit-sig

```jsonc
{
  "result": "PASS",
  "signer_did": "did:key:z6Mk...",
  "commit_sha": "abc123...",
  "message": "commit:abc123..."
}
```

### JSON output — export/aggregate bundle

```jsonc
{
  "result": "PASS",
  "schema_version": "export-bundle.v1",
  "reason_codes": [],
  "warnings": []
}
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | PASS (valid) |
| 1 | FAIL (invalid) |
| 2 | USAGE or CONFIG error |

### Fail-closed behavior

- Unknown hash algorithms are rejected (no fallback).
- Unknown envelope types are rejected.
- Missing `--input` exits with code 2.
- If a config references trusted DIDs, only those DIDs pass; all others fail.

---

## 4. Explain — `clawverify explain`

Look up any reason code from the Clawsig Protocol reason code registry.

### Usage

```bash
clawverify explain HASH_MISMATCH
clawverify explain HASH_MISMATCH --json
clawverify explain SIGNATURE_INVALID --json
```

### JSON output

```jsonc
{
  "code": "HASH_MISMATCH",
  "severity": "FAIL",           // "PASS" | "FAIL" | "ERROR" | "UNKNOWN"
  "description": "Content hash does not match the declared hash...",
  "remediation": "Content hash does not match the declared hash..."
}
```

### Common reason codes

| Code | Severity | Meaning |
|------|----------|---------|
| `OK` | PASS | Verification passed |
| `SIGNATURE_INVALID` | FAIL | Ed25519 signature mismatch |
| `HASH_MISMATCH` | FAIL | Payload hash does not match content |
| `HASH_CHAIN_BREAK` | FAIL | Event chain linkage broken |
| `SCHEMA_VALIDATION_FAILED` | FAIL | Input does not match JSON schema |
| `INVALID_DID` | FAIL | Malformed DID |
| `RECEIPT_BINDING_MISMATCH` | FAIL | Receipt run_id does not match bundle |
| `INCONSISTENT_RUN_ID` | FAIL | Run IDs differ across bundle elements |
| `EMPTY_CHAIN` | FAIL | Event chain has no entries |
| `COMMIT_MESSAGE_INVALID` | FAIL | Commit sig message format wrong |
| `CONFIG_ERROR` | ERROR | Bad config file |
| `USAGE_ERROR` | ERROR | Invalid CLI usage |

Full registry: `docs/specs/clawsig-protocol/REASON_CODE_REGISTRY.md`

---

## 5. Compliance — `clawverify compliance`

Generate a framework-specific compliance report from a proof bundle.

### Usage

```bash
# SOC2 Type 2 (default)
clawverify compliance bundle.json --json

# ISO 27001
clawverify compliance bundle.json --framework iso27001 --json

# EU AI Act
clawverify compliance bundle.json --framework eu-ai-act --json

# NIST AI RMF
clawverify compliance bundle.json --framework nist-ai-rmf --json

# Write to file
clawverify compliance bundle.json --framework soc2 --output report.json --json
```

### Supported frameworks

| Flag value | Framework |
|------------|-----------|
| `soc2` (default) | SOC2 Type 2 |
| `iso27001` | ISO 27001 |
| `eu-ai-act` | EU AI Act |
| `nist-ai-rmf` | NIST AI RMF |

### JSON output

The compliance report is always JSON (stdout or `--output` file). Structure is framework-specific but includes control mappings, evidence references, and pass/fail per control.

---

## 6. Migrate Policy — `clawverify migrate-policy`

Migrate a v1 Work Policy Contract to the current format.

### Usage

```bash
clawverify migrate-policy old-policy.json --json
```

Output is the migrated policy JSON on stdout.

---

## 7. Version — `clawverify version`

```bash
clawverify version --json
```

### JSON output

```jsonc
{
  "version": "0.2.0",
  "name": "clawverify"
}
```

---

## 8. Work Commands (planned — not yet shipped)

The following work-lifecycle commands are planned but **not yet implemented** in the CLI. Do not attempt to run them. They are documented here for forward planning only.

| Planned command | Intent | Status |
|-----------------|--------|--------|
| `clawsig work init` | Initialize a work session with DID + scope binding | Not implemented |
| `clawsig work register` | Register agent availability for a task/bounty | Not implemented |
| `clawsig work list` | List available work items from marketplace | Not implemented |
| `clawsig work claim` | Claim a work item with DID-signed commitment | Not implemented |
| `clawsig work submit` | Submit completed work with proof bundle attachment | Not implemented |

### Safe fallback for work-lifecycle tasks

Until `work` subcommands ship, use this equivalent workflow:

```bash
# 1. Ensure identity exists
clawsig init --json

# 2. Wrap the agent run (produces proof bundle)
clawsig wrap --json --output proof_bundle.json -- <agent-command>

# 3. Verify the bundle offline
clawverify verify proof-bundle --input proof_bundle.json --json

# 4. Attach bundle to PR / submit manually
#    (proof_bundle.json is the deliverable)
```

---

## Error handling (--json)

All commands emit structured errors to stderr when `--json` is active:

```jsonc
{
  "error": true,
  "code": "USAGE_ERROR",       // "USAGE_ERROR" | "CONFIG_ERROR" | "INTERNAL_ERROR"
  "message": "Missing required flag: --input <path>",
  "exit_code": 2
}
```

### Troubleshooting checklist

1. **"No persistent identity found"** — Run `clawsig init` or `clawsig init --global`.
2. **SIGNATURE_INVALID** — The signing key changed. Regenerate the bundle with the current identity.
3. **HASH_MISMATCH** — The bundle payload was modified after signing. Do not edit bundle JSON manually.
4. **SCHEMA_VALIDATION_FAILED** — Upgrade CLI: `npm install -g clawsig@latest`.
5. **CONFIG_ERROR** — Validate config: `cat clawverify.config.v1.json | jq .`
6. **Bundle is 0 bytes / missing** — Check that the child process exited (not hung). Wrap waits for child exit before compiling.
7. **Codex base URL error** — Codex uses OAuth; base URL override is disabled by default. Set `CLAWSIG_FORCE_BASE_URL_OVERRIDE=1` if needed.
8. **"VaaS unavailable"** — Network issue or VaaS maintenance. Bundle is still written locally to `.clawsig/proof_bundle.json`.
9. **DYLD/LD_PRELOAD warnings** — macOS SIP may block DYLD_INSERT_LIBRARIES. The interpose sentinel degrades gracefully; other sentinels remain active.

### Fail-closed principle

The clawsig CLI follows fail-closed design:
- Unknown inputs are rejected, not ignored.
- Unknown envelope types, hash algorithms, and schema versions produce FAIL, not warnings.
- Missing required fields produce FAIL, not defaults.
- If verification cannot complete (e.g., missing config for trusted DIDs), the result is FAIL, not PASS.

---

## Quick reference

```
clawsig init [--global] [--force] [--dir <path>] [--json]
clawsig wrap [--json] [--verbose] [--no-publish] [--output <path>] -- <command> [args...]
clawverify verify proof-bundle --input <path> [--urm <path>] [--config <path>] [--json]
clawverify verify export-bundle --input <path> [--config <path>] [--json]
clawverify verify aggregate-bundle --input <path> [--config <path>] [--json]
clawverify verify commit-sig --input <path> [--json]
clawverify compliance <bundle.json> [--framework soc2|iso27001|eu-ai-act|nist-ai-rmf] [--output <file>] [--json]
clawverify explain <REASON_CODE> [--json]
clawverify migrate-policy <v1-policy.json> [--json]
clawverify version [--json]
```
