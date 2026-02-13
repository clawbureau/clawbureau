# Troubleshooting

Common issues when using `npx clawsig wrap`.

## Agent hangs or SSL errors

**Symptom:** Agent fails with `UNABLE_TO_VERIFY_LEAF_SIGNATURE`, `self signed certificate`, or hangs on API calls.

**Cause:** Corporate VPN/proxy (Zscaler, Netskope) or custom CA certificates conflict with the local interceptor proxy.

**Fix:**
```bash
# Option 1: Tell Node to trust your corporate CA bundle
export NODE_EXTRA_CA_CERTS=/path/to/your/corporate-ca.pem

# Option 2: For Python agents (aider, etc.)
export REQUESTS_CA_BUNDLE=/path/to/your/corporate-ca.pem
export SSL_CERT_FILE=/path/to/your/corporate-ca.pem

# Option 3: Disable TLS verification (development only, NOT recommended)
export NODE_TLS_REJECT_UNAUTHORIZED=0
```

## "It blocked my valid PR!"

**Symptom:** GitHub App posts `UNATTESTED_FILE_MUTATION` on a PR where you manually edited files.

**Cause:** You edited files after the agent ran. The receipt hashes don't match the final commit.

**Fix:** This is expected! As of v0.2.1, the app uses **Differential Provenance** — files edited by humans after the agent are classified as "mixed" and the PR passes. If you're seeing this error, update the GitHub App to the latest version.

If you don't have a `.clawsig/policy.json` file, the app runs in **Observe Mode** and posts a neutral (yellow) check — it never blocks.

## "Does this send my code to your servers?"

**No.** The proof bundle contains only SHA-256 hashes of your code, not the code itself. Raw source, prompts, and API responses never leave your machine.

The only data sent to `api.clawverify.com` (if you opt in with `--publish`):
- Ed25519 signatures
- SHA-256 hashes of tool args and results
- Timestamps and receipt metadata
- Your agent's ephemeral DID (a random public key)

Use `--no-publish` to keep everything local. Use `clawsig wrap --no-publish -- your-agent` to generate a local bundle only.

## Agent bypasses the proxy

**Symptom:** The agent uses `--noproxy '*'`, `unset HTTP_PROXY`, or absolute path binaries to bypass the local proxy.

**This is expected and documented.** The proxy is for *observability*, not *containment*. The Sentinel Shell (`trap DEBUG`) still logs the bypass attempt, and the GitHub App catches unattested mutations at the PR gate.

If the agent bypasses the proxy:
- Tool receipts: Still captured via HTTP stream parsing (Causal Sieve)
- File mutations: Still captured via FS Sentinel and git diff
- Network connections: Still visible via Net Sentinel (lsof/procfs)
- The bypass itself: Logged as `env_manipulation` by the Sentinel Shell

## Windows support

The Sentinel Shell (`BASH_ENV` + `trap DEBUG`) requires bash. On Windows:
- **WSL2:** Works natively. Run `clawsig wrap` inside WSL.
- **Git Bash:** Partial support. `BASH_ENV` works but `fs.watch` recursive may miss events.
- **PowerShell/cmd:** Not supported for shell tracing. FS and Net sentinels still work.

## Agent is slow

The sentinels add <1% overhead:
- Sentinel Shell: ~0.5ms per command (single `echo` to JSONL file)
- FS Sentinel: Passive kernel callbacks (FSEvents/inotify), zero polling
- Net Sentinel: 500ms lsof poll (unref'd, doesn't block Node exit)

If you see >5% slowdown, check if your agent is making excessive small file writes that flood the FS Sentinel's event queue. Add patterns to ignore:

```json
// .clawsig/policy.json
{
  "sentinel": {
    "fs_ignore": ["*.log", "*.tmp", ".cache/"]
  }
}
```

## "No receipts collected"

**Symptom:** Bundle shows 0 tool receipts and 0 side-effect receipts.

**Likely causes:**
1. Agent doesn't use `OPENAI_BASE_URL` or `ANTHROPIC_BASE_URL` env vars (check agent docs)
2. Agent uses a provider not yet supported (only OpenAI and Anthropic HTTP formats parsed)
3. Agent makes no tool calls during the session

**Debug:** Run with verbose logging:
```bash
CLAWSIG_DEBUG=1 npx clawsig wrap -- your-agent
```

## Getting help

- GitHub Issues: https://github.com/clawbureau/clawbureau/issues
- Discord: (coming soon)
- Email: security@clawbureau.com
