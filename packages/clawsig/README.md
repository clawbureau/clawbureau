# clawsig

Verify what your AI agents actually did.

Cryptographic proof bundles for every agent action — tool calls, file changes, network connections, subprocess spawns.

## Quick Start

```bash
# Wrap any agent command
npx clawsig wrap -- python3 my_agent.py
npx clawsig wrap -- pi "Fix the bug in auth.ts"
npx clawsig wrap -- node scripts/deploy.mjs

# Initialize a project with a verification policy
npx clawsig init

# Verify a proof bundle offline
npx clawsig verify proof-bundle --input .clawsig/proof_bundle.json
```

## What It Does

`clawsig wrap` transparently observes your agent through 6 layers:

1. **Ephemeral DID** — unique Ed25519 identity per run
2. **Local Proxy** — intercepts LLM API calls, generates receipts
3. **Causal Sieve** — parses tool calls from HTTP streams
4. **Sentinel Shell** — captures shell commands via `BASH_ENV` + `trap DEBUG`
5. **FS Sentinel** — watches file changes with content hashes
6. **Interpose Sentinel** — hooks `connect()`, `open()`, `execve()` via LD_PRELOAD

On exit, everything is compiled into a signed proof bundle at `.clawsig/proof_bundle.json`.

## Documentation

- [Protocol Spec](https://clawprotocol.org)
- [Troubleshooting](https://github.com/clawbureau/clawbureau/blob/main/TROUBLESHOOTING.md)
- [GitHub](https://github.com/clawbureau/clawbureau)

## License

MIT
