# GitHub Actions integration starter pack

One-command smoke (from repo root):

```bash
node docs/examples/integrations/github-actions/run.mjs
```

Deterministic output location:

```text
artifacts/examples/integrations/github-actions/
```

Produced artifacts:

- `proof-bundle.json`
- `urm.json`
- `verify.json`
- `smoke.json`

## Copy/paste workflow skeleton

Use `workflow.example.yml` as a baseline. It runs the starter smoke and uploads generated artifacts.
