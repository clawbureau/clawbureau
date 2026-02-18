# Integration starter packs (ADP-US-002)

These packs are copy/paste-oriented, fixture-backed integration starters for Clawsig v0.2.

Each pack has a one-command smoke and writes deterministic artifacts:

- `proof-bundle.json`
- `urm.json`
- `verify.json`
- `smoke.json`

## Packs

### 1) Node minimal

```bash
node docs/examples/integrations/node-minimal/run.mjs
```

Outputs:

- `artifacts/examples/integrations/node-minimal/`

### 2) GitHub Actions

```bash
node docs/examples/integrations/github-actions/run.mjs
```

Outputs:

- `artifacts/examples/integrations/github-actions/`

Includes workflow skeleton:

- `docs/examples/integrations/github-actions/workflow.example.yml`

### 3) Enterprise CI (GitLab / Buildkite)

```bash
node docs/examples/integrations/enterprise-ci/run.mjs
```

Outputs:

- `artifacts/examples/integrations/enterprise-ci/`

Includes pipeline skeletons:

- `docs/examples/integrations/enterprise-ci/gitlab-ci.example.yml`
- `docs/examples/integrations/enterprise-ci/buildkite.pipeline.example.yml`
