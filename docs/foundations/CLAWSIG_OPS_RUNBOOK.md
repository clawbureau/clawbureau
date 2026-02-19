> **Type:** Runbook
> **Status:** ACTIVE
> **Owner:** @clawbureau/ops
> **Last reviewed:** 2026-02-19
> **Source of truth:**
> - `scripts/ops/run-clawsig-guarded-deploy.mjs`
> - `scripts/ops/smoke-clawsig-surface.mjs`
> - `scripts/ops/seed-clawsig-canary-run.mjs`
> - `.github/workflows/clawsig-guarded-deploy.yml`
> - `.github/workflows/clawsig-surface-synthetic-smoke.yml`
>
> **Scope:**
> - Clawsig ledger/explorer deploy + rollback flow
> - Synthetic failure triage and alert routing
> - Canary seeding SOP
> - Domain/routing incident checklist

# Clawsig Ops Runbook (ledger + explorer)

## 1) Guarded deploy flow (staging -> smoke -> prod -> smoke -> rollback)

### 1.1 Local/manual execution

```bash
# from repo root
node scripts/ops/run-clawsig-guarded-deploy.mjs --max-run-ref-age-minutes 180
```

### 1.2 GitHub workflow execution

```bash
# manual trigger
gh workflow run clawsig-guarded-deploy.yml -f max_run_ref_age_minutes=180

# inspect latest run
gh run list --workflow clawsig-guarded-deploy.yml --limit 5
```

### 1.3 Expected behavior (fail-closed)

1. Capture current staging/prod versions for both services.
2. Deploy staging:
   - `services/clawsig-ledger`
   - `services/clawsig-explorer`
3. Seed staging canary and run strict staging synthetic smoke.
4. Deploy prod:
   - `services/clawsig-ledger`
   - `services/clawsig-explorer`
5. Seed prod canary and run strict prod synthetic smoke.
6. If prod deploy/smoke fails, rollback both services to baseline prod versions.
7. Re-run prod smoke post-rollback.
8. Workflow/job remains failed when rollback path is used (incident signal preserved).

### 1.4 Artifact expectations

Run output root:

```text
artifacts/ops/clawsig-guarded-deploy/<timestamp>/
```

Required files (minimum):

- `summary.json`
- `ledger-staging-current-version.log`
- `explorer-staging-current-version.log`
- `ledger-prod-current-version.log`
- `explorer-prod-current-version.log`
- `ledger-staging-deploy.log`
- `explorer-staging-deploy.log`
- `seed-staging.log`
- `smoke-staging.log`
- `ledger-prod-deploy.log`
- `explorer-prod-deploy.log`
- `seed-prod.log`
- `smoke-prod.log`
- rollback logs when rollback path is triggered

Success criteria in `summary.json`:

- `ok: true`
- `rollback.attempted: false`

Rollback criteria in `summary.json`:

- `ok: false`
- `rollback.attempted: true`
- `rollback.reason_code` present

---

## 2) Synthetic failure triage (strict smoke)

### 2.1 Run strict smoke manually

```bash
# all surfaces
node scripts/ops/smoke-clawsig-surface.mjs --env all --max-run-ref-age-minutes 180

# env-specific
node scripts/ops/smoke-clawsig-surface.mjs --env staging --max-run-ref-age-minutes 180
node scripts/ops/smoke-clawsig-surface.mjs --env prod --max-run-ref-age-minutes 180
```

### 2.2 Inspect latest smoke artifacts

```bash
LATEST="$(ls -1dt artifacts/ops/clawsig-synthetic/* | head -n 1)"

jq . "$LATEST/summary.json"
jq '.checks[] | select(.ok == false)' "$LATEST/checks.json"
```

### 2.3 Deterministic alert routing (Slack/Discord)

```bash
LATEST="$(ls -1dt artifacts/ops/clawsig-synthetic/* | head -n 1)"

node scripts/ops/route-clawsig-synthetic-alert.mjs \
  --summary "$LATEST/summary.json" \
  --checks "$LATEST/checks.json" \
  --workflow-file clawsig-surface-synthetic-smoke.yml
```

Required env vars for routing:

- `SYNTHETIC_ALERT_SLACK_WEBHOOK` (optional)
- `SYNTHETIC_ALERT_DISCORD_WEBHOOK` (optional)

Alert payload includes:

- reason code
- host
- route/path
- commit SHA
- workflow run URL

De-dup behavior:

- dedupe repeated failures within same run (`reason|host|route`)
- suppress recent same-SHA failure spam window in workflow mode

---

## 3) Canary seeding SOP

### 3.1 Seed

```bash
# both envs
node scripts/ops/seed-clawsig-canary-run.mjs --env all

# single env
node scripts/ops/seed-clawsig-canary-run.mjs --env staging
node scripts/ops/seed-clawsig-canary-run.mjs --env prod
```

### 3.2 Verify seed results

```bash
LATEST="$(ls -1dt artifacts/ops/clawsig-canary-seed/* | head -n 1)"

jq . "$LATEST/summary.json"
jq '.checks[] | select(.ok == false)' "$LATEST/checks.json"
```

Expected summary:

- `ok: true`
- `failed_checks: 0`
- both env entries present when `--env all`

---

## 4) Domain/routing incident checklist

### 4.1 DNS + health matrix

```bash
# DNS
for h in staging-api.clawverify.com api.clawverify.com staging-explorer.clawsig.com explorer.clawsig.com; do
  dig +short "$h" A
  dig +short "$h" AAAA
done

# Health
for u in \
  https://staging-api.clawverify.com/health \
  https://api.clawverify.com/health \
  https://staging-explorer.clawsig.com/health \
  https://explorer.clawsig.com/health; do
  curl -sS -o /dev/null -w "%{http_code} ${u}\n" "$u"
done
```

### 4.2 Explorer route checks

```bash
curl -sS https://staging-explorer.clawsig.com/ops -o /dev/null -w "%{http_code}\n"
curl -sS https://explorer.clawsig.com/ops -o /dev/null -w "%{http_code}\n"
```

### 4.3 Recovery actions

1. Re-run canary seed (`--env` scoped to impacted env).
2. Re-run env-scoped strict smoke.
3. If deploy regression confirmed, execute guarded rollback flow (or manual rollback below).

Manual rollback commands:

```bash
# ledger
cd services/clawsig-ledger
npx wrangler deployments list --json --env staging
npx wrangler deployments list --json
npx wrangler rollback <staging-version-id> -y --env staging
npx wrangler rollback <prod-version-id> -y

# explorer
cd ../clawsig-explorer
npx wrangler deployments list --json --env staging
npx wrangler deployments list --json
npx wrangler rollback <staging-version-id> -y --env staging
npx wrangler rollback <prod-version-id> -y
```

4. Confirm with:
   - `/health` matrix
   - strict smoke (`--env` scoped)
   - artifacts captured under `artifacts/ops/clawsig-surface/` and `artifacts/ops/clawsig-synthetic/`
