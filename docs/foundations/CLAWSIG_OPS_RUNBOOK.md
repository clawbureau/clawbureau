> **Type:** Runbook
> **Status:** ACTIVE (v2)
> **Owner:** @clawbureau/ops
> **Last reviewed:** 2026-02-19
> **Source of truth:**
> - `scripts/ops/run-clawsig-guarded-deploy.mjs`
> - `scripts/ops/smoke-clawsig-surface.mjs`
> - `scripts/ops/seed-clawsig-canary-run.mjs`
> - `scripts/ops/route-clawsig-synthetic-alert.mjs`
> - `scripts/ops/check-clawsig-prod-parity-drift.mjs`
> - `.github/workflows/clawsig-guarded-deploy.yml`
> - `.github/workflows/clawsig-surface-synthetic-smoke.yml`
> - `.github/workflows/clawsig-prod-parity-drift.yml`
>
> **Scope:**
> - Guarded deploy + rollback (staging -> smoke -> prod -> smoke)
> - Synthetic alert routing (warn/critical tiers)
> - Canary seeding + strict smoke
> - Staging/prod parity drift gate
> - Incident-mode triage (`/ops`, `/ops/slo-health.json`)
> - Domain/routing recovery checklist

# Clawsig Ops Handbook v2 (ledger + explorer)

## 1) Guarded deploy + rollback (fail-closed)

### 1.1 Local/manual command

```bash
# from repo root
node scripts/ops/run-clawsig-guarded-deploy.mjs --max-run-ref-age-minutes 180
```

### 1.2 Workflow trigger

```bash
gh workflow run clawsig-guarded-deploy.yml -f max_run_ref_age_minutes=180
gh run list --workflow clawsig-guarded-deploy.yml --limit 5
```

### 1.3 Execution contract

1. Capture baseline staging/prod versions (ledger + explorer).
2. Deploy staging services.
3. Seed staging canary.
4. Run strict staging smoke.
5. Deploy prod services.
6. Seed prod canary.
7. Run strict prod smoke.
8. Run staging/prod parity drift gate (`max_drift_count=0`).
9. If prod deploy/smoke fails, rollback both services to baseline prod versions and re-smoke prod.
10. Workflow remains failed when rollback path is taken (incident signal preserved).

### 1.4 Required guarded-deploy artifacts

Output root:

```text
artifacts/ops/clawsig-guarded-deploy/<timestamp>/
```

Minimum evidence files:

- `summary.json`
- `ledger-staging-current-version.log`
- `ledger-prod-current-version.log`
- `explorer-staging-current-version.log`
- `explorer-prod-current-version.log`
- `ledger-staging-deploy.log`
- `ledger-prod-deploy.log`
- `explorer-staging-deploy.log`
- `explorer-prod-deploy.log`
- `seed-staging.log`
- `seed-prod.log`
- `smoke-staging.log`
- `smoke-prod.log`
- rollback logs (`*-rollback-*.log`) when rollback is attempted

Success flags in `summary.json`:

- `ok: true`
- `rollback.attempted: false`

Rollback flags in `summary.json`:

- `ok: false`
- `rollback.attempted: true`
- `rollback.reason_code` present

---

## 2) Synthetic smoke + alert routing (warn/critical)

### 2.1 Run strict smoke

```bash
# all environments
node scripts/ops/smoke-clawsig-surface.mjs --env all --max-run-ref-age-minutes 180

# environment scoped
node scripts/ops/smoke-clawsig-surface.mjs --env staging --max-run-ref-age-minutes 180
node scripts/ops/smoke-clawsig-surface.mjs --env prod --max-run-ref-age-minutes 180
```

### 2.2 Inspect smoke summary and checks

```bash
LATEST="$(ls -1dt artifacts/ops/clawsig-synthetic/* | head -n 1)"

jq . "$LATEST/summary.json"
jq '.checks[] | select(.ok == false)' "$LATEST/checks.json"
```

### 2.3 Route alerts (deterministic severity + reason code)

```bash
LATEST="$(ls -1dt artifacts/ops/clawsig-synthetic/* | head -n 1)"

node scripts/ops/route-clawsig-synthetic-alert.mjs \
  --summary "$LATEST/summary.json" \
  --checks "$LATEST/checks.json" \
  --workflow-file clawsig-surface-synthetic-smoke.yml
```

Alert tiers:

- `warn` -> SLO burn-rate warning conditions
- `critical` -> strict smoke failures / critical SLO conditions

Deterministic fields are emitted in payload:

- `severity`
- `reason_code`
- host + route + commit SHA + workflow URL

Required env vars (optional channels):

- `SYNTHETIC_ALERT_SLACK_WEBHOOK`
- `SYNTHETIC_ALERT_DISCORD_WEBHOOK`

De-dup policy:

- in-run dedupe by `reason|host|route`
- same-SHA suppression window via workflow run history

### 2.4 Expected synthetic artifacts

Output root:

```text
artifacts/ops/clawsig-synthetic/<timestamp>/
```

Evidence files:

- `summary.json` (includes `slo_health` + `alert`)
- `checks.json`

---

## 3) Canary seeding SOP

### 3.1 Seed commands

```bash
node scripts/ops/seed-clawsig-canary-run.mjs --env all
node scripts/ops/seed-clawsig-canary-run.mjs --env staging
node scripts/ops/seed-clawsig-canary-run.mjs --env prod
```

### 3.2 Verify seed output

```bash
LATEST="$(ls -1dt artifacts/ops/clawsig-canary-seed/* | head -n 1)"

jq . "$LATEST/summary.json"
jq '.checks[] | select(.ok == false)' "$LATEST/checks.json"
```

Expected:

- `ok: true`
- `failed_checks: 0`
- env entries present for requested scope

---

## 4) Staging/prod parity drift gate

### 4.1 Run parity checker

```bash
# strict gate
node scripts/ops/check-clawsig-prod-parity-drift.mjs --max-drift-count 0

# diagnostic mode (allow temporary drift while investigating)
node scripts/ops/check-clawsig-prod-parity-drift.mjs --max-drift-count 20
```

### 4.2 Workflow trigger

```bash
gh workflow run clawsig-prod-parity-drift.yml -f max_drift_count=0
gh run list --workflow clawsig-prod-parity-drift.yml --limit 5
```

### 4.3 Expected parity artifacts

Output root:

```text
artifacts/ops/clawsig-parity-drift/<timestamp>/
```

Evidence files:

- `summary.json`
- `checks.json`
- `parity-diff-report.json`
- `parity-diff-report.md`

Threshold semantics:

- hard fail when `drift_count > max_drift_count`
- threshold failure reason code: `PARITY_DRIFT_THRESHOLD_EXCEEDED`

---

## 5) Incident-mode triage (Explorer)

When SLO is degraded (`warn` or `critical`), `/ops` enables compact incident-mode layout.

### 5.1 Operator endpoints

```bash
curl -sS https://staging-explorer.clawsig.com/ops -o /dev/null -w "%{http_code}\n"
curl -sS https://explorer.clawsig.com/ops -o /dev/null -w "%{http_code}\n"

curl -sS https://staging-explorer.clawsig.com/ops/slo-health.json | jq .
curl -sS https://explorer.clawsig.com/ops/slo-health.json | jq .
```

### 5.2 Incident-mode expectations

- Banner includes deterministic SLO `reason_code`
- Failing routes/reason buckets are rendered first
- Latest artifact links are surfaced in incident zone
- Full history cards are compacted while incident mode is active

---

## 6) Domain/routing recovery checklist

### 6.1 DNS + health matrix

```bash
for h in staging-api.clawverify.com api.clawverify.com staging-explorer.clawsig.com explorer.clawsig.com; do
  dig +short "$h" A
  dig +short "$h" AAAA
done

for u in \
  https://staging-api.clawverify.com/health \
  https://api.clawverify.com/health \
  https://staging-explorer.clawsig.com/health \
  https://explorer.clawsig.com/health \
  https://staging-explorer.clawsig.com/ops \
  https://explorer.clawsig.com/ops; do
  curl -sS -o /dev/null -w "%{http_code} ${u}\n" "$u"
done
```

### 6.2 Recovery sequence

1. Re-seed canary for impacted env.
2. Re-run env-scoped strict smoke.
3. Re-run parity drift gate.
4. If deployment regression is confirmed, run guarded deploy rollback path or manual rollback.

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

5. Confirm green state with:
   - domain matrix (`/health`, `/ops`)
   - `seed-clawsig-canary-run` summary
   - strict smoke summary (`failed_checks: 0`)
   - parity summary (`drift_count <= max_drift_count`)
