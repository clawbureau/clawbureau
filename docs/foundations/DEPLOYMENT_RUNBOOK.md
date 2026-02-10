> **Type:** Guide
> **Status:** DRAFT
> **Owner:** @clawbureau/infra
> **Last reviewed:** 2026-02-10
> **Source of truth:**
> - `services/clawproxy/wrangler.toml`
> - `services/clawverify/wrangler.toml`
> - Tripwire: `scripts/poh/smoke-fal-openrouter-via-clawproxy.mjs`
>
> **Scope:**
> - Safe manual deploy procedure for `clawproxy` + `clawverify` (staging → production).
> - The exact “tripwire” command to validate receipts end-to-end.
> - Does **not** cover DNS setup, secrets provisioning, or incident response.

# Deployment Runbook — clawproxy + clawverify (staging → prod)

## 0) Preconditions

- You are on a **clean checkout** of `origin/main`.
- You have Cloudflare access for the ClawBureau account and `wrangler` is authenticated.
- Required service secrets/vars already exist in Cloudflare (do **not** print them).
- For the tripwire smoke test you have `FAL_KEY` available in your local env (fal OpenRouter router key).

> The tripwire performs real upstream calls (cost). Run it sparingly.

---

## 1) Deploy clawproxy (gateway) — staging first

### 1.1 Deploy staging

```bash
cd services/clawproxy
npm ci
wrangler deploy --env staging
curl -sS https://staging.clawproxy.com/health | jq .
```

Expected: `{ status: "ok", ... }`

### 1.2 Validate staging with the ecosystem tripwire

```bash
cd ../../
node scripts/poh/smoke-fal-openrouter-via-clawproxy.mjs --env staging
```

Expected:
- `ok: true`
- Receipt metadata includes:
  - `payload.metadata.model_identity`
  - `payload.metadata.model_identity_hash_b64u`
- `model_identity.tier === "closed_opaque"`
- `verify_status: "VALID"`

---

## 2) Deploy clawproxy — production

> Wrangler will warn if multiple environments exist and you don’t specify one. That’s expected.

```bash
cd services/clawproxy
wrangler deploy
curl -sS https://clawproxy.com/health | jq .
```

### 2.1 Validate production with the ecosystem tripwire

```bash
cd ../../
node scripts/poh/smoke-fal-openrouter-via-clawproxy.mjs --env prod
```

---

## 3) Deploy clawverify (verifier) — staging → production

### 3.1 Deploy staging

```bash
cd services/clawverify
npm ci
npm test
wrangler deploy --env staging
curl -sS https://staging.clawverify.com/health | jq .
```

### 3.2 Deploy production

```bash
wrangler deploy
curl -sS https://clawverify.com/health | jq .
```

---

## 4) Common pitfalls

- **Tripwire fails with missing model_identity:** clawproxy deploy didn’t include the latest `main` build (or you deployed the wrong env).
- **Tripwire fails with verify_status != VALID:** clawverify signer allowlists / gateway receipt signer DIDs may be misconfigured in that env.
- **fal/OpenRouter auth errors:** ensure `FAL_KEY` is present locally; the smoke script uses `x-provider-api-key`.

---

## 5) Rollback (last resort)

Use Wrangler’s deployments tooling to list/rollback versions:

```bash
cd services/clawproxy
wrangler deployments list --env staging
# wrangler deployments rollback <version-id> --env staging

wrangler deployments list
# wrangler deployments rollback <version-id>
```

(Repeat similarly for `services/clawverify`.)
