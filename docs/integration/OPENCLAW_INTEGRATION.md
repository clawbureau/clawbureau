> **Type:** Integration
> **Status:** ACTIVE
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-07
> **Source of truth:** `docs/openclaw/*` (constraints) + Claw Bureau service PRDs
>
> **Scope:**
> - How Claw Bureau services map onto OpenClaw plugins/skills.
> - Constraint doc; does not imply features are already shipped.

# Claw Bureau ↔ OpenClaw Integration Plan

## Why this document exists
Claw Bureau services are intended to be the **trust + authorization layer** for the OpenClaw runtime.

OpenClaw is not “just another client”; it is the **reference harness**:
- Agents run inside the OpenClaw Gateway (single-process, plugin-driven).
- Capabilities are exposed as **tools**.
- External integrations are delivered as **extensions/plugins**.
- Guidance is delivered as **skills** (`SKILL.md`), optionally with `skill.json` env overrides.

This plan sharpens Claw Bureau PRDs so that each service maps cleanly onto OpenClaw’s extension model.

---

## OpenClaw architectural constraints (what we optimize for)
From the upstream OpenClaw documentation (maintained in the separate OpenClaw project, external to this repository):

1) **Plugins are first-class**
- Extensions live under `extensions/*` and are loaded via `openclaw.extensions`.
- Slot types: `channel`, `tool`, `provider`, `memory`.

2) **Skills are prompt-injected docs, not executable code**
- Skills live under `~/.openclaw/workspace/skills/<name>/SKILL.md`.
- Skills can optionally include `skill.json` (env overrides, dependencies, install hints).

3) **Tool policy and sandboxing are the local safety boundary**
- OpenClaw already enforces allow/deny lists (`tools.profile`, `tools.allow`, `tools.deny`) and Docker sandboxing.
- Claw Bureau should *not* try to replace this; it should complement it for **remote service calls**.

4) **Multi-agent is normal**
- Session keys embed agent IDs (`agent:<agentId>:...`).
- Each agent can have distinct policies, workspaces, and identities.

---

## Recommended service ↔ plugin mapping

| Claw Bureau domain | Primary OpenClaw integration | Why |
| --- | --- | --- |
| **clawproxy** | **Provider plugin** | OpenClaw’s model calls should go through clawproxy *without the LLM manually proxying*. Receipts become automatic.
| **clawscope** | Tool/plugin used by providers/tools | Central CST issuer + introspection + revocation + key discovery (JWKS). Used by other plugins to get/verify tokens.
| **clawclaim** | Tool plugin + skill | DID binding + platform claims should be a guided workflow that the OpenClaw user can run.
| **clawverify** | Tool plugin (optional) | Verification is useful both for external platforms and for OpenClaw self-checks.
| **clawsig** | Optional UX; OpenClaw uses DID Work by default | OpenClaw already supports cryptographic identity patterns. clawsig is for interactive/enterprise/custody flows.
| **clawcontrols** | Policy registry + translation layer | Stores Work Policy Contracts (WPC) and token policies; OpenClaw can map WPC → tool policy constraints.
| **clawlogs** | Audit sink (optional) | External append-only audit trail; OpenClaw can export run + receipt metadata.

---

## Canonical identity + auth model (OpenClaw-first)

### 1) Agent identity
- Each OpenClaw agent should have a **cryptographic DID** (initially `did:key` Ed25519).
- This matches OpenClaw’s existing challenge/response patterns (device pairing) and the Claw Bureau DID Work tooling.

### 2) DID binding (clawclaim)
- OpenClaw user binds agent DID(s) via challenge/response.
- Binding record should support OpenClaw metadata:
  - `openclaw_agent_id` (e.g., `main`, `work`)
  - optional `openclaw_instance_id` (stable per gateway install)

### 3) Scoped tokens (clawscope)
Used by OpenClaw plugins (provider/tool) when calling Claw Bureau services.

**Recommended claim mapping:**
- `sub`: agent DID (`did:key:...`) – the caller identity
- `aud`: service identifier (prefer `did:web:<service>` or an explicit string audience)
- `scope`: permission strings, aligned to *service actions*, not OpenClaw local tools
- `mission_id`: OpenClaw correlation ID
  - default: OpenClaw `sessionKey` (e.g., `agent:main:dm:whatsapp:+1555...`)
  - optional: finer-grained “run id” if OpenClaw exposes one
- `owner_ref`: optional reference to an owner attestation (future)

**Scope taxonomy (recommended):**
- `clawproxy:<action>` (e.g., `clawproxy:invoke`)
- `clawclaim:<action>` (e.g., `clawclaim:bind`, `clawclaim:revoke`)
- `clawverify:<action>` (e.g., `clawverify:verify`)

### 4) Correlation headers (recommended)
When OpenClaw calls Claw Bureau services, include:
- `X-OpenClaw-Agent-Id: <agentId>`
- `X-OpenClaw-Session-Key: <sessionKey>`
- `X-OpenClaw-Model: <provider/model>` (for receipts)

For PoH receipt binding (clawproxy), also include:
- `X-Run-Id: <run_id>`
- `X-Event-Hash: <event_hash_b64u>`
- `X-Idempotency-Key: <nonce>`

These fields should be echoed into receipts/audit entries to make runs explainable.

### 5) Model identity + verifiable audits (PoH vNext)
Enterprise defaults route to closed providers, so we must be honest about what can be proven.

- Receipts should carry a tiered `model_identity` object in metadata (closed providers default to `closed_opaque`).
- Runs/bundles may carry references to `audit_result_attestation` objects that bind audits (code+dataset+config) to model identity.

See:
- `docs/roadmaps/proof-of-harness/DESIGN_model-identity-and-verifiable-audits.md`
- `docs/roadmaps/proof-of-harness/ROADMAP_vNext.md`

---

## Re-plan: what to prioritize next (to maximize OpenClaw fit)

1) **OpenClaw provider plugin for clawproxy**
- Goal: route OpenClaw model traffic through clawproxy and attach receipts automatically.

2) **OpenClaw tool plugin for clawclaim + a skill workflow**
- Goal: bind/revoke DID from within OpenClaw with minimal user friction.

3) **Token bootstrap without long-lived secrets**
- Goal: exchange DID-challenge proof for token issuance (clawclaim ↔ clawscope).

4) **WPC ↔ OpenClaw tool policy mapping**
- Goal: import a Work Policy Contract and narrow OpenClaw’s tool set deterministically.

5) **Model identity + audit attestations (PoH vNext)**
- Goal: propagate tiered `model_identity` + optional `audit_result_attestation` references into receipts/bundles for enterprise compliance.

---

## OpenClaw Airlock pattern (OCL-US-001)

### Goal
Treat buyer-controlled repos/uploads as **untrusted JobRoot** while keeping bootstrap/personality/skills in a **trusted IdentityRoot**.

### Recommended layout
- `IdentityRoot` (trusted): immutable operator-managed files (bootstrap, personality, security policy, skills)
- `JobRoot` (untrusted): buyer repo, uploads, artifacts

### Enforced behavior
In sensitive profiles, bootstrap/prompt-pack capture must only accept files from `IdentityRoot`.
If bootstrap discovery yields files from `JobRoot` (or unknown roots), fail closed with:
- `AIRLOCK_BOOTSTRAP_VIOLATION`

### Plugin config (provider-clawproxy)
```json
{
  "plugins": {
    "entries": {
      "provider-clawproxy": {
        "config": {
          "baseUrl": "https://clawproxy.com",
          "airlock": {
            "enabled": true,
            "identityRoots": ["/opt/openclaw/identity"],
            "jobRoots": ["/workspace/job"],
            "requireTrustedBootstrap": true
          }
        }
      }
    }
  }
}
```

This keeps trusted and untrusted contexts partitioned and prevents accidental bootstrap/skills auto-discovery from buyer mounts in sensitive runs.

## Directive authorization by role (OCL-US-002)

### Goal
Prevent buyer-originated messages from applying security-sensitive directives that can downgrade posture (e.g. `/exec`, `/elevated`, `/model`).

### Plugin policy
`provider-clawproxy` supports role-aware directive authorization in `before_agent_start`:
- Extract directives from prompt/message text
- Resolve sender role from context/event metadata
- Deny restricted directives unless sender role is operator-allowlisted
- Fail closed with deterministic errors:
  - `DIRECTIVE_AUTH_ROLE_REQUIRED`
  - `DIRECTIVE_AUTH_DENIED`

### Config snippet
```json
{
  "plugins": {
    "entries": {
      "provider-clawproxy": {
        "config": {
          "baseUrl": "https://clawproxy.com",
          "directiveAuth": {
            "enabled": true,
            "operatorRoles": ["operator", "admin"],
            "buyerRoles": ["buyer", "customer"],
            "restrictedDirectives": ["/exec", "/elevated", "/model"]
          }
        }
      }
    }
  }
}
```

## Sensitive consulting preset (OCL-US-003)

Shipped preset file:
- `packages/openclaw-provider-clawproxy/presets/sensitive-consulting.openclaw.json`

Preset defaults:
- `sandbox.mode = all`
- `sandbox.workspaceAccess = none`
- `sandbox.network = none`
- minimal tool allowlist (`read`, `write`, `exec`) + deny browser/web/session/message/network groups
- `directiveAuth` enabled for operator-only restricted directives
- `airlock` enabled for IdentityRoot vs JobRoot partitioning
- `sensitiveProfile.forbidSkillAutoAllowBins = true`

### Trust-tier mapping
- This preset is designed for **sandbox-ready posture**.
- Actual `proof_tier=sandbox` still requires valid execution attestation verification in clawverify.
- Without execution attestation, receipts remain `gateway` (or lower) even when runtime policy is strict.

## Notes / guardrails
- Do not leak admin keys into LLM context; keep them in plugin config or gateway env.
- Prefer offline verification (JWKS + EdDSA) for speed; introspection remains for revocation checks.
- Keep schemas versioned and fail-closed (OpenClaw uses strict validation; Claw Bureau should too).
