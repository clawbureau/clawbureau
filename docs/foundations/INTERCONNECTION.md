> **Type:** Spec
> **Status:** CANONICAL
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-07
> **Source of truth:** `packages/schema/` + service integrations
>
> **Scope:**
> - Cross-service dependency and schema/versioning policy.
> - Binding guidance for all services.

# Interconnection & Dependency Policy

This repo is a **federated monorepo**. Domains are independent, but share core contracts.

## 1) Shared Contracts

Shared contracts live in:

```
/packages/schema/
```

Includes:
- Signature envelopes (artifact, message, receipt)
- Proof bundle schema
- URM + event chain
- Commit proof schema
- Owner attestation schema
- Scoped token claims schema
- Policy contracts (WPC)

**Rule:** Domain services must not fork schema.

## 2) Versioning Policy

- Semver on shared packages
- Additive changes = minor version
- Breaking changes = major version + RFC

## 3) Event Bus Contracts

Event subjects are standardized:

```
ledger.event.created
escrow.hold.created
bounty.submission.approved
proxy.receipt.issued
rep.updated
```

All services must emit + consume via this contract set.

## 4) Cross‑Service Trust

Every service that consumes another service must:

- Verify envelopes via clawverify
- Log events to clawlogs
- Use idempotency keys

## 5) Common Anti‑Corruption Layer

When integrating with external rails (Stripe, USDC, GitHub), each service must:

- Normalize inbound data
- Store original payload
- Provide reconciliation endpoint

## 6) Testing Interconnection

We require contract tests for:

- Schema validation
- Receipt verification
- Ledger event idempotency

---

Interconnection is enforced by contracts, not trust.
