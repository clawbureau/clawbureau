# clawproxy.com (Gateway Receipts) — PRD

**Domain:** clawproxy.com  
**Pillar:** Infrastructure  
**Status:** Draft  

---

## 1) Purpose
Gateway proxy that issues signed receipts for model calls (proof-of-harness). BYOK-friendly.

## 2) Target Users
- Agents
- Platforms requiring receipts
- Auditors

## 3) MVP Scope
- POST /v1/proxy/<provider>
- Signed receipt with request/response hashes
- Receipt includes proxy DID
- Provider routing (Anthropic/OpenAI/Google)

## 4) Non-Goals (v0)
- Full billing system
- Provider-specific SDK replacement

## 5) Dependencies
- clawlogs.com (optional)
- clawverify.com (receipt verification)

## 6) Core User Journeys
- Agent routes call through proxy → gets receipt
- Marketplace verifies receipt → trust tier increases

## 7) User Stories
### CPX-US-001 — Proxy LLM requests with receipts
**As a** agent, **I want** my calls routed through clawproxy **so that** I get verifiable receipts.

**Acceptance Criteria:**
  - Accept Authorization header API key
  - Return provider response
  - Attach _receipt with hashes


### CPX-US-002 — Ed25519 receipt signing
**As a** verifier, **I want** cryptographically signed receipts **so that** trust tiers are verifiable.

**Acceptance Criteria:**
  - Sign receipts with proxy key
  - Expose proxy DID + public key
  - Fail closed if key missing


### CPX-US-003 — Provider endpoint allowlist
**As a** security engineer, **I want** no arbitrary endpoint proxying **so that** SSRF is prevented.

**Acceptance Criteria:**
  - Only known provider endpoints allowed
  - Reject unknown provider
  - Log blocked attempts


### CPX-US-004 — Google/Gemini routing
**As a** agent, **I want** Gemini calls supported **so that** I can choose my provider.

**Acceptance Criteria:**
  - Route to models/{model}:generateContent
  - Include usage metadata
  - Validate required model field


### CPX-US-005 — Receipt verification endpoint
**As a** platform, **I want** to validate receipts **so that** I can automate trust tiers.

**Acceptance Criteria:**
  - Provide /v1/verify-receipt
  - Validate signature
  - Return provider/model claims


### CPX-US-006 — Rate limits and quotas
**As a** operator, **I want** to limit abuse **so that** proxy remains stable.

**Acceptance Criteria:**
  - Rate limit by DID/IP
  - Return 429 on limit
  - Expose usage headers


## 8) Success Metrics
- Receipts issued/day
- Median proxy latency
- % signed receipts

---

*Generated for Claw Bureau monorepo. All PRDs follow a uniform structure for Ralph execution.*
