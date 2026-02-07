Below is a focused red-team list against the current PoH primitives, based on:

- Spec: `docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md`
- Verifier: `services/clawverify/src/verify-proof-bundle.ts`, `services/clawverify/src/verify-receipt.ts`
- Proxy: `services/clawproxy/src/index.ts`, `services/clawproxy/src/receipt.ts`, `services/clawproxy/src/idempotency.ts`
- Schemas: `packages/schema/poh/proof_bundle.v1.json`, `packages/schema/poh/receipt_binding.v1.json`

---

## 1) Top 25 worker cheat / gaming attacks

| Attack | Impact (what evidence gets corrupted) | Current coverage (caught?) | Mitigation (prefer fail-closed) |
|---|---|---|---|
| 1. Fabricate an event chain with arbitrary `event_hash_b64u` values (only maintain `prev_hash` linkage) | “Tamper-evident” log becomes meaningless; worker can claim any sequence | **Not caught**: verifier **does not recompute** `event_hash_b64u` from header; it only checks linkage (`validateEventChain` in `verify-proof-bundle.ts`). Spec calls this gap (§10 in `ADAPTER_SPEC_v1.md`). | In `clawverify`, recompute every `event_hash_b64u` per canonical header + SHA-256 (spec §4.2) and fail if mismatch. |
| 2. Bind receipts to fake events by choosing any `X-Event-Hash` and including that hash in fabricated chain | Receipts appear “bound” but binding is to attacker-invented hashes, not real event headers | **Not caught** because receipt binding check only requires the hash string be present in the chain (`verifyReceiptEnvelope` in `verify-proof-bundle.ts`). | Fix #1 (recompute event hashes). Additionally require receipt-bound event’s `event_type === "llm_call"` and that the corresponding payload hash exists (see #6/#7). |
| 3. Impersonate another agent in payload: set `payload.agent_did` to victim DID while signing envelope with attacker DID | Marketplace attribution (“by whom”) becomes wrong | **Not caught**: `verifyProofBundle` validates DID format but never enforces `envelope.signer_did === payload.agent_did` (`verify-proof-bundle.ts`). | Fail-closed: require equality of signer and payload agent DID. |
| 4. Self-award “attested/full” tier using fake attestations (structurally valid, bogus signature) | Attestation tier becomes trivially forgeable | **Not caught**: `validateAttestation` checks only structure/expiry, **not signature**; `computeTrustTier` treats `attestations_valid` as meaningful (`verify-proof-bundle.ts`). | Until signature verification exists: do **not** elevate trust tier based on attestations; or require allowlisted attester DIDs + cryptographic verification. |
| 5. Add extra fields (because code doesn’t enforce `additionalProperties:false`) to confuse downstream | “Shadow” claims: embed alternate roots, policy, trust tier, URIs, etc. | **Not caught**: code uses ad-hoc validators; it does not fully enforce JSON schema restrictions from `packages/schema/poh/proof_bundle.v1.json`. | Use Ajv (or equivalent) to validate against schemas strictly; fail on unknown fields everywhere (bundle, events, receipts, attestations). |
| 6. Use `payload_hash_b64u` fields without providing payload blobs anywhere | Event chain is unverifiable in substance; only hashes exist | **Not caught**: verifier never sees payload bytes; `payload_hash_b64u` is only format-checked (`verify-proof-bundle.ts`). | Require payload materialization: event payloads stored as URM resources (or embedded) with fetchable URIs; verifier must hash fetched bytes and match `payload_hash_b64u`. Fail-closed if missing. |
| 7. Claim tool activity/artifacts in event types but omit corresponding outputs in URM | Inflates apparent work done; hides that outputs were produced out-of-band | **Not caught**: URM is only a reference; `validateURM` checks reference shape only (`verify-proof-bundle.ts`). | Make URM retrievable (URI + hash), and verify cross-links: `artifact_written` events must correspond to URM outputs; fail if mismatch. |
| 8. URM substitution: reference a URM hash that verifier never fetches; use URM to assert anything off-chain | URM becomes a non-verified narrative | **Not caught**: only `URMReference` format validated (`validateURM` in `verify-proof-bundle.ts`). | Require URM bytes (inline or fetch-by-URI) and verify `resource_hash_b64u`. Reject if URM cannot be retrieved/hashed. |
| 9. Replay someone else’s receipts + event chain (copy bundle components) and sign as self | Worker “borrows” gateway evidence | **Partially caught / mostly not**: receipt signer is checked (`verify-receipt.ts`), binding checks run/event hash membership, but nothing ties receipts to *agent identity* (no `client_did` binding). | Add `client_did` (or subject DID) into signed receipt payload in `clawproxy` and require it matches `payload.agent_did`. Alternatively require job-scoped CST and verify receipt `token_scope_hash_b64u` equals expected (see #13). |
| 10. Reuse the same `run_id` across multiple jobs/runs to enable replay of bound receipts | Cross-job evidence reuse | **Not caught**: run_id uniqueness is only “recommended” (spec §3.1); verifier doesn’t check global uniqueness. | Marketplace-side replay protection: store seen `(agent_did, run_id)` and/or `(receipt_id)` and reject duplicates. |
| 11. Duplicate the same receipt multiple times inside one bundle | Inflates “receipt count” metrics; may trick heuristics | **Not caught**: `receipts_valid` only checks each verifies; duplicates not checked (`verify-proof-bundle.ts`). | Enforce uniqueness of `receipt_id`, and optionally uniqueness of `(binding.nonce)` per run. |
| 12. Omit `binding.nonce` and issue many receipts for the “same” logical call | Eases receipt spam; complicates de-dupe/accounting | **Not caught**: binding nonce is optional in schema and verifier (`receipt_binding.v1.json`, `verifyReceiptEnvelope`). Proxy idempotency only applies if nonce exists (`clawproxy/src/idempotency.ts`). | Require nonce for all receipts to count toward gateway tier; proxy can enforce `X-Idempotency-Key` required for PoH mode. |
| 13. Use a CST that isn’t job-scoped (or no CST), so receipts aren’t job-attributable | Weakens “this job” binding; enables reuse | **Not caught**: verifier doesn’t check `token_scope_hash_b64u` at all. Proxy may include it (`clawproxy/src/index.ts`). | In `clawbounties`, require a job-issued CST; store expected `token_scope_hash_b64u` and require every receipt has it and matches. Fail-closed for gateway tier. |
| 14. Policy hash confusion: provide a permissive WPC so proxy allows disallowed models/tools while still producing receipts | Receipts attest to a policy, but not the marketplace-required one | **Not caught**: verifier doesn’t compare `binding.policy_hash` to job policy. Proxy injects policy hash (`clawproxy/src/index.ts`). | Marketplace must pass/require the exact WPC; verify each receipt `binding.policy_hash` equals expected job policy hash. Reject otherwise. |
| 15. Bind receipts to non-LLM events (e.g., tool_call) | Weakens semantic meaning of receipt/event binding | **Not caught**: receipt binding only checks event_hash membership, not event_type (`verifyReceiptEnvelope`). | Require referenced event has `event_type === "llm_call"` (or an allowlist) and optionally payload includes provider/model hashable fields. |
| 16. Timestamp games: set event timestamps arbitrarily to fit SLAs; backdate/forward-date | Misleads time-based policy and audit | **Not caught**: ISO format only (`isValidIsoDate`); no monotonic check (`verify-proof-bundle.ts`). | Enforce monotonic non-decreasing timestamps; enforce `run_start`/`run_end` window; enforce receipt timestamp within window (±skew). |
| 17. Receipt/event time mismatch: bind receipt to event but receipt timestamp doesn’t align | Weakens causality (receipt could be from elsewhere) | **Not caught**: verifier doesn’t compare receipt `timestamp` to event `timestamp` (`verify-proof-bundle.ts`). | Require `receipt.timestamp >= bound_event.timestamp` and within configured max delta. |
| 18. Numeric NaN/Infinity injection in receipt fields (`tokens_input`, etc.) | Downstream logic corruption (cost calc, thresholds) | **Not caught**: `typeof === 'number'` and `< 0` checks allow NaN (`verify-receipt.ts`). | Use `Number.isFinite` checks for all numeric fields; fail-closed. |
| 19. Very large arrays / objects (events/receipts/metadata) to DoS verifier | Resource exhaustion; verification bypass via timeouts | **Not caught**: no size limits in `verify-proof-bundle.ts` / schema enforcement in code | Add strict limits: max events, max receipts, max metadata size, max string lengths; reject on exceed. |
| 20. Receipt signer format mismatch exploitation during transition (mix legacy `_receipt` bridged into envelope) | Worker supplies “receipt-like” objects that look valid to humans but aren’t verifiable | **Caught if using clawverify**: `verifyReceipt` requires allowlisted `did:key` signer; bridged legacy receipts will fail (`verify-receipt.ts`). But humans might be fooled. | Explicitly label unverified receipts; in adapters/SDK, disable legacy bridging for submissions that claim gateway tier (`packages/clawproof-sdk/src/run.ts` bridges legacy). |
| 21. Fake “harness metadata” (`metadata.harness`) to claim trusted runtime | Audit confusion; potential policy gating bypass | **Not caught**: metadata is unsigned only insofar as it’s inside signed bundle, but it’s self-asserted and unverifiable (`proof_bundle.v1.json`, `verify-proof-bundle.ts`). | Treat harness metadata as informational only (spec already says this). For enforcement, require sandbox attestation (future) or allowlisted recorder attestations. |
| 22. Missing required event types (no `run_start`/`run_end`, no artifact events) | Makes audit incomplete while still “verified” | **Not caught**: event_type is free-form string, no required sequence (`validateEventChain`). Trust tier elevates on any “valid” chain (`computeTrustTier`). | Add PoH policy profiles: require minimum event types and ordering; fail gateway/verified tier if missing. |
| 23. Event_id collisions / reuse | Can confuse correlators, UIs, and cross-checking | **Not caught**: `validateEventChain` doesn’t enforce uniqueness of `event_id` (`verify-proof-bundle.ts`). | Enforce unique `event_id` within run; fail-closed on duplicates. |
| 24. Receipt spam with valid signatures but irrelevant to job (wrong provider/model) | “Gateway tier” without actually using allowed model/policy | **Not caught** in clawverify; proxy enforces WPC only if the provided policy does so (`clawproxy/src/index.ts`). | Marketplace must enforce allowed provider/model by checking receipt payload fields, and require policy hash match (#14). |
| 25. Split-brain logs: do real work out-of-band (local model, manual edits), then generate minimal PoH artifacts post-hoc | Fundamental integrity gap: PoH proves *some* proxied calls occurred, not that they produced the output | **Not solvable in v1**: spec non-goals include proving harness binary integrity / full execution (`ADAPTER_SPEC_v1.md` §1). | Compensate with sandbox tier (execution attestations), reproducible build checks, and marketplace controls (see below). |

---

## 2) “Hard” unsolved problems + compensating controls

These are either explicitly out-of-scope in v1 (per `docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md` §1) or require stronger primitives.

1) **Proving the output was produced by the logged execution** (vs manual edits / out-of-band compute)  
   - Control: require running tests/verification in a marketplace-controlled sandbox; add “sandbox tier” attestations; random audits that reproduce result from the URM inputs.

2) **Proving harness/tooling integrity** (user can patch their harness/recorder)  
   - Control: allowlisted harness distributions, signed binaries, remote attestation (future), and reputation/stake-based incentives.

3) **Attributing gateway usage to the same agent DID** (prevent receipt theft/replay from other agents)  
   - Control: job-scoped CST issuance; include `client_did` (or token subject) as a signed receipt claim; maintain server-side replay DB for receipts.

4) **Confidentiality vs auditability tradeoffs** (hash-only receipts limit what you can verify)  
   - Control: encrypted receipts with controlled disclosure; selective reveals during dispute/human review; require minimal verifiable metadata in cleartext.

5) **Human intent / originality / “no plagiarism”**  
   - Control: marketplace policy + human review + plagiarism detection on patches; stake/slashing on fraud.

---

## 3) Automated verification checks to add (clawverify and/or clawbounties)

### Add to `clawverify` (cryptographic + structural correctness)
1) **Recompute `event_hash_b64u`** for every event per spec canonical header + SHA-256 (gap noted in `ADAPTER_SPEC_v1.md` §10; current code in `validateEventChain` only checks linkage in `verify-proof-bundle.ts`).  
2) **Enforce `envelope.signer_did === payload.agent_did`** (currently missing in `verify-proof-bundle.ts`).  
3) **Strict JSON-schema validation** using `packages/schema/poh/proof_bundle.v1.json` and `receipt_binding.v1.json` (code currently does partial validation and misses `additionalProperties:false`).  
4) **Attestation signature verification or disable attestation-based tiering** (currently `validateAttestation` is shape-only in `verify-proof-bundle.ts`).  
5) **Numeric hardening**: `Number.isFinite` for receipt numeric fields (NaN/Infinity) (`verify-receipt.ts`).  
6) **Uniqueness checks**: event_id unique, receipt_id unique, and optionally nonce unique per run.  
7) **Size/limit checks**: max events/receipts, max string lengths, max metadata size; fail fast before expensive operations.  
8) **Semantic binding checks**: receipt-bound event must be `event_type="llm_call"`; receipt timestamp within allowed skew relative to that event.  
9) **Run consistency checks**: require a single run_id across event chain *and* match URM run_id (once URM is materialized).  
10) **Tier computation hardening**: do not grant “verified” tier from an event chain unless event hashes are recomputed + required event types present.

### Add to `clawbounties` (job/policy enforcement)
1) **Expected WPC hash enforcement**: require each receipt `binding.policy_hash` equals the bounty’s policy hash (#14).  
2) **Expected token scope enforcement**: require each receipt has `token_scope_hash_b64u` matching the job-issued CST (#13).  
3) **Provider/model allowlist**: check receipt payload `provider`/`model` against bounty constraints (independent of worker-supplied policy).  
4) **Replay DB**: store and reject previously-seen `(receipt.signer_did, payload.receipt_id)` and/or `(token_scope_hash, nonce)` across submissions.  
5) **Minimum proof profile**: define per-bounty required evidence (e.g., “must have ≥N receipts”, “must have run_start/run_end”, “must include URM and artifact hashes”).

---

## 4) Top 10 engineering changes (prioritized)

1) **Implement event hash recomputation in `clawverify`** and reject mismatches.  
   - Files: `services/clawverify/src/verify-proof-bundle.ts` (replace/extend `validateEventChain`), spec rules in `docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md` §4.2.

2) **Bind agent identity correctly**: enforce `envelope.signer_did === payload.agent_did`.  
   - File: `services/clawverify/src/verify-proof-bundle.ts`.

3) **Stop treating attestations as meaningful until verified**: either cryptographically verify attestations with an allowlist, or remove tier uplift.  
   - File: `services/clawverify/src/verify-proof-bundle.ts` (`validateAttestation`, `computeTrustTier`).

4) **Adopt strict schema validation (Ajv) everywhere** and enforce `additionalProperties:false`.  
   - Schemas: `packages/schema/poh/proof_bundle.v1.json`, `packages/schema/poh/receipt_binding.v1.json`.  
   - Code: `services/clawverify/src/verify-proof-bundle.ts`, `services/clawverify/src/verify-receipt.ts`.

5) **Make URM verifiable (materialize it)**: require URM bytes inline or fetch-by-URI, then hash-verify against `resource_hash_b64u`.  
   - Current gap: verifier only validates `URMReference` (`validateURM` in `verify-proof-bundle.ts`).

6) **Receipt ↔ agent binding**: add `client_did` (or equivalent) as a signed claim in `GatewayReceiptPayload` emitted by proxy, derived from validated CST subject.  
   - Files: `services/clawproxy/src/index.ts` (CST validation), `services/clawproxy/src/receipt.ts` (`generateReceiptEnvelope`).  
   - Then verify in `clawverify` and/or `clawbounties`.

7) **Job policy enforcement in marketplace**: require `binding.policy_hash` and `token_scope_hash_b64u` match expected bounty values.  
   - Proxy already injects these (`services/clawproxy/src/index.ts`), verifier just needs to check.

8) **Tier definition hardening**: redefine “verified” so a self-signed fabricated chain can’t qualify; require either gateway receipts bound to recomputed events or sandbox attestation.  
   - File: `services/clawverify/src/verify-proof-bundle.ts` (`computeTrustTier`).

9) **Anti-replay & uniqueness**: enforce unique receipt_id and run_id per agent at marketplace ingestion; add a replay database.  
   - (This is marketplace-side state, not purely cryptographic.)

10) **Limit/DoS hardening**: enforce maximum sizes and validate lengths in proxy and verifier.  
   - Proxy binding header length checks: `services/clawproxy/src/idempotency.ts` / `services/clawproxy/src/index.ts`.  
   - Verifier limits: `services/clawverify/src/verify-proof-bundle.ts`.

If you want, I can convert the “mitigations” into an explicit checklist with pass/fail rules (exact error codes) for `clawverify` and a separate “bounty policy profile” spec for `clawbounties`.
