# CPL-US-006-ECON: @clawbureau/clawsig-sdk Integration Notes

## What Was Tested

Wired `smoke-econ-risk-loss-resolve-loop-receipted.mjs` to use the clawsig-sdk:
- `createRun()` → create a run with harness metadata
- `run.recordEvent()` → record run_start and run_end events
- `run.recordToolCall()` → record each HTTP call (4 calls per run)
- `run.finalize()` → produce signed proof bundle + URM

## What Worked Well

1. **API ergonomics**: `createRun()` + `recordToolCall()` + `finalize()` is a clean 3-step flow
2. **Key management**: `importKeyPairJWK()` / `exportKeyPairJWK()` makes key persistence trivial
3. **Hash-linked chain**: Event chain builds automatically — no manual prev_hash wiring
4. **Tool receipts**: `recordToolCall()` captures args/result hashes + latency + status cleanly
5. **URM generation**: Automatic input/output resource descriptors with hash linking

## SDK Gaps (for Agent A)

### Gap 1: Schema mismatch — `tool_receipts` not in `proof_bundle.v1.json`

**Severity**: BLOCKING for offline verification

The SDK correctly emits `payload.tool_receipts` (array of `ToolReceiptPayload`), but the
`proof_bundle.v1.json` schema has `additionalProperties: false` and doesn't include
`tool_receipts`, `side_effect_receipts`, or `human_approval_receipts` as allowed properties.

The individual schemas exist (`tool_receipt.v1.json`, `side_effect_receipt.v1.json`,
`human_approval_receipt.v1.json`) but aren't referenced from the proof bundle schema.

**Result**: `clawverify-cli verify proof-bundle` returns `FAIL` with:
```
SCHEMA_VALIDATION_FAILED: proof_bundle_envelope.v1: [additionalProperties]
must NOT have additional properties: tool_receipts
```

**Fix needed**: Add `tool_receipts`, `side_effect_receipts`, `human_approval_receipts`
array properties to `proof_bundle.v1.json`, each referencing their respective schemas.

### Gap 2: No `hashJsonB64u` re-export for ergonomic resource descriptors

When building `FinalizeOptions.inputs/outputs`, callers need to provide `hashB64u` for
each `ResourceDescriptor`. The SDK exports `hashJsonB64u` which works, but it would be
more ergonomic to have a helper like `describeResource(type, data, metadata?)` that
hashes automatically.

**Workaround**: Import `hashJsonB64u` directly and compute hashes manually.

### Gap 3: No built-in "tool-call-only" mode

For scripts that don't use LLM proxy calls (pure API automation), you still need to
provide `proxyBaseUrl` in the config even though it's never used. A `createToolRun()`
factory that omits proxy config would be cleaner.

**Workaround**: Pass any URL — it's never fetched for tool-only runs.

### Gap 4: Auth redaction not built-in

Authorization headers in tool call args get hashed as-is. For defense-in-depth, the SDK
could auto-redact known auth headers before hashing (or at least warn). Currently the
caller must sanitize manually.

**Workaround**: Manually redact `authorization` header in args before passing to
`recordToolCall()`.

## Verification Status

| Env | Tool Receipts | Events | Bundle Written | Offline Verify |
|-----|--------------|--------|----------------|----------------|
| Staging | 4 | 6 | ✅ | ❌ (Gap 1) |
| Prod | 4 | 6 | ✅ | ❌ (Gap 1) |

Offline verification will pass once Gap 1 (schema update) is resolved by Agent A.

## Recommendations

1. **Agent A**: Update `proof_bundle.v1.json` to include `tool_receipts` array property
2. **Agent A**: Rebuild `clawverify-core` + `clawverify-cli` after schema update
3. **Then**: Re-run `clawverify-cli verify proof-bundle` to confirm PASS
4. **Nice-to-have**: Add `createToolRun()` factory for non-LLM automation scripts
