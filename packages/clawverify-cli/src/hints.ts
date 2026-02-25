/**
 * Actionable hints for reason codes.
 *
 * Each hint should tell the user what to check or do next.
 * MUST NOT contain secrets. MUST be safe for CI logs.
 */

const HINTS: Record<string, string> = {
  // ── Pass ──────────────────────────────────────────────
  OK: 'Verification passed. No action required.',
  VALID: 'Verification passed. No action required.',

  // ── Signature ─────────────────────────────────────────
  SIGNATURE_INVALID:
    'The Ed25519 signature does not match the payload. Check that the signing key matches signer_did and the payload was not modified after signing.',
  CO_SIGNATURE_INVALID:
    'A co-signature did not verify against the committed payload hash. Ensure each co-signer signed the exact payload hash and signer_did is correct.',

  // ── Schema ────────────────────────────────────────────
  SCHEMA_VALIDATION_FAILED:
    'The input does not match the expected JSON schema. Run with `--input` pointing to the raw JSON file and check for missing required fields or wrong types.',
  UNKNOWN_SCHEMA_ID:
    'The schema ID is not in the clawsig registry. Ensure you are using a supported envelope type.',
  UNKNOWN_SCHEMA_VERSION:
    'This schema version is not recognized. Upgrade clawverify-cli: npm install -g @clawbureau/clawverify-cli@latest',
  DEPRECATED_SCHEMA:
    'This schema version is deprecated. Migrate to the latest version per the protocol spec.',

  // ── Unknown ───────────────────────────────────────────
  UNKNOWN_VERSION:
    'Envelope version not recognized. Ensure envelope_version is "1" for clawsig v0.2. If you are using a newer version, upgrade: npm install -g @clawbureau/clawverify-cli@latest',
  UNKNOWN_TYPE:
    'Envelope type not recognized. Supported types: proof_bundle, gateway_receipt, tool_receipt, side_effect_receipt, human_approval_receipt, export_bundle.',
  UNKNOWN_ALGORITHM:
    'Hash or signature algorithm not recognized. Clawsig v0.2 supports Ed25519 for signatures and SHA-256 for hashing.',
  UNKNOWN_HASH_ALGORITHM:
    'Hash algorithm not recognized. Use "SHA-256". BLAKE3 inputs are currently fail-closed in this verifier runtime.',
  UNKNOWN_ENVELOPE_TYPE:
    'Envelope type not recognized. Check the envelope_type field matches a registered type.',
  UNKNOWN_ENVELOPE_VERSION:
    'Envelope version not recognized. Check envelope_version is "1".',

  // ── Disclosure ────────────────────────────────────────
  DISCLOSURE_ALGORITHM_UNKNOWN:
    'Selective disclosure algorithm is not allowlisted. Use vir_v2_typed_lexicographical.',
  DISCLOSURE_ROOT_MISMATCH:
    'Selective disclosure Merkle root does not match the committed hash. Recompute leaf hashes and root deterministically.',
  DISCLOSURE_TYPE_MISMATCH:
    'A disclosed leaf value type does not match its declared type. Ensure runtime JSON type and declared leaf.type agree.',

  // ── Hash ──────────────────────────────────────────────
  HASH_MISMATCH:
    'Content hash does not match the declared hash. The payload may have been modified after signing. Regenerate the proof bundle with a fresh signature.',
  HASH_CHAIN_BREAK:
    'Event chain hash linkage is broken. Each event\'s prev_hash_b64u must match the previous event\'s event_hash_b64u. Check event ordering.',

  // ── Invalid ───────────────────────────────────────────
  INVALID_DID:
    'DID is malformed. Expected format: did:key:z6Mk... (Ed25519 multicodec). Check your key generation.',
  INVALID_DID_FORMAT:
    'DID format not supported. Clawsig v0.1 requires did:key with Ed25519. Generate a key with: clawsig init',
  INVALID_JSON:
    'Input is not valid JSON. Check for trailing commas, unescaped characters, or encoding issues.',
  INVALID_ROOT:
    'Merkle/hash root is invalid. Recompute the root from the leaf hashes.',

  // ── Malformed ─────────────────────────────────────────
  MALFORMED_ENVELOPE:
    'Envelope is missing required fields. Required: envelope_version, envelope_type, payload, payload_hash_b64u, hash_algorithm, signature_b64u, algorithm, signer_did, issued_at.',
  MISSING_REQUIRED_FIELD:
    'A required field is missing. Check the error message for which field. See the protocol spec for the full schema.',
  MISSING_EVENT_FIELD:
    'An event chain entry is missing required fields. Each event needs: event_id, run_id, event_type, timestamp, payload_hash_b64u, prev_hash_b64u, event_hash_b64u.',
  MISSING_NONCE:
    'A required nonce is missing from a binding or control-chain context. Provide a deterministic nonce and re-sign.',

  // ── Canonicalization ──────────────────────────────────
  CANONICALIZATION_ERROR:
    'JCS canonicalization failed. The payload may contain values that cannot be canonicalized (e.g., undefined, functions). Ensure all values are JSON-safe.',

  // ── Dependency ────────────────────────────────────────
  DEPENDENCY_MISSING:
    'A required dependency is not available. Check that all referenced files exist and are readable.',
  DEPENDENCY_NOT_CONFIGURED:
    'Governance/allowlist dependency not configured. Pass --config with a clawverify.config.*.v1.json file that lists trusted signer DIDs.',

  // ── Bundle ────────────────────────────────────────────
  PROOF_BUNDLE_INVALID:
    'Proof bundle verification failed. Run the verifier on the individual components (receipts, events) for more detail.',
  PROOF_BUNDLE_AGENT_MISMATCH:
    'The agent DID in the bundle does not match the expected DID. If the agent key was rotated, include a rotation certificate.',
  INCONSISTENT_RUN_ID:
    'Run IDs are inconsistent across bundle elements. All events, receipts, and attestations in a single bundle must share the same run_id.',
  EMPTY_CHAIN:
    'Event chain has no entries. A proof bundle must have at least one event.',
  IDENTITY_CONFLICT:
    'A forbidden DID overlap was detected (for example, aggregate issuer equals member agent DID). Use distinct identities for orchestrator and members.',
  URM_MISSING:
    'A URM reference exists in the bundle but the materialized URM document was not provided to verifier options. Provide the exact URM JSON bytes for offline hash verification.',
  URM_MISMATCH:
    'The provided URM content hash does not match payload.urm.resource_hash_b64u. Regenerate or provide the correct URM artifact.',
  PROMPT_COMMITMENT_MISMATCH:
    'Prompt commitment hashes diverge from the declared prompt-pack/system prompt commitments. Recompute commitments deterministically and re-sign.',
  EVIDENCE_MISMATCH:
    'Deterministic evidence is contradictory for the same subject/event. Resolve conflicting receipts/attestations before signing.',
  CLAIM_NOT_FOUND:
    'A required signed claim or referenced claim path is missing. Ensure all required claims are embedded and referenced correctly.',

  // ── Aggregate ─────────────────────────────────────────
  AGGREGATE_BUNDLE_INVALID:
    'Aggregate bundle structure or invariants failed. Check signer/issuer binding, manifest integrity, and member schema validity.',
  AGGREGATE_SIGNER_MISMATCH:
    'Aggregate envelope signer_did must match payload.issuer_did.',
  AGGREGATE_MEMBER_INVALID:
    'At least one aggregate member failed verification under strict-liability cascade. Verify failing member independently.',
  AGGREGATE_DUPLICATE_MEMBER:
    'Duplicate canonical member hash detected. Remove duplicate members from the aggregate.',
  AGGREGATE_DUPLICATE_BUNDLE_ID:
    'Duplicate bundle_id detected across aggregate members. Each member must represent a distinct bundle.',
  AGGREGATE_DUPLICATE_RUN_ID:
    'Duplicate run_id detected across aggregate members. Each member must represent a distinct run.',
  AGGREGATE_TTL_EXCEEDS_MEMBER:
    'Aggregate expires_at exceeds at least one member expiry. Aggregate TTL cannot outlive member TTL.',
  CAUSAL_AGGREGATE_MEMBER_CONFLICT:
    'Aggregate members contain conflicting causal span semantics for the same run namespace/span_id lineage. Normalize cross-member causal bindings before aggregation.',
  CAUSAL_AGGREGATE_RECEIPT_REPLAY:
    'Aggregate members reuse the same receipt_id with divergent content. Ensure replayed receipt_ids are byte-identical or reissue unique IDs.',
  UNSORTED_MEMBER_ARRAY:
    'Aggregate member array is not lexicographically sorted by canonical hash. Reorder members deterministically before signing.',
  FLEET_SUMMARY_MISMATCH:
    'Declared fleet_summary values do not match computed member metrics. Recompute totals and proof tier before signing.',

  // ── Rate limit ───────────────────────────────────────
  RATE_LIMIT_WINDOW_INVALID:
    'Rate-limit claim window is invalid. Ensure window_start is less than or equal to window_end.',
  RATE_LIMIT_CLAIM_INCONSISTENT:
    'Rate-limit claim fields are inconsistent (missing pairs, conflicting limits, or run mismatch). Normalize claim structure before signing.',
  RATE_LIMIT_EXCEEDED:
    'Observed usage exceeds declared rate-limit maximum. Claims must fail closed when observed usage is above max thresholds.',

  // ── Time ──────────────────────────────────────────────
  EXPIRED_TTL:
    'A TTL-bound envelope or payload has expired for the verification timestamp. Re-sign with a fresh expires_at or verify at an archival timestamp.',
  EXPIRED:
    'The referenced artifact or attestation is expired for current verification context. Refresh/reissue the evidence with valid time bounds.',
  CAUSAL_CLOCK_CONTRADICTION:
    'Timestamp causality is broken (e.g., created_at > issued_at). Fix timestamps before signing.',
  FUTURE_TIMESTAMP_POISONING:
    'issued_at is too far in the future relative to verification time and skew allowance. Correct system clock or issued_at.',

  // ── Causal / coverage hardening ──────────────────────
  CAUSAL_REFERENCE_DANGLING:
    'A causal parent/tool span reference points to a span_id that does not exist in this bundle. Ensure all causal references resolve inside the same bundle.',
  CAUSAL_CYCLE_DETECTED:
    'Causal graph contains a parent-span cycle. Break the cycle so lineage is a DAG.',
  CAUSAL_PHASE_INVALID:
    'binding.phase is invalid. Allowed phases: setup, planning, reasoning, execution, observation, reflection, teardown.',
  CAUSAL_PHASE_TRANSITION_INVALID:
    'Causal phase transition is invalid for the parent/tool lineage. Ensure child phases follow the deterministic automaton (setup→planning→reasoning→execution→observation→reflection→teardown).',
  CAUSAL_CONFIDENCE_OUT_OF_RANGE:
    'attribution_confidence must be a finite number in [0.0, 1.0]. Normalize confidence before signing.',
  CAUSAL_CONFIDENCE_EVIDENCE_INCONSISTENT:
    'attribution_confidence overclaims available evidence class. Use 1.0 only for provable direct lineage, 0.5 for inferred linkage, and 0.0 for unattributed fallback.',
  CAUSAL_BINDING_FIELD_CONFLICT:
    'Causal binding includes conflicting snake_case and camelCase values. Keep canonical snake_case or ensure both forms normalize to identical values.',
  CAUSAL_BINDING_NORMALIZATION_FAILED:
    'Causal binding normalization failed (empty/malformed canonical identifiers). Provide non-empty normalized span identifiers.',
  CAUSAL_RECEIPT_REPLAY_DETECTED:
    'Same receipt_id appears with divergent content. Use unique receipt_ids or exact-content replay only.',
  CAUSAL_SPAN_REUSE_CONFLICT:
    'Same span_id was reused with incompatible semantics (parent/tool/phase/confidence drift). Use one stable semantic definition per span_id.',
  CAUSAL_GRAPH_DISCONNECTED:
    'Causal graph is disconnected in enforce mode. Ensure all non-root spans are connected to a single valid root lineage.',
  CAUSAL_SIDE_EFFECT_ORPHANED:
    'A side-effect receipt is not causally anchored to a known span lineage. Bind side-effect receipts to parent/tool/root span IDs from the same bundle.',
  CAUSAL_HUMAN_APPROVAL_ORPHANED:
    'A human-approval receipt is not causally anchored to a known span lineage. Bind approval receipts to parent/tool/root span IDs from the same bundle.',
  CAUSAL_POLICY_PROFILE_INVALID:
    'causal_policy_profile is invalid. Use one of: compat, strict.',
  CAUSAL_POLICY_PROFILE_DOWNGRADE:
    'Strict causal policy profile rejected weaker override modes. Remove downgrade overrides or use compat profile explicitly.',
  COVERAGE_CLDD_DISCREPANCY_ENFORCED:
    'CLDD runtime telemetry disagrees with coverage attestation under enforce mode. Reconcile sentinel telemetry with attested coverage metrics.',

  // ── Receipt ───────────────────────────────────────────
  RECEIPT_BINDING_MISMATCH:
    'Receipt binding (run_id or event_hash) does not match the bundle. Check that the receipt was generated during the same run.',
  RECEIPT_VERIFICATION_FAILED:
    'A receipt envelope failed verification. Check the receipt\'s signature and signer_did against the config allowlist.',
  INCLUSION_PROOF_INVALID:
    'Transparency/log inclusion proof verification failed. Regenerate proof material and verify root signature + audit path against the referenced leaf hash.',
  REVOKED:
    'Evidence is explicitly revoked by policy or revocation list. Refresh with non-revoked attestations/keys.',

  // ── Side effect ───────────────────────────────────────
  SIDE_EFFECT_UNKNOWN_CLASS:
    'Side-effect receipt effect_class not recognized. Supported classes: network_egress, filesystem_write, external_api_write.',
  SIDE_EFFECT_AGENT_MISMATCH:
    'Side-effect receipt agent_did does not match the bundle agent_did.',

  // ── Human approval ────────────────────────────────────
  HUMAN_APPROVAL_UNKNOWN_TYPE:
    'Approval type not recognized. Supported types: explicit_approve, explicit_deny, auto_approve, timeout_deny.',
  HUMAN_APPROVAL_AGENT_MISMATCH:
    'Human approval receipt agent_did does not match the bundle agent_did.',

  // ── Commit sig ────────────────────────────────────────
  COMMIT_MESSAGE_INVALID:
    'Commit sig message format is wrong. Expected: "commit:<40-char-hex-sha>". Generate with: node scripts/did-work/sign-message.mjs "commit:$(git rev-parse HEAD)"',
  COMMIT_NOT_FOUND:
    'The signed commit SHA was not found in the current checkout. Ensure you are in the correct git repo and branch.',

  // ── Config ────────────────────────────────────────────
  CONFIG_ERROR:
    'Configuration error. Check the config file is valid JSON and matches the clawverify.config.*.v1 schema.',
  USAGE_ERROR:
    'Invalid command usage. Run: clawverify --help',
  INTERNAL_ERROR:
    'An unexpected internal error occurred. This is a bug — please report it at https://github.com/clawbureau/clawbureau/issues',
  PARSE_ERROR:
    'Input parsing failed for a structured protocol artifact. Validate JSON shape/encoding and retry with canonical payload form.',

  // ── Control chain ─────────────────────────────────────
  CONTROL_CHAIN_NOT_FOUND:
    'Required control chain entries are missing. Include the referenced chain for offline verification.',
  CONTROL_CHAIN_CONTEXT_MISMATCH:
    'Control chain context does not match the proof bundle context (subject/run/scope mismatch). Rebind control-chain evidence to the exact bundle context.',

  // ── Token control ─────────────────────────────────────
  TOKEN_CONTROL_SCOPE_HASH_MISMATCH:
    'Token-control scope hash does not match expected canonical scope hash. Recompute scope hash from canonical claims.',
  TOKEN_CONTROL_AUDIENCE_MISMATCH:
    'Token-control audience does not match expected audience binding. Mint token for the correct verifier audience.',
  TOKEN_CONTROL_SCOPE_MISSING:
    'Token-control claims are missing required scope fields. Include scope claim and corresponding canonical hash.',
  TOKEN_CONTROL_TRANSITION_FORBIDDEN:
    'Token-control chain transition is forbidden by policy (invalid state transition).',
  TOKEN_CONTROL_CHAIN_MISSING:
    'Token-control chain evidence is missing. Provide the complete chain for offline verification.',
  TOKEN_CONTROL_SUBJECT_MISMATCH:
    'Token-control subject does not match expected DID/subject binding.',
  TOKEN_CONTROL_KEY_UNKNOWN:
    'Token-control key identifier is not in allowlisted key material. Add/rotate key metadata before issuing tokens.',
  TOKEN_CONTROL_KEY_EXPIRED:
    'Token-control signing key is expired. Reissue with an active key.',
  TOKEN_CONTROL_TRANSPARENCY_STALE:
    'Token-control transparency anchor is stale beyond freshness bound. Refresh transparency state before verification.',
  TOKEN_CONTROL_TRANSPARENCY_KID_UNKNOWN:
    'Transparency key ID is unknown for token-control verification. Sync transparency keyset.',
  TOKEN_CONTROL_TRANSPARENCY_KID_EXPIRED:
    'Transparency key ID is expired for token-control verification. Rotate to active transparency key material.',

  // ── Model identity ────────────────────────────────────
  MODEL_IDENTITY_HASH_MISMATCH:
    'Model identity hash does not match. The model claim in receipts does not match the event chain evidence.',
  MODEL_IDENTITY_MISSING_DEFAULTED:
    'No model identity evidence found. The bundle will be verified but model identity will be "opaque".',
  MODEL_IDENTITY_OPAQUE:
    'Model identity cannot be verified. The gateway did not provide model fingerprint evidence.',
  MODEL_IDENTITY_HETEROGENEOUS:
    'Multiple different models detected in a single bundle. Each bundle should represent one agent run with consistent model usage.',
};

/**
 * Look up an actionable hint for a reason code.
 * Returns undefined if no hint is registered (callers should not emit a hint field).
 */
export function hintForReasonCode(code: string): string | undefined {
  return HINTS[code];
}

/**
 * Structured reason-code explanation for --json output.
 */
export interface ReasonCodeExplanation {
  code: string;
  severity: 'PASS' | 'FAIL' | 'ERROR' | 'UNKNOWN';
  description: string;
  remediation: string;
}

/**
 * Return a structured explanation object for a reason code.
 * Used by `clawverify explain <CODE> --json`.
 */
export function explainReasonCodeJson(code: string): ReasonCodeExplanation {
  const hint = HINTS[code];

  let severity: ReasonCodeExplanation['severity'];
  if (code === 'OK' || code === 'VALID') {
    severity = 'PASS';
  } else if (
    code === 'INTERNAL_ERROR' ||
    code === 'USAGE_ERROR' ||
    code === 'CONFIG_ERROR' ||
    code === 'PARSE_ERROR' ||
    code === 'CANONICALIZATION_ERROR'
  ) {
    severity = 'ERROR';
  } else if (hint) {
    severity = 'FAIL';
  } else {
    severity = 'UNKNOWN';
  }

  return {
    code,
    severity,
    description: hint ?? `Unknown reason code: ${code}`,
    remediation: hint ?? 'See the full reason code registry for details.',
  };
}

/**
 * Full explanation: reason code + meaning + hint.
 * Used by `--explain` flag.
 */
export function explainReasonCode(code: string): string {
  const hint = HINTS[code];
  if (!hint) {
    return `${code}: Unknown reason code. This code is not in the hint registry.\n\nSee: https://github.com/clawbureau/clawbureau/blob/main/docs/specs/clawsig-protocol/REASON_CODE_REGISTRY.md`;
  }
  return `${code}\n\n${hint}\n\nFull registry: https://github.com/clawbureau/clawbureau/blob/main/docs/specs/clawsig-protocol/REASON_CODE_REGISTRY.md`;
}
