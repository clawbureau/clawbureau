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
    'Envelope version not recognized. Ensure envelope_version is "1" for clawsig v0.1. If you are using a newer version, upgrade: npm install -g @clawbureau/clawverify-cli@latest',
  UNKNOWN_TYPE:
    'Envelope type not recognized. Supported types: proof_bundle, gateway_receipt, tool_receipt, side_effect_receipt, human_approval_receipt, export_bundle.',
  UNKNOWN_ALGORITHM:
    'Hash or signature algorithm not recognized. Clawsig v0.1 supports Ed25519 for signatures and SHA-256 for hashing.',
  UNKNOWN_HASH_ALGORITHM:
    'Hash algorithm not recognized. Use "SHA-256". BLAKE3 support is planned for v0.2.',
  UNKNOWN_ENVELOPE_TYPE:
    'Envelope type not recognized. Check the envelope_type field matches a registered type.',
  UNKNOWN_ENVELOPE_VERSION:
    'Envelope version not recognized. Check envelope_version is "1".',

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

  // ── Receipt ───────────────────────────────────────────
  RECEIPT_BINDING_MISMATCH:
    'Receipt binding (run_id or event_hash) does not match the bundle. Check that the receipt was generated during the same run.',
  RECEIPT_VERIFICATION_FAILED:
    'A receipt envelope failed verification. Check the receipt\'s signature and signer_did against the config allowlist.',

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
