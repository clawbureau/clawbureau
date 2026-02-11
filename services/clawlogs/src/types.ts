export interface Env {
  LOGS: DurableObjectNamespace;
  SERVICE_VERSION: string;

  /** Ed25519 seed (base64url, 32 bytes) used to sign root_hash_b64u strings. */
  LOGS_SIGNING_KEY?: string;

  /** Bearer token required for append operations. */
  ADMIN_TOKEN?: string;
}

export interface RootSignature {
  signer_did: string;
  sig_b64u: string;
}

export interface LogRootState {
  root_hash_b64u: string;
  tree_size: number;
}

export interface LogAppendResult extends LogRootState {
  leaf_hash_b64u: string;
  leaf_index: number;
}

export interface LogProofResult extends LogRootState {
  leaf_hash_b64u: string;
  leaf_index: number;
  audit_path: string[];
}
