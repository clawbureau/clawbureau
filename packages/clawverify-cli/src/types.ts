export type CliKind = 'proof_bundle' | 'export_bundle';

export type CliStatus = 'PASS' | 'FAIL' | 'ERROR';

export interface CliOutputBase {
  status: CliStatus;
  verified_at: string;
  reason_code: string;
  reason: string;
}

export interface CliVerifyOutput extends CliOutputBase {
  kind: CliKind;
  input: {
    path: string;
    /** Optional config path (if provided explicitly). */
    config_path?: string;
  };

  /** Raw verifier output (intentionally preserved for offline parity/debugging). */
  verification?: unknown;
}

export interface CliErrorOutput extends CliOutputBase {
  kind?: CliKind;
  input?: {
    path?: string;
    config_path?: string;
  };
}

export type CliOutput = CliVerifyOutput | CliErrorOutput;

export interface ClawverifyConfigV1 {
  config_version: '1';
  allowlists?: {
    gateway_receipt_signer_dids?: string[];
    web_receipt_signer_dids?: string[];
    attestation_signer_dids?: string[];
    execution_attestation_signer_dids?: string[];
    derivation_attestation_signer_dids?: string[];
    audit_result_attestation_signer_dids?: string[];
  };
}

export interface ResolvedVerifierConfig {
  gatewayReceiptSignerDids: string[];
  webReceiptSignerDids: string[];
  attestationSignerDids: string[];
  executionAttestationSignerDids: string[];
  derivationAttestationSignerDids: string[];
  auditResultAttestationSignerDids: string[];
}
