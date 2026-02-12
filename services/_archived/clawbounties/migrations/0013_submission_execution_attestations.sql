-- Store execution attestation evidence for sandbox-tier submissions (CEA-US-010)

ALTER TABLE submissions ADD COLUMN execution_attestations_json TEXT;
