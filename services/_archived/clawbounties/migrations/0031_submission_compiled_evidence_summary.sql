-- CBA-RV-001/CBA-RV-002/CBA-RV-003: compiled evidence attachment contract + normalized reviewer summary

ALTER TABLE submissions ADD COLUMN compiled_evidence_attachment_json TEXT;
ALTER TABLE submissions ADD COLUMN compiled_evidence_summary_json TEXT;
