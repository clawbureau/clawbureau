#!/usr/bin/env node
/**
 * Deterministic integrity guard for the Clawsig v0.2 package release checklist.
 *
 * Verifies that all three detached-digest sources agree:
 * 1) SHA-256(file bytes) of checklist JSON
 * 2) digest line in checklist markdown
 * 3) release-checklist signature message suffix
 */

import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '../..');

const CHECKLIST_JSON_PATH =
  'docs/releases/clawsig-v0.2-package-release-checklist.v1.json';
const CHECKLIST_MD_PATH =
  'docs/releases/clawsig-v0.2-package-release-checklist.md';
const RELEASE_SIG_PATH =
  'proofs/chore/release/CPL-V2-package-prep/release-checklist.sig.json';

function readUtf8(relativePath) {
  const full = path.resolve(repoRoot, relativePath);
  return fs.readFileSync(full, 'utf8');
}

function sha256HexFromFile(relativePath) {
  const full = path.resolve(repoRoot, relativePath);
  const bytes = fs.readFileSync(full);
  return createHash('sha256').update(bytes).digest('hex');
}

function extractMarkdownDigest(markdown) {
  const match = markdown.match(/sha256:\s*([0-9a-f]{64})/i);
  return match?.[1]?.toLowerCase() ?? null;
}

function extractSignatureDigest(message) {
  const match = String(message).match(
    /^release-checklist:clawsig-v0\.2\.0:([0-9a-f]{64})$/i
  );
  return match?.[1]?.toLowerCase() ?? null;
}

function run() {
  const issues = [];

  const checklistJsonRaw = readUtf8(CHECKLIST_JSON_PATH);
  const checklistMdRaw = readUtf8(CHECKLIST_MD_PATH);
  const releaseSigRaw = readUtf8(RELEASE_SIG_PATH);

  let checklistJson;
  let releaseSig;

  try {
    checklistJson = JSON.parse(checklistJsonRaw);
  } catch {
    issues.push('Checklist JSON is not valid JSON');
  }

  try {
    releaseSig = JSON.parse(releaseSigRaw);
  } catch {
    issues.push('Release checklist signature file is not valid JSON');
  }

  const fileSha256 = sha256HexFromFile(CHECKLIST_JSON_PATH);
  const markdownDigest = extractMarkdownDigest(checklistMdRaw);
  const signatureMessage = releaseSig?.message ?? null;
  const signatureDigest = extractSignatureDigest(signatureMessage);

  if (!checklistJson || typeof checklistJson !== 'object') {
    issues.push('Checklist JSON object could not be parsed');
  } else {
    if (Object.prototype.hasOwnProperty.call(checklistJson, 'checklist_sha256')) {
      issues.push(
        'Self-referential checklist_sha256 is forbidden; use detached_signature_message model'
      );
    }

    if (checklistJson.integrity_model !== 'detached_signature_message') {
      issues.push('integrity_model must be "detached_signature_message"');
    }

    if (checklistJson.signature_artifact !== RELEASE_SIG_PATH) {
      issues.push(`signature_artifact must equal ${RELEASE_SIG_PATH}`);
    }
  }

  if (!markdownDigest) {
    issues.push('Could not find sha256 digest line in checklist markdown');
  }

  if (!signatureDigest) {
    issues.push(
      'Signature message must match release-checklist:clawsig-v0.2.0:<64-hex-digest>'
    );
  }

  if (markdownDigest && fileSha256 !== markdownDigest) {
    issues.push(
      `Checklist markdown digest mismatch (file=${fileSha256}, markdown=${markdownDigest})`
    );
  }

  if (signatureDigest && fileSha256 !== signatureDigest) {
    issues.push(
      `Checklist signature digest mismatch (file=${fileSha256}, signature=${signatureDigest})`
    );
  }

  const result = {
    ok: issues.length === 0,
    release_line: 'clawsig-v0.2.0',
    integrity_model: checklistJson?.integrity_model ?? null,
    checklist_json: CHECKLIST_JSON_PATH,
    checklist_markdown: CHECKLIST_MD_PATH,
    signature_file: RELEASE_SIG_PATH,
    file_sha256: fileSha256,
    markdown_digest: markdownDigest,
    signature_digest: signatureDigest,
    signature_message: signatureMessage,
    issues,
  };

  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);

  if (!result.ok) {
    process.exitCode = 1;
  }
}

run();
