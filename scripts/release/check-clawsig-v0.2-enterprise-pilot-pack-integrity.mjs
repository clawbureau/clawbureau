#!/usr/bin/env node
/**
 * Deterministic integrity guard for the enterprise pilot pack checklist.
 *
 * Verifies detached digest equality across:
 * 1) SHA-256(file bytes) of checklist JSON
 * 2) digest line in pilot markdown
 * 3) signature message suffix in pilot checklist signature envelope
 */

import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '../..');

const CHECKLIST_JSON_PATH =
  'docs/pilot/clawsig-v0.2-enterprise-pilot-pack-checklist.v1.json';
const PILOT_MD_PATH = 'docs/pilot/clawsig-v0.2-enterprise-pilot-pack.md';
const PILOT_SIG_PATH =
  'proofs/docs/pilot/ADP-US-003-enterprise-pilot-pack/pilot-pack-checklist.sig.json';

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
    /^pilot-pack-checklist:clawsig-v0\.2\.0:([0-9a-f]{64})$/i
  );
  return match?.[1]?.toLowerCase() ?? null;
}

function run() {
  const issues = [];

  const checklistJsonRaw = readUtf8(CHECKLIST_JSON_PATH);
  const pilotMdRaw = readUtf8(PILOT_MD_PATH);
  const pilotSigRaw = readUtf8(PILOT_SIG_PATH);

  let checklistJson;
  let pilotSig;

  try {
    checklistJson = JSON.parse(checklistJsonRaw);
  } catch {
    issues.push('Pilot checklist JSON is not valid JSON');
  }

  try {
    pilotSig = JSON.parse(pilotSigRaw);
  } catch {
    issues.push('Pilot checklist signature file is not valid JSON');
  }

  const fileSha256 = sha256HexFromFile(CHECKLIST_JSON_PATH);
  const markdownDigest = extractMarkdownDigest(pilotMdRaw);
  const signatureMessage = pilotSig?.message ?? null;
  const signatureDigest = extractSignatureDigest(signatureMessage);

  if (!checklistJson || typeof checklistJson !== 'object') {
    issues.push('Pilot checklist JSON object could not be parsed');
  } else {
    if (Object.prototype.hasOwnProperty.call(checklistJson, 'checklist_sha256')) {
      issues.push(
        'Self-referential checklist_sha256 is forbidden; use detached_signature_message model'
      );
    }

    if (checklistJson.integrity_model !== 'detached_signature_message') {
      issues.push('integrity_model must be "detached_signature_message"');
    }

    if (checklistJson.signature_artifact !== PILOT_SIG_PATH) {
      issues.push(`signature_artifact must equal ${PILOT_SIG_PATH}`);
    }
  }

  if (!markdownDigest) {
    issues.push('Could not find sha256 digest line in pilot markdown');
  }

  if (!signatureDigest) {
    issues.push(
      'Signature message must match pilot-pack-checklist:clawsig-v0.2.0:<64-hex-digest>'
    );
  }

  if (markdownDigest && fileSha256 !== markdownDigest) {
    issues.push(
      `Pilot markdown digest mismatch (file=${fileSha256}, markdown=${markdownDigest})`
    );
  }

  if (signatureDigest && fileSha256 !== signatureDigest) {
    issues.push(
      `Pilot signature digest mismatch (file=${fileSha256}, signature=${signatureDigest})`
    );
  }

  const result = {
    ok: issues.length === 0,
    pilot_line: 'clawsig-v0.2.0-enterprise-pilot',
    integrity_model: checklistJson?.integrity_model ?? null,
    checklist_json: CHECKLIST_JSON_PATH,
    checklist_markdown: PILOT_MD_PATH,
    signature_file: PILOT_SIG_PATH,
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
