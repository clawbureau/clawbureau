#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';

const REPO_ROOT = process.cwd();

const PRD_DIR = path.join(REPO_ROOT, 'docs', 'prds');
const SCHEMA_ROOT = path.join(REPO_ROOT, 'packages', 'schema');

const SERVICE_SLUG_MAP = {
  clawledger: 'ledger',
  clawescrow: 'escrow',
};

function exists(p) {
  try {
    fs.accessSync(p);
    return true;
  } catch {
    return false;
  }
}

function listFilesRecursive(dir) {
  const out = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const e of entries) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...listFilesRecursive(p));
    else out.push(p);
  }
  return out;
}

function loadSchemaIds() {
  const ids = new Set();
  if (!exists(SCHEMA_ROOT)) return ids;

  const jsonFiles = listFilesRecursive(SCHEMA_ROOT).filter((p) => p.endsWith('.json'));
  for (const file of jsonFiles) {
    try {
      const raw = fs.readFileSync(file, 'utf8');
      const obj = JSON.parse(raw);
      if (typeof obj.$id === 'string' && obj.$id.trim().length > 0) ids.add(obj.$id);
    } catch {
      // Ignore parse errors; schemas should be valid JSON, but lint should not crash the repo.
    }
  }

  return ids;
}

function lint() {
  const errors = [];

  if (!exists(PRD_DIR)) {
    errors.push({ file: 'docs/prds', message: 'Missing docs/prds directory' });
    return errors;
  }

  const schemaIds = loadSchemaIds();

  const prdFiles = fs
    .readdirSync(PRD_DIR)
    .filter((f) => f.endsWith('.md'))
    .sort();

  for (const prdFile of prdFiles) {
    const relPath = path.join('docs', 'prds', prdFile);
    const absPath = path.join(PRD_DIR, prdFile);
    const content = fs.readFileSync(absPath, 'utf8');

    // 1) Status block (high-signal requirement)
    if (!content.startsWith('> **Type:**')) {
      errors.push({ file: relPath, message: 'Missing status block (must start with "> **Type:**")' });
    }
    if (!content.includes('> **Status:**')) {
      errors.push({ file: relPath, message: 'Missing "> **Status:**" in status block' });
    }
    if (!content.includes('> **Last reviewed:**')) {
      errors.push({ file: relPath, message: 'Missing "> **Last reviewed:**" in status block' });
    }

    // 2) Implementation status section
    if (!content.includes('## Implementation status')) {
      errors.push({ file: relPath, message: 'Missing "## Implementation status" section' });
    }

    // 3) If a service-level tracker exists, require the PRD to link it.
    const slug = prdFile.replace(/\.md$/, '');
    const serviceSlug = SERVICE_SLUG_MAP[slug] ?? slug;
    const serviceDir = path.join(REPO_ROOT, 'services', serviceSlug);

    const servicePrd = path.join(serviceDir, 'prd.json');
    const serviceProgress = path.join(serviceDir, 'progress.txt');

    if (exists(servicePrd) && exists(serviceProgress)) {
      const prdRef = `services/${serviceSlug}/prd.json`;
      const progressRef = `services/${serviceSlug}/progress.txt`;

      if (!content.includes(prdRef)) {
        errors.push({
          file: relPath,
          message: `Service tracker exists but PRD does not reference it: ${prdRef}`,
        });
      }
      if (!content.includes(progressRef)) {
        errors.push({
          file: relPath,
          message: `Service tracker exists but PRD does not reference it: ${progressRef}`,
        });
      }
    }

    // 4) Validate referenced schema files exist (when referenced)
    const schemaFileRefs = [...content.matchAll(/packages\/schema\/[A-Za-z0-9_\-\/\.]+\.json/g)].map(
      (m) => m[0]
    );

    for (const ref of schemaFileRefs) {
      const refAbs = path.join(REPO_ROOT, ref);
      if (!exists(refAbs)) {
        errors.push({ file: relPath, message: `References missing schema file: ${ref}` });
      }
    }

    // 5) Validate schema $id references exist (when present)
    const schemaIdRefs = [...content.matchAll(/https?:\/\/schemas\.clawbureau\.org\/[A-Za-z0-9_\-\/\.]+/g)].map(
      (m) => m[0]
    );

    for (const schemaId of schemaIdRefs) {
      if (!schemaIds.has(schemaId)) {
        errors.push({ file: relPath, message: `References unknown schema $id: ${schemaId}` });
      }
    }
  }

  return errors;
}

const errors = lint();

if (errors.length > 0) {
  console.error('PRD lint failed:');
  for (const e of errors) {
    console.error(`- ${e.file}: ${e.message}`);
  }
  process.exit(1);
}

console.log('PRD lint OK');
