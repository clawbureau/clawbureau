#!/usr/bin/env node

/**
 * Validate PoH harness registry invariants.
 *
 * Usage:
 *   node scripts/poh/validate-harness-registry.mjs
 */

import { existsSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';

const ALLOWED_KINDS = new Set(['native', 'external-cli', 'sdk']);
const ALLOWED_STATUSES = new Set(['supported', 'experimental', 'planned']);

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function main() {
  const here = dirname(fileURLToPath(import.meta.url));
  const repoRoot = join(here, '..', '..');

  const registryPath = join(repoRoot, 'docs/roadmaps/proof-of-harness/harnesses.mjs');
  assert(existsSync(registryPath), `Missing registry file: ${registryPath}`);

  const mod = await import(pathToFileURL(registryPath).href);
  const harnesses = mod.harnesses ?? mod.default;
  assert(Array.isArray(harnesses), 'Registry did not export an array named "harnesses"');

  const ids = new Set();

  for (const [i, h] of harnesses.entries()) {
    assert(h && typeof h === 'object', `Harness[${i}] must be an object`);

    assert(typeof h.id === 'string' && h.id.trim().length > 0, `Harness[${i}] missing id`);
    assert(typeof h.displayName === 'string' && h.displayName.trim().length > 0, `Harness[${h.id}] missing displayName`);
    assert(ALLOWED_KINDS.has(h.kind), `Harness[${h.id}] invalid kind: ${h.kind}`);
    assert(ALLOWED_STATUSES.has(h.status), `Harness[${h.id}] invalid status: ${h.status}`);

    assert(!ids.has(h.id), `Duplicate harness id: ${h.id}`);
    ids.add(h.id);

    const listFields = ['knowsOfFiles', 'connectsVia', 'recommendedCommands', 'upstreamAuth', 'bestPractices', 'limitations'];
    for (const f of listFields) {
      if (h[f] === undefined) continue;
      assert(Array.isArray(h[f]), `Harness[${h.id}] field ${f} must be an array`);
      for (const [j, v] of h[f].entries()) {
        assert(typeof v === 'string', `Harness[${h.id}] field ${f}[${j}] must be a string`);
      }
    }

    if (h.baseUrlOverrides !== undefined) {
      assert(h.baseUrlOverrides && typeof h.baseUrlOverrides === 'object' && !Array.isArray(h.baseUrlOverrides), `Harness[${h.id}] baseUrlOverrides must be an object`);
      for (const [k, v] of Object.entries(h.baseUrlOverrides)) {
        assert(typeof k === 'string' && k.length > 0, `Harness[${h.id}] baseUrlOverrides has invalid key`);
        assert(typeof v === 'string', `Harness[${h.id}] baseUrlOverrides[${k}] must be a string`);
      }
    }

    // Link rot prevention: ensure referenced implementation files exist.
    if (Array.isArray(h.knowsOfFiles)) {
      for (const p of h.knowsOfFiles) {
        const abs = join(repoRoot, p);
        assert(existsSync(abs), `Harness[${h.id}] knowsOfFiles references missing path: ${p}`);
      }
    }
  }

  process.stdout.write(`OK: ${harnesses.length} harnesses validated\n`);
}

main().catch((err) => {
  process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
