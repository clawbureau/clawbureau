#!/usr/bin/env node

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '../..');

const TYPES_PATH = path.join(repoRoot, 'services/clawverify/src/types.ts');
const REGISTRY_PATH = path.join(
  repoRoot,
  'docs/specs/clawsig-protocol/REASON_CODE_REGISTRY.md'
);
const HINTS_PATH = path.join(repoRoot, 'packages/clawverify-cli/src/hints.ts');

function uniqueSorted(values) {
  return [...new Set(values)].sort((a, b) => a.localeCompare(b));
}

function extractVerificationErrorCodes(typesSource) {
  const match = typesSource.match(
    /export\s+type\s+VerificationErrorCode\s*=([\s\S]*?);\n/
  );

  if (!match) {
    throw new Error('Could not locate VerificationErrorCode union in services/clawverify/src/types.ts');
  }

  return uniqueSorted(
    [...match[1].matchAll(/'([A-Z0-9_]+)'/g)].map((m) => m[1])
  );
}

function extractRegistryCodes(registrySource) {
  return uniqueSorted(
    [...registrySource.matchAll(/`([A-Z][A-Z0-9_]+)`/g)].map((m) => m[1])
  );
}

function extractHintCodes(hintsSource) {
  const blockMatch = hintsSource.match(
    /const\s+HINTS\s*:\s*Record<string,\s*string>\s*=\s*\{([\s\S]*?)\n\};/
  );

  if (!blockMatch) {
    throw new Error('Could not locate HINTS map in packages/clawverify-cli/src/hints.ts');
  }

  return uniqueSorted(
    [...blockMatch[1].matchAll(/^\s*([A-Z][A-Z0-9_]+)\s*:/gm)].map((m) => m[1])
  );
}

function difference(from, againstSet) {
  return from.filter((code) => !againstSet.has(code));
}

async function main() {
  const [typesSource, registrySource, hintsSource] = await Promise.all([
    fs.readFile(TYPES_PATH, 'utf8'),
    fs.readFile(REGISTRY_PATH, 'utf8'),
    fs.readFile(HINTS_PATH, 'utf8'),
  ]);

  const verifierCodes = extractVerificationErrorCodes(typesSource);
  const registryCodes = extractRegistryCodes(registrySource);
  const hintCodes = extractHintCodes(hintsSource);

  const registrySet = new Set(registryCodes);
  const hintSet = new Set(hintCodes);

  const missingInRegistry = difference(verifierCodes, registrySet);
  const missingInHints = difference(verifierCodes, hintSet);

  const summary = {
    verifier_code_count: verifierCodes.length,
    registry_code_count: registryCodes.length,
    hint_code_count: hintCodes.length,
    missing_in_registry: missingInRegistry,
    missing_in_hints: missingInHints,
  };

  if (missingInRegistry.length > 0 || missingInHints.length > 0) {
    console.error('[reason-code-parity] FAIL');
    console.error(JSON.stringify(summary, null, 2));
    process.exit(1);
  }

  console.log('[reason-code-parity] PASS');
  console.log(JSON.stringify(summary, null, 2));
}

main().catch((error) => {
  console.error('[reason-code-parity] ERROR');
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exit(1);
});
