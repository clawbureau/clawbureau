import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

import { hintForReasonCode } from '../src/hints';

function uniqueSorted(values: string[]): string[] {
  return [...new Set(values)].sort((a, b) => a.localeCompare(b));
}

function extractVerificationErrorCodes(typesSource: string): string[] {
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

function extractRegistryCodes(registrySource: string): Set<string> {
  return new Set(
    uniqueSorted(
      [...registrySource.matchAll(/`([A-Z][A-Z0-9_]+)`/g)].map((m) => m[1])
    )
  );
}

describe('reason-code parity', () => {
  const __dirname = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.resolve(__dirname, '../../..');

  const typesPath = path.join(repoRoot, 'services/clawverify/src/types.ts');
  const registryPath = path.join(
    repoRoot,
    'docs/specs/clawsig-protocol/REASON_CODE_REGISTRY.md'
  );
  const scriptPath = path.join(
    repoRoot,
    'scripts/protocol/check-reason-code-parity.mjs'
  );

  const verifierCodes = extractVerificationErrorCodes(
    fs.readFileSync(typesPath, 'utf8')
  );
  const registryCodes = extractRegistryCodes(fs.readFileSync(registryPath, 'utf8'));

  it('every verifier reason code has a CLI hint', () => {
    const missingHints = verifierCodes.filter((code) => !hintForReasonCode(code));
    expect(missingHints).toEqual([]);
  });

  it('every verifier reason code is present in protocol registry', () => {
    const missingRegistryEntries = verifierCodes.filter(
      (code) => !registryCodes.has(code)
    );
    expect(missingRegistryEntries).toEqual([]);
  });

  it('parity checker script succeeds', () => {
    const result = spawnSync('node', [scriptPath], {
      cwd: repoRoot,
      encoding: 'utf8',
    });

    if (result.status !== 0) {
      throw new Error(
        `check-reason-code-parity failed:\nstdout:\n${result.stdout}\n\nstderr:\n${result.stderr}`
      );
    }

    expect(result.status).toBe(0);
  });
});
