import fs from 'node:fs';

const FALLBACK_VERSION = '0.0.0';

function readVersionFromPackageJson(): string {
  try {
    const packageJsonPath = new URL('../package.json', import.meta.url);
    const raw = fs.readFileSync(packageJsonPath, 'utf8');
    const parsed = JSON.parse(raw) as { version?: unknown };

    if (typeof parsed.version === 'string' && parsed.version.trim().length > 0) {
      return parsed.version.trim();
    }
  } catch {
    // fail closed to deterministic fallback string
  }

  return FALLBACK_VERSION;
}

export const CLI_VERSION = readVersionFromPackageJson();

export function formatCliVersion(): string {
  return `clawverify ${CLI_VERSION}`;
}
