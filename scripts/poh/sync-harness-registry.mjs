#!/usr/bin/env node

/**
 * Sync PoH harness registry markdown from the canonical JS registry.
 *
 * Usage:
 *   node scripts/poh/sync-harness-registry.mjs
 *   node scripts/poh/sync-harness-registry.mjs --check
 */

import { readFile, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';

function parseArgs(argv) {
  const args = new Set();
  for (const a of argv) {
    if (a.startsWith('--')) args.add(a.slice(2));
  }
  return args;
}

function mdEscape(text) {
  return String(text).replace(/\|/g, '\\|').replace(/\n/g, ' ');
}

function renderKeyValueTable(obj) {
  const entries = Object.entries(obj);
  if (entries.length === 0) return '(none)';
  return entries
    .map(([k, v]) => `- \`${k}\`: ${v}`)
    .join('\n');
}

function renderList(items) {
  if (!items || items.length === 0) return '(none)';
  return items.map((x) => `- ${x}`).join('\n');
}

function renderCodeBlock(lines) {
  if (!lines || lines.length === 0) return '```\n# (none)\n```';
  return `\`\`\`bash\n${lines.join('\n')}\n\`\`\``;
}

async function main() {
  const flags = parseArgs(process.argv.slice(2));
  const check = flags.has('check');

  const here = dirname(fileURLToPath(import.meta.url));
  const repoRoot = join(here, '..', '..');

  const registryPath = join(repoRoot, 'docs/roadmaps/proof-of-harness/harnesses.mjs');
  const outPath = join(repoRoot, 'docs/roadmaps/proof-of-harness/HARNESS_REGISTRY.md');

  if (!existsSync(registryPath)) {
    throw new Error(`Missing registry file: ${registryPath}`);
  }

  const mod = await import(pathToFileURL(registryPath).href);
  const harnesses = mod.harnesses ?? mod.default;
  if (!Array.isArray(harnesses)) {
    throw new Error('Registry did not export an array named "harnesses"');
  }

  const sorted = [...harnesses].sort((a, b) => String(a.id).localeCompare(String(b.id)));

  const relLink = (p) => `../../../${p.replace(/^\/+/, '')}`;

  let md = '';
  md += '# PoH Harness Registry\n\n';
  md +=
    'This file is **generated** from `docs/roadmaps/proof-of-harness/harnesses.mjs`.\n' +
    'Edit the registry, then run `node scripts/poh/sync-harness-registry.mjs`.\n\n';

  md += '## Supported / planned harnesses\n\n';
  md += '| Harness | ID | Kind | Status | Connects via |\n';
  md += '|---|---|---|---|---|\n';
  for (const h of sorted) {
    const connects = Array.isArray(h.connectsVia) && h.connectsVia.length > 0 ? h.connectsVia[0] : '';
    md += `| ${mdEscape(h.displayName)} | \`${mdEscape(h.id)}\` | ${mdEscape(h.kind)} | ${mdEscape(h.status)} | ${mdEscape(connects)} |\n`;
  }

  md += '\n---\n\n';

  for (const h of sorted) {
    md += `## ${h.displayName} (\`${h.id}\`)\n\n`;
    md += `- **Kind:** ${h.kind}\n`;
    md += `- **Status:** ${h.status}\n\n`;

    md += '### Key implementations ("knows of" this harness)\n\n';
    if (Array.isArray(h.knowsOfFiles) && h.knowsOfFiles.length > 0) {
      for (const p of h.knowsOfFiles) {
        md += `- [\`${p}\`](${relLink(p)})\n`;
      }
    } else {
      md += '(none)\n';
    }

    md += '\n### How it connects\n\n';
    md += renderList(h.connectsVia) + '\n\n';

    md += '### Base URL overrides\n\n';
    md += renderKeyValueTable(h.baseUrlOverrides ?? {}) + '\n\n';

    md += '### Upstream auth\n\n';
    md += renderList(h.upstreamAuth) + '\n\n';

    md += '### Recommended commands\n\n';
    md += renderCodeBlock(h.recommendedCommands) + '\n\n';

    md += '### Best practices\n\n';
    md += renderList(h.bestPractices) + '\n\n';

    md += '### Limitations\n\n';
    md += renderList(h.limitations) + '\n\n';

    md += '---\n\n';
  }

  if (check) {
    let existing = '';
    try {
      existing = await readFile(outPath, 'utf-8');
    } catch {
      existing = '';
    }

    if (existing !== md) {
      process.stderr.write(`HARNESS_REGISTRY.md is out of date. Run: node scripts/poh/sync-harness-registry.mjs\n`);
      process.exit(1);
    }

    process.stdout.write('HARNESS_REGISTRY.md is up to date.\n');
    return;
  }

  await writeFile(outPath, md, 'utf-8');
  process.stdout.write(`Wrote ${outPath}\n`);
}

main().catch((err) => {
  process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
