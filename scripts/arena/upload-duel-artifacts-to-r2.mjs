#!/usr/bin/env node
/**
 * Upload duel batch artifacts (screenshots, journeys, lighthouse) to R2 via the
 * clawbounties upload-artifact endpoint. Then update proof_pack evidence_links
 * with the public URLs via the backfill endpoint.
 *
 * Usage:
 *   node scripts/arena/upload-duel-artifacts-to-r2.mjs \
 *     --artifacts-dir artifacts/ops/arena-productization/2026-02-20T20-11-37Z-agp-us-083-real-duel-batch-v2 \
 *     --base-url https://staging.clawbounties.com \
 *     --admin-key "$ADMIN_KEY"
 */
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import path from 'node:path';

function parseArgs(argv) {
  const args = { artifactsDir: null, baseUrl: null, adminKey: null, dryRun: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => argv[++i];
    if (a === '--artifacts-dir') args.artifactsDir = next();
    else if (a === '--base-url') args.baseUrl = next();
    else if (a === '--admin-key') args.adminKey = next();
    else if (a === '--dry-run') args.dryRun = true;
  }
  return args;
}

function getMimeType(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const mimeTypes = {
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.webm': 'video/webm',
    '.json': 'application/json',
    '.html': 'text/html',
  };
  return mimeTypes[ext] || 'application/octet-stream';
}

function walkDir(dir, base) {
  const files = [];
  for (const entry of readdirSync(dir)) {
    const full = path.join(dir, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) {
      files.push(...walkDir(full, base));
    } else if (stat.isFile() && stat.size > 0 && stat.size < 5 * 1024 * 1024) {
      files.push({ path: full, relative: path.relative(base, full), size: stat.size });
    }
  }
  return files;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (!args.artifactsDir || !args.baseUrl || !args.adminKey) {
    console.error('Usage: --artifacts-dir <dir> --base-url <url> --admin-key <key> [--dry-run]');
    process.exit(1);
  }

  if (!existsSync(args.artifactsDir)) {
    console.error(`Artifacts dir not found: ${args.artifactsDir}`);
    process.exit(1);
  }

  // Find all bounty/contender artifact files
  const files = walkDir(args.artifactsDir, args.artifactsDir);
  console.log(`Found ${files.length} artifact files to upload`);

  if (args.dryRun) {
    for (const f of files) {
      console.log(`  [dry-run] arena/${f.relative} (${f.size} bytes, ${getMimeType(f.path)})`);
    }
    console.log(`\nDry run complete. ${files.length} files would be uploaded.`);
    return;
  }

  let uploaded = 0;
  let failed = 0;
  const urlMap = {};

  for (const f of files) {
    const key = `arena/${f.relative}`;
    const mime = getMimeType(f.path);
    const body = readFileSync(f.path);

    try {
      const resp = await fetch(`${args.baseUrl}/v1/arena/desk/upload-artifact?key=${encodeURIComponent(key)}`, {
        method: 'POST',
        headers: {
          'x-admin-key': args.adminKey,
          'content-type': mime,
        },
        body,
      });

      const result = await resp.json();
      if (resp.ok && result.ok) {
        uploaded += 1;
        urlMap[f.relative] = result.url;
        console.log(`  [ok] ${key} -> ${result.url}`);
      } else {
        failed += 1;
        console.error(`  [fail] ${key}: ${resp.status} ${JSON.stringify(result)}`);
      }
    } catch (err) {
      failed += 1;
      console.error(`  [error] ${key}: ${err.message}`);
    }
  }

  console.log(`\nUpload complete: ${uploaded} uploaded, ${failed} failed`);
  console.log(`URL map: ${JSON.stringify(urlMap, null, 2)}`);
}

main().catch((err) => { console.error(err); process.exit(1); });
