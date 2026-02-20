#!/usr/bin/env node

import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import lighthouse from 'lighthouse';
import * as chromeLauncher from 'chrome-launcher';

function parseArgs(argv) {
  const args = {
    url: '',
    outputDir: '',
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--url') {
      args.url = argv[i + 1] ?? '';
      i += 1;
      continue;
    }
    if (arg === '--output-dir') {
      args.outputDir = argv[i + 1] ?? '';
      i += 1;
      continue;
    }
  }

  if (!args.url) throw new Error('Missing --url');
  if (!args.outputDir) throw new Error('Missing --output-dir');
  return args;
}

function toRelative(filePath) {
  if (typeof filePath !== 'string' || filePath.length === 0) return filePath;
  return path.relative(process.cwd(), filePath) || filePath;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const outputDir = path.resolve(args.outputDir);
  mkdirSync(outputDir, { recursive: true });

  const chrome = await chromeLauncher.launch({
    chromeFlags: ['--headless', '--no-sandbox', '--disable-dev-shm-usage'],
  });

  try {
    const runnerResult = await lighthouse(
      args.url,
      {
        logLevel: 'error',
        output: 'json',
        onlyCategories: ['performance', 'accessibility', 'best-practices', 'seo'],
        port: chrome.port,
      },
      undefined,
    );

    if (!runnerResult?.lhr) {
      throw new Error('LIGHTHOUSE_RESULT_MISSING');
    }

    const lhr = runnerResult.lhr;

    const summary = {
      schema_version: 'arena_ui_duel_lighthouse.v1',
      generated_at: new Date().toISOString(),
      requested_url: lhr.requestedUrl,
      final_url: lhr.finalUrl,
      categories: {
        performance_score: Number((lhr.categories.performance?.score ?? 0).toFixed(4)),
        accessibility_score: Number((lhr.categories.accessibility?.score ?? 0).toFixed(4)),
        best_practices_score: Number((lhr.categories['best-practices']?.score ?? 0).toFixed(4)),
        seo_score: Number((lhr.categories.seo?.score ?? 0).toFixed(4)),
      },
      metrics: {
        fcp_ms: Number(lhr.audits['first-contentful-paint']?.numericValue ?? 0),
        lcp_ms: Number(lhr.audits['largest-contentful-paint']?.numericValue ?? 0),
        tbt_ms: Number(lhr.audits['total-blocking-time']?.numericValue ?? 0),
        cls: Number(lhr.audits['cumulative-layout-shift']?.numericValue ?? 0),
        speed_index_ms: Number(lhr.audits['speed-index']?.numericValue ?? 0),
      },
      warnings: Array.isArray(lhr.runWarnings) ? lhr.runWarnings : [],
      artifacts: {
        raw_lhr_json: toRelative(path.join(outputDir, 'lighthouse.raw.json')),
      },
    };

    writeFileSync(path.join(outputDir, 'lighthouse.raw.json'), `${runnerResult.report}\n`);
    writeFileSync(path.join(outputDir, 'lighthouse.summary.json'), `${JSON.stringify(summary, null, 2)}\n`);

    process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
  } finally {
    await chrome.kill();
  }
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
});
