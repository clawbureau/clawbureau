#!/usr/bin/env node

import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { chromium } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

function parseArgs(argv) {
  const args = {
    baseUrl: 'https://staging.clawbounties.com',
    uiPath: '/duel',
    adminKey: '',
    workerDid: 'did:key:z6MkneMkZqwqRiU5mJzSG3kDwzt9P8C59N4NGTfBLfSGE7c7',
    bountyId: null,
    outputDir: '',
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--base-url') {
      args.baseUrl = argv[i + 1] ?? args.baseUrl;
      i += 1;
      continue;
    }
    if (arg === '--ui-path') {
      args.uiPath = argv[i + 1] ?? args.uiPath;
      i += 1;
      continue;
    }
    if (arg === '--admin-key') {
      args.adminKey = argv[i + 1] ?? '';
      i += 1;
      continue;
    }
    if (arg === '--worker-did') {
      args.workerDid = argv[i + 1] ?? args.workerDid;
      i += 1;
      continue;
    }
    if (arg === '--bounty-id') {
      args.bountyId = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--output-dir') {
      args.outputDir = argv[i + 1] ?? '';
      i += 1;
      continue;
    }
  }

  if (!args.adminKey) {
    throw new Error('Missing --admin-key');
  }
  if (!args.outputDir) {
    throw new Error('Missing --output-dir');
  }

  return args;
}

function toRelative(filePath) {
  if (typeof filePath !== 'string' || filePath.length === 0) return filePath;
  return path.relative(process.cwd(), filePath) || filePath;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const outputDir = path.resolve(args.outputDir);
  const screenshotDir = path.join(outputDir, 'screenshots');
  const videoDir = path.join(outputDir, 'videos');

  mkdirSync(screenshotDir, { recursive: true });
  mkdirSync(videoDir, { recursive: true });

  const consoleErrors = [];
  const consoleWarnings = [];
  const runtimeErrors = [];

  let browseOk = false;
  let detailsOk = false;
  let claimOk = false;
  let submitOk = false;

  const timings = {
    browse: 0,
    details: 0,
    claim: 0,
    submit: 0,
  };

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: { width: 1440, height: 960 },
    recordVideo: {
      dir: videoDir,
      size: { width: 1280, height: 720 },
    },
  });

  const page = await context.newPage();
  page.on('console', (msg) => {
    const type = msg.type();
    if (type === 'error') {
      consoleErrors.push(msg.text());
    } else if (type === 'warning') {
      consoleWarnings.push(msg.text());
    }
  });

  page.on('pageerror', (err) => {
    runtimeErrors.push(err?.message ?? String(err));
  });

  const startedAt = performance.now();

  const uiUrl = `${args.baseUrl.replace(/\/$/, '')}${args.uiPath.startsWith('/') ? args.uiPath : `/${args.uiPath}`}`;

  try {
    await page.goto(uiUrl, { waitUntil: 'domcontentloaded', timeout: 60_000 });

    await page.waitForSelector('#adminKey', { timeout: 20_000 });
    await page.waitForSelector('#workerDid', { timeout: 20_000 });
    await page.waitForSelector('#loadBounties', { timeout: 20_000 });
    await page.waitForSelector('#claimBounty', { timeout: 20_000 });
    await page.waitForSelector('#submitBounty', { timeout: 20_000 });
    await page.waitForSelector('#actionStatus', { timeout: 20_000 });

    await page.fill('#adminKey', args.adminKey);
    await page.fill('#workerDid', args.workerDid);

    const browseStart = performance.now();
    await page.click('#loadBounties');
    await page.waitForSelector('[data-testid="bounty-row"]', { timeout: 30_000 });
    timings.browse = Number((performance.now() - browseStart).toFixed(2));
    browseOk = true;

    await page.screenshot({ path: path.join(screenshotDir, '01-browse.png'), fullPage: true });

    const detailsStart = performance.now();
    if (args.bountyId) {
      const specific = page.locator(`[data-testid="bounty-row"][data-bounty-id="${args.bountyId}"]`).first();
      if (await specific.count() > 0) {
        await specific.click();
      } else {
        await page.locator('[data-testid="bounty-row"]').first().click();
      }
    } else {
      await page.locator('[data-testid="bounty-row"]').first().click();
    }

    await page.waitForFunction(() => {
      const node = document.querySelector('#bountyDetails');
      return !!node && (node.textContent ?? '').trim().length > 0;
    }, { timeout: 20_000 });

    timings.details = Number((performance.now() - detailsStart).toFixed(2));
    detailsOk = true;

    await page.screenshot({ path: path.join(screenshotDir, '02-details.png'), fullPage: true });

    const claimStart = performance.now();
    await page.click('#claimBounty');
    await page.waitForFunction(() => {
      const text = (document.querySelector('#actionStatus')?.textContent ?? '').toLowerCase();
      return text.includes('claimed') || text.includes('target_met') || text.includes('replay') || text.includes('decision');
    }, { timeout: 45_000 });
    timings.claim = Number((performance.now() - claimStart).toFixed(2));
    claimOk = true;

    await page.screenshot({ path: path.join(screenshotDir, '03-claim.png'), fullPage: true });

    const submitStart = performance.now();
    await page.click('#submitBounty');
    await page.waitForFunction(() => {
      const text = (document.querySelector('#actionStatus')?.textContent ?? '').toLowerCase();
      return text.includes('pending_review') || text.includes('successful_pending_review') || text.includes('submission');
    }, { timeout: 75_000 });
    timings.submit = Number((performance.now() - submitStart).toFixed(2));
    submitOk = true;

    await page.screenshot({ path: path.join(screenshotDir, '04-submit.png'), fullPage: true });
  } catch (err) {
    runtimeErrors.push(err instanceof Error ? err.message : String(err));
  }

  let axeCritical = 0;
  let axeTotal = 0;
  let axeResult = null;
  try {
    const analysis = await new AxeBuilder({ page }).analyze();
    axeResult = analysis;
    axeTotal = Array.isArray(analysis.violations) ? analysis.violations.length : 0;
    axeCritical = Array.isArray(analysis.violations)
      ? analysis.violations.filter((item) => item?.impact === 'critical').length
      : 0;
  } catch (err) {
    runtimeErrors.push(`AXE_ANALYZE_FAILED:${err instanceof Error ? err.message : String(err)}`);
  }

  const totalDuration = Number((performance.now() - startedAt).toFixed(2));

  const statusText = await page.locator('#actionStatus').first().textContent().catch(() => null);
  const selectedBountyId = await page.evaluate(() => {
    const row = document.querySelector('[data-testid="bounty-row"].is-selected');
    return row instanceof HTMLElement ? row.dataset.bountyId ?? null : null;
  }).catch(() => null);

  const videoPath = await page.video()?.path().catch(() => null);

  const result = {
    schema_version: 'arena_ui_duel_journey.v1',
    generated_at: new Date().toISOString(),
    ui_url: uiUrl,
    selected_bounty_id: selectedBountyId,
    flows: {
      browse: browseOk,
      details: detailsOk,
      claim: claimOk,
      submit: submitOk,
    },
    timings_ms: timings,
    total_duration_ms: totalDuration,
    friction_events:
      Number(consoleWarnings.length) +
      Number(runtimeErrors.length) +
      (timings.claim > 20_000 ? 1 : 0) +
      (timings.submit > 30_000 ? 1 : 0),
    console: {
      error_count: consoleErrors.length,
      warn_count: consoleWarnings.length,
      errors: consoleErrors.slice(0, 80),
      warnings: consoleWarnings.slice(0, 120),
    },
    runtime_errors: runtimeErrors,
    accessibility: {
      total_violations: axeTotal,
      critical_violations: axeCritical,
    },
    action_status_text: statusText,
    artifacts: {
      screenshots: {
        browse: toRelative(path.join(screenshotDir, '01-browse.png')),
        details: toRelative(path.join(screenshotDir, '02-details.png')),
        claim: toRelative(path.join(screenshotDir, '03-claim.png')),
        submit: toRelative(path.join(screenshotDir, '04-submit.png')),
      },
      video: toRelative(videoPath),
      axe_raw: toRelative(path.join(outputDir, 'axe-results.json')),
    },
  };

  if (axeResult) {
    writeFileSync(path.join(outputDir, 'axe-results.json'), `${JSON.stringify(axeResult, null, 2)}\n`);
  }

  writeFileSync(path.join(outputDir, 'journey.json'), `${JSON.stringify(result, null, 2)}\n`);

  await context.close();
  await browser.close();

  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
});
