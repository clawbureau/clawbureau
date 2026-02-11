#!/usr/bin/env npx tsx
/**
 * Weekly growth report for clawea-www.
 *
 * Pulls:
 * - /api/events/summary (date range)
 * - /api/index-queue/status
 *
 * Writes:
 * - reports/growth/weekly-growth-YYYY-MM-DD.json
 * - reports/growth/weekly-growth-YYYY-MM-DD.md
 */

import * as fs from "node:fs";
import * as path from "node:path";

const args = process.argv.slice(2);
const getArg = (name: string) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 && i + 1 < args.length ? args[i + 1] : undefined;
};

const TOKEN = process.env.INDEX_AUTOMATION_TOKEN ?? process.env.CLAWEA_INDEX_AUTOMATION_TOKEN;
if (!TOKEN) {
  console.error("Missing INDEX_AUTOMATION_TOKEN (or CLAWEA_INDEX_AUTOMATION_TOKEN)");
  process.exit(1);
}

const baseUrl = getArg("base") ?? process.env.CLAWEA_BASE_URL ?? "https://clawea.com";
const eventsEndpoint = getArg("events-endpoint") ?? `${baseUrl.replace(/\/+$/, "")}/api/events/summary`;
const queueEndpoint = getArg("queue-endpoint") ?? `${baseUrl.replace(/\/+$/, "")}/api/index-queue/status`;
const leadsEndpoint = getArg("leads-endpoint") ?? `${baseUrl.replace(/\/+$/, "")}/api/leads/status`;
const winnersEndpoint = getArg("winners-endpoint") ?? `${baseUrl.replace(/\/+$/, "")}/api/experiments/winners`;
const days = Math.max(1, Math.min(90, Number(getArg("days") ?? process.env.CLAWEA_GROWTH_DAYS ?? "7")));

const now = new Date();
const stamp = now.toISOString().slice(0, 10);
const outJson = path.resolve(
  getArg("output") ?? path.resolve(import.meta.dirname ?? ".", `../reports/growth/weekly-growth-${stamp}.json`),
);
const outMd = path.resolve(
  getArg("markdown") ?? path.resolve(import.meta.dirname ?? ".", `../reports/growth/weekly-growth-${stamp}.md`),
);

function writeJson(filePath: string, data: unknown): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

function topRows(rows: any[] | undefined, limit = 8): Array<{ key: string; count: number }> {
  if (!Array.isArray(rows)) return [];
  return rows
    .filter((r) => typeof r?.key === "string" && Number.isFinite(Number(r?.count)))
    .slice(0, limit)
    .map((r) => ({ key: String(r.key), count: Number(r.count) }));
}

function bullets(rows: Array<{ key: string; count: number }>, fallback = "- none"): string {
  if (!rows.length) return fallback;
  return rows.map((r) => `- ${r.key}: ${r.count}`).join("\n");
}

function bulletsCta(rows: any[] | undefined, fallback = "- none"): string {
  if (!Array.isArray(rows) || rows.length === 0) return fallback;
  return rows
    .slice(0, 8)
    .map((r) => `- ${r.pageFamily}: views=${r.views}, clicks=${r.clicks}, actions=${r.actions}, actionRate=${r.actionRate}`)
    .join("\n");
}

function bulletsVariant(rows: any[] | undefined, fallback = "- none"): string {
  if (!Array.isArray(rows) || rows.length === 0) return fallback;
  return rows
    .slice(0, 8)
    .map((r) => `- ${r.variantId}: impressions=${r.impressions}, clicks=${r.clicks}, submits=${r.submits}, submitRate=${r.submitRate}`)
    .join("\n");
}

function bulletsWinners(rows: any[] | undefined, fallback = "- none"): string {
  if (!Array.isArray(rows) || rows.length === 0) return fallback;
  return rows
    .slice(0, 10)
    .map((r) => {
      const winner = r?.winner;
      if (!winner) return `- ${r.pageFamily}: no winner yet`;
      const rate = winner.events > 0 ? Number((winner.contactSubmits / winner.events).toFixed(4)) : 0;
      return `- ${r.pageFamily}: ${winner.variant} (events=${winner.events}, submits=${winner.contactSubmits}, submitRate=${rate})`;
    })
    .join("\n");
}

function bulletsLeadStatus(rows: any[] | undefined, fallback = "- none"): string {
  if (!Array.isArray(rows) || rows.length === 0) return fallback;
  return rows
    .slice(0, 8)
    .map((r) => `- ${r.key}: ${r.count}`)
    .join("\n");
}

async function authedJson(url: string, init: RequestInit): Promise<any> {
  const res = await fetch(url, {
    ...init,
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${TOKEN}`,
      ...(init.headers ?? {}),
    },
  });

  const raw = await res.text();
  let parsed: any = raw;
  try {
    parsed = raw ? JSON.parse(raw) : null;
  } catch {
    // keep raw text
  }

  if (!res.ok) {
    throw new Error(`Request failed (${res.status}) ${url}: ${typeof parsed === "string" ? parsed : JSON.stringify(parsed)}`);
  }

  return parsed;
}

async function main() {
  const to = new Date();
  const from = new Date(to.getTime() - days * 24 * 60 * 60 * 1000);

  const events = await authedJson(eventsEndpoint, {
    method: "POST",
    body: JSON.stringify({
      from: from.toISOString(),
      to: to.toISOString(),
      days,
    }),
  });

  const queue = await authedJson(queueEndpoint, { method: "GET" });

  let leads: any = null;
  try {
    leads = await authedJson(leadsEndpoint, { method: "GET" });
  } catch (err: any) {
    leads = { ok: false, error: String(err?.message ?? "LEADS_STATUS_UNAVAILABLE") };
  }

  let winners: any = null;
  try {
    winners = await authedJson(winnersEndpoint, { method: "GET" });
  } catch (err: any) {
    winners = { ok: false, error: String(err?.message ?? "VARIANT_WINNERS_UNAVAILABLE") };
  }

  const report = {
    generatedAt: new Date().toISOString(),
    period: {
      from: from.toISOString(),
      to: to.toISOString(),
      days,
    },
    events,
    queue,
    leads,
    winners,
    highlights: {
      topLandingPages: topRows(events?.breakdown?.topPages, 10),
      searchToClick: {
        queries: Number(events?.totals?.searchQueries ?? 0),
        clicks: Number(events?.totals?.searchResultClicks ?? 0),
        rate: Number(events?.totals?.searchToClickRate ?? 0),
        topQueries: Array.isArray(events?.funnel?.search?.topQueries)
          ? events.funnel.search.topQueries.slice(0, 10)
          : [],
      },
      ctaByPageFamily: Array.isArray(events?.funnel?.ctaByPageFamily)
        ? events.funnel.ctaByPageFamily.slice(0, 12)
        : [],
      variantPerformance: Array.isArray(events?.funnel?.variants)
        ? events.funnel.variants.slice(0, 16)
        : [],
      winnerByFamily: Array.isArray(winners?.report?.winners)
        ? winners.report.winners.slice(0, 16)
        : [],
      leadStatus: Array.isArray(leads?.breakdown?.byStatus)
        ? leads.breakdown.byStatus.slice(0, 12)
        : [],
      indexingBacklog: queue?.summary ?? null,
      indexingLastRun: queue?.lastRun ?? null,
    },
  };

  writeJson(outJson, report);

  const md = `# clawea.com Weekly Growth Report\n\n`
    + `- generatedAt: ${report.generatedAt}\n`
    + `- periodFrom: ${report.period.from}\n`
    + `- periodTo: ${report.period.to}\n`
    + `- days: ${report.period.days}\n\n`
    + `## Top landing pages\n${bullets(report.highlights.topLandingPages)}\n\n`
    + `## Search-to-click performance\n`
    + `- queries: ${report.highlights.searchToClick.queries}\n`
    + `- clicks: ${report.highlights.searchToClick.clicks}\n`
    + `- rate: ${report.highlights.searchToClick.rate}\n\n`
    + `## CTA conversion by page family\n${bulletsCta(report.highlights.ctaByPageFamily)}\n\n`
    + `## Variant performance (events funnel)\n${bulletsVariant(report.highlights.variantPerformance)}\n\n`
    + `## Weekly winner candidates by page family\n${bulletsWinners(report.highlights.winnerByFamily)}\n\n`
    + `## Lead pipeline status\n${bulletsLeadStatus(report.highlights.leadStatus)}\n\n`
    + `## Indexing backlog\n`
    + `- totalEntries: ${Number(queue?.summary?.totalEntries ?? 0)}\n`
    + `- nextAttemptAt: ${queue?.summary?.nextAttemptAt ?? "none"}\n`
    + `- indexnow queued/retry/failed: ${Number(queue?.summary?.byEngine?.indexnow?.queued ?? 0)}/${Number(queue?.summary?.byEngine?.indexnow?.retry ?? 0)}/${Number(queue?.summary?.byEngine?.indexnow?.failed ?? 0)}\n`
    + `- google queued/retry/failed: ${Number(queue?.summary?.byEngine?.google?.queued ?? 0)}/${Number(queue?.summary?.byEngine?.google?.retry ?? 0)}/${Number(queue?.summary?.byEngine?.google?.failed ?? 0)}\n\n`
    + `## Last indexing queue run\n`
    + `${queue?.lastRun
      ? `- runId: ${queue.lastRun.runId}\n- source: ${queue.lastRun.source}\n- processedEntries: ${queue.lastRun.processedEntries}\n- succeeded: ${queue.lastRun.succeeded}\n- scheduledRetry: ${queue.lastRun.scheduledRetry}\n- failed: ${queue.lastRun.failed}`
      : "- no run artifact yet"}
`;

  fs.mkdirSync(path.dirname(outMd), { recursive: true });
  fs.writeFileSync(outMd, md);

  console.log(`Wrote ${outJson}`);
  console.log(`Wrote ${outMd}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
