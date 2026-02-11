#!/usr/bin/env node
/* ------------------------------------------------------------------ */
/*  Query Analytics Engine for cross-domain visit intelligence.       */
/*                                                                    */
/*  Usage:                                                            */
/*    CF_API_TOKEN=... CF_ACCOUNT_ID=... node scripts/query-analytics.mjs          */
/*    CF_API_TOKEN=... CF_ACCOUNT_ID=... node scripts/query-analytics.mjs --days 7 */
/*    CF_API_TOKEN=... CF_ACCOUNT_ID=... node scripts/query-analytics.mjs --domain clawinsure.com */
/* ------------------------------------------------------------------ */

const ACCOUNT_ID =
  process.env.CF_ACCOUNT_ID || "b8f2c66f1848dff476faa874282d781e";
const API_TOKEN = process.env.CF_API_TOKEN;

if (!API_TOKEN) {
  console.error("Set CF_API_TOKEN env var (Cloudflare API token with Analytics read)");
  process.exit(1);
}

const args = process.argv.slice(2);
const days = parseInt(getArg("--days") || "30", 10);
const filterDomain = getArg("--domain");

function getArg(flag) {
  const idx = args.indexOf(flag);
  return idx !== -1 && args[idx + 1] ? args[idx + 1] : null;
}

const DATASET = "claw_domain_visits";
const BASE = `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/analytics_engine/sql`;

async function query(sql) {
  const res = await fetch(BASE, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${API_TOKEN}`,
      "Content-Type": "text/plain",
    },
    body: sql,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Analytics Engine query failed (${res.status}): ${text}`);
  }
  return res.json();
}

function printRows(rows, formatter) {
  for (const row of rows || []) {
    console.log(formatter(row));
  }
}

async function main() {
  console.log(`\n📊  Claw Domains — Analytics (last ${days} days)\n`);

  const domainFilter = filterDomain ? `AND blob1 = '${filterDomain}'` : "";

  // ── 1) Domain summary ───────────────────────────────────────────
  const summarySql = `
    SELECT
      blob1 AS domain,
      COUNT(*) AS total_hits,
      SUM(CASE WHEN blob5 = 'pageview' THEN 1 ELSE 0 END) AS pageviews,
      SUM(CASE WHEN blob5 IN ('inquiry','offer') THEN 1 ELSE 0 END) AS form_events,
      SUM(CASE WHEN blob5 LIKE '%click' THEN 1 ELSE 0 END) AS click_events,
      SUM(CASE WHEN blob5 = 'offer' THEN 1 ELSE 0 END) AS offers,
      MAX(double2) AS max_offer_usd
    FROM ${DATASET}
    WHERE timestamp >= NOW() - INTERVAL '${days}' DAY
      ${domainFilter}
    GROUP BY blob1
    ORDER BY total_hits DESC
    LIMIT 60
  `;

  try {
    const summaryData = await query(summarySql);
    console.log("Domain                     Views  Forms  Clicks  Offers  Max Offer");
    console.log("─".repeat(74));
    printRows(summaryData.data, (row) =>
      `${String(row.domain || "").padEnd(27)} ${String(row.pageviews || 0).padStart(5)}  ${String(row.form_events || 0).padStart(5)}  ${String(row.click_events || 0).padStart(6)}  ${String(row.offers || 0).padStart(6)}  ${row.max_offer_usd ? "$" + Number(row.max_offer_usd).toLocaleString() : "—"}`,
    );
  } catch (e) {
    console.log("  (no Analytics Engine data yet — ensure worker + dataset are configured)");
  }

  // ── 2) Action mix ───────────────────────────────────────────────
  const actionSql = `
    SELECT blob5 AS action, COUNT(*) AS hits
    FROM ${DATASET}
    WHERE timestamp >= NOW() - INTERVAL '${days}' DAY
      ${domainFilter}
    GROUP BY blob5
    ORDER BY hits DESC
    LIMIT 30
  `;

  try {
    const actionData = await query(actionSql);
    console.log("\n\nAction Mix");
    console.log("─".repeat(50));
    printRows(actionData.data, (row) =>
      `  ${String(row.action || "unknown").padEnd(24)} ${row.hits}`,
    );
  } catch {
    /* ignore */
  }

  // ── 3) Top click targets/labels (blob6 context) ────────────────
  const clickSql = `
    SELECT blob6 AS context, COUNT(*) AS hits
    FROM ${DATASET}
    WHERE timestamp >= NOW() - INTERVAL '${days}' DAY
      AND blob5 LIKE '%click'
      ${domainFilter}
    GROUP BY blob6
    ORDER BY hits DESC
    LIMIT 20
  `;

  try {
    const clickData = await query(clickSql);
    console.log("\n\nTop click contexts");
    console.log("─".repeat(50));
    printRows(clickData.data, (row) => {
      const context = row.context || "(none)";
      return `  ${String(context).slice(0, 80).padEnd(82)} ${row.hits}`;
    });
  } catch {
    /* ignore */
  }

  // ── 4) Top referrers ────────────────────────────────────────────
  const refSql = `
    SELECT blob3 AS referrer, COUNT(*) AS hits
    FROM ${DATASET}
    WHERE timestamp >= NOW() - INTERVAL '${days}' DAY
      AND blob5 = 'pageview'
      ${domainFilter}
    GROUP BY blob3
    ORDER BY hits DESC
    LIMIT 15
  `;

  try {
    const refData = await query(refSql);
    console.log("\n\nTop Referrers");
    console.log("─".repeat(50));
    printRows(refData.data, (row) =>
      `  ${String(row.referrer || "direct").padEnd(35)} ${row.hits}`,
    );
  } catch {
    /* ignore */
  }

  // ── 5) Top countries ────────────────────────────────────────────
  const geoSql = `
    SELECT blob4 AS country, COUNT(*) AS hits
    FROM ${DATASET}
    WHERE timestamp >= NOW() - INTERVAL '${days}' DAY
      AND blob5 = 'pageview'
      ${domainFilter}
    GROUP BY blob4
    ORDER BY hits DESC
    LIMIT 15
  `;

  try {
    const geoData = await query(geoSql);
    console.log("\n\nTop Countries");
    console.log("─".repeat(50));
    printRows(geoData.data, (row) =>
      `  ${String(row.country || "XX").padEnd(10)} ${row.hits}`,
    );
  } catch {
    /* ignore */
  }

  // ── 6) Approx unique visitors ───────────────────────────────────
  const uvSql = `
    SELECT
      blob1 AS domain,
      COUNT(DISTINCT index1) AS unique_visitors
    FROM ${DATASET}
    WHERE timestamp >= NOW() - INTERVAL '${days}' DAY
      AND blob5 = 'pageview'
      ${domainFilter}
    GROUP BY blob1
    ORDER BY unique_visitors DESC
    LIMIT 60
  `;

  try {
    const uvData = await query(uvSql);
    console.log("\n\nUnique Visitors (approx)");
    console.log("─".repeat(50));
    printRows(uvData.data, (row) =>
      `  ${String(row.domain || "").padEnd(30)} ${row.unique_visitors}`,
    );
  } catch {
    /* ignore */
  }

  console.log("\n");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
