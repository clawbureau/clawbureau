#!/usr/bin/env node
/* ------------------------------------------------------------------ */
/*  Query Analytics Engine for cross-domain visit intelligence.       */
/*                                                                    */
/*  Usage:                                                            */
/*    CF_API_TOKEN=... CF_ACCOUNT_ID=... node scripts/query-analytics.mjs           */
/*    CF_API_TOKEN=... CF_ACCOUNT_ID=... node scripts/query-analytics.mjs --days 7  */
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

async function main() {
  console.log(`\n📊  Claw Domains — Analytics (last ${days} days)\n`);

  // ── 1. Visits per domain ──────────────────────────────────────────
  const domainFilter = filterDomain
    ? `AND blob1 = '${filterDomain}'`
    : "";

  const visitsSql = `
    SELECT
      blob1 AS domain,
      COUNT(*) AS total_hits,
      SUM(CASE WHEN blob5 = 'pageview' THEN 1 ELSE 0 END) AS pageviews,
      SUM(CASE WHEN blob5 = 'inquiry' THEN 1 ELSE 0 END) AS inquiries,
      SUM(CASE WHEN blob5 = 'offer' THEN 1 ELSE 0 END) AS offers,
      MAX(double2) AS max_offer_usd
    FROM ${DATASET}
    WHERE timestamp >= NOW() - INTERVAL '${days}' DAY
      ${domainFilter}
    GROUP BY blob1
    ORDER BY total_hits DESC
    LIMIT 50
  `;

  try {
    const visitsData = await query(visitsSql);
    console.log("Domain                     Pageviews  Inquiries  Offers  Max Offer");
    console.log("─".repeat(72));
    for (const row of visitsData.data || []) {
      console.log(
        `${(row.domain || "").padEnd(27)} ${String(row.pageviews || 0).padStart(8)}  ${String(row.inquiries || 0).padStart(9)}  ${String(row.offers || 0).padStart(6)}  ${row.max_offer_usd ? "$" + Number(row.max_offer_usd).toLocaleString() : "—"}`
      );
    }
  } catch (e) {
    console.log("  (no Analytics Engine data yet — deploy the worker first)\n");
  }

  // ── 2. Top referrers ─────────────────────────────────────────────
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
    console.log("\n\nTop Referrers");
    console.log("─".repeat(50));
    const refData = await query(refSql);
    for (const row of refData.data || []) {
      console.log(`  ${(row.referrer || "direct").padEnd(35)} ${row.hits}`);
    }
  } catch {
    /* ignore if no data */
  }

  // ── 3. Top countries ──────────────────────────────────────────────
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
    console.log("\n\nTop Countries");
    console.log("─".repeat(50));
    const geoData = await query(geoSql);
    for (const row of geoData.data || []) {
      console.log(`  ${(row.country || "XX").padEnd(10)} ${row.hits}`);
    }
  } catch {
    /* ignore if no data */
  }

  // ── 4. Unique visitors (approximation via index1 hash) ───────────
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
    LIMIT 50
  `;

  try {
    console.log("\n\nUnique Visitors (approx)");
    console.log("─".repeat(50));
    const uvData = await query(uvSql);
    for (const row of uvData.data || []) {
      console.log(`  ${(row.domain || "").padEnd(30)} ${row.unique_visitors}`);
    }
  } catch {
    /* ignore if no data */
  }

  console.log("\n");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
