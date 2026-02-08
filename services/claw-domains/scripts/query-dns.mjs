#!/usr/bin/env node
/* ------------------------------------------------------------------ */
/*  Query Cloudflare DNS Analytics for all claw* zones.               */
/*  Shows DNS query volume per domain — the cheapest "interest"       */
/*  signal, available even without a deployed Worker.                  */
/*                                                                    */
/*  Usage:                                                            */
/*    CF_API_TOKEN=... node scripts/query-dns.mjs                     */
/*    CF_API_TOKEN=... node scripts/query-dns.mjs --days 7            */
/* ------------------------------------------------------------------ */

const ACCOUNT_ID =
  process.env.CF_ACCOUNT_ID || "b8f2c66f1848dff476faa874282d781e";
const API_TOKEN = process.env.CF_API_TOKEN;

if (!API_TOKEN) {
  console.error("Set CF_API_TOKEN env var (needs Zone:Analytics:Read)");
  process.exit(1);
}

const args = process.argv.slice(2);
const days = parseInt(args[args.indexOf("--days") + 1] || "30", 10);

const GQL_URL = "https://api.cloudflare.com/client/v4/graphql";
const API_URL = "https://api.cloudflare.com/client/v4";

async function cfFetch(url, opts = {}) {
  const res = await fetch(url, {
    ...opts,
    headers: {
      Authorization: `Bearer ${API_TOKEN}`,
      "Content-Type": "application/json",
      ...(opts.headers || {}),
    },
  });
  if (!res.ok) {
    throw new Error(`CF API ${res.status}: ${await res.text()}`);
  }
  return res.json();
}

async function listZones() {
  const zones = [];
  let page = 1;
  while (true) {
    const data = await cfFetch(
      `${API_URL}/zones?account.id=${ACCOUNT_ID}&per_page=50&page=${page}`
    );
    zones.push(...data.result);
    if (page >= data.result_info.total_pages) break;
    page++;
  }
  return zones.filter((z) => z.name.includes("claw") || z.name === "joinclaw.com");
}

async function dnsQueryCount(zoneTag, since) {
  const query = `{
    viewer {
      zones(filter: { zoneTag: "${zoneTag}" }) {
        dnsAnalyticsAdaptiveGroups(
          filter: { datetime_gt: "${since}" }
          limit: 1
        ) {
          count
        }
      }
    }
  }`;

  try {
    const data = await cfFetch(GQL_URL, {
      method: "POST",
      body: JSON.stringify({ query }),
    });
    const groups =
      data?.data?.viewer?.zones?.[0]?.dnsAnalyticsAdaptiveGroups ?? [];
    return groups.reduce((sum, g) => sum + (g.count || 0), 0);
  } catch {
    return null;
  }
}

async function httpRequestCount(zoneTag, since) {
  const query = `{
    viewer {
      zones(filter: { zoneTag: "${zoneTag}" }) {
        httpRequests1dGroups(
          filter: { date_gt: "${since.split("T")[0]}" }
          limit: 100
        ) {
          sum { requests }
        }
      }
    }
  }`;

  try {
    const data = await cfFetch(GQL_URL, {
      method: "POST",
      body: JSON.stringify({ query }),
    });
    const groups =
      data?.data?.viewer?.zones?.[0]?.httpRequests1dGroups ?? [];
    return groups.reduce((sum, g) => sum + (g?.sum?.requests || 0), 0);
  } catch {
    return null;
  }
}

async function main() {
  const since = new Date(Date.now() - days * 86400000).toISOString();
  console.log(`\n🔍  DNS & HTTP Analytics — last ${days} days (since ${since.split("T")[0]})\n`);

  const zones = await listZones();
  console.log(`Found ${zones.length} claw* zones\n`);

  console.log(
    "Domain                      DNS Queries   HTTP Requests   Status"
  );
  console.log("─".repeat(75));

  const results = [];

  for (const zone of zones.sort((a, b) => a.name.localeCompare(b.name))) {
    const dns = await dnsQueryCount(zone.id, since);
    const http = await httpRequestCount(zone.id, since);

    results.push({ domain: zone.name, dns, http, status: zone.status });

    console.log(
      `${zone.name.padEnd(28)} ${dns !== null ? String(dns).padStart(11) : "     —     "}   ${http !== null ? String(http).padStart(13) : "      —      "}   ${zone.status}`
    );
  }

  // ── Summary: top domains by interest ──────────────────────────────
  console.log("\n\n📈  Top domains by DNS query volume:");
  console.log("─".repeat(50));
  const sorted = results
    .filter((r) => r.dns !== null && r.dns > 0)
    .sort((a, b) => (b.dns ?? 0) - (a.dns ?? 0));

  if (sorted.length === 0) {
    console.log("  (no DNS query data — zones may need a few hours after activation)");
  } else {
    for (const r of sorted.slice(0, 15)) {
      const bar = "█".repeat(Math.min(40, Math.ceil(((r.dns ?? 0) / (sorted[0]?.dns ?? 1)) * 40)));
      console.log(`  ${r.domain.padEnd(28)} ${String(r.dns).padStart(8)}  ${bar}`);
    }
  }

  console.log("\n");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
