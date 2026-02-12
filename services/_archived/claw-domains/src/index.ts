/* ------------------------------------------------------------------ */
/*  claw-domains — multi-domain landing pages + analytics + inquiries */
/* ------------------------------------------------------------------ */

import type { Env, InquiryPayload, TrackPayload } from "./types.js";
import {
  DOMAIN_MAP,
  ECOSYSTEM_DOMAINS,
  ECOSYSTEM_BY_DOMAIN,
} from "./config.js";
import { trackEvent } from "./analytics.js";
import { comingSoonPage, ecosystemPage, forSalePage } from "./pages.js";

/* ── helpers ──────────────────────────────────────────────────────── */

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json",
      "access-control-allow-origin": "*",
    },
  });
}

function html(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: {
      "content-type": "text/html;charset=utf-8",
      "cache-control": "public, max-age=300, s-maxage=3600",
      "x-robots-tag": "noindex",
    },
  });
}

function isAdminAuthed(request: Request, env: Env): boolean {
  const auth = request.headers.get("authorization");
  if (!auth) return false;
  const expected = env.ADMIN_TOKEN;
  if (!expected) return false;
  return auth === `Bearer ${expected}`;
}

function getRelatedDomains(hostname: string): typeof ECOSYSTEM_DOMAINS {
  const cfg = DOMAIN_MAP[hostname];
  const related = (cfg?.related_domains ?? [])
    .map((d) => ECOSYSTEM_BY_DOMAIN[d])
    .filter((d): d is (typeof ECOSYSTEM_DOMAINS)[number] => Boolean(d));

  if (related.length > 0) return related;

  // Fallback: show domains in the same pillar as this host.
  if (!cfg) return [];
  return ECOSYSTEM_DOMAINS.filter(
    (d) => d.pillar === cfg.pillar && d.domain !== hostname,
  ).slice(0, 4);
}

function getFeaturedLiveDomains(limit = 6): typeof ECOSYSTEM_DOMAINS {
  return ECOSYSTEM_DOMAINS.filter((d) => d.status === "live")
    .sort((a, b) => a.domain.localeCompare(b.domain))
    .slice(0, limit);
}

/* ── inquiry handler ──────────────────────────────────────────────── */

async function handleInquiry(request: Request, env: Env): Promise<Response> {
  const hostname = new URL(request.url).hostname.replace(/^www\./, "");

  let body: InquiryPayload;
  try {
    body = (await request.json()) as InquiryPayload;
  } catch {
    return json({ error: "invalid JSON" }, 400);
  }

  if (!body.email || typeof body.email !== "string") {
    return json({ error: "email required" }, 400);
  }

  const id = crypto.randomUUID();

  await env.INQUIRIES_DB.prepare(
    `INSERT INTO inquiries (id, domain, name, email, offer_amount, message,
       referrer, country, user_agent, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
  )
    .bind(
      id,
      hostname,
      body.name ?? "",
      body.email,
      body.offer_amount ?? null,
      body.message ?? "",
      request.headers.get("referer") ?? "",
      request.headers.get("cf-ipcountry") ?? "XX",
      (request.headers.get("user-agent") ?? "").slice(0, 512),
    )
    .run();

  void trackEvent(
    env,
    request,
    body.offer_amount ? "offer" : "inquiry",
    body.offer_amount ?? 0,
    {
      label: `${hostname}:api_inquiry`,
      target: "/api/inquiries",
    },
  );

  return json({ ok: true, id });
}

/* ── lightweight click tracker ────────────────────────────────────── */

const TRACK_ACTIONS = new Set([
  "pageview",
  "inquiry",
  "offer",
  "cta_click",
  "nav_click",
  "related_click",
  "ecosystem_click",
  "outbound_click",
]);

async function handleTrack(request: Request, env: Env): Promise<Response> {
  if (request.method !== "POST") {
    return json({ error: "method not allowed" }, 405);
  }

  let body: TrackPayload;
  try {
    body = (await request.json()) as TrackPayload;
  } catch {
    return json({ error: "invalid JSON" }, 400);
  }

  if (!body?.action || !TRACK_ACTIONS.has(body.action)) {
    return json({ error: "invalid action" }, 400);
  }

  void trackEvent(env, request, body.action, body.value ?? 0, {
    label: body.label,
    target: body.target,
  });

  return json({ ok: true });
}

/* ── admin: list inquiries ────────────────────────────────────────── */

async function handleListInquiries(request: Request, env: Env): Promise<Response> {
  if (!isAdminAuthed(request, env)) {
    return json({ error: "unauthorized" }, 401);
  }

  const url = new URL(request.url);
  const domain = url.searchParams.get("domain");
  const limit = Math.min(Number(url.searchParams.get("limit") ?? 100), 500);

  let sql = "SELECT * FROM inquiries";
  const params: string[] = [];
  if (domain) {
    sql += " WHERE domain = ?";
    params.push(domain);
  }
  sql += " ORDER BY created_at DESC LIMIT ?";

  const stmt = env.INQUIRIES_DB.prepare(sql).bind(...params, limit);
  const { results } = await stmt.all();

  return json({ inquiries: results, count: results.length });
}

/* ── admin: D1 inquiry summary ────────────────────────────────────── */

async function handleAnalyticsSummary(request: Request, env: Env): Promise<Response> {
  if (!isAdminAuthed(request, env)) {
    return json({ error: "unauthorized" }, 401);
  }

  const { results } = await env.INQUIRIES_DB.prepare(
    `SELECT domain,
            COUNT(*) AS inquiry_count,
            SUM(CASE WHEN offer_amount > 0 THEN 1 ELSE 0 END) AS offer_count,
            MAX(offer_amount) AS max_offer,
            MAX(created_at) AS last_inquiry
     FROM inquiries
     GROUP BY domain
     ORDER BY inquiry_count DESC`,
  ).all();

  return json({
    note: "Visit/click analytics are in Analytics Engine dataset 'claw_domain_visits'",
    inquiry_summary: results,
  });
}

/* ── router ───────────────────────────────────────────────────────── */

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const hostname = url.hostname.replace(/^www\./, "");

    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "access-control-allow-origin": "*",
          "access-control-allow-methods": "GET, POST, OPTIONS",
          "access-control-allow-headers": "content-type, authorization",
        },
      });
    }

    if (url.pathname === "/health") {
      return json({ ok: true, domain: hostname, ts: new Date().toISOString() });
    }

    if (url.pathname === "/api/inquiries") {
      if (request.method === "POST") return handleInquiry(request, env);
      if (request.method === "GET") return handleListInquiries(request, env);
      return json({ error: "method not allowed" }, 405);
    }

    if (url.pathname === "/api/track") {
      return handleTrack(request, env);
    }

    if (url.pathname === "/api/analytics" && request.method === "GET") {
      return handleAnalyticsSummary(request, env);
    }

    if (url.pathname === "/api/domains" && request.method === "GET") {
      const host = url.searchParams.get("host")?.replace(/^www\./, "");
      return json({
        host,
        host_config: host ? DOMAIN_MAP[host] ?? null : null,
        related: host ? getRelatedDomains(host) : [],
        domains: ECOSYSTEM_DOMAINS,
      });
    }

    if (url.pathname === "/ecosystem") {
      void trackEvent(env, request, "pageview", 0, {
        label: `${hostname}:ecosystem`,
        target: "/ecosystem",
      });

      return html(
        ecosystemPage(hostname, env.CF_WEB_ANALYTICS_TOKEN ?? "", ECOSYSTEM_DOMAINS),
      );
    }

    const cfg = DOMAIN_MAP[hostname];
    if (!cfg) {
      return Response.redirect("https://clawbureau.com", 302);
    }

    if (cfg.mode === "redirect" && cfg.redirect_url) {
      return Response.redirect(cfg.redirect_url, 301);
    }

    void trackEvent(env, request, "pageview");

    const analyticsToken = env.CF_WEB_ANALYTICS_TOKEN ?? "";
    const contactEmail = env.INQUIRY_FORWARD_EMAIL ?? "domains@clawbureau.com";
    const related = getRelatedDomains(hostname);
    const featured = getFeaturedLiveDomains();

    if (cfg.mode === "for_sale") {
      return html(
        forSalePage(
          hostname,
          cfg,
          analyticsToken,
          contactEmail,
          related,
          featured,
        ),
      );
    }

    return html(comingSoonPage(hostname, cfg, analyticsToken, related, featured));
  },
} satisfies ExportedHandler<Env>;
