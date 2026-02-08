/* ------------------------------------------------------------------ */
/*  claw-domains — multi-domain landing page & inquiry capture        */
/*                                                                    */
/*  One Worker serves all parked/candidate Claw Bureau domains.       */
/*  Routes:                                                           */
/*    GET  /            → landing page (for_sale | coming_soon)       */
/*    POST /api/inquiries → store offer in D1                         */
/*    GET  /api/inquiries → list inquiries (admin, bearer-gated)      */
/*    GET  /api/analytics → cross-domain summary (admin)              */
/*    GET  /health       → health check                               */
/* ------------------------------------------------------------------ */

import type { Env, InquiryPayload } from "./types.js";
import { DOMAIN_MAP } from "./config.js";
import { trackEvent } from "./analytics.js";
import { forSalePage, comingSoonPage } from "./pages.js";

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
      "cache-control": "public, max-age=3600, s-maxage=86400",
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

/* ── inquiry handler ──────────────────────────────────────────────── */

async function handleInquiry(
  request: Request,
  env: Env,
): Promise<Response> {
  const hostname = new URL(request.url).hostname;

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

  // fire-and-forget analytics
  void trackEvent(
    env,
    request,
    body.offer_amount ? "offer" : "inquiry",
    body.offer_amount ?? 0,
  );

  return json({ ok: true, id });
}

/* ── admin: list inquiries ────────────────────────────────────────── */

async function handleListInquiries(
  request: Request,
  env: Env,
): Promise<Response> {
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

/* ── admin: cross-domain analytics summary ────────────────────────── */

async function handleAnalyticsSummary(
  request: Request,
  env: Env,
): Promise<Response> {
  if (!isAdminAuthed(request, env)) {
    return json({ error: "unauthorized" }, 401);
  }

  // Summary from D1 (inquiries per domain + total offers)
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
    note: "For visit analytics, query Analytics Engine SQL API with dataset 'claw_domain_visits'",
    inquiry_summary: results,
  });
}

/* ── main router ──────────────────────────────────────────────────── */

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const hostname = url.hostname.replace(/^www\./, "");

    /* CORS preflight */
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "access-control-allow-origin": "*",
          "access-control-allow-methods": "GET, POST, OPTIONS",
          "access-control-allow-headers": "content-type, authorization",
        },
      });
    }

    /* health */
    if (url.pathname === "/health") {
      return json({ ok: true, domain: hostname, ts: new Date().toISOString() });
    }

    /* API routes */
    if (url.pathname === "/api/inquiries") {
      if (request.method === "POST") return handleInquiry(request, env);
      if (request.method === "GET") return handleListInquiries(request, env);
      return json({ error: "method not allowed" }, 405);
    }
    if (url.pathname === "/api/analytics" && request.method === "GET") {
      return handleAnalyticsSummary(request, env);
    }

    /* domain config lookup */
    const cfg = DOMAIN_MAP[hostname];
    if (!cfg) {
      /* Unknown domain — generic redirect to clawbureau.com */
      return Response.redirect("https://clawbureau.com", 302);
    }

    /* redirect mode */
    if (cfg.mode === "redirect" && cfg.redirect_url) {
      return Response.redirect(cfg.redirect_url, 301);
    }

    /* track pageview (fire-and-forget) */
    void trackEvent(env, request, "pageview");

    const analyticsToken = env.CF_WEB_ANALYTICS_TOKEN ?? "";
    const contactEmail = env.INQUIRY_FORWARD_EMAIL ?? "domains@clawbureau.com";

    /* render page */
    if (cfg.mode === "for_sale") {
      return html(forSalePage(hostname, cfg, analyticsToken, contactEmail));
    }

    return html(comingSoonPage(hostname, cfg, analyticsToken));
  },
} satisfies ExportedHandler<Env>;
