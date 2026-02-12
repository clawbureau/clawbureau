/**
 * Lead intake, scoring, routing, CRM handoff, ops, tracking, experiments, queue handler.
 * Extracted from index.ts for maintainability.
 */

import type {
  Env, LeadSubmissionPayload, LeadRow, LeadScoreResult, LeadScoreReason,
  LeadScoreBand, LeadSegment, LeadSourceIntent, LeadLifecycleStatus,
  LeadHandoffEnvelope, CrmProvider, CrmRoutingRule, CrmRoutingConfig,
  TurnstilePosture, TurnstilePostureCode, LeadBehaviorSignals,
  ExperimentVariantConfig, ExperimentFamilyConfig,
  Article, ManifestEntry, SearchDocument, SearchDocumentKind, SearchResult,
} from "./index";
type TrackingEventType =
  | "cta_click"
  | "contact_intent_view"
  | "contact_email_click"
  | "contact_intent_submit"
  | "lead_submit"
  | "variant_assignment"
  | "search_query"
  | "search_result_click"
  | "search_clear"
  | "book_prompt_shown"
  | "booking_submit"
  | "booking_complete";


import {
  json, html, apiJson, apiError, apiHeaders,
  checkOpsAuth, checkAutomationAuth,
  DEFAULT_CRM_ROUTING_CONFIG, DISPOSABLE_EMAIL_DOMAINS,
  LEAD_STATE_TRANSITIONS, RESPONSE_SLA_OPEN_STATES, RESPONSE_SLA_CLOSED_STATES,
  DEFAULT_EXPERIMENT_CONFIG,
  loadIndexQueue, summarizeIndexQueue, loadLastQueueRun,
} from "./index";

type TrackingEvent = {
  eventType: TrackingEventType;
  page: string;
  pageFamily: string;
  href?: string;
  ctaId?: string;
  ctaVariant?: string;
  actionOutcome?: string;
  query?: string;
  resultCount?: number;
  targetPath?: string;
  variantId?: string;
  heroVariant?: string;
  visitorId?: string;
  ts: string;
  source: string;
  attribution: Record<string, string>;
  context: {
    referrer?: string;
    country?: string;
    userAgent?: string;
    ipClassC?: string;
  };
};

const TRACKING_EVENT_TYPES = new Set<TrackingEventType>([
  "cta_click",
  "contact_intent_view",
  "contact_email_click",
  "contact_intent_submit",
  "lead_submit",
  "variant_assignment",
  "search_query",
  "search_result_click",
  "search_clear",
  "book_prompt_shown",
  "booking_submit",
  "booking_complete",
]);

export function clipString(input: unknown, maxLen: number): string | undefined {
  if (typeof input !== "string") return undefined;
  const v = input.trim();
  if (!v) return undefined;
  return v.slice(0, maxLen);
}

export function pageFamilyFromPath(input: string | undefined): string {
  const path = (input ?? "/").trim();
  if (!path || path === "/") return "home";
  const parts = path.replace(/^\//, "").split("/").filter(Boolean);
  if (parts.length === 0) return "home";

  const known = new Set([
    "controls",
    "workflows",
    "tools",
    "channels",
    "policy",
    "proof",
    "verify",
    "audit",
    "mcp",
    "supply-chain",
    "events",
    "compliance",
    "guides",
    "glossary",
    "trust",
    "secure-workers",
    "consulting",
    "pricing",
    "contact",
    "assessment",
    "sources",
    "book",
    "about",
  ]);

  const first = parts[0];
  if (known.has(first)) return first;
  return "root";
}

function normalizeResultCount(input: unknown): number | undefined {
  const n = Number(input);
  if (!Number.isFinite(n) || n < 0) return undefined;
  return Math.min(100_000, Math.floor(n));
}

function normalizeAttribution(input: unknown): Record<string, string> {
  const src = typeof input === "object" && input !== null ? (input as Record<string, unknown>) : {};

  const allowedKeys = [
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "gclid",
    "fbclid",
    "msclkid",
    "referrer_host",
    "landing_path",
    "source",
    "first_touch_ts",
    "first_touch_path",
    "first_touch_page_family",
  ];

  const out: Record<string, string> = {};
  for (const key of allowedKeys) {
    const v = clipString(src[key], 160);
    if (v) out[key] = v;
  }

  return out;
}

function deriveSource(attribution: Record<string, string>): string {
  if (attribution.source) return attribution.source;
  if (attribution.utm_source) return `utm:${attribution.utm_source}`;
  if (attribution.referrer_host) return `ref:${attribution.referrer_host}`;
  return "direct";
}

function anonymizeIpClassC(ip: string | null): string | undefined {
  if (!ip) return undefined;
  const m = ip.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (!m) return undefined;
  return `${m[1]}.${m[2]}.${m[3]}.x`;
}

async function storeTrackingEvent(env: Env, event: TrackingEvent): Promise<string> {
  const day = event.ts.slice(0, 10);
  const random = typeof crypto.randomUUID === "function"
    ? crypto.randomUUID().slice(0, 8)
    : Math.random().toString(36).slice(2, 10);
  const key = `events/${day}/${event.ts.replace(/[:.]/g, "-")}-${random}.json`;

  await env.ARTICLES.put(key, JSON.stringify(event), {
    httpMetadata: { contentType: "application/json" },
  });

  await persistTrackingEventD1(env, event);
  return key;
}

export async function ingestTrackingEvent(request: Request, env: Env): Promise<Response> {
  if (request.method !== "POST") {
    return apiError("METHOD_NOT_ALLOWED", "Use POST for this endpoint", 405);
  }

  let body: any;
  try {
    body = await request.json<any>();
  } catch {
    return apiError("INVALID_JSON", "Request body must be valid JSON", 400);
  }

  const eventTypeRaw = clipString(body?.eventType, 64);
  const eventType = eventTypeRaw && TRACKING_EVENT_TYPES.has(eventTypeRaw as TrackingEventType)
    ? (eventTypeRaw as TrackingEventType)
    : null;

  if (!eventType) {
    return apiError("EVENT_TYPE_INVALID", "eventType is missing or not allowed", 400);
  }

  const page = clipString(body?.page, 240) ?? "/";
  const pageFamily = clipString(body?.pageFamily, 80) ?? pageFamilyFromPath(page);
  const ts = clipString(body?.ts, 80) ?? new Date().toISOString();
  const parsedTs = Number.isNaN(Date.parse(ts)) ? new Date().toISOString() : ts;

  const attribution = normalizeAttribution(body?.attribution);

  const event: TrackingEvent = {
    eventType,
    page,
    pageFamily,
    href: clipString(body?.href, 500),
    ctaId: clipString(body?.ctaId, 160),
    ctaVariant: clipString(body?.ctaVariant, 120),
    actionOutcome: clipString(body?.actionOutcome, 120),
    query: clipString(body?.query, 120),
    resultCount: normalizeResultCount(body?.resultCount),
    targetPath: clipString(body?.targetPath, 240),
    variantId: clipString(body?.variantId, 120),
    heroVariant: clipString(body?.heroVariant, 120),
    visitorId: clipString(body?.visitorId, 140),
    ts: parsedTs,
    source: deriveSource(attribution),
    attribution,
    context: {
      referrer: clipString(request.headers.get("referer"), 500),
      country: clipString(request.headers.get("cf-ipcountry"), 8),
      userAgent: clipString(request.headers.get("user-agent"), 180),
      ipClassC: anonymizeIpClassC(request.headers.get("cf-connecting-ip")),
    },
  };

  const key = await storeTrackingEvent(env, event);
  return apiJson({ ok: true, eventId: key });
}

async function listTrackingEvents(env: Env, fromMs: number, toMs: number): Promise<TrackingEvent[]> {
  const out: TrackingEvent[] = [];
  let cursor: string | undefined;

  while (true) {
    const listed = await env.ARTICLES.list({
      prefix: "events/",
      cursor,
      limit: 1000,
    });

    for (const obj of listed.objects) {
      const file = await env.ARTICLES.get(obj.key);
      if (!file) continue;

      try {
        const evRaw = await file.json<TrackingEvent>();
        const ev: TrackingEvent = {
          ...evRaw,
          pageFamily: clipString((evRaw as any)?.pageFamily, 80) ?? pageFamilyFromPath((evRaw as any)?.page),
        };

        const tsMs = Date.parse(ev.ts);
        if (Number.isNaN(tsMs) || tsMs < fromMs || tsMs > toMs) continue;
        if (!TRACKING_EVENT_TYPES.has(ev.eventType)) continue;
        out.push(ev);
      } catch {
        // ignore malformed rows
      }
    }

    if (!listed.truncated || !listed.cursor) break;
    cursor = listed.cursor;
  }

  return out;
}

function topCounts(map: Map<string, number>, limit = 10): Array<{ key: string; count: number }> {
  return [...map.entries()]
    .sort((a, b) => (b[1] - a[1]) || a[0].localeCompare(b[0], "en"))
    .slice(0, limit)
    .map(([key, count]) => ({ key, count }));
}

export async function summarizeTrackingEvents(request: Request, env: Env): Promise<Response> {
  const authError = checkOpsAuth(request, env);
  if (authError) return authError;

  if (request.method !== "POST") {
    return apiError("METHOD_NOT_ALLOWED", "Use POST for this endpoint", 405);
  }

  let body: any = {};
  try {
    body = await request.json<any>();
  } catch {
    // allow empty JSON body
  }

  const daysRaw = Number(body?.days ?? 7);
  const days = Number.isFinite(daysRaw) ? Math.min(90, Math.max(1, Math.floor(daysRaw))) : 7;

  const nowMs = Date.now();
  const fromRaw = clipString(body?.from, 80);
  const toRaw = clipString(body?.to, 80);

  const fallbackFromMs = nowMs - (days * 24 * 60 * 60 * 1000);
  const fromMs = fromRaw ? Date.parse(fromRaw) : fallbackFromMs;
  const toMs = toRaw ? Date.parse(toRaw) : nowMs;

  if (Number.isNaN(fromMs) || Number.isNaN(toMs) || fromMs > toMs) {
    return apiError("DATE_RANGE_INVALID", "Invalid from/to date range", 400);
  }

  const events = await listTrackingEvents(env, fromMs, toMs);

  const byType = new Map<string, number>();
  const bySource = new Map<string, number>();
  const byPage = new Map<string, number>();
  const byPageFamily = new Map<string, number>();
  const byCta = new Map<string, number>();
  const byCtaVariant = new Map<string, number>();
  const byVariantId = new Map<string, number>();
  const byHeroVariant = new Map<string, number>();
  const byOutcome = new Map<string, number>();

  const variantOutcome = new Map<string, { impressions: number; clicks: number; submits: number }>();

  const searchQueryCount = new Map<string, number>();
  const searchQueryClicks = new Map<string, number>();
  const searchQueryResultsSum = new Map<string, number>();

  const ctaFamilyViews = new Map<string, number>();
  const ctaFamilyActions = new Map<string, number>();
  const ctaFamilyClicks = new Map<string, number>();

  let contactIntentViews = 0;
  let contactIntentActions = 0;
  let leadSubmits = 0;
  let bookingSubmits = 0;
  let bookingCompletions = 0;
  let searchQueries = 0;
  let searchResultClicks = 0;

  for (const ev of events) {
    byType.set(ev.eventType, (byType.get(ev.eventType) ?? 0) + 1);
    bySource.set(ev.source, (bySource.get(ev.source) ?? 0) + 1);
    byPage.set(ev.page, (byPage.get(ev.page) ?? 0) + 1);
    byPageFamily.set(ev.pageFamily, (byPageFamily.get(ev.pageFamily) ?? 0) + 1);

    const ctaKey = ev.ctaId ?? ev.href ?? "unknown";
    if (ev.eventType === "cta_click" || ev.eventType === "contact_email_click") {
      byCta.set(ctaKey, (byCta.get(ctaKey) ?? 0) + 1);
    }

    if (ev.ctaVariant) {
      byCtaVariant.set(ev.ctaVariant, (byCtaVariant.get(ev.ctaVariant) ?? 0) + 1);
    }

    if (ev.variantId) {
      byVariantId.set(ev.variantId, (byVariantId.get(ev.variantId) ?? 0) + 1);

      const current = variantOutcome.get(ev.variantId) ?? { impressions: 0, clicks: 0, submits: 0 };
      if (ev.eventType === "variant_assignment") current.impressions += 1;
      if (ev.eventType === "cta_click") current.clicks += 1;
      if (ev.eventType === "contact_intent_submit" || ev.eventType === "lead_submit" || ev.eventType === "booking_submit") current.submits += 1;
      variantOutcome.set(ev.variantId, current);
    }

    if (ev.heroVariant) {
      byHeroVariant.set(ev.heroVariant, (byHeroVariant.get(ev.heroVariant) ?? 0) + 1);
    }

    if (ev.actionOutcome) {
      byOutcome.set(ev.actionOutcome, (byOutcome.get(ev.actionOutcome) ?? 0) + 1);
    }

    if (ev.eventType === "contact_intent_view") {
      contactIntentViews += 1;
      ctaFamilyViews.set(ev.pageFamily, (ctaFamilyViews.get(ev.pageFamily) ?? 0) + 1);
    }

    if (ev.eventType === "cta_click") {
      ctaFamilyClicks.set(ev.pageFamily, (ctaFamilyClicks.get(ev.pageFamily) ?? 0) + 1);
    }

    if (ev.eventType === "contact_email_click" || ev.eventType === "contact_intent_submit" || ev.eventType === "lead_submit" || ev.eventType === "booking_submit") {
      contactIntentActions += 1;
      ctaFamilyActions.set(ev.pageFamily, (ctaFamilyActions.get(ev.pageFamily) ?? 0) + 1);
    }

    if (ev.eventType === "lead_submit") {
      leadSubmits += 1;
    }

    if (ev.eventType === "booking_submit") {
      bookingSubmits += 1;
    }

    if (ev.eventType === "booking_complete") {
      bookingCompletions += 1;
    }

    if (ev.eventType === "search_query" && ev.query) {
      searchQueries += 1;
      searchQueryCount.set(ev.query, (searchQueryCount.get(ev.query) ?? 0) + 1);
      const rc = typeof ev.resultCount === "number" ? ev.resultCount : 0;
      searchQueryResultsSum.set(ev.query, (searchQueryResultsSum.get(ev.query) ?? 0) + rc);
    }

    if (ev.eventType === "search_result_click") {
      searchResultClicks += 1;
      if (ev.query) {
        searchQueryClicks.set(ev.query, (searchQueryClicks.get(ev.query) ?? 0) + 1);
      }
    }
  }

  const intentToActionRate = contactIntentViews > 0
    ? Number((contactIntentActions / contactIntentViews).toFixed(4))
    : 0;
  const searchToClickRate = searchQueries > 0
    ? Number((searchResultClicks / searchQueries).toFixed(4))
    : 0;
  const leadToBookingRate = leadSubmits > 0
    ? Number((bookingSubmits / leadSubmits).toFixed(4))
    : 0;
  const bookingCompletionRate = bookingSubmits > 0
    ? Number((bookingCompletions / bookingSubmits).toFixed(4))
    : 0;

  const topSearchQueries = [...searchQueryCount.entries()]
    .map(([query, queries]) => {
      const clicks = searchQueryClicks.get(query) ?? 0;
      const resultsTotal = searchQueryResultsSum.get(query) ?? 0;
      return {
        query,
        queries,
        clicks,
        ctr: queries > 0 ? Number((clicks / queries).toFixed(4)) : 0,
        avgResults: queries > 0 ? Number((resultsTotal / queries).toFixed(2)) : 0,
      };
    })
    .sort((a, b) => (b.queries - a.queries) || a.query.localeCompare(b.query, "en"))
    .slice(0, 20);

  const ctaByPageFamily = [...new Set([
    ...ctaFamilyViews.keys(),
    ...ctaFamilyActions.keys(),
    ...ctaFamilyClicks.keys(),
  ])]
    .map((family) => {
      const views = ctaFamilyViews.get(family) ?? 0;
      const actions = ctaFamilyActions.get(family) ?? 0;
      const clicks = ctaFamilyClicks.get(family) ?? 0;
      return {
        pageFamily: family,
        views,
        clicks,
        actions,
        actionRate: views > 0 ? Number((actions / views).toFixed(4)) : 0,
      };
    })
    .sort((a, b) => (b.actions - a.actions) || a.pageFamily.localeCompare(b.pageFamily, "en"));

  const variantPerformance = [...variantOutcome.entries()]
    .map(([variantId, row]) => ({
      variantId,
      impressions: row.impressions,
      clicks: row.clicks,
      submits: row.submits,
      clickRate: row.impressions > 0 ? Number((row.clicks / row.impressions).toFixed(4)) : 0,
      submitRate: row.impressions > 0 ? Number((row.submits / row.impressions).toFixed(4)) : 0,
    }))
    .sort((a, b) => (b.submitRate - a.submitRate) || (b.impressions - a.impressions) || a.variantId.localeCompare(b.variantId, "en"))
    .slice(0, 40);

  const queue = await loadIndexQueue(env);
  const queueSummary = summarizeIndexQueue(queue);
  const lastQueueRun = await loadLastQueueRun(env);

  return apiJson({
    ok: true,
    range: {
      from: new Date(fromMs).toISOString(),
      to: new Date(toMs).toISOString(),
      days,
    },
    generatedAt: new Date().toISOString(),
    totals: {
      events: events.length,
      contactIntentViews,
      contactIntentActions,
      leadSubmits,
      bookingSubmits,
      bookingCompletions,
      intentToActionRate,
      leadToBookingRate,
      bookingCompletionRate,
      searchQueries,
      searchResultClicks,
      searchToClickRate,
    },
    breakdown: {
      byType: topCounts(byType, 30),
      bySource: topCounts(bySource, 30),
      topPages: topCounts(byPage, 30),
      byPageFamily: topCounts(byPageFamily, 30),
      topCtas: topCounts(byCta, 30),
      byCtaVariant: topCounts(byCtaVariant, 30),
      byVariantId: topCounts(byVariantId, 40),
      byHeroVariant: topCounts(byHeroVariant, 40),
      byOutcome: topCounts(byOutcome, 30),
    },
    funnel: {
      search: {
        queries: searchQueries,
        clicks: searchResultClicks,
        searchToClickRate,
        topQueries: topSearchQueries,
      },
      ctaByPageFamily,
      variants: variantPerformance,
      booking: {
        leadSubmits,
        bookingSubmits,
        bookingCompletions,
        leadToBookingRate,
        bookingCompletionRate,
      },
    },
    indexing: {
      queue: queueSummary,
      lastRun: lastQueueRun,
    },
  });
}

function envFlag(value: string | undefined, fallback = false): boolean {
  if (value === undefined) return fallback;
  const v = value.trim().toLowerCase();
  if (!v) return fallback;
  return v === "1" || v === "true" || v === "yes" || v === "on";
}

const TURNSTILE_DEFAULT_TEST_SITE_KEY = "1x00000000000000000000AA";
const TURNSTILE_TEST_SITE_KEYS = new Set([
  TURNSTILE_DEFAULT_TEST_SITE_KEY,
  "2x00000000000000000000AB",
]);

function isTurnstileTestSiteKey(siteKey: string | undefined): boolean {
  if (!siteKey) return false;
  return TURNSTILE_TEST_SITE_KEYS.has(siteKey);
}

export function resolveTurnstilePosture(env: Env): TurnstilePosture {
  const required = envFlag(env.TURNSTILE_REQUIRED, true);
  const strictRealKey = envFlag(env.TURNSTILE_STRICT_REAL_KEY, (env.ENVIRONMENT ?? "").trim().toLowerCase() === "production");
  const siteKey = clipString(env.TURNSTILE_SITE_KEY, 120);
  const secretConfigured = Boolean(clipString(env.TURNSTILE_SECRET_KEY, 200));
  const usesTestSiteKey = isTurnstileTestSiteKey(siteKey);

  if (!required) {
    return {
      required,
      strictRealKey,
      siteKey,
      secretConfigured,
      usesTestSiteKey,
      formEnabled: true,
      code: "TURNSTILE_OPTIONAL",
      message: siteKey
        ? "Form protection is optional in this environment."
        : "Form protection is optional in this environment and Turnstile is disabled.",
    };
  }

  if (!secretConfigured) {
    return {
      required,
      strictRealKey,
      siteKey,
      secretConfigured,
      usesTestSiteKey,
      formEnabled: false,
      code: "TURNSTILE_NOT_CONFIGURED",
      message: "Lead intake is temporarily unavailable while bot protection is being configured.",
    };
  }

  if (!siteKey) {
    return {
      required,
      strictRealKey,
      siteKey,
      secretConfigured,
      usesTestSiteKey,
      formEnabled: false,
      code: "TURNSTILE_SITE_KEY_MISSING",
      message: "Lead intake is temporarily unavailable while bot protection keys are being rotated.",
    };
  }

  if (strictRealKey && usesTestSiteKey) {
    return {
      required,
      strictRealKey,
      siteKey,
      secretConfigured,
      usesTestSiteKey,
      formEnabled: false,
      code: "TURNSTILE_TEST_KEY_FORBIDDEN",
      message: "Lead intake is paused until production-grade Turnstile keys are active.",
    };
  }

  return {
    required,
    strictRealKey,
    siteKey,
    secretConfigured,
    usesTestSiteKey,
    formEnabled: true,
    code: "TURNSTILE_READY",
    message: "Bot protection active.",
  };
}

export function shouldRenderTurnstileWidget(posture: TurnstilePosture): boolean {
  return Boolean(posture.siteKey) && posture.formEnabled;
}

function randomId(prefix = "id"): string {
  const raw = typeof crypto.randomUUID === "function"
    ? crypto.randomUUID().replace(/-/g, "")
    : Math.random().toString(36).slice(2) + Date.now().toString(36);
  return `${prefix}_${raw.slice(0, 24)}`;
}

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }

  const b64 = btoa(binary);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function sha256Base64Url(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return base64Url(new Uint8Array(digest));
}

async function hmacSha256Base64Url(secret: string, payload: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );

  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(payload));
  return base64Url(new Uint8Array(sig));
}

function normalizeLeadStatus(raw: string | undefined): LeadLifecycleStatus {
  const v = (raw ?? "").trim().toLowerCase();
  if (v === "enriched") return "scored";
  if (v === "rejected") return "disqualified";
  if (v === "closed") return "booked";
  if (
    v === "new"
    || v === "validated"
    || v === "scored"
    || v === "routed"
    || v === "contacted"
    || v === "qualified"
    || v === "disqualified"
    || v === "booked"
  ) {
    return v;
  }
  return "new";
}

function scoreBandFromQualification(score: number): LeadScoreBand {
  if (score >= 80) return "high";
  if (score >= 55) return "medium";
  return "low";
}

function segmentFromPayload(payload: LeadSubmissionPayload, qualificationScore: number): LeadSegment {
  const source = (payload.attribution?.source ?? "").toLowerCase();
  const campaign = (payload.attribution?.utm_campaign ?? "").toLowerCase();
  const role = (payload.role ?? "").toLowerCase();
  const team = (payload.teamSize ?? "").toLowerCase();

  if (
    source.includes("partner")
    || campaign.includes("partner")
    || role.includes("partner")
    || role.includes("reseller")
  ) {
    return "partner";
  }

  if (
    qualificationScore >= 72
    || team.includes("500")
    || team.includes("1000")
    || team.includes("enterprise")
    || role.includes("cto")
    || role.includes("security")
  ) {
    return "enterprise";
  }

  return "smb";
}

function leadWindowMinutes(env: Env): number {
  return Math.max(1, Math.min(120, Number(env.LEAD_SUBMIT_WINDOW_MINUTES ?? "10")));
}

function leadIpWindowLimit(env: Env): number {
  return Math.max(5, Math.min(500, Number(env.LEAD_SUBMIT_IP_WINDOW_LIMIT ?? "24")));
}

function leadEmailWindowLimit(env: Env): number {
  return Math.max(2, Math.min(100, Number(env.LEAD_SUBMIT_EMAIL_WINDOW_LIMIT ?? "8")));
}

function routingMaxAttempts(env: Env): number {
  return Math.max(1, Math.min(12, Number(env.ROUTING_MAX_ATTEMPTS ?? "5")));
}

function leadResponseSlaMinutes(env: Env): number {
  return Math.max(5, Math.min(24 * 60, Number(env.LEAD_RESPONSE_SLA_MINUTES ?? "45")));
}

function routingQueueLagAlertMinutes(env: Env): number {
  return Math.max(5, Math.min(24 * 60, Number(env.ROUTING_QUEUE_LAG_ALERT_MINUTES ?? "20")));
}

function inferSourceIntent(payload: LeadSubmissionPayload): LeadSourceIntent {
  const source = String(payload.attribution?.source ?? payload.firstTouch?.source ?? "direct").toLowerCase();
  const campaign = String(payload.attribution?.utm_campaign ?? "").toLowerCase();
  const intentText = [payload.primaryUseCase, payload.intentNote, payload.role, payload.timeline]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();

  if (source.includes("partner") || campaign.includes("partner") || intentText.includes("reseller")) {
    return "partner";
  }

  if (/(buyer|book|demo|assessment|enterprise|security|audit|compliance|sox|hipaa|incident|migration|approval|pilot|procurement)/.test(`${campaign} ${intentText}`)) {
    return "high-intent";
  }

  if (source.startsWith("utm:") || /(google|linkedin|bing|paid|ads)/.test(source) || /(ppc|paid|cpc)/.test(campaign)) {
    return "paid-intent";
  }

  if (source.startsWith("ref:") || /(organic|seo|blog|newsletter)/.test(source)) {
    return "organic";
  }

  return "direct";
}

function normalizeSourceIntent(input: string | undefined): LeadSourceIntent {
  const v = (input ?? "").trim().toLowerCase();
  if (v === "partner" || v === "paid-intent" || v === "high-intent" || v === "organic" || v === "direct") {
    return v;
  }
  return "direct";
}

async function leadSubmitLockAcquire(env: Env, idempotencyKey: string): Promise<{
  ok: boolean;
  replay: boolean;
  inFlight: boolean;
  leadId?: string;
}> {
  const id = env.LEAD_SUBMIT_LOCK.idFromName(idempotencyKey);
  const stub = env.LEAD_SUBMIT_LOCK.get(id);
  const res = await stub.fetch("https://lead-submit-lock/acquire", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ ttlMs: 45_000 }),
  });

  const payload = await res.json<any>().catch(() => ({}));
  if (res.status === 409) {
    return { ok: false, replay: false, inFlight: true };
  }

  if (!res.ok || payload?.ok !== true) {
    return { ok: false, replay: false, inFlight: false };
  }

  return {
    ok: true,
    replay: payload?.replay === true,
    inFlight: false,
    leadId: typeof payload?.leadId === "string" ? payload.leadId : undefined,
  };
}

async function leadSubmitLockComplete(env: Env, idempotencyKey: string, leadId: string): Promise<void> {
  const id = env.LEAD_SUBMIT_LOCK.idFromName(idempotencyKey);
  const stub = env.LEAD_SUBMIT_LOCK.get(id);
  await stub.fetch("https://lead-submit-lock/complete", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ leadId }),
  });
}

async function leadSubmitLockFail(env: Env, idempotencyKey: string): Promise<void> {
  const id = env.LEAD_SUBMIT_LOCK.idFromName(idempotencyKey);
  const stub = env.LEAD_SUBMIT_LOCK.get(id);
  await stub.fetch("https://lead-submit-lock/fail", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: "{}",
  });
}

function normalizeEmail(input: string | undefined): string {
  return (input ?? "").trim().toLowerCase();
}

function safeJsonParse<T>(raw: string | null, fallback: T): T {
  if (!raw) return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

function normalizeLeadPayload(body: any): LeadSubmissionPayload {
  const behaviorSrc = typeof body?.behavior === "object" && body.behavior !== null
    ? body.behavior as Record<string, unknown>
    : {};

  return {
    fullName: clipString(body?.fullName, 120),
    email: clipString(body?.email, 200),
    company: clipString(body?.company, 160),
    role: clipString(body?.role, 120),
    teamSize: clipString(body?.teamSize, 80),
    timeline: clipString(body?.timeline, 120),
    primaryUseCase: clipString(body?.primaryUseCase, 600),
    intentNote: clipString(body?.intentNote, 1200),
    assessment: {
      readinessScore: normalizeResultCount(body?.assessment?.readinessScore),
      roiScore: normalizeResultCount(body?.assessment?.roiScore),
      riskScore: normalizeResultCount(body?.assessment?.riskScore),
      confidenceLabel: clipString(body?.assessment?.confidenceLabel, 80),
    },
    behavior: {
      sessionEvents: normalizeResultCount(behaviorSrc.sessionEvents),
      ctaClicks: normalizeResultCount(behaviorSrc.ctaClicks),
      intentViews: normalizeResultCount(behaviorSrc.intentViews),
      assessmentCompleted: behaviorSrc.assessmentCompleted === true,
      secondsOnSite: normalizeResultCount(behaviorSrc.secondsOnSite),
    },
    attribution: normalizeAttribution(body?.attribution),
    firstTouch: {
      ts: clipString(body?.firstTouch?.ts, 80),
      path: clipString(body?.firstTouch?.path, 240),
      pageFamily: clipString(body?.firstTouch?.pageFamily, 80),
      source: clipString(body?.firstTouch?.source, 80),
    },
    page: clipString(body?.page, 240),
    pageFamily: clipString(body?.pageFamily, 80),
    variantId: clipString(body?.variantId, 120),
    heroVariant: clipString(body?.heroVariant, 120),
    ctaVariant: clipString(body?.ctaVariant, 120),
    visitorId: clipString(body?.visitorId, 140),
    turnstileToken: clipString(body?.turnstileToken, 3000),
    idempotencyKey: clipString(body?.idempotencyKey, 160),
  };
}

function scoreLeadIntent(payload: LeadSubmissionPayload): LeadScoreResult {
  const baseReadiness = Math.min(100, Math.max(0, Number(payload.assessment?.readinessScore ?? 0)));
  const baseRoi = Math.min(100, Math.max(0, Number(payload.assessment?.roiScore ?? 0)));
  const baseRisk = Math.min(100, Math.max(0, Number(payload.assessment?.riskScore ?? 40)));
  const sourceIntent = inferSourceIntent(payload);

  const scoreReasons: LeadScoreReason[] = [];

  const teamBoost = (() => {
    const t = (payload.teamSize ?? "").toLowerCase();
    if (/(500|1000|enterprise|global)/.test(t)) return 16;
    if (/(100|200|300|400)/.test(t)) return 10;
    if (/(50|75)/.test(t)) return 6;
    return 2;
  })();
  if (teamBoost > 0) {
    scoreReasons.push({ code: "team_size", points: teamBoost, detail: payload.teamSize ?? "unknown" });
  }

  const timelineBoost = (() => {
    const t = (payload.timeline ?? "").toLowerCase();
    if (/(now|immediate|this week|2 weeks)/.test(t)) return 14;
    if (/(30|month|q1|q2|q3|q4)/.test(t)) return 8;
    if (/(quarter|90)/.test(t)) return 4;
    return 1;
  })();
  if (timelineBoost > 0) {
    scoreReasons.push({ code: "timeline_urgency", points: timelineBoost, detail: payload.timeline ?? "unknown" });
  }

  const sourceBoost = sourceIntent === "partner"
    ? 10
    : sourceIntent === "high-intent"
      ? 8
      : sourceIntent === "paid-intent"
        ? 6
        : sourceIntent === "organic"
          ? 3
          : 1;
  scoreReasons.push({ code: "source_intent", points: sourceBoost, detail: sourceIntent });

  const campaign = String(payload.attribution?.utm_campaign ?? "").toLowerCase();
  const campaignBoost = /(enterprise|security|audit|compliance|pilot|buyer|intent|book|demo)/.test(campaign)
    ? 6
    : 0;
  if (campaignBoost > 0) {
    scoreReasons.push({ code: "campaign_match", points: campaignBoost, detail: campaign });
  }

  const behavior = payload.behavior ?? {};
  const behaviorBoost = Math.min(
    18,
    Math.round(
      (Number(behavior.ctaClicks ?? 0) * 2.2)
      + (Number(behavior.intentViews ?? 0) * 1.3)
      + (Number(behavior.sessionEvents ?? 0) * 0.5)
      + (behavior.assessmentCompleted ? 6 : 0)
      + Math.min(5, Number(behavior.secondsOnSite ?? 0) / 120),
    ),
  );
  if (behaviorBoost > 0) {
    scoreReasons.push({
      code: "behavior_signals",
      points: behaviorBoost,
      detail: `cta=${Number(behavior.ctaClicks ?? 0)},intentViews=${Number(behavior.intentViews ?? 0)}`,
    });
  }

  const intentSignals = [
    payload.primaryUseCase,
    payload.intentNote,
    payload.role,
  ].join(" ").toLowerCase();

  const urgencyBoost = /(approval|security|audit|compliance|risk|incident|production|rollout|migration|sox|hipaa|soc 2)/.test(intentSignals)
    ? 10
    : 0;
  if (urgencyBoost > 0) {
    scoreReasons.push({ code: "problem_urgency", points: urgencyBoost, detail: "regulatory-or-incident-signal" });
  }

  const intentScore = Math.min(100, baseReadiness + teamBoost + timelineBoost + urgencyBoost + sourceBoost + campaignBoost + behaviorBoost);
  const readinessScore = Math.min(100, Math.max(0, baseReadiness || Math.round(intentScore * 0.72)));
  const roiScore = Math.min(100, Math.max(0, baseRoi || Math.round(intentScore * 0.68)));
  const riskScore = Math.min(100, Math.max(0, baseRisk));

  const qualificationScore = Math.max(
    0,
    Math.min(
      100,
      Math.round((intentScore * 0.36) + (readinessScore * 0.27) + (roiScore * 0.23) + ((100 - riskScore) * 0.14)),
    ),
  );

  const confidenceLabel = qualificationScore >= 78
    ? "high-intent"
    : qualificationScore >= 55
      ? "medium-intent"
      : "early-intent";

  const scoreBand = scoreBandFromQualification(qualificationScore);
  const segment = segmentFromPayload(payload, qualificationScore);

  return {
    intentScore,
    readinessScore,
    roiScore,
    riskScore,
    qualificationScore,
    confidenceLabel,
    scoreBand,
    segment,
    sourceIntent,
    scoreReasons: scoreReasons.sort((a, b) => b.points - a.points),
  };
}

async function verifyTurnstile(token: string | undefined, request: Request, env: Env): Promise<{ ok: boolean; error?: string }> {
  const posture = resolveTurnstilePosture(env);

  if (!posture.required) {
    return { ok: true };
  }

  if (!posture.formEnabled) {
    return { ok: false, error: posture.code };
  }

  const secret = env.TURNSTILE_SECRET_KEY?.trim();
  if (!secret) {
    return { ok: false, error: "TURNSTILE_NOT_CONFIGURED" };
  }

  if (!token) {
    return { ok: false, error: "TURNSTILE_TOKEN_MISSING" };
  }

  try {
    const ip = clipString(request.headers.get("cf-connecting-ip"), 120);
    const form = new URLSearchParams();
    form.set("secret", secret);
    form.set("response", token);
    if (ip) form.set("remoteip", ip);

    const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: form.toString(),
    });

    const payload = safeJsonParse<any>(await res.text(), {});
    if (payload?.success === true) return { ok: true };

    const errorCodes = Array.isArray(payload?.["error-codes"])
      ? payload["error-codes"]
      : [];

    const errCode = errorCodes.length > 0
      ? String(errorCodes[0])
      : "TURNSTILE_VERIFY_FAILED";

    return { ok: false, error: errCode };
  } catch {
    return { ok: false, error: "TURNSTILE_UPSTREAM_UNAVAILABLE" };
  }
}

async function transitionLeadState(
  env: Env,
  leadId: string,
  nextState: LeadLifecycleStatus,
  reasonCode: string,
  metadata: Record<string, unknown> = {},
): Promise<void> {
  const currentRow = await env.DB.prepare(
    `SELECT status FROM leads WHERE lead_id = ?1 LIMIT 1`,
  ).bind(leadId).first<{ status: string }>();

  const current = normalizeLeadStatus(currentRow?.status);
  if (current === nextState) return;

  const allowedNext = LEAD_STATE_TRANSITIONS[current] ?? [];
  if (!allowedNext.includes(nextState)) {
    return;
  }

  const nowIso = new Date().toISOString();

  await env.DB.prepare(
    `UPDATE leads SET status = ?2, lifecycle_updated_at = ?3, updated_at = ?3 WHERE lead_id = ?1`,
  ).bind(leadId, nextState, nowIso).run();

  await env.DB.prepare(
    `INSERT INTO lead_state_transitions (
      transition_id,
      lead_id,
      from_state,
      to_state,
      reason_code,
      metadata_json,
      created_at
    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)`,
  )
    .bind(
      randomId("lead_state"),
      leadId,
      current,
      nextState,
      reasonCode,
      JSON.stringify(metadata),
      nowIso,
    )
    .run();

  if (RESPONSE_SLA_CLOSED_STATES.has(nextState)) {
    await env.DB.prepare(
      `UPDATE lead_alerts
       SET status = 'resolved', resolved_at = ?2, updated_at = ?2
       WHERE alert_type = 'lead_response_sla_miss'
         AND lead_id = ?1
         AND status = 'open'`,
    ).bind(leadId, nowIso).run().catch(() => {});
  }
}

function addMinutesIso(iso: string, minutes: number): string {
  const ms = Date.parse(iso);
  if (Number.isNaN(ms)) return new Date().toISOString();
  return new Date(ms + minutes * 60_000).toISOString();
}

function diffMinutes(fromIso: string, toIso: string): number {
  const fromMs = Date.parse(fromIso);
  const toMs = Date.parse(toIso);
  if (Number.isNaN(fromMs) || Number.isNaN(toMs)) return 0;
  return Math.max(0, Math.floor((toMs - fromMs) / 60_000));
}

async function upsertLeadAlert(env: Env, params: {
  alertKey: string;
  alertType: string;
  severity: "info" | "warning" | "critical";
  leadId?: string;
  jobId?: string;
  summary: string;
  metadata?: Record<string, unknown>;
}): Promise<void> {
  const nowIso = new Date().toISOString();
  await env.DB.prepare(
    `INSERT INTO lead_alerts (
      alert_id,
      alert_key,
      alert_type,
      severity,
      lead_id,
      job_id,
      status,
      summary,
      metadata_json,
      first_seen_at,
      last_seen_at,
      created_at,
      updated_at
    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'open', ?7, ?8, ?9, ?9, ?9, ?9)
    ON CONFLICT(alert_key)
    DO UPDATE SET
      status = 'open',
      severity = excluded.severity,
      summary = excluded.summary,
      metadata_json = excluded.metadata_json,
      last_seen_at = excluded.last_seen_at,
      updated_at = excluded.updated_at,
      resolved_at = NULL`,
  )
    .bind(
      randomId("alert"),
      params.alertKey,
      params.alertType,
      params.severity,
      params.leadId ?? null,
      params.jobId ?? null,
      params.summary.slice(0, 280),
      JSON.stringify(params.metadata ?? {}),
      nowIso,
    )
    .run();
}

async function resolveLeadAlertsByType(env: Env, alertType: string, keepKeys: string[] = []): Promise<void> {
  const nowIso = new Date().toISOString();
  if (keepKeys.length === 0) {
    await env.DB.prepare(
      `UPDATE lead_alerts
       SET status = 'resolved', resolved_at = ?2, updated_at = ?2
       WHERE alert_type = ?1 AND status = 'open'`,
    ).bind(alertType, nowIso).run();
    return;
  }

  const placeholders = keepKeys.map((_, i) => `?${i + 3}`).join(",");
  await env.DB.prepare(
    `UPDATE lead_alerts
     SET status = 'resolved', resolved_at = ?2, updated_at = ?2
     WHERE alert_type = ?1
       AND status = 'open'
       AND alert_key NOT IN (${placeholders})`,
  ).bind(alertType, nowIso, ...keepKeys).run();
}

async function hashIpForAbuse(request: Request, env: Env): Promise<string> {
  const rawIp = clipString(request.headers.get("cf-connecting-ip"), 120) ?? "0.0.0.0";
  const salt = env.LEAD_ID_HASH_SALT?.trim() ?? "clawea-www-lead";
  return sha256Base64Url(`${salt}|ip|${rawIp}`);
}

async function evaluateLeadAbuse(
  payload: LeadSubmissionPayload,
  request: Request,
  env: Env,
): Promise<{
  ok: boolean;
  denyCode?: string;
  ipHash: string;
  emailHash: string | null;
}> {
  const email = normalizeEmail(payload.email);
  const salt = env.LEAD_ID_HASH_SALT?.trim() ?? "clawea-www-lead";
  const ipHash = await hashIpForAbuse(request, env);
  const emailHash = email ? await sha256Base64Url(`${salt}|email|${email}`) : null;

  const domain = email.includes("@") ? email.split("@")[1] : "";
  if (domain && DISPOSABLE_EMAIL_DOMAINS.has(domain)) {
    return { ok: false, denyCode: "DISPOSABLE_EMAIL_DENY", ipHash, emailHash };
  }

  const minutes = leadWindowMinutes(env);
  const cutoff = new Date(Date.now() - minutes * 60_000).toISOString();

  const ipRow = await env.DB.prepare(
    `SELECT COUNT(*) AS count
     FROM lead_submit_attempts
     WHERE ip_hash = ?1 AND created_at >= ?2`,
  ).bind(ipHash, cutoff).first<{ count: number }>();

  if (Number(ipRow?.count ?? 0) >= leadIpWindowLimit(env)) {
    return { ok: false, denyCode: "RATE_LIMIT_IP_WINDOW", ipHash, emailHash };
  }

  if (emailHash) {
    const emailRow = await env.DB.prepare(
      `SELECT COUNT(*) AS count
       FROM lead_submit_attempts
       WHERE email_hash = ?1 AND created_at >= ?2`,
    ).bind(emailHash, cutoff).first<{ count: number }>();

    if (Number(emailRow?.count ?? 0) >= leadEmailWindowLimit(env)) {
      return { ok: false, denyCode: "RATE_LIMIT_EMAIL_WINDOW", ipHash, emailHash };
    }
  }

  return { ok: true, ipHash, emailHash };
}

async function recordLeadSubmitAttempt(env: Env, params: {
  leadId?: string;
  ipHash: string;
  emailHash: string | null;
  idempotencyKey?: string;
  visitorId?: string;
  source: string;
  campaignId: string;
  pageFamily: string;
  outcomeCode: string;
}): Promise<void> {
  await env.DB.prepare(
    `INSERT INTO lead_submit_attempts (
      attempt_id,
      lead_id,
      ip_hash,
      email_hash,
      idempotency_key,
      visitor_id,
      source,
      campaign_id,
      page_family,
      outcome_code,
      created_at
    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)`,
  )
    .bind(
      randomId("lead_attempt"),
      params.leadId ?? null,
      params.ipHash,
      params.emailHash,
      params.idempotencyKey ?? null,
      params.visitorId ?? null,
      params.source,
      params.campaignId,
      params.pageFamily,
      params.outcomeCode,
      new Date().toISOString(),
    )
    .run();
}

async function loadCrmRoutingConfig(env: Env): Promise<CrmRoutingConfig> {
  const key = env.CRM_PROVIDER_CONFIG_KEY?.trim() || "crm-provider-config-v1";
  const kvRaw = await env.VARIANT_CONFIG.get(key, "text").catch(() => null);
  const envRaw = env.CRM_PROVIDER_CONFIG_JSON?.trim() || null;
  const raw = kvRaw || envRaw;

  if (!raw) return DEFAULT_CRM_ROUTING_CONFIG;

  const parsed = safeJsonParse<any>(raw, {});
  const parsedProviders = Array.isArray(parsed?.providers) ? parsed.providers as Array<Record<string, unknown>> : [];

  const providers: CrmProvider[] = parsedProviders.length > 0
    ? parsedProviders
      .filter((p) => typeof p?.id === "string")
      .map((p) => {
        const authTypeRaw = typeof p.authType === "string" ? p.authType : "none";
        const authType: CrmProvider["authType"] = authTypeRaw === "bearer" || authTypeRaw === "header" || authTypeRaw === "none"
          ? authTypeRaw
          : "none";

        return {
          id: String(p.id),
          endpoint: typeof p.endpoint === "string" ? p.endpoint : undefined,
          authType,
          authHeader: typeof p.authHeader === "string" ? p.authHeader : undefined,
        };
      })
    : DEFAULT_CRM_ROUTING_CONFIG.providers;

  const defaults = (parsed?.defaultProviderBySegment ?? {}) as Partial<Record<LeadSegment, string>>;
  const parsedRules = Array.isArray(parsed?.providerRules)
    ? parsed.providerRules as Array<Record<string, unknown>>
    : [];

  const providerRules: CrmRoutingRule[] = [];
  for (const rule of parsedRules) {
    const providerId = clipString(rule?.providerId, 80);
    if (!providerId) continue;

    const segmentRaw = clipString(rule?.segment, 24);
    const segment = segmentRaw === "enterprise" || segmentRaw === "smb" || segmentRaw === "partner"
      ? segmentRaw
      : undefined;

    const scoreBandRaw = clipString(rule?.scoreBand, 24);
    const scoreBand = scoreBandRaw === "high" || scoreBandRaw === "medium" || scoreBandRaw === "low"
      ? scoreBandRaw
      : undefined;

    const sourceIntentRaw = clipString(rule?.sourceIntent, 24);
    const sourceIntent = sourceIntentRaw
      ? normalizeSourceIntent(sourceIntentRaw)
      : undefined;

    providerRules.push({
      providerId,
      segment,
      scoreBand,
      sourceIntent,
    });
  }

  const config: CrmRoutingConfig = {
    defaultProviderBySegment: {
      enterprise: typeof defaults.enterprise === "string" ? defaults.enterprise : DEFAULT_CRM_ROUTING_CONFIG.defaultProviderBySegment.enterprise,
      smb: typeof defaults.smb === "string" ? defaults.smb : DEFAULT_CRM_ROUTING_CONFIG.defaultProviderBySegment.smb,
      partner: typeof defaults.partner === "string" ? defaults.partner : DEFAULT_CRM_ROUTING_CONFIG.defaultProviderBySegment.partner,
    },
    providers,
    providerRules: providerRules.length > 0 ? providerRules : DEFAULT_CRM_ROUTING_CONFIG.providerRules,
  };

  return config;
}

function crmAuthTokenMap(env: Env): Record<string, string> {
  return safeJsonParse<Record<string, string>>(env.CRM_PROVIDER_AUTH_JSON ?? null, {});
}

function selectProviderForLead(
  config: CrmRoutingConfig,
  segment: LeadSegment,
  scoreBand: LeadScoreBand,
  sourceIntent: LeadSourceIntent,
): string {
  const providers = new Set(config.providers.map((p) => p.id));

  const matchedRule = config.providerRules.find((rule) => {
    if (rule.segment && rule.segment !== segment) return false;
    if (rule.scoreBand && rule.scoreBand !== scoreBand) return false;
    if (rule.sourceIntent && rule.sourceIntent !== sourceIntent) return false;
    return true;
  });

  const ruleProvider = matchedRule?.providerId;
  if (ruleProvider && providers.has(ruleProvider)) {
    return ruleProvider;
  }

  const fallback = config.defaultProviderBySegment[segment] ?? "internal-r2";
  if (providers.has(fallback)) return fallback;

  return providers.values().next().value ?? "internal-r2";
}

function queueForSegment(env: Env, segment: LeadSegment): Queue {
  if (segment === "enterprise") return env.LEAD_ROUTE_ENTERPRISE;
  if (segment === "partner") return env.LEAD_ROUTE_PARTNER;
  return env.LEAD_ROUTE_SMB;
}

async function enqueueRoutingJob(env: Env, segment: LeadSegment, body: Record<string, unknown>): Promise<void> {
  const q = queueForSegment(env, segment);
  await q.send(body);
}

async function persistTrackingEventD1(env: Env, event: TrackingEvent): Promise<void> {
  try {
    await env.DB.prepare(
      `INSERT INTO funnel_events (
        event_id,
        event_type,
        page,
        page_family,
        source,
        cta_id,
        cta_variant,
        action_outcome,
        query,
        result_count,
        target_path,
        variant_id,
        hero_variant,
        visitor_id,
        attribution_json,
        event_ts,
        created_at
      ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
      `,
    )
      .bind(
        randomId("ev"),
        event.eventType,
        event.page,
        event.pageFamily,
        event.source,
        event.ctaId ?? null,
        event.ctaVariant ?? null,
        event.actionOutcome ?? null,
        event.query ?? null,
        event.resultCount ?? null,
        event.targetPath ?? null,
        event.variantId ?? null,
        event.heroVariant ?? null,
        event.visitorId ?? null,
        JSON.stringify(event.attribution ?? {}),
        event.ts,
        new Date().toISOString(),
      )
      .run();

    env.ANALYTICS?.writeDataPoint({
      indexes: [event.eventType, event.pageFamily, event.ctaVariant ?? "none", event.source],
      blobs: [event.page, event.variantId ?? "none", event.actionOutcome ?? "none"],
      doubles: [
        Number(event.resultCount ?? 0),
        Number(event.eventType === "cta_click" ? 1 : 0),
        Number(event.eventType === "lead_submit" ? 1 : 0),
      ],
    });
  } catch (err) {
    console.error("FUNNEL_EVENT_D1_INSERT_FAILED", err);
  }
}

async function upsertLeadFromPayload(payload: LeadSubmissionPayload, request: Request, env: Env): Promise<{
  leadId: string;
  deduped: boolean;
  idempotentReplay: boolean;
  scores: LeadScoreResult;
  idempotencyKey: string;
  segment: LeadSegment;
  routeJobId: string | null;
}> {
  const nowIso = new Date().toISOString();
  const email = normalizeEmail(payload.email);

  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw new Error("EMAIL_INVALID");
  }

  const idempotencyKey = payload.idempotencyKey
    ?? `idem_${(await sha256Base64Url([
      email,
      payload.page ?? "/contact",
      payload.attribution?.utm_campaign ?? "",
      payload.visitorId ?? "",
    ].join("|"))).slice(0, 30)}`;

  const lock = await leadSubmitLockAcquire(env, idempotencyKey);
  if (!lock.ok) {
    if (lock.inFlight) {
      throw new Error("IDEMPOTENCY_IN_FLIGHT");
    }
    throw new Error("IDEMPOTENCY_LOCK_FAILED");
  }

  if (lock.replay && lock.leadId) {
    const replayScores = scoreLeadIntent(payload);
    return {
      leadId: lock.leadId,
      deduped: true,
      idempotentReplay: true,
      scores: replayScores,
      idempotencyKey,
      segment: replayScores.segment,
      routeJobId: null,
    };
  }

  try {
    const salt = env.LEAD_ID_HASH_SALT?.trim() ?? "clawea-www-lead";
    const identityHash = await sha256Base64Url(`${salt}|${email}`);
    const emailHash = await sha256Base64Url(email);

    const page = payload.page ?? "/contact";
    const pageFamily = payload.pageFamily ?? pageFamilyFromPath(page);
    const source = payload.attribution?.source ?? payload.firstTouch?.source ?? "direct";
    const campaignId = payload.attribution?.utm_campaign ?? "";

    const scores = scoreLeadIntent(payload);

    const emailParts = email.split("@");
    const emailHint = emailParts.length === 2
      ? `${emailParts[0].slice(0, 2)}***@${emailParts[1]}`
      : "***";

    const existing = await env.DB.prepare(
      `SELECT lead_id, dedupe_count, status FROM leads WHERE identity_hash = ?1 LIMIT 1`,
    ).bind(identityHash).first<{ lead_id: string; dedupe_count: number; status: string }>();

    const leadId = existing?.lead_id ?? randomId("lead");
    const deduped = Boolean(existing?.lead_id);

    if (!deduped) {
      await env.DB.prepare(
        `INSERT INTO leads (
          lead_id,
          identity_hash,
          email_hash,
          email_hint,
          full_name,
          company,
          role,
          team_size,
          timeline,
          primary_use_case,
          intent_note,
          source,
          source_intent,
          page,
          page_family,
          attribution_json,
          first_touch_json,
          assessment_json,
          behavior_json,
          readiness_score,
          roi_score,
          risk_score,
          intent_score,
          qualification_score,
          score_band,
          segment,
          campaign_id,
          variant_id,
          hero_variant,
          cta_variant,
          status,
          route_status,
          dedupe_count,
          created_at,
          updated_at,
          last_seen_at,
          lifecycle_updated_at
        ) VALUES (
          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
          ?, ?, ?, ?, ?, ?, ?, ?,
          ?, ?, ?, ?, ?, ?, ?,
          ?, ?, ?, ?, 'new', 'pending', 0, ?, ?, ?, ?
        )`,
      )
        .bind(
          leadId,
          identityHash,
          emailHash,
          emailHint,
          payload.fullName ?? "",
          payload.company ?? "",
          payload.role ?? "",
          payload.teamSize ?? "",
          payload.timeline ?? "",
          payload.primaryUseCase ?? "",
          payload.intentNote ?? "",
          source,
          scores.sourceIntent,
          page,
          pageFamily,
          JSON.stringify(payload.attribution ?? {}),
          JSON.stringify(payload.firstTouch ?? {}),
          JSON.stringify(payload.assessment ?? {}),
          JSON.stringify(payload.behavior ?? {}),
          scores.readinessScore,
          scores.roiScore,
          scores.riskScore,
          scores.intentScore,
          scores.qualificationScore,
          scores.scoreBand,
          scores.segment,
          campaignId,
          payload.variantId ?? "",
          payload.heroVariant ?? "",
          payload.ctaVariant ?? "",
          nowIso,
          nowIso,
          nowIso,
          nowIso,
        )
        .run();
    } else {
      await env.DB.prepare(
        `UPDATE leads
          SET
            full_name = COALESCE(NULLIF(?,''), full_name),
            company = COALESCE(NULLIF(?,''), company),
            role = COALESCE(NULLIF(?,''), role),
            team_size = COALESCE(NULLIF(?,''), team_size),
            timeline = COALESCE(NULLIF(?,''), timeline),
            primary_use_case = COALESCE(NULLIF(?,''), primary_use_case),
            intent_note = COALESCE(NULLIF(?,''), intent_note),
            source = COALESCE(NULLIF(?,''), source),
            source_intent = COALESCE(NULLIF(?,''), source_intent),
            page = COALESCE(NULLIF(?,''), page),
            page_family = COALESCE(NULLIF(?,''), page_family),
            campaign_id = COALESCE(NULLIF(?,''), campaign_id),
            variant_id = COALESCE(NULLIF(?,''), variant_id),
            hero_variant = COALESCE(NULLIF(?,''), hero_variant),
            cta_variant = COALESCE(NULLIF(?,''), cta_variant),
            attribution_json = CASE WHEN ? <> '{}' THEN ? ELSE attribution_json END,
            first_touch_json = CASE WHEN ? <> '{}' THEN ? ELSE first_touch_json END,
            assessment_json = CASE WHEN ? <> '{}' THEN ? ELSE assessment_json END,
            behavior_json = CASE WHEN ? <> '{}' THEN ? ELSE behavior_json END,
            readiness_score = MAX(readiness_score, ?),
            roi_score = MAX(roi_score, ?),
            risk_score = MIN(risk_score, ?),
            intent_score = MAX(intent_score, ?),
            qualification_score = MAX(qualification_score, ?),
            score_band = CASE WHEN MAX(qualification_score, ?) >= 80 THEN 'high' WHEN MAX(qualification_score, ?) >= 55 THEN 'medium' ELSE 'low' END,
            segment = CASE WHEN ? = 'partner' THEN 'partner' WHEN ? = 'enterprise' THEN 'enterprise' ELSE segment END,
            dedupe_count = dedupe_count + 1,
            updated_at = ?,
            last_seen_at = ?
          WHERE lead_id = ?`,
      )
        .bind(
          payload.fullName ?? "",
          payload.company ?? "",
          payload.role ?? "",
          payload.teamSize ?? "",
          payload.timeline ?? "",
          payload.primaryUseCase ?? "",
          payload.intentNote ?? "",
          source,
          scores.sourceIntent,
          page,
          pageFamily,
          campaignId,
          payload.variantId ?? "",
          payload.heroVariant ?? "",
          payload.ctaVariant ?? "",
          JSON.stringify(payload.attribution ?? {}),
          JSON.stringify(payload.attribution ?? {}),
          JSON.stringify(payload.firstTouch ?? {}),
          JSON.stringify(payload.firstTouch ?? {}),
          JSON.stringify(payload.assessment ?? {}),
          JSON.stringify(payload.assessment ?? {}),
          JSON.stringify(payload.behavior ?? {}),
          JSON.stringify(payload.behavior ?? {}),
          scores.readinessScore,
          scores.roiScore,
          scores.riskScore,
          scores.intentScore,
          scores.qualificationScore,
          scores.qualificationScore,
          scores.qualificationScore,
          scores.segment,
          scores.segment,
          nowIso,
          nowIso,
          leadId,
        )
        .run();
    }

    await env.DB.prepare(
      `INSERT OR REPLACE INTO lead_idempotency (idempotency_key, lead_id, created_at)
       VALUES (?1, ?2, ?3)`,
    ).bind(idempotencyKey, leadId, nowIso).run();

    await env.DB.prepare(
      `INSERT INTO lead_events (
        event_id,
        lead_id,
        event_type,
        event_payload_json,
        source,
        page,
        page_family,
        created_at
      ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)`,
    )
      .bind(
        randomId("lead_evt"),
        leadId,
        deduped ? "lead_deduped" : "lead_submitted",
        JSON.stringify({
          deduped,
          scores,
          emailHint,
          attribution: payload.attribution ?? {},
          campaignId,
          variantId: payload.variantId ?? null,
          ctaVariant: payload.ctaVariant ?? null,
          heroVariant: payload.heroVariant ?? null,
        }),
        source,
        page,
        pageFamily,
        nowIso,
      )
      .run();

    await transitionLeadState(env, leadId, "validated", "turnstile_validated", {
      source,
      pageFamily,
    });
    await transitionLeadState(env, leadId, "scored", "score_v3", {
      qualificationScore: scores.qualificationScore,
      scoreBand: scores.scoreBand,
      segment: scores.segment,
      sourceIntent: scores.sourceIntent,
      scoreReasons: scores.scoreReasons,
    });

    const routingConfig = await loadCrmRoutingConfig(env);
    const providerId = selectProviderForLead(
      routingConfig,
      scores.segment,
      scores.scoreBand,
      scores.sourceIntent,
    );

    await transitionLeadState(env, leadId, "routed", "routing_enqueued", {
      segment: scores.segment,
      sourceIntent: scores.sourceIntent,
      scoreBand: scores.scoreBand,
      providerId,
    });

    let routeJobId: string | null = null;

    const existingJob = await env.DB.prepare(
      `SELECT job_id FROM lead_routing_jobs WHERE idempotency_key = ?1 LIMIT 1`,
    ).bind(idempotencyKey).first<{ job_id: string }>();

    if (existingJob?.job_id) {
      routeJobId = existingJob.job_id;
    } else {
      routeJobId = randomId("route_job");

      await env.DB.prepare(
        `INSERT INTO lead_routing_jobs (
          job_id,
          lead_id,
          segment,
          provider_id,
          state,
          attempts,
          max_attempts,
          payload_json,
          idempotency_key,
          created_at,
          updated_at
        ) VALUES (?1, ?2, ?3, ?4, 'queued', 0, ?5, ?6, ?7, ?8, ?8)`,
      )
        .bind(
          routeJobId,
          leadId,
          scores.segment,
          providerId,
          routingMaxAttempts(env),
          JSON.stringify({
            source,
            sourceIntent: scores.sourceIntent,
            campaignId,
            scoreBand: scores.scoreBand,
            scoreReasons: scores.scoreReasons,
            variantId: payload.variantId ?? null,
          }),
          idempotencyKey,
          nowIso,
        )
        .run();

      await env.DB.prepare(
        `UPDATE leads
         SET route_status = 'queued', routed_provider_id = ?2, updated_at = ?3
         WHERE lead_id = ?1`,
      ).bind(leadId, providerId, nowIso).run();

      await enqueueRoutingJob(env, scores.segment, {
        type: "lead_route_dispatch",
        routeJobId,
        leadId,
        segment: scores.segment,
      });
    }

    await leadSubmitLockComplete(env, idempotencyKey, leadId);

    return {
      leadId,
      deduped,
      idempotentReplay: false,
      scores,
      idempotencyKey,
      segment: scores.segment,
      routeJobId,
    };
  } catch (err) {
    await leadSubmitLockFail(env, idempotencyKey);
    throw err;
  }
}

export async function submitLead(request: Request, env: Env): Promise<Response> {
  if (request.method !== "POST") {
    return apiError("METHOD_NOT_ALLOWED", "Use POST for this endpoint", 405);
  }

  let body: any;
  try {
    body = await request.json<any>();
  } catch {
    return apiError("INVALID_JSON", "Request body must be valid JSON", 400);
  }

  const payload = normalizeLeadPayload(body);
  const source = payload.attribution?.source ?? payload.firstTouch?.source ?? "direct";
  const campaignId = payload.attribution?.utm_campaign ?? "";
  const pageFamily = payload.pageFamily ?? pageFamilyFromPath(payload.page ?? "/contact");

  const abuse = await evaluateLeadAbuse(payload, request, env);
  if (!abuse.ok) {
    await recordLeadSubmitAttempt(env, {
      ipHash: abuse.ipHash,
      emailHash: abuse.emailHash,
      idempotencyKey: payload.idempotencyKey,
      visitorId: payload.visitorId,
      source,
      campaignId,
      pageFamily,
      outcomeCode: abuse.denyCode ?? "RATE_LIMIT_DENY",
    });

    return apiError(
      abuse.denyCode ?? "RATE_LIMIT_DENY",
      "Lead submission blocked by abuse protection policy",
      429,
    );
  }

  const turnstile = await verifyTurnstile(payload.turnstileToken, request, env);
  if (!turnstile.ok) {
    await recordLeadSubmitAttempt(env, {
      ipHash: abuse.ipHash,
      emailHash: abuse.emailHash,
      idempotencyKey: payload.idempotencyKey,
      visitorId: payload.visitorId,
      source,
      campaignId,
      pageFamily,
      outcomeCode: `TURNSTILE_${turnstile.error ?? "FAILED"}`,
    });

    return apiError("TURNSTILE_FAILED", turnstile.error ?? "Turnstile validation failed", 403);
  }

  try {
    const saved = await upsertLeadFromPayload(payload, request, env);

    await recordLeadSubmitAttempt(env, {
      leadId: saved.leadId,
      ipHash: abuse.ipHash,
      emailHash: abuse.emailHash,
      idempotencyKey: saved.idempotencyKey,
      visitorId: payload.visitorId,
      source,
      campaignId,
      pageFamily,
      outcomeCode: saved.idempotentReplay ? "IDEMPOTENT_REPLAY" : (saved.deduped ? "DEDUPED" : "ACCEPTED"),
    });

    try {
      await storeTrackingEvent(env, {
        eventType: "lead_submit",
        page: payload.page ?? "/contact",
        pageFamily,
        source,
        ctaId: payload.pageFamily === "assessment" ? "assessment-result-submit" : "contact-fast-submit",
        ctaVariant: payload.ctaVariant ?? "submit",
        actionOutcome: saved.deduped ? "deduped" : "submitted",
        variantId: payload.variantId ?? `${pageFamily}:proof:submit`,
        heroVariant: payload.heroVariant ?? "proof",
        visitorId: payload.visitorId,
        ts: new Date().toISOString(),
        attribution: payload.attribution ?? {},
        context: {},
        targetPath: saved.routeJobId ? "/api/routing/status" : undefined,
      });
    } catch (telemetryErr) {
      console.error("LEAD_SUBMIT_TELEMETRY_FAILED", telemetryErr);
    }

    return apiJson({
      ok: true,
      leadId: saved.leadId,
      routeJobId: saved.routeJobId,
      segment: saved.segment,
      scoreBand: saved.scores.scoreBand,
      deduped: saved.deduped,
      idempotentReplay: saved.idempotentReplay,
      confidenceLabel: saved.scores.confidenceLabel,
      qualificationScore: saved.scores.qualificationScore,
      sourceIntent: saved.scores.sourceIntent,
      scoreReasons: saved.scores.scoreReasons.slice(0, 8),
      next: saved.scores.qualificationScore >= 78 ? "priority_follow_up" : "standard_follow_up",
      bookPath: `/book?lead=${encodeURIComponent(saved.leadId)}`,
    });
  } catch (err: any) {
    const code = String(err?.message ?? "LEAD_SUBMIT_FAILED");

    if (code === "IDEMPOTENCY_IN_FLIGHT") {
      await recordLeadSubmitAttempt(env, {
        ipHash: abuse.ipHash,
        emailHash: abuse.emailHash,
        idempotencyKey: payload.idempotencyKey,
        visitorId: payload.visitorId,
        source,
        campaignId,
        pageFamily,
        outcomeCode: "IDEMPOTENCY_IN_FLIGHT",
      });
      return apiError("IDEMPOTENCY_IN_FLIGHT", "A lead submission with this key is already processing", 409);
    }

    if (code === "EMAIL_INVALID") {
      await recordLeadSubmitAttempt(env, {
        ipHash: abuse.ipHash,
        emailHash: abuse.emailHash,
        idempotencyKey: payload.idempotencyKey,
        visitorId: payload.visitorId,
        source,
        campaignId,
        pageFamily,
        outcomeCode: "EMAIL_INVALID",
      });
      return apiError("EMAIL_INVALID", "A valid work email is required", 400);
    }

    console.error("LEAD_SUBMIT_FAILED", err);
    await recordLeadSubmitAttempt(env, {
      ipHash: abuse.ipHash,
      emailHash: abuse.emailHash,
      idempotencyKey: payload.idempotencyKey,
      visitorId: payload.visitorId,
      source,
      campaignId,
      pageFamily,
      outcomeCode: "LEAD_SUBMIT_FAILED",
    });

    return apiError("LEAD_SUBMIT_FAILED", "Lead intake failed", 500);
  }
}

function csvEscape(value: unknown): string {
  const s = String(value ?? "");
  if (/[",\n]/.test(s)) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

export async function leadsStatus(request: Request, env: Env): Promise<Response> {
  if (request.method !== "GET") {
    return apiError("METHOD_NOT_ALLOWED", "Use GET for this endpoint", 405);
  }

  const authError = checkOpsAuth(request, env);
  if (authError) return authError;

  const totalRow = await env.DB.prepare(`SELECT COUNT(*) AS count FROM leads`).first<{ count: number }>();

  const statusRows = await env.DB.prepare(
    `SELECT status AS key, COUNT(*) AS count FROM leads GROUP BY status ORDER BY count DESC`,
  ).all<{ key: string; count: number }>();

  const sourceRows = await env.DB.prepare(
    `SELECT source AS key, COUNT(*) AS count FROM leads GROUP BY source ORDER BY count DESC LIMIT 20`,
  ).all<{ key: string; count: number }>();

  const familyRows = await env.DB.prepare(
    `SELECT page_family AS key, COUNT(*) AS count FROM leads GROUP BY page_family ORDER BY count DESC LIMIT 20`,
  ).all<{ key: string; count: number }>();

  const transitionRows = await env.DB.prepare(
    `SELECT to_state AS key, COUNT(*) AS count FROM lead_state_transitions GROUP BY to_state ORDER BY count DESC LIMIT 20`,
  ).all<{ key: string; count: number }>();

  const recentRows = await env.DB.prepare(
    `SELECT
      lead_id,
      created_at,
      updated_at,
      last_seen_at,
      status,
      qualification_score,
      intent_score,
      risk_score,
      readiness_score,
      roi_score,
      dedupe_count,
      source,
      source_intent,
      page,
      page_family,
      full_name,
      company,
      role,
      team_size,
      timeline,
      primary_use_case,
      email_hint,
      score_band,
      segment,
      campaign_id,
      variant_id,
      hero_variant,
      cta_variant,
      route_status,
      routed_provider_id,
      booked_at,
      completed_at
    FROM leads
    ORDER BY last_seen_at DESC
    LIMIT 50`,
  ).all<LeadRow>();

  return apiJson({
    ok: true,
    generatedAt: new Date().toISOString(),
    totals: {
      leads: Number(totalRow?.count ?? 0),
      recentWindow: Number(recentRows.results?.length ?? 0),
    },
    breakdown: {
      byStatus: statusRows.results ?? [],
      bySource: sourceRows.results ?? [],
      byPageFamily: familyRows.results ?? [],
      byTransition: transitionRows.results ?? [],
    },
    recent: (recentRows.results ?? []).map((row) => ({
      leadId: row.lead_id,
      status: row.status,
      qualificationScore: row.qualification_score,
      intentScore: row.intent_score,
      readinessScore: row.readiness_score,
      roiScore: row.roi_score,
      riskScore: row.risk_score,
      dedupeCount: row.dedupe_count,
      source: row.source,
      sourceIntent: normalizeSourceIntent(row.source_intent),
      page: row.page,
      pageFamily: row.page_family,
      company: row.company,
      role: row.role,
      teamSize: row.team_size,
      timeline: row.timeline,
      scoreBand: row.score_band,
      segment: row.segment,
      campaignId: row.campaign_id,
      variantId: row.variant_id,
      heroVariant: row.hero_variant,
      ctaVariant: row.cta_variant,
      routeStatus: row.route_status,
      routedProviderId: row.routed_provider_id,
      bookedAt: row.booked_at,
      completedAt: row.completed_at,
      emailHint: row.email_hint,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      lastSeenAt: row.last_seen_at,
    })),
  });
}

export async function leadsExport(request: Request, env: Env): Promise<Response> {
  if (request.method !== "GET") {
    return apiError("METHOD_NOT_ALLOWED", "Use GET for this endpoint", 405);
  }

  const authError = checkOpsAuth(request, env);
  if (authError) return authError;

  const url = new URL(request.url);
  const format = (clipString(url.searchParams.get("format"), 12) ?? "json").toLowerCase();
  const statusFilter = clipString(url.searchParams.get("status"), 32);
  const segmentFilter = clipString(url.searchParams.get("segment"), 24);
  const scoreBandFilter = clipString(url.searchParams.get("scoreBand"), 24);
  const limit = Math.min(2000, Math.max(1, Number(url.searchParams.get("limit") ?? "500")));

  let sql = `SELECT
    lead_id,
    status,
    qualification_score,
    intent_score,
    readiness_score,
    roi_score,
    risk_score,
    dedupe_count,
    source,
    source_intent,
    page,
    page_family,
    company,
    role,
    team_size,
    timeline,
    primary_use_case,
    email_hint,
    score_band,
    segment,
    campaign_id,
    variant_id,
    hero_variant,
    cta_variant,
    route_status,
    routed_provider_id,
    booked_at,
    completed_at,
    created_at,
    updated_at,
    last_seen_at
  FROM leads`;

  const binds: Array<string | number> = [];
  const where: string[] = [];

  if (statusFilter) {
    where.push(`status = ?${binds.length + 1}`);
    binds.push(statusFilter);
  }

  if (segmentFilter) {
    where.push(`segment = ?${binds.length + 1}`);
    binds.push(segmentFilter);
  }

  if (scoreBandFilter) {
    where.push(`score_band = ?${binds.length + 1}`);
    binds.push(scoreBandFilter);
  }

  if (where.length > 0) {
    sql += ` WHERE ${where.join(" AND ")}`;
  }

  sql += ` ORDER BY last_seen_at DESC LIMIT ${limit}`;

  const rows = binds.length > 0
    ? await env.DB.prepare(sql).bind(...binds).all<Record<string, unknown>>()
    : await env.DB.prepare(sql).all<Record<string, unknown>>();
  const results = rows.results ?? [];

  if (format === "csv") {
    const headers = [
      "lead_id",
      "status",
      "qualification_score",
      "intent_score",
      "readiness_score",
      "roi_score",
      "risk_score",
      "score_band",
      "segment",
      "campaign_id",
      "variant_id",
      "hero_variant",
      "cta_variant",
      "route_status",
      "routed_provider_id",
      "dedupe_count",
      "source",
      "source_intent",
      "page",
      "page_family",
      "company",
      "role",
      "team_size",
      "timeline",
      "primary_use_case",
      "email_hint",
      "booked_at",
      "completed_at",
      "created_at",
      "updated_at",
      "last_seen_at",
    ];

    const lines = [headers.join(",")];
    for (const row of results) {
      lines.push(headers.map((h) => csvEscape(row[h])).join(","));
    }

    return new Response(lines.join("\n"), {
      status: 200,
      headers: apiHeaders({
        "content-type": "text/csv;charset=utf-8",
        "content-disposition": `attachment; filename="clawea-leads-${new Date().toISOString().slice(0, 10)}.csv"`,
      }),
    });
  }

  return apiJson({
    ok: true,
    generatedAt: new Date().toISOString(),
    count: results.length,
    leads: results,
  });
}

export async function computeLeadResponseSla(env: Env): Promise<{
  nowIso: string;
  slaMinutes: number;
  totalLeads: number;
  openLeads: number;
  dueSoon: number;
  breached: number;
  breachRate: number;
  openByStatus: Array<{ key: string; count: number }>;
  breachedBySegment: Array<{ key: string; count: number }>;
  topBreaches: Array<Record<string, unknown>>;
}> {
  const nowIso = new Date().toISOString();
  const nowMs = Date.parse(nowIso);
  const slaMinutes = leadResponseSlaMinutes(env);
  const recentCutoff = new Date(nowMs - (30 * 24 * 60 * 60 * 1000)).toISOString();

  const rows = await env.DB.prepare(
    `SELECT
      lead_id,
      status,
      created_at,
      source,
      source_intent,
      page_family,
      campaign_id,
      segment,
      score_band,
      qualification_score
     FROM leads
     WHERE created_at >= ?1
     ORDER BY created_at DESC
     LIMIT 4000`,
  ).bind(recentCutoff).all<Record<string, unknown>>();

  const openByStatus = new Map<string, number>();
  const breachedBySegment = new Map<string, number>();
  const topBreaches: Array<Record<string, unknown>> = [];
  const activeAlertKeys: string[] = [];

  let totalLeads = 0;
  let openLeads = 0;
  let dueSoon = 0;
  let breached = 0;

  for (const row of rows.results ?? []) {
    totalLeads += 1;
    const leadId = String(row.lead_id ?? "");
    const status = normalizeLeadStatus(clipString(row.status, 24));
    if (!RESPONSE_SLA_OPEN_STATES.has(status)) {
      continue;
    }

    openLeads += 1;
    openByStatus.set(status, (openByStatus.get(status) ?? 0) + 1);

    const createdAt = String(row.created_at ?? nowIso);
    const dueAt = addMinutesIso(createdAt, slaMinutes);
    const dueMs = Date.parse(dueAt);
    if (Number.isNaN(dueMs)) continue;

    const minutesToDue = Math.floor((dueMs - nowMs) / 60_000);
    const overdueMinutes = Math.max(0, Math.floor((nowMs - dueMs) / 60_000));

    if (minutesToDue <= 15 && minutesToDue >= 0) {
      dueSoon += 1;
    }

    if (nowMs <= dueMs) continue;

    breached += 1;
    const segment = clipString(row.segment, 24) ?? "smb";
    breachedBySegment.set(segment, (breachedBySegment.get(segment) ?? 0) + 1);

    const alertKey = `lead_response_sla_miss:${leadId}`;
    activeAlertKeys.push(alertKey);

    await upsertLeadAlert(env, {
      alertKey,
      alertType: "lead_response_sla_miss",
      severity: overdueMinutes >= 120 ? "critical" : "warning",
      leadId,
      summary: `Lead ${leadId} missed first-response SLA by ${overdueMinutes}m`,
      metadata: {
        status,
        createdAt,
        dueAt,
        overdueMinutes,
        source: String(row.source ?? "direct"),
        sourceIntent: String(row.source_intent ?? "direct"),
        pageFamily: String(row.page_family ?? "contact"),
        campaignId: String(row.campaign_id ?? ""),
        scoreBand: String(row.score_band ?? "low"),
        qualificationScore: Number(row.qualification_score ?? 0),
      },
    });

    topBreaches.push({
      leadId,
      status,
      createdAt,
      dueAt,
      overdueMinutes,
      source: String(row.source ?? "direct"),
      sourceIntent: String(row.source_intent ?? "direct"),
      pageFamily: String(row.page_family ?? "contact"),
      campaignId: String(row.campaign_id ?? ""),
      segment,
      scoreBand: String(row.score_band ?? "low"),
      qualificationScore: Number(row.qualification_score ?? 0),
    });
  }

  await resolveLeadAlertsByType(env, "lead_response_sla_miss", activeAlertKeys);

  topBreaches.sort((a, b) => Number(b.overdueMinutes ?? 0) - Number(a.overdueMinutes ?? 0));

  const openByStatusRows = [...openByStatus.entries()]
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count);

  const breachedBySegmentRows = [...breachedBySegment.entries()]
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count);

  return {
    nowIso,
    slaMinutes,
    totalLeads,
    openLeads,
    dueSoon,
    breached,
    breachRate: openLeads > 0 ? Number((breached / openLeads).toFixed(4)) : 0,
    openByStatus: openByStatusRows,
    breachedBySegment: breachedBySegmentRows,
    topBreaches: topBreaches.slice(0, 40),
  };
}

async function collectFailingStepBuckets(env: Env, fromIso: string, toIso: string): Promise<{
  leadSubmit: Array<{ key: string; count: number }>;
  routing: Array<{ key: string; count: number }>;
  top: Array<{ key: string; count: number }>;
}> {
  const submitRows = await env.DB.prepare(
    `SELECT outcome_code AS key, COUNT(*) AS count
     FROM lead_submit_attempts
     WHERE created_at >= ?1 AND created_at <= ?2
       AND outcome_code NOT IN ('ACCEPTED', 'DEDUPED', 'IDEMPOTENT_REPLAY')
     GROUP BY outcome_code
     ORDER BY count DESC
     LIMIT 50`,
  ).bind(fromIso, toIso).all<{ key: string; count: number }>();

  const routingRows = await env.DB.prepare(
    `SELECT COALESCE(NULLIF(last_error_code,''), state) AS key, COUNT(*) AS count
     FROM lead_routing_jobs
     WHERE updated_at >= ?1 AND updated_at <= ?2
       AND (state IN ('failed', 'dead_letter') OR last_error_code <> '')
     GROUP BY COALESCE(NULLIF(last_error_code,''), state)
     ORDER BY count DESC
     LIMIT 50`,
  ).bind(fromIso, toIso).all<{ key: string; count: number }>();

  const aggregate = new Map<string, number>();
  for (const row of submitRows.results ?? []) {
    aggregate.set(`submit:${row.key}`, (aggregate.get(`submit:${row.key}`) ?? 0) + Number(row.count ?? 0));
  }
  for (const row of routingRows.results ?? []) {
    aggregate.set(`routing:${row.key}`, (aggregate.get(`routing:${row.key}`) ?? 0) + Number(row.count ?? 0));
  }

  const top = [...aggregate.entries()]
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 30);

  return {
    leadSubmit: submitRows.results ?? [],
    routing: routingRows.results ?? [],
    top,
  };
}

export async function computeRoutingHealth(env: Env): Promise<{
  queueLagThresholdMinutes: number;
  maxLagMinutes: number;
  laggingJobs: Array<Record<string, unknown>>;
  stateCounts: Array<{ key: string; count: number }>;
  segmentCounts: Array<{ key: string; count: number }>;
  deadLetter: { total: number; pending: number };
}> {
  const nowIso = new Date().toISOString();
  const nowMs = Date.parse(nowIso);
  const lagThreshold = routingQueueLagAlertMinutes(env);

  const stateCountsRows = await env.DB.prepare(
    `SELECT state AS key, COUNT(*) AS count
     FROM lead_routing_jobs
     GROUP BY state
     ORDER BY count DESC`,
  ).all<{ key: string; count: number }>();

  const segmentCountsRows = await env.DB.prepare(
    `SELECT segment AS key, COUNT(*) AS count
     FROM lead_routing_jobs
     GROUP BY segment
     ORDER BY count DESC`,
  ).all<{ key: string; count: number }>();

  const jobsRows = await env.DB.prepare(
    `SELECT
      job_id,
      lead_id,
      segment,
      state,
      attempts,
      max_attempts,
      created_at,
      updated_at,
      next_attempt_at,
      last_error_code
     FROM lead_routing_jobs
     WHERE state IN ('queued', 'processing', 'failed')
     ORDER BY updated_at ASC
     LIMIT 500`,
  ).all<Record<string, unknown>>();

  const deadLetterRow = await env.DB.prepare(
    `SELECT
      COUNT(*) AS total,
      SUM(CASE WHEN replayed_at IS NULL THEN 1 ELSE 0 END) AS pending
     FROM lead_handoff_dead_letter`,
  ).first<{ total: number; pending: number }>();

  const laggingJobs: Array<Record<string, unknown>> = [];
  const activeLagAlerts: string[] = [];
  let maxLagMinutes = 0;

  for (const row of jobsRows.results ?? []) {
    const referenceIso = String(row.updated_at ?? row.created_at ?? nowIso);
    const lagMinutes = diffMinutes(referenceIso, nowIso);
    if (lagMinutes > maxLagMinutes) maxLagMinutes = lagMinutes;

    if (lagMinutes < lagThreshold) continue;

    const jobId = String(row.job_id ?? "");
    const leadId = String(row.lead_id ?? "");
    const alertKey = `routing_queue_lag:${jobId}`;
    activeLagAlerts.push(alertKey);

    await upsertLeadAlert(env, {
      alertKey,
      alertType: "routing_queue_lag",
      severity: lagMinutes >= lagThreshold * 3 ? "critical" : "warning",
      leadId,
      jobId,
      summary: `Routing job ${jobId} lagging ${lagMinutes}m in ${String(row.state ?? 'queued')}`,
      metadata: {
        lagMinutes,
        thresholdMinutes: lagThreshold,
        segment: String(row.segment ?? "smb"),
        state: String(row.state ?? "queued"),
        attempts: Number(row.attempts ?? 0),
        maxAttempts: Number(row.max_attempts ?? 0),
        lastErrorCode: String(row.last_error_code ?? ""),
      },
    });

    laggingJobs.push({
      jobId,
      leadId,
      segment: String(row.segment ?? "smb"),
      state: String(row.state ?? "queued"),
      attempts: Number(row.attempts ?? 0),
      maxAttempts: Number(row.max_attempts ?? 0),
      lagMinutes,
      lastErrorCode: String(row.last_error_code ?? ""),
      updatedAt: String(row.updated_at ?? ""),
      nextAttemptAt: String(row.next_attempt_at ?? ""),
    });
  }

  await resolveLeadAlertsByType(env, "routing_queue_lag", activeLagAlerts);

  const deadPending = Number(deadLetterRow?.pending ?? 0);
  if (deadPending > 0) {
    await upsertLeadAlert(env, {
      alertKey: "routing_dead_letter_pending",
      alertType: "routing_dead_letter_pending",
      severity: deadPending >= 10 ? "critical" : "warning",
      summary: `${deadPending} dead-letter routing jobs pending replay`,
      metadata: {
        pending: deadPending,
        total: Number(deadLetterRow?.total ?? 0),
      },
    });
  } else {
    await resolveLeadAlertsByType(env, "routing_dead_letter_pending", []);
  }

  laggingJobs.sort((a, b) => Number(b.lagMinutes ?? 0) - Number(a.lagMinutes ?? 0));

  return {
    queueLagThresholdMinutes: lagThreshold,
    maxLagMinutes,
    laggingJobs: laggingJobs.slice(0, 50),
    stateCounts: stateCountsRows.results ?? [],
    segmentCounts: segmentCountsRows.results ?? [],
    deadLetter: {
      total: Number(deadLetterRow?.total ?? 0),
      pending: deadPending,
    },
  };
}

async function conversionHeatmap(env: Env, days: number): Promise<{
  fromIso: string;
  toIso: string;
  rows: Array<Record<string, unknown>>;
  totals: { leads: number; booked: number; completed: number };
}> {
  const toIso = new Date().toISOString();
  const fromIso = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();

  const rows = await env.DB.prepare(
    `SELECT
      source,
      source_intent,
      campaign_id,
      page_family,
      cta_variant,
      COUNT(*) AS leads,
      SUM(CASE WHEN booked_at IS NOT NULL THEN 1 ELSE 0 END) AS booked,
      SUM(CASE WHEN completed_at IS NOT NULL THEN 1 ELSE 0 END) AS completed
     FROM leads
     WHERE created_at >= ?1 AND created_at <= ?2
     GROUP BY source, source_intent, campaign_id, page_family, cta_variant
     ORDER BY leads DESC
     LIMIT 1000`,
  ).bind(fromIso, toIso).all<Record<string, unknown>>();

  const normalized = (rows.results ?? []).map((row) => {
    const leads = Number(row.leads ?? 0);
    const booked = Number(row.booked ?? 0);
    const completed = Number(row.completed ?? 0);
    return {
      source: String(row.source ?? "direct"),
      sourceIntent: normalizeSourceIntent(clipString(row.source_intent, 24)),
      campaignId: String(row.campaign_id ?? ""),
      pageFamily: String(row.page_family ?? "root"),
      variant: String(row.cta_variant ?? ""),
      leads,
      booked,
      completed,
      leadToBookedRate: leads > 0 ? Number((booked / leads).toFixed(4)) : 0,
      bookedToCompletedRate: booked > 0 ? Number((completed / booked).toFixed(4)) : 0,
      leadToCompletedRate: leads > 0 ? Number((completed / leads).toFixed(4)) : 0,
    };
  });

  const totals = normalized.reduce(
    (acc, row) => {
      acc.leads += Number(row.leads ?? 0);
      acc.booked += Number(row.booked ?? 0);
      acc.completed += Number(row.completed ?? 0);
      return acc;
    },
    { leads: 0, booked: 0, completed: 0 },
  );

  return { fromIso, toIso, rows: normalized, totals };
}

function redactKeyPreview(value: string | undefined): string | null {
  if (!value) return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  if (trimmed.length <= 8) return "••••";
  return `${trimmed.slice(0, 4)}••••${trimmed.slice(-4)}`;
}

export async function opsLeadIntakeSecurityPosture(request: Request, env: Env): Promise<Response> {
  if (request.method !== "GET") {
    return apiError("METHOD_NOT_ALLOWED", "Use GET for this endpoint", 405);
  }

  const authError = checkOpsAuth(request, env);
  if (authError) return authError;

  const posture = resolveTurnstilePosture(env);

  return apiJson({
    ok: true,
    generatedAt: new Date().toISOString(),
    environment: clipString(env.ENVIRONMENT, 40) ?? "unknown",
    leadIntake: {
      turnstile: {
        required: posture.required,
        strictRealKey: posture.strictRealKey,
        formEnabled: posture.formEnabled,
        code: posture.code,
        message: posture.message,
        usesTestSiteKey: posture.usesTestSiteKey,
        siteKeyPreview: redactKeyPreview(posture.siteKey),
        secretConfigured: posture.secretConfigured,
      },
    },
  });
}

export async function opsLeadFunnelHealth(request: Request, env: Env): Promise<Response> {
  if (request.method !== "GET") {
    return apiError("METHOD_NOT_ALLOWED", "Use GET for this endpoint", 405);
  }

  const authError = checkOpsAuth(request, env);
  if (authError) return authError;

  const sla = await computeLeadResponseSla(env);
  const url = new URL(request.url);
  const days = Math.max(1, Math.min(30, Number(url.searchParams.get("days") ?? "7")));
  const toIso = new Date().toISOString();
  const fromIso = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
  const failing = await collectFailingStepBuckets(env, fromIso, toIso);

  const statusRows = await env.DB.prepare(
    `SELECT status AS key, COUNT(*) AS count FROM leads GROUP BY status ORDER BY count DESC`,
  ).all<{ key: string; count: number }>();

  return apiJson({
    ok: true,
    generatedAt: new Date().toISOString(),
    sla,
    totals: {
      byStatus: statusRows.results ?? [],
    },
    failingSteps: failing,
  });
}

export async function opsRoutingHealth(request: Request, env: Env): Promise<Response> {
  if (request.method !== "GET") {
    return apiError("METHOD_NOT_ALLOWED", "Use GET for this endpoint", 405);
  }

  const authError = checkOpsAuth(request, env);
  if (authError) return authError;

  const health = await computeRoutingHealth(env);

  return apiJson({
    ok: true,
    generatedAt: new Date().toISOString(),
    ...health,
  });
}

export async function opsConversionHeatmap(request: Request, env: Env): Promise<Response> {
  if (request.method !== "GET") {
    return apiError("METHOD_NOT_ALLOWED", "Use GET for this endpoint", 405);
  }

  const authError = checkOpsAuth(request, env);
  if (authError) return authError;

  const url = new URL(request.url);
  const days = Math.max(1, Math.min(90, Number(url.searchParams.get("days") ?? "14")));
  const heatmap = await conversionHeatmap(env, days);

  return apiJson({
    ok: true,
    generatedAt: new Date().toISOString(),
    range: {
      from: heatmap.fromIso,
      to: heatmap.toIso,
      days,
    },
    totals: {
      ...heatmap.totals,
      leadToBookedRate: heatmap.totals.leads > 0 ? Number((heatmap.totals.booked / heatmap.totals.leads).toFixed(4)) : 0,
      leadToCompletedRate: heatmap.totals.leads > 0 ? Number((heatmap.totals.completed / heatmap.totals.leads).toFixed(4)) : 0,
    },
    rows: heatmap.rows,
  });
}

export async function opsFailingSteps(request: Request, env: Env): Promise<Response> {
  if (request.method !== "GET") {
    return apiError("METHOD_NOT_ALLOWED", "Use GET for this endpoint", 405);
  }

  const authError = checkOpsAuth(request, env);
  if (authError) return authError;

  const url = new URL(request.url);
  const days = Math.max(1, Math.min(30, Number(url.searchParams.get("days") ?? "7")));
  const toIso = new Date().toISOString();
  const fromIso = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();

  const buckets = await collectFailingStepBuckets(env, fromIso, toIso);
  return apiJson({
    ok: true,
    generatedAt: new Date().toISOString(),
    range: { from: fromIso, to: toIso, days },
    buckets,
  });
}

export async function attributionRevenueSummary(request: Request, env: Env): Promise<Response> {
  if (request.method !== "GET") {
    return apiError("METHOD_NOT_ALLOWED", "Use GET for this endpoint", 405);
  }

  const authError = checkOpsAuth(request, env);
  if (authError) return authError;

  const url = new URL(request.url);
  const days = Math.max(1, Math.min(90, Number(url.searchParams.get("days") ?? "14")));
  const toIso = new Date().toISOString();
  const fromIso = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();

  const rows = await env.DB.prepare(
    `SELECT
      lead_id,
      source,
      source_intent,
      campaign_id,
      page_family,
      cta_variant,
      first_touch_json,
      booked_at,
      completed_at
     FROM leads
     WHERE created_at >= ?1 AND created_at <= ?2
     ORDER BY created_at DESC
     LIMIT 8000`,
  ).bind(fromIso, toIso).all<Record<string, unknown>>();

  type Rollup = { leads: number; booked: number; completed: number; assists: number };
  const firstTouch = new Map<string, Rollup>();
  const lastTouch = new Map<string, Rollup>();
  const assists = new Map<string, Rollup>();

  const bump = (map: Map<string, Rollup>, key: string, booked: number, completed: number, assist = 0) => {
    const current = map.get(key) ?? { leads: 0, booked: 0, completed: 0, assists: 0 };
    current.leads += 1;
    current.booked += booked;
    current.completed += completed;
    current.assists += assist;
    map.set(key, current);
  };

  for (const row of rows.results ?? []) {
    const booked = row.booked_at ? 1 : 0;
    const completed = row.completed_at ? 1 : 0;

    const firstTouchJson = safeJsonParse<Record<string, string>>(String(row.first_touch_json ?? "{}"), {});
    const first = clipString(firstTouchJson.source, 120)
      ?? clipString(firstTouchJson.utm_source, 120)
      ?? String(row.source ?? "direct");
    const last = String(row.source ?? "direct");

    bump(firstTouch, first, booked, completed);
    bump(lastTouch, last, booked, completed);

    if (first !== last) {
      bump(assists, first, booked, completed, 1);
      bump(assists, last, booked, completed, 1);
    }
  }

  const toRows = (map: Map<string, Rollup>) => [...map.entries()]
    .map(([source, m]) => ({
      source,
      leads: m.leads,
      booked: m.booked,
      completed: m.completed,
      assists: m.assists,
      leadToBookedRate: m.leads > 0 ? Number((m.booked / m.leads).toFixed(4)) : 0,
      leadToCompletedRate: m.leads > 0 ? Number((m.completed / m.leads).toFixed(4)) : 0,
    }))
    .sort((a, b) => (b.completed - a.completed) || (b.booked - a.booked) || (b.leads - a.leads));

  const heatmap = await conversionHeatmap(env, days);

  return apiJson({
    ok: true,
    generatedAt: new Date().toISOString(),
    range: { from: fromIso, to: toIso, days },
    totals: {
      leads: heatmap.totals.leads,
      booked: heatmap.totals.booked,
      completed: heatmap.totals.completed,
      leadToBookedRate: heatmap.totals.leads > 0 ? Number((heatmap.totals.booked / heatmap.totals.leads).toFixed(4)) : 0,
      leadToCompletedRate: heatmap.totals.leads > 0 ? Number((heatmap.totals.completed / heatmap.totals.leads).toFixed(4)) : 0,
    },
    attribution: {
      firstTouch: toRows(firstTouch).slice(0, 50),
      lastTouch: toRows(lastTouch).slice(0, 50),
      assists: toRows(assists).slice(0, 50),
    },
    conversionByDimension: heatmap.rows,
  });
}

export async function routingStatus(request: Request, env: Env): Promise<Response> {
  if (request.method !== "GET") {
    return apiError("METHOD_NOT_ALLOWED", "Use GET for this endpoint", 405);
  }

  const authError = checkOpsAuth(request, env);
  if (authError) return authError;

  const health = await computeRoutingHealth(env);

  const recentJobs = await env.DB.prepare(
    `SELECT
      job_id,
      lead_id,
      segment,
      provider_id,
      state,
      attempts,
      max_attempts,
      next_attempt_at,
      last_error_code,
      updated_at,
      sent_at,
      dead_lettered_at
    FROM lead_routing_jobs
    ORDER BY updated_at DESC
    LIMIT 40`,
  ).all<Record<string, unknown>>();

  return apiJson({
    ok: true,
    generatedAt: new Date().toISOString(),
    summary: {
      byState: health.stateCounts,
      bySegment: health.segmentCounts,
      deadLetter: health.deadLetter,
      queueLagThresholdMinutes: health.queueLagThresholdMinutes,
      maxLagMinutes: health.maxLagMinutes,
      laggingJobs: health.laggingJobs.slice(0, 20),
    },
    recentJobs: recentJobs.results ?? [],
  });
}

export async function routingReplay(request: Request, env: Env): Promise<Response> {
  if (request.method !== "POST") {
    return apiError("METHOD_NOT_ALLOWED", "Use POST for this endpoint", 405);
  }

  const authError = checkOpsAuth(request, env);
  if (authError) return authError;

  const body = await request.json<any>().catch(() => ({}));
  const limit = Math.max(1, Math.min(100, Number(body?.limit ?? 10)));
  const rawIds: unknown[] = Array.isArray(body?.jobIds) ? body.jobIds : [];
  const ids = rawIds
    .map((x) => clipString(x, 80))
    .filter((x): x is string => Boolean(x));

  const dryRun = body?.dryRun !== false;
  const force = body?.force === true;
  const includeReplayed = body?.includeReplayed === true;
  const confirm = clipString(body?.confirm, 32);
  const maxAgeHours = Math.max(1, Math.min(24 * 30, Number(body?.maxAgeHours ?? 24 * 14)));
  const cutoffIso = new Date(Date.now() - maxAgeHours * 60 * 60 * 1000).toISOString();

  if (!dryRun && confirm !== "replay") {
    return apiError("REPLAY_CONFIRM_REQUIRED", "Set confirm=replay to execute replay", 400);
  }

  let rows: Array<{ job_id: string; segment: string; reason_code: string; created_at: string; replay_count: number }> = [];

  if (ids.length > 0) {
    const placeholders = ids.map((_: string, i: number) => `?${i + 1}`).join(",");
    const out = await env.DB.prepare(
      `SELECT DISTINCT job_id, segment, reason_code, created_at, replay_count
       FROM lead_handoff_dead_letter
       WHERE job_id IN (${placeholders})
         AND created_at >= ?${ids.length + 1}
       ORDER BY created_at DESC
       LIMIT ${limit}`,
    ).bind(...ids, cutoffIso).all<{ job_id: string; segment: string; reason_code: string; created_at: string; replay_count: number }>();
    rows = out.results ?? [];
  } else {
    const whereReplayed = includeReplayed ? "" : "AND replayed_at IS NULL";
    const out = await env.DB.prepare(
      `SELECT DISTINCT job_id, segment, reason_code, created_at, replay_count
       FROM lead_handoff_dead_letter
       WHERE created_at >= ?1
       ${whereReplayed}
       ORDER BY created_at DESC
       LIMIT ${limit}`,
    ).bind(cutoffIso).all<{ job_id: string; segment: string; reason_code: string; created_at: string; replay_count: number }>();
    rows = out.results ?? [];
  }

  if (!dryRun && !force && rows.length > 20) {
    return apiError("REPLAY_FORCE_REQUIRED", `Refusing to replay ${rows.length} jobs without force=true`, 400);
  }

  const preview = rows.map((row) => ({
    jobId: row.job_id,
    segment: row.segment,
    reasonCode: row.reason_code,
    createdAt: row.created_at,
    replayCount: Number(row.replay_count ?? 0),
  }));

  if (dryRun) {
    return apiJson({
      ok: true,
      dryRun: true,
      requested: preview.length,
      selected: preview,
    });
  }

  let requeued = 0;
  const failures: Array<{ jobId: string; error: string }> = [];

  for (const row of rows) {
    const segment = (clipString(row.segment, 24) ?? "smb") as LeadSegment;
    const nowIso = new Date().toISOString();

    try {
      await env.DB.prepare(
        `UPDATE lead_routing_jobs
         SET state = 'queued', attempts = 0, last_error_code = '', last_error_message = '', updated_at = ?2, dead_lettered_at = NULL
         WHERE job_id = ?1`,
      ).bind(row.job_id, nowIso).run();

      await env.DB.prepare(
        `UPDATE leads
         SET route_status = 'queued', updated_at = ?2
         WHERE lead_id = (SELECT lead_id FROM lead_routing_jobs WHERE job_id = ?1 LIMIT 1)`,
      ).bind(row.job_id, nowIso).run();

      await env.DB.prepare(
        `UPDATE lead_handoff_dead_letter
         SET replay_count = replay_count + 1, replayed_at = ?2
         WHERE job_id = ?1`,
      ).bind(row.job_id, nowIso).run();

      await enqueueRoutingJob(env, segment, {
        type: "lead_route_dispatch",
        routeJobId: row.job_id,
        replay: true,
      });

      requeued += 1;
    } catch (err: any) {
      failures.push({ jobId: row.job_id, error: String(err?.message ?? err) });
    }
  }

  return apiJson({
    ok: failures.length === 0,
    dryRun: false,
    requested: rows.length,
    requeued,
    failures,
  });
}

export async function attributionSummary(request: Request, env: Env): Promise<Response> {
  if (request.method !== "GET") {
    return apiError("METHOD_NOT_ALLOWED", "Use GET for this endpoint", 405);
  }

  const authError = checkOpsAuth(request, env);
  if (authError) return authError;

  const url = new URL(request.url);
  const days = Math.max(1, Math.min(90, Number(url.searchParams.get("days") ?? "7")));
  const to = new Date();
  const from = new Date(to.getTime() - (days * 24 * 60 * 60 * 1000));
  const fromIso = from.toISOString();
  const toIso = to.toISOString();

  const rows = await env.DB.prepare(
    `SELECT
      source,
      source_intent,
      campaign_id,
      page_family,
      cta_variant,
      score_band,
      COUNT(*) AS leads,
      SUM(CASE WHEN booked_at IS NOT NULL THEN 1 ELSE 0 END) AS booked,
      SUM(CASE WHEN completed_at IS NOT NULL THEN 1 ELSE 0 END) AS completed
    FROM leads
    WHERE created_at >= ?1 AND created_at <= ?2
    GROUP BY source, source_intent, campaign_id, page_family, cta_variant, score_band
    ORDER BY leads DESC
    LIMIT 500`,
  ).bind(fromIso, toIso).all<any>();

  const normalized = (rows.results ?? []).map((row) => {
    const leads = Number(row.leads ?? 0);
    const booked = Number(row.booked ?? 0);
    const completed = Number(row.completed ?? 0);
    return {
      source: String(row.source ?? "direct"),
      sourceIntent: normalizeSourceIntent(clipString(row.source_intent, 24)),
      campaignId: String(row.campaign_id ?? ""),
      pageFamily: String(row.page_family ?? "root"),
      variant: String(row.cta_variant ?? ""),
      scoreBand: String(row.score_band ?? "low"),
      leads,
      booked,
      completed,
      bookedRate: leads > 0 ? Number((booked / leads).toFixed(4)) : 0,
      completedRate: leads > 0 ? Number((completed / leads).toFixed(4)) : 0,
    };
  });

  const totals = normalized.reduce(
    (acc, row) => {
      acc.leads += row.leads;
      acc.booked += row.booked;
      acc.completed += row.completed;
      return acc;
    },
    { leads: 0, booked: 0, completed: 0 },
  );

  return apiJson({
    ok: true,
    generatedAt: new Date().toISOString(),
    range: { from: fromIso, to: toIso, days },
    totals: {
      leads: totals.leads,
      booked: totals.booked,
      completed: totals.completed,
      bookedRate: totals.leads > 0 ? Number((totals.booked / totals.leads).toFixed(4)) : 0,
      completedRate: totals.leads > 0 ? Number((totals.completed / totals.leads).toFixed(4)) : 0,
    },
    rows: normalized,
  });
}

function wilsonLowerBound(successes: number, trials: number, z = 1.96): number {
  if (trials <= 0) return 0;
  const p = successes / trials;
  const z2 = z * z;
  const denom = 1 + z2 / trials;
  const center = p + z2 / (2 * trials);
  const margin = z * Math.sqrt((p * (1 - p) + z2 / (4 * trials)) / trials);
  return Math.max(0, (center - margin) / denom);
}

function wilsonUpperBound(successes: number, trials: number, z = 1.96): number {
  if (trials <= 0) return 0;
  const p = successes / trials;
  const z2 = z * z;
  const denom = 1 + z2 / trials;
  const center = p + z2 / (2 * trials);
  const margin = z * Math.sqrt((p * (1 - p) + z2 / (4 * trials)) / trials);
  return Math.min(1, (center + margin) / denom);
}

export async function recommendExperimentWinners(request: Request, env: Env): Promise<Response> {
  if (request.method !== "POST") {
    return apiError("METHOD_NOT_ALLOWED", "Use POST for this endpoint", 405);
  }

  const authError = checkOpsAuth(request, env);
  if (authError) return authError;

  const body = await request.json<any>().catch(() => ({}));
  const days = Math.max(1, Math.min(90, Number(body?.days ?? 7)));
  const to = new Date();
  const from = new Date(to.getTime() - (days * 24 * 60 * 60 * 1000));
  const fromIso = from.toISOString();
  const toIso = to.toISOString();

  const impressionRows = await env.DB.prepare(
    `SELECT page_family, cta_variant, COUNT(*) AS impressions
     FROM funnel_events
     WHERE event_type = 'variant_assignment'
       AND event_ts >= ?1 AND event_ts <= ?2
       AND cta_variant IS NOT NULL
     GROUP BY page_family, cta_variant`,
  ).bind(fromIso, toIso).all<any>();

  const submitRows = await env.DB.prepare(
    `SELECT page_family, cta_variant, COUNT(*) AS submits
     FROM funnel_events
     WHERE event_type IN ('lead_submit', 'contact_intent_submit', 'booking_submit')
       AND event_ts >= ?1 AND event_ts <= ?2
       AND cta_variant IS NOT NULL
     GROUP BY page_family, cta_variant`,
  ).bind(fromIso, toIso).all<any>();

  const bookedRows = await env.DB.prepare(
    `SELECT page_family, cta_variant, COUNT(*) AS booked
     FROM leads
     WHERE created_at >= ?1 AND created_at <= ?2
       AND cta_variant <> ''
       AND status = 'booked'
     GROUP BY page_family, cta_variant`,
  ).bind(fromIso, toIso).all<any>();

  const map = new Map<string, { pageFamily: string; variant: string; impressions: number; submits: number; booked: number }>();
  const keyFor = (family: string, variant: string) => `${family}::${variant}`;

  for (const row of impressionRows.results ?? []) {
    const family = String(row.page_family ?? "root");
    const variant = String(row.cta_variant ?? "unknown");
    map.set(keyFor(family, variant), {
      pageFamily: family,
      variant,
      impressions: Number(row.impressions ?? 0),
      submits: 0,
      booked: 0,
    });
  }

  for (const row of submitRows.results ?? []) {
    const family = String(row.page_family ?? "root");
    const variant = String(row.cta_variant ?? "unknown");
    const key = keyFor(family, variant);
    const current = map.get(key) ?? { pageFamily: family, variant, impressions: 0, submits: 0, booked: 0 };
    current.submits = Number(row.submits ?? 0);
    map.set(key, current);
  }

  for (const row of bookedRows.results ?? []) {
    const family = String(row.page_family ?? "root");
    const variant = String(row.cta_variant ?? "unknown");
    const key = keyFor(family, variant);
    const current = map.get(key) ?? { pageFamily: family, variant, impressions: 0, submits: 0, booked: 0 };
    current.booked = Number(row.booked ?? 0);
    map.set(key, current);
  }

  const grouped = new Map<string, Array<{ pageFamily: string; variant: string; impressions: number; submits: number; booked: number }>>();
  for (const row of map.values()) {
    const existing = grouped.get(row.pageFamily) ?? [];
    existing.push(row);
    grouped.set(row.pageFamily, existing);
  }

  const minImpressions = Math.max(1, Number(env.EXPERIMENT_WINNER_MIN_IMPRESSIONS ?? "40"));
  const minBooked = Math.max(0, Number(env.EXPERIMENT_WINNER_MIN_BOOKED ?? "2"));
  const minConfidence = Math.max(0, Math.min(1, Number(env.EXPERIMENT_WINNER_MIN_CONFIDENCE ?? "0.12")));
  const holdoutPercent = Math.max(0, Math.min(30, Number(env.EXPERIMENT_HOLDOUT_PERCENT ?? String(DEFAULT_EXPERIMENT_CONFIG.holdoutPercent ?? 0))));
  const nowIso = new Date().toISOString();

  const recommendations = [...grouped.entries()].map(([pageFamily, variants]) => {
    const sorted = [...variants]
      .map((v) => {
        const submitRate = v.impressions > 0 ? Number((v.submits / v.impressions).toFixed(4)) : 0;
        const bookedRate = v.impressions > 0 ? Number((v.booked / v.impressions).toFixed(4)) : 0;
        const confidenceFloor = Number(wilsonLowerBound(v.booked, Math.max(1, v.impressions)).toFixed(4));
        const confidenceUpper = Number(wilsonUpperBound(v.booked, Math.max(1, v.impressions)).toFixed(4));
        return {
          ...v,
          submitRate,
          bookedRate,
          confidenceFloor,
          confidenceUpper,
        };
      })
      .sort((a, b) => (b.bookedRate - a.bookedRate) || (b.submitRate - a.submitRate) || (b.impressions - a.impressions));

    const winner = sorted[0] ?? null;
    const runnerUp = sorted[1] ?? null;

    const guardrailNotes: string[] = [];
    let recommendedVariant: string | null = winner?.variant ?? null;

    if (!winner) {
      guardrailNotes.push("no_variants");
      recommendedVariant = null;
    } else {
      if (winner.variant === "holdout") guardrailNotes.push("holdout_variant_not_promotable");
      if (winner.impressions < minImpressions) guardrailNotes.push("insufficient_impressions");
      if (winner.booked < minBooked) guardrailNotes.push("insufficient_bookings");
      if (winner.confidenceFloor < minConfidence) guardrailNotes.push("insufficient_confidence");
      if (runnerUp && winner.bookedRate - runnerUp.bookedRate < 0.01) guardrailNotes.push("margin_too_small");
      if (runnerUp && winner.confidenceFloor <= runnerUp.confidenceUpper) guardrailNotes.push("confidence_overlap_runner_up");
    }

    if (guardrailNotes.length > 0) {
      recommendedVariant = null;
    }

    return {
      pageFamily,
      recommendedVariant,
      winner,
      runnerUp,
      candidates: sorted,
      holdoutPercent,
      guardrailNotes,
    };
  });

  for (const rec of recommendations) {
    await env.DB.prepare(
      `INSERT INTO experiment_winner_recommendations (
        recommendation_id,
        period_from,
        period_to,
        page_family,
        recommended_variant,
        support_impressions,
        support_submits,
        support_booked,
        confidence,
        guardrail_notes,
        metadata_json,
        created_at
      ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)`,
    )
      .bind(
        randomId("winner_rec"),
        fromIso,
        toIso,
        rec.pageFamily,
        rec.recommendedVariant,
        Number(rec.winner?.impressions ?? 0),
        Number(rec.winner?.submits ?? 0),
        Number(rec.winner?.booked ?? 0),
        Number(rec.winner?.confidenceFloor ?? 0),
        rec.guardrailNotes.join(","),
        JSON.stringify({
          winner: rec.winner,
          runnerUp: rec.runnerUp,
          candidates: rec.candidates,
          autoApply: false,
        }),
        nowIso,
      )
      .run();
  }

  const artifact = {
    generatedAt: nowIso,
    range: { from: fromIso, to: toIso, days },
    guardrails: {
      minImpressions,
      minBooked,
      minConfidence,
      holdoutPercent,
      autoApply: false,
    },
    recommendations,
  };

  const key = `reports/growth/experiment-winner-recommendation-${nowIso.slice(0, 10)}.json`;
  await env.ARTICLES.put(key, JSON.stringify(artifact, null, 2), {
    httpMetadata: { contentType: "application/json" },
  });

  return apiJson({
    ok: true,
    key,
    guardrails: {
      minImpressions,
      minBooked,
      minConfidence,
      holdoutPercent,
      autoApply: false,
    },
    recommendations,
  });
}

async function findLeadForBooking(env: Env, leadId: string | undefined, email: string | undefined): Promise<{ leadId: string; created: boolean }> {
  const nowIso = new Date().toISOString();
  const emailNorm = normalizeEmail(email);
  const salt = env.LEAD_ID_HASH_SALT?.trim() ?? "clawea-www-lead";

  if (leadId) {
    const existing = await env.DB.prepare(
      `SELECT lead_id FROM leads WHERE lead_id = ?1 LIMIT 1`,
    ).bind(leadId).first<{ lead_id: string }>();

    if (existing?.lead_id) {
      return { leadId: existing.lead_id, created: false };
    }
  }

  if (emailNorm) {
    const identityHash = await sha256Base64Url(`${salt}|${emailNorm}`);
    const existingByEmail = await env.DB.prepare(
      `SELECT lead_id FROM leads WHERE identity_hash = ?1 LIMIT 1`,
    ).bind(identityHash).first<{ lead_id: string }>();

    if (existingByEmail?.lead_id) {
      return { leadId: existingByEmail.lead_id, created: false };
    }

    const leadIdNew = randomId("lead");
    const emailHash = await sha256Base64Url(emailNorm);
    const emailParts = emailNorm.split("@");
    const emailHint = emailParts.length === 2 ? `${emailParts[0].slice(0, 2)}***@${emailParts[1]}` : "***";

    await env.DB.prepare(
      `INSERT INTO leads (
        lead_id,
        identity_hash,
        email_hash,
        email_hint,
        source,
        source_intent,
        page,
        page_family,
        readiness_score,
        roi_score,
        risk_score,
        intent_score,
        qualification_score,
        score_band,
        segment,
        status,
        route_status,
        created_at,
        updated_at,
        last_seen_at,
        lifecycle_updated_at
      ) VALUES (?1, ?2, ?3, ?4, 'book-form', 'high-intent', '/book', 'book', 50, 50, 30, 55, 60, 'medium', 'enterprise', 'new', 'booking_direct', ?5, ?5, ?5, ?5)`,
    )
      .bind(leadIdNew, identityHash, emailHash, emailHint, nowIso)
      .run();

    return { leadId: leadIdNew, created: true };
  }

  throw new Error("LEAD_NOT_FOUND");
}

export async function bookSubmit(request: Request, env: Env): Promise<Response> {
  if (request.method !== "POST") {
    return apiError("METHOD_NOT_ALLOWED", "Use POST for this endpoint", 405);
  }

  const body = await request.json<any>().catch(() => null);
  if (!body || typeof body !== "object") {
    return apiError("INVALID_JSON", "Request body must be valid JSON", 400);
  }

  const leadIdIn = clipString(body?.leadId, 80);
  const email = clipString(body?.email, 200);
  const company = clipString(body?.company, 160) ?? "";
  const slotIso = clipString(body?.slotIso, 80);
  const notes = clipString(body?.notes, 1200) ?? "";

  if (!email && !leadIdIn) {
    return apiError("EMAIL_OR_LEAD_REQUIRED", "Provide leadId or work email", 400);
  }

  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return apiError("EMAIL_INVALID", "A valid work email is required", 400);
  }

  const turnstileToken = clipString(body?.turnstileToken, 3000);
  const turnstile = await verifyTurnstile(turnstileToken, request, env);
  if (!turnstile.ok) {
    return apiError("TURNSTILE_FAILED", turnstile.error ?? "Turnstile validation failed", 403);
  }

  const nowIso = new Date().toISOString();

  try {
    const found = await findLeadForBooking(env, leadIdIn ?? undefined, email ?? undefined);

    if (company) {
      await env.DB.prepare(
        `UPDATE leads SET company = COALESCE(NULLIF(?2,''), company), updated_at = ?3, last_seen_at = ?3 WHERE lead_id = ?1`,
      ).bind(found.leadId, company, nowIso).run();
    }

    await transitionLeadState(env, found.leadId, "validated", "book_submit");
    await transitionLeadState(env, found.leadId, "scored", "book_submit");
    await transitionLeadState(env, found.leadId, "routed", "book_submit");
    await transitionLeadState(env, found.leadId, "contacted", "book_submit");
    await transitionLeadState(env, found.leadId, "qualified", "book_submit");
    await transitionLeadState(env, found.leadId, "booked", "book_submit");

    await env.DB.prepare(
      `UPDATE leads SET booked_at = ?2, updated_at = ?2, last_seen_at = ?2 WHERE lead_id = ?1`,
    ).bind(found.leadId, nowIso).run();

    const bookingId = randomId("booking");

    await env.DB.prepare(
      `INSERT INTO booking_events (
        booking_id,
        lead_id,
        status,
        slot_iso,
        notes,
        source,
        metadata_json,
        created_at,
        updated_at
      ) VALUES (?1, ?2, 'booked', ?3, ?4, 'book-form', ?5, ?6, ?6)`,
    )
      .bind(
        bookingId,
        found.leadId,
        slotIso ?? null,
        notes,
        JSON.stringify({
          createdLead: found.created,
          company,
        }),
        nowIso,
      )
      .run();

    await env.DB.prepare(
      `INSERT INTO lead_events (
        event_id,
        lead_id,
        event_type,
        event_payload_json,
        source,
        page,
        page_family,
        created_at
      ) VALUES (?1, ?2, 'booking_booked', ?3, 'book-form', '/book', 'book', ?4)`,
    )
      .bind(
        randomId("lead_evt"),
        found.leadId,
        JSON.stringify({
          bookingId,
          slotIso,
          notes,
        }),
        nowIso,
      )
      .run();

    try {
      await storeTrackingEvent(env, {
        eventType: "booking_submit",
        page: "/book",
        pageFamily: "book",
        source: "book-form",
        ctaId: "book-submit-primary",
        ctaVariant: "submit",
        actionOutcome: "submitted",
        variantId: "book:proof:submit",
        heroVariant: "proof",
        visitorId: undefined,
        ts: nowIso,
        attribution: {},
        context: {},
      });
    } catch (telemetryErr) {
      console.error("BOOKING_SUBMIT_TELEMETRY_FAILED", telemetryErr);
    }

    return apiJson({
      ok: true,
      bookingId,
      leadId: found.leadId,
      createdLead: found.created,
      status: "booked",
    });
  } catch (err: any) {
    const code = String(err?.message ?? "BOOK_SUBMIT_FAILED");
    if (code === "LEAD_NOT_FOUND") {
      return apiError("LEAD_NOT_FOUND", "Could not resolve lead for booking", 404);
    }
    console.error("BOOK_SUBMIT_FAILED", err);
    return apiError("BOOK_SUBMIT_FAILED", "Booking submission failed", 500);
  }
}

export async function bookComplete(request: Request, env: Env): Promise<Response> {
  if (request.method !== "POST") {
    return apiError("METHOD_NOT_ALLOWED", "Use POST for this endpoint", 405);
  }

  const authError = checkOpsAuth(request, env);
  if (authError) return authError;

  const body = await request.json<any>().catch(() => null);
  const bookingId = clipString(body?.bookingId, 80);

  if (!bookingId) {
    return apiError("BOOKING_ID_REQUIRED", "bookingId is required", 400);
  }

  const row = await env.DB.prepare(
    `SELECT booking_id, lead_id FROM booking_events WHERE booking_id = ?1 LIMIT 1`,
  ).bind(bookingId).first<{ booking_id: string; lead_id: string }>();

  if (!row?.booking_id) {
    return apiError("BOOKING_NOT_FOUND", "Booking not found", 404);
  }

  const nowIso = new Date().toISOString();

  await env.DB.prepare(
    `UPDATE booking_events SET status = 'completed', completed_at = ?2, updated_at = ?2 WHERE booking_id = ?1`,
  ).bind(bookingId, nowIso).run();

  await env.DB.prepare(
    `UPDATE leads SET completed_at = ?2, updated_at = ?2, last_seen_at = ?2 WHERE lead_id = ?1`,
  ).bind(row.lead_id, nowIso).run();

  await env.DB.prepare(
    `INSERT INTO lead_events (
      event_id,
      lead_id,
      event_type,
      event_payload_json,
      source,
      page,
      page_family,
      created_at
    ) VALUES (?1, ?2, 'booking_completed', ?3, 'book-api', '/book', 'book', ?4)`,
  )
    .bind(
      randomId("lead_evt"),
      row.lead_id,
      JSON.stringify({ bookingId }),
      nowIso,
    )
    .run();

  try {
    await storeTrackingEvent(env, {
      eventType: "booking_complete",
      page: "/book",
      pageFamily: "book",
      source: "book-api",
      ctaId: "booking-complete",
      ctaVariant: "submit",
      actionOutcome: "completed",
      variantId: "book:proof:submit",
      heroVariant: "proof",
      visitorId: undefined,
      ts: nowIso,
      attribution: {},
      context: {},
    });
  } catch (telemetryErr) {
    console.error("BOOKING_COMPLETE_TELEMETRY_FAILED", telemetryErr);
  }

  return apiJson({
    ok: true,
    bookingId,
    leadId: row.lead_id,
    status: "completed",
  });
}

export async function experimentsWinners(request: Request, env: Env): Promise<Response> {
  if (request.method !== "GET") {
    return apiError("METHOD_NOT_ALLOWED", "Use GET for this endpoint", 405);
  }

  const authError = checkOpsAuth(request, env);
  if (authError) return authError;

  const url = new URL(request.url);
  const date = clipString(url.searchParams.get("date"), 10);

  let key = date ? `reports/growth/variant-performance-${date}.json` : null;

  if (!key) {
    const listed = await env.ARTICLES.list({
      prefix: "reports/growth/variant-performance-",
      limit: 100,
    });

    const latest = listed.objects
      .map((o) => o.key)
      .filter((k) => k.startsWith("reports/growth/variant-performance-") && k.endsWith(".json"))
      .sort((a, b) => b.localeCompare(a, "en"))[0];

    key = latest ?? null;
  }

  if (!key) {
    return apiError("REPORT_NOT_FOUND", "No variant report found", 404);
  }

  const obj = await env.ARTICLES.get(key);
  if (!obj) {
    return apiError("REPORT_NOT_FOUND", `Variant report not found for key ${key}`, 404);
  }

  const parsed = safeJsonParse(await obj.text(), null);
  return apiJson({
    ok: true,
    key,
    report: parsed,
  });
}

export function stableHash(input: string): number {
  let hash = 2166136261;
  for (let i = 0; i < input.length; i++) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}

export async function loadExperimentConfig(env: Env): Promise<ExperimentVariantConfig> {
  const key = env.EXPERIMENT_CONFIG_KEY?.trim() || "experiment-config-v1";

  const fallback = {
    ...DEFAULT_EXPERIMENT_CONFIG,
    seed: env.EXPERIMENT_SEED?.trim() || DEFAULT_EXPERIMENT_CONFIG.seed,
    holdoutPercent: Math.max(0, Math.min(30, Number(env.EXPERIMENT_HOLDOUT_PERCENT ?? String(DEFAULT_EXPERIMENT_CONFIG.holdoutPercent ?? 0)))),
  } satisfies ExperimentVariantConfig;

  try {
    const raw = await env.VARIANT_CONFIG.get(key, "text");
    if (!raw) {
      return fallback;
    }

    const parsed = safeJsonParse<ExperimentVariantConfig>(raw, fallback);
    const seed = clipString(parsed?.seed, 120) ?? fallback.seed;
    const holdoutPercent = Math.max(
      0,
      Math.min(
        30,
        Number(parsed?.holdoutPercent ?? env.EXPERIMENT_HOLDOUT_PERCENT ?? fallback.holdoutPercent ?? 0),
      ),
    );

    const rawFamilies = parsed?.families && typeof parsed.families === "object"
      ? parsed.families
      : fallback.families;

    const families: Record<string, ExperimentFamilyConfig> = {};
    for (const [family, cfg] of Object.entries(rawFamilies)) {
      const hero = Array.isArray(cfg?.hero) ? cfg.hero.filter((x): x is string => typeof x === "string" && x.length > 0) : [];
      const cta = Array.isArray(cfg?.cta) ? cfg.cta.filter((x): x is string => typeof x === "string" && x.length > 0) : [];
      const holdout = Number((cfg as ExperimentFamilyConfig)?.holdoutPercent ?? holdoutPercent);
      families[family] = {
        hero: hero.length > 0 ? hero : ["proof"],
        cta: cta.length > 0 ? cta : ["sales"],
        holdoutPercent: Math.max(0, Math.min(30, holdout)),
      };
    }

    return { seed, holdoutPercent, families };
  } catch {
    return fallback;
  }
}

export function assignVariant(config: ExperimentVariantConfig, visitorId: string, pageFamily: string): {
  pageFamily: string;
  heroVariant: string;
  ctaVariant: string;
} {
  const family = pageFamily || "root";
  const familyConfig = config.families[family] ?? config.families.root ?? { hero: ["proof"], cta: ["sales"], holdoutPercent: 0 };

  const heroOptions = familyConfig.hero.length > 0 ? familyConfig.hero : ["proof"];
  const ctaOptions = familyConfig.cta.length > 0 ? familyConfig.cta : ["sales"];

  const holdoutPercent = Math.max(
    0,
    Math.min(
      30,
      Number(familyConfig.holdoutPercent ?? config.holdoutPercent ?? 0),
    ),
  );

  const holdoutHash = stableHash(`${config.seed}|holdout|${family}|${visitorId}`) % 100;
  if (holdoutPercent > 0 && holdoutHash < holdoutPercent) {
    return {
      pageFamily: family,
      heroVariant: "holdout",
      ctaVariant: "holdout",
    };
  }

  const heroHash = stableHash(`${config.seed}|hero|${family}|${visitorId}`);
  const ctaHash = stableHash(`${config.seed}|cta|${family}|${visitorId}`);

  const heroVariant = heroOptions[heroHash % heroOptions.length];
  const ctaVariant = ctaOptions[ctaHash % ctaOptions.length];

  return {
    pageFamily: family,
    heroVariant,
    ctaVariant,
  };
}

export function readCookie(request: Request, name: string): string | null {
  const cookies = request.headers.get("cookie") ?? "";
  const entries = cookies.split(";").map((x) => x.trim());
  for (const entry of entries) {
    const [k, ...rest] = entry.split("=");
    if (!k || rest.length === 0) continue;
    if (k === name) return decodeURIComponent(rest.join("="));
  }
  return null;
}

export function getOrCreateVisitorId(request: Request): { visitorId: string; cookieNeeded: boolean } {
  const existing = clipString(readCookie(request, "clawea_vid"), 120);
  if (existing) {
    return { visitorId: existing, cookieNeeded: false };
  }

  return {
    visitorId: randomId("vid"),
    cookieNeeded: true,
  };
}

export function applyExperimentCookies(response: Response, visitorId: string, assignment: {
  pageFamily: string;
  heroVariant: string;
  ctaVariant: string;
}, setVisitorCookie: boolean, setExperimentCookie: boolean): Response {
  const headers = new Headers(response.headers);
  if (setVisitorCookie) {
    headers.append(
      "set-cookie",
      `clawea_vid=${encodeURIComponent(visitorId)}; Path=/; Max-Age=31536000; SameSite=Lax; Secure`,
    );
  }

  if (setExperimentCookie) {
    headers.append(
      "set-cookie",
      `clawea_exp=${encodeURIComponent(`${assignment.pageFamily}:${assignment.heroVariant}:${assignment.ctaVariant}`)}; Path=/; Max-Age=2592000; SameSite=Lax; Secure`,
    );
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

export async function experimentAssignmentEndpoint(request: Request, env: Env): Promise<Response> {
  if (request.method !== "GET") {
    return apiError("METHOD_NOT_ALLOWED", "Use GET for this endpoint", 405);
  }

  const url = new URL(request.url);
  const visitorId = clipString(url.searchParams.get("visitorId"), 120)
    ?? getOrCreateVisitorId(request).visitorId;
  const pageFamily = clipString(url.searchParams.get("pageFamily"), 80) ?? "root";

  const config = await loadExperimentConfig(env);
  const assignment = assignVariant(config, visitorId, pageFamily);

  return apiJson({
    ok: true,
    visitorId,
    seed: config.seed,
    holdoutPercent: config.holdoutPercent ?? 0,
    assignment,
  });
}

export async function leadJobsQueue(batch: MessageBatch<any>, env: Env): Promise<void> {
  for (const message of batch.messages) {
    const payload = message.body as Record<string, unknown>;
    const type = String(payload?.type ?? "");

    try {
      if (type === "lead_enrich") {
        const leadId = clipString(payload?.leadId, 80);
        if (!leadId) {
          message.ack();
          continue;
        }

        const lead = await env.DB.prepare(
          `SELECT lead_id, qualification_score FROM leads WHERE lead_id = ?1 LIMIT 1`,
        ).bind(leadId).first<{ lead_id: string; qualification_score: number }>();

        if (!lead?.lead_id) {
          message.ack();
          continue;
        }

        if (Number(lead.qualification_score ?? 0) >= 78) {
          await transitionLeadState(env, leadId, "qualified", "lead_enrich");
        }

        message.ack();
        continue;
      }

      if (type === "lead_route_dispatch") {
        const routeJobId = clipString(payload?.routeJobId, 80);
        if (!routeJobId) {
          message.ack();
          continue;
        }

        const job = await env.DB.prepare(
          `SELECT
            job_id,
            lead_id,
            segment,
            provider_id,
            state,
            attempts,
            max_attempts,
            idempotency_key,
            payload_json
          FROM lead_routing_jobs
          WHERE job_id = ?1
          LIMIT 1`,
        ).bind(routeJobId).first<any>();

        if (!job?.job_id) {
          message.ack();
          continue;
        }

        const currentState = String(job.state ?? "queued");
        if (currentState === "sent" || currentState === "dead_letter") {
          message.ack();
          continue;
        }

        if (Number(job.attempts ?? 0) >= Number(job.max_attempts ?? routingMaxAttempts(env))) {
          message.ack();
          continue;
        }

        const lead = await env.DB.prepare(
          `SELECT
            lead_id,
            company,
            role,
            team_size,
            timeline,
            primary_use_case,
            email_hint,
            source,
            source_intent,
            campaign_id,
            page_family,
            variant_id,
            hero_variant,
            cta_variant,
            qualification_score,
            intent_score,
            readiness_score,
            roi_score,
            risk_score,
            score_band,
            segment,
            status
          FROM leads
          WHERE lead_id = ?1
          LIMIT 1`,
        ).bind(String(job.lead_id)).first<any>();

        if (!lead?.lead_id) {
          message.ack();
          continue;
        }

        const attempts = Number(job.attempts ?? 0) + 1;
        const nowIso = new Date().toISOString();

        await env.DB.prepare(
          `UPDATE lead_routing_jobs
           SET state = 'processing', attempts = ?2, updated_at = ?3
           WHERE job_id = ?1`,
        ).bind(routeJobId, attempts, nowIso).run();

        const routingConfig = await loadCrmRoutingConfig(env);
        const provider = routingConfig.providers.find((p) => p.id === String(job.provider_id));

        if (!provider) {
          throw new Error("ROUTING_PROVIDER_NOT_CONFIGURED");
        }

        const jobPayload = safeJsonParse<Record<string, unknown>>(String(job.payload_json ?? "{}"), {});
        const sourceIntent = normalizeSourceIntent(clipString(lead.source_intent, 24) ?? clipString(jobPayload.sourceIntent, 24));
        const scoreReasons = Array.isArray(jobPayload.scoreReasons)
          ? (jobPayload.scoreReasons as Array<Record<string, unknown>>)
            .map((r) => ({
              code: clipString(r.code, 80) ?? "unknown",
              points: Number(r.points ?? 0),
              detail: clipString(r.detail, 240),
            }))
          : [];

        const envelope: LeadHandoffEnvelope = {
          version: "1.0",
          handoffId: String(job.job_id),
          leadId: String(lead.lead_id),
          idempotencyKey: String(job.idempotency_key),
          occurredAt: nowIso,
          segment: (clipString(lead.segment, 24) ?? "smb") as LeadSegment,
          score: {
            qualification: Number(lead.qualification_score ?? 0),
            band: (clipString(lead.score_band, 24) ?? "low") as LeadScoreBand,
            intent: Number(lead.intent_score ?? 0),
            readiness: Number(lead.readiness_score ?? 0),
            roi: Number(lead.roi_score ?? 0),
            risk: Number(lead.risk_score ?? 0),
            sourceIntent,
            reasons: scoreReasons,
          },
          attribution: {
            source: String(lead.source ?? "direct"),
            campaignId: String(lead.campaign_id ?? ""),
            pageFamily: String(lead.page_family ?? "root"),
            variantId: String(lead.variant_id ?? ""),
            heroVariant: String(lead.hero_variant ?? ""),
            ctaVariant: String(lead.cta_variant ?? ""),
          },
          lead: {
            company: String(lead.company ?? ""),
            role: String(lead.role ?? ""),
            teamSize: String(lead.team_size ?? ""),
            timeline: String(lead.timeline ?? ""),
            primaryUseCase: String(lead.primary_use_case ?? ""),
            emailHint: String(lead.email_hint ?? ""),
          },
        };

        const signingSecret = env.CRM_HANDOFF_SIGNING_SECRET?.trim()
          || env.LEAD_ID_HASH_SALT?.trim()
          || "clawea-handoff";
        const envelopeJson = JSON.stringify(envelope);
        const signature = await hmacSha256Base64Url(signingSecret, envelopeJson);

        let endpoint = provider.endpoint ?? "r2://internal-handoff";
        let status = "success";
        let httpStatus: number | null = 200;
        let responseSnippet = "ok";

        if (provider.id === "internal-r2") {
          const key = `handoffs/${nowIso.slice(0, 10)}/${routeJobId}.json`;
          await env.ARTICLES.put(key, JSON.stringify({ envelope, signature }, null, 2), {
            httpMetadata: { contentType: "application/json" },
          });
          responseSnippet = `stored:${key}`;
        } else {
          if (!provider.endpoint) {
            throw new Error("ROUTING_PROVIDER_ENDPOINT_MISSING");
          }

          endpoint = provider.endpoint;
          const authMap = crmAuthTokenMap(env);
          const headers: Record<string, string> = {
            "content-type": "application/json",
            "x-clawea-signature": `sha256=${signature}`,
            "x-clawea-idempotency-key": String(job.idempotency_key),
          };

          if (provider.authType === "bearer") {
            const token = authMap[provider.id];
            if (!token) throw new Error("CRM_PROVIDER_AUTH_MISSING");
            headers.authorization = `Bearer ${token}`;
          }

          if (provider.authType === "header") {
            const token = authMap[provider.id];
            if (!token) throw new Error("CRM_PROVIDER_AUTH_MISSING");
            headers[provider.authHeader || "x-api-key"] = token;
          }

          const res = await fetch(provider.endpoint, {
            method: "POST",
            headers,
            body: envelopeJson,
          });

          httpStatus = res.status;
          responseSnippet = (await res.text()).slice(0, 500);

          if (!res.ok) {
            throw new Error(`ROUTING_UPSTREAM_${res.status}`);
          }
        }

        await env.DB.prepare(
          `UPDATE lead_routing_jobs
           SET state = 'sent', sent_at = ?2, updated_at = ?2, last_error_code = '', last_error_message = ''
           WHERE job_id = ?1`,
        ).bind(routeJobId, nowIso).run();

        await env.DB.prepare(
          `UPDATE leads
           SET route_status = 'sent', routed_provider_id = ?2, updated_at = ?3
           WHERE lead_id = ?1`,
        ).bind(String(lead.lead_id), String(job.provider_id), nowIso).run();

        await env.DB.prepare(
          `INSERT INTO lead_handoff_deliveries (
            delivery_id,
            job_id,
            lead_id,
            provider_id,
            endpoint,
            status,
            http_status,
            response_snippet,
            signature,
            attempt,
            created_at
          ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)`,
        )
          .bind(
            randomId("handoff_delivery"),
            routeJobId,
            String(lead.lead_id),
            String(job.provider_id),
            endpoint,
            status,
            httpStatus,
            responseSnippet,
            signature,
            attempts,
            nowIso,
          )
          .run();

        await transitionLeadState(env, String(lead.lead_id), "contacted", "routing_delivery", {
          providerId: job.provider_id,
          routeJobId,
        });

        const qualificationScore = Number(lead.qualification_score ?? 0);
        await transitionLeadState(
          env,
          String(lead.lead_id),
          qualificationScore >= 72 ? "qualified" : "disqualified",
          "routing_scored_disposition",
          { qualificationScore },
        );

        await env.DB.prepare(
          `INSERT INTO lead_events (
            event_id,
            lead_id,
            event_type,
            event_payload_json,
            source,
            page,
            page_family,
            created_at
          ) VALUES (?1, ?2, 'lead_routed', ?3, ?4, ?5, ?6, ?7)`,
        )
          .bind(
            randomId("lead_evt"),
            String(lead.lead_id),
            JSON.stringify({
              routeJobId,
              providerId: job.provider_id,
              attempt: attempts,
              responseSnippet,
              sourceIntent,
              scoreBand: clipString(lead.score_band, 24) ?? "low",
            }),
            String(lead.source ?? "direct"),
            String(lead.page ?? "/contact"),
            String(lead.page_family ?? "contact"),
            nowIso,
          )
          .run();

        message.ack();
        continue;
      }

      if (type === "variant_weekly_report") {
        const nowIso = new Date().toISOString();
        const fromIso = new Date(Date.now() - (7 * 24 * 60 * 60 * 1000)).toISOString();

        const rows = await env.DB.prepare(
          `SELECT
            page_family,
            cta_variant,
            COUNT(*) AS events,
            SUM(CASE WHEN event_type = 'cta_click' THEN 1 ELSE 0 END) AS cta_clicks,
            SUM(CASE WHEN event_type IN ('contact_intent_submit', 'lead_submit', 'booking_submit') THEN 1 ELSE 0 END) AS contact_submits
          FROM funnel_events
          WHERE event_ts >= ?1 AND event_ts <= ?2
            AND cta_variant IS NOT NULL
          GROUP BY page_family, cta_variant
          ORDER BY page_family ASC, events DESC`,
        ).bind(fromIso, nowIso).all<any>();

        const bookedRows = await env.DB.prepare(
          `SELECT page_family, cta_variant, COUNT(*) AS booked
           FROM leads
           WHERE created_at >= ?1 AND created_at <= ?2
             AND cta_variant <> ''
             AND status = 'booked'
           GROUP BY page_family, cta_variant`,
        ).bind(fromIso, nowIso).all<any>();

        const byFamily = new Map<string, Array<any>>();
        for (const row of rows.results ?? []) {
          const family = String(row.page_family ?? "root");
          const variants = byFamily.get(family) ?? [];
          variants.push({
            variant: String(row.cta_variant ?? "unknown"),
            events: Number(row.events ?? 0),
            ctaClicks: Number(row.cta_clicks ?? 0),
            contactSubmits: Number(row.contact_submits ?? 0),
            booked: 0,
          });
          byFamily.set(family, variants);
        }

        const bookedMap = new Map<string, number>();
        for (const row of bookedRows.results ?? []) {
          const key = `${String(row.page_family ?? "root")}::${String(row.cta_variant ?? "unknown")}`;
          bookedMap.set(key, Number(row.booked ?? 0));
        }

        const winners = [...byFamily.entries()].map(([family, variants]) => {
          const hydrated = variants.map((v) => {
            const booked = bookedMap.get(`${family}::${v.variant}`) ?? 0;
            return {
              ...v,
              booked,
              submitRate: v.events > 0 ? Number((v.contactSubmits / v.events).toFixed(4)) : 0,
              bookedRate: v.events > 0 ? Number((booked / v.events).toFixed(4)) : 0,
            };
          });

          const sorted = [...hydrated].sort((a, b) => {
            if (b.bookedRate !== a.bookedRate) return b.bookedRate - a.bookedRate;
            if (b.submitRate !== a.submitRate) return b.submitRate - a.submitRate;
            return b.events - a.events;
          });

          const winner = sorted[0] ?? null;
          return {
            pageFamily: family,
            winner,
            candidates: sorted,
          };
        });

        const artifact = {
          generatedAt: nowIso,
          range: { from: fromIso, to: nowIso, days: 7 },
          winners,
          guardrail: {
            autoPublish: false,
            note: "winner suggestions are advisory and require explicit operator approval",
          },
        };

        const key = `reports/growth/variant-performance-${nowIso.slice(0, 10)}.json`;
        await env.ARTICLES.put(key, JSON.stringify(artifact, null, 2), {
          httpMetadata: { contentType: "application/json" },
        });

        message.ack();
        continue;
      }

      message.ack();
    } catch (err: any) {
      const routeJobId = clipString(payload?.routeJobId, 80);
      const typeLocal = String(payload?.type ?? "");
      console.error("LEAD_QUEUE_MESSAGE_FAILED", { type: typeLocal, routeJobId, err });

      if (typeLocal === "lead_route_dispatch" && routeJobId) {
        const job = await env.DB.prepare(
          `SELECT job_id, lead_id, segment, provider_id, attempts, max_attempts FROM lead_routing_jobs WHERE job_id = ?1 LIMIT 1`,
        ).bind(routeJobId).first<any>();

        if (job?.job_id) {
          const attempts = Number(job.attempts ?? 1);
          const maxAttempts = Number(job.max_attempts ?? routingMaxAttempts(env));
          const nowIso = new Date().toISOString();
          const errorCode = String(err?.message ?? "ROUTING_UNKNOWN_ERROR").slice(0, 80);
          const errorMessage = String(err?.stack ?? err?.message ?? err).slice(0, 800);

          if (attempts >= maxAttempts) {
            await env.DB.prepare(
              `UPDATE lead_routing_jobs
               SET state = 'dead_letter', last_error_code = ?2, last_error_message = ?3, updated_at = ?4, dead_lettered_at = ?4
               WHERE job_id = ?1`,
            ).bind(routeJobId, errorCode, errorMessage, nowIso).run();

            await env.DB.prepare(
              `UPDATE leads SET route_status = 'dead_letter', updated_at = ?2, last_deny_code = ?3 WHERE lead_id = ?1`,
            ).bind(String(job.lead_id), nowIso, errorCode).run();

            await env.DB.prepare(
              `INSERT INTO lead_handoff_dead_letter (
                dead_letter_id,
                job_id,
                lead_id,
                segment,
                provider_id,
                reason_code,
                reason_message,
                payload_json,
                created_at
              ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)`,
            )
              .bind(
                randomId("dead_letter"),
                routeJobId,
                String(job.lead_id),
                String(job.segment ?? "smb"),
                String(job.provider_id ?? "unknown"),
                errorCode,
                errorMessage,
                JSON.stringify(payload ?? {}),
                nowIso,
              )
              .run();

            await env.DB.prepare(
              `INSERT INTO lead_events (
                event_id,
                lead_id,
                event_type,
                event_payload_json,
                source,
                page,
                page_family,
                created_at
              ) VALUES (?1, ?2, 'lead_routing_dead_letter', ?3, 'queue', '/api/routing', 'ops', ?4)`,
            )
              .bind(
                randomId("lead_evt"),
                String(job.lead_id),
                JSON.stringify({ routeJobId, errorCode, errorMessage }),
                nowIso,
              )
              .run();

            message.ack();
            continue;
          }

          await env.DB.prepare(
            `UPDATE lead_routing_jobs
             SET state = 'failed', last_error_code = ?2, last_error_message = ?3, updated_at = ?4
             WHERE job_id = ?1`,
          ).bind(routeJobId, errorCode, errorMessage, nowIso).run();

          await env.DB.prepare(
            `UPDATE leads
             SET route_status = 'retrying', updated_at = ?2, last_deny_code = ?3
             WHERE lead_id = ?1`,
          ).bind(String(job.lead_id), nowIso, errorCode).run();

          await env.DB.prepare(
            `INSERT INTO lead_events (
              event_id,
              lead_id,
              event_type,
              event_payload_json,
              source,
              page,
              page_family,
              created_at
            ) VALUES (?1, ?2, 'lead_routing_retry', ?3, 'queue', '/api/routing', 'ops', ?4)`,
          )
            .bind(
              randomId("lead_evt"),
              String(job.lead_id),
              JSON.stringify({ routeJobId, errorCode, attempts, maxAttempts }),
              nowIso,
            )
            .run();
        }
      }

      message.retry();
    }
  }
}

export async function enqueueWeeklyVariantReportIfDue(env: Env): Promise<void> {
  const now = new Date();
  const isMondayMorningUtc = now.getUTCDay() === 1 && now.getUTCHours() >= 6 && now.getUTCHours() < 8;
  if (!isMondayMorningUtc) return;

  const weekKey = `${now.getUTCFullYear()}-W${String(Math.ceil(((Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()) - Date.UTC(now.getUTCFullYear(), 0, 1)) / 86400000 + 1) / 7)).padStart(2, "0")}`;
  const lockKey = `variant-report-lock:${weekKey}`;

  const exists = await env.VARIANT_CONFIG.get(lockKey, "text");
  if (exists) return;

  await env.VARIANT_CONFIG.put(lockKey, now.toISOString(), { expirationTtl: 14 * 24 * 60 * 60 });
  await env.LEAD_JOBS.send({
    type: "variant_weekly_report",
    weekKey,
    requestedAt: now.toISOString(),
  });
}

