/* ------------------------------------------------------------------ */
/*  Analytics Engine writer                                           */
/*                                                                    */
/*  Schema (query with CF Analytics SQL API):                         */
/*    blob1   hostname (e.g. clawinsure.com)                          */
/*    blob2   path+query (e.g. /ecosystem?host=clawrep.com)           */
/*    blob3   referrer domain (e.g. google.com or direct)             */
/*    blob4   country (CF-IPCountry)                                  */
/*    blob5   action (pageview / inquiry / offer / click actions)     */
/*    blob6   context (label, target, user-agent snippet)             */
/*    double1 count metric (always 1 for SUM)                         */
/*    double2 numeric value (offer amount or 0)                       */
/*    index1  visitor hash (IP-based pseudo-identifier)               */
/* ------------------------------------------------------------------ */

import type { AnalyticsAction, Env } from "./types.js";

function refDomain(referer: string | null): string {
  if (!referer) return "direct";
  try {
    return new URL(referer).hostname;
  } catch {
    return "unknown";
  }
}

async function visitorHash(ip: string): Promise<string> {
  const buf = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(ip + ":claw-domains-salt-2026"),
  );
  const arr = new Uint8Array(buf);
  return Array.from(arr.slice(0, 8))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function trunc(value: string, max: number): string {
  return value.length <= max ? value : value.slice(0, max);
}

function contextBlob(request: Request, label?: string, target?: string): string {
  const ua = trunc(request.headers.get("user-agent") ?? "", 96);
  const parts = [
    label ? `label=${trunc(label, 80)}` : "",
    target ? `target=${trunc(target, 120)}` : "",
    ua ? `ua=${ua}` : "",
  ].filter(Boolean);
  return trunc(parts.join(";"), 255);
}

export async function trackEvent(
  env: Env,
  request: Request,
  action: AnalyticsAction,
  numericValue = 0,
  meta?: { label?: string; target?: string },
): Promise<void> {
  const url = new URL(request.url);
  const ip = request.headers.get("cf-connecting-ip") ?? "0.0.0.0";

  const pathWithQuery = trunc(
    `${url.pathname}${url.search}` || "/",
    180,
  );

  env.ANALYTICS.writeDataPoint({
    blobs: [
      url.hostname,
      pathWithQuery,
      refDomain(request.headers.get("referer")),
      request.headers.get("cf-ipcountry") ?? "XX",
      action,
      contextBlob(request, meta?.label, meta?.target),
    ],
    doubles: [1, Number.isFinite(numericValue) ? numericValue : 0],
    indexes: [await visitorHash(ip)],
  });
}
