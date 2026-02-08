/* ------------------------------------------------------------------ */
/*  Analytics Engine writer                                           */
/*                                                                    */
/*  Schema (query with the CF SQL API):                               */
/*    blob1  — hostname          (e.g. "clawinsure.com")              */
/*    blob2  — path              (e.g. "/")                           */
/*    blob3  — referrer domain   (e.g. "google.com" or "direct")      */
/*    blob4  — country           (CF-IPCountry header)                */
/*    blob5  — action            ("pageview" | "inquiry" | "offer")   */
/*    blob6  — user-agent (first 256 chars)                           */
/*    double1 — 1                (count — always 1 for easy SUM)      */
/*    double2 — offer amount USD (0 if not an offer)                  */
/*    index1  — visitor hash     (IP-based, for unique counting)      */
/* ------------------------------------------------------------------ */

import type { Env } from "./types.js";

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

export async function trackEvent(
  env: Env,
  request: Request,
  action: "pageview" | "inquiry" | "offer",
  offerAmount = 0,
): Promise<void> {
  const url = new URL(request.url);
  const ip = request.headers.get("cf-connecting-ip") ?? "0.0.0.0";

  env.ANALYTICS.writeDataPoint({
    blobs: [
      url.hostname,
      url.pathname,
      refDomain(request.headers.get("referer")),
      request.headers.get("cf-ipcountry") ?? "XX",
      action,
      (request.headers.get("user-agent") ?? "").slice(0, 256),
    ],
    doubles: [1, offerAmount],
    indexes: [await visitorHash(ip)],
  });
}
