/* ------------------------------------------------------------------ */
/*  claw-domains — shared types                                       */
/* ------------------------------------------------------------------ */

export interface Env {
  INQUIRIES_DB: D1Database;
  ANALYTICS: AnalyticsEngineDataset;
  ENVIRONMENT: string;
  CF_WEB_ANALYTICS_TOKEN: string;
  INQUIRY_FORWARD_EMAIL: string;
  /** Admin bearer token (set via `wrangler secret put ADMIN_TOKEN`). */
  ADMIN_TOKEN?: string;
}

export type DomainMode = "for_sale" | "coming_soon" | "redirect";

export interface DomainConfig {
  mode: DomainMode;
  /** Headline tagline shown under the domain name */
  tagline: string;
  /** Ecosystem pillar label */
  pillar: string;
  /** Buy-it-now price (USD). Only used when mode = "for_sale" */
  bin_price?: number;
  /** Redirect target. Only used when mode = "redirect" */
  redirect_url?: string;
}

export interface InquiryPayload {
  name: string;
  email: string;
  offer_amount: number | null;
  message: string;
}
