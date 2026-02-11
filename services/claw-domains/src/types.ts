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

export type EcosystemStatus =
  | "live"
  | "building"
  | "planned"
  | "for_sale";

export interface DomainConfig {
  mode: DomainMode;
  /** Headline tagline shown under the domain name */
  tagline: string;
  /** Ecosystem pillar label */
  pillar: string;
  /** Clear purpose statement shown in landing content */
  purpose: string;
  /** Buy-it-now price (USD). Only used when mode = "for_sale" */
  bin_price?: number;
  /** Redirect target. Only used when mode = "redirect" */
  redirect_url?: string;
  /** Related domains to interlink for clear user navigation */
  related_domains?: string[];
  /** Optional status hint for the landing card */
  status_hint?: EcosystemStatus;
}

export interface EcosystemDomain {
  domain: string;
  tagline: string;
  pillar: string;
  purpose: string;
  status: EcosystemStatus;
  /** If true, this domain currently has a dedicated service runtime */
  active_service?: boolean;
}

export interface InquiryPayload {
  name: string;
  email: string;
  offer_amount: number | null;
  message: string;
}

export type AnalyticsAction =
  | "pageview"
  | "inquiry"
  | "offer"
  | "cta_click"
  | "nav_click"
  | "related_click"
  | "ecosystem_click"
  | "outbound_click";

export interface TrackPayload {
  action: AnalyticsAction;
  label?: string;
  target?: string;
  value?: number;
}
