/* ------------------------------------------------------------------ */
/*  Per-domain configuration                                          */
/*                                                                    */
/*  Domains with active services (bounties, escrow, verify, etc.)     */
/*  are NOT listed here — they have their own Workers.                */
/*                                                                    */
/*  Modes:                                                            */
/*    for_sale     — "This domain may be available" + offer form      */
/*    coming_soon  — branded holding page linking to clawbureau.com   */
/*    redirect     — 301 to another URL                               */
/* ------------------------------------------------------------------ */

import type { DomainConfig } from "./types.js";

export const DOMAIN_MAP: Record<string, DomainConfig> = {
  /* ── For-sale candidates (highest resale / lowest ecosystem need) ── */
  "clawinsure.com": {
    mode: "for_sale",
    bin_price: 79_000,
    tagline: "Insurance infrastructure for the agent economy",
    pillar: "Economy & Settlement",
  },
  "clawsettle.com": {
    mode: "for_sale",
    bin_price: 59_000,
    tagline: "Settlement and payout rails",
    pillar: "Economy & Settlement",
  },
  "clawportfolio.com": {
    mode: "for_sale",
    bin_price: 39_000,
    tagline: "Agent portfolio and showcase platform",
    pillar: "Community & Growth",
  },
  "clawadvisory.com": {
    mode: "for_sale",
    bin_price: 29_000,
    tagline: "Governance and advisory services",
    pillar: "Governance & Risk Controls",
  },
  "clawcareers.com": {
    mode: "for_sale",
    bin_price: 24_000,
    tagline: "Careers in the agent economy",
    pillar: "Labor & Delegation",
  },

  /* ── Coming-soon — planned ecosystem services, not yet live ─────── */
  "clawrep.com": {
    mode: "coming_soon",
    tagline: "Portable reputation for AI agents",
    pillar: "Identity & Trust",
  },
  "clawsig.com": {
    mode: "coming_soon",
    tagline: "Public signing and attestation service",
    pillar: "Identity & Trust",
  },
  "clawea.com": {
    mode: "coming_soon",
    tagline: "Execution attestation and sandbox proofs",
    pillar: "Labor & Delegation",
  },
  "clawsilo.com": {
    mode: "coming_soon",
    tagline: "Encrypted artifact storage for proof bundles",
    pillar: "Infrastructure",
  },
  "clawdelegate.com": {
    mode: "coming_soon",
    tagline: "Delegation and approval workflows",
    pillar: "Labor & Delegation",
  },
  "clawintel.com": {
    mode: "coming_soon",
    tagline: "Fraud detection and risk intelligence",
    pillar: "Infrastructure",
  },
  "clawtrials.com": {
    mode: "coming_soon",
    tagline: "Dispute arbitration and resolution",
    pillar: "Governance & Risk Controls",
  },
  "clawcontrols.com": {
    mode: "coming_soon",
    tagline: "Policy controls and kill switches",
    pillar: "Governance & Risk Controls",
  },
  "clawmanage.com": {
    mode: "coming_soon",
    tagline: "Admin operations and case management",
    pillar: "Governance & Risk Controls",
  },
  "clawlogs.com": {
    mode: "coming_soon",
    tagline: "Tamper-evident audit logging",
    pillar: "Identity & Trust",
  },
  "clawforhire.com": {
    mode: "coming_soon",
    tagline: "Agent services marketplace",
    pillar: "Labor & Delegation",
  },
  "clawproviders.com": {
    mode: "coming_soon",
    tagline: "Provider registry and onboarding",
    pillar: "Labor & Delegation",
  },
  "clawsupply.com": {
    mode: "coming_soon",
    tagline: "Compute and work supply marketplace",
    pillar: "Economy & Settlement",
  },
  "clawincome.com": {
    mode: "coming_soon",
    tagline: "Statements, invoices, and tax exports",
    pillar: "Economy & Settlement",
  },
  "clawgrant.com": {
    mode: "coming_soon",
    tagline: "Protocol grants and funding",
    pillar: "Community & Growth",
  },
  "clawgang.com": {
    mode: "coming_soon",
    tagline: "Community hub and events",
    pillar: "Community & Growth",
  },
  "clawmerch.com": {
    mode: "coming_soon",
    tagline: "Official Claw Bureau merchandise",
    pillar: "Community & Growth",
  },
  "clawscope.com": {
    mode: "redirect",
    tagline: "Scoped tokens and observability",
    pillar: "Infrastructure",
    redirect_url: "https://clawbureau.com",
  },
};

/** Domains that already have their own Workers — never match here */
export const ACTIVE_SERVICE_DOMAINS = new Set([
  "clawbounties.com",
  "clawbureau.com",
  "clawclaim.com",
  "clawcuts.com",
  "clawescrow.com",
  "clawledger.com",
  "clawproxy.com",
  "clawverify.com",
  "joinclaw.com",
]);
