#!/usr/bin/env npx tsx
/*
 * Model write-off: generate the same 3 target articles across multiple OpenRouter models
 * via fal's OpenRouter router, using identical retrieval context per article.
 *
 * IMPORTANT: Candidate outputs are anonymized.
 * - No model IDs are written to the output folder.
 * - A private mapping (candidateId -> modelId) is written to ~/.clawbureau-secrets/.
 */

import * as fs from "fs";
import * as path from "path";

import { z } from "zod";

import { generateAllTopics, type Topic } from "./taxonomy";
import { braveWebSearch } from "./brave";
import { exaContents, exaSearchAndContents, type ExaSearchResult } from "./exa";
import { lintText } from "./quality";
import {
  buildPlatformTruthTable,
  evaluateClaimSafety,
  loadIntegrationManifest,
  resolveTargetIntegrationContext,
} from "./integration-manifest";
import { officialChannelSources, officialDoc, officialRepoSnippet } from "./openclaw-docs";

const OPENROUTER_CHAT_COMPLETIONS_URL =
  process.env.OPENROUTER_CHAT_COMPLETIONS_URL ??
  "https://fal.run/openrouter/router/openai/v1/chat/completions";

const FAL_KEY = process.env.FAL_KEY;
if (!FAL_KEY) {
  console.error("FAL_KEY not set");
  process.exit(1);
}

const BRAVE_WEB_API_KEY = process.env.BRAVE_WEB_API_KEY ?? process.env.BRAVE_PRO_API_KEY;
const EXA_API_KEY = process.env.EXA_API_KEY;

const REPO_ROOT = path.resolve(import.meta.dirname ?? ".", "../../..");

const HIGH_TRUST_DOMAINS = [
  // Standards and security
  "owasp.org",
  "cheatsheetseries.owasp.org",
  "genai.owasp.org",
  "nist.gov",
  "cisa.gov",
  "modelcontextprotocol.io",
  "openpolicyagent.org",

  // Microsoft
  "learn.microsoft.com",
  "docs.microsoft.com",
  "developer.microsoft.com",

  // Cloudflare
  "developers.cloudflare.com",
  "blog.cloudflare.com",
  "cloudflare.com",

  // GitHub
  "github.com",
  "docs.github.com",

  // Atlassian
  "developer.atlassian.com",
  "support.atlassian.com",
  "atlassian.com",

  // Slack
  "api.slack.com",
  "docs.slack.dev",
  "slack.com",

  // Discord
  "discord.com",
  "support-dev.discord.com",

  // Notion
  "developers.notion.com",

  // Okta
  "developer.okta.com",
  "okta.com",

  // Stripe
  "docs.stripe.com",
  "stripe.com",

  // Observability
  "docs.datadoghq.com",
  "datadoghq.com",
  "docs.splunk.com",
  "splunk.com",
  "docs.newrelic.com",
  "newrelic.com",
  "grafana.com",
  "elastic.co",

  // AWS / Google Cloud
  "docs.aws.amazon.com",
  "aws.amazon.com",
  "cloud.google.com",
  "developers.google.com",

  // Enterprise apps / platforms
  "developer.salesforce.com",
  "salesforce.com",
  "help.sap.com",
  "api.sap.com",
  "sap.com",
  "docs.servicenow.com",
  "developer.servicenow.com",
  "servicenow.com",
  "docs.workday.com",
  "workday.com",
  "docs.snowflake.com",
  "snowflake.com",
  "docs.databricks.com",
  "databricks.com",
  "postgresql.org",
  "redis.io",
  "mongodb.com",
  "docs.mongodb.com",
  "docs.pagerduty.com",
  "pagerduty.com",
  "developers.hubspot.com",
  "hubspot.com",
  "developers.intercom.com",
  "intercom.com",
  "developer.zendesk.com",
  "zendesk.com",
  "developers.notion.com",
  "notion.com",
  "developer.box.com",
  "box.com",
  "docs.coupa.com",
  "coupa.com",
] as const;

const LOW_TRUST_DOMAIN_SUBSTRINGS = [
  "medium.com",
  "towardsdatascience.com",
  "substack.com",
  "dev.to",
  "reddit.com",
  "youtube.com",
  "tiktok.com",
  "facebook.com",
  "x.com",
  "twitter.com",
  "apidog.com",
  "mindstudio.ai",
  "skywork.ai",
  "cloudmatos.ai",
  "petronellatech.com",
] as const;

function hostFromUrl(u: string): string {
  try {
    return new URL(u).hostname.toLowerCase();
  } catch {
    return "";
  }
}

function isLowTrust(u: string): boolean {
  const h = hostFromUrl(u);
  return LOW_TRUST_DOMAIN_SUBSTRINGS.some((s) => h === s || h.endsWith(`.${s}`) || h.includes(s));
}

function isHighTrust(u: string, allowDomains?: string[]): boolean {
  const h = hostFromUrl(u);
  const allow = allowDomains?.length ? allowDomains : [...HIGH_TRUST_DOMAINS];
  // GitHub is only "high trust" for a curated org allowlist (avoids random low-signal repos).
  if (h === "github.com") {
    return isAllowedGithubUrl(u);
  }

  return allow.some((d) => h === d || h.endsWith(`.${d}`));
}

const ALLOWED_GITHUB_ORGS = [
  "openclaw",
  "modelcontextprotocol",
  "github",
  "anthropic-experimental",
  "makenotion",
  "sooperset",
  "FedRAMP",
  "OWASP",
] as const;

function isAllowedGithubUrl(u: string): boolean {
  try {
    const url = new URL(u);
    if (url.hostname.toLowerCase() !== "github.com") return false;
    const parts = url.pathname.split("/").filter(Boolean);
    const org = (parts[0] ?? "").toLowerCase();
    return (ALLOWED_GITHUB_ORGS as readonly string[]).some((o) => o.toLowerCase() === org);
  } catch {
    return false;
  }
}

function githubBlobToRawUrl(u: string): string | null {
  try {
    const url = new URL(u);
    if (url.hostname.toLowerCase() !== "github.com") return null;

    const parts = url.pathname.split("/").filter(Boolean);
    // /<org>/<repo>/blob/<ref>/<path...>
    if (parts.length < 5) return null;
    if ((parts[2] ?? "").toLowerCase() !== "blob") return null;

    const org = parts[0];
    const repo = parts[1];
    const ref = parts[3];
    const filePath = parts.slice(4).join("/");
    return `https://raw.githubusercontent.com/${org}/${repo}/${ref}/${filePath}`;
  } catch {
    return null;
  }
}

async function fetchTextSnippet(u: string, maxChars = 3200): Promise<string | null> {
  const ctrl = new AbortController();
  const timeout = setTimeout(() => ctrl.abort(), 12000);
  try {
    const res = await fetch(u, { signal: ctrl.signal });
    if (!res.ok) return null;
    const t = await res.text();
    return t.replace(/\r\n/g, "\n").trim().slice(0, maxChars);
  } catch {
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

const LEARN_DROP_LINE_RX: RegExp[] = [
  /^skip to main content/i,
  /^skip to ask learn/i,
  /^this browser is no longer supported/i,
  /^upgrade to microsoft edge/i,
  /^acceptrejectmanage cookies/i,
  /^acceptreject/i,
  /^manage cookies/i,
  /^privacy statement/i,
  /^third-party cookies/i,
  /^table of contents/i,
  /^ask learn/i,
  /^focus mode/i,
  /^read in english/i,
  /^add to collections/i,
  /^add to plan/i,
  /^share via/i,
  /^print$/i,
  /^feedback$/i,
  /^summarize this article/i,
  /^suggestions will filter as you type/i,
  /^sign in$/i,
  /^sign out$/i,
  /access to this page requires authorization/i,
];

const GITHUB_DROP_LINE_RX: RegExp[] = [
  /^skip to content/i,
  /^navigation menu/i,
  /^toggle navigation/i,
  /^appearance settings/i,
  /^search or jump to/i,
  /^search code, repositories, users, issues, pull requests/i,
  /^provide feedback/i,
  /^saved searches/i,
  /^search syntax tips/i,
  /^resetting focus/i,
  /^you signed (in|out) with another tab/i,
  /^dismiss alert/i,
  /^sign in$/i,
  /^sign up$/i,
  /^notifications/i,
  /^fork/i,
  /^star/i,
];

function cleanSourceText(url: string, text: string): string {
  const host = hostFromUrl(url);
  const raw = (text ?? "").replace(/\r\n/g, "\n");

  const lines = raw
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .filter((l) => l !== "[]")
    // Drop "[Link]"-only nav tokens, but keep longer bracket-only lines.
    .filter((l) => !/^\[[^\]]*\]$/.test(l) || l.length > 50);

  const isLearn =
    host === "learn.microsoft.com" ||
    host.endsWith(".learn.microsoft.com") ||
    host === "developer.microsoft.com" ||
    host.endsWith(".developer.microsoft.com") ||
    host === "docs.microsoft.com" ||
    host.endsWith(".docs.microsoft.com");

  const isGithub = host === "github.com";

  const rx = isLearn ? LEARN_DROP_LINE_RX : isGithub ? GITHUB_DROP_LINE_RX : [];
  const filtered = rx.length ? lines.filter((l) => !rx.some((r) => r.test(l))) : lines;

  const out = filtered.join("\n").replace(/\n{3,}/g, "\n\n").trim();

  // Avoid sign-in-only pages.
  if (/access to this page requires authorization/i.test(out)) return "";
  return out;
}

function readLocalExcerpt(filePath: string, maxChars = 2800): string {
  const full = fs.readFileSync(filePath, "utf-8").replace(/\r\n/g, "\n");
  const cleaned = full.startsWith("---") ? full.replace(/^---[\s\S]*?---\n/, "") : full;
  return cleaned.trim().slice(0, maxChars);
}

function localDocBlock(label: string, repoRelPath: string, maxChars = 2600): { label: string; excerpt: string } | null {
  const fp = path.join(REPO_ROOT, repoRelPath);
  if (!fs.existsSync(fp)) return null;
  return { label, excerpt: readLocalExcerpt(fp, maxChars) };
}

const DEFAULT_MODELS: string[] = [
  "anthropic/claude-opus-4.6",
  "moonshotai/kimi-k2.5",
  "minimax/minimax-m2.1",
  "openai/gpt-5.2-chat",
  "openai/gpt-5.2",
  "qwen/qwen3-max-thinking",
  "z-ai/glm-4.7",
  "perplexity/sonar-pro-search",
];

function parseCommaListEnv(name: string): string[] | null {
  const raw = process.env[name];
  if (!raw?.trim()) return null;
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

const MODELS: string[] = (() => {
  const env = parseCommaListEnv("WRITE_OFF_MODELS");
  if (!env?.length) return DEFAULT_MODELS;
  // Preserve order, remove duplicates.
  const seen = new Set<string>();
  const out: string[] = [];
  for (const m of env) {
    if (seen.has(m)) continue;
    seen.add(m);
    out.push(m);
  }
  return out;
})();

// Representative targets: pillar, workflow, enterprise tool security, plus one strict JSON wizard output.
type RetrievalProfile = {
  query: string;
  includeDomains: string[];
  maxResults: number;
};

type WriteoffTarget =
  | { kind: "article"; slug: string; retrieval: RetrievalProfile; notes: string }
  | {
      kind: "wizard";
      slug: string;
      title: string;
      company: { name: string; domain: string };
      retrieval: RetrievalProfile;
      notes: string;
    };

const DEFAULT_TARGETS: WriteoffTarget[] = [
  {
    kind: "article",
    slug: "policy-as-code-for-agents",
    retrieval: {
      query: "policy as code for AI agents tool allowlist egress approvals budgets",
      includeDomains: [
        "owasp.org",
        "cheatsheetseries.owasp.org",
        "genai.owasp.org",
        "modelcontextprotocol.io",
        "openpolicyagent.org",
        "nist.gov",
        "cisa.gov",
        "learn.microsoft.com",
        "developers.cloudflare.com",
        "blog.cloudflare.com",
        "github.com",
      ],
      maxResults: 10,
    },
    notes: "Core positioning pillar. Must sound like security engineering, not marketing.",
  },
  {
    kind: "article",
    slug: "workflows/production-deploy-approval/entra-id/microsoft-teams",
    retrieval: {
      query: "two person approval production deployment Microsoft Entra ID Conditional Access PIM Teams",
      includeDomains: [
        "learn.microsoft.com",
        "developer.microsoft.com",
        "owasp.org",
        "cheatsheetseries.owasp.org",
        "nist.gov",
      ],
      maxResults: 10,
    },
    notes: "Workflow-first pattern, Microsoft-heavy. Must emphasize irreversible actions + approvals + proof.",
  },
  {
    kind: "article",
    slug: "tools/sharepoint/security",
    retrieval: {
      query: "SharePoint security least privilege Microsoft Graph permissions DLP retention",
      includeDomains: [
        "learn.microsoft.com",
        "developer.microsoft.com",
        "owasp.org",
        "genai.owasp.org",
        "nist.gov",
      ],
      maxResults: 10,
    },
    notes: "Enterprise tool security posture. Must avoid over-claiming and focus on Graph scopes + DLP + audit evidence.",
  },
  {
    kind: "article",
    slug: "agent-proof-and-attestation",
    retrieval: {
      query: "cryptographic receipts for AI model calls audit trail proof bundle verification",
      includeDomains: [
        "nist.gov",
        "cisa.gov",
        "owasp.org",
        "cheatsheetseries.owasp.org",
        "developers.cloudflare.com",
        "blog.cloudflare.com",
      ],
      maxResults: 10,
    },
    notes: "Pillar page for receipts + proof bundles + verification. Must be precise about what is shipped vs implementable.",
  },
  {
    kind: "wizard",
    slug: "wizard/enterprise-intake/firecrawl",
    title: "Enterprise intake wizard output for firecrawl.dev (strict JSON) | Claw EA",
    company: { name: "Firecrawl", domain: "firecrawl.dev" },
    retrieval: {
      query: "firecrawl api documentation",
      includeDomains: ["firecrawl.dev"],
      maxResults: 8,
    },
    notes: "Wizard output. Strict JSON only. Must recommend connectors and a WPC skeleton without over-claiming shipped capabilities.",
  },
];

const REQUESTED_TARGET_SLUGS = parseCommaListEnv("WRITE_OFF_TARGET_SLUGS");
const TOP_N = Number(process.env.WRITE_OFF_TOP_N ?? "0");
const INDEXABLE_ONLY = process.env.WRITE_OFF_INDEXABLE_ONLY !== "0";
const EXCLUDE_CATEGORIES = new Set(parseCommaListEnv("WRITE_OFF_EXCLUDE_CATEGORIES") ?? []);

function titleBase(t: Topic): string {
  return t.title.replace(/ \| Claw EA$/, "").trim();
}

function queryForTopic(t: Topic): string {
  const base = titleBase(t).replace(/\([^)]*\)/g, "").replace(/\s+/g, " ").trim();
  const s = t.slug;

  if (s.startsWith("controls/")) return `${base} for AI agents policy as code`;
  if (s.includes("proof") || s.includes("attestation") || s.includes("verify")) {
    return `${base} cryptographic receipts proof bundle verification`;
  }
  if (s.includes("audit") || s.includes("replay")) return `${base} audit replay evidence retention`;
  if (s.includes("supply-chain")) return `${base} supply chain security plugins MCP`;
  if (s.includes("mcp")) return `${base} MCP security governance model context protocol`;
  if (s.includes("event") || s.startsWith("events/")) return `${base} webhooks changefeed idempotency security`;
  if (s.includes("policy") || s.includes("governance")) return `${base} permissioned execution approvals`;

  return `${base} enterprise AI agents security`;
}

function dynamicRetrievalForTopic(t: Topic): RetrievalProfile {
  const s = t.slug.toLowerCase();

  const baseDomains: string[] = [
    // Standards and security
    "owasp.org",
    "cheatsheetseries.owasp.org",
    "genai.owasp.org",
    "nist.gov",
    "cisa.gov",

    // Policy + protocol
    "openpolicyagent.org",
    "modelcontextprotocol.io",

    // Cloudflare + OpenClaw references
    "developers.cloudflare.com",
    "blog.cloudflare.com",
    "github.com",

    // Big enterprise doc hubs across providers
    "learn.microsoft.com",
    "developer.microsoft.com",
    "docs.aws.amazon.com",
    "aws.amazon.com",
    "cloud.google.com",
    "developers.google.com",
    "developer.salesforce.com",
    "salesforce.com",
    "help.sap.com",
    "api.sap.com",
    "sap.com",
    "docs.servicenow.com",
    "developer.servicenow.com",
    "servicenow.com",
  ];

  const extras: string[] = [];

  if (/aws|eventbridge|sqs/.test(s)) {
    extras.push("docs.aws.amazon.com", "aws.amazon.com");
  }

  if (/google|bigquery|pubsub|gmail|drive|calendar/.test(s)) {
    extras.push("cloud.google.com", "developers.google.com");
  }

  if (/salesforce|hubspot|intercom|zendesk/.test(s)) {
    extras.push(
      "developer.salesforce.com",
      "salesforce.com",
      "developers.hubspot.com",
      "hubspot.com",
      "developers.intercom.com",
      "intercom.com",
      "developer.zendesk.com",
      "zendesk.com",
    );
  }

  if (/sap|netsuite|workday|coupa/.test(s)) {
    extras.push(
      "help.sap.com",
      "api.sap.com",
      "sap.com",
      "docs.workday.com",
      "workday.com",
      "docs.coupa.com",
      "coupa.com",
    );
  }

  if (/snowflake|databricks|postgres|redis|mongodb|bigquery/.test(s)) {
    extras.push(
      "docs.snowflake.com",
      "snowflake.com",
      "docs.databricks.com",
      "databricks.com",
      "postgresql.org",
      "redis.io",
      "mongodb.com",
      "docs.mongodb.com",
      "cloud.google.com",
    );
  }

  if (/servicenow|okta|onepassword|crowdstrike|wiz|prisma|defender|sentinel|purview/.test(s)) {
    extras.push(
      "docs.servicenow.com",
      "developer.servicenow.com",
      "servicenow.com",
      "developer.okta.com",
      "okta.com",
      "1password.com",
      "crowdstrike.com",
      "wiz.io",
      "paloaltonetworks.com",
      "learn.microsoft.com",
    );
  }

  if (/splunk|elastic|datadog|grafana|newrelic|pagerduty|siem|observability/.test(s)) {
    extras.push(
      "docs.splunk.com",
      "splunk.com",
      "elastic.co",
      "docs.datadoghq.com",
      "datadoghq.com",
      "grafana.com",
      "docs.newrelic.com",
      "newrelic.com",
      "docs.pagerduty.com",
      "pagerduty.com",
    );
  }

  const includeDomains = [...new Set([...baseDomains, ...extras])];

  return {
    query: queryForTopic(t),
    includeDomains,
    maxResults: Number(process.env.WRITE_OFF_RETRIEVAL_MAX_RESULTS ?? "8"),
  };
}

function dynamicArticleTarget(t: Topic): WriteoffTarget {
  return {
    kind: "article",
    slug: t.slug,
    retrieval: dynamicRetrievalForTopic(t),
    notes: `Auto target (category=${t.category}, priority=${t.priority})`,
  };
}

function selectTargets(allTopics: Topic[], topicBySlug: Map<string, Topic>): WriteoffTarget[] {
  const defaultsBySlug = new Map(DEFAULT_TARGETS.map((t) => [t.slug, t] as const));

  if (REQUESTED_TARGET_SLUGS?.length) {
    const out: WriteoffTarget[] = [];
    for (const slug of REQUESTED_TARGET_SLUGS) {
      const d = defaultsBySlug.get(slug);
      if (d) {
        out.push(d);
        continue;
      }
      const topic = topicBySlug.get(slug);
      if (!topic) throw new Error(`Unknown slug in WRITE_OFF_TARGET_SLUGS: ${slug}`);
      out.push(dynamicArticleTarget(topic));
    }
    return out;
  }

  if (TOP_N > 0) {
    const filtered = allTopics
      .filter((t) => (INDEXABLE_ONLY ? t.indexable === true : true))
      .filter((t) => !EXCLUDE_CATEGORIES.has(t.category))
      .sort((a, b) => (b.priority - a.priority) || a.slug.localeCompare(b.slug, "en"));

    return filtered.slice(0, TOP_N).map(dynamicArticleTarget);
  }

  return DEFAULT_TARGETS;
}

const APPEND = process.env.WRITE_OFF_APPEND === "1";
const OUT_ROOT_ENV = process.env.WRITE_OFF_OUT_ROOT ? path.resolve(process.env.WRITE_OFF_OUT_ROOT) : null;

const RUN_ID =
  process.env.WRITE_OFF_RUN_ID ??
  (OUT_ROOT_ENV ? path.basename(OUT_ROOT_ENV) : new Date().toISOString().replace(/[:.]/g, "-"));

const OUT_ROOT = OUT_ROOT_ENV ?? path.resolve(import.meta.dirname ?? ".", `../sample-output/model-writeoff/${RUN_ID}`);

const PRIVATE_MAP_PATH = path.join(
  process.env.HOME ?? "~",
  ".clawbureau-secrets",
  `clawea-model-writeoff-map.${RUN_ID}.json`,
);

const SANITIZE_SOURCES = process.env.WRITE_OFF_SANITIZE !== "0";
const SANITIZER_REGEN_ATTEMPTS = Number(process.env.WRITE_OFF_SANITIZER_REGEN_ATTEMPTS ?? "0");

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function shuffle<T>(arr: T[]): T[] {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

function ensureDir(p: string): void {
  fs.mkdirSync(p, { recursive: true });
}

function cleanHtml(s: string): string {
  let t = s.trim();
  t = t.replace(/^```html\s*/i, "");
  t = t.replace(/^```\s*/i, "");
  t = t.replace(/```\s*$/i, "");
  return t.trim();
}

function cleanJson(s: string): string {
  let t = s.trim();
  t = t.replace(/^```json\s*/i, "");
  t = t.replace(/^```\s*/i, "");
  t = t.replace(/```\s*$/i, "");
  return t.trim();
}

function extractJsonObjectText(s: string): string {
  const t = cleanJson(s);
  const start = t.indexOf("{");
  const end = t.lastIndexOf("}");
  if (start >= 0 && end > start) return t.slice(start, end + 1).trim();
  return t;
}

function candidateId(n: number): string {
  return `candidate-${String(n).padStart(2, "0")}`;
}

function toSafeFolderName(slug: string): string {
  return slug.replace(/\//g, "__");
}

function maxCandidateNumberFromDir(dir: string): number {
  if (!fs.existsSync(dir)) return 0;
  const items = fs.readdirSync(dir);
  let max = 0;
  for (const it of items) {
    const m = it.match(/^candidate-(\d+)/i);
    if (!m) continue;
    const n = Number(m[1]);
    if (Number.isFinite(n)) max = Math.max(max, n);
  }
  return max;
}

function extractHrefUrls(html: string): string[] {
  const out: string[] = [];
  const rx = /href\s*=\s*["']([^"']+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = rx.exec(html)) !== null) {
    out.push(m[1]);
  }
  return [...new Set(out)];
}

function sanitizeHtmlAnchors(html: string, allowed: Set<string>): { html: string; removed: string[] } {
  const removed: string[] = [];
  const out = html.replace(/<a\b[^>]*>/gi, (tag) => {
    const m = tag.match(/\bhref\s*=\s*("([^"]+)"|'([^']+)')/i);
    if (!m) return tag;
    const url = m[2] ?? m[3] ?? "";
    if (allowed.has(url)) return tag;

    removed.push(url);

    // Remove href and the typical link-only attributes for cleanliness.
    let t = tag.replace(m[0], "");
    t = t.replace(/\s+target\s*=\s*("([^"]*)"|'([^']*)')/i, "");
    t = t.replace(/\s+rel\s*=\s*("([^"]*)"|'([^']*)')/i, "");
    t = t.replace(/\s{2,}/g, " ");
    return t;
  });

  return { html: out, removed: [...new Set(removed)] };
}

function hasOpenclawLink(hrefs: string[]): boolean {
  return hrefs.some((u) => openclawUrl(u));
}

function hasExternalLink(hrefs: string[]): boolean {
  return hrefs.some((u) => !openclawUrl(u));
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function hasH2(html: string, heading: string): boolean {
  const rx = new RegExp(`<h2[^>]*>\\s*${escapeRegExp(heading)}\\s*<\\/h2>`, "i");
  return rx.test(html);
}

function h2Index(html: string, heading: string): number {
  const rx = new RegExp(`<h2[^>]*>\\s*${escapeRegExp(heading)}\\s*<\\/h2>`, "i");
  const m = rx.exec(html);
  return m?.index ?? -1;
}

function microsoftSlug(slug: string): boolean {
  return /entra-id|sharepoint|microsoft-teams|outlook-exchange|microsoft-graph|azure-devops/i.test(slug);
}

function openclawUrl(u: string): boolean {
  return u.includes("github.com/openclaw/openclaw/blob/");
}

function microsoftDocUrl(u: string): boolean {
  const h = hostFromUrl(u);
  return h === "learn.microsoft.com" || h.endsWith(".learn.microsoft.com") || h === "developer.microsoft.com" || h.endsWith(".developer.microsoft.com");
}

async function openrouterChat(
  model: string,
  system: string,
  user: string,
  opts: {
    temperature: number;
    maxTokens: number;
  },
): Promise<{ text: string; usage?: any; finishReason?: string; raw?: any }> {
  const body: any = {
    model,
    messages: [
      { role: "system", content: system },
      { role: "user", content: user },
    ],
    temperature: opts.temperature,
    max_tokens: opts.maxTokens,
    top_p: 1,
  };

  for (let attempt = 0; attempt < 8; attempt++) {
    try {
      const res = await fetch(OPENROUTER_CHAT_COMPLETIONS_URL, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "authorization": `Key ${FAL_KEY}`,
        },
        body: JSON.stringify(body),
      });

      if (res.status === 429 || res.status === 503 || res.status === 500) {
        const wait = Math.min(1500 * 2 ** attempt, 30000);
        await sleep(wait);
        continue;
      }

      if (!res.ok) {
        const t = await res.text();
        throw new Error(`OpenRouter failed ${res.status}: ${t.slice(0, 300)}`);
      }

      const data = (await res.json()) as any;
      const text =
        data?.choices?.[0]?.message?.content ??
        data?.choices?.[0]?.text ??
        "";

      const finishReason = data?.choices?.[0]?.finish_reason;

      if (typeof text !== "string" || !text.trim()) {
        // transient empty output happens; retry
        const wait = Math.min(1200 * 2 ** attempt, 15000);
        await sleep(wait);
        continue;
      }

      return { text, usage: data?.usage, finishReason, raw: data };
    } catch (e: any) {
      // network-level fetch failures
      const wait = Math.min(1200 * 2 ** attempt, 20000);
      await sleep(wait);
      if (attempt === 7) throw e;
    }
  }

  throw new Error("OpenRouter retries exhausted");
}

function hostMatchesDomain(host: string, domain: string): boolean {
  const h = host.toLowerCase();
  const d = domain.toLowerCase();
  return h === d || h.endsWith(`.${d}`);
}

function selectDiverseSources(
  items: Array<{ title: string; url: string; text: string }>,
  includeDomains: string[],
  maxResults: number,
): Array<{ title: string; url: string; text: string }> {
  const out: Array<{ title: string; url: string; text: string }> = [];
  const used = new Set<string>();

  // Pick at most 2 per preferred domain, in the order provided.
  for (const dom of includeDomains) {
    const picked = items.filter((i) => hostMatchesDomain(hostFromUrl(i.url), dom) && !used.has(i.url)).slice(0, 2);
    for (const p of picked) {
      out.push(p);
      used.add(p.url);
      if (out.length >= maxResults) return out;
    }
  }

  // Fill remaining.
  for (const i of items) {
    if (used.has(i.url)) continue;
    out.push(i);
    used.add(i.url);
    if (out.length >= maxResults) break;
  }

  return out;
}

async function fetchWebSources(profile: RetrievalProfile): Promise<Array<{ title: string; url: string; text: string }>> {
  const includeDomains = profile.includeDomains;

  // Prefer Exa search with includeDomains for high-quality, controllable sources.
  if (EXA_API_KEY) {
    const results = await exaSearchAndContents(EXA_API_KEY, profile.query, {
      numResults: Math.max(profile.maxResults, 8),
      type: "auto",
      includeDomains,
      maxCharacters: 2500,
      // Prefer fresh caches. We are not strictly enforcing recency here, but avoid very stale.
      maxAgeHours: 30 * 24,
    });

    const filtered = results
      .filter((r) => r.url && !isLowTrust(r.url) && isHighTrust(r.url, includeDomains))
      .map((r) => ({
        title: r.title ?? r.url,
        url: r.url,
        text: cleanSourceText(r.url, (r.text ?? "").toString().trim()),
      }))
      .filter((r) => r.text.length >= 120);

    // If a source is a GitHub blob URL, prefer the raw file content for cleaner excerpts.
    const hydrated = await Promise.all(
      filtered.map(async (s) => {
        const rawUrl = githubBlobToRawUrl(s.url);
        if (!rawUrl) return s;
        const raw = await fetchTextSnippet(rawUrl, 3200);
        if (!raw) return s;
        return { ...s, text: raw };
      }),
    );

    return selectDiverseSources(hydrated.filter((s) => s.text.length >= 120), includeDomains, profile.maxResults);
  }

  // Fallback: Brave web search + strict filtering
  if (!BRAVE_WEB_API_KEY) return [];

  const web = await braveWebSearch(BRAVE_WEB_API_KEY, profile.query, {
    count: Math.min(profile.maxResults, 10),
    country: "us",
    searchLang: "en",
  });

  const urls = (web.web?.results ?? [])
    .filter((r) => r?.url)
    .map((r) => ({
      title: r.title ?? r.url,
      url: r.url,
      snippet: [r.description, ...(r.extra_snippets ?? [])].filter(Boolean).join("\n"),
    }))
    .filter((r) => !isLowTrust(r.url) && isHighTrust(r.url, includeDomains))
    .slice(0, profile.maxResults);

  return urls
    .map((i) => ({
      title: i.title,
      url: i.url,
      text: cleanSourceText(i.url, (i.snippet ?? "").toString().trim()),
    }))
    .filter((s) => s.text.length >= 80);
}

function formatSourcesBlock(sources: Array<{ title: string; url: string; text: string }>): string {
  if (!sources.length) return "(none)";
  return sources
    .map((s, idx) => {
      const excerpt = (s.text ?? "").replace(/\s+/g, " ").trim().slice(0, 900);
      return `[Source ${idx + 1}] ${s.title}\nURL: ${s.url}\nExcerpt: ${excerpt || "(no excerpt)"}`;
    })
    .join("\n\n");
}

function formatOpenclawBlock(excerpts: Array<{ label: string; canonicalUrl?: string; excerpt: string }>): string {
  if (!excerpts.length) return "(none)";
  return excerpts
    .map((e) => {
      const u = e.canonicalUrl ? `URL: ${e.canonicalUrl}` : "URL: (local)";
      const ex = e.excerpt.replace(/\s+$/g, "").slice(0, 2200);
      return `[${e.label}]\n${u}\n${ex}`;
    })
    .join("\n\n");
}

type TargetManifestPromptContext = {
  recordIds: string[];
  nonShippedIds: string[];
  integrationSummaries: string[];
  allowedClaims: string[];
  mustNotImply: string[];
};

function formatPlatformTruthTableBlock(platformTruth: { shipped: string[]; planned: string[] }): string {
  return `Capability truth table for Claw Bureau (consistency rules):
Shipped (you may describe as available):
${platformTruth.shipped.map((x) => `- ${x}`).join("\n") || "- (none)"}

Planned or optional (label as planned, optional, or "can be implemented"):
${platformTruth.planned.map((x) => `- ${x}`).join("\n") || "- (none)"}

Rule: If a feature is not in the Shipped list, do not present it as shipped.`;
}

function formatManifestContextBlock(ctx: TargetManifestPromptContext): string {
  if (!ctx.recordIds.length) {
    return "(none: target is not mapped to a specific integration record)";
  }

  return `Target integration records: ${ctx.recordIds.join(", ")}
Non-shipped records: ${ctx.nonShippedIds.join(", ") || "(none)"}

Integration claim allowlist (you may use only these claims):
${ctx.allowedClaims.map((x) => `- ${x}`).join("\n") || "- (none)"}

Must-not-imply constraints (hard fail if violated):
${ctx.mustNotImply.map((x) => `- ${x}`).join("\n") || "- (none)"}

Integration summaries:
${ctx.integrationSummaries.map((x) => `- ${x}`).join("\n") || "- (none)"}`;
}

function toManifestPromptContext(
  resolved: ReturnType<typeof resolveTargetIntegrationContext>,
): TargetManifestPromptContext {
  return {
    recordIds: resolved.recordIds,
    nonShippedIds: resolved.nonShippedIds,
    integrationSummaries: resolved.records.map(
      (r) => `${r.id} [${r.status}] modes=${r.modes_supported.join("|")} auth=${r.auth_modes.join("|")}`,
    ),
    allowedClaims: resolved.allowedClaims,
    mustNotImply: resolved.mustNotImply,
  };
}

function buildSystemPrompt(platformTruth: { shipped: string[]; planned: string[] }): string {
  return `You write for clawea.com (Claw EA), an enterprise platform for running OpenClaw agents with secure execution.

Hard constraints:
- Output HTML fragments only. No markdown and no code fences.
- Do not include your chain-of-thought or internal reasoning. Output only the final HTML.
- No em dashes (—).
- Avoid buzzwords and generic AI marketing phrases.
- Short paragraphs (2 to 3 sentences).
- Be concrete and operational.
- Do not invent product endpoints or claim native connectors. If unsure: say "via official API" or "via MCP server" or "enterprise buildout".

Terminology glossary (use these exact expansions, do not invent others):
- WPC = Work Policy Contract (signed, hash-addressed policy artifact; served by clawcontrols).
- CST = scoped token (issued by clawscope). Do not expand CST as anything else.
- Gateway receipts = model call receipts emitted by clawproxy (used for verification).
- Proof bundle = a harness artifact bundling receipts and related metadata for audit/verification.
- Trust Pulse = a marketplace-stored artifact for audit/viewing (do not invent extra semantics).

${formatPlatformTruthTableBlock(platformTruth)}

Required structure (use these exact <h2> headings, in this order):
1) <h2>Direct Answer</h2>
2) <h2>Step-by-step runbook</h2>
3) <h2>Threat model</h2>
4) <h2>Policy-as-code example</h2>
5) <h2>What proof do you get?</h2>
6) <h2>Rollback posture</h2>
7) <h2>FAQ</h2>
8) <h2>Sources</h2>

FAQ rules:
- 3 to 6 questions.
- Each question must be an <h3> ending with a question mark.

AEO formatting guidance:
- If you have 3 or more comparable rows, prefer an HTML <table> in the Threat model and Rollback posture sections.
  Example columns: Threat | What happens | Control, and Action | Safe rollback | Evidence.

Sources rules:
- Use ONLY the URLs in the "Allowed citation URLs" list.
- Do not introduce new URLs.
- Format: <ul><li><a href=...>Title</a></li>...</ul>.`;
}

function buildUserPrompt(args: {
  topic: Topic;
  query: string;
  notes: string;
  webSources: Array<{ title: string; url: string; text: string }>;
  openclawExcerpts: Array<{ label: string; canonicalUrl?: string; excerpt: string }>;
  clawbureauContext: Array<{ label: string; excerpt: string }>;
  manifestContext: TargetManifestPromptContext;
  platformTruth: { shipped: string[]; planned: string[] };
  /** Optional override to keep allowed URLs identical when appending candidates to an existing run. */
  allowedUrlsOverride?: string[];
}): { prompt: string; allowedUrls: string[]; openclawUrls: string[] } {
  const { topic, query, notes, webSources, openclawExcerpts, clawbureauContext, manifestContext, platformTruth, allowedUrlsOverride } = args;

  const openclawUrls = openclawExcerpts.map((e) => e.canonicalUrl).filter(Boolean).map(String);
  const webUrls = webSources.map((s) => s.url);

  // Allowed citation URLs include OpenClaw canonical URLs plus curated web sources.
  const computedAllowedUrls = [...new Set([...openclawUrls, ...webUrls])];
  const allowedUrls = allowedUrlsOverride?.length ? [...new Set(allowedUrlsOverride)] : computedAllowedUrls;

  const clawbureauBlock = clawbureauContext.length
    ? clawbureauContext
        .map((c) => `[${c.label}]\n(NOT CITEABLE, internal reference)\n${c.excerpt}`)
        .join("\n\n")
    : "(none)";

  const topicBrief = (topic.prompt ?? "").slice(0, 3000);

  const prompt = `Page title: ${topic.title}
Page slug: /${topic.slug}
Primary query: ${query}
Notes: ${notes}

You must write a high-trust, non-generic page that matches the query and the title.

Hard requirements:
- Mention OpenClaw as the baseline agent runtime at least once.
- Explain why the execution layer must be permissioned (policy-as-code) instead of prompt-only.
- Use Claw Bureau primitives where relevant: Work Policy Contracts (WPC), scoped tokens (CST, from clawscope), gateway receipts (from clawproxy), proof bundles.
- Do not invent acronym expansions. Use the glossary in the system prompt (for example: CST = scoped token).
- If the topic involves Microsoft tools: use Microsoft terminology (Entra ID, Microsoft Graph permissions/scopes, Conditional Access, PIM) and be careful not to over-claim.
- For integration-specific pages, use only manifest-allowed claims and obey must-not-imply constraints.

Sources requirements:
- In <h2>Sources</h2>, include at least 1 OpenClaw URL from the allowed list.
- In <h2>Sources</h2>, include at least 1 vendor or standards URL from the allowed list (for Microsoft pages, that means a learn.microsoft.com URL).

Manifest-driven capability truth table (NOT citeable):
${formatPlatformTruthTableBlock(platformTruth)}

Manifest-driven integration constraints (NOT citeable):
${formatManifestContextBlock(manifestContext)}

Internal Claw Bureau context (NOT citeable, internal reference, may include planned items):
${clawbureauBlock}

Internal page brief (NOT citeable, use only to align intent, do not copy verbatim):
${topicBrief || "(none)"}

OpenClaw official excerpts (ground truth for OpenClaw behavior, citeable):
${formatOpenclawBlock(openclawExcerpts)}

Web sources (high-trust only, citeable):
${formatSourcesBlock(webSources)}

Allowed citation URLs (use ONLY these exact URLs in the Sources section):
${allowedUrls.map((u) => `- ${u}`).join("\n") || "(none)"}

Now write the HTML.`;

  return { prompt, allowedUrls, openclawUrls };
}

const WizardOutputSchema = z.object({
  company: z.object({
    name: z.string().min(2).max(80),
    domain: z.string().min(4).max(120),
  }),
  goal: z.string().min(20).max(160),
  recommended_connectors: z
    .array(
      z.object({
        name: z.string().min(2).max(80),
        integration_mode: z.string().min(3).max(40),
        why: z.string().min(20).max(240),
      }),
    )
    .min(3)
    .max(8),
  wpc_skeleton: z.object({
    egress_allow: z.array(z.string().min(3).max(160)).min(1).max(20),
    approval_gates: z.array(z.string().min(8).max(160)).min(1).max(12),
    notes: z.array(z.string().min(10).max(200)).max(8).optional(),
  }),
  proof_you_get: z.array(z.string().min(10).max(200)).min(3).max(8),
  capability_labels: z
    .array(
      z.object({
        item: z.string().min(6).max(120),
        status: z.enum(["shipped", "planned", "optional", "implementable"]),
        note: z.string().min(10).max(200).optional(),
      }),
    )
    .min(3)
    .max(12),
  assumptions: z.array(z.string().min(10).max(200)).max(10).optional(),
  citations: z
    .array(
      z.object({
        title: z.string().min(2).max(120),
        url: z.string().url(),
      }),
    )
    .min(2)
    .max(10),
});

type WizardOutput = z.infer<typeof WizardOutputSchema>;

function buildWizardSystemPrompt(platformTruth: { shipped: string[]; planned: string[] }): string {
  return `You are producing output for a clawea.com enterprise intake wizard.

Hard constraints:
- Output a single JSON object only. No markdown and no code fences.
- Do not include your chain-of-thought or internal reasoning. Output only JSON.
- No em dashes (—).
- Avoid buzzwords and generic AI marketing phrases.
- Be concrete and operational.
- Do not invent product endpoints or claim native connectors. If unsure: say "via official API" or "via MCP server" or "enterprise buildout".

Terminology glossary (use these exact expansions, do not invent others):
- WPC = Work Policy Contract (signed, hash-addressed policy artifact; served by clawcontrols).
- CST = scoped token (issued by clawscope). Do not expand CST as anything else.
- Gateway receipts = model call receipts emitted by clawproxy (used for verification).
- Proof bundle = a harness artifact bundling receipts and related metadata for audit/verification.
- Trust Pulse = a marketplace-stored artifact for audit/viewing (do not invent extra semantics).

${formatPlatformTruthTableBlock(platformTruth)}

JSON requirements:
- Output must be valid JSON (not JSON5).
- Must match the required keys and types.
- citations[].url must be from the "Allowed citation URLs" list in the user prompt.
- Include at least 1 OpenClaw citation and at least 1 vendor citation.`;
}

function buildWizardPrompt(args: {
  targetTitle: string;
  targetSlug: string;
  company: { name: string; domain: string };
  query: string;
  notes: string;
  webSources: Array<{ title: string; url: string; text: string }>;
  openclawExcerpts: Array<{ label: string; canonicalUrl?: string; excerpt: string }>;
  clawbureauContext: Array<{ label: string; excerpt: string }>;
  manifestContext: TargetManifestPromptContext;
}): { prompt: string; allowedUrls: string[]; openclawUrls: string[] } {
  const { targetTitle, targetSlug, company, query, notes, webSources, openclawExcerpts, clawbureauContext, manifestContext } = args;

  const openclawUrls = openclawExcerpts.map((e) => e.canonicalUrl).filter(Boolean).map(String);
  const webUrls = webSources.map((s) => s.url);
  const allowedUrls = [...new Set([...openclawUrls, ...webUrls])];

  const clawbureauBlock = clawbureauContext.length
    ? clawbureauContext
        .map((c) => `[${c.label}]\n(NOT CITEABLE, internal reference)\n${c.excerpt}`)
        .join("\n\n")
    : "(none)";

  const prompt = `Wizard title: ${targetTitle}
Wizard slug: /${targetSlug}

Company:
- Name: ${company.name}
- Domain: ${company.domain}

Primary query: ${query}
Notes: ${notes}

Task:
- Produce a single JSON object that matches this shape:
{
  "company": { "name": string, "domain": string },
  "goal": string,
  "recommended_connectors": [{ "name": string, "integration_mode": string, "why": string }],
  "wpc_skeleton": { "egress_allow": string[], "approval_gates": string[], "notes"?: string[] },
  "proof_you_get": string[],
  "capability_labels": [{ "item": string, "status": "shipped"|"planned"|"optional"|"implementable", "note"?: string }],
  "assumptions"?: string[],
  "citations": [{ "title": string, "url": string }]
}

Rules:
- Do not invent product endpoints or claim native connectors.
- Use the capability truth table in the system prompt. If you mention planned features, label them planned/optional/implementable in capability_labels.
- Use the terminology glossary in the system prompt. Do not invent acronym expansions.
- Use only integration claims from the manifest context below.
- citations[].url must use ONLY the allowed URLs list below.
- Include at least 1 OpenClaw URL in citations.
- Include at least 1 vendor URL for the company domain in citations.

Manifest-driven integration constraints (NOT citeable):
${formatManifestContextBlock(manifestContext)}

OpenClaw official excerpts (citeable):
${formatOpenclawBlock(openclawExcerpts)}

Web sources (citeable):
${formatSourcesBlock(webSources)}

Internal Claw Bureau context (NOT citeable):
${clawbureauBlock}

Allowed citation URLs (use ONLY these exact URLs in citations):
${allowedUrls.map((u) => `- ${u}`).join("\n") || "(none)"}

Return JSON only.`;

  return { prompt, allowedUrls, openclawUrls };
}

async function runPool<T>(
  items: T[],
  concurrency: number,
  fn: (item: T, idx: number) => Promise<void>,
): Promise<void> {
  const queue = [...items];
  const workers = new Array(concurrency).fill(null).map(async (_, workerIdx) => {
    while (queue.length) {
      const item = queue.shift();
      if (!item) break;
      const idx = items.length - queue.length - 1;
      try {
        await fn(item, idx);
      } catch (e: any) {
        console.error(`[worker ${workerIdx}] FAIL: ${e?.message ?? e}`);
      }
    }
  });
  await Promise.all(workers);
}

async function main(): Promise<void> {
  if (APPEND) {
    if (!fs.existsSync(OUT_ROOT)) {
      console.error(`WRITE_OFF_APPEND=1 but output folder does not exist: ${OUT_ROOT}`);
      process.exit(1);
    }
  } else {
    ensureDir(OUT_ROOT);
  }

  const integrationManifestPath = process.env.WRITE_OFF_INTEGRATION_MANIFEST;
  const integrationManifest = loadIntegrationManifest(integrationManifestPath);
  const platformTruth = buildPlatformTruthTable(integrationManifest);

  const all = generateAllTopics();
  const topicBySlug = new Map(all.map((t) => [t.slug, t] as const));

  const targets = selectTargets(all, topicBySlug);
  if (targets.length === 0) {
    console.error("No targets selected. Provide WRITE_OFF_TARGET_SLUGS, or set WRITE_OFF_TOP_N.");
    process.exit(1);
  }

  const articleCount = targets.filter((t) => t.kind === "article").length;
  const wizardCount = targets.filter((t) => t.kind === "wizard").length;
  const targetSummary = `${articleCount} HTML page${articleCount === 1 ? "" : "s"}${wizardCount ? ` + ${wizardCount} strict JSON wizard output${wizardCount === 1 ? "" : "s"}` : ""}`;

  const privateMap: any = (() => {
    if (APPEND && fs.existsSync(PRIVATE_MAP_PATH)) {
      try {
        return JSON.parse(fs.readFileSync(PRIVATE_MAP_PATH, "utf-8"));
      } catch (e: any) {
        console.error(`Failed to parse existing private map at ${PRIVATE_MAP_PATH}: ${e?.message ?? e}`);
      }
    }

    return {
      runId: RUN_ID,
      createdAt: new Date().toISOString(),
      articles: {},
    };
  })();

  privateMap.runId ??= RUN_ID;
  privateMap.createdAt ??= new Date().toISOString();
  privateMap.articles ??= {};

  if (!APPEND) {
    // Write top-level readme without model IDs.
    fs.writeFileSync(
      path.join(OUT_ROOT, "README.md"),
      `# Model write-off (anonymized)\n\nThis folder contains ${targets.length} targets (${targetSummary}), each generated ${MODELS.length} times by different models.\n\nImportant:\n- Candidate outputs are anonymized. There are no model names in this folder.\n- Reviewers should score writing quality, specificity, and policy/proof correctness.\n\nSee REVIEW_CHECKLIST.md for a suggested rubric.\n`,
    );
  }

  if (!APPEND) {
    // Run settings (safe to share; contains no model IDs)
    fs.writeFileSync(
      path.join(OUT_ROOT, "RUN_SETTINGS.json"),
      JSON.stringify(
        {
          runId: RUN_ID,
          createdAt: new Date().toISOString(),
          modelCount: MODELS.length,
          targetCount: targets.length,
          targetSummary,
          targets: targets.map((t) =>
            t.kind === "wizard"
              ? { kind: t.kind, slug: t.slug, title: t.title, company: t.company }
              : { kind: t.kind, slug: t.slug },
          ),
          temperature: Number(process.env.WRITE_OFF_TEMPERATURE ?? "0.35"),
          maxTokens: Number(process.env.WRITE_OFF_MAX_TOKENS ?? "9000"),
          retrieval: {
            prefer: EXA_API_KEY ? "exaSearchAndContents" : "braveWebSearch",
            lowTrustBlocked: [...LOW_TRUST_DOMAIN_SUBSTRINGS],
            githubOrgAllowlist: [...ALLOWED_GITHUB_ORGS],
            highTrustDomains: [...HIGH_TRUST_DOMAINS],
          },
          integrationManifest: {
            path: integrationManifestPath ?? "(default)",
            schema_name: integrationManifest.schema_name,
            schema_version: integrationManifest.schema_version,
            manifest_id: integrationManifest.manifest.id,
            generated_at: integrationManifest.manifest.generated_at,
            integrations: integrationManifest.integrations.length,
          },
        },
        null,
        2,
      ),
    );
  }

  if (!APPEND) {
    fs.writeFileSync(
      path.join(OUT_ROOT, "REVIEW_CHECKLIST.md"),
      `# External review checklist (blind)\n\nEach target folder contains ${MODELS.length} anonymized candidates:\n- candidates/candidate-01.(html|json) ... candidate-${String(MODELS.length).padStart(2, "0")}.(html|json)\n- each has a machine report: candidates/candidate-XX.report.json\n\nFor HTML page targets (most folders):\nScore each candidate 1–5 on each dimension:\n\n1) Directness\n- Does <h2>Direct Answer</h2> answer the query in 2–3 sentences?\n\n2) Specificity\n- Concrete steps, concrete controls, concrete failure modes. No vague claims.\n\n3) OpenClaw alignment\n- Mentions OpenClaw as the baseline runtime.\n- Uses realistic concepts: tool policy, sandboxing, allowlists, access control, security audit.\n\n4) Claw EA alignment\n- Frames the wedge correctly: permissioned execution, policy-as-code, approvals, budgets, proof.\n- Avoids inventing product endpoints or claiming native connectors.\n\n5) Enterprise correctness\n- For Microsoft-heavy pages: uses correct terminology and avoids made-up features.\n- Uses safe language: via official API, via MCP server, or enterprise buildout.\n\n6) Security quality\n- Threat model is real: prompt injection, tool abuse, exfiltration, privilege escalation, replay/TOCTOU, approval spoofing.\n- Controls match risks (egress allowlist, approvals, budgets, least privilege).\n\n7) Policy-as-code quality\n- Policy snippet is plausible, readable, and enforceable.\n- Avoids hand-wavy pseudo-policy.\n\n8) Proof/evidence quality\n- Explains what artifacts exist (receipts, audit logs, hashes, approvals) and what is verifiable.\n\n9) Structure + style compliance\n- Uses the required <h2> headings in order.\n- Short paragraphs. No em dashes.\n\nFor wizard JSON targets (folder slugs that start with wizard/):\nScore each candidate 1–5 on:\n\nA) JSON validity + schema compliance\n- candidate-XX.json parses and has the expected keys and types.\n\nB) Connector recommendations\n- Specific and realistic. Correctly labels integration mode (official API vs MCP server vs enterprise buildout).\n\nC) WPC skeleton quality\n- Egress allowlist and approval gates are plausible, safe, and not over-broad.\n\nD) Shipped vs planned correctness\n- capability_labels uses shipped/planned/optional/implementable correctly. No over-claims.\n\nE) Proof/evidence quality\n- Correct explanation of receipts, proof bundles, WPC, CST.\n\nF) Citation compliance\n- Uses only allowed URLs. Includes at least one OpenClaw URL and one vendor URL.\n\nNotes to record:\n- Any hallucinated vendor feature\n- Any unsafe advice\n- Any missing required section or missing required JSON key\n- Any generic filler or AI-blog tone\n\nTip: do not guess model families from style. Treat it as a writing contest.\n`,
    );
  }

  for (const target of targets) {
    const slug = target.slug;
    const kind = target.kind;

    const topic = kind === "article" ? topicBySlug.get(slug) : undefined;
    if (kind === "article" && !topic) {
      throw new Error(`Unknown slug in targets list: ${slug}`);
    }

    const title = kind === "wizard" ? target.title : topic!.title;

    console.log(`\n=== Target: ${slug} (${kind})`);

    const resolvedManifestContext = resolveTargetIntegrationContext(integrationManifest, slug);
    if (resolvedManifestContext.missingRequiredIds.length > 0) {
      throw new Error(
        `Manifest fail-closed: missing required integration records for /${slug}: ${resolvedManifestContext.missingRequiredIds.join(", ")}`,
      );
    }
    const manifestPromptContext = toManifestPromptContext(resolvedManifestContext);

    const systemPrompt =
      kind === "wizard"
        ? buildWizardSystemPrompt(platformTruth)
        : buildSystemPrompt(platformTruth);

    const targetDir = path.join(OUT_ROOT, toSafeFolderName(slug));
    const candidatesDir = path.join(targetDir, "candidates");
    ensureDir(candidatesDir);

    const sourcesPath = path.join(targetDir, "sources.json");
    const specPath = path.join(targetDir, "spec.json");
    const existingSpec = APPEND && fs.existsSync(specPath)
      ? JSON.parse(fs.readFileSync(specPath, "utf-8"))
      : null;

    // Retrieval once per target (same sources shared across all candidate models).
    const webSources: Array<{ title: string; url: string; text: string }> =
      APPEND && fs.existsSync(sourcesPath)
        ? JSON.parse(fs.readFileSync(sourcesPath, "utf-8"))
        : await fetchWebSources(target.retrieval);

    if (!(APPEND && fs.existsSync(sourcesPath))) {
      await sleep(1200);
    }

    const openclawExcerpts: Array<{ label: string; canonicalUrl?: string; excerpt: string }> = [];

    // Core OpenClaw security/tool-policy context.
    const sec = officialDoc("gateway/security/index.md", "OpenClaw Gateway Security (audit + footguns)", 2200);
    if (sec) openclawExcerpts.push(sec);

    const sandboxVs = officialDoc(
      "gateway/sandbox-vs-tool-policy-vs-elevated.md",
      "OpenClaw: Sandbox vs Tool Policy vs Elevated",
      2200,
    );
    if (sandboxVs) openclawExcerpts.push(sandboxVs);

    const toolSec = officialDoc(
      "gateway/sandboxing.md",
      "OpenClaw: Sandboxing",
      2200,
    );
    if (toolSec) openclawExcerpts.push(toolSec);

    // If we are evaluating a chat control plane workflow, include channel excerpt + mention gating code.
    if (slug.includes("microsoft-teams")) {
      for (const ex of officialChannelSources("microsoft-teams")) {
        openclawExcerpts.push({
          label: ex.label,
          canonicalUrl: ex.canonicalUrl,
          excerpt: ex.excerpt,
        });
      }
    }

    // Add OpenClaw mention gating defaults for Discord as a general pattern (helps threat model sections).
    const mentionDefaults = officialRepoSnippet(
      "src/discord/monitor/allow-list.ts",
      /resolveDiscordShouldRequireMention/,
      "OpenClaw source: mention gating defaults",
      { before: 6, after: 40, maxChars: 1800 },
    );
    if (mentionDefaults) {
      openclawExcerpts.push({
        label: mentionDefaults.label,
        canonicalUrl: mentionDefaults.canonicalUrl,
        excerpt: mentionDefaults.excerpt,
      });
    }

    const clawbureauContext: Array<{ label: string; excerpt: string }> = [];
    const ctxFiles = [
      ["Claw Bureau ↔ OpenClaw integration plan", "docs/integration/OPENCLAW_INTEGRATION.md"],
      ["clawea.com PRD (planned scope)", "docs/prds/clawea.md"],
      ["clawproxy PRD (receipts + policy enforcement)", "docs/prds/clawproxy.md"],
      ["clawcontrols PRD (WPC registry)", "docs/prds/clawcontrols.md"],
      ["clawscope PRD (scoped tokens)", "docs/prds/clawscope.md"],
      ["clawverify PRD (verification)", "docs/prds/clawverify.md"],
    ] as const;

    for (const [label, rel] of ctxFiles) {
      const ex = localDocBlock(label, rel, 1800);
      if (ex) clawbureauContext.push(ex);
    }

    const built =
      target.kind === "wizard"
        ? buildWizardPrompt({
            targetTitle: title,
            targetSlug: slug,
            company: target.company,
            query: target.retrieval.query,
            notes: target.notes,
            webSources,
            openclawExcerpts,
            clawbureauContext,
            manifestContext: manifestPromptContext,
          })
        : buildUserPrompt({
            topic: topic!,
            query: target.retrieval.query,
            notes: target.notes,
            webSources,
            openclawExcerpts,
            clawbureauContext,
            manifestContext: manifestPromptContext,
            platformTruth,
            allowedUrlsOverride: Array.isArray(existingSpec?.allowedUrls) ? existingSpec.allowedUrls : undefined,
          });

    // Persist retrieval context for fairness. In append mode, preserve the original spec/sources.
    if (!APPEND || !fs.existsSync(specPath)) {
      fs.writeFileSync(
        specPath,
        JSON.stringify(
          {
            kind,
            slug,
            title,
            company: target.kind === "wizard" ? target.company : undefined,
            query: target.retrieval.query,
            notes: target.notes,
            retrieval: {
              exaSearchAndContents: EXA_API_KEY
                ? {
                    numResults: target.retrieval.maxResults,
                    includeDomains: target.retrieval.includeDomains,
                    maxCharacters: 2500,
                    maxAgeHours: 720,
                  }
                : null,
              braveFallback: EXA_API_KEY
                ? null
                : { count: Math.min(target.retrieval.maxResults, 8), country: "us", searchLang: "en" },
            },
            webSources: webSources.map((s) => ({ title: s.title, url: s.url })),
            allowedUrls: built.allowedUrls,
            manifestContext: {
              requiredIds: resolvedManifestContext.requiredIds,
              recordIds: resolvedManifestContext.recordIds,
              nonShippedIds: resolvedManifestContext.nonShippedIds,
              allowedClaims: resolvedManifestContext.allowedClaims,
              mustNotImply: resolvedManifestContext.mustNotImply,
              statusByIntegration: Object.fromEntries(
                resolvedManifestContext.records.map((r) => [r.id, r.status] as const),
              ),
            },
          },
          null,
          2,
        ),
      );
    }

    if (!APPEND || !fs.existsSync(sourcesPath)) {
      fs.writeFileSync(sourcesPath, JSON.stringify(webSources, null, 2));
    }

    const existingCandidates: Record<string, string> = privateMap.articles?.[slug]?.candidates ?? {};
    const usedModels = new Set(Object.values(existingCandidates));

    // Shuffle per-target to avoid cross-target correlation (when starting a fresh run).
    // In append mode, preserve existing candidates and append sequential IDs.
    const modelsToRun = APPEND
      ? MODELS.filter((m) => !usedModels.has(m))
      : shuffle(MODELS);

    const startN = APPEND ? maxCandidateNumberFromDir(candidatesDir) + 1 : 1;

    // Run candidates with a small concurrency limit.
    // Temperature guidance:
    // - 0.25–0.35 tends to be crisp and less fluffy.
    // - 0.45–0.6 tends to be more expressive but higher risk of generic filler.
    // - 0.8–1.0 can be more natural for some modern models but increases hallucination risk.
    const temperature = Number(process.env.WRITE_OFF_TEMPERATURE ?? "0.35");
    const maxTokens = Number(process.env.WRITE_OFF_MAX_TOKENS ?? "9000");

    const candidateJobs = modelsToRun.map((m, i) => ({
      modelId: m,
      candidate: candidateId(startN + i),
    }));

    const candidateMap: Record<string, string> = APPEND ? { ...existingCandidates } : {};
    for (const j of candidateJobs) {
      candidateMap[j.candidate] = j.modelId;
    }
    privateMap.articles[slug] = { candidates: candidateMap };

    if (APPEND && candidateJobs.length === 0) {
      console.log("  (append) no new models to run");
      continue;
    }

    await runPool(candidateJobs, 2, async (job) => {
      const started = Date.now();
      const resp = await openrouterChat(job.modelId, systemPrompt, built.prompt, {
        temperature,
        maxTokens,
      });

      const truncated = resp.finishReason === "length" || resp.finishReason === "max_tokens";

      if (kind === "wizard") {
        const jsonText = extractJsonObjectText(resp.text);

        let parsed: any = null;
        let parseOk = false;
        let parseError: string | null = null;
        try {
          parsed = JSON.parse(jsonText);
          parseOk = true;
        } catch (e: any) {
          parseError = e?.message ?? String(e);
        }

        const allowedSet = new Set(built.allowedUrls);

        let sanitized = false;
        let removedCitationViolations: string[] = [];
        let citationUrlsPre: string[] = [];
        let citationUrls: string[] = [];

        const vendorDomain = target.kind === "wizard" ? target.company.domain : "";
        let hasOpenclawCitation = false;
        let hasExternalCitation = false;
        let hasVendorCitation = false;

        if (parseOk) {
          const citationsRaw = Array.isArray(parsed?.citations) ? parsed.citations : [];
          citationUrlsPre = citationsRaw
            .map((x: any) => x?.url)
            .filter((u: any) => typeof u === "string") as string[];

          removedCitationViolations = citationUrlsPre.filter((u) => !allowedSet.has(u));

          if (SANITIZE_SOURCES && removedCitationViolations.length) {
            sanitized = true;
            parsed.citations = citationsRaw.filter((x: any) => typeof x?.url === "string" && allowedSet.has(x.url));
          }

          const citationsAfter = Array.isArray(parsed?.citations) ? parsed.citations : [];
          citationUrls = citationsAfter
            .map((x: any) => x?.url)
            .filter((u: any) => typeof u === "string") as string[];

          hasOpenclawCitation = citationUrls.some((u) => openclawUrl(u));
          hasExternalCitation = citationUrls.some((u) => !openclawUrl(u));
          hasVendorCitation = vendorDomain
            ? citationUrls.some((u) => hostMatchesDomain(hostFromUrl(u), vendorDomain))
            : false;
        }

        const violationsPost = citationUrls.filter((u) => !allowedSet.has(u));

        const requiresOpenclaw = built.openclawUrls.length > 0;
        const requiresVendor = Boolean(vendorDomain);

        const sanitizerFailedReason =
          requiresOpenclaw && !hasOpenclawCitation
            ? "missing_openclaw_citation_after_sanitize"
            : requiresVendor && !hasVendorCitation
              ? "missing_vendor_citation_after_sanitize"
              : violationsPost.length > 0
                ? "citation_violations_remain_after_sanitize"
                : null;

        const claimSafety = evaluateClaimSafety({
          text: parseOk ? JSON.stringify(parsed) : resp.text,
          context: resolvedManifestContext,
          allowedCitationUrls: built.allowedUrls,
        });

        const capabilityLabelMismatches: string[] = [];
        if (parseOk && Array.isArray((parsed as any)?.capability_labels)) {
          const plannedLower = platformTruth.planned.map((x) => x.toLowerCase());
          const integrationNeedPlan = resolvedManifestContext.records
            .filter((r) => r.status !== "shipped")
            .map((r) => ({ id: r.id.toLowerCase(), name: r.name.toLowerCase() }));

          for (const row of (parsed as any).capability_labels as Array<{ item?: string; status?: string }>) {
            const item = String(row?.item ?? "").toLowerCase().trim();
            const status = String(row?.status ?? "").toLowerCase().trim();
            if (!item || status !== "shipped") continue;

            if (plannedLower.some((p) => item.includes(p) || p.includes(item))) {
              capabilityLabelMismatches.push(`capability_label_planned_marked_shipped:${row.item ?? item}`);
            }

            for (const rec of integrationNeedPlan) {
              if (item.includes(rec.id) || item.includes(rec.name)) {
                capabilityLabelMismatches.push(`capability_label_nonshipped_integration_marked_shipped:${row.item ?? item}`);
              }
            }
          }
        }

        if (capabilityLabelMismatches.length > 0) {
          claimSafety.shipped_planned_mismatch.push(...capabilityLabelMismatches);
          claimSafety.claim_state_violations.push(...capabilityLabelMismatches);
        }

        claimSafety.claim_state_violations = [...new Set(claimSafety.claim_state_violations)];
        claimSafety.endpoint_invention_violations = [...new Set(claimSafety.endpoint_invention_violations)];
        claimSafety.shipped_planned_mismatch = [...new Set(claimSafety.shipped_planned_mismatch)];

        const schema = parseOk ? WizardOutputSchema.safeParse(parsed) : null;
        const schemaOk = schema?.success === true;
        const schemaIssues =
          schema && !schema.success
            ? schema.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`)
            : [];

        const companyDomain = (parsed as any)?.company?.domain;
        const companyDomainOk =
          typeof companyDomain === "string" && vendorDomain ? companyDomain.includes(vendorDomain) : null;

        if (parseOk) {
          const outJson = path.join(candidatesDir, `${job.candidate}.json`);
          fs.writeFileSync(outJson, JSON.stringify(parsed, null, 2));
        } else {
          const outRaw = path.join(candidatesDir, `${job.candidate}.raw.txt`);
          fs.writeFileSync(outRaw, resp.text);
        }

        const outReport = path.join(candidatesDir, `${job.candidate}.report.json`);
        const ok =
          parseOk &&
          schemaOk &&
          !sanitizerFailedReason &&
          claimSafety.claim_state_violations.length === 0 &&
          claimSafety.endpoint_invention_violations.length === 0 &&
          claimSafety.shipped_planned_mismatch.length === 0;

        fs.writeFileSync(
          outReport,
          JSON.stringify(
            {
              candidate: job.candidate,
              kind,
              generatedAt: new Date().toISOString(),
              ms: Date.now() - started,
              chars: resp.text.length,
              finishReason: resp.finishReason ?? null,
              truncated,
              sanitized,
              removed_citation_violations: removedCitationViolations,
              sanitizer_failed_reason: sanitizerFailedReason,
              json: {
                parseOk,
                parseError,
                schemaOk,
                schemaIssues,
                companyDomainOk,
              },
              citations: {
                urlCount: citationUrls.length,
                hasOpenclawCitation,
                hasExternalCitation,
                vendorDomain,
                hasVendorCitation,
                violations_pre: removedCitationViolations,
                violations: violationsPost,
              },
              claim_state_violations: claimSafety.claim_state_violations,
              endpoint_invention_violations: claimSafety.endpoint_invention_violations,
              shipped_planned_mismatch: claimSafety.shipped_planned_mismatch,
              manifest_context: {
                requiredIds: resolvedManifestContext.requiredIds,
                recordIds: resolvedManifestContext.recordIds,
                nonShippedIds: resolvedManifestContext.nonShippedIds,
              },
            },
            null,
            2,
          ),
        );

        const issueCount =
          (parseOk ? 0 : 1) +
          (schemaOk ? 0 : 1) +
          violationsPost.length +
          (sanitizerFailedReason ? 1 : 0) +
          claimSafety.claim_state_violations.length +
          claimSafety.endpoint_invention_violations.length +
          claimSafety.shipped_planned_mismatch.length;

        console.log(`  - ${job.candidate}: ok=${ok} (issues=${issueCount})`);

        // Be gentle with upstream rate limits.
        await sleep(900);
        return;
      }

      const rawHtml = cleanHtml(resp.text);

      const allowedSet = new Set(built.allowedUrls);

      const hrefsPre = extractHrefUrls(rawHtml);
      const hrefViolationsPre = hrefsPre.filter((u) => !allowedSet.has(u));

      let html = rawHtml;
      let sanitized = false;
      let removedHrefViolations: string[] = [];

      if (SANITIZE_SOURCES) {
        const san = sanitizeHtmlAnchors(html, allowedSet);
        html = san.html;
        removedHrefViolations = san.removed;
        sanitized = removedHrefViolations.length > 0;
      }

      const hrefs = extractHrefUrls(html);
      const hrefViolations = hrefs.filter((u) => !allowedSet.has(u));

      const hasOpenclawCitation = hasOpenclawLink(hrefs);
      const hasExternalCitation = hasExternalLink(hrefs);
      const needsMicrosoft = microsoftSlug(slug);
      const hasMicrosoftCitation = hrefs.some((u) => microsoftDocUrl(u));

      const requiresOpenclaw = built.openclawUrls.length > 0;
      const requiresExternal = built.allowedUrls.some((u) => !openclawUrl(u));

      const sanitizerFailedReason =
        requiresOpenclaw && !hasOpenclawCitation
          ? "missing_openclaw_citation_after_sanitize"
          : requiresExternal && !hasExternalCitation
            ? "missing_external_citation_after_sanitize"
            : hrefViolations.length > 0
              ? "href_violations_remain_after_sanitize"
              : null;

      const lint = lintText(html);

      const claimSafety = evaluateClaimSafety({
        text: html,
        context: resolvedManifestContext,
        allowedCitationUrls: built.allowedUrls,
      });

      const requiredH2 = [
        "Direct Answer",
        "Step-by-step runbook",
        "Threat model",
        "Policy-as-code example",
        "What proof do you get?",
        "Rollback posture",
        "FAQ",
        "Sources",
      ];

      const missingH2 = requiredH2.filter((h) => !hasH2(html, h));
      const orderOk = (() => {
        const idxs = requiredH2.map((h) => h2Index(html, h));
        if (idxs.some((x) => x < 0)) return false;
        for (let i = 1; i < idxs.length; i++) {
          if (idxs[i] <= idxs[i - 1]) return false;
        }
        return true;
      })();

      const faqQCount = (html.match(/<h3\b[^>]*>[^<]*\?<\/h3>/gi) ?? []).length;
      const faqCountOk = faqQCount >= 3 && faqQCount <= 6;

      const outHtml = path.join(candidatesDir, `${job.candidate}.html`);
      fs.writeFileSync(outHtml, html);

      const outReport = path.join(candidatesDir, `${job.candidate}.report.json`);

      const ok =
        !truncated &&
        lint.ok &&
        missingH2.length === 0 &&
        orderOk &&
        faqCountOk &&
        hrefViolations.length === 0 &&
        !sanitizerFailedReason &&
        claimSafety.claim_state_violations.length === 0 &&
        claimSafety.endpoint_invention_violations.length === 0 &&
        claimSafety.shipped_planned_mismatch.length === 0;

      fs.writeFileSync(
        outReport,
        JSON.stringify(
          {
            candidate: job.candidate,
            kind,
            generatedAt: new Date().toISOString(),
            ms: Date.now() - started,
            chars: html.length,
            finishReason: resp.finishReason ?? null,
            truncated,
            sanitized,
            removed_href_violations: removedHrefViolations,
            sanitizer_failed_reason: sanitizerFailedReason,
            lint,
            structure: {
              missingH2,
              orderOk,
              faqQCount,
              faqCountOk,
            },
            citations: {
              hrefCount: hrefs.length,
              hrefCountPre: hrefsPre.length,
              hasOpenclawCitation,
              hasExternalCitation,
              needsMicrosoft,
              hasMicrosoftCitation,
              violations_pre: hrefViolationsPre,
              violations: hrefViolations,
            },
            claim_state_violations: claimSafety.claim_state_violations,
            endpoint_invention_violations: claimSafety.endpoint_invention_violations,
            shipped_planned_mismatch: claimSafety.shipped_planned_mismatch,
            manifest_context: {
              requiredIds: resolvedManifestContext.requiredIds,
              recordIds: resolvedManifestContext.recordIds,
              nonShippedIds: resolvedManifestContext.nonShippedIds,
            },
          },
          null,
          2,
        ),
      );

      const issueCount =
        lint.issues.length +
        missingH2.length +
        (orderOk ? 0 : 1) +
        (faqCountOk ? 0 : 1) +
        hrefViolations.length +
        (sanitizerFailedReason ? 1 : 0) +
        claimSafety.claim_state_violations.length +
        claimSafety.endpoint_invention_violations.length +
        claimSafety.shipped_planned_mismatch.length;

      // Do not print model names.
      console.log(
        `  - ${job.candidate}: ok=${ok} (chars=${html.length}, issues=${issueCount}, sanitized=${sanitized})`,
      );

      // Be gentle with upstream rate limits.
      await sleep(900);
    });
  }

  // Write private mapping.
  ensureDir(path.dirname(PRIVATE_MAP_PATH));
  fs.writeFileSync(PRIVATE_MAP_PATH, JSON.stringify(privateMap, null, 2));

  console.log(`\nDone.`);
  console.log(`Outputs: ${OUT_ROOT}`);
  console.log(`Private mapping (do not share with reviewers): ${PRIVATE_MAP_PATH}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
