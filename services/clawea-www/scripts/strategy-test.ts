#!/usr/bin/env node
/**
 * Strategy test harness.
 *
 * Generates a small set of pages using multiple strategies and prints quality signals.
 * This runs BEFORE we commit to Batch API for bulk generation.
 */

import * as fs from "fs";
import * as path from "path";

import { exaContents, exaContext, exaSearchAndContents } from "./exa";
import { consume, loadUsageState, usageSummary } from "./budget";
import {
  braveChatCompletions,
  braveGetSummarizerKey,
  braveParsePageAge,
  braveSummarizerFollowups,
  braveSummarizerSearch,
  braveWebSearch,
} from "./brave";
import {
  deepwikiDoc,
  officialChannelSources,
  officialProviderDoc,
  hasDeepWiki,
  hasOpenClawRef,
} from "./openclaw-docs";
import { buildJsonDraftPrompt } from "./prompts";
import { generateDraftWithGemini, type GeminiToolStrategy } from "./gemini";
import { renderDraftToHtml } from "./render";
import { lintMetaDescription, lintText } from "./quality";

const OUT_DIR = path.resolve(import.meta.dirname ?? ".", "../test-output");

// Optional CLI filters (to reduce cost during iteration)
//   --case integrations/slack
//   --strategy exa_then_gemini
const ARGS = process.argv.slice(2);
function getArg(name: string): string | undefined {
  const idx = ARGS.indexOf(name);
  return idx >= 0 && idx + 1 < ARGS.length ? ARGS[idx + 1] : undefined;
}
const ONLY_CASE = getArg("--case");
const ONLY_STRATEGY = getArg("--strategy");

const PRODUCT_FACTS = [
  "Claw EA deploys managed OpenClaw AI agent instances for enterprises.",
  "Each agent runs in its own isolated Cloudflare Sandbox container.",
  "Trust layer: model calls can be routed through clawproxy for signed gateway receipts (Proof of Harness).",
  "Work Policy Contracts (WPCs) define egress rules, DLP redaction, model restrictions, and approval gates.",
  "Fleet management: deploy, monitor, budget, and control many agents.",
  "Model routing: primary and fallback models, task-based routing rules.",
  "BYOK: bring your own model provider keys.",
];

type TestCase = {
  slug: string;
  title: string;
  intent: "deploy" | "integration" | "use-case" | "industry" | "model" | "compliance" | "comparison" | "glossary" | "guide";
  primaryQuery: string;
  audience: string;
  channelSlug?: string;
  providerSlug?: string;
  exaQuery?: string;
  exaContextQuery?: string;
  mustIncludeTemplates?: boolean;
};

const TEST_CASES: TestCase[] = [
  {
    slug: "integrations/slack",
    title: "Slack AI Agent Integration | Deploy in Minutes | Claw EA",
    intent: "integration",
    primaryQuery: "Slack AI agent for enterprise",
    audience: "IT admins and platform engineers deploying agents to Slack",
    channelSlug: "slack",
    exaQuery: "Slack bot enterprise security best practices 2025",
    exaContextQuery:
      "openclaw slack integration SLACK_APP_TOKEN SLACK_BOT_TOKEN socket mode slack bolt app_mention channels:history",
    mustIncludeTemplates: true,
  },
  {
    slug: "integrations/discord",
    title: "Discord AI Agent Integration | Deploy in Minutes | Claw EA",
    intent: "integration",
    primaryQuery: "Discord AI agent for enterprise",
    audience: "IT admins and platform engineers deploying agents to Discord",
    channelSlug: "discord",
    exaQuery: "Discord bot security enterprise best practices 2025",
    exaContextQuery:
      "openclaw discord integration DISCORD_BOT_TOKEN channels.discord token requireMention Message Content Intent Server Members Intent",
    mustIncludeTemplates: true,
  },
  {
    slug: "deploy/slack/financial-services",
    title: "Deploy AI Agent on Slack for Financial Services | Claw EA",
    intent: "deploy",
    primaryQuery: "deploy AI agent on Slack for financial services",
    audience: "compliance teams and engineering teams in regulated finance",
    channelSlug: "slack",
    exaQuery: "financial services AI governance audit trail requirements 2025",
    mustIncludeTemplates: true,
  },
  {
    slug: "models/gemini-3-pro",
    title: "Gemini 3 Pro Enterprise Deployment | Managed Google AI | Claw EA",
    intent: "model",
    primaryQuery: "Gemini 3 Pro enterprise deployment",
    audience: "AI platform teams evaluating Gemini for enterprise workloads",
    providerSlug: "google",
    exaQuery: "Gemini 3 Pro enterprise pricing security features 2026",
  },
  {
    slug: "guides/configure-work-policy-contract",
    title: "How to Configure a Work Policy Contract | Step-by-Step Guide | Claw EA",
    intent: "guide",
    primaryQuery: "how to enforce egress allowlist and DLP for AI agents",
    audience: "security engineers and CISOs",
    exaQuery: "LLM egress controls DLP best practices 2025",
    mustIncludeTemplates: true,
  },
];

type Strategy = {
  name: string;
  toolStrategy: GeminiToolStrategy;

  // Exa
  useExaSearch?: boolean;
  useExaContext?: boolean;

  // Brave
  useBraveWeb?: boolean;
  useBraveSummarizer?: boolean;
  useBraveGrounding?: boolean;
  braveGroundingResearch?: boolean;

  /**
   * If true, after Brave yields candidate URLs we hydrate them via Exa /contents
   * to get consistent text excerpts.
   */
  hydrateWithExaContents?: boolean;

  /** Prefer sources published within this many days when possible. */
  preferPublishedDays?: number;
  /** Avoid sources older than this many days when possible. */
  maxPublishedDays?: number;

  thinking: "LOW" | "HIGH";
};

const STRATEGIES: Strategy[] = [
  // Gemini tool strategies (baseline)
  { name: "gemini_google_search", toolStrategy: "google_search", thinking: "HIGH" },
  { name: "gemini_url_context", toolStrategy: "url_context", thinking: "HIGH" },
  { name: "gemini_google+url", toolStrategy: "google_search+url_context", thinking: "HIGH" },

  // Exa web search (freshness-aware)
  {
    name: "exa_web_fresh_then_gemini",
    toolStrategy: "none",
    useExaSearch: true,
    preferPublishedDays: 30,
    maxPublishedDays: 365,
    thinking: "HIGH",
  },

  // Exa Code (context API)
  { name: "exa_code_then_gemini", toolStrategy: "none", useExaContext: true, thinking: "HIGH" },

  // Exa combined
  {
    name: "exa_web+code_then_gemini",
    toolStrategy: "none",
    useExaSearch: true,
    useExaContext: true,
    preferPublishedDays: 30,
    maxPublishedDays: 365,
    thinking: "HIGH",
  },

  // Brave web
  {
    name: "brave_web_fresh_then_gemini",
    toolStrategy: "none",
    useBraveWeb: true,
    preferPublishedDays: 30,
    maxPublishedDays: 365,
    thinking: "HIGH",
  },

  // Brave summarizer
  {
    name: "brave_summarizer_then_gemini",
    toolStrategy: "none",
    useBraveSummarizer: true,
    preferPublishedDays: 30,
    maxPublishedDays: 365,
    thinking: "HIGH",
  },

  // Brave AI grounding
  {
    name: "brave_grounding_then_gemini",
    toolStrategy: "none",
    useBraveGrounding: true,
    thinking: "HIGH",
  },
  // NOTE: Brave "research" mode is intentionally not used here.
  // It is much more expensive and (currently) cannot be combined with citations.

  // Brave combined
  {
    name: "brave_web+grounding_then_gemini",
    toolStrategy: "none",
    useBraveWeb: true,
    useBraveGrounding: true,
    preferPublishedDays: 30,
    maxPublishedDays: 365,
    thinking: "HIGH",
  },
  {
    name: "brave_web+grounding_then_exa_contents_then_gemini",
    toolStrategy: "none",
    useBraveWeb: true,
    useBraveGrounding: true,
    hydrateWithExaContents: true,
    preferPublishedDays: 30,
    maxPublishedDays: 365,
    thinking: "HIGH",
  },
];

type WebResult = { url: string; title: string; publishedDate?: string; text?: string };

type ExtraContextBlock = { label: string; response: string; urls: string[] };

function scoreLint(descIssues: number, textErrors: number, textWarns: number, citations: number): number {
  // simple heuristic scoring
  let score = 100;
  score -= descIssues * 3;
  score -= textErrors * 20;
  score -= textWarns * 2;
  score += Math.min(citations, 6) * 2;
  return Math.max(0, score);
}

function isoDaysAgo(days: number): string {
  return new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
}

function publishedWithinDays(publishedDate: string | undefined, days: number): boolean {
  if (!publishedDate) return false;
  const t = Date.parse(publishedDate);
  if (!Number.isFinite(t)) return false;
  return Date.now() - t <= days * 24 * 60 * 60 * 1000;
}

function selectFreshExaResults(
  results: Array<{ url: string; title: string; publishedDate?: string; text?: string }>,
  opts: { preferDays: number; maxDays: number; limit: number },
): Array<{ url: string; title: string; publishedDate?: string; text?: string }> {
  const uniq: Record<string, boolean> = {};
  const deduped = results.filter((r) => {
    if (!r.url) return false;
    if (uniq[r.url]) return false;
    uniq[r.url] = true;
    return true;
  });

  const fresh = deduped.filter((r) => publishedWithinDays(r.publishedDate, opts.preferDays));
  const withinMax = deduped.filter(
    (r) =>
      !publishedWithinDays(r.publishedDate, opts.preferDays) &&
      (publishedWithinDays(r.publishedDate, opts.maxDays) || !r.publishedDate),
  );

  // Avoid explicitly old sources when dates are present.
  const picked = [...fresh, ...withinMax].slice(0, opts.limit);
  return picked;
}

function mergeWebResults(...lists: Array<WebResult[] | undefined>): WebResult[] {
  const byUrl = new Map<string, WebResult>();

  for (const list of lists) {
    for (const r of list ?? []) {
      if (!r?.url) continue;
      const existing = byUrl.get(r.url);
      if (!existing) {
        byUrl.set(r.url, { ...r });
        continue;
      }
      if (!existing.title && r.title) existing.title = r.title;
      if (!existing.publishedDate && r.publishedDate) existing.publishedDate = r.publishedDate;
      if (!existing.text && r.text) existing.text = r.text;
    }
  }

  return Array.from(byUrl.values());
}

function braveWebToWebResults(results: any[]): WebResult[] {
  return (results ?? [])
    .filter((r) => r?.url && r?.title)
    .map((r) => {
      const publishedDate = braveParsePageAge(r);
      const textParts: string[] = [];
      if (r.description) textParts.push(String(r.description));
      if (Array.isArray(r.extra_snippets)) textParts.push(...r.extra_snippets.map(String));
      const text = textParts.join("\n").trim();

      return {
        url: String(r.url),
        title: String(r.title),
        publishedDate,
        text: text || undefined,
      } satisfies WebResult;
    });
}

function braveGroundingCitationsToWebResults(citations: any[]): WebResult[] {
  return (citations ?? [])
    .filter((c) => c?.url)
    .map((c) => ({
      url: String(c.url),
      title: String(c.url),
      text: c.snippet ? String(c.snippet) : undefined,
    }));
}

function braveSummarizerContextToWebResults(items: any[]): WebResult[] {
  return (items ?? [])
    .filter((i) => i?.url && i?.title)
    .map((i) => ({ url: String(i.url), title: String(i.title) }));
}

function extractUrls(text: string): string[] {
  const urls = text.match(/https?:\/\/[^\s)\]]+/g) ?? [];
  const cleaned = urls
    .map((u) => u.replace(/[\s"'<>]+$/g, "").replace(/[),.;]+$/g, ""))
    .filter((u) => u.startsWith("http"));

  const seen = new Set<string>();
  const out: string[] = [];
  for (const u of cleaned) {
    if (seen.has(u)) continue;
    seen.add(u);
    out.push(u);
    if (out.length >= 10) break;
  }
  return out;
}

async function getExaCodeContext(
  apiKey: string,
  query: string,
): Promise<{ response: string; urls: string[] }> {
  consume({ contextCalls: 1 });
  const ctx = await exaContext(apiKey, query, 3500);
  const urls = extractUrls(ctx.response);
  return { response: ctx.response, urls };
}

async function main(): Promise<void> {
  console.log("Strategy test harness");
  console.log("OpenClaw ref present:", hasOpenClawRef());
  console.log("Deepwiki present:", hasDeepWiki());
  console.log("EXA_API_KEY set:", !!process.env.EXA_API_KEY);
  console.log("BRAVE_WEB_API_KEY set:", !!(process.env.BRAVE_WEB_API_KEY || process.env.BRAVE_PRO_API_KEY));
  console.log("BRAVE_SUMMARIZER_API_KEY set:", !!(process.env.BRAVE_SUMMARIZER_API_KEY || process.env.BRAVE_PRO_API_KEY));
  console.log("BRAVE_GROUNDING_API_KEY set:", !!process.env.BRAVE_GROUNDING_API_KEY);

  const usage = loadUsageState();
  console.log("Usage:", usageSummary(usage));
  console.log();

  fs.mkdirSync(OUT_DIR, { recursive: true });

  for (const tc of TEST_CASES) {
    if (ONLY_CASE && tc.slug !== ONLY_CASE) continue;

    console.log(`\n=== Test case: ${tc.slug} ===`);

    const officialExcerpts = [] as any[];
    if (tc.channelSlug) {
      officialExcerpts.push(...officialChannelSources(tc.channelSlug));
    }
    if (tc.providerSlug) {
      const ex = officialProviderDoc(tc.providerSlug);
      if (ex) officialExcerpts.push(ex);
    }

    const deepwikiExcerpts = [] as any[];
    // lightweight deepwiki add-on
    const dw = deepwikiDoc("1-overview.md", "Deepwiki: OpenClaw overview", 2500);
    if (dw) deepwikiExcerpts.push(dw);

    for (const s of STRATEGIES) {
      if (ONLY_STRATEGY && s.name !== ONLY_STRATEGY) continue;

      const needsExa = !!(s.useExaSearch || s.useExaContext || s.hydrateWithExaContents);
      const needsBraveWeb = !!s.useBraveWeb;
      const needsBraveSummarizer = !!s.useBraveSummarizer;
      const needsBraveGrounding = !!s.useBraveGrounding;

      const braveWebKey = process.env.BRAVE_WEB_API_KEY ?? process.env.BRAVE_PRO_API_KEY;
      const braveSummarizerKey = process.env.BRAVE_SUMMARIZER_API_KEY ?? process.env.BRAVE_PRO_API_KEY;

      const braveWebBudgetDelta =
        process.env.BRAVE_FREE_API_KEY && braveWebKey === process.env.BRAVE_FREE_API_KEY
          ? { freeWebSearch: 1 }
          : { proWebSearch: 1 };

      if (needsExa && !process.env.EXA_API_KEY) {
        console.log(`- ${s.name}: SKIP (no EXA_API_KEY)`);
        continue;
      }
      if (needsBraveWeb && !braveWebKey) {
        console.log(`- ${s.name}: SKIP (no BRAVE_WEB_API_KEY)`);
        continue;
      }
      if (needsBraveSummarizer && !braveSummarizerKey) {
        console.log(`- ${s.name}: SKIP (no BRAVE_SUMMARIZER_API_KEY)`);
        continue;
      }
      if (needsBraveGrounding && !process.env.BRAVE_GROUNDING_API_KEY) {
        console.log(`- ${s.name}: SKIP (no BRAVE_GROUNDING_API_KEY)`);
        continue;
      }

      const model = "gemini-3-flash-preview";

      try {
        const preferDays = s.preferPublishedDays ?? 30;
        const maxDays = s.maxPublishedDays ?? 365;

      const extraContexts: ExtraContextBlock[] = [];
      let faqSeeds: string[] | undefined;

      const exaWeb: WebResult[] | undefined = s.useExaSearch && tc.exaQuery
        ? selectFreshExaResults(
            await (consume({ searchCalls: 1 }), exaSearchAndContents(process.env.EXA_API_KEY!, tc.exaQuery, {
              numResults: 10,
              type: "auto",
              maxCharacters: 2500,
              startCrawlDate: isoDaysAgo(maxDays),
              // keep cached content reasonably fresh
              maxAgeHours: preferDays * 24,
            })),
            { preferDays, maxDays, limit: 4 }
          )
        : undefined;

      const braveWeb: WebResult[] | undefined = s.useBraveWeb && tc.exaQuery
        ? selectFreshExaResults(
            braveWebToWebResults(
              (await (consume(braveWebBudgetDelta), braveWebSearch(braveWebKey!, tc.exaQuery, { count: 10 })))
                .web?.results ?? [],
            ),
            { preferDays, maxDays, limit: 4 },
          )
        : undefined;

      let braveSummarizerWeb: WebResult[] | undefined;
      let braveSummarizerContext: WebResult[] | undefined;

      if (s.useBraveSummarizer) {
        const q = tc.exaQuery ?? tc.primaryQuery;
        const { key, web } = await (consume({ proWebSearch: 1 }), braveGetSummarizerKey(braveSummarizerKey!, q, { count: 10 }));
        braveSummarizerWeb = selectFreshExaResults(braveWebToWebResults(web), { preferDays, maxDays, limit: 4 });

        if (key) {
          const sum = await braveSummarizerSearch(braveSummarizerKey!, key, { inlineReferences: true });
          const enrich = (sum as any).enrichments ?? {};
          const raw = typeof enrich.raw === "string" ? enrich.raw : "";
          const ctxItems = Array.isArray(enrich.context) ? enrich.context : [];

          braveSummarizerContext = braveSummarizerContextToWebResults(ctxItems);

          const urls = ctxItems.map((i: any) => i?.url).filter(Boolean).map(String);
          if (raw) {
            extraContexts.push({
              label: "Brave Summarizer (raw)",
              response: raw,
              urls,
            });
          }

          // Follow-up questions are useful as FAQ seeds and as candidates for sub-pages.
          // We DO NOT treat them as sources.
          try {
            const follow = await braveSummarizerFollowups(braveSummarizerKey!, key);
            const f = (follow as any)?.followups;
            if (Array.isArray(f)) {
              faqSeeds = f
                .map((x) => String(x).trim())
                .filter(Boolean)
                .filter((q) => q.length >= 8 && q.length <= 140)
                .slice(0, 8);
            }
          } catch {
            // best-effort
          }
        }
      }

      let braveGroundingWeb: WebResult[] | undefined;
      if (s.useBraveGrounding) {
        const q = tc.exaQuery ?? tc.primaryQuery;
        const msg = `${q}\n\nPrefer sources from the last ${preferDays} days when possible. Avoid sources older than ${maxDays} days. Provide citations.`;
        consume({ groundingRequests: 1 });
        const g = await braveChatCompletions(
          process.env.BRAVE_GROUNDING_API_KEY!,
          [{ role: "user", content: msg }],
          { enableCitations: true, enableResearch: s.braveGroundingResearch ?? false },
        );

        const urls = g.citations.map((c) => c.url).filter(Boolean);
        if (g.text) {
          extraContexts.push({
            label: s.braveGroundingResearch ? "Brave AI Grounding (research answer)" : "Brave AI Grounding (answer)",
            response: g.text,
            urls,
          });
        }

        braveGroundingWeb = braveGroundingCitationsToWebResults(g.citations).slice(0, 6);
      }

      let webResults = mergeWebResults(
        exaWeb,
        braveWeb,
        braveSummarizerWeb,
        braveSummarizerContext,
        braveGroundingWeb,
      ).slice(0, 6);

      if (s.hydrateWithExaContents && webResults.length > 0) {
        consume({ contentsPieces: webResults.length });
        const hydrated = await exaContents(
          process.env.EXA_API_KEY!,
          webResults.map((r) => r.url),
          { maxCharacters: 2500, maxAgeHours: preferDays * 24 },
        );
        webResults = selectFreshExaResults(hydrated, { preferDays, maxDays, limit: 6 });
      }

      const exaCodeContext = s.useExaContext
        ? await getExaCodeContext(process.env.EXA_API_KEY!, tc.exaContextQuery ?? tc.exaQuery ?? tc.primaryQuery)
        : undefined;

      const prompt = buildJsonDraftPrompt({
        pageTitle: tc.title,
        primaryQuery: tc.primaryQuery,
        audience: tc.audience,
        intent: tc.intent,
        productFacts: PRODUCT_FACTS,
        officialExcerpts,
        deepwikiExcerpts,
        exaResults: webResults,
        exaCodeContext,
        extraContexts,
        faqSeeds,
        mustIncludeTemplates: tc.mustIncludeTemplates,
      });

        const result = await generateDraftWithGemini({
          model,
          prompt,
          toolStrategy: s.toolStrategy,
          thinkingLevel: s.thinking,
        });

        const html = renderDraftToHtml(result.draft);

        const descLint = lintMetaDescription(result.draft.metaDescription);
        const textLint = lintText(html);

        const errors = textLint.issues.filter((i) => i.level === "error").length;
        const warns = textLint.issues.filter((i) => i.level === "warn").length;

        const score = scoreLint(descLint.issues.length, errors, warns, result.draft.citations.length);

        console.log(
          `- ${s.name}: score=${score} citations=${result.draft.citations.length} descIssues=${descLint.issues.length} textErrors=${errors} textWarns=${warns}`
        );

        const outPath = path.join(OUT_DIR, s.name, tc.slug.replace(/\//g, "__") + ".json");
        fs.mkdirSync(path.dirname(outPath), { recursive: true });
        fs.writeFileSync(outPath, JSON.stringify({
          slug: tc.slug,
          title: tc.title,
          strategy: s.name,
          model,
          draft: result.draft,
          html,
          lint: { desc: descLint, text: textLint, score },
        }, null, 2));
      } catch (err: any) {
        console.log(`- ${s.name}: FAIL ${err.message?.slice(0, 120)}`);
      }
    }
  }

  console.log(`\nWrote outputs to: ${OUT_DIR}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
