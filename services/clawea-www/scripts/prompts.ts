import type { DocExcerpt } from "./openclaw-docs";
import type { ExaSearchResult } from "./exa";

export interface PromptContext {
  pageTitle: string;
  primaryQuery: string;
  audience: string;
  intent:
    | "deploy"
    | "integration"
    | "use-case"
    | "industry"
    | "model"
    | "compliance"
    | "comparison"
    | "glossary"
    | "guide";
  productFacts: string[];
  officialExcerpts?: DocExcerpt[];
  deepwikiExcerpts?: DocExcerpt[];
  /** Web results from Exa search+contents */
  exaResults?: ExaSearchResult[];
  /** Exa Code (context API) response + extracted URLs */
  exaCodeContext?: { response: string; urls: string[] };
  /** Arbitrary extra context blocks (e.g., Brave grounding answer, Brave summarizer raw). */
  extraContexts?: Array<{ label: string; response: string; urls: string[] }>;
  /** Optional suggested questions for FAQ selection (e.g., Brave summarizer followups). */
  faqSeeds?: string[];
  mustIncludeTemplates?: boolean;
}

export function buildJsonDraftPrompt(ctx: PromptContext): string {
  const officialExcerpts = ctx.officialExcerpts ?? [];
  const deepwikiExcerpts = ctx.deepwikiExcerpts ?? [];
  const exaResults = ctx.exaResults ?? [];

  const extraContexts: Array<{ label: string; response: string; urls: string[] }> = [
    ...(ctx.extraContexts ?? []),
    ...(ctx.exaCodeContext ? [{ label: "Exa Code Context", ...ctx.exaCodeContext }] : []),
  ];

  const official = officialExcerpts
    .map((e) => `\n[${e.label}]\nURL: ${e.canonicalUrl ?? "(local excerpt)"}\n${e.excerpt}`)
    .join("\n\n");

  // Deepwiki is internal-only context. Never cite it.
  const deepwiki = deepwikiExcerpts
    .map((e) => `\n[${e.label}]\n(NOT CITEABLE)\n${e.excerpt}`)
    .join("\n\n");

  const sources = exaResults
    .slice(0, 6)
    .map((r, i) => {
      const snippet = (r.text ?? "").slice(0, 800);
      const published = r.publishedDate ? `\nPublished: ${r.publishedDate}` : "";
      return `\n[Source ${i + 1}] ${r.title}\nURL: ${r.url}${published}\nExcerpt: ${snippet}`;
    })
    .join("\n\n");

  const extraBlocks = extraContexts
    .map((b) => `\n[${b.label}]\n${b.response.slice(0, 6000)}`)
    .join("\n\n");

  const allowedCitationUrls = [
    ...officialExcerpts.map((e) => e.canonicalUrl).filter(Boolean),
    ...exaResults.map((r) => r.url).filter(Boolean),
    ...extraContexts.flatMap((b) => b.urls ?? []),
  ] as string[];

  const openclawGithubUrls = allowedCitationUrls.filter((u) =>
    u.includes("github.com/openclaw/openclaw/blob/"),
  );
  const openclawDocUrls = openclawGithubUrls.filter((u) => u.includes("/docs/"));
  const openclawCodeUrls = openclawGithubUrls.filter((u) => u.includes("/src/"));

  const citationHardRequirements: string[] = [];
  if (openclawDocUrls.length) {
    citationHardRequirements.push(
      "- In citations, include at least one OpenClaw docs URL (a /docs/ link).",
    );
  }
  if (openclawCodeUrls.length) {
    citationHardRequirements.push(
      "- In citations, include at least one OpenClaw source code URL (a /src/ link).",
    );
  }

  const allowedList = allowedCitationUrls.length
    ? allowedCitationUrls.map((u) => `- ${u}`).join("\n")
    : "(none)";

  const facts = ctx.productFacts.map((f) => `- ${f}`).join("\n");

  // NOTE: We force AEO structure via the JSON schema: directAnswer + howToSteps + FAQs.
  // We also enforce anti-generic-AI style constraints.

  return `You are writing for clawea.com (Claw EA), an enterprise AI agent platform.

Write high-trust, non-generic content that matches the search intent: ${ctx.primaryQuery}.
Audience: ${ctx.audience}.

Hard requirements:
- No em dashes (—).
- Avoid buzzwords. Use concrete language.
- Put the direct answer first (2 to 3 sentences).
- Provide a practical step-by-step section.
- Provide 3 to 6 FAQs with questions written exactly like a person would search (include question marks).
- Use short paragraphs (2 to 3 sentences).
- For sections where it is genuinely useful, include an "impact" sentence that answers: what changes for the reader if they follow this advice (risk/cost/auditability/latency/compliance). Do not force one for trivial sections.
- Citations must be real and must use ONLY the allowed URLs list below.
${citationHardRequirements.length ? citationHardRequirements.join("\n") + "\n" : ""}- Do not cite deepwiki excerpts.
- Do not invent product API endpoints, SDKs, or commands.

Allowed citation URLs (use these exact URLs only):
${allowedList}

Product facts (must be accurate):
${facts}

${ctx.faqSeeds?.length ? `Suggested follow-up questions (use as FAQ inspiration, include only if answerable with allowed citations):
${ctx.faqSeeds.map((q) => `- ${q}`).join("\n")}

` : ""}
${ctx.mustIncludeTemplates ? `Template requirements:\n- Include templates.openclawConfigJson5 and templates.envVars when relevant and grounded in the official excerpt.\n- Do NOT include templates.deployCurl unless a real public endpoint is provided in sources.\n- If a snippet would be guesswork, omit the field instead of inventing.\n` : ""}

Official OpenClaw docs excerpts (canonical source):
${official || "(none provided)"}

Deepwiki excerpts (supplemental, NOT citeable):
${deepwiki || "(none provided)"}

Web sources (Exa search results):
${sources || "(none provided)"}

Additional context blocks (may include code/docs excerpts and grounded answers):
${extraBlocks || "(none provided)"}

Now produce a single JSON object that matches the response schema. Do not wrap in markdown.`;
}
