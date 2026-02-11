/**
 * Minimal Exa client (no SDK) for search + contents.
 *
 * Docs: https://exa.ai/docs/llms.txt
 */

export interface ExaSearchResult {
  url: string;
  title: string;
  publishedDate?: string;
  author?: string;
  text?: string;
}

export interface ExaSearchResponse {
  results: ExaSearchResult[];
}

export interface ExaSearchOptions {
  numResults?: number;
  type?: "auto" | "neural" | "fast" | "deep" | "instant";
  category?:
    | "company"
    | "research paper"
    | "news"
    | "tweet"
    | "personal site"
    | "financial report"
    | "people";
  maxCharacters?: number;
  includeDomains?: string[];
  excludeDomains?: string[];

  /** Filters */
  startCrawlDate?: string;
  endCrawlDate?: string;
  startPublishedDate?: string;
  endPublishedDate?: string;

  /**
   * Deprecated by Exa in favor of maxAgeHours, but still supported.
   * See https://exa.ai/docs/reference/search
   */
  livecrawl?: "never" | "fallback" | "preferred" | "always";

  /** Max allowed age of cached content. */
  maxAgeHours?: number;
}

export interface ExaAnswerCitation {
  url: string;
  title: string;
}

export interface ExaAnswerResponse {
  answer: string | Record<string, unknown>;
  citations: ExaAnswerCitation[];
}

export async function exaSearchAndContents(
  apiKey: string,
  query: string,
  opts: ExaSearchOptions = {},
): Promise<ExaSearchResult[]> {
  const res = await fetch("https://api.exa.ai/search", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-api-key": apiKey,
    },
    body: JSON.stringify({
      query,
      type: opts.type ?? "auto",
      category: opts.category,
      numResults: opts.numResults ?? 5,
      includeDomains: opts.includeDomains,
      excludeDomains: opts.excludeDomains,
      startCrawlDate: opts.startCrawlDate,
      endCrawlDate: opts.endCrawlDate,
      startPublishedDate: opts.startPublishedDate,
      endPublishedDate: opts.endPublishedDate,
      // Freshness controls (cache vs livecrawl)
      livecrawl: opts.livecrawl,
      maxAgeHours: opts.maxAgeHours,
      contents: {
        text: {
          maxCharacters: opts.maxCharacters ?? 2500,
          includeHtmlTags: false,
        },
      },
    }),
  });

  if (!res.ok) {
    const t = await res.text();
    throw new Error(`Exa /search failed ${res.status}: ${t.slice(0, 200)}`);
  }

  const data = (await res.json()) as ExaSearchResponse;
  return (data.results ?? []).map((r) => ({
    url: r.url,
    title: r.title,
    publishedDate: r.publishedDate,
    author: r.author,
    text: r.text,
  }));
}

export async function exaAnswer(
  apiKey: string,
  query: string,
  opts: { text?: boolean; outputSchema?: Record<string, unknown> } = {},
): Promise<ExaAnswerResponse> {
  const res = await fetch("https://api.exa.ai/answer", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-api-key": apiKey,
    },
    body: JSON.stringify({
      query,
      text: opts.text ?? false,
      outputSchema: opts.outputSchema,
    }),
  });

  if (!res.ok) {
    const t = await res.text();
    throw new Error(`Exa /answer failed ${res.status}: ${t.slice(0, 200)}`);
  }

  const data = (await res.json()) as any;
  return {
    answer: data.answer,
    citations: (data.citations ?? []).map((c: any) => ({
      url: c.url,
      title: c.title ?? c.url,
    })),
  };
}

export async function exaContext(
  apiKey: string,
  query: string,
  tokensNum: number | "dynamic" = "dynamic",
): Promise<{ response: string; resultsCount: number }> {
  const res = await fetch("https://api.exa.ai/context", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-api-key": apiKey,
    },
    body: JSON.stringify({ query, tokensNum }),
  });

  if (!res.ok) {
    const t = await res.text();
    throw new Error(`Exa /context failed ${res.status}: ${t.slice(0, 200)}`);
  }

  const data = (await res.json()) as any;
  return {
    response: String(data.response ?? ""),
    resultsCount: Number(data.resultsCount ?? 0),
  };
}

export async function exaContents(
  apiKey: string,
  urls: string[],
  opts: { maxCharacters?: number; maxAgeHours?: number } = {},
): Promise<ExaSearchResult[]> {
  const res = await fetch("https://api.exa.ai/contents", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-api-key": apiKey,
    },
    body: JSON.stringify({
      urls,
      text: {
        maxCharacters: opts.maxCharacters ?? 2500,
        includeHtmlTags: false,
      },
      maxAgeHours: opts.maxAgeHours,
    }),
  });

  if (!res.ok) {
    const t = await res.text();
    throw new Error(`Exa /contents failed ${res.status}: ${t.slice(0, 200)}`);
  }

  const data = (await res.json()) as any;
  return (data.results ?? []).map((r: any) => ({
    url: r.url,
    title: r.title,
    publishedDate: r.publishedDate,
    author: r.author,
    text: r.text,
  }));
}
