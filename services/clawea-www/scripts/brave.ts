/**
 * Minimal Brave Search client.
 *
 * Endpoints:
 * - Web search: GET https://api.search.brave.com/res/v1/web/search
 * - Summarizer: GET https://api.search.brave.com/res/v1/summarizer/*
 * - AI Grounding (OpenAI-compatible): POST https://api.search.brave.com/res/v1/chat/completions
 */

export interface BraveWebSearchResult {
  url: string;
  title: string;
  description?: string;
  age?: string;
  page_age?: string;
  extra_snippets?: string[];
}

export interface BraveWebSearchResponse {
  type: string;
  web?: { results?: BraveWebSearchResult[] };
  summarizer?: { type?: string; key?: string };
}

export interface BraveWebSearchOpts {
  count?: number;
  country?: string;
  searchLang?: string;
  safesearch?: "off" | "moderate" | "strict";
  summary?: boolean;
}

function braveHeaders(apiKey: string): Record<string, string> {
  return {
    "accept": "application/json",
    "x-subscription-token": apiKey,
  };
}

export async function braveWebSearch(
  apiKey: string,
  query: string,
  opts: BraveWebSearchOpts = {},
): Promise<BraveWebSearchResponse> {
  const u = new URL("https://api.search.brave.com/res/v1/web/search");
  u.searchParams.set("q", query);
  u.searchParams.set("count", String(opts.count ?? 5));
  if (opts.country) u.searchParams.set("country", opts.country);
  if (opts.searchLang) u.searchParams.set("search_lang", opts.searchLang);
  if (opts.safesearch) u.searchParams.set("safesearch", opts.safesearch);
  if (opts.summary) u.searchParams.set("summary", "1");

  const res = await fetch(u.toString(), {
    method: "GET",
    headers: braveHeaders(apiKey),
  });

  if (!res.ok) {
    const t = await res.text();
    throw new Error(`Brave web search failed ${res.status}: ${t.slice(0, 200)}`);
  }

  return (await res.json()) as BraveWebSearchResponse;
}

export async function braveGetSummarizerKey(
  apiKey: string,
  query: string,
  opts: Omit<BraveWebSearchOpts, "summary"> = {},
): Promise<{ key: string | null; web: BraveWebSearchResult[] }> {
  const r = await braveWebSearch(apiKey, query, { ...opts, summary: true });
  const key = r.summarizer?.key ?? null;
  const web = r.web?.results ?? [];
  return { key, web };
}

export interface BraveSummarizerReference {
  url: string;
  title?: string;
  snippet?: string;
}

export interface BraveSummarizerContextItem {
  title: string;
  url: string;
  description?: string;
}

export interface BraveSummarizerEnrichments {
  raw?: string;
  context?: BraveSummarizerContextItem[];
  // Remaining fields vary; keep them loose.
  entities?: unknown;
  images?: unknown;
  qa?: unknown;
}

export interface BraveSummarizerResponse {
  type?: string;
  status?: string;
  title?: string;
  summary?: unknown;
  references?: BraveSummarizerReference[];
  enrichments?: BraveSummarizerEnrichments | unknown;
  followups?: unknown;
  entities_infos?: unknown;
}

async function braveSummarizerGet(
  apiKey: string,
  endpoint: string,
  key: string,
  params: Record<string, string | number | boolean | undefined> = {},
): Promise<BraveSummarizerResponse> {
  const u = new URL(`https://api.search.brave.com/res/v1/summarizer/${endpoint}`);
  u.searchParams.set("key", key);
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined) continue;
    u.searchParams.set(k, String(v));
  }

  const res = await fetch(u.toString(), {
    method: "GET",
    headers: braveHeaders(apiKey),
  });

  if (!res.ok) {
    const t = await res.text();
    throw new Error(`Brave summarizer/${endpoint} failed ${res.status}: ${t.slice(0, 200)}`);
  }

  return (await res.json()) as BraveSummarizerResponse;
}

export async function braveSummarizerSearch(
  apiKey: string,
  key: string,
  opts: { inlineReferences?: boolean; entityInfo?: boolean } = {},
): Promise<BraveSummarizerResponse> {
  return braveSummarizerGet(apiKey, "search", key, {
    inline_references: opts.inlineReferences ?? true,
    entity_info: opts.entityInfo ?? false,
  });
}

export async function braveSummarizerSummary(
  apiKey: string,
  key: string,
  opts: { inlineReferences?: boolean } = {},
): Promise<BraveSummarizerResponse> {
  return braveSummarizerGet(apiKey, "summary", key, {
    inline_references: opts.inlineReferences ?? true,
  });
}

export async function braveSummarizerTitle(apiKey: string, key: string): Promise<BraveSummarizerResponse> {
  return braveSummarizerGet(apiKey, "title", key);
}

export async function braveSummarizerEnrichments(apiKey: string, key: string): Promise<BraveSummarizerResponse> {
  return braveSummarizerGet(apiKey, "enrichments", key);
}

export async function braveSummarizerFollowups(apiKey: string, key: string): Promise<BraveSummarizerResponse> {
  return braveSummarizerGet(apiKey, "followups", key);
}

export async function braveSummarizerEntityInfo(apiKey: string, key: string): Promise<BraveSummarizerResponse> {
  return braveSummarizerGet(apiKey, "entity_info", key);
}

// ── AI grounding (OpenAI-compatible) ───────────────────────────────

export type BraveChatRole = "system" | "user" | "assistant";

export interface BraveChatMessage {
  role: BraveChatRole;
  content: string;
}

export interface BraveGroundingCitation {
  number: number;
  url: string;
  snippet?: string;
  start_index?: number;
  end_index?: number;
}

export interface BraveChatCompletionResult {
  text: string;
  citations: BraveGroundingCitation[];
}

export async function braveChatCompletions(
  apiKey: string,
  messages: BraveChatMessage[],
  opts: {
    enableCitations?: boolean;
    enableEntities?: boolean;
    enableResearch?: boolean;
    country?: string;
    language?: string;
  } = {},
): Promise<BraveChatCompletionResult> {
  const enableCitations = opts.enableCitations ?? true;
  const enableEntities = opts.enableEntities ?? false;
  const enableResearch = opts.enableResearch ?? false;

  // Brave only supports citations in streaming mode.
  const stream = enableCitations || enableEntities || enableResearch;

  const body: any = {
    model: "brave",
    stream,
    messages,
    country: opts.country ?? "us",
    language: opts.language ?? "en",
  };

  if (stream) {
    if (enableCitations) body.enable_citations = true;
    if (enableEntities) body.enable_entities = true;
    if (enableResearch) body.enable_research = true;
  }

  const res = await fetch("https://api.search.brave.com/res/v1/chat/completions", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-subscription-token": apiKey,
      "accept": stream ? "text/event-stream" : "application/json",
    },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const t = await res.text();
    throw new Error(`Brave chat/completions failed ${res.status}: ${t.slice(0, 200)}`);
  }

  if (!stream) {
    const data = (await res.json()) as any;
    const content = data?.choices?.[0]?.message?.content;
    const text = typeof content === "string" ? content : "";
    const { cleanText, citations } = parseBraveGroundingText(text);
    return { text: cleanText, citations };
  }

  const reader = res.body?.getReader();
  if (!reader) {
    throw new Error("Brave chat/completions returned no body for streaming response");
  }

  const decoder = new TextDecoder();
  let buffer = "";
  let raw = "";
  let sawDone = false;

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    while (true) {
      const sep = buffer.indexOf("\n\n");
      if (sep === -1) break;

      const event = buffer.slice(0, sep);
      buffer = buffer.slice(sep + 2);

      for (const line of event.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed.startsWith("data:")) continue;

        const payload = trimmed.slice("data:".length).trim();
        if (!payload) continue;
        if (payload === "[DONE]") {
          sawDone = true;
          break;
        }

        try {
          const obj = JSON.parse(payload);
          const delta = obj?.choices?.[0]?.delta?.content;
          if (typeof delta === "string") raw += delta;
        } catch {
          // ignore JSON parse errors
        }
      }

      if (sawDone) break;
    }

    if (sawDone) break;
  }

  const { cleanText, citations } = parseBraveGroundingText(raw);
  return { text: cleanText, citations };
}

export function parseBraveGroundingText(text: string): { cleanText: string; citations: BraveGroundingCitation[] } {
  const citations: BraveGroundingCitation[] = [];

  const rx = /<citation>([\s\S]*?)<\/citation>/g;
  let m: RegExpExecArray | null;
  while ((m = rx.exec(text)) !== null) {
    try {
      const obj = JSON.parse(m[1]);
      if (obj?.url && obj?.number) {
        citations.push({
          number: Number(obj.number),
          url: String(obj.url),
          snippet: obj.snippet ? String(obj.snippet) : undefined,
          start_index: obj.start_index,
          end_index: obj.end_index,
        });
      }
    } catch {
      // ignore
    }
  }

  const cleanText = text
    .replace(/<citation>[\s\S]*?<\/citation>/g, "")
    .replace(/<enum_item>[\s\S]*?<\/enum_item>/g, "")
    .replace(/<usage>[\s\S]*?<\/usage>/g, "")
    .replace(/\n{3,}/g, "\n\n")
    .trim();

  return { cleanText, citations };
}

export function braveParsePageAge(result: { page_age?: string; age?: string }): string | undefined {
  // Brave web search includes page_age like "2025-01-15T00:00:00".
  if (result.page_age && /^\d{4}-\d{2}-\d{2}T/.test(result.page_age)) {
    // Normalize to ISO with Z to make parsing consistent.
    return result.page_age.endsWith("Z") ? result.page_age : result.page_age + "Z";
  }

  // "age" is often a human date like "January 15, 2025".
  if (result.age) {
    const t = Date.parse(result.age);
    if (Number.isFinite(t)) return new Date(t).toISOString();
  }

  return undefined;
}
