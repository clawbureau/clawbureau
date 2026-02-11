import { GoogleGenAI, type Tool } from "@google/genai";
import type { ArticleDraft } from "./draft-schema";
import { ArticleDraftSchema } from "./draft-schema";

export type GeminiToolStrategy = "google_search" | "none" | "url_context" | "google_search+url_context";

export interface GeminiGenerateOpts {
  apiKey?: string;
  model: string;
  prompt: string;
  toolStrategy: GeminiToolStrategy;
  thinkingLevel?: "LOW" | "MEDIUM" | "HIGH" | "MINIMAL";
}

export interface GeminiGenerateResult {
  draft: ArticleDraft;
  rawJson: unknown;
}

const RESPONSE_SCHEMA = {
  type: "object",
  properties: {
    metaDescription: { type: "string" },
    directAnswer: { type: "string" },
    intro: { type: "string" },
    howToTitle: { type: "string" },
    howToSteps: {
      type: "array",
      items: {
        type: "object",
        properties: {
          name: { type: "string" },
          text: { type: "string" },
        },
        required: ["name", "text"],
      },
    },
    sections: {
      type: "array",
      items: {
        type: "object",
        properties: {
          heading: { type: "string" },
          paragraphs: { type: "array", items: { type: "string" } },
          bullets: { type: "array", items: { type: "string" } },
          impact: { type: "string" },
        },
        required: ["heading", "paragraphs"],
      },
    },

    faqs: {
      type: "array",
      items: {
        type: "object",
        properties: {
          q: { type: "string" },
          a: { type: "string" },
        },
        required: ["q", "a"],
      },
    },
    citations: {
      type: "array",
      items: {
        type: "object",
        properties: {
          title: { type: "string" },
          url: { type: "string" },
        },
        required: ["title", "url"],
      },
    },
    caveats: { type: "array", items: { type: "string" } },
    templates: {
      type: "object",
      properties: {
        openclawConfigJson5: { type: "string" },
        envVars: { type: "array", items: { type: "string" } },
        wpcExampleJson: { type: "string" },
        deployCurl: { type: "string" },
      },
    },
  },
  required: [
    "metaDescription",
    "directAnswer",
    "intro",
    "howToTitle",
    "howToSteps",
    "sections",
    "faqs",
    "citations",
  ],
  additionalProperties: false,
} as const;

function buildTools(strategy: GeminiToolStrategy): Tool[] | undefined {
  if (strategy === "none") return undefined;

  const tools: Tool[] = [];
  if (strategy.includes("google_search")) tools.push({ googleSearch: {} });
  if (strategy.includes("url_context")) tools.push({ urlContext: {} });

  return tools.length ? tools : undefined;
}

export async function generateDraftWithGemini(
  opts: GeminiGenerateOpts,
): Promise<GeminiGenerateResult> {
  const apiKey = opts.apiKey ?? process.env.GEMINI_API_KEY ?? process.env.GOOGLE_API_KEY;
  if (!apiKey) throw new Error("Missing GEMINI_API_KEY or GOOGLE_API_KEY");

  const ai = new GoogleGenAI({ apiKey });

  const tools = buildTools(opts.toolStrategy);

  const resp = await ai.models.generateContent({
    model: opts.model,
    contents: opts.prompt,
    config: {
      temperature: 0.6,
      maxOutputTokens: 8192,
      responseMimeType: "application/json",
      responseJsonSchema: RESPONSE_SCHEMA,
      thinkingConfig: opts.thinkingLevel ? { thinkingLevel: opts.thinkingLevel } : undefined,
      tools,
    },
  });

  const text = resp.text;
  if (!text) throw new Error("Gemini returned empty text");

  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    // If model returned non-strict json, include a hint.
    throw new Error(`Failed to parse JSON response. First 200 chars: ${text.slice(0, 200)}`);
  }

  const draft = ArticleDraftSchema.parse(raw);

  return { draft, rawJson: raw };
}
