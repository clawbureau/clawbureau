#!/usr/bin/env npx tsx
import * as fs from "node:fs";
import * as path from "node:path";
import { GoogleGenAI } from "@google/genai";

type Severity = "P0" | "P1" | "P2";

interface CritiqueIssue {
  issue_id: string;
  page: string;
  severity: Severity;
  evidence: string;
  trust_impact: string;
  exact_fix_recommendation: string;
  accessibility_impact: string;
  conversion_impact: string;
}

const args = process.argv.slice(2);
const getArg = (name: string): string | undefined => {
  const idx = args.indexOf(`--${name}`);
  return idx >= 0 && idx + 1 < args.length ? args[idx + 1] : undefined;
};
const hasFlag = (name: string): boolean => args.includes(`--${name}`);

const screenshotsDir = path.resolve(
  getArg("screenshots") ?? path.resolve(import.meta.dirname ?? ".", "../../artifacts/ops/clawea-www/ux-capture"),
);
const outFile = path.resolve(
  getArg("output") ?? path.resolve(import.meta.dirname ?? ".", "../../artifacts/ops/clawea-www/gemini-critique.json"),
);
const model = getArg("model") ?? "gemini-3-pro-preview";
const failOnP0P1 = hasFlag("fail-on-p0p1");

const apiKey = process.env.GEMINI_API_KEY ?? process.env.GOOGLE_API_KEY;
if (!apiKey) {
  console.error("Missing GEMINI_API_KEY (or GOOGLE_API_KEY)");
  process.exit(1);
}

const schema = {
  type: "array",
  items: {
    type: "object",
    properties: {
      issue_id: { type: "string" },
      page: { type: "string" },
      severity: { type: "string", enum: ["P0", "P1", "P2"] },
      evidence: { type: "string" },
      trust_impact: { type: "string" },
      exact_fix_recommendation: { type: "string" },
      accessibility_impact: { type: "string" },
      conversion_impact: { type: "string" },
    },
    required: [
      "issue_id",
      "page",
      "severity",
      "evidence",
      "trust_impact",
      "exact_fix_recommendation",
      "accessibility_impact",
      "conversion_impact",
    ],
    additionalProperties: false,
  },
} as const;

function readImageBase64(filePath: string): string {
  return fs.readFileSync(filePath).toString("base64");
}

function collectScreenshots(dir: string): Map<string, string[]> {
  const files = fs.readdirSync(dir)
    .filter((f) => f.endsWith(".png"))
    .sort((a, b) => a.localeCompare(b, "en"));

  const grouped = new Map<string, string[]>();
  for (const file of files) {
    const [slug] = file.split("__");
    const current = grouped.get(slug) ?? [];
    current.push(path.join(dir, file));
    grouped.set(slug, current);
  }
  return grouped;
}

function routeFromSlug(slug: string): string {
  if (slug === "home") return "/";
  return `/${slug.replace(/__/g, "/")}`;
}

function normalizeIssue(raw: any, index: number, route: string): CritiqueIssue {
  const severity = raw?.severity === "P0" || raw?.severity === "P1" || raw?.severity === "P2"
    ? raw.severity
    : "P2";

  return {
    issue_id: String(raw?.issue_id ?? `${route.replace(/\W+/g, "_")}_ISSUE_${index + 1}`),
    page: String(raw?.page ?? route),
    severity,
    evidence: String(raw?.evidence ?? "missing evidence"),
    trust_impact: String(raw?.trust_impact ?? "not provided"),
    exact_fix_recommendation: String(raw?.exact_fix_recommendation ?? "not provided"),
    accessibility_impact: String(raw?.accessibility_impact ?? "not provided"),
    conversion_impact: String(raw?.conversion_impact ?? "not provided"),
  };
}

function applySeverityPolicy(issue: CritiqueIssue): CritiqueIssue {
  if (issue.severity !== "P1") return issue;

  const text = [
    issue.evidence,
    issue.trust_impact,
    issue.exact_fix_recommendation,
    issue.accessibility_impact,
    issue.conversion_impact,
  ].join(" ").toLowerCase();

  const objectiveSignals = /(wcag|contrast|illegible|invisible|cut off|clipped|truncated|overlap|broken|inaccessible|obscured|required field|required\s*asterisk|not visible|missing field|dead end|unreadable|touch target|hidden|off-screen|overflow)/;

  if (!objectiveSignals.test(text)) {
    return { ...issue, severity: "P2" };
  }

  return issue;
}

async function critiquePage(ai: GoogleGenAI, route: string, images: string[]): Promise<CritiqueIssue[]> {
  const prompt = [
    "You are a principal UX/UI reviewer for enterprise conversion pages.",
    "Audit these screenshots for trust-damaging visual defects and conversion blockers.",
    "Prioritize visual quality, information hierarchy, spacing/typography consistency, CTA clarity, mobile behavior, and anything that looks AI-generated/low-trust.",
    "Return ONLY JSON array matching schema.",
    "Severity rules:",
    "- P0: severe trust failure or inaccessible blocker",
    "- P1: objective usability/accessibility defect that materially blocks progression",
    "- P2: polish, copy preference, product strategy suggestions, social-proof wishes, or non-blocking optimization ideas",
    "Do not classify social proof requests, CTA wording debates, or preference-based marketing suggestions as P1.",
    `Page route: ${route}`,
  ].join("\n");

  const parts: Array<any> = [{ text: prompt }];
  for (const imgPath of images) {
    parts.push({ text: `Screenshot file: ${path.basename(imgPath)}` });
    parts.push({
      inlineData: {
        mimeType: "image/png",
        data: readImageBase64(imgPath),
      },
    });
  }

  const resp = await ai.models.generateContent({
    model,
    contents: [{ role: "user", parts }],
    config: {
      temperature: 0.2,
      responseMimeType: "application/json",
      responseJsonSchema: schema,
    },
  });

  const text = resp.text;
  if (!text) return [];

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error(`Gemini returned non-JSON for ${route}`);
  }

  if (!Array.isArray(parsed)) {
    throw new Error(`Gemini returned non-array critique for ${route}`);
  }

  return parsed.map((issue, idx) => applySeverityPolicy(normalizeIssue(issue, idx, route)));
}

async function main(): Promise<void> {
  if (!fs.existsSync(screenshotsDir)) {
    throw new Error(`Screenshots dir not found: ${screenshotsDir}`);
  }

  const grouped = collectScreenshots(screenshotsDir);
  const ai = new GoogleGenAI({ apiKey });

  const issues: CritiqueIssue[] = [];
  for (const [slug, files] of grouped.entries()) {
    const route = routeFromSlug(slug);
    const pageIssues = await critiquePage(ai, route, files);
    issues.push(...pageIssues);
  }

  const bySeverity = {
    P0: issues.filter((i) => i.severity === "P0").length,
    P1: issues.filter((i) => i.severity === "P1").length,
    P2: issues.filter((i) => i.severity === "P2").length,
  };

  const payload = {
    generatedAt: new Date().toISOString(),
    model,
    screenshotsDir,
    totals: {
      issues: issues.length,
      ...bySeverity,
    },
    issues,
  };

  fs.mkdirSync(path.dirname(outFile), { recursive: true });
  fs.writeFileSync(outFile, JSON.stringify(payload, null, 2));

  console.log(`Critique written: ${outFile}`);
  console.log(JSON.stringify(payload.totals));

  if (failOnP0P1 && (bySeverity.P0 > 0 || bySeverity.P1 > 0)) {
    console.error(`Gate failed: P0=${bySeverity.P0}, P1=${bySeverity.P1}`);
    process.exit(2);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
