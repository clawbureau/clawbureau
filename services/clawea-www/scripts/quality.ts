/**
 * Quality and anti-generic-AI linting for generated SEO drafts.
 */

export interface LintIssue {
  level: "error" | "warn";
  code: string;
  message: string;
}

export interface HumanToneMetrics {
  score: number;
  sentenceCount: number;
  avgSentenceWords: number;
  longSentenceRatio: number;
  clicheCount: number;
  connectorCount: number;
}

export interface LintResult {
  ok: boolean;
  issues: LintIssue[];
  humanTone?: HumanToneMetrics;
}

const BANNED_SUBSTRINGS: { code: string; s: string }[] = [
  { code: "ai_phrase_ever_evolving", s: "ever-evolving" },
  { code: "ai_phrase_in_todays", s: "in today's" },
  { code: "ai_phrase_digital_age", s: "digital age" },
  { code: "ai_verb_delve", s: "delve" },
  { code: "ai_verb_leverage", s: "leverage" },
  { code: "ai_verb_utilize", s: "utilize" },
  { code: "ai_verb_facilitate", s: "facilitate" },
  { code: "ai_verb_streamline", s: "streamline" },
  { code: "ai_adj_cutting_edge", s: "cutting-edge" },
  { code: "ai_adj_robust", s: "robust" },
  { code: "ai_adj_comprehensive", s: "comprehensive" },
  { code: "ai_phrase_in_conclusion", s: "in conclusion" },
  { code: "ai_phrase_to_sum_up", s: "to sum up" },
  { code: "ai_phrase_as_an_ai", s: "as an ai language model" },
  { code: "ai_phrase_lets_dive", s: "let's dive" },
];

const HUMAN_TONE_CLICHES = [
  "seamlessly",
  "transformative",
  "unprecedented",
  "revolutionary",
  "best-in-class",
  "unlock the power",
  "next-generation",
];

const HUMAN_TONE_CONNECTORS = [
  "furthermore",
  "moreover",
  "additionally",
  "in conclusion",
  "to summarize",
  "ultimately",
];

function scoreHumanTone(text: string): HumanToneMetrics {
  const plain = text
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim();

  const sentences = plain
    .split(/[.!?]+/)
    .map((s) => s.trim())
    .filter(Boolean);

  const sentenceCount = Math.max(1, sentences.length);
  const sentenceWordCounts = sentences.map((s) => s.split(/\s+/).filter(Boolean).length);
  const totalWords = sentenceWordCounts.reduce((acc, c) => acc + c, 0);
  const avgSentenceWords = sentenceCount > 0 ? totalWords / sentenceCount : 0;

  const longSentences = sentenceWordCounts.filter((c) => c >= 34).length;
  const longSentenceRatio = sentenceCount > 0 ? longSentences / sentenceCount : 0;

  const lower = plain.toLowerCase();
  const clicheCount = HUMAN_TONE_CLICHES
    .map((s) => (lower.match(new RegExp(`\\b${s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`, "g")) ?? []).length)
    .reduce((acc, c) => acc + c, 0);

  const connectorCount = HUMAN_TONE_CONNECTORS
    .map((s) => (lower.match(new RegExp(`\\b${s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`, "g")) ?? []).length)
    .reduce((acc, c) => acc + c, 0);

  let score = 100;
  score -= Math.min(30, longSentenceRatio * 100 * 0.6);
  score -= Math.min(22, clicheCount * 4);
  score -= Math.min(18, connectorCount * 3);

  if (sentenceCount < 3) score -= 6;
  if (avgSentenceWords > 28) score -= Math.min(12, (avgSentenceWords - 28) * 0.8);

  return {
    score: Number(Math.max(0, Math.min(100, score)).toFixed(2)),
    sentenceCount,
    avgSentenceWords: Number(avgSentenceWords.toFixed(2)),
    longSentenceRatio: Number(longSentenceRatio.toFixed(4)),
    clicheCount,
    connectorCount,
  };
}

export function lintText(text: string): LintResult {
  const issues: LintIssue[] = [];
  const lower = text.toLowerCase();

  // Em dash (primary AI tell)
  if (text.includes("—")) {
    issues.push({
      level: "error",
      code: "ai_em_dash",
      message: "Contains em dash (—). Replace with commas/colons/parentheses.",
    });
  }

  for (const b of BANNED_SUBSTRINGS) {
    if (lower.includes(b.s)) {
      const level: LintIssue["level"] = b.code === "ai_phrase_as_an_ai" ? "error" : "warn";
      issues.push({
        level,
        code: b.code,
        message: `Contains overused AI phrase/word: "${b.s}"`,
      });
    }
  }

  const humanTone = scoreHumanTone(text);

  if (humanTone.score < 58) {
    issues.push({
      level: "error",
      code: "human_tone_low_score",
      message: `Human tone score too low (${humanTone.score}). Reduce generic phrasing and long sentence density.`,
    });
  } else if (humanTone.score < 72) {
    issues.push({
      level: "warn",
      code: "human_tone_needs_polish",
      message: `Human tone score borderline (${humanTone.score}). Tighten language for a more natural voice.`,
    });
  }

  if (humanTone.longSentenceRatio >= 0.45) {
    issues.push({
      level: "warn",
      code: "human_tone_long_sentence_ratio_high",
      message: `Long sentence ratio is high (${humanTone.longSentenceRatio}).`,
    });
  }

  if (humanTone.clicheCount >= 4) {
    issues.push({
      level: "warn",
      code: "human_tone_cliches_high",
      message: `Detected ${humanTone.clicheCount} sales-cliche phrases.`,
    });
  }

  return { ok: issues.every((i) => i.level !== "error"), issues, humanTone };
}

export function lintMetaDescription(desc: string): LintResult {
  const issues: LintIssue[] = [];
  const len = desc.trim().length;

  if (len < 120) {
    issues.push({ level: "warn", code: "meta_desc_short", message: `Meta description is short (${len} chars). Target ~150-160.` });
  }
  if (len > 170) {
    issues.push({ level: "warn", code: "meta_desc_long", message: `Meta description is long (${len} chars). Target ~150-160.` });
  }

  const t = lintText(desc);
  issues.push(...t.issues);

  return { ok: issues.every((i) => i.level !== "error"), issues, humanTone: t.humanTone };
}
