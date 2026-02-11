/**
 * Quality and anti-generic-AI linting for generated SEO drafts.
 */

export interface LintIssue {
  level: "error" | "warn";
  code: string;
  message: string;
}

export interface LintResult {
  ok: boolean;
  issues: LintIssue[];
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
];

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
      issues.push({
        level: "warn",
        code: b.code,
        message: `Contains overused AI phrase/word: "${b.s}"`,
      });
    }
  }

  return { ok: issues.every((i) => i.level !== "error"), issues };
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

  return { ok: issues.every((i) => i.level !== "error"), issues };
}
