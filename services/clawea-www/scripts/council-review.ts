#!/usr/bin/env npx tsx
/**
 * Council review benchmark: run 3 independent "reviewer" models over the same
 * anonymized candidates and aggregate their scores.
 *
 * - Uses fal's OpenRouter router (OpenAI-compatible).
 * - Reviewers see candidate IDs only (candidate-01..candidate-09).
 * - Writes reviewer JSON outputs + an aggregated summary.
 * - Stores reviewer model mapping privately under ~/.clawbureau-secrets/.
 *
 * Usage:
 *   source ~/.clawbureau-secrets/clawea-www.env.sh
 *   npx tsx scripts/council-review.ts --run sample-output/model-writeoff/<runId> --target workflows__...
 */

import * as fs from "fs";
import * as path from "path";
import { z } from "zod";

const OPENROUTER_CHAT_COMPLETIONS_URL =
  process.env.OPENROUTER_CHAT_COMPLETIONS_URL ??
  "https://fal.run/openrouter/router/openai/v1/chat/completions";

const FAL_KEY = process.env.FAL_KEY;
if (!FAL_KEY) {
  console.error("FAL_KEY not set");
  process.exit(1);
}

const args = process.argv.slice(2);
const getArg = (name: string) => {
  const idx = args.indexOf(`--${name}`);
  return idx >= 0 && idx + 1 < args.length ? args[idx + 1] : undefined;
};

const RUN_ROOT_RAW = getArg("run") ?? "";
if (!RUN_ROOT_RAW) {
  console.error("Missing --run <path-to-run-folder>");
  process.exit(1);
}

const RUN_ROOT = path.resolve(RUN_ROOT_RAW);
if (!fs.existsSync(RUN_ROOT) || !fs.statSync(RUN_ROOT).isDirectory()) {
  console.error(`Run folder not found: ${RUN_ROOT}`);
  process.exit(1);
}

const TARGET_FILTER = getArg("target"); // optional: safe folder name or original slug

const COUNCIL_TEMP = Number(process.env.COUNCIL_TEMPERATURE ?? "0.2");
const COUNCIL_MAX_TOKENS = Number(process.env.COUNCIL_MAX_TOKENS ?? "6000");

const COUNCIL_USE_STRUCTURED = process.env.COUNCIL_STRUCTURED !== "0";
const COUNCIL_USE_RESPONSE_HEALING = process.env.COUNCIL_RESPONSE_HEALING !== "0";
const COUNCIL_RESUME = process.env.COUNCIL_RESUME === "1";


// Review council (model IDs are stored privately; reviewers are anonymized in outputs)
const COUNCIL_MODELS = [
  "anthropic/claude-opus-4.6",
  "google/gemini-3-pro-preview",
  "openai/gpt-5.2",
] as const;

type Reviewer = { reviewerId: string; modelId: string };

const REVIEWERS: Reviewer[] = COUNCIL_MODELS.map((m, i) => ({
  reviewerId: `reviewer-${String(i + 1).padStart(2, "0")}`,
  modelId: m,
}));

const runId = path.basename(RUN_ROOT);

const PRIVATE_MAP_PATH = path.join(
  process.env.HOME ?? "~",
  ".clawbureau-secrets",
  `clawea-council-map.${runId}.json`,
);

function ensureDir(p: string): void {
  fs.mkdirSync(p, { recursive: true });
}

function cleanJson(s: string): string {
  let t = (s ?? "").trim();
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

const REQUEST_TIMEOUT_MS = Number(process.env.OPENROUTER_TIMEOUT_MS ?? "180000");

async function openrouterChat(
  model: string,
  system: string,
  user: string,
  opts: {
    temperature: number;
    maxTokens: number;
    responseFormat?: any;
    plugins?: any[];
  },
): Promise<{ text: string; finishReason?: string; raw?: any }> {
  const body: any = {
    model,
    messages: [
      { role: "system", content: system },
      { role: "user", content: user },
    ],
    temperature: opts.temperature,
    max_tokens: opts.maxTokens,
    top_p: 1,
    stream: false,
    ...(opts.responseFormat ? { response_format: opts.responseFormat } : {}),
    ...(opts.plugins?.length ? { plugins: opts.plugins } : {}),
  };

  for (let attempt = 0; attempt < 10; attempt++) {
    const ctrl = new AbortController();
    const to = setTimeout(() => ctrl.abort(), REQUEST_TIMEOUT_MS);

    try {
      const res = await fetch(OPENROUTER_CHAT_COMPLETIONS_URL, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "authorization": `Key ${FAL_KEY}`,
        },
        body: JSON.stringify(body),
        signal: ctrl.signal,
      });

      if (res.status === 429 || res.status === 503 || res.status === 500) {
        const wait = Math.min(1500 * 2 ** attempt, 30000);
        await new Promise((r) => setTimeout(r, wait));
        continue;
      }

      if (!res.ok) {
        const t = await res.text();
        throw new Error(`OpenRouter failed ${res.status}: ${t.slice(0, 400)}`);
      }

      const data = (await res.json()) as any;
      const text = data?.choices?.[0]?.message?.content ?? data?.choices?.[0]?.text ?? "";
      const finishReason = data?.choices?.[0]?.finish_reason;

      if (typeof text !== "string" || !text.trim()) {
        const wait = Math.min(1200 * 2 ** attempt, 20000);
        await new Promise((r) => setTimeout(r, wait));
        continue;
      }

      return { text, finishReason, raw: data };
    } catch (e: any) {
      const msg = e?.message ?? String(e);
      const wait = Math.min(1500 * 2 ** attempt, 30000);
      // Retry on network timeouts/aborts.
      if (attempt === 9) throw new Error(`OpenRouter fetch failed: ${msg}`);
      await new Promise((r) => setTimeout(r, wait));
      continue;
    } finally {
      clearTimeout(to);
    }
  }

  throw new Error("OpenRouter retries exhausted");
}

const Score = z.number().int().min(1).max(5);

const CandidateScoreSchema = z.object({
  directness: Score,
  specificity: Score,
  openclaw_alignment: Score,
  clawea_alignment: Score,
  enterprise_correctness: Score,
  security_quality: Score,
  policy_quality: Score,
  proof_quality: Score,
  structure_style: Score,
});

function councilJsonSchema(): any {
  // JSON Schema for OpenRouter structured outputs.
  // We intentionally do not enforce the exact number of candidates here;
  // the script validates coverage programmatically.
  return {
    type: "object",
    additionalProperties: false,
    properties: {
      reviewer_id: { type: "string" },
      target: {
        type: "object",
        additionalProperties: false,
        properties: {
          slug: { type: "string" },
          title: { type: "string" },
          query: { type: "string" },
          notes: { type: "string" },
        },
        required: ["slug", "title", "query"],
      },
      candidates: {
        type: "array",
        items: {
          type: "object",
          additionalProperties: false,
          properties: {
            candidate: { type: "string", pattern: "^candidate-\\d{2}$" },
            scores: {
              type: "object",
              additionalProperties: false,
              properties: {
                directness: { type: "integer", minimum: 1, maximum: 5 },
                specificity: { type: "integer", minimum: 1, maximum: 5 },
                openclaw_alignment: { type: "integer", minimum: 1, maximum: 5 },
                clawea_alignment: { type: "integer", minimum: 1, maximum: 5 },
                enterprise_correctness: { type: "integer", minimum: 1, maximum: 5 },
                security_quality: { type: "integer", minimum: 1, maximum: 5 },
                policy_quality: { type: "integer", minimum: 1, maximum: 5 },
                proof_quality: { type: "integer", minimum: 1, maximum: 5 },
                structure_style: { type: "integer", minimum: 1, maximum: 5 },
              },
              required: [
                "directness",
                "specificity",
                "openclaw_alignment",
                "clawea_alignment",
                "enterprise_correctness",
                "security_quality",
                "policy_quality",
                "proof_quality",
                "structure_style",
              ],
            },
            pros: { type: "array", items: { type: "string" }, maxItems: 6 },
            cons: { type: "array", items: { type: "string" }, maxItems: 6 },
            critical_issues: { type: "array", items: { type: "string" }, maxItems: 6 },
          },
          required: ["candidate", "scores", "pros", "cons"],
        },
      },
      top3: {
        type: "array",
        minItems: 1,
        maxItems: 3,
        items: { type: "string", pattern: "^candidate-\\d{2}$" },
      },
      overall_notes: { type: "array", items: { type: "string" }, maxItems: 10 },
    },
    required: ["reviewer_id", "target", "candidates", "top3"],
  };
}

function councilResponseFormat(): any {
  return {
    type: "json_schema",
    json_schema: {
      name: "CouncilReview",
      strict: true,
      schema: councilJsonSchema(),
    },
  };
}

function responseHealingPlugin(): any[] {
  return [{ id: "response-healing" }];
}


const CandidateReviewSchema = z.object({
  candidate: z.string().regex(/^candidate-\d{2}$/),
  scores: CandidateScoreSchema,
  pros: z.array(z.string().min(5).max(400)).max(6),
  cons: z.array(z.string().min(5).max(400)).max(6),
  critical_issues: z.array(z.string().min(5).max(400)).max(6).optional(),
});

const CouncilReviewSchema = z.object({
  reviewer_id: z.string().min(3).max(40),
  target: z.object({
    slug: z.string().min(1).max(240),
    title: z.string().min(3).max(200),
    query: z.string().min(3).max(300),
    notes: z.string().min(0).max(600).optional(),
  }),
  candidates: z.array(CandidateReviewSchema).min(1).max(30),
  top3: z.array(z.string().regex(/^candidate-\d{2}$/)).min(1).max(3),
  overall_notes: z.array(z.string().min(5).max(600)).max(10).optional(),
});

type CouncilReview = z.infer<typeof CouncilReviewSchema>;

function average(nums: number[]): number {
  if (!nums.length) return 0;
  return nums.reduce((a, b) => a + b, 0) / nums.length;
}

function stddev(nums: number[]): number {
  if (nums.length <= 1) return 0;
  const m = average(nums);
  const v = average(nums.map((x) => (x - m) ** 2));
  return Math.sqrt(v);
}

function overallFromScores(s: z.infer<typeof CandidateScoreSchema>): number {
  const vals = Object.values(s);
  return average(vals);
}

function buildCouncilSystemPrompt(reviewerId: string): string {
  return `You are an enterprise security technical editor reviewing a clawea.com (Claw EA) page.

Hard constraints:
- Output a single JSON object only. No markdown and no code fences.
- Do not include chain-of-thought.
- Be strict and consistent.
- Candidate IDs are anonymized. Do not guess the authoring model.

Terminology glossary (treat incorrect expansions as an error):
- WPC = Work Policy Contract (signed, hash-addressed policy artifact; served by clawcontrols)
- CST = scoped token (issued by clawscope). Do not expand CST as anything else.
- Gateway receipts = model call receipts emitted by clawproxy
- Proof bundle = harness artifact bundling receipts and related metadata

Capability truth table (penalize over-claiming):
Shipped:
- WPC registry plus proxy fetch/verify
- CST scope hash and optional policy hash pinning
- Gateway receipts for model calls
- Proof bundles
- Marketplace anti-replay binding (job-scoped CST binding)
- Trust Pulse artifact storage/viewer
- OpenRouter via fal routed through clawproxy

Planned or optional (must be labeled planned/optional/implementable if mentioned):
- Egress allowlists enforced outside clawproxy
- Automatic cost budget enforcement
- Transparency log inclusion proofs

Rule: If not shipped, it can be described as implementable (often within 24 hours) by Antfarm, but do not present it as shipped.

Style constraints (penalize violations):
- No em dashes (—)
- Short paragraphs, concrete language
- Avoid generic AI marketing fluff

You are reviewer_id=${reviewerId}. Return JSON matching the requested schema exactly.`;
}

function buildCouncilUserPrompt(input: {
  reviewerId: string;
  target: { slug: string; title: string; query: string; notes?: string };
  candidates: Array<{ candidate: string; html: string }>;
}): string {
  const { reviewerId, target, candidates } = input;

  const rubric = `Rubric: score each dimension 1–5 (integers).

Dimensions:
- directness: Opening paragraphs are 2–3 sentences and answer the query without a generic “Direct Answer” heading.
- specificity: Concrete steps, concrete controls, concrete failure modes.
- openclaw_alignment: Mentions OpenClaw correctly, uses realistic security primitives.
- clawea_alignment: Correctly frames permissioned execution, WPC/CST/receipts/proof bundles, without inventing endpoints.
- enterprise_correctness: Microsoft terminology correct, least privilege posture, avoids made-up features.
- security_quality: Real threat model + matched controls.
- policy_quality: Policy snippet is plausible and enforceable.
- proof_quality: Evidence artifacts are specific and verifiable.
- structure_style: Required headings in order, short paragraphs, no em dashes.

Scoring anchors:
- 5: excellent, would ship as-is.
- 3: acceptable but needs edits.
- 1: unsafe, incorrect, or mostly fluff.`;

  const schemaHint = `Return JSON with this shape:
{
  "reviewer_id": "${reviewerId}",
  "target": { "slug": string, "title": string, "query": string, "notes"?: string },
  "candidates": [
    {
      "candidate": "candidate-01",
      "scores": {
        "directness": 1|2|3|4|5,
        "specificity": 1|2|3|4|5,
        "openclaw_alignment": 1|2|3|4|5,
        "clawea_alignment": 1|2|3|4|5,
        "enterprise_correctness": 1|2|3|4|5,
        "security_quality": 1|2|3|4|5,
        "policy_quality": 1|2|3|4|5,
        "proof_quality": 1|2|3|4|5,
        "structure_style": 1|2|3|4|5
      },
      "pros": [string, ...],
      "cons": [string, ...],
      "critical_issues"?: [string, ...]
    }
  ],
  "top3": ["candidate-..", "candidate-.." /* ... K items where K = min(3, candidateCount) */],
  "overall_notes"?: [string, ...]
}

Rules:
- Include ALL candidates exactly once.
- top3 must reference candidate IDs from the set.
- top3 length must be K = min(3, number of candidates).
- Keep pros/cons short (max 6 each).`;

  const blocks = candidates
    .map((c) => `\n\n[${c.candidate}]\n<BEGIN_HTML>\n${c.html.trim()}\n<END_HTML>`)
    .join("");

  return `Target:
- slug: /${target.slug}
- title: ${target.title}
- primary query: ${target.query}
- notes: ${target.notes ?? "(none)"}

${rubric}

${schemaHint}

Candidates:${blocks}
`;
}

function listTargetDirs(runRoot: string): Array<{ name: string; abs: string }> {
  const out: Array<{ name: string; abs: string }> = [];
  for (const ent of fs.readdirSync(runRoot, { withFileTypes: true })) {
    if (!ent.isDirectory()) continue;
    const abs = path.join(runRoot, ent.name);
    if (!fs.existsSync(path.join(abs, "spec.json"))) continue;
    if (!fs.existsSync(path.join(abs, "candidates"))) continue;
    out.push({ name: ent.name, abs });
  }
  return out;
}

function resolveTargetDir(runRoot: string, targetArg: string): { name: string; abs: string } | null {
  // Accept either safe folder name or original slug.
  const safe = targetArg.includes("/") ? targetArg.replace(/\//g, "__") : targetArg;
  const abs = path.join(runRoot, safe);
  if (fs.existsSync(abs) && fs.existsSync(path.join(abs, "spec.json")) && fs.existsSync(path.join(abs, "candidates"))) {
    return { name: safe, abs };
  }
  return null;
}

function loadCandidates(targetDir: string): Array<{ candidate: string; html: string }> {
  const candDir = path.join(targetDir, "candidates");
  const files = fs.readdirSync(candDir).filter((f) => /^candidate-\d{2}\.html$/.test(f));
  const sorted = files.sort((a, b) => a.localeCompare(b, "en"));
  return sorted.map((f) => ({
    candidate: f.replace(/\.html$/, ""),
    html: fs.readFileSync(path.join(candDir, f), "utf-8"),
  }));
}

function normalizeCouncilReviewShape(input: any): any {
  if (!input || typeof input !== "object") return input;
  const obj = input as any;

  // Allow candidates to come back as an object keyed by candidate id.
  if (obj.candidates && !Array.isArray(obj.candidates) && typeof obj.candidates === "object") {
    obj.candidates = Object.entries(obj.candidates).map(([candidate, v]) => ({
      candidate,
      ...(v as any),
    }));
  }

  if (Array.isArray(obj.candidates)) {
    obj.candidates = obj.candidates.map((c: any) => {
      const out = { ...(c ?? {}) };
      if (typeof out.candidate !== "string" && typeof out.candidate_id === "string") {
        out.candidate = out.candidate_id;
      }
      if (!Array.isArray(out.pros)) out.pros = [];
      if (!Array.isArray(out.cons)) out.cons = [];
      if (!Array.isArray(out.critical_issues) && out.critical_issues != null) {
        out.critical_issues = Array.isArray(out.critical_issues) ? out.critical_issues : [];
      }
      return out;
    });
  }

  return obj;
}

function validateCouncilReviewOrThrow(
  parsed: unknown,
  expectedCandidates: Set<string>,
): CouncilReview {
  const normalized = normalizeCouncilReviewShape(parsed as any);
  const res = CouncilReviewSchema.safeParse(normalized);
  if (!res.success) {
    const issues = res.error.issues
      .slice(0, 12)
      .map((i) => `${i.path.join(".")}: ${i.message}`)
      .join("; ");
    throw new Error(`Schema mismatch: ${issues}`);
  }

  const got = res.data.candidates.map((c) => c.candidate);
  const gotSet = new Set(got);
  const missing = [...expectedCandidates].filter((x) => !gotSet.has(x));
  const extras = got.filter((x) => !expectedCandidates.has(x));
  const dupes = got.filter((x, i) => got.indexOf(x) !== i);

  if (missing.length || extras.length || dupes.length) {
    throw new Error(
      `Candidate coverage mismatch. missing=[${missing.join(",")}], extras=[${extras.join(",")}], dupes=[${dupes.join(",")}]`,
    );
  }

  const badTop = res.data.top3.filter((x) => !expectedCandidates.has(x));
  if (badTop.length) {
    throw new Error(`top3 contains unknown candidates: ${badTop.join(",")}`);
  }

  const dupTop = res.data.top3.filter((x, i) => res.data.top3.indexOf(x) !== i);
  if (dupTop.length) {
    throw new Error(`top3 contains duplicates: ${dupTop.join(",")}`);
  }

  const expectedTopLen = Math.min(3, expectedCandidates.size);
  if (res.data.top3.length !== expectedTopLen) {
    throw new Error(`top3 length must be ${expectedTopLen} (got ${res.data.top3.length})`);
  }

  return res.data;
}

function buildRepairSystemPrompt(reviewerId: string): string {
  return `You are a JSON repair tool.

Rules:
- Output ONLY valid JSON.
- Do not add markdown.
- Do not change any numeric scores.
- Do not change candidate IDs.
- Do not omit required fields.

You are reviewer_id=${reviewerId}.`;
}

function buildRepairUserPrompt(reviewerId: string, broken: string): string {
  return `Your previous output for reviewer_id=${reviewerId} was not valid JSON.

Fix it so it is valid JSON that matches the expected schema and includes every candidate exactly once.

Return JSON only.

Broken output:
${broken}`;
}

async function getCouncilReview(params: {
  reviewer: Reviewer;
  target: { slug: string; title: string; query: string; notes?: string };
  candidates: Array<{ candidate: string; html: string }>;
  debugDir: string;
}): Promise<CouncilReview> {
  const { reviewer, target, candidates, debugDir } = params;

  const expectedCandidates = new Set(candidates.map((c) => c.candidate));

  const system = buildCouncilSystemPrompt(reviewer.reviewerId);
  const userBase = buildCouncilUserPrompt({ reviewerId: reviewer.reviewerId, target, candidates });

  const tryParse = (text: string): unknown | null => {
    try {
      return JSON.parse(extractJsonObjectText(text));
    } catch {
      return null;
    }
  };

  const repairAndParse = async (brokenText: string, label: string): Promise<unknown> => {
    const repair = await openrouterChat(
      reviewer.modelId,
      buildRepairSystemPrompt(reviewer.reviewerId),
      buildRepairUserPrompt(reviewer.reviewerId, brokenText.slice(0, 45000)),
      {
        temperature: 0,
        maxTokens: COUNCIL_MAX_TOKENS,
        // Try to force valid JSON.
        responseFormat: COUNCIL_USE_STRUCTURED ? councilResponseFormat() : { type: "json_object" },
        plugins: COUNCIL_USE_RESPONSE_HEALING ? responseHealingPlugin() : undefined,
      },
    );

    fs.writeFileSync(path.join(debugDir, `${reviewer.reviewerId}.${label}.repair.raw.txt`), repair.text);

    const parsed = tryParse(repair.text);
    if (!parsed) {
      throw new Error("JSON repair did not produce parseable JSON");
    }
    return parsed;
  };

  const tryStructured = async (label: string, extraUser: string): Promise<string> => {
    const resp = await openrouterChat(reviewer.modelId, system, userBase + extraUser, {
      temperature: COUNCIL_TEMP,
      maxTokens: COUNCIL_MAX_TOKENS,
      responseFormat: COUNCIL_USE_STRUCTURED ? councilResponseFormat() : undefined,
      plugins: COUNCIL_USE_RESPONSE_HEALING ? responseHealingPlugin() : undefined,
    });
    fs.writeFileSync(path.join(debugDir, `${reviewer.reviewerId}.${label}.raw.txt`), resp.text);
    return resp.text;
  };

  const runFull = async (label: string, extraUser: string): Promise<string> => {
    try {
      return await tryStructured(label, extraUser);
    } catch (e: any) {
      const msg = String(e?.message ?? e);
      const looksLikeUnsupported = /response_format|json_schema|structured|plugins|response-healing|unknown parameter|not supported/i.test(msg);
      if (!looksLikeUnsupported) throw e;

      // Fallback: no structured outputs or plugins.
      const resp = await openrouterChat(reviewer.modelId, system, userBase + extraUser, {
        temperature: COUNCIL_TEMP,
        maxTokens: COUNCIL_MAX_TOKENS,
      });
      fs.writeFileSync(path.join(debugDir, `${reviewer.reviewerId}.${label}.fallback.raw.txt`), resp.text);
      return resp.text;
    }
  };

  // Attempt 1
  const t1 = await runFull("attempt1", "");
  const p1 = tryParse(t1);
  if (p1) {
    try {
      return validateCouncilReviewOrThrow(p1, expectedCandidates);
    } catch {
      // fall through
    }
  } else {
    // Parse failed, attempt repair.
    const repaired = await repairAndParse(t1, "attempt1");
    try {
      return validateCouncilReviewOrThrow(repaired, expectedCandidates);
    } catch {
      // fall through
    }
  }

  // Attempt 2: stronger instruction, still same candidates.
  const t2 = await runFull(
    "attempt2",
    "\n\nIMPORTANT: Return a single JSON object ONLY. Use key \"candidate\" (not candidate_id). Include ALL candidates exactly once. Keep overall_notes items under 600 chars.",
  );

  const p2 = tryParse(t2) ?? (await repairAndParse(t2, "attempt2"));
  return validateCouncilReviewOrThrow(p2, expectedCandidates);
}

async function reviewTarget(targetDirName: string, targetDirAbs: string): Promise<void> {
  const spec = JSON.parse(fs.readFileSync(path.join(targetDirAbs, "spec.json"), "utf-8")) as any;
  if (spec.kind !== "article") {
    console.error(`Skipping non-article target: ${spec.slug} (kind=${spec.kind})`);
    return;
  }

  const slug = String(spec.slug ?? targetDirName.replace(/__/g, "/"));
  const title = String(spec.title ?? slug);
  const query = String(spec.query ?? "");
  const notes = typeof spec.notes === "string" ? spec.notes : undefined;

  const candidates = loadCandidates(targetDirAbs);
  if (candidates.length === 0) {
    throw new Error(`No candidates found in ${targetDirAbs}/candidates`);
  }

  console.log(`\nCouncil reviewing target: ${slug} (candidates=${candidates.length})`);

  const councilDir = path.join(RUN_ROOT, "council", targetDirName);
  ensureDir(councilDir);

  const summaryPath = path.join(councilDir, "summary.json");
  if (COUNCIL_RESUME && fs.existsSync(summaryPath)) {
    console.log(`  (resume) skipping, already has summary.json`);
    return;
  }

  const privateMap: any = {
    runId,
    createdAt: new Date().toISOString(),
    target: { slug },
    reviewers: Object.fromEntries(REVIEWERS.map((r) => [r.reviewerId, r.modelId])),
  };
  ensureDir(path.dirname(PRIVATE_MAP_PATH));
  fs.writeFileSync(PRIVATE_MAP_PATH, JSON.stringify(privateMap, null, 2));

  // Run all reviewers in parallel.
  const results = await Promise.allSettled(
    REVIEWERS.map(async (reviewer) => {
      const debugDir = path.join(councilDir, "debug");
      ensureDir(debugDir);

      const review = await getCouncilReview({
        reviewer,
        target: { slug, title, query, notes },
        candidates,
        debugDir,
      });

      const outPath = path.join(councilDir, `${reviewer.reviewerId}.json`);
      fs.writeFileSync(outPath, JSON.stringify(review, null, 2));
      console.log(`  - ${reviewer.reviewerId}: ok`);
      return review;
    }),
  );

  const failures = results.filter((r) => r.status === "rejected") as PromiseRejectedResult[];
  if (failures.length) {
    for (const f of failures) console.error(f.reason);
    throw new Error(`Council review failed for ${failures.length}/${REVIEWERS.length} reviewers. See council debug raw outputs.`);
  }

  const reviews = (results as PromiseFulfilledResult<CouncilReview>[]).map((r) => r.value);


  // Aggregate.
  const byCandidate: Record<string, any> = {};
  for (const c of candidates) {
    byCandidate[c.candidate] = {
      candidate: c.candidate,
      perReviewer: {},
      dims: {},
      meanOverall: 0,
      stdevOverall: 0,
      top3Count: 0,
    };
  }

  for (const r of reviews) {
    // top3 presence
    for (const cid of r.top3) {
      if (byCandidate[cid]) byCandidate[cid].top3Count++;
    }

    for (const cr of r.candidates) {
      const overall = overallFromScores(cr.scores);
      byCandidate[cr.candidate].perReviewer[r.reviewer_id] = {
        overall,
        scores: cr.scores,
      };
    }
  }

  // Compute means and per-dimension means
  const dimKeys = Object.keys((reviews[0]?.candidates?.[0] as any)?.scores ?? {}) as Array<keyof z.infer<typeof CandidateScoreSchema>>;

  for (const cid of Object.keys(byCandidate)) {
    const overallVals = reviews
      .map((r) => byCandidate[cid].perReviewer[r.reviewer_id]?.overall)
      .filter((n: any) => typeof n === "number") as number[];

    byCandidate[cid].meanOverall = average(overallVals);
    byCandidate[cid].stdevOverall = stddev(overallVals);

    const dimMeans: Record<string, number> = {};
    for (const k of dimKeys) {
      const vals = reviews
        .map((r) => byCandidate[cid].perReviewer[r.reviewer_id]?.scores?.[k])
        .filter((n: any) => typeof n === "number") as number[];
      dimMeans[k] = average(vals);
    }
    byCandidate[cid].dims = dimMeans;
  }

  const ranking = Object.values(byCandidate)
    .sort((a: any, b: any) => b.meanOverall - a.meanOverall)
    .map((x: any) => x.candidate);

  const perReviewerRankings: Record<string, string[]> = {};
  for (const r of reviews) {
    const rows = r.candidates
      .map((cr) => ({
        candidate: cr.candidate,
        overall: overallFromScores(cr.scores),
      }))
      .sort((a, b) => b.overall - a.overall);
    perReviewerRankings[r.reviewer_id] = rows.map((x) => x.candidate);
  }

  const summary = {
    runId,
    target: { slug, title, query, notes },
    reviewers: REVIEWERS.map((r) => ({ reviewer_id: r.reviewerId })),
    candidateCount: candidates.length,
    consensus: {
      ranking,
      byCandidate,
    },
    perReviewer: {
      rankings: perReviewerRankings,
      top3: Object.fromEntries(reviews.map((r) => [r.reviewer_id, r.top3])),
    },
  };

  fs.writeFileSync(path.join(councilDir, "summary.json"), JSON.stringify(summary, null, 2));

  const md = `# Council summary (blind)\n\nTarget: /${slug}\n\nConsensus ranking (by mean overall):\n${ranking.map((c, i) => `${i + 1}. ${c}`).join("\n")}\n\nTop-3 votes:\n${Object.values(byCandidate)
    .sort((a: any, b: any) => b.top3Count - a.top3Count)
    .map((c: any) => `- ${c.candidate}: ${c.top3Count}/3`)
    .join("\n")}\n\nPer reviewer top-3:\n${reviews.map((r) => `- ${r.reviewer_id}: ${r.top3.join(", ")}`).join("\n")}\n`;

  fs.writeFileSync(path.join(councilDir, "summary.md"), md);

  console.log(`  Wrote: ${path.join(councilDir, "summary.json")}`);
}

async function main(): Promise<void> {
  const targets = TARGET_FILTER
    ? [resolveTargetDir(RUN_ROOT, TARGET_FILTER)].filter(Boolean) as Array<{ name: string; abs: string }>
    : listTargetDirs(RUN_ROOT);

  if (targets.length === 0) {
    console.error("No target dirs found");
    process.exit(1);
  }

  if (targets.length > 1) {
    console.log(`Found ${targets.length} targets, running council review sequentially (one target per council prompt).`);
  }

  for (const t of targets) {
    await reviewTarget(t.name, t.abs);
  }

  console.log(`\nDone. Council outputs under: ${path.join(RUN_ROOT, "council")}`);
  console.log(`Private reviewer map (do not share): ${PRIVATE_MAP_PATH}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
