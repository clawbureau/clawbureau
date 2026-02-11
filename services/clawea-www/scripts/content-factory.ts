#!/usr/bin/env npx tsx
/**
 * AEO-CONTENT-004 - Autonomous Content Factory + Quality Council pipeline.
 *
 * Deterministic stages:
 * 1) campaign manifest load + deterministic run ID
 * 2) generation (model-writeoff) with resumable target execution
 * 3) council review/aggregate
 * 4) council auto-selection + fail-closed gating
 * 5) publish orchestration (canary/full) + rollback manifest
 * 6) weekly content ops summary artifact
 *
 * Required artifacts under artifacts/ops/clawea-www/<stamp>/:
 * - campaign-summary.json
 * - council-gate-summary.json
 * - publish-manifest.json
 * - rollback-manifest.json
 * - quality-failure-breakdown.json
 * - content-ops-weekly-summary.json
 */

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { spawnSync } from "node:child_process";

import { z } from "zod";

import { generateAllTopics } from "./taxonomy";

type RunMode = "dry-run" | "full-run";
type PublishMode = "canary" | "full";

type CommandResult = {
  command: string;
  args: string[];
  cwd: string;
  ok: boolean;
  exitCode: number;
  durationMs: number;
  stdoutTail: string;
  stderrTail: string;
};

type StopCondition = {
  code: string;
  message: string;
  at: string;
  stage: string;
};

type UsageTotals = {
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
  estimatedUsd: number;
  entries: number;
  byModel: Array<{
    modelId: string;
    candidates: number;
    promptTokens: number;
    completionTokens: number;
    totalTokens: number;
    estimatedUsd: number;
  }>;
};

const CandidateDimSchema = z.object({
  directness: z.number(),
  specificity: z.number(),
  openclaw_alignment: z.number(),
  clawea_alignment: z.number(),
  enterprise_correctness: z.number(),
  security_quality: z.number(),
  policy_quality: z.number(),
  proof_quality: z.number(),
  structure_style: z.number(),
});

const CampaignManifestSchema = z.object({
  schema_name: z.literal("clawea.content_campaign"),
  schema_version: z.literal("1.0"),
  campaign: z.object({
    id: z.string().min(3).max(80).regex(/^[a-z0-9][a-z0-9-]+$/),
    name: z.string().min(3).max(200),
    seed: z.string().min(3).max(120),
    notes: z.string().max(2000).optional(),
  }),
  execution: z.object({
    mode: z.enum(["dry-run", "full-run"]).optional(),
    resume: z.boolean().optional(),
    simulate: z.boolean().optional(),
    run_root: z.string().min(1).optional(),
  }).optional(),
  targets: z.object({
    slugs: z.array(z.string().min(1)).min(1).optional(),
    top_n: z.number().int().min(1).max(500).optional(),
    indexable_only: z.boolean().optional(),
    exclude_categories: z.array(z.string().min(1).max(80)).optional(),
  }),
  source_allowlist: z.object({
    domains: z.array(z.string().min(3).max(200)).min(1),
  }),
  model_pool: z.array(
    z.object({
      id: z.string().min(3).max(160),
      enabled: z.boolean().optional(),
      cost_usd_per_1m_input_tokens: z.number().min(0).optional(),
      cost_usd_per_1m_output_tokens: z.number().min(0).optional(),
    }),
  ).min(1),
  council: z.object({
    min_mean_overall: z.number().min(1).max(5),
    min_dimension_score: z.number().min(1).max(5),
    max_stdev_overall: z.number().min(0).max(5),
    require_top3_votes: z.number().int().min(0).max(3).optional(),
  }),
  publish: z.object({
    mode: z.enum(["canary", "full"]),
    canary_size: z.number().int().min(1).max(500),
    apply_to_articles: z.boolean().optional(),
    upload_to_r2: z.boolean().optional(),
    auto_index: z.boolean().optional(),
    bucket: z.string().min(1).max(120).optional(),
  }),
  budgets: z.object({
    max_candidates: z.number().int().min(1).max(20_000),
    max_prompt_tokens: z.number().int().min(1).optional(),
    max_completion_tokens: z.number().int().min(1).optional(),
    max_total_tokens: z.number().int().min(1),
    max_usd: z.number().min(0),
    max_retryable_failures: z.number().int().min(0).max(500),
  }),
  reporting: z.object({
    base_url: z.string().min(1).optional(),
    days: z.number().int().min(1).max(90).optional(),
  }).optional(),
});

type CampaignManifest = z.infer<typeof CampaignManifestSchema>;

type GateCandidateOutcome = {
  candidate: string;
  meanOverall: number;
  stdevOverall: number;
  top3Count: number;
  dimensionMins: number;
  reasons: string[];
  passed: boolean;
};

type GateTargetOutcome = {
  slug: string;
  selectedCandidate: string | null;
  selectedMeanOverall: number | null;
  selectedTop3Votes: number | null;
  status: "promoted" | "quarantined";
  reasons: string[];
  considered: GateCandidateOutcome[];
};

const args = process.argv.slice(2);

const getArg = (name: string) => {
  const idx = args.indexOf(`--${name}`);
  return idx >= 0 && idx + 1 < args.length ? args[idx + 1] : undefined;
};

const hasFlag = (name: string) => args.includes(`--${name}`);

const manifestArg = getArg("manifest") ?? path.resolve(import.meta.dirname ?? ".", "../src/content/content-campaign.v1.json");
const manifestPath = path.resolve(manifestArg);

if (!fs.existsSync(manifestPath)) {
  console.error(`Campaign manifest not found: ${manifestPath}`);
  process.exit(1);
}

const modeOverride = getArg("mode") as RunMode | undefined;
if (modeOverride && modeOverride !== "dry-run" && modeOverride !== "full-run") {
  console.error(`Invalid --mode: ${modeOverride}`);
  process.exit(1);
}

const publishModeOverride = getArg("publish-mode") as PublishMode | undefined;
if (publishModeOverride && publishModeOverride !== "canary" && publishModeOverride !== "full") {
  console.error(`Invalid --publish-mode: ${publishModeOverride}`);
  process.exit(1);
}

const stamp = getArg("stamp") ?? new Date().toISOString().replace(/[:.]/g, "-");
const outDir = path.resolve(
  getArg("out-dir") ?? path.resolve(import.meta.dirname ?? ".", `../artifacts/ops/clawea-www/${stamp}`),
);

const forceSimulate = hasFlag("simulate");
const forceResume = hasFlag("resume");
const forceApply = hasFlag("apply");

const serviceRoot = path.resolve(import.meta.dirname ?? ".", "..");
const articlesDir = path.resolve(serviceRoot, "articles");

function ensureDir(dir: string): void {
  fs.mkdirSync(dir, { recursive: true });
}

function readJson<T>(filePath: string): T {
  return JSON.parse(fs.readFileSync(filePath, "utf-8")) as T;
}

function writeJson(filePath: string, data: unknown): void {
  ensureDir(path.dirname(filePath));
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

function stableValue(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(stableValue);
  if (v && typeof v === "object") {
    const obj = v as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(obj).sort((a, b) => a.localeCompare(b, "en"))) {
      out[k] = stableValue(obj[k]);
    }
    return out;
  }
  return v;
}

function stableStringify(v: unknown): string {
  return JSON.stringify(stableValue(v));
}

function sha256(input: string): string {
  return crypto.createHash("sha256").update(input).digest("hex");
}

function hashFile(filePath: string): string {
  const h = crypto.createHash("sha256");
  h.update(fs.readFileSync(filePath));
  return h.digest("hex");
}

function normalizeDomain(domain: string): string {
  return domain
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/^\./, "")
    .replace(/\/$/, "");
}

function safeFolderFromSlug(slug: string): string {
  return slug.replace(/^\//, "").replace(/\//g, "__");
}

function normalizeSlug(s: string): string {
  return s.replace(/^\//, "").trim();
}

function commandTail(s: string, max = 5000): string {
  if (!s) return "";
  if (s.length <= max) return s;
  return s.slice(s.length - max);
}

function runCommand(command: string, commandArgs: string[], cwd: string, env?: Record<string, string>): CommandResult {
  const started = Date.now();
  const res = spawnSync(command, commandArgs, {
    cwd,
    env: {
      ...process.env,
      ...(env ?? {}),
    },
    encoding: "utf8",
  });

  const durationMs = Date.now() - started;
  return {
    command,
    args: commandArgs,
    cwd,
    ok: (res.status ?? 1) === 0,
    exitCode: res.status ?? 1,
    durationMs,
    stdoutTail: commandTail(String(res.stdout ?? "")),
    stderrTail: commandTail(String(res.stderr ?? "")),
  };
}

function resolveTargets(manifest: CampaignManifest): string[] {
  const topicIndex = generateAllTopics();
  const bySlug = new Map(topicIndex.map((t) => [t.slug, t] as const));

  if (manifest.targets.slugs?.length) {
    const out = manifest.targets.slugs.map((s) => normalizeSlug(s));
    for (const slug of out) {
      if (!bySlug.has(slug)) {
        throw new Error(`Unknown target slug in manifest.targets.slugs: ${slug}`);
      }
    }
    return [...new Set(out)].sort((a, b) => a.localeCompare(b, "en"));
  }

  const topN = manifest.targets.top_n ?? 0;
  if (topN <= 0) {
    throw new Error("Manifest must provide targets.slugs or targets.top_n");
  }

  const exclude = new Set((manifest.targets.exclude_categories ?? []).map((x) => x.toLowerCase()));
  const indexableOnly = manifest.targets.indexable_only !== false;

  return topicIndex
    .filter((t) => (indexableOnly ? t.indexable === true : true))
    .filter((t) => !exclude.has(String(t.category).toLowerCase()))
    .sort((a, b) => (b.priority - a.priority) || a.slug.localeCompare(b.slug, "en"))
    .slice(0, topN)
    .map((t) => t.slug);
}

function deterministicRunId(manifest: CampaignManifest, targetSlugs: string[], modelIds: string[]): string {
  const stable = stableStringify({
    schema: `${manifest.schema_name}@${manifest.schema_version}`,
    campaign: manifest.campaign,
    targets: targetSlugs,
    models: modelIds,
    source_allowlist: manifest.source_allowlist,
    council: manifest.council,
    publish: manifest.publish,
    budgets: manifest.budgets,
  });

  const digest = sha256(stable).slice(0, 12);
  return `${manifest.campaign.id}-${manifest.campaign.seed}-${digest}`;
}

function loadCampaignState(statePath: string, runId: string, manifestHash: string, mode: RunMode, publishMode: PublishMode) {
  if (fs.existsSync(statePath)) {
    try {
      const parsed = readJson<any>(statePath);
      return {
        ...parsed,
        runId,
        manifestHash,
        mode,
        publishMode,
      };
    } catch {
      // fall through and recreate
    }
  }

  return {
    runId,
    manifestHash,
    mode,
    publishMode,
    startedAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    steps: {
      generation: { status: "pending", details: null },
      council: { status: "pending", details: null },
      gate: { status: "pending", details: null },
      publish: { status: "pending", details: null },
      reporting: { status: "pending", details: null },
    },
    stopConditions: [] as StopCondition[],
    commands: [] as CommandResult[],
  };
}

function saveCampaignState(statePath: string, state: any): void {
  state.updatedAt = new Date().toISOString();
  writeJson(statePath, state);
}

function addStopCondition(state: any, stage: string, code: string, message: string): void {
  const next: StopCondition = {
    code,
    message,
    stage,
    at: new Date().toISOString(),
  };
  state.stopConditions.push(next);
}

function loadRunUsage(runRoot: string): {
  entries: Array<{
    slug: string;
    candidate: string;
    promptTokens: number;
    completionTokens: number;
    totalTokens: number;
  }>;
} {
  const usagePath = path.join(runRoot, "RUN_USAGE.json");
  if (!fs.existsSync(usagePath)) {
    return { entries: [] };
  }

  const raw = readJson<any>(usagePath);
  const entries = Array.isArray(raw?.entries)
    ? raw.entries
      .filter((x: any) => x && typeof x.slug === "string" && typeof x.candidate === "string")
      .map((x: any) => ({
        slug: normalizeSlug(String(x.slug)),
        candidate: String(x.candidate),
        promptTokens: Number(x.promptTokens ?? 0) || 0,
        completionTokens: Number(x.completionTokens ?? 0) || 0,
        totalTokens: Number(x.totalTokens ?? 0) || 0,
      }))
    : [];

  return { entries };
}

function loadPrivateModelMap(runId: string): Record<string, Record<string, string>> {
  const mapPath = path.join(os.homedir(), ".clawbureau-secrets", `clawea-model-writeoff-map.${runId}.json`);
  if (!fs.existsSync(mapPath)) return {};

  try {
    const parsed = readJson<any>(mapPath);
    const out: Record<string, Record<string, string>> = {};
    const articles = parsed?.articles;
    if (!articles || typeof articles !== "object") return {};

    for (const [slug, row] of Object.entries(articles as Record<string, any>)) {
      const candidates = row?.candidates;
      if (!candidates || typeof candidates !== "object") continue;
      out[normalizeSlug(slug)] = Object.fromEntries(
        Object.entries(candidates)
          .filter(([, model]) => typeof model === "string")
          .map(([candidate, model]) => [String(candidate), String(model)]),
      );
    }

    return out;
  } catch {
    return {};
  }
}

function usageWithCosts(runId: string, runRoot: string, modelPool: CampaignManifest["model_pool"]): UsageTotals {
  const usage = loadRunUsage(runRoot);
  const privateMap = loadPrivateModelMap(runId);
  const modelIds = modelPool.filter((m) => m.enabled !== false).map((m) => m.id);
  const fallbackModel = modelIds[0] ?? "unknown";

  const costByModel = new Map(
    modelPool.map((m) => [
      m.id,
      {
        inPer1m: Number(m.cost_usd_per_1m_input_tokens ?? 0),
        outPer1m: Number(m.cost_usd_per_1m_output_tokens ?? 0),
      },
    ]),
  );

  const agg = new Map<string, {
    modelId: string;
    candidates: number;
    promptTokens: number;
    completionTokens: number;
    totalTokens: number;
    estimatedUsd: number;
  }>();

  let promptTokens = 0;
  let completionTokens = 0;
  let totalTokens = 0;
  let estimatedUsd = 0;

  for (const row of usage.entries) {
    const model = privateMap[row.slug]?.[row.candidate]
      ?? modelIds[(Math.max(1, Number(row.candidate.match(/candidate-(\d+)/)?.[1] ?? "1")) - 1) % Math.max(1, modelIds.length)]
      ?? fallbackModel;

    const pricing = costByModel.get(model) ?? { inPer1m: 0, outPer1m: 0 };
    const rowUsd = (row.promptTokens / 1_000_000) * pricing.inPer1m
      + (row.completionTokens / 1_000_000) * pricing.outPer1m;

    promptTokens += row.promptTokens;
    completionTokens += row.completionTokens;
    totalTokens += row.totalTokens;
    estimatedUsd += rowUsd;

    const existing = agg.get(model) ?? {
      modelId: model,
      candidates: 0,
      promptTokens: 0,
      completionTokens: 0,
      totalTokens: 0,
      estimatedUsd: 0,
    };

    existing.candidates += 1;
    existing.promptTokens += row.promptTokens;
    existing.completionTokens += row.completionTokens;
    existing.totalTokens += row.totalTokens;
    existing.estimatedUsd += rowUsd;

    agg.set(model, existing);
  }

  const byModel = [...agg.values()]
    .sort((a, b) => (b.estimatedUsd - a.estimatedUsd) || a.modelId.localeCompare(b.modelId, "en"));

  return {
    promptTokens,
    completionTokens,
    totalTokens,
    estimatedUsd: Number(estimatedUsd.toFixed(6)),
    entries: usage.entries.length,
    byModel,
  };
}

function isRetryableOutput(out: string): boolean {
  return /(429|rate\s*limit|resource_exhausted|quota|too\s*many\s*requests)/i.test(out);
}

function targetComplete(runRoot: string, slug: string, expectedCandidates: number): boolean {
  const targetDir = path.join(runRoot, safeFolderFromSlug(slug));
  if (!fs.existsSync(targetDir)) return false;

  const candidatesDir = path.join(targetDir, "candidates");
  if (!fs.existsSync(candidatesDir)) return false;

  const reports = fs.readdirSync(candidatesDir).filter((f) => f.endsWith(".report.json"));
  return reports.length >= expectedCandidates;
}

function seedSyntheticRun(runRoot: string, slugs: string[], modelIds: string[], allowlistDomains: string[]): void {
  ensureDir(runRoot);
  const topicBySlug = new Map(generateAllTopics().map((t) => [t.slug, t] as const));

  const usageEntries: Array<any> = [];

  const councilRoot = path.join(runRoot, "council");
  ensureDir(councilRoot);

  for (const slug of slugs) {
    const topic = topicBySlug.get(slug);
    const title = topic?.title ?? `${slug} | Claw EA`;
    const targetDir = path.join(runRoot, safeFolderFromSlug(slug));
    const candidatesDir = path.join(targetDir, "candidates");
    ensureDir(candidatesDir);

    const spec = {
      kind: "article",
      slug,
      title,
      query: `${title} enterprise controls`,
      notes: "synthetic fixture run",
      retrieval: {
        exaSearchAndContents: {
          numResults: 6,
          includeDomains: allowlistDomains,
          maxCharacters: 1200,
          maxAgeHours: 720,
        },
      },
    };
    writeJson(path.join(targetDir, "spec.json"), spec);

    const sourceDomainA = allowlistDomains[0] ?? "owasp.org";
    const sourceDomainB = allowlistDomains[1] ?? "developers.cloudflare.com";

    writeJson(path.join(targetDir, "sources.json"), [
      {
        title: `Official source A for ${slug}`,
        url: `https://${sourceDomainA}/docs/${slug.replace(/\//g, "-")}`,
        text: "Synthetic source context for deterministic simulation.",
      },
      {
        title: `Official source B for ${slug}`,
        url: `https://${sourceDomainB}/guides/${slug.replace(/\//g, "-")}`,
        text: "Synthetic source context for deterministic simulation.",
      },
    ]);

    const candidateRows = [
      {
        candidate: "candidate-01",
        meanOverall: 4.4,
        stdevOverall: 0.31,
        top3Count: 3,
        pass: true,
        report: {
          kind: "article",
          generatedAt: new Date().toISOString(),
          ms: 850,
          chars: 4200,
          usage: { promptTokens: 1150, completionTokens: 870, totalTokens: 2020 },
          truncated: false,
          sanitizer_failed_reason: null,
          lint: { ok: true, issues: [] },
          structure: { missingH2: [], orderOk: true, faqQCount: 4, faqCountOk: true },
          citations: {
            hrefCount: 7,
            hrefCountPre: 7,
            hasOpenclawCitation: true,
            hasExternalCitation: true,
            needsMicrosoft: false,
            hasMicrosoftCitation: false,
            violations_pre: [],
            violations: [],
          },
          claim_state_violations: [],
          endpoint_invention_violations: [],
          shipped_planned_mismatch: [],
        },
      },
      {
        candidate: "candidate-02",
        meanOverall: 3.2,
        stdevOverall: 0.62,
        top3Count: 1,
        pass: false,
        report: {
          kind: "article",
          generatedAt: new Date().toISOString(),
          ms: 810,
          chars: 3950,
          usage: { promptTokens: 1120, completionTokens: 760, totalTokens: 1880 },
          truncated: false,
          sanitizer_failed_reason: null,
          lint: { ok: true, issues: [] },
          structure: { missingH2: [], orderOk: true, faqQCount: 3, faqCountOk: true },
          citations: { violations: [] },
          claim_state_violations: ["synthetic_claim_state_violation"],
          endpoint_invention_violations: [],
          shipped_planned_mismatch: [],
        },
      },
      {
        candidate: "candidate-03",
        meanOverall: 2.9,
        stdevOverall: 0.71,
        top3Count: 0,
        pass: false,
        report: {
          kind: "article",
          generatedAt: new Date().toISOString(),
          ms: 790,
          chars: 3100,
          usage: { promptTokens: 1090, completionTokens: 650, totalTokens: 1740 },
          truncated: false,
          sanitizer_failed_reason: "href_violations_remain_after_sanitize",
          lint: { ok: true, issues: [] },
          structure: { missingH2: ["Threat model"], orderOk: false, faqQCount: 2, faqCountOk: false },
          citations: { violations: ["https://example.com/not-allowed"] },
          claim_state_violations: [],
          endpoint_invention_violations: ["synthetic_endpoint_invention"],
          shipped_planned_mismatch: [],
        },
      },
    ];

    for (const row of candidateRows) {
      const html = `<h1>${title}</h1>\n<p>Synthetic deterministic fixture for ${slug} (${row.candidate}).</p>\n<h2>Step-by-step runbook</h2>\n<p>Runbook content.</p>\n<h2>Threat model</h2>\n<p>Threat model content.</p>\n<h2>Policy-as-code example</h2>\n<p>Policy content.</p>\n<h2>What proof do you get?</h2>\n<p>Proof content.</p>\n<h2>Rollback posture</h2>\n<p>Rollback content.</p>\n<h2>FAQ</h2>\n<h3>What changes in enterprise mode?</h3><p>Enterprise details.</p>\n<h3>How is policy enforced?</h3><p>Policy enforcement details.</p>\n<h3>How do approvals work?</h3><p>Approval details.</p>\n<h2>Sources</h2>\n<ul><li><a href="https://${sourceDomainA}/docs/${slug.replace(/\//g, "-")}">Source A</a></li></ul>`;
      fs.writeFileSync(path.join(candidatesDir, `${row.candidate}.html`), html);
      writeJson(path.join(candidatesDir, `${row.candidate}.report.json`), {
        candidate: row.candidate,
        ...row.report,
      });

      usageEntries.push({
        slug,
        candidate: row.candidate,
        kind: "article",
        promptTokens: row.report.usage.promptTokens,
        completionTokens: row.report.usage.completionTokens,
        totalTokens: row.report.usage.totalTokens,
        chars: row.report.chars,
        ms: row.report.ms,
        generatedAt: row.report.generatedAt,
      });
    }

    const byCandidate = Object.fromEntries(
      candidateRows.map((r) => [
        r.candidate,
        {
          candidate: r.candidate,
          meanOverall: r.meanOverall,
          stdevOverall: r.stdevOverall,
          top3Count: r.top3Count,
          dims: {
            directness: r.pass ? 4.5 : 3,
            specificity: r.pass ? 4.3 : 3,
            openclaw_alignment: r.pass ? 4.4 : 3,
            clawea_alignment: r.pass ? 4.4 : 2.8,
            enterprise_correctness: r.pass ? 4.2 : 2.7,
            security_quality: r.pass ? 4.6 : 2.8,
            policy_quality: r.pass ? 4.4 : 2.9,
            proof_quality: r.pass ? 4.5 : 2.8,
            structure_style: r.pass ? 4.1 : 2.5,
          },
        },
      ]),
    );

    const councilSummary = {
      runId: path.basename(runRoot),
      target: { slug, title, query: `${title} enterprise controls` },
      reviewers: [{ reviewer_id: "reviewer-01" }, { reviewer_id: "reviewer-02" }, { reviewer_id: "reviewer-03" }],
      candidateCount: candidateRows.length,
      consensus: {
        ranking: ["candidate-01", "candidate-02", "candidate-03"],
        byCandidate,
      },
      perReviewer: {
        rankings: {
          "reviewer-01": ["candidate-01", "candidate-02", "candidate-03"],
          "reviewer-02": ["candidate-01", "candidate-03", "candidate-02"],
          "reviewer-03": ["candidate-01", "candidate-02", "candidate-03"],
        },
        top3: {
          "reviewer-01": ["candidate-01", "candidate-02", "candidate-03"],
          "reviewer-02": ["candidate-01", "candidate-03", "candidate-02"],
          "reviewer-03": ["candidate-01", "candidate-02", "candidate-03"],
        },
      },
    };

    const councilTargetDir = path.join(councilRoot, safeFolderFromSlug(slug));
    ensureDir(councilTargetDir);
    writeJson(path.join(councilTargetDir, "summary.json"), councilSummary);
  }

  writeJson(path.join(councilRoot, "aggregate.blind.json"), {
    runId: path.basename(runRoot),
    targetCount: slugs.length,
    targets: slugs.map((slug) => ({ slug, winnerCandidate: "candidate-01", winnerMeanOverall: 4.4 })),
  });

  const totals = usageEntries.reduce(
    (acc, row) => {
      acc.promptTokens += row.promptTokens;
      acc.completionTokens += row.completionTokens;
      acc.totalTokens += row.totalTokens;
      return acc;
    },
    { promptTokens: 0, completionTokens: 0, totalTokens: 0 },
  );

  writeJson(path.join(runRoot, "RUN_USAGE.json"), {
    runId: path.basename(runRoot),
    updatedAt: new Date().toISOString(),
    entries: usageEntries,
    totals,
  });

  // Synthetic private model map to allow model-level costing in simulate mode.
  const privateMapPath = path.join(os.homedir(), ".clawbureau-secrets", `clawea-model-writeoff-map.${path.basename(runRoot)}.json`);
  ensureDir(path.dirname(privateMapPath));

  const articles = Object.fromEntries(
    slugs.map((slug) => [
      slug,
      {
        candidates: {
          "candidate-01": modelIds[0] ?? "synthetic/model-a",
          "candidate-02": modelIds[1] ?? modelIds[0] ?? "synthetic/model-a",
          "candidate-03": modelIds[2] ?? modelIds[0] ?? "synthetic/model-a",
        },
      },
    ]),
  );

  writeJson(privateMapPath, {
    runId: path.basename(runRoot),
    createdAt: new Date().toISOString(),
    articles,
  });
}

function candidateReportReasons(report: any): string[] {
  const reasons: string[] = [];

  if (!report || typeof report !== "object") {
    reasons.push("missing_report");
    return reasons;
  }

  if (report.truncated === true) reasons.push("truncated");
  if (report.lint?.ok === false) reasons.push("lint_not_ok");
  if (report.sanitizer_failed_reason) reasons.push(`sanitizer_failed:${String(report.sanitizer_failed_reason)}`);

  if (Array.isArray(report?.citations?.violations) && report.citations.violations.length > 0) {
    reasons.push("citation_violations");
  }

  if (Array.isArray(report.claim_state_violations) && report.claim_state_violations.length > 0) {
    reasons.push("claim_state_violations");
  }

  if (Array.isArray(report.endpoint_invention_violations) && report.endpoint_invention_violations.length > 0) {
    reasons.push("endpoint_invention_violations");
  }

  if (Array.isArray(report.shipped_planned_mismatch) && report.shipped_planned_mismatch.length > 0) {
    reasons.push("shipped_planned_mismatch");
  }

  if (Array.isArray(report?.structure?.missingH2) && report.structure.missingH2.length > 0) {
    reasons.push("missing_h2");
  }

  if (report?.structure?.orderOk === false) reasons.push("heading_order_invalid");
  if (report?.structure?.faqCountOk === false) reasons.push("faq_count_invalid");

  return [...new Set(reasons)];
}

function evaluateCouncilGate(runRoot: string, manifest: CampaignManifest): {
  summary: {
    runId: string;
    generatedAt: string;
    thresholds: CampaignManifest["council"];
    targets: GateTargetOutcome[];
    promoted: Array<{ slug: string; candidate: string; meanOverall: number; top3Votes: number }>;
    quarantined: Array<{ slug: string; reasons: string[] }>;
    counts: {
      targets: number;
      promoted: number;
      quarantined: number;
      candidateRejections: number;
    };
  };
  failureBreakdown: {
    runId: string;
    generatedAt: string;
    totalFailures: number;
    byReason: Array<{ reason: string; count: number }>;
    byTarget: Array<{ slug: string; reasonCounts: Array<{ reason: string; count: number }> }>;
  };
} {
  const councilRoot = path.join(runRoot, "council");
  const targetDirs = fs.existsSync(councilRoot)
    ? fs.readdirSync(councilRoot, { withFileTypes: true }).filter((d) => d.isDirectory())
    : [];

  const outcomes: GateTargetOutcome[] = [];
  const promoted: Array<{ slug: string; candidate: string; meanOverall: number; top3Votes: number }> = [];
  const quarantined: Array<{ slug: string; reasons: string[] }> = [];

  const globalReasons = new Map<string, number>();
  const perTargetReasons = new Map<string, Map<string, number>>();

  const bump = (map: Map<string, number>, key: string) => {
    map.set(key, (map.get(key) ?? 0) + 1);
  };

  for (const dir of targetDirs) {
    const summaryPath = path.join(councilRoot, dir.name, "summary.json");
    if (!fs.existsSync(summaryPath)) continue;

    const sum = readJson<any>(summaryPath);
    const slug = normalizeSlug(String(sum?.target?.slug ?? dir.name.replace(/__/g, "/")));

    const ranking = Array.isArray(sum?.consensus?.ranking)
      ? sum.consensus.ranking.map((x: any) => String(x))
      : [];

    const byCandidate = (sum?.consensus?.byCandidate ?? {}) as Record<string, any>;

    const considered: GateCandidateOutcome[] = [];

    for (const candidate of ranking) {
      const row = byCandidate[candidate] ?? {};
      const meanOverall = Number(row?.meanOverall ?? 0) || 0;
      const stdevOverall = Number(row?.stdevOverall ?? 0) || 0;
      const top3Count = Number(row?.top3Count ?? 0) || 0;

      const dimsParsed = CandidateDimSchema.safeParse(row?.dims ?? {});
      const dims = dimsParsed.success ? dimsParsed.data : {
        directness: 0,
        specificity: 0,
        openclaw_alignment: 0,
        clawea_alignment: 0,
        enterprise_correctness: 0,
        security_quality: 0,
        policy_quality: 0,
        proof_quality: 0,
        structure_style: 0,
      };

      const dimValues = Object.values(dims);
      const dimensionMins = dimValues.length ? Math.min(...dimValues) : 0;

      const reasons: string[] = [];
      if (meanOverall < manifest.council.min_mean_overall) reasons.push("council_mean_below_threshold");
      if (dimensionMins < manifest.council.min_dimension_score) reasons.push("council_dimension_below_threshold");
      if (stdevOverall > manifest.council.max_stdev_overall) reasons.push("council_stdev_above_threshold");
      if ((manifest.council.require_top3_votes ?? 0) > top3Count) reasons.push("council_top3_votes_below_threshold");

      const reportPath = path.join(runRoot, safeFolderFromSlug(slug), "candidates", `${candidate}.report.json`);
      const report = fs.existsSync(reportPath) ? readJson<any>(reportPath) : null;
      reasons.push(...candidateReportReasons(report));

      const uniqueReasons = [...new Set(reasons)];
      const passed = uniqueReasons.length === 0;

      considered.push({
        candidate,
        meanOverall,
        stdevOverall,
        top3Count,
        dimensionMins,
        reasons: uniqueReasons,
        passed,
      });

      if (!passed) {
        for (const r of uniqueReasons) {
          bump(globalReasons, r);
          const tMap = perTargetReasons.get(slug) ?? new Map<string, number>();
          bump(tMap, r);
          perTargetReasons.set(slug, tMap);
        }
      }
    }

    const winner = considered.find((c) => c.passed) ?? null;

    if (winner) {
      outcomes.push({
        slug,
        selectedCandidate: winner.candidate,
        selectedMeanOverall: winner.meanOverall,
        selectedTop3Votes: winner.top3Count,
        status: "promoted",
        reasons: [],
        considered,
      });

      promoted.push({
        slug,
        candidate: winner.candidate,
        meanOverall: winner.meanOverall,
        top3Votes: winner.top3Count,
      });
    } else {
      const topReasons = considered.length > 0
        ? considered[0].reasons
        : ["no_candidates_found"];

      outcomes.push({
        slug,
        selectedCandidate: null,
        selectedMeanOverall: null,
        selectedTop3Votes: null,
        status: "quarantined",
        reasons: topReasons,
        considered,
      });

      quarantined.push({ slug, reasons: topReasons });
    }
  }

  outcomes.sort((a, b) => a.slug.localeCompare(b.slug, "en"));
  promoted.sort((a, b) => (b.meanOverall - a.meanOverall) || a.slug.localeCompare(b.slug, "en"));
  quarantined.sort((a, b) => a.slug.localeCompare(b.slug, "en"));

  const byReason = [...globalReasons.entries()]
    .map(([reason, count]) => ({ reason, count }))
    .sort((a, b) => (b.count - a.count) || a.reason.localeCompare(b.reason, "en"));

  const byTarget = [...perTargetReasons.entries()]
    .map(([slug, counts]) => ({
      slug,
      reasonCounts: [...counts.entries()]
        .map(([reason, count]) => ({ reason, count }))
        .sort((a, b) => (b.count - a.count) || a.reason.localeCompare(b.reason, "en")),
    }))
    .sort((a, b) => a.slug.localeCompare(b.slug, "en"));

  const candidateRejections = outcomes.reduce((acc, t) => acc + t.considered.filter((c) => !c.passed).length, 0);

  return {
    summary: {
      runId: path.basename(runRoot),
      generatedAt: new Date().toISOString(),
      thresholds: manifest.council,
      targets: outcomes,
      promoted,
      quarantined,
      counts: {
        targets: outcomes.length,
        promoted: promoted.length,
        quarantined: quarantined.length,
        candidateRejections,
      },
    },
    failureBreakdown: {
      runId: path.basename(runRoot),
      generatedAt: new Date().toISOString(),
      totalFailures: byReason.reduce((acc, row) => acc + row.count, 0),
      byReason,
      byTarget,
    },
  };
}

function decodeEntities(s: string): string {
  return s
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'");
}

function stripTags(s: string): string {
  return s.replace(/<[^>]*>/g, " ");
}

function normalizeText(s: string): string {
  return decodeEntities(stripTags(s)).replace(/\s+/g, " ").trim();
}

function extractMeta(html: string, fallbackTitle: string): { description: string; faqs: { q: string; a: string }[] } {
  const firstP = html.match(/<p[^>]*>([\s\S]*?)<\/p>/i);
  const pText = firstP ? normalizeText(firstP[1]).slice(0, 220) : "";
  const description = pText.length >= 50 ? pText : fallbackTitle;

  const faqs: { q: string; a: string }[] = [];
  const faqRegex = /<h[34][^>]*>([^<]*\?)<\/h[34]>\s*<p[^>]*>([\s\S]*?)<\/p>/gi;
  let m: RegExpExecArray | null;
  while ((m = faqRegex.exec(html)) !== null) {
    const q = normalizeText(m[1]);
    const a = normalizeText(m[2]);
    if (q && a) faqs.push({ q, a });
  }

  return { description, faqs };
}

function ensureBofuConversionBlocks(html: string, slug: string): string {
  const isBofu =
    slug.startsWith("tools/") ||
    slug.startsWith("workflows/") ||
    slug.startsWith("compare/") ||
    slug.startsWith("compliance/") ||
    slug.startsWith("channels/");

  if (!isBofu) return html;

  const hasContactCta = /href=["']\/contact["']/i.test(html);
  const hasTrustLink = /href=["']\/trust["']/i.test(html);

  if (hasContactCta && hasTrustLink) return html;

  const block = `
<div class="cta-banner" data-cta="bofu-endcap">
  <h2>Ready to put this workflow into production?</h2>
  <p>Get a scoped deployment plan with Work Policy Contracts, approval gates, and cryptographic proof bundles for your team.</p>
  <a href="/contact" class="cta-btn cta-btn-lg" data-cta="bofu-talk-to-sales">Talk to Sales</a>
  <a href="/trust" class="cta-btn cta-btn-outline cta-btn-lg" style="margin-left:.75rem" data-cta="bofu-trust-layer">Review Trust Layer</a>
</div>
`;

  return `${html.trim()}\n${block}`;
}

function mapSources(src: Array<{ title?: string; url?: string; uri?: string }>): Array<{ title: string; uri: string }> {
  const out: Array<{ title: string; uri: string }> = [];
  const seen = new Set<string>();

  for (const row of src) {
    const uri = String(row?.url ?? row?.uri ?? "").trim();
    if (!uri || seen.has(uri)) continue;
    seen.add(uri);
    const title = String(row?.title ?? uri).trim() || uri;
    out.push({ title, uri });
  }

  return out;
}

function buildArticleJsonFromWinner(runRoot: string, slug: string, candidate: string) {
  const topic = generateAllTopics().find((t) => t.slug === slug);
  const targetDir = path.join(runRoot, safeFolderFromSlug(slug));
  const specPath = path.join(targetDir, "spec.json");
  const htmlPath = path.join(targetDir, "candidates", `${candidate}.html`);
  const reportPath = path.join(targetDir, "candidates", `${candidate}.report.json`);
  const sourcesPath = path.join(targetDir, "sources.json");

  if (!fs.existsSync(specPath)) throw new Error(`missing spec.json for ${slug}`);
  if (!fs.existsSync(htmlPath)) throw new Error(`missing candidate html for ${slug}:${candidate}`);
  if (!fs.existsSync(reportPath)) throw new Error(`missing candidate report for ${slug}:${candidate}`);

  const spec = readJson<any>(specPath);
  const report = readJson<any>(reportPath);
  const html = fs.readFileSync(htmlPath, "utf-8").trim();
  const htmlWithBlocks = ensureBofuConversionBlocks(html, slug);

  const sourceRows = fs.existsSync(sourcesPath) ? readJson<Array<{ title?: string; url?: string; uri?: string }>>(sourcesPath) : [];
  const sources = mapSources(sourceRows);
  const title = String(spec?.title ?? topic?.title ?? slug);
  const category = topic?.category ?? (slug.includes("/") ? slug.split("/")[0] : "pillars");
  const meta = extractMeta(htmlWithBlocks, title);

  return {
    slug,
    title,
    category,
    html: htmlWithBlocks,
    description: meta.description,
    faqs: meta.faqs,
    sources,
    model: candidate,
    generatedAt: String(report?.generatedAt ?? new Date().toISOString()),
    indexable: true,
  };
}

function publishFromGate(
  runRoot: string,
  outDir: string,
  gateSummary: ReturnType<typeof evaluateCouncilGate>["summary"],
  publishMode: PublishMode,
  canarySize: number,
  applyToArticles: boolean,
): {
  publishManifest: any;
  rollbackManifest: any;
} {
  const sortedPromoted = [...gateSummary.promoted].sort((a, b) => {
    if (b.meanOverall !== a.meanOverall) return b.meanOverall - a.meanOverall;
    return a.slug.localeCompare(b.slug, "en");
  });

  const selected = publishMode === "canary"
    ? sortedPromoted.slice(0, Math.min(canarySize, sortedPromoted.length))
    : sortedPromoted;

  const held = publishMode === "canary"
    ? sortedPromoted.slice(Math.min(canarySize, sortedPromoted.length))
    : [];

  const backupsDir = path.join(outDir, "backups");
  if (applyToArticles) ensureDir(backupsDir);

  const publishedRows: any[] = [];
  const rollbackRows: any[] = [];

  for (const row of selected) {
    const article = buildArticleJsonFromWinner(runRoot, row.slug, row.candidate);

    const outPath = path.join(articlesDir, `${row.slug}.json`);
    ensureDir(path.dirname(outPath));

    const existed = fs.existsSync(outPath);
    const previousSha256 = existed ? hashFile(outPath) : null;
    const backupPath = existed ? path.join(backupsDir, `${row.slug.replace(/\//g, "__")}.json`) : null;

    if (applyToArticles) {
      if (existed && backupPath) {
        ensureDir(path.dirname(backupPath));
        fs.copyFileSync(outPath, backupPath);
      }
      fs.writeFileSync(outPath, JSON.stringify(article, null, 2));
    }

    publishedRows.push({
      slug: row.slug,
      candidate: row.candidate,
      meanOverall: row.meanOverall,
      top3Votes: row.top3Votes,
      articlePath: outPath,
      applied: applyToArticles,
    });

    rollbackRows.push({
      slug: row.slug,
      articlePath: outPath,
      rollbackAction: existed ? "restore" : "delete",
      previous: {
        existed,
        sha256: previousSha256,
        backupPath: applyToArticles ? backupPath : null,
      },
    });
  }

  const publishManifest = {
    runId: gateSummary.runId,
    generatedAt: new Date().toISOString(),
    publishMode,
    canarySize,
    applyToArticles,
    requestedPromotions: gateSummary.promoted.length,
    publishedCount: publishedRows.length,
    heldCount: held.length,
    quarantinedCount: gateSummary.quarantined.length,
    published: publishedRows,
    held,
    quarantined: gateSummary.quarantined,
  };

  const rollbackManifest = {
    runId: gateSummary.runId,
    generatedAt: new Date().toISOString(),
    publishMode,
    entries: rollbackRows,
  };

  return { publishManifest, rollbackManifest };
}

function mapCountRows(rows: any[]): Map<string, number> {
  const m = new Map<string, number>();
  if (!Array.isArray(rows)) return m;
  for (const row of rows) {
    const key = String(row?.key ?? "").trim();
    const count = Number(row?.count ?? 0);
    if (!key) continue;
    m.set(key, Number.isFinite(count) ? count : 0);
  }
  return m;
}

function mapCtaFamily(rows: any[]): Map<string, { views: number; clicks: number; actions: number; actionRate: number }> {
  const m = new Map<string, { views: number; clicks: number; actions: number; actionRate: number }>();
  if (!Array.isArray(rows)) return m;

  for (const row of rows) {
    const key = String(row?.pageFamily ?? "").trim();
    if (!key) continue;

    m.set(key, {
      views: Number(row?.views ?? 0) || 0,
      clicks: Number(row?.clicks ?? 0) || 0,
      actions: Number(row?.actions ?? 0) || 0,
      actionRate: Number(row?.actionRate ?? 0) || 0,
    });
  }

  return m;
}

async function authPostJson(url: string, token: string, body: unknown): Promise<any> {
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(body),
  });

  const raw = await res.text();
  let parsed: any = raw;
  try {
    parsed = raw ? JSON.parse(raw) : null;
  } catch {
    // keep raw text
  }

  if (!res.ok) {
    throw new Error(`POST ${url} failed (${res.status}): ${typeof parsed === "string" ? parsed : JSON.stringify(parsed)}`);
  }

  return parsed;
}

async function authGetJson(url: string, token: string): Promise<any> {
  const res = await fetch(url, {
    method: "GET",
    headers: {
      accept: "application/json",
      authorization: `Bearer ${token}`,
    },
  });

  const raw = await res.text();
  let parsed: any = raw;
  try {
    parsed = raw ? JSON.parse(raw) : null;
  } catch {
    // keep raw
  }

  if (!res.ok) {
    throw new Error(`GET ${url} failed (${res.status}): ${typeof parsed === "string" ? parsed : JSON.stringify(parsed)}`);
  }

  return parsed;
}

async function buildContentOpsWeeklySummary(params: {
  manifest: CampaignManifest;
  gateSummary: ReturnType<typeof evaluateCouncilGate>["summary"];
  qualityFailure: ReturnType<typeof evaluateCouncilGate>["failureBreakdown"];
  publishManifest: any;
  usage: UsageTotals;
  mode: RunMode;
}): Promise<any> {
  const token = process.env.INDEX_AUTOMATION_TOKEN ?? process.env.CLAWEA_INDEX_AUTOMATION_TOKEN;
  const baseUrl = (params.manifest.reporting?.base_url ?? "https://clawea.com").replace(/\/+$/, "");
  const days = params.manifest.reporting?.days ?? 7;

  const now = Date.now();
  const periodMs = days * 24 * 60 * 60 * 1000;

  const currentFrom = new Date(now - periodMs).toISOString();
  const currentTo = new Date(now).toISOString();
  const previousFrom = new Date(now - (periodMs * 2)).toISOString();
  const previousTo = new Date(now - periodMs).toISOString();

  const out: any = {
    runId: params.gateSummary.runId,
    generatedAt: new Date().toISOString(),
    mode: params.mode,
    period: {
      days,
      current: { from: currentFrom, to: currentTo },
      previous: { from: previousFrom, to: previousTo },
    },
    pipeline: {
      generatedCandidates: params.usage.entries,
      promoted: params.gateSummary.counts.promoted,
      published: Number(params.publishManifest?.publishedCount ?? 0),
      rejected: params.gateSummary.counts.quarantined,
      qualityFailureReasons: params.qualityFailure.byReason,
      usage: params.usage,
    },
    indexingQueueHealth: null,
    trafficConversionDeltasByPageFamily: [],
    telemetryError: null,
  };

  if (!token) {
    out.telemetryError = "INDEX_AUTOMATION_TOKEN missing; skipping authenticated summary fetch";
    return out;
  }

  try {
    const eventsCurrent = await authPostJson(`${baseUrl}/api/events/summary`, token, {
      from: currentFrom,
      to: currentTo,
      days,
    });

    const eventsPrevious = await authPostJson(`${baseUrl}/api/events/summary`, token, {
      from: previousFrom,
      to: previousTo,
      days,
    });

    const queue = await authGetJson(`${baseUrl}/api/index-queue/status`, token);

    out.indexingQueueHealth = {
      summary: queue?.summary ?? null,
      pendingCount: Array.isArray(queue?.pending) ? queue.pending.length : 0,
      lastRun: queue?.lastRun ?? null,
    };

    const currentPageFamily = mapCountRows(eventsCurrent?.breakdown?.byPageFamily ?? []);
    const previousPageFamily = mapCountRows(eventsPrevious?.breakdown?.byPageFamily ?? []);

    const currentCta = mapCtaFamily(eventsCurrent?.funnel?.ctaByPageFamily ?? []);
    const previousCta = mapCtaFamily(eventsPrevious?.funnel?.ctaByPageFamily ?? []);

    const allFamilies = [...new Set([
      ...currentPageFamily.keys(),
      ...previousPageFamily.keys(),
      ...currentCta.keys(),
      ...previousCta.keys(),
    ])].sort((a, b) => a.localeCompare(b, "en"));

    out.trafficConversionDeltasByPageFamily = allFamilies
      .map((family) => {
        const currTraffic = currentPageFamily.get(family) ?? 0;
        const prevTraffic = previousPageFamily.get(family) ?? 0;

        const currCta = currentCta.get(family) ?? { views: 0, clicks: 0, actions: 0, actionRate: 0 };
        const prevCta = previousCta.get(family) ?? { views: 0, clicks: 0, actions: 0, actionRate: 0 };

        return {
          pageFamily: family,
          traffic: {
            current: currTraffic,
            previous: prevTraffic,
            delta: currTraffic - prevTraffic,
          },
          conversion: {
            viewsCurrent: currCta.views,
            viewsPrevious: prevCta.views,
            viewsDelta: currCta.views - prevCta.views,
            clicksCurrent: currCta.clicks,
            clicksPrevious: prevCta.clicks,
            clicksDelta: currCta.clicks - prevCta.clicks,
            actionsCurrent: currCta.actions,
            actionsPrevious: prevCta.actions,
            actionsDelta: currCta.actions - prevCta.actions,
            actionRateCurrent: currCta.actionRate,
            actionRatePrevious: prevCta.actionRate,
            actionRateDelta: Number((currCta.actionRate - prevCta.actionRate).toFixed(4)),
          },
        };
      })
      .sort((a, b) => {
        const ad = Math.abs(b.traffic.delta) - Math.abs(a.traffic.delta);
        if (ad !== 0) return ad;
        return a.pageFamily.localeCompare(b.pageFamily, "en");
      });
  } catch (err: any) {
    out.telemetryError = String(err?.message ?? err);
  }

  return out;
}

async function main(): Promise<void> {
  ensureDir(outDir);

  const manifestRaw = readJson<unknown>(manifestPath);
  const manifest = CampaignManifestSchema.parse(manifestRaw);

  const targetSlugs = resolveTargets(manifest);
  const modelPool = manifest.model_pool.filter((m) => m.enabled !== false);
  const modelIds = modelPool.map((m) => m.id);
  if (modelIds.length === 0) {
    throw new Error("model_pool has no enabled models");
  }

  const mode: RunMode = modeOverride ?? manifest.execution?.mode ?? "full-run";
  const publishMode: PublishMode = publishModeOverride ?? manifest.publish.mode;
  const resume = forceResume || manifest.execution?.resume !== false;
  const simulate = forceSimulate || manifest.execution?.simulate === true;

  const runId = getArg("run-id") ?? deterministicRunId(manifest, targetSlugs, modelIds);
  const runBase = manifest.execution?.run_root
    ? path.resolve(manifest.execution.run_root)
    : path.resolve(serviceRoot, "sample-output/model-writeoff");

  const runRoot = path.join(runBase, runId);
  ensureDir(runRoot);

  const manifestHash = sha256(stableStringify(manifest));
  const statePath = path.join(runRoot, "CAMPAIGN_STATE.v1.json");
  const state = loadCampaignState(statePath, runId, manifestHash, mode, publishMode);

  const commands: CommandResult[] = Array.isArray(state.commands) ? state.commands : [];
  let retryableFailures = Number(state?.retryableFailures ?? 0) || 0;

  // --- Stage 1: generation ---
  if (mode === "dry-run") {
    state.steps.generation = {
      status: "skipped",
      details: {
        reason: "dry-run",
        targetCount: targetSlugs.length,
        modelCount: modelIds.length,
      },
    };
    saveCampaignState(statePath, state);
  } else if (simulate) {
    seedSyntheticRun(runRoot, targetSlugs, modelIds, manifest.source_allowlist.domains.map(normalizeDomain));
    state.steps.generation = {
      status: "completed",
      details: {
        synthetic: true,
        targetCount: targetSlugs.length,
        modelCount: modelIds.length,
      },
    };
    saveCampaignState(statePath, state);
  } else {
    for (const slug of targetSlugs) {
      if (resume && targetComplete(runRoot, slug, modelIds.length)) {
        continue;
      }

      const env = {
        WRITE_OFF_RUN_ID: runId,
        WRITE_OFF_OUT_ROOT: runRoot,
        WRITE_OFF_APPEND: fs.existsSync(path.join(runRoot, "RUN_SETTINGS.json")) ? "1" : "0",
        WRITE_OFF_TARGET_SLUGS: slug,
        WRITE_OFF_MODELS: modelIds.join(","),
        WRITE_OFF_SOURCE_ALLOWLIST_DOMAINS: manifest.source_allowlist.domains.map(normalizeDomain).join(","),
      };

      const cmd = runCommand(
        "npx",
        ["tsx", path.resolve(serviceRoot, "scripts/model-writeoff.ts")],
        serviceRoot,
        env,
      );
      commands.push(cmd);
      state.commands = commands;

      if (!cmd.ok) {
        if (isRetryableOutput(`${cmd.stdoutTail}\n${cmd.stderrTail}`)) {
          retryableFailures += 1;
          state.retryableFailures = retryableFailures;
        }

        if (retryableFailures > manifest.budgets.max_retryable_failures) {
          addStopCondition(
            state,
            "generation",
            "RETRYABLE_FAILURE_LIMIT",
            `Retryable failures exceeded: ${retryableFailures} > ${manifest.budgets.max_retryable_failures}`,
          );
          break;
        }
      }

      const usage = usageWithCosts(runId, runRoot, modelPool);

      if (usage.entries > manifest.budgets.max_candidates) {
        addStopCondition(
          state,
          "generation",
          "MAX_CANDIDATES_EXCEEDED",
          `Candidate budget exceeded: ${usage.entries} > ${manifest.budgets.max_candidates}`,
        );
        break;
      }

      if (manifest.budgets.max_prompt_tokens && usage.promptTokens > manifest.budgets.max_prompt_tokens) {
        addStopCondition(
          state,
          "generation",
          "MAX_PROMPT_TOKENS_EXCEEDED",
          `Prompt token budget exceeded: ${usage.promptTokens} > ${manifest.budgets.max_prompt_tokens}`,
        );
        break;
      }

      if (manifest.budgets.max_completion_tokens && usage.completionTokens > manifest.budgets.max_completion_tokens) {
        addStopCondition(
          state,
          "generation",
          "MAX_COMPLETION_TOKENS_EXCEEDED",
          `Completion token budget exceeded: ${usage.completionTokens} > ${manifest.budgets.max_completion_tokens}`,
        );
        break;
      }

      if (usage.totalTokens > manifest.budgets.max_total_tokens) {
        addStopCondition(
          state,
          "generation",
          "MAX_TOTAL_TOKENS_EXCEEDED",
          `Total token budget exceeded: ${usage.totalTokens} > ${manifest.budgets.max_total_tokens}`,
        );
        break;
      }

      if (usage.estimatedUsd > manifest.budgets.max_usd) {
        addStopCondition(
          state,
          "generation",
          "MAX_USD_EXCEEDED",
          `USD budget exceeded: ${usage.estimatedUsd.toFixed(4)} > ${manifest.budgets.max_usd}`,
        );
        break;
      }

      saveCampaignState(statePath, state);
    }

    state.steps.generation = {
      status: state.stopConditions.length ? "failed" : "completed",
      details: {
        runRoot,
        targetsRequested: targetSlugs.length,
        retryableFailures,
      },
    };
    saveCampaignState(statePath, state);
  }

  const blocked = Array.isArray(state.stopConditions) && state.stopConditions.length > 0;

  // --- Stage 2: council ---
  if (mode === "dry-run") {
    state.steps.council = {
      status: "skipped",
      details: { reason: "dry-run" },
    };
  } else if (simulate) {
    state.steps.council = {
      status: "completed",
      details: { synthetic: true },
    };
  } else if (blocked) {
    state.steps.council = {
      status: "skipped",
      details: { reason: "stop_condition" },
    };
  } else {
    const env = { COUNCIL_RESUME: resume ? "1" : "0" };

    const councilReview = runCommand(
      "npx",
      ["tsx", path.resolve(serviceRoot, "scripts/council-review.ts"), "--run", runRoot],
      serviceRoot,
      env,
    );
    commands.push(councilReview);

    const councilAggregate = runCommand(
      "npx",
      ["tsx", path.resolve(serviceRoot, "scripts/council-aggregate.ts"), "--run", runRoot],
      serviceRoot,
      env,
    );
    commands.push(councilAggregate);

    state.commands = commands;

    if (!councilReview.ok || !councilAggregate.ok) {
      addStopCondition(state, "council", "COUNCIL_STAGE_FAILED", "council-review or council-aggregate failed");
      state.steps.council = {
        status: "failed",
        details: {
          reviewExit: councilReview.exitCode,
          aggregateExit: councilAggregate.exitCode,
        },
      };
    } else {
      state.steps.council = {
        status: "completed",
        details: {
          reviewExit: councilReview.exitCode,
          aggregateExit: councilAggregate.exitCode,
        },
      };
    }
  }
  saveCampaignState(statePath, state);

  // --- Stage 3: gate ---
  let gateSummary: ReturnType<typeof evaluateCouncilGate>["summary"] = {
    runId,
    generatedAt: new Date().toISOString(),
    thresholds: manifest.council,
    targets: [],
    promoted: [],
    quarantined: [],
    counts: { targets: 0, promoted: 0, quarantined: 0, candidateRejections: 0 },
  };

  let qualityFailure: ReturnType<typeof evaluateCouncilGate>["failureBreakdown"] = {
    runId,
    generatedAt: new Date().toISOString(),
    totalFailures: 0,
    byReason: [],
    byTarget: [],
  };

  if (mode === "dry-run") {
    state.steps.gate = {
      status: "skipped",
      details: { reason: "dry-run" },
    };
  } else {
    const gate = evaluateCouncilGate(runRoot, manifest);
    gateSummary = gate.summary;
    qualityFailure = gate.failureBreakdown;

    state.steps.gate = {
      status: "completed",
      details: {
        promoted: gateSummary.counts.promoted,
        quarantined: gateSummary.counts.quarantined,
      },
    };
  }

  writeJson(path.join(outDir, "council-gate-summary.json"), gateSummary);
  writeJson(path.join(outDir, "quality-failure-breakdown.json"), qualityFailure);

  saveCampaignState(statePath, state);

  // --- Stage 4: publish ---
  const applyToArticles = forceApply || (manifest.publish.apply_to_articles === true && mode === "full-run");

  let publishManifest: any = {
    runId,
    generatedAt: new Date().toISOString(),
    publishMode,
    canarySize: manifest.publish.canary_size,
    applyToArticles,
    requestedPromotions: 0,
    publishedCount: 0,
    heldCount: 0,
    quarantinedCount: 0,
    published: [],
    held: [],
    quarantined: [],
  };

  let rollbackManifest: any = {
    runId,
    generatedAt: new Date().toISOString(),
    publishMode,
    entries: [],
  };

  if (mode === "dry-run") {
    state.steps.publish = {
      status: "skipped",
      details: { reason: "dry-run" },
    };
  } else {
    const publish = publishFromGate(
      runRoot,
      outDir,
      gateSummary,
      publishMode,
      manifest.publish.canary_size,
      applyToArticles,
    );

    publishManifest = publish.publishManifest;
    rollbackManifest = publish.rollbackManifest;

    if (applyToArticles && manifest.publish.upload_to_r2 === true) {
      const uploadArgs = ["tsx", path.resolve(serviceRoot, "scripts/upload-to-r2.ts")];
      if (manifest.publish.bucket) {
        uploadArgs.push("--bucket", manifest.publish.bucket);
      }
      if (manifest.publish.auto_index === true) {
        uploadArgs.push("--auto-index");
      }

      const uploadCmd = runCommand("npx", uploadArgs, serviceRoot);
      commands.push(uploadCmd);
      state.commands = commands;

      publishManifest.r2Upload = {
        ok: uploadCmd.ok,
        exitCode: uploadCmd.exitCode,
        stdoutTail: uploadCmd.stdoutTail,
        stderrTail: uploadCmd.stderrTail,
      };

      if (!uploadCmd.ok) {
        addStopCondition(state, "publish", "R2_UPLOAD_FAILED", "upload-to-r2 publish step failed");
      }
    }

    state.steps.publish = {
      status: state.stopConditions.length ? "failed" : "completed",
      details: {
        publishMode,
        applyToArticles,
        published: publishManifest.publishedCount,
        held: publishManifest.heldCount,
      },
    };
  }

  writeJson(path.join(outDir, "publish-manifest.json"), publishManifest);
  writeJson(path.join(outDir, "rollback-manifest.json"), rollbackManifest);

  saveCampaignState(statePath, state);

  // --- Stage 5: reporting ---
  const usage = usageWithCosts(runId, runRoot, modelPool);

  const contentOpsWeekly = await buildContentOpsWeeklySummary({
    manifest,
    gateSummary,
    qualityFailure,
    publishManifest,
    usage,
    mode,
  });

  writeJson(path.join(outDir, "content-ops-weekly-summary.json"), contentOpsWeekly);

  state.steps.reporting = {
    status: "completed",
    details: {
      telemetryError: contentOpsWeekly.telemetryError,
      families: Array.isArray(contentOpsWeekly.trafficConversionDeltasByPageFamily)
        ? contentOpsWeekly.trafficConversionDeltasByPageFamily.length
        : 0,
    },
  };

  saveCampaignState(statePath, state);

  const campaignSummary = {
    runId,
    generatedAt: new Date().toISOString(),
    manifestPath,
    manifestHash,
    mode,
    publishMode,
    simulate,
    resume,
    runRoot,
    outDir,
    targets: targetSlugs,
    models: modelIds,
    budgets: manifest.budgets,
    usage,
    steps: state.steps,
    stopConditions: state.stopConditions,
    retryableFailures,
    commands: commands.map((c) => ({
      command: [c.command, ...c.args].join(" "),
      cwd: c.cwd,
      ok: c.ok,
      exitCode: c.exitCode,
      durationMs: c.durationMs,
      stdoutTail: c.stdoutTail,
      stderrTail: c.stderrTail,
    })),
    outputs: {
      campaignSummary: path.join(outDir, "campaign-summary.json"),
      councilGateSummary: path.join(outDir, "council-gate-summary.json"),
      publishManifest: path.join(outDir, "publish-manifest.json"),
      rollbackManifest: path.join(outDir, "rollback-manifest.json"),
      qualityFailureBreakdown: path.join(outDir, "quality-failure-breakdown.json"),
      contentOpsWeeklySummary: path.join(outDir, "content-ops-weekly-summary.json"),
    },
  };

  writeJson(path.join(outDir, "campaign-summary.json"), campaignSummary);

  console.log(`AEO-CONTENT-004 pipeline complete.`);
  console.log(`runId: ${runId}`);
  console.log(`runRoot: ${runRoot}`);
  console.log(`artifacts: ${outDir}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
