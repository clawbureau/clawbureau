#!/usr/bin/env npx tsx
/**
 * Compute sanitizer + allowlist metrics for a model-writeoff run.
 *
 * Usage:
 *   npx tsx scripts/writeoff-metrics.ts --run sample-output/model-writeoff/<runId>
 */

import * as fs from "fs";
import * as path from "path";

const args = process.argv.slice(2);
const getArg = (name: string) => {
  const idx = args.indexOf(`--${name}`);
  return idx >= 0 && idx + 1 < args.length ? args[idx + 1] : undefined;
};

const runArg = getArg("run");
if (!runArg) {
  console.error("Missing --run <run-folder>");
  process.exit(1);
}

const runRoot = path.resolve(runArg);
if (!fs.existsSync(runRoot) || !fs.statSync(runRoot).isDirectory()) {
  console.error(`Run folder not found: ${runRoot}`);
  process.exit(1);
}

type Counts = {
  targets: number;
  candidates: number;
  candidatesArticle: number;
  candidatesWizard: number;
  sanitized: number;
  sanitizerFailed: number;
  sanitizerFailedByReason: Record<string, number>;
  preViolationCandidates: number;
  preViolationUrls: number;
  postViolationCandidates: number;
  postViolationUrls: number;
  removedViolationUrls: number;
  removedViolationCandidates: number;
  missingOpenclawAfter: number;
  missingExternalAfter: number;
  missingVendorAfter: number;
  claimStateViolationCandidates: number;
  claimStateViolations: number;
  claimStateViolationByReason: Record<string, number>;
  endpointInventionViolationCandidates: number;
  endpointInventionViolations: number;
  endpointInventionByReason: Record<string, number>;
  shippedPlannedMismatchCandidates: number;
  shippedPlannedMismatches: number;
  shippedPlannedMismatchByReason: Record<string, number>;
};

function addBy(map: Record<string, number>, key: string, n = 1): void {
  map[key] = (map[key] ?? 0) + n;
}

function topReasons(map: Record<string, number>, top = 12): Array<{ reason: string; count: number }> {
  return Object.entries(map)
    .map(([reason, count]) => ({ reason, count }))
    .sort((a, b) => b.count - a.count || a.reason.localeCompare(b.reason, "en"))
    .slice(0, top);
}

function listTargetDirs(root: string): string[] {
  return fs
    .readdirSync(root, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => path.join(root, d.name))
    .filter((p) => fs.existsSync(path.join(p, "spec.json")) && fs.existsSync(path.join(p, "candidates")));
}

function main(): void {
  const counts: Counts = {
    targets: 0,
    candidates: 0,
    candidatesArticle: 0,
    candidatesWizard: 0,
    sanitized: 0,
    sanitizerFailed: 0,
    sanitizerFailedByReason: {},
    preViolationCandidates: 0,
    preViolationUrls: 0,
    postViolationCandidates: 0,
    postViolationUrls: 0,
    removedViolationUrls: 0,
    removedViolationCandidates: 0,
    missingOpenclawAfter: 0,
    missingExternalAfter: 0,
    missingVendorAfter: 0,
    claimStateViolationCandidates: 0,
    claimStateViolations: 0,
    claimStateViolationByReason: {},
    endpointInventionViolationCandidates: 0,
    endpointInventionViolations: 0,
    endpointInventionByReason: {},
    shippedPlannedMismatchCandidates: 0,
    shippedPlannedMismatches: 0,
    shippedPlannedMismatchByReason: {},
  };

  const targets = listTargetDirs(runRoot);
  counts.targets = targets.length;

  for (const tDir of targets) {
    const candDir = path.join(tDir, "candidates");
    const reports = fs.readdirSync(candDir).filter((f) => f.endsWith(".report.json"));

    for (const rf of reports) {
      const rep = JSON.parse(fs.readFileSync(path.join(candDir, rf), "utf-8")) as any;
      const kind = String(rep.kind ?? "article");
      counts.candidates++;
      if (kind === "wizard") counts.candidatesWizard++; else counts.candidatesArticle++;

      const sanitized = rep.sanitized === true;
      if (sanitized) counts.sanitized++;

      const failReason = rep.sanitizer_failed_reason;
      if (typeof failReason === "string" && failReason) {
        counts.sanitizerFailed++;
        addBy(counts.sanitizerFailedByReason, failReason);

        if (failReason.includes("missing_openclaw")) counts.missingOpenclawAfter++;
        if (failReason.includes("missing_external")) counts.missingExternalAfter++;
        if (failReason.includes("missing_vendor")) counts.missingVendorAfter++;
      }

      const pre = rep?.citations?.violations_pre;
      const post = rep?.citations?.violations;

      const preList = Array.isArray(pre) ? (pre as string[]) : [];
      const postList = Array.isArray(post) ? (post as string[]) : [];

      if (preList.length) counts.preViolationCandidates++;
      counts.preViolationUrls += preList.length;

      if (postList.length) counts.postViolationCandidates++;
      counts.postViolationUrls += postList.length;

      // removed violations
      const removed = kind === "wizard" ? rep.removed_citation_violations : rep.removed_href_violations;
      const removedList = Array.isArray(removed) ? (removed as string[]) : [];
      if (removedList.length) counts.removedViolationCandidates++;
      counts.removedViolationUrls += removedList.length;

      const claimState = Array.isArray(rep?.claim_state_violations) ? (rep.claim_state_violations as string[]) : [];
      if (claimState.length) counts.claimStateViolationCandidates++;
      counts.claimStateViolations += claimState.length;
      for (const v of claimState) addBy(counts.claimStateViolationByReason, String(v));

      const endpoint = Array.isArray(rep?.endpoint_invention_violations)
        ? (rep.endpoint_invention_violations as string[])
        : [];
      if (endpoint.length) counts.endpointInventionViolationCandidates++;
      counts.endpointInventionViolations += endpoint.length;
      for (const v of endpoint) addBy(counts.endpointInventionByReason, String(v));

      const mismatch = Array.isArray(rep?.shipped_planned_mismatch)
        ? (rep.shipped_planned_mismatch as string[])
        : [];
      if (mismatch.length) counts.shippedPlannedMismatchCandidates++;
      counts.shippedPlannedMismatches += mismatch.length;
      for (const v of mismatch) addBy(counts.shippedPlannedMismatchByReason, String(v));
    }
  }

  const outPath = path.join(runRoot, "METRICS.json");
  fs.writeFileSync(outPath, JSON.stringify(counts, null, 2));

  const complianceSummaryPath = path.join(runRoot, "COMPLIANCE_SUMMARY.md");
  const summaryMd = `# Write-off Compliance Summary\n\nRun: ${path.basename(runRoot)}\n\n## Totals\n- Targets: ${counts.targets}\n- Candidates: ${counts.candidates}\n- Sanitizer failed candidates: ${counts.sanitizerFailed}\n- Claim-state violation candidates: ${counts.claimStateViolationCandidates}\n- Endpoint-invention violation candidates: ${counts.endpointInventionViolationCandidates}\n- Shipped/planned mismatch candidates: ${counts.shippedPlannedMismatchCandidates}\n\n## Sanitizer failures by reason\n${topReasons(counts.sanitizerFailedByReason)
    .map((x) => `- ${x.reason}: ${x.count}`)
    .join("\n") || "- (none)"}\n\n## Claim-state violations by reason\n${topReasons(counts.claimStateViolationByReason)
    .map((x) => `- ${x.reason}: ${x.count}`)
    .join("\n") || "- (none)"}\n\n## Endpoint invention violations by reason\n${topReasons(counts.endpointInventionByReason)
    .map((x) => `- ${x.reason}: ${x.count}`)
    .join("\n") || "- (none)"}\n\n## Shipped/planned mismatch by reason\n${topReasons(counts.shippedPlannedMismatchByReason)
    .map((x) => `- ${x.reason}: ${x.count}`)
    .join("\n") || "- (none)"}\n`;
  fs.writeFileSync(complianceSummaryPath, summaryMd);

  console.log(JSON.stringify({ runId: path.basename(runRoot), ...counts }, null, 2));
  console.log(`\nWrote ${outPath}`);
  console.log(`Wrote ${complianceSummaryPath}`);
}

main();
