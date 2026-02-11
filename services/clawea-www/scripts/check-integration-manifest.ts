#!/usr/bin/env npx tsx
/**
 * Strict checker for integrations-manifest.v1.json
 *
 * Usage:
 *   npx tsx scripts/check-integration-manifest.ts
 *   npx tsx scripts/check-integration-manifest.ts --manifest src/content/integrations-manifest.v1.json
 */

import * as path from "path";

import {
  DEFAULT_MANIFEST_PATH,
  loadIntegrationManifest,
  summarizeManifest,
  type IntegrationManifestV1,
} from "./integration-manifest";

const args = process.argv.slice(2);

function getArg(name: string): string | undefined {
  const idx = args.indexOf(`--${name}`);
  return idx >= 0 && idx + 1 < args.length ? args[idx + 1] : undefined;
}

function hasFlag(name: string): boolean {
  return args.includes(`--${name}`);
}

function lifecycleRank(state: string): number {
  switch (state) {
    case "shipped":
      return 4;
    case "beta":
      return 3;
    case "implementable":
      return 2;
    case "planned":
      return 1;
    default:
      return 0;
  }
}

function strictSemanticChecks(manifest: IntegrationManifestV1): string[] {
  const errors: string[] = [];

  for (const r of manifest.integrations) {
    // Claim-safety fields are mandatory for SEO fail-closed generation.
    if (!Array.isArray(r.claims.must_not_imply) || r.claims.must_not_imply.length === 0) {
      errors.push(`integrations.${r.id}: claims.must_not_imply is required and must be non-empty`);
    }
    if (!Array.isArray(r.claims.allowed) || r.claims.allowed.length === 0) {
      errors.push(`integrations.${r.id}: claims.allowed is required and must be non-empty`);
    }

    // Contradictory claim language should fail hard.
    const allowedText = r.claims.allowed.join(" ").toLowerCase();
    const mustNotText = r.claims.must_not_imply.join(" ").toLowerCase();
    if (allowedText.includes("available now") || allowedText.includes("out-of-the-box") || allowedText.includes("native connector")) {
      if (r.status !== "shipped") {
        errors.push(`integrations.${r.id}: non-shipped entry contains shipped wording in claims.allowed`);
      }
    }

    if (r.status !== "shipped") {
      const safetyPhrasePresent =
        mustNotText.includes("available now") ||
        mustNotText.includes("out-of-the-box") ||
        mustNotText.includes("native connector") ||
        mustNotText.includes("shipped");
      if (!safetyPhrasePresent) {
        errors.push(`integrations.${r.id}: non-shipped entry must include shipped/planned wording guardrails in claims.must_not_imply`);
      }
    }

    // If status is stronger than public availability, fail.
    if (lifecycleRank(r.claims.public_availability) !== lifecycleRank(r.status)) {
      errors.push(
        `integrations.${r.id}: claims.public_availability (${r.claims.public_availability}) must match status (${r.status})`,
      );
    }

    // Shipped requires all gates pass.
    if (r.status === "shipped") {
      const gateValues = Object.entries(r.release_gates);
      for (const [k, gate] of gateValues) {
        if (gate.status !== "pass") {
          errors.push(`integrations.${r.id}: shipped entries require ${k}=pass`);
        }
      }
    }
  }

  return errors;
}

function main(): void {
  const manifestPath = path.resolve(getArg("manifest") ?? DEFAULT_MANIFEST_PATH);
  const asJson = hasFlag("json");

  try {
    const manifest = loadIntegrationManifest(manifestPath);
    const strictErrors = strictSemanticChecks(manifest);
    if (strictErrors.length > 0) {
      console.error(`Manifest strict checks failed (${manifestPath})`);
      for (const e of strictErrors) {
        console.error(`- ${e}`);
      }
      process.exit(1);
    }

    const summary = summarizeManifest(manifest);
    if (asJson) {
      console.log(
        JSON.stringify(
          {
            manifest: manifestPath,
            schema: `${manifest.schema_name}.v${manifest.schema_version}`,
            summary,
          },
          null,
          2,
        ),
      );
      return;
    }

    console.log(`Manifest OK: ${manifestPath}`);
    console.log(`Schema: ${manifest.schema_name}.v${manifest.schema_version}`);
    console.log(`Integrations: ${summary.integrations}`);
    console.log(`By status: ${JSON.stringify(summary.byStatus)}`);
    console.log(`By category: ${JSON.stringify(summary.byCategory)}`);
  } catch (err: any) {
    console.error(err?.message ?? err);
    process.exit(1);
  }
}

main();
