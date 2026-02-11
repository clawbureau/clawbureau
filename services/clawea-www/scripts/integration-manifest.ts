#!/usr/bin/env npx tsx

import * as fs from "fs";
import * as path from "path";

import { fileURLToPath } from "url";
import { z } from "zod";

import {
  CONTROLS_V1,
  CONTROLS_V2,
  EVENT_SOURCES_V1,
  MCP_SERVERS_V1,
  TOOLS_V1,
  WORKFLOWS_V1,
} from "./taxonomy";

export const INTEGRATION_MANIFEST_SCHEMA_NAME = "clawea.integration_manifest" as const;
export const INTEGRATION_MANIFEST_SCHEMA_VERSION = 1 as const;

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));

export const DEFAULT_MANIFEST_PATH = path.resolve(
  SCRIPT_DIR,
  "../src/content/integrations-manifest.v1.json",
);

const LifecycleStateSchema = z.enum(["shipped", "beta", "planned", "implementable", "deprecated"]);
const CapabilityWordSchema = z.enum(["shipped", "planned", "optional", "not_supported"]);
const ModeSchema = z.enum(["mcp", "api", "plugin", "ai_tool"]);
const OperationSchema = z.enum(["read", "write", "admin", "event"]);
const AuthModeSchema = z.enum(["oauth", "api_key", "service_account", "webhook"]);
const ApprovalLevelSchema = z.enum(["required", "optional", "not_supported"]);
const ProofArtifactSchema = z.enum([
  "wpc",
  "cst",
  "gateway_receipt",
  "proof_bundle",
  "trust_pulse",
  "execution_attestation",
  "urm",
]);

const ReviewGateSchema = z
  .object({
    status: z.enum(["pass", "fail"]),
    approved_by: z.string().optional(),
    approved_at: z.string().datetime().optional(),
    evidence_urls: z.array(z.string().url()).min(1),
    notes: z.string().optional(),
  })
  .strict();

const IntegrationRecordSchema = z
  .object({
    id: z.string().regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/),
    name: z.string().min(2),
    vendor: z.string().min(2),
    suite: z.string().optional(),
    category: z.enum([
      "cloud",
      "identity",
      "collaboration",
      "crm",
      "erp",
      "itsm",
      "data",
      "observability",
      "events",
      "devops",
      "security",
      "storage",
      "other",
    ]),
    modes_supported: z.array(ModeSchema).min(1),
    operations: z.array(OperationSchema).min(1),
    auth_modes: z.array(AuthModeSchema).min(1),
    required_egress_hosts: z.array(z.string().min(2)).min(1),
    default_wpc_controls: z.array(z.string().regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/)).min(1),
    approval_requirements: z
      .object({
        write: ApprovalLevelSchema,
        admin: ApprovalLevelSchema,
        notes: z.string().optional(),
      })
      .strict(),
    proof_artifacts: z.array(ProofArtifactSchema).min(1),
    status: LifecycleStateSchema,
    source_urls: z.array(z.string().url()).min(1),
    release_gates: z
      .object({
        security_review: ReviewGateSchema,
        ops_review: ReviewGateSchema,
        proof_review: ReviewGateSchema,
        docs_review: ReviewGateSchema,
      })
      .strict(),
    claims: z
      .object({
        public_availability: LifecycleStateSchema,
        allowed: z.array(z.string().min(6)).min(1),
        must_not_imply: z.array(z.string().min(6)).min(1),
      })
      .strict(),
    taxonomy_refs: z
      .object({
        tool_slug: z.string().regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/).optional(),
        mcp_server_slug: z.string().regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/).optional(),
        event_source_slugs: z.array(z.string().regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/)).optional(),
        workflow_slugs: z.array(z.string().regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/)).optional(),
        control_slugs: z.array(z.string().regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/)).optional(),
      })
      .strict()
      .optional(),
    notes: z.string().optional(),
  })
  .strict();

const IntegrationManifestSchema = z
  .object({
    schema_name: z.literal(INTEGRATION_MANIFEST_SCHEMA_NAME),
    schema_version: z.literal(INTEGRATION_MANIFEST_SCHEMA_VERSION),
    manifest: z
      .object({
        id: z.string().min(8),
        generated_at: z.string().datetime(),
        owner: z.string().min(2),
        source_repo: z.string().min(3),
        notes: z.string().optional(),
      })
      .strict(),
    platform: z
      .object({
        truths: z
          .object({
            shipped: z
              .array(
                z
                  .object({
                    key: z.string().min(2),
                    label: z.string().min(2),
                  })
                  .strict(),
              )
              .min(1),
            planned_or_optional: z.array(
              z
                .object({
                  key: z.string().min(2),
                  label: z.string().min(2),
                })
                .strict(),
            ),
          })
          .strict(),
        capabilities: z
          .object({
            wpc: z.object({ status: CapabilityWordSchema, notes: z.string().min(2) }).strict(),
            cst: z.object({ status: CapabilityWordSchema, notes: z.string().min(2) }).strict(),
            receipts: z.object({ status: CapabilityWordSchema, notes: z.string().min(2) }).strict(),
            proof_bundles: z.object({ status: CapabilityWordSchema, notes: z.string().min(2) }).strict(),
            trust_pulse: z.object({ status: CapabilityWordSchema, notes: z.string().min(2) }).strict(),
            egress_outside_clawproxy: z
              .object({ status: CapabilityWordSchema, notes: z.string().min(2) })
              .strict(),
            automatic_budget_enforcement: z
              .object({ status: CapabilityWordSchema, notes: z.string().min(2) })
              .strict(),
            transparency_log_inclusion_proofs: z
              .object({ status: CapabilityWordSchema, notes: z.string().min(2) })
              .strict(),
          })
          .strict(),
      })
      .strict(),
    integrations: z.array(IntegrationRecordSchema).min(1),
  })
  .strict();

export type IntegrationManifestV1 = z.infer<typeof IntegrationManifestSchema>;
export type IntegrationRecordV1 = z.infer<typeof IntegrationRecordSchema>;

const KNOWN_CONTROL_SLUGS = new Set([...CONTROLS_V1, ...CONTROLS_V2].map((c) => c.slug));
const KNOWN_TOOL_SLUGS = new Set(TOOLS_V1.map((t) => t.slug));
const KNOWN_WORKFLOW_SLUGS = new Set(WORKFLOWS_V1.map((w) => w.slug));
const KNOWN_EVENT_SOURCE_SLUGS = new Set(EVENT_SOURCES_V1.map((e) => e.slug));
const KNOWN_MCP_SERVER_SLUGS = new Set(MCP_SERVERS_V1.map((m) => m.slug));

const SHIPPING_LANGUAGE = [
  "available now",
  "now available",
  "shipped",
  "generally available",
  "native connector",
  "built-in connector",
  "out-of-the-box",
  "out of the box",
  "fully supported today",
] as const;

export const SOURCE_URL_ALLOWLIST = [
  "clawea.com",
  "openclaw.dev",
  "modelcontextprotocol.io",
  "owasp.org",
  "nist.gov",
  "cisa.gov",
  "developers.cloudflare.com",
  "blog.cloudflare.com",
  "learn.microsoft.com",
  "developer.microsoft.com",
  "graph.microsoft.com",
  "developer.salesforce.com",
  "salesforce.com",
  "api.sap.com",
  "help.sap.com",
  "sap.com",
  "developer.servicenow.com",
  "docs.servicenow.com",
  "servicenow.com",
  "docs.workday.com",
  "workday.com",
  "docs.aws.amazon.com",
  "aws.amazon.com",
  "cloud.google.com",
  "developers.google.com",
  "developer.atlassian.com",
  "support.atlassian.com",
  "atlassian.com",
  "docs.github.com",
  "github.com",
  "docs.gitlab.com",
  "readthedocs.io",
  "oracle.com",
  "coupa.com",
  "docs.pagerduty.com",
  "pagerduty.com",
  "docs.datadoghq.com",
  "datadoghq.com",
  "docs.splunk.com",
  "splunk.com",
  "elastic.co",
  "grafana.com",
  "sentry.io",
  "docs.newrelic.com",
  "newrelic.com",
  "docs.snowflake.com",
  "snowflake.com",
  "docs.databricks.com",
  "databricks.com",
  "postgresql.org",
  "redis.io",
  "mongodb.com",
  "docs.mongodb.com",
  "kubernetes.io",
  "developer.hashicorp.com",
  "box.com",
  "developer.box.com",
  "developers.notion.com",
  "notion.com",
  "developers.hubspot.com",
  "hubspot.com",
  "developers.intercom.com",
  "intercom.com",
  "developer.zendesk.com",
  "zendesk.com",
  "developer.okta.com",
  "okta.com",
  "1password.com",
  "docs.crowdstrike.com",
  "crowdstrike.com",
  "docs.wiz.io",
  "wiz.io",
  "docs.paloaltonetworks.com",
  "paloaltonetworks.com",
  "api.slack.com",
  "docs.slack.dev",
  "stripe.com",
  "docs.stripe.com",
  "confluent.io",
  "kafka.apache.org",
] as const;

function hostFromUrl(u: string): string {
  try {
    return new URL(u).hostname.toLowerCase();
  } catch {
    return "";
  }
}

function isAllowedSourceUrl(url: string): boolean {
  const host = hostFromUrl(url);
  if (!host) return false;
  return SOURCE_URL_ALLOWLIST.some((d) => host === d || host.endsWith(`.${d}`));
}

function uniq<T>(arr: T[]): T[] {
  return [...new Set(arr)];
}

function normalizeText(s: string): string {
  return s.toLowerCase().replace(/\s+/g, " ").trim();
}

function formatZodIssues(issues: z.ZodIssue[]): string[] {
  return issues.map((i) => {
    const p = i.path.length ? i.path.join(".") : "(root)";
    return `${p}: ${i.message}`;
  });
}

export function semanticManifestErrors(manifest: IntegrationManifestV1): string[] {
  const errors: string[] = [];

  const ids = new Set<string>();

  for (const record of manifest.integrations) {
    if (ids.has(record.id)) {
      errors.push(`integrations.${record.id}: duplicate id`);
    }
    ids.add(record.id);

    if (record.claims.public_availability !== record.status) {
      errors.push(
        `integrations.${record.id}: claims.public_availability (${record.claims.public_availability}) must match status (${record.status})`,
      );
    }

    if (record.status !== "shipped") {
      const hasShippingGuardrail = record.claims.must_not_imply.some((s) => {
        const n = normalizeText(s);
        return SHIPPING_LANGUAGE.some((p) => n.includes(p));
      });
      if (!hasShippingGuardrail) {
        errors.push(
          `integrations.${record.id}: non-shipped entries must include at least one shipping guardrail phrase in claims.must_not_imply`,
        );
      }

      const unsafeAllowed = record.claims.allowed.filter((s) => {
        const n = normalizeText(s);
        return SHIPPING_LANGUAGE.some((p) => n.includes(p));
      });
      if (unsafeAllowed.length > 0) {
        errors.push(
          `integrations.${record.id}: non-shipped entries must not include shipping language in claims.allowed (${unsafeAllowed.join("; ")})`,
        );
      }
    }

    if (record.status === "shipped") {
      for (const [gateName, gate] of Object.entries(record.release_gates)) {
        if (gate.status !== "pass") {
          errors.push(`integrations.${record.id}: shipped entries require ${gateName}.status=pass`);
        }
      }
    }

    if (record.operations.includes("write") && record.approval_requirements.write !== "required") {
      errors.push(`integrations.${record.id}: write operations require approval_requirements.write=required`);
    }
    if (record.operations.includes("admin") && record.approval_requirements.admin !== "required") {
      errors.push(`integrations.${record.id}: admin operations require approval_requirements.admin=required`);
    }

    for (const c of record.default_wpc_controls) {
      if (!KNOWN_CONTROL_SLUGS.has(c)) {
        errors.push(`integrations.${record.id}: unknown control slug in default_wpc_controls: ${c}`);
      }
    }

    for (const src of record.source_urls) {
      if (!src.startsWith("https://")) {
        errors.push(`integrations.${record.id}: source_urls must be https:// (${src})`);
      }
      if (!isAllowedSourceUrl(src)) {
        errors.push(`integrations.${record.id}: source url host not allowlisted (${src})`);
      }
    }

    const refs = record.taxonomy_refs;
    if (refs?.tool_slug && !KNOWN_TOOL_SLUGS.has(refs.tool_slug)) {
      errors.push(`integrations.${record.id}: unknown taxonomy tool_slug (${refs.tool_slug})`);
    }
    if (refs?.mcp_server_slug && !KNOWN_MCP_SERVER_SLUGS.has(refs.mcp_server_slug)) {
      errors.push(`integrations.${record.id}: unknown taxonomy mcp_server_slug (${refs.mcp_server_slug})`);
    }
    for (const s of refs?.workflow_slugs ?? []) {
      if (!KNOWN_WORKFLOW_SLUGS.has(s)) {
        errors.push(`integrations.${record.id}: unknown taxonomy workflow_slugs entry (${s})`);
      }
    }
    for (const s of refs?.event_source_slugs ?? []) {
      if (!KNOWN_EVENT_SOURCE_SLUGS.has(s)) {
        errors.push(`integrations.${record.id}: unknown taxonomy event_source_slugs entry (${s})`);
      }
    }
    for (const s of refs?.control_slugs ?? []) {
      if (!KNOWN_CONTROL_SLUGS.has(s)) {
        errors.push(`integrations.${record.id}: unknown taxonomy control_slugs entry (${s})`);
      }
    }

    const overlap = record.claims.allowed.filter((a) =>
      record.claims.must_not_imply.some((b) => normalizeText(a) === normalizeText(b)),
    );
    if (overlap.length > 0) {
      errors.push(`integrations.${record.id}: claims.allowed overlaps claims.must_not_imply (${overlap.join("; ")})`);
    }

    if (!record.proof_artifacts.includes("proof_bundle")) {
      errors.push(`integrations.${record.id}: proof_artifacts must include proof_bundle`);
    }
    if (!record.proof_artifacts.includes("wpc")) {
      errors.push(`integrations.${record.id}: proof_artifacts must include wpc`);
    }
    if (!record.proof_artifacts.includes("cst")) {
      errors.push(`integrations.${record.id}: proof_artifacts must include cst`);
    }
  }

  return errors;
}

export function parseIntegrationManifest(raw: unknown, source = "manifest"): IntegrationManifestV1 {
  const parsed = IntegrationManifestSchema.safeParse(raw);
  if (!parsed.success) {
    const msg = formatZodIssues(parsed.error.issues)
      .map((e) => `- ${e}`)
      .join("\n");
    throw new Error(`Invalid integration manifest (${source})\n${msg}`);
  }

  const semanticErrors = semanticManifestErrors(parsed.data);
  if (semanticErrors.length > 0) {
    throw new Error(
      `Integration manifest failed semantic checks (${source})\n${semanticErrors.map((e) => `- ${e}`).join("\n")}`,
    );
  }

  return parsed.data;
}

export function loadIntegrationManifest(manifestPath = DEFAULT_MANIFEST_PATH): IntegrationManifestV1 {
  const abs = path.resolve(manifestPath);
  if (!fs.existsSync(abs)) {
    throw new Error(`Integration manifest file not found: ${abs}`);
  }
  const json = JSON.parse(fs.readFileSync(abs, "utf-8"));
  return parseIntegrationManifest(json, abs);
}

export function integrationById(manifest: IntegrationManifestV1): Map<string, IntegrationRecordV1> {
  return new Map(manifest.integrations.map((r) => [r.id, r] as const));
}

export type TargetIntegrationContext = {
  requiredIds: string[];
  missingRequiredIds: string[];
  recordIds: string[];
  records: IntegrationRecordV1[];
  allowedClaims: string[];
  mustNotImply: string[];
  nonShippedIds: string[];
};

export function resolveTargetIntegrationContext(
  manifest: IntegrationManifestV1,
  targetSlug: string,
): TargetIntegrationContext {
  const byId = integrationById(manifest);
  const segments = targetSlug.toLowerCase().split("/").filter(Boolean);

  const requiredIds = uniq(segments.filter((s) => KNOWN_TOOL_SLUGS.has(s)));

  const recordIds = uniq(segments.filter((s) => byId.has(s)));
  for (const id of requiredIds) {
    if (!recordIds.includes(id)) recordIds.push(id);
  }

  const missingRequiredIds = requiredIds.filter((id) => !byId.has(id));
  const records = recordIds.map((id) => byId.get(id)).filter((r): r is IntegrationRecordV1 => Boolean(r));

  return {
    requiredIds,
    missingRequiredIds,
    recordIds,
    records,
    allowedClaims: uniq(records.flatMap((r) => r.claims.allowed)),
    mustNotImply: uniq(records.flatMap((r) => r.claims.must_not_imply)),
    nonShippedIds: uniq(records.filter((r) => r.status !== "shipped").map((r) => r.id)),
  };
}

export function buildPlatformTruthTable(manifest: IntegrationManifestV1): {
  shipped: string[];
  planned: string[];
} {
  return {
    shipped: manifest.platform.truths.shipped.map((x) => x.label),
    planned: manifest.platform.truths.planned_or_optional.map((x) => x.label),
  };
}

export type ClaimSafetyResult = {
  claim_state_violations: string[];
  endpoint_invention_violations: string[];
  shipped_planned_mismatch: string[];
};

const POSITIVE_SHIPPED_PHRASES = [
  /\bavailable now\b/gi,
  /\bnow available\b/gi,
  /\bgenerally available\b/gi,
  /\bfully supported today\b/gi,
  /\bnative connector\b/gi,
  /\bbuilt-?in connector\b/gi,
  /\bout[- ]of[- ]the[- ]box\b/gi,
  /\bshipped\b/gi,
] as const;

const NEGATION_HINTS = /\b(not|is not|isn't|planned|implementable|optional|beta|not yet)\b/i;
const METHOD_PATH_RX = /\b(?:GET|POST|PUT|PATCH|DELETE)\s+\/[A-Za-z0-9._~\-/]+/g;
const URL_RX = /https?:\/\/[^\s<>")]+/g;

function dedupeAndSort(values: string[]): string[] {
  return [...new Set(values)].sort((a, b) => a.localeCompare(b, "en"));
}

function cleanExtractedUrl(u: string): string {
  return u.replace(/[),.;]+$/g, "");
}

export function evaluateClaimSafety(args: {
  text: string;
  context: TargetIntegrationContext;
  allowedCitationUrls?: string[];
}): ClaimSafetyResult {
  const { text, context } = args;
  if (!context.records.length) {
    return {
      claim_state_violations: [],
      endpoint_invention_violations: [],
      shipped_planned_mismatch: [],
    };
  }

  const lower = text.toLowerCase();

  const claimState: string[] = [];
  const endpoint: string[] = [];
  const mismatch: string[] = [];

  const allowedUrlSet = new Set(
    [
      ...(args.allowedCitationUrls ?? []),
      ...context.records.flatMap((r) => r.source_urls),
    ].map((u) => u.toLowerCase()),
  );

  for (const m of text.matchAll(METHOD_PATH_RX)) {
    endpoint.push(`method_path:${m[0]}`);
  }

  for (const m of text.matchAll(URL_RX)) {
    const raw = cleanExtractedUrl(m[0]);
    if (!allowedUrlSet.has(raw.toLowerCase())) {
      endpoint.push(`url_not_allowlisted:${raw}`);
    }
  }

  for (const rec of context.records) {
    for (const banned of rec.claims.must_not_imply) {
      const b = normalizeText(banned);
      if (b && lower.includes(b)) {
        claimState.push(`${rec.id}:must_not_imply:${banned}`);
      }
    }

    if (rec.status === "shipped") continue;

    const mentionTokens = [rec.id, rec.name, rec.vendor].map((s) => s.toLowerCase());

    for (const rx of POSITIVE_SHIPPED_PHRASES) {
      for (const m of text.matchAll(rx)) {
        const idx = m.index ?? -1;
        if (idx < 0) continue;

        const around = lower.slice(Math.max(0, idx - 80), Math.min(lower.length, idx + 160));
        if (NEGATION_HINTS.test(around)) continue;

        const mentionsRecord =
          mentionTokens.some((t) => around.includes(t)) ||
          (context.records.length === 1 && !around.includes("integration"));

        if (!mentionsRecord) continue;

        const msg = `${rec.id}:shipping_phrase:${m[0]}`;
        mismatch.push(msg);
        claimState.push(msg);
      }
    }
  }

  return {
    claim_state_violations: dedupeAndSort(claimState),
    endpoint_invention_violations: dedupeAndSort(endpoint),
    shipped_planned_mismatch: dedupeAndSort(mismatch),
  };
}

export function summarizeManifest(manifest: IntegrationManifestV1): {
  integrations: number;
  byStatus: Record<string, number>;
  byCategory: Record<string, number>;
} {
  const byStatus: Record<string, number> = {};
  const byCategory: Record<string, number> = {};

  for (const r of manifest.integrations) {
    byStatus[r.status] = (byStatus[r.status] ?? 0) + 1;
    byCategory[r.category] = (byCategory[r.category] ?? 0) + 1;
  }

  return {
    integrations: manifest.integrations.length,
    byStatus,
    byCategory,
  };
}
