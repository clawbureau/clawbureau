/**
 * clawea.com programmatic SEO taxonomy (v2).
 *
 * 2026 bet: OpenClaw shows what becomes commodity (chat control plane + always-on agents + skills).
 * The bottleneck becomes secure execution.
 *
 * This taxonomy is permissioned-execution-first:
 * - Policy-as-code for agents (WPC, scoped tokens, allow/deny, egress, DLP, approvals, budgets)
 * - Proof + attestation (receipts, proof bundles, event chains, verification)
 * - Supply chain (signed skills/plugins, manifests, provenance)
 * - Event-native agents (webhooks/changefeeds/queues), paired with policy + proof
 * - Enterprise tool suites (Microsoft 365 + Azure control surfaces) as first-class.
 *
 * Goal:
 * - Design ~10k useful pages.
 * - Only index 500–1,500 core pages at launch (Plan A).
 */

// ── Types ─────────────────────────────────────────────────────────

export interface Topic {
  /** URL path without leading slash (e.g. "workflows/production-deploy-approval/github/slack") */
  slug: string;
  title: string;
  /** High-level family/category for grouping + badge label. */
  category: string;
  /** Prompt for Gemini HTML generation (scripts/generate.ts). */
  prompt: string;
  /** 0..1. Used only for generation ordering today. */
  priority: number;
  /** Plan A index gating. True means allowed into core sitemap. */
  indexable: boolean;
}

type ToolIntegrationMode = "mcp-official" | "mcp-community" | "api-only" | "roadmap";

type Channel = {
  slug: string;
  name: string;
  notes?: string;
};

type Tool = {
  slug: string;
  name: string;
  suite?: string;
  mode: ToolIntegrationMode;
  notes?: string;
};

type Control = {
  slug: string;
  name: string;
  notes?: string;
};

type Workflow = {
  slug: string;
  name: string;
  irreversibleActions: string[];
  requiredControls: Array<Control["slug"]>;
  notes?: string;
};

type ComplianceFramework = {
  slug: string;
  name: string;
};

type EventSource = {
  slug: string;
  name: string;
  triggers: string[];
  notes?: string;
};

type McpServer = {
  slug: string;
  name: string;
  mode: "official" | "community";
  notes?: string;
};

// ── Axes ─────────────────────────────────────────────────────────

export const CHANNELS_V1: readonly Channel[] = [
  { slug: "microsoft-teams", name: "Microsoft Teams", notes: "Primary enterprise chat control plane" },
  { slug: "slack", name: "Slack" },
  { slug: "email", name: "Email", notes: "Inbox + outbound is a high-risk irreversible surface" },
  { slug: "google-chat", name: "Google Chat" },
  { slug: "mattermost", name: "Mattermost", notes: "Self-hosted enterprise chat" },
  { slug: "discord", name: "Discord", notes: "Common for dev communities, less common for enterprise" },
  { slug: "telegram", name: "Telegram" },
  { slug: "whatsapp", name: "WhatsApp" },
  { slug: "signal", name: "Signal" },
  { slug: "matrix", name: "Matrix" },
] as const;

export const CONTROLS_V1: readonly Control[] = [
  { slug: "tool-allow-deny", name: "Tool allow/deny lists" },
  { slug: "provider-model-allowlist", name: "Provider and model allowlists" },
  { slug: "egress-allowlist", name: "Egress allowlist (domains, IPs)" },
  { slug: "file-path-scopes", name: "File path read/write scopes" },
  { slug: "dlp-redaction", name: "DLP and redaction rules" },
  { slug: "approval-gates", name: "Step-up approvals (human-in-the-loop)" },
  { slug: "two-person-rule", name: "Two-person rule" },
  { slug: "forced-dry-run", name: "Forced dry-run / simulate-first" },
  { slug: "budgets", name: "Token and cost budgets" },
  { slug: "rate-limits", name: "Rate limits and concurrency limits" },
  { slug: "secret-boundary", name: "Secrets isolation and scoped credentials" },
  { slug: "kill-switch", name: "Kill switch and emergency halt" },
] as const;

export const CONTROLS_V2: readonly Control[] = [
  { slug: "data-residency", name: "Data residency and region pinning" },
  { slug: "prompt-input-firewall", name: "Prompt injection defenses and input validation" },
  { slug: "output-policy", name: "Output policy and redaction" },
  { slug: "provenance-requirements", name: "Provenance requirements for plugins/tools" },
  { slug: "replay-requirements", name: "Replay, rollback posture, and evidence retention" },
] as const;

const ALL_CONTROLS: readonly Control[] = [...CONTROLS_V1, ...CONTROLS_V2];

const MICROSOFT_TOOLS: readonly Tool[] = [
  { slug: "microsoft-graph", name: "Microsoft Graph", suite: "Microsoft 365", mode: "api-only", notes: "Canonical API surface for M365 tools" },
  { slug: "outlook-exchange", name: "Outlook / Exchange", suite: "Microsoft 365", mode: "api-only" },
  { slug: "sharepoint", name: "SharePoint", suite: "Microsoft 365", mode: "api-only" },
  { slug: "onedrive", name: "OneDrive", suite: "Microsoft 365", mode: "api-only" },
  { slug: "microsoft-calendar", name: "Microsoft Calendar", suite: "Microsoft 365", mode: "api-only" },
  { slug: "power-automate", name: "Power Automate", suite: "Microsoft 365", mode: "api-only" },
  { slug: "powerbi", name: "Power BI", suite: "Microsoft 365", mode: "api-only" },

  { slug: "entra-id", name: "Microsoft Entra ID (Azure AD)", suite: "Azure", mode: "api-only" },
  { slug: "azure-devops", name: "Azure DevOps", suite: "Azure", mode: "api-only" },
  { slug: "azure-sentinel", name: "Microsoft Sentinel", suite: "Azure", mode: "api-only" },
  { slug: "microsoft-defender", name: "Microsoft Defender", suite: "Azure", mode: "api-only" },
  { slug: "microsoft-purview", name: "Microsoft Purview", suite: "Azure", mode: "api-only" },
  { slug: "azure-key-vault", name: "Azure Key Vault", suite: "Azure", mode: "api-only" },
  { slug: "azure-storage", name: "Azure Storage", suite: "Azure", mode: "api-only" },
  { slug: "azure-event-grid", name: "Azure Event Grid", suite: "Azure", mode: "api-only" },
  { slug: "azure-service-bus", name: "Azure Service Bus", suite: "Azure", mode: "api-only" },
] as const;

const GOOGLE_TOOLS: readonly Tool[] = [
  { slug: "gmail", name: "Gmail", suite: "Google Workspace", mode: "api-only" },
  { slug: "google-drive", name: "Google Drive", suite: "Google Workspace", mode: "api-only" },
  { slug: "google-calendar", name: "Google Calendar", suite: "Google Workspace", mode: "api-only" },
  { slug: "google-admin", name: "Google Workspace Admin", suite: "Google Workspace", mode: "api-only" },
] as const;

const ATLASSIAN_TOOLS: readonly Tool[] = [
  { slug: "jira", name: "Jira", suite: "Atlassian", mode: "mcp-official" },
  { slug: "confluence", name: "Confluence", suite: "Atlassian", mode: "mcp-official" },
  { slug: "opsgenie", name: "Opsgenie", suite: "Atlassian", mode: "api-only" },
] as const;

const DEVOPS_TOOLS: readonly Tool[] = [
  { slug: "github", name: "GitHub", suite: "Developer", mode: "mcp-official" },
  { slug: "gitlab", name: "GitLab", suite: "Developer", mode: "mcp-community" },
  { slug: "bitbucket", name: "Bitbucket", suite: "Developer", mode: "api-only" },
  { slug: "github-actions", name: "GitHub Actions", suite: "CI/CD", mode: "api-only" },
  { slug: "terraform-cloud", name: "Terraform Cloud", suite: "Infra", mode: "api-only" },
  { slug: "kubernetes", name: "Kubernetes", suite: "Infra", mode: "api-only" },
  { slug: "argo-cd", name: "Argo CD", suite: "Infra", mode: "api-only" },
] as const;

const ITSM_AND_IDENTITY_TOOLS: readonly Tool[] = [
  { slug: "servicenow", name: "ServiceNow", suite: "ITSM", mode: "api-only" },
  { slug: "okta", name: "Okta", suite: "Identity", mode: "api-only" },
  { slug: "onepassword", name: "1Password", suite: "Secrets", mode: "api-only" },
] as const;

const BUSINESS_TOOLS: readonly Tool[] = [
  { slug: "salesforce", name: "Salesforce", suite: "CRM", mode: "api-only" },
  { slug: "zendesk", name: "Zendesk", suite: "Support", mode: "mcp-community" },
  { slug: "hubspot", name: "HubSpot", suite: "CRM", mode: "api-only" },
  { slug: "intercom", name: "Intercom", suite: "Support", mode: "api-only" },
  { slug: "workday", name: "Workday", suite: "HR", mode: "api-only" },
  { slug: "sap", name: "SAP", suite: "ERP", mode: "api-only" },
  { slug: "netsuite", name: "NetSuite", suite: "ERP", mode: "api-only" },
  { slug: "coupa", name: "Coupa", suite: "Procurement", mode: "api-only" },
  { slug: "stripe", name: "Stripe", suite: "Payments", mode: "api-only" },
] as const;

const DATA_AND_OBSERVABILITY_TOOLS: readonly Tool[] = [
  { slug: "snowflake", name: "Snowflake", suite: "Data", mode: "api-only" },
  { slug: "databricks", name: "Databricks", suite: "Data", mode: "api-only" },
  { slug: "bigquery", name: "BigQuery", suite: "Data", mode: "api-only" },
  { slug: "postgres", name: "PostgreSQL", suite: "Data", mode: "api-only" },
  { slug: "redis", name: "Redis", suite: "Data", mode: "api-only" },
  { slug: "mongodb", name: "MongoDB", suite: "Data", mode: "api-only" },
  { slug: "datadog", name: "Datadog", suite: "Observability", mode: "api-only" },
  { slug: "splunk", name: "Splunk", suite: "SIEM", mode: "api-only" },
  { slug: "elastic", name: "Elastic", suite: "SIEM", mode: "api-only" },
  { slug: "grafana", name: "Grafana", suite: "Observability", mode: "api-only" },
  { slug: "sentry", name: "Sentry", suite: "Observability", mode: "api-only" },
  { slug: "newrelic", name: "New Relic", suite: "Observability", mode: "api-only" },
  { slug: "pagerduty", name: "PagerDuty", suite: "Incident", mode: "api-only" },
] as const;

const SECURITY_VENDOR_TOOLS: readonly Tool[] = [
  { slug: "crowdstrike", name: "CrowdStrike", suite: "Security", mode: "api-only" },
  { slug: "wiz", name: "Wiz", suite: "Security", mode: "api-only" },
  { slug: "prisma-cloud", name: "Prisma Cloud", suite: "Security", mode: "api-only" },
] as const;

const KNOWLEDGE_AND_DOCS_TOOLS: readonly Tool[] = [
  { slug: "notion", name: "Notion", suite: "Knowledge", mode: "mcp-official" },
  { slug: "box", name: "Box", suite: "Knowledge", mode: "api-only" },
] as const;

const EVENT_AND_QUEUE_TOOLS: readonly Tool[] = [
  { slug: "kafka", name: "Kafka", suite: "Events", mode: "api-only" },
  { slug: "aws-eventbridge", name: "AWS EventBridge", suite: "Events", mode: "api-only" },
  { slug: "aws-sqs", name: "AWS SQS", suite: "Queues", mode: "api-only" },
  { slug: "google-pubsub", name: "Google Pub/Sub", suite: "Events", mode: "api-only" },
  { slug: "webhooks", name: "Generic Webhooks", suite: "Events", mode: "api-only" },
] as const;

export const TOOLS_V1: readonly Tool[] = [
  ...MICROSOFT_TOOLS,
  ...GOOGLE_TOOLS,
  ...ATLASSIAN_TOOLS,
  ...DEVOPS_TOOLS,
  ...ITSM_AND_IDENTITY_TOOLS,
  ...BUSINESS_TOOLS,
  ...DATA_AND_OBSERVABILITY_TOOLS,
  ...SECURITY_VENDOR_TOOLS,
  ...KNOWLEDGE_AND_DOCS_TOOLS,
  ...EVENT_AND_QUEUE_TOOLS,
] as const;

// Keep order stable. Indexable tools are the top N tools (Microsoft-heavy first).
const INDEXABLE_TOOL_SLUGS = new Set(TOOLS_V1.slice(0, 40).map((t) => t.slug));

const WORKFLOW_TOOL_INDEXABLE_SLUGS = new Set<string>([
  // Microsoft
  ...MICROSOFT_TOOLS.map((t) => t.slug),
  // Top non-Microsoft (10-ish)
  "github",
  "jira",
  "servicenow",
  "okta",
  "salesforce",
  "zendesk",
  "datadog",
  "splunk",
  "pagerduty",
  "stripe",
]);

export const WORKFLOWS_V1: readonly Workflow[] = [
  {
    slug: "production-deploy-approval",
    name: "Production deploy with two-person approval",
    irreversibleActions: ["Deploy to production", "Rotate credentials", "Change firewall or IAM"],
    requiredControls: ["approval-gates", "two-person-rule", "forced-dry-run", "budgets", "rate-limits", "kill-switch"],
  },
  {
    slug: "access-request-automation",
    name: "Access requests and entitlement changes",
    irreversibleActions: ["Grant access", "Change group membership", "Issue privileged roles"],
    requiredControls: ["approval-gates", "two-person-rule", "secret-boundary", "budgets", "replay-requirements"],
  },
  {
    slug: "credential-rotation",
    name: "Credential rotation and secrets hygiene",
    irreversibleActions: ["Rotate API keys", "Invalidate sessions", "Update secret stores"],
    requiredControls: [
      "approval-gates",
      "two-person-rule",
      "secret-boundary",
      "forced-dry-run",
      "replay-requirements",
      "budgets",
    ],
  },
  {
    slug: "payment-approval",
    name: "Payment and invoice approvals",
    irreversibleActions: ["Send payment", "Approve invoice", "Update payout destinations"],
    requiredControls: ["approval-gates", "two-person-rule", "budgets", "forced-dry-run", "dlp-redaction"],
  },
  {
    slug: "customer-email-send",
    name: "Customer communications with DLP and approvals",
    irreversibleActions: ["Send outbound email", "Send refunds or credits", "Share attachments"],
    requiredControls: ["dlp-redaction", "approval-gates", "output-policy", "budgets", "rate-limits"],
  },
  {
    slug: "incident-triage",
    name: "Incident triage and response coordination",
    irreversibleActions: ["Disable access", "Block egress", "Rotate keys", "Declare incident"],
    requiredControls: ["tool-allow-deny", "approval-gates", "kill-switch", "rate-limits", "replay-requirements"],
  },
  {
    slug: "siem-evidence-collection",
    name: "Compliance evidence collection to SIEM",
    irreversibleActions: ["Export logs", "Share evidence artifacts"],
    requiredControls: ["egress-allowlist", "dlp-redaction", "budgets", "replay-requirements"],
  },
  {
    slug: "change-management",
    name: "Change management ticketing and approvals",
    irreversibleActions: ["Approve change", "Close change request"],
    requiredControls: ["approval-gates", "two-person-rule", "forced-dry-run", "replay-requirements"],
  },
  {
    slug: "data-exfiltration-prevention",
    name: "Prevent agent exfiltration in tool runs",
    irreversibleActions: ["Upload files", "Send sensitive data out of boundary"],
    requiredControls: ["egress-allowlist", "dlp-redaction", "file-path-scopes", "prompt-input-firewall", "kill-switch"],
  },
  {
    slug: "phishing-response",
    name: "Inbox phishing triage with safe links policy",
    irreversibleActions: ["Click or fetch external content", "Forward emails", "Quarantine messages"],
    requiredControls: ["egress-allowlist", "prompt-input-firewall", "approval-gates", "dlp-redaction"],
  },

  // Expansion to reach ~20 workflows
  {
    slug: "vendor-risk-review",
    name: "Vendor risk review and security questionnaire automation",
    irreversibleActions: ["Send vendor questionnaires", "Share security evidence"],
    requiredControls: ["dlp-redaction", "approval-gates", "replay-requirements"],
  },
  {
    slug: "sox-control-testing",
    name: "SOX control testing evidence runs",
    irreversibleActions: ["Export reports", "File audit evidence"],
    requiredControls: ["replay-requirements", "dlp-redaction", "approval-gates"],
  },
  {
    slug: "privileged-breakglass",
    name: "Privileged break-glass workflows (timeboxed)",
    irreversibleActions: ["Grant temporary admin", "Disable security controls"],
    requiredControls: ["two-person-rule", "approval-gates", "kill-switch", "rate-limits"],
  },
  {
    slug: "release-notes-to-customers",
    name: "Release notes and customer notifications with approvals",
    irreversibleActions: ["Publish release notes", "Email customers"],
    requiredControls: ["approval-gates", "dlp-redaction", "output-policy"],
  },
  {
    slug: "onboarding-offboarding",
    name: "Employee onboarding/offboarding automation",
    irreversibleActions: ["Create accounts", "Disable accounts", "Assign licenses"],
    requiredControls: ["approval-gates", "two-person-rule", "secret-boundary"],
  },
  {
    slug: "vulnerability-triage",
    name: "Vulnerability triage and patch coordination",
    irreversibleActions: ["Apply patches", "Restart services", "Open incident"],
    requiredControls: ["tool-allow-deny", "approval-gates", "forced-dry-run"],
  },
  {
    slug: "ticket-auto-routing",
    name: "Support ticket classification and routing",
    irreversibleActions: ["Assign tickets", "Change priority", "Notify customers"],
    requiredControls: ["output-policy", "rate-limits", "dlp-redaction"],
  },
  {
    slug: "knowledge-base-updates",
    name: "Knowledge base updates with review",
    irreversibleActions: ["Publish KB articles", "Edit policies"],
    requiredControls: ["approval-gates", "two-person-rule", "replay-requirements"],
  },
  {
    slug: "contract-review-approval",
    name: "Contract review and approval workflow",
    irreversibleActions: ["Approve contract language", "Send redlines"],
    requiredControls: ["dlp-redaction", "approval-gates", "output-policy"],
  },
  {
    slug: "cloud-cost-anomaly-response",
    name: "Cloud cost anomaly response",
    irreversibleActions: ["Stop workloads", "Scale down", "Disable services"],
    requiredControls: ["approval-gates", "forced-dry-run", "budgets"],
  },
] as const;

export const COMPLIANCE_FRAMEWORKS_V1: readonly ComplianceFramework[] = [
  { slug: "soc2", name: "SOC 2 Type II" },
  { slug: "hipaa", name: "HIPAA" },
  { slug: "gdpr", name: "GDPR" },
  { slug: "fedramp", name: "FedRAMP" },
  { slug: "iso27001", name: "ISO 27001" },
  { slug: "pci-dss", name: "PCI DSS" },
  { slug: "nist-ai-rmf", name: "NIST AI RMF" },
  { slug: "eu-ai-act", name: "EU AI Act" },
  { slug: "dora", name: "DORA (EU)" },
  { slug: "sox", name: "SOX" },
] as const;

export const EVENT_SOURCES_V1: readonly EventSource[] = [
  {
    slug: "microsoft-graph",
    name: "Microsoft Graph change notifications",
    triggers: ["mail inbox delta", "calendar event created", "SharePoint file changed"],
  },
  { slug: "github-webhooks", name: "GitHub webhooks", triggers: ["pull request opened", "push", "issue created"] },
  { slug: "jira-webhooks", name: "Jira webhooks", triggers: ["issue created", "status changed", "comment added"] },
  { slug: "servicenow-webhooks", name: "ServiceNow webhooks", triggers: ["incident created", "change request updated"] },
  { slug: "pagerduty-events", name: "PagerDuty events", triggers: ["incident triggered", "incident acknowledged"] },
  { slug: "datadog-monitors", name: "Datadog monitors", triggers: ["monitor alert", "SLO burn rate"] },
  { slug: "splunk-alerts", name: "Splunk alerts", triggers: ["saved search alert", "notable event"] },
  { slug: "okta-system-log", name: "Okta System Log", triggers: ["new device", "admin role changed"] },
  { slug: "salesforce-events", name: "Salesforce platform events", triggers: ["lead updated", "case escalated"] },
  { slug: "zendesk-triggers", name: "Zendesk triggers", triggers: ["ticket created", "SLA breach"] },
  { slug: "google-workspace-push", name: "Google Workspace push notifications", triggers: ["gmail message", "drive change"] },
  { slug: "azure-event-grid", name: "Azure Event Grid", triggers: ["storage blob created", "resource change"] },
  { slug: "aws-eventbridge", name: "AWS EventBridge", triggers: ["cloudtrail event", "schedule"] },
  { slug: "kafka", name: "Kafka topics", triggers: ["message on topic", "consumer lag threshold"] },
  { slug: "webhooks", name: "Generic webhooks", triggers: ["incoming webhook"] },
] as const;

export const MCP_TOPICS_V1 = [
  { slug: "what-is-mcp", title: "What is MCP (Model Context Protocol)?" },
  { slug: "security-best-practices", title: "MCP Security Best Practices" },
  { slug: "permission-manifests", title: "Permission Manifests for MCP Servers" },
  { slug: "server-auth", title: "MCP Server Authentication and Least Privilege" },
  { slug: "prompt-injection", title: "Prompt Injection in MCP Workflows" },
  { slug: "tool-poisoning", title: "Tool Poisoning and Supply Chain Risks" },
  { slug: "audit-and-logging", title: "Audit and Logging for MCP Tool Calls" },
  { slug: "testing-and-evals", title: "Testing MCP Workflows (Evals, Replay, Drift)" },
  { slug: "enterprise-controls", title: "Enterprise Controls for MCP-connected Agents" },
  { slug: "governance", title: "Governance for MCP Servers in Enterprises" },
] as const;

export const MCP_SERVERS_V1: readonly McpServer[] = [
  { slug: "github", name: "GitHub MCP Server", mode: "official" },
  { slug: "notion", name: "Notion MCP Server", mode: "official" },
  { slug: "atlassian", name: "Atlassian MCP Server (Jira/Confluence)", mode: "official" },
  { slug: "slack", name: "Slack MCP Server", mode: "official" },
  { slug: "zendesk", name: "Zendesk MCP Server", mode: "community" },
  { slug: "linear", name: "Linear MCP Server", mode: "community" },
  { slug: "gitlab", name: "GitLab MCP Server", mode: "community" },
  { slug: "google-drive", name: "Google Drive MCP Server", mode: "community" },
  { slug: "salesforce", name: "Salesforce MCP Server", mode: "community" },
  { slug: "servicenow", name: "ServiceNow MCP Server", mode: "community" },
] as const;

export const SUPPLY_CHAIN_TOPICS_V1 = [
  { slug: "signed-skills", title: "Signed Skills and Plugins" },
  { slug: "reproducible-builds", title: "Reproducible Builds for Agent Extensions" },
  { slug: "permission-manifests", title: "Permission Manifests (Tool Surfaces)" },
  { slug: "sbom", title: "SBOM for Agent Extensions" },
  { slug: "dependency-pinning", title: "Dependency Pinning and Lockfiles" },
  { slug: "static-scanning", title: "Static Scanning for Skills and MCP Servers" },
  { slug: "dynamic-scanning", title: "Dynamic Scanning and Sandbox Testing" },
  { slug: "provenance", title: "Provenance and Publisher Identity" },
  { slug: "marketplace-trust", title: "Marketplace Trust and Reputation" },
  { slug: "wasm-sandboxing", title: "WASM Sandboxing for Skills" },
  { slug: "container-sandboxing", title: "Container Sandboxing for Tool Execution" },
  { slug: "secret-exfiltration", title: "Preventing Secret Exfiltration" },
  { slug: "prompt-injection", title: "Prompt Injection as a Supply Chain Vector" },
  { slug: "update-channels", title: "Safe Update Channels and Rollbacks" },
  { slug: "key-management", title: "Key Management for Signing" },
  { slug: "attestation", title: "Build and Artifact Attestation" },
  { slug: "review-workflows", title: "Human Review Workflows for Extensions" },
  { slug: "quarantine", title: "Quarantine and Kill Switches" },
  { slug: "risk-scoring", title: "Risk Scoring for Extensions" },
  { slug: "audit-logs", title: "Audit Logs for Extension Actions" },
  // Keep list flexible. We'll generate more by repeating a few core angles.
] as const;

export const GLOSSARY_TERMS_V2 = [
  { slug: "permissioned-execution", term: "Permissioned Execution" },
  { slug: "policy-as-code", term: "Policy as Code" },
  { slug: "policy-as-code-for-agents", term: "Policy as Code for Agents" },
  { slug: "work-policy-contract", term: "Work Policy Contract (WPC)" },
  { slug: "scoped-token", term: "Scoped Token (CST)" },
  { slug: "token-scope-hash", term: "Token Scope Hash" },
  { slug: "receipt-binding", term: "Receipt Binding" },
  { slug: "gateway-receipt", term: "Gateway Receipt" },
  { slug: "proof-bundle", term: "Proof Bundle" },
  { slug: "event-chain", term: "Event Chain" },
  { slug: "universal-run-manifest", term: "Universal Run Manifest (URM)" },
  { slug: "execution-attestation", term: "Execution Attestation" },
  { slug: "proof-of-harness", term: "Proof of Harness (PoH)" },
  { slug: "tamper-evident-audit-log", term: "Tamper-evident Audit Log" },
  { slug: "replay-and-rollback", term: "Replay and Rollback" },
  { slug: "mcp", term: "Model Context Protocol (MCP)" },
  { slug: "mcp-server", term: "MCP Server" },
  { slug: "tool-policy", term: "Tool Policy" },
  { slug: "tool-allowlist", term: "Tool Allowlist" },
  { slug: "egress-allowlist", term: "Egress Allowlist" },
  { slug: "dlp-redaction", term: "DLP Redaction" },
  { slug: "step-up-approval", term: "Step-up Approval" },
  { slug: "two-person-rule", term: "Two-person Rule" },
  { slug: "forced-dry-run", term: "Forced Dry-Run" },
  { slug: "agent-sandbox", term: "Agent Sandbox" },
  { slug: "sandboxing", term: "Sandboxing" },
  { slug: "prompt-injection", term: "Prompt Injection" },
  { slug: "tool-poisoning", term: "Tool Poisoning" },
  { slug: "supply-chain-security", term: "Supply Chain Security" },
  { slug: "signed-extensions", term: "Signed Extensions" },
  { slug: "reproducible-build", term: "Reproducible Build" },
  { slug: "sbom", term: "Software Bill of Materials (SBOM)" },
  { slug: "provenance", term: "Provenance" },
  { slug: "openclaw", term: "OpenClaw" },
  { slug: "plugin-system", term: "Plugin System" },
  { slug: "skills", term: "Skills" },
  { slug: "byok", term: "Bring Your Own Key (BYOK)" },
  { slug: "model-routing", term: "Model Routing" },
  { slug: "human-in-the-loop", term: "Human in the Loop" },
  { slug: "audit-trail", term: "Audit Trail" },
  { slug: "idempotency", term: "Idempotency" },
  { slug: "json-canonicalization", term: "JSON Canonicalization (JCS)" },
  { slug: "ed25519", term: "Ed25519 Signatures" },
  { slug: "did", term: "Decentralized Identifier (DID)" },
  { slug: "event-native", term: "Event-native Automation" },
  { slug: "webhooks", term: "Webhooks" },
  { slug: "changefeed", term: "Changefeed" },
  { slug: "queue", term: "Queues" },
  { slug: "rate-limiting", term: "Rate Limiting" },
  { slug: "budgets", term: "Budgets" },
  { slug: "data-residency", term: "Data Residency" },
  { slug: "soc2", term: "SOC 2" },
  { slug: "hipaa", term: "HIPAA" },
  { slug: "gdpr", term: "GDPR" },
  { slug: "fedramp", term: "FedRAMP" },
  { slug: "iso27001", term: "ISO 27001" },
  { slug: "pci-dss", term: "PCI DSS" },
  { slug: "nist-ai-rmf", term: "NIST AI RMF" },
  { slug: "eu-ai-act", term: "EU AI Act" },
  { slug: "dora", term: "DORA" },
  { slug: "sox", term: "SOX" },
  { slug: "enterprise-agent-governance", term: "Enterprise Agent Governance" },
  { slug: "shadow-ai", term: "Shadow AI" },
  { slug: "least-privilege", term: "Least Privilege" },
  { slug: "scoped-credentials", term: "Scoped Credentials" },
  { slug: "secret-exfiltration", term: "Secret Exfiltration" },
  { slug: "kill-switch", term: "Kill Switch" },
  { slug: "rollback", term: "Rollback" },
  { slug: "evidence-retention", term: "Evidence Retention" },
  { slug: "drift", term: "Drift" },
  { slug: "evals", term: "Agent Evals" },
  { slug: "observability", term: "Agent Observability" },
  { slug: "siem", term: "SIEM" },
  { slug: "incident-response", term: "Incident Response" },
  { slug: "change-management", term: "Change Management" },
  { slug: "access-review", term: "Access Review" },
  { slug: "breakglass", term: "Break-glass Access" },
  { slug: "graph-permissions", term: "Microsoft Graph Permissions" },
  { slug: "oauth-scopes", term: "OAuth Scopes" },
  { slug: "app-registration", term: "App Registration" },
  { slug: "service-principal", term: "Service Principal" },
  { slug: "conditional-access", term: "Conditional Access" },
  { slug: "dlp", term: "Data Loss Prevention (DLP)" },
  { slug: "secrets-manager", term: "Secrets Manager" },
  { slug: "key-rotation", term: "Key Rotation" },
  { slug: "approval-workflow", term: "Approval Workflow" },
  { slug: "simulate-first", term: "Simulate-first" },
  { slug: "policy-simulation", term: "Policy Simulation" },
  { slug: "policy-diff", term: "Policy Diff" },
  { slug: "policy-versioning", term: "Policy Versioning" },
  { slug: "artifact-hash", term: "Artifact Hash" },
  { slug: "merkle-root", term: "Merkle Root" },
  { slug: "content-provenance", term: "Content Provenance" },
  { slug: "c2pa", term: "C2PA" },
  { slug: "llm-firewall", term: "LLM Firewall" },
  { slug: "agent-firewall", term: "Agent Firewall" },
  { slug: "secure-workers", term: "Secure Workers" },
  { slug: "secure-runtime", term: "Secure Runtime" },
  { slug: "container-isolation", term: "Container Isolation" },
  { slug: "confidential-computing", term: "Confidential Computing" },
  { slug: "tee", term: "Trusted Execution Environment (TEE)" },
  { slug: "attestation", term: "Attestation" },
  { slug: "audit-ready", term: "Audit-ready" },
  { slug: "vendor-lock-in", term: "Vendor Lock-in" },
  { slug: "model-lock-in", term: "Model Lock-in" },
  { slug: "data-exfiltration", term: "Data Exfiltration" },
  { slug: "ssrf", term: "SSRF" },
  { slug: "prompt-pack", term: "Prompt Pack" },
  { slug: "system-prompt-report", term: "System Prompt Report" },
  { slug: "trust-pulse", term: "Trust Pulse" },
  { slug: "device-pairing", term: "Device Pairing" },
  { slug: "channel-routing", term: "Channel Routing" },
  { slug: "mention-gating", term: "Mention Gating" },
  { slug: "allowlist", term: "Allowlist" },
  { slug: "denylist", term: "Denylist" },
  { slug: "sandbox-mode", term: "Sandbox Mode" },
  { slug: "workspace-access", term: "Workspace Access" },
  { slug: "multi-agent", term: "Multi-agent" },
  { slug: "mission-id", term: "Mission ID" },
  { slug: "observability-stack", term: "Observability Stack" },
  { slug: "opentelemetry", term: "OpenTelemetry" },
  { slug: "structured-output", term: "Structured Output" },
  { slug: "streaming", term: "Streaming" },
  { slug: "idempotency-key", term: "Idempotency Key" },
] as const;

export const COMPETITORS = [
  { slug: "langchain", name: "LangChain" },
  { slug: "crewai", name: "CrewAI" },
  { slug: "autogen", name: "AutoGen" },
  { slug: "openai-agents-sdk", name: "OpenAI Agents SDK" },
  { slug: "aws-bedrock-agents", name: "AWS Bedrock Agents" },
  { slug: "google-vertex-agents", name: "Google Vertex AI Agents" },
  { slug: "semantic-kernel", name: "Microsoft Semantic Kernel" },
  { slug: "llamaindex", name: "LlamaIndex Agents" },
  { slug: "dify", name: "Dify" },
  { slug: "n8n", name: "n8n" },
  { slug: "relevance-ai", name: "Relevance AI" },
  { slug: "dust", name: "Dust" },
  { slug: "pipedream", name: "Pipedream" },
  { slug: "zapier", name: "Zapier" },
  { slug: "workato", name: "Workato" },
] as const;

export const ROLES = [
  { slug: "ciso", name: "CISO", concerns: "agent governance, policy enforcement, supply chain, auditability" },
  { slug: "cio", name: "CIO", concerns: "IT governance, budgets, shadow AI, fleet management" },
  { slug: "cto", name: "CTO", concerns: "platform architecture, scalability, vendor lock-in" },
  { slug: "platform-engineering", name: "Platform Engineering", concerns: "deployment, reliability, policy-as-code, observability" },
  { slug: "security-engineering", name: "Security Engineering", concerns: "egress control, DLP, incident response, threat models" },
  { slug: "internal-audit", name: "Internal Audit", concerns: "evidence, replayability, controls mapping" },
  { slug: "compliance-officer", name: "Compliance Officer", concerns: "framework mapping, audit readiness" },
  { slug: "data-protection-officer", name: "Data Protection Officer", concerns: "GDPR, DLP, data residency" },
  { slug: "head-of-ai", name: "Head of AI", concerns: "evals, model routing, governance" },
  { slug: "procurement", name: "Procurement", concerns: "vendor risk, contracts, SLAs" },
] as const;

// ── Prompt building ──────────────────────────────────────────────

const SYSTEM_CONTEXT = `You are writing for clawea.com (Claw EA), an enterprise platform for running OpenClaw agents with secure execution.

Core thesis:
- OpenClaw-era agents make chat control planes + always-on agents + skills commodity.
- The bottleneck is secure execution: permissioned execution under machine-enforced constraints.
- Differentiation is control layers: policy-as-code, sandbox, attestation, auditing, rollback posture, secrets, approvals.

Hard requirements:
- No em dashes (—).
- Avoid buzzwords. Write like an engineer briefing an enterprise team.
- Short paragraphs (2 to 3 sentences).
- Direct answer first (2 to 3 sentences).
- Include a practical step-by-step section (3 to 7 steps).
- Include 3 to 6 FAQs. FAQ questions must end with question marks.
- Include:
  - A "Threat model" section with concrete failure modes.
  - A "Policy-as-code example" section with a short JSON-like snippet.
  - A "What proof do you get" section describing receipts, proofs, or audit artifacts.
- Do not invent product endpoints. If an integration is not guaranteed, describe it as "via official API" or "via MCP server" or "enterprise buildout" explicitly.

Terminology glossary (use these exact expansions, do not invent others):
- WPC = Work Policy Contract (signed, hash-addressed policy artifact; served by clawcontrols).
- CST = scoped token (issued by clawscope). Do not expand CST as anything else.
- Gateway receipts = signed receipts emitted by clawproxy for model calls.
- Proof bundle = harness artifact bundling receipts and related metadata for audit/verification.
- Trust Pulse = marketplace-stored artifact for audit/viewing (do not invent extra semantics).

Platform truth table (consistency rules):
Shipped (you may describe as available):
- WPC registry plus proxy fetch/verify
- CST scope hash and optional policy hash pinning
- Gateway receipts for model calls
- Proof bundles
- Marketplace anti-replay binding (job-scoped CST binding)
- Trust Pulse artifact storage/viewer
- OpenRouter via fal routed through clawproxy

Planned or optional (label as planned, optional, or "can be implemented" if mentioned):
- Egress allowlists enforced outside clawproxy
- Automatic cost budget enforcement
- Transparency log inclusion proofs

Rule: If a feature is not in the Shipped list, do not present it as shipped. If relevant, you may say it can usually be fast-forwarded quickly (often within 24 hours) by Antfarm.

Output:
- Return clean HTML fragments only. No markdown code fences.
- Use <h2> for main sections and <h3> for FAQ questions.`;

function controlBySlug(slug: string): Control | undefined {
  return ALL_CONTROLS.find((c) => c.slug === slug);
}

function formatControls(slugs: Array<Control["slug"]>): string {
  const names = slugs
    .map((s) => controlBySlug(s)?.name ?? s)
    .filter(Boolean);
  return names.map((n) => `- ${n}`).join("\n");
}

function formatIrreversibleActions(items: string[]): string {
  return items.map((x) => `- ${x}`).join("\n");
}

function toolModeLine(tool: Tool): string {
  const mode = tool.mode;
  if (mode === "mcp-official") return "Connectable via an official MCP server or official API.";
  if (mode === "mcp-community") return "Connectable via a community MCP server or official API.";
  if (mode === "api-only") return "Connectable via official APIs (no MCP server assumed).";
  return "Integration should be described as enterprise buildout (roadmap) unless citations prove otherwise.";
}

function makeHubPrompt(title: string, audience: string, bullets: string[]): string {
  return `${SYSTEM_CONTEXT}

Write a 800-1100 word hub page: "${title}".
Audience: ${audience}.

Cover:
- What this section is and why it exists.
- A tight taxonomy: 6 to 10 subtopics with one-sentence descriptions.
- How Claw EA applies permissioned execution here (policy, approvals, budgets, proof).
- A short "How to get started" checklist.
- FAQ (3-5).

Include these subtopics:
${bullets.map((b) => `- ${b}`).join("\n")}

End with a CTA: Talk to Sales for enterprise rollout guidance.`;
}

function makePillarPrompt(title: string, angle: string): string {
  return `${SYSTEM_CONTEXT}

Write a 900-1300 word pillar page: "${title}".
Angle: ${angle}.

Must include:
- Direct answer first.
- A step-by-step implementation plan.
- Threat model (concrete attacks and misconfigurations).
- Policy-as-code example (short JSON-like snippet).
- What proof do you get (receipts, audit logs, replayability, retention).
- FAQ (4-6).

Avoid generic "AI adoption" stats. Focus on enforcement, evidence, and failure modes.`;
}

function makeControlPrompt(c: Control): string {
  return `${SYSTEM_CONTEXT}

Write a 700-1000 word page: "${c.name} for Enterprise Agents".
Slug concept: /controls/${c.slug}

Cover:
- What this control is.
- What it prevents (threat model).
- How to implement it in an agent runtime (OpenClaw-style tool policy + sandbox boundary).
- Policy-as-code example snippet showing the rule.
- What proof/evidence you log for audits.
- Step-by-step setup.
- FAQ (3-5).

Be concrete. Prefer examples that mention Microsoft 365 and common enterprise tools.`;
}

function makeControlExamplesPrompt(c: Control): string {
  return `${SYSTEM_CONTEXT}

Write a 700-1000 word page: "Examples: ${c.name} Policies".
Slug concept: /controls/${c.slug}/examples

Provide:
- 5 to 8 distinct policy examples (short snippets) for different scenarios.
- For each example: what it blocks, what it allows, and why.
- Include at least two Microsoft-heavy examples (Graph, SharePoint, Entra).
- Include one example for MCP-connected tools.
- Include one example for incident response.

Include a short verification checklist and FAQ (3 questions).`;
}

function makePolicyArtifactPrompt(slug: string, title: string, focus: string): string {
  return `${SYSTEM_CONTEXT}

Write a 800-1100 word page: "${title}".
Path: /policy/${slug}
Focus: ${focus}

Include:
- Direct answer.
- How it works (conceptually).
- A minimal schema-style snippet (fields and meaning).
- Validation rules (fail-closed behavior).
- Threat model.
- What proof do you get.
- FAQ (3-5).

Avoid invented endpoint URLs.`;
}

function makeProofPrompt(slug: string, title: string, focus: string): string {
  return `${SYSTEM_CONTEXT}

Write a 800-1100 word page: "${title}".
Path: /${slug}
Focus: ${focus}

Include:
- Direct answer.
- What is signed, what is hashed, what is replayable.
- A short example "receipt" or "bundle" shape.
- Verification steps.
- Common pitfalls.
- FAQ (3-5).`;
}

function makeChannelPrompt(channel: Channel, sub: "hub" | "access-control" | "deployment" | "threat-model"): string {
  const baseTitle = `${channel.name} Agent Control Plane`;
  const title =
    sub === "hub"
      ? baseTitle
      : sub === "access-control"
        ? `${channel.name} Agent Access Control`
        : sub === "deployment"
          ? `${channel.name} Agent Deployment and Hardening`
          : `${channel.name} Agent Threat Model`;

  const focus =
    sub === "hub"
      ? "overview, why this channel is a good control plane, how approvals and proof show up in the chat UI"
      : sub === "access-control"
        ? "pairing, allowlists, mention gating, admin boundaries, least privilege"
        : sub === "deployment"
          ? "setup checklist, permissions, secrets handling, operational hardening"
          : "attack paths: prompt injection via chat, tool misuse, exfiltration, social engineering";

  return `${SYSTEM_CONTEXT}

Write a 700-1000 word page: "${title}".
Path: /channels/${channel.slug}${sub === "hub" ? "" : `/${sub}`}
Focus: ${focus}

Include:
- Direct answer first.
- A concrete setup flow.
- A policy-as-code snippet tailored to this channel.
- Threat model.
- What proof do you get.
- FAQ (3-5).

If the channel is not a typical enterprise system (e.g. Discord), be honest about where it fits.`;
}

function makeToolPrompt(tool: Tool, sub: "hub" | "security" | "api" | "mcp" | "workflows"): string {
  const title =
    sub === "hub"
      ? `${tool.name} for Permissioned Agents`
      : sub === "security"
        ? `${tool.name} Security for Agents (Least Privilege + Approvals)`
        : sub === "api"
          ? `${tool.name} API Integration Pattern for Agents`
          : sub === "mcp"
            ? `${tool.name} via MCP Server (Security + Governance)`
            : `${tool.name} Workflows for Enterprise Agents`;

  const focus =
    sub === "hub"
      ? `what ${tool.name} is used for, why it is risky for agents, and the control surface you must enforce`
      : sub === "security"
        ? `permissions model, least privilege scopes, approval gates, DLP, audit evidence`
        : sub === "api"
          ? `API-only integration approach, scope minimization, idempotency, safe retries`
          : sub === "mcp"
            ? `MCP server approach, permission manifests, supply chain, tool allowlists`
            : `3 to 5 high-value workflows, each with required controls and proof artifacts`;

  const modeLine = toolModeLine(tool);

  return `${SYSTEM_CONTEXT}

Write a 700-1000 word page: "${title}".
Path: /tools/${tool.slug}${sub === "hub" ? "" : `/${sub}`}
Tool suite: ${tool.suite ?? "(none)"}
Connection mode note: ${modeLine}
Focus: ${focus}

Must include:
- Direct answer.
- Threat model: what can go wrong if a skill/plugin is malicious or misconfigured.
- Policy-as-code example snippet for this tool.
- What proof do you get.
- Step-by-step.
- FAQ (3-5).

Do not claim Claw EA ships a native connector unless you can state it as "via official API" or "via MCP server" or "enterprise buildout".`;
}

function makeWorkflowPrompt(
  workflow: Workflow,
  tool?: Tool,
  channel?: Channel,
): string {
  const title = tool
    ? channel
      ? `${workflow.name} with ${tool.name} in ${channel.name}`
      : `${workflow.name} with ${tool.name}`
    : `${workflow.name} (Permissioned Execution)`;

  const path = tool
    ? channel
      ? `/workflows/${workflow.slug}/${tool.slug}/${channel.slug}`
      : `/workflows/${workflow.slug}/${tool.slug}`
    : `/workflows/${workflow.slug}`;

  const toolLine = tool
    ? `Tool: ${tool.name} (${toolModeLine(tool)})`
    : "Tool: (generic)";

  const channelLine = channel ? `Channel: ${channel.name}` : "Channel: (any control plane)";

  return `${SYSTEM_CONTEXT}

Write a 800-1200 word workflow page: "${title}".
Path: ${path}
${toolLine}
${channelLine}

Irreversible actions to treat as high risk:
${formatIrreversibleActions(workflow.irreversibleActions)}

Required controls (must appear as concrete steps and policy snippets):
${formatControls(workflow.requiredControls)}

Must include:
- Direct answer.
- A step-by-step runbook.
- Threat model for this workflow.
- Policy-as-code example snippet tailored to this workflow.
- What proof do you get (receipts, audit logs, replay posture).
- Rollback posture: what can be rolled back and what cannot.
- FAQ (4-6).

Avoid vague ROI claims. Stay concrete and safety-first.`;
}

function makeEventSourcePrompt(es: EventSource, sub: "hub" | "security" | "policy"): string {
  const title =
    sub === "hub"
      ? `${es.name} for Event-native Agents`
      : sub === "security"
        ? `${es.name} Security (Webhooks, Spoofing, Replay, Least Privilege)`
        : `${es.name} Policy-as-Code Templates for Triggers`;

  const focus =
    sub === "hub"
      ? `how to trigger agents from ${es.name}, why cron is weaker, and how to keep it safe`
      : sub === "security"
        ? `webhook verification, replay protection, idempotency, egress constraints`
        : `example policies for triggers: budgets, approvals, allowlists, evidence retention`;

  return `${SYSTEM_CONTEXT}

Write a 700-1000 word page: "${title}".
Path: /events/${es.slug}${sub === "hub" ? "" : `/${sub}`}
Focus: ${focus}

Event examples:
${es.triggers.map((t) => `- ${t}`).join("\n")}

Must include:
- Direct answer.
- Step-by-step.
- Threat model.
- Policy-as-code example.
- What proof do you get.
- FAQ (3-5).`;
}

function makeMcpTopicPrompt(slug: string, title: string): string {
  return `${SYSTEM_CONTEXT}

Write a 800-1100 word page: "${title}".
Path: /mcp/${slug}

Include:
- Direct answer.
- Threat model: prompt injection and tool poisoning via MCP.
- Permission manifest guidance.
- Governance: who can add servers, how to review updates.
- Policy-as-code example snippet for allowlisting MCP tools.
- What proof do you get.
- FAQ (3-5).`;
}

function makeMcpServerPrompt(server: McpServer, sub: "hub" | "security"): string {
  const title =
    sub === "hub" ? `${server.name} (Enterprise Setup Pattern)` : `${server.name} Security and Governance`;

  const modeLine = server.mode === "official" ? "Official MCP server exists." : "Community MCP server exists.";

  return `${SYSTEM_CONTEXT}

Write a 800-1100 word page: "${title}".
Path: /mcp/servers/${server.slug}${sub === "hub" ? "" : "/security"}
Note: ${modeLine}

Include:
- Direct answer.
- How to connect an agent to this server safely.
- Threat model and supply chain posture.
- Policy-as-code example (tool allowlist + egress allowlist).
- What proof do you get.
- FAQ (3-5).`;
}

function makeSupplyChainPrompt(slug: string, title: string): string {
  return `${SYSTEM_CONTEXT}

Write a 800-1100 word page: "${title}".
Path: /supply-chain/${slug}

Include:
- Direct answer.
- Threat model: how malicious skills/plugins compromise systems.
- A practical checklist.
- A permission manifest example.
- An evidence and retention recommendation.
- FAQ (3-5).`;
}

function makeCompliancePrompt(cf: ComplianceFramework, sub: "hub" | "controls" | "evidence"): string {
  const title =
    sub === "hub"
      ? `${cf.name} for Permissioned Agents`
      : sub === "controls"
        ? `${cf.name} Controls Mapping for Agents`
        : `${cf.name} Evidence (Proof Bundles, Receipts, Audit Logs)`;

  const focus =
    sub === "hub"
      ? "what this framework expects, and how agent execution changes the control surface"
      : sub === "controls"
        ? "map agent controls to audit controls, be specific"
        : "what artifacts you need, how to retain, how to replay";

  return `${SYSTEM_CONTEXT}

Write a 800-1100 word page: "${title}".
Path: /compliance/${cf.slug}${sub === "hub" ? "" : `/${sub}`}
Focus: ${focus}

Include:
- Direct answer.
- Step-by-step.
- Threat model.
- Policy-as-code example.
- What proof do you get.
- FAQ (3-5).`;
}

function makeComplianceWorkflowPrompt(cf: ComplianceFramework, wf: Workflow): string {
  return `${SYSTEM_CONTEXT}

Write a 800-1100 word page: "${cf.name} Evidence for: ${wf.name}".
Path: /compliance/${cf.slug}/workflows/${wf.slug}

Focus:
- Evidence artifacts and retention policy.
- The minimum controls needed to pass an audit for this workflow.

Required controls:
${formatControls(wf.requiredControls)}

Include:
- Direct answer.
- Step-by-step.
- Threat model.
- Policy-as-code snippet.
- What proof do you get.
- FAQ (3-5).

Do not invent framework clauses; keep it practical.`;
}

function makeGuidePrompt(slug: string, title: string, brief: string): string {
  return `${SYSTEM_CONTEXT}

Write a 900-1400 word implementation guide: "${title}".
Path: /guides/${slug}
Brief: ${brief}

Format:
1) Brief intro (2-3 sentences)
2) Prerequisites
3) Step-by-step instructions (4-8 steps)
4) Verification (how to confirm)
5) Troubleshooting (3 issues)
6) FAQ (3-5)

Include at least one policy-as-code example and one proof/evidence note.`;
}

function makeGlossaryPrompt(term: string): string {
  return `${SYSTEM_CONTEXT}

Write a 450-650 word glossary entry: "What is ${term}?".

Format:
- Definition (2 sentences).
- How it works (4-6 sentences, technical).
- Why it matters for enterprise agents (3-5 sentences).
- How Claw EA/OpenClaw relates (avoid invented features).
- FAQ (2-3 questions).

This should be optimized for AEO featured snippets. Use short, direct sentences.`;
}

function makeComparisonPrompt(slug: string, title: string, angle: string): string {
  return `${SYSTEM_CONTEXT}

Write a 900-1300 word comparison page: "${title}".
Path: /compare/${slug}
Angle: ${angle}

Include:
- Direct answer.
- A comparison table focused on enforcement: policy, sandbox boundary, proof artifacts, supply chain posture, audit readiness.
- When to choose each approach.
- FAQ (3-5).

Avoid hype. Be fair and specific.`;
}

function makeCompetitorPrompt(comp: { slug: string; name: string }): string {
  return `${SYSTEM_CONTEXT}

Write a 900-1300 word page: "Claw EA vs ${comp.name} for Secure Enterprise Agents".
Path: /vs/${comp.slug}

Be fair and factual.
Cover:
- What ${comp.name} is.
- What Claw EA is (permissioned execution + policy-as-code + proof).
- Comparison table: tool policy, sandboxing, approvals, budgets, receipts/proofs, supply chain posture.
- Migration path.
- FAQ (3-5).

Do not claim ${comp.name} features you cannot cite. Focus on categories and trade-offs.`;
}

function makeRolePrompt(r: { slug: string; name: string; concerns: string }): string {
  return `${SYSTEM_CONTEXT}

Write a 800-1100 word page: "Claw EA for ${r.name}".
Path: /for/${r.slug}
Their concerns: ${r.concerns}

Cover:
- What could go wrong with agents without permissioned execution.
- What controls they can enforce.
- What evidence they can export.
- A rollout checklist.
- FAQ (3-5).`;
}

// ── Topic Generation ──────────────────────────────────────────────

export function generateAllTopics(): Topic[] {
  const topics: Topic[] = [];
  const seen = new Set<string>();

  function add(t: Topic): void {
    if (seen.has(t.slug)) {
      throw new Error(`Duplicate slug in taxonomy: ${t.slug}`);
    }
    seen.add(t.slug);
    topics.push(t);
  }

  // Pillars
  const pillarPages: Array<{ slug: string; title: string; angle: string }> = [
    { slug: "policy-as-code-for-agents", title: "Policy-as-Code for Agents (Permissioned Execution) | Claw EA", angle: "The enforceable rules that make agents safe in enterprise." },
    { slug: "secure-agent-execution", title: "Secure Agent Execution (Permissioned Runtime) | Claw EA", angle: "Sandboxing, tool policy, secrets boundaries, and fail-closed behavior." },
    { slug: "agent-proof-and-attestation", title: "Agent Proof and Attestation (Receipts and Proof Bundles) | Claw EA", angle: "What you can prove, to whom, and how verification works." },
    { slug: "agent-supply-chain-security", title: "Agent Supply Chain Security (Skills, Plugins, MCP) | Claw EA", angle: "Signed extensions, permission manifests, provenance, and safe updates." },
    { slug: "event-native-agents", title: "Event-native Agents (Webhooks, Changefeeds, Queues) | Claw EA", angle: "Replace cron with event streams, but keep policy and proof." },
    { slug: "mcp-security", title: "MCP Security for Enterprise Agents | Claw EA", angle: "How to use MCP without turning tools into an exfiltration surface." },
    { slug: "agent-audit-and-replay", title: "Agent Audit and Replay (Evidence, Retention, Rollback) | Claw EA", angle: "Audit-ready operations with replay and rollback posture." },
    { slug: "enterprise-agent-governance", title: "Enterprise Agent Governance (Policy, Approvals, Budgets) | Claw EA", angle: "How to govern agents as a new security boundary." },
  ];

  for (const p of pillarPages) {
    add({
      slug: p.slug,
      title: p.title,
      category: "pillars",
      priority: 0.95,
      indexable: true,
      prompt: makePillarPrompt(p.title.replace(/ \| Claw EA$/, ""), p.angle),
    });
  }

  // Hub index pages (ensure sitemap doesn't include dead links)
  const hubPages: Array<{ slug: string; title: string; bullets: string[] }> = [
    {
      slug: "controls",
      title: "Agent Controls (Policy-as-Code) | Claw EA",
      bullets: ALL_CONTROLS.slice(0, 10).map((c) => c.name),
    },
    {
      slug: "tools",
      title: "Enterprise Tools for Permissioned Agents | Claw EA",
      bullets: TOOLS_V1.slice(0, 10).map((t) => t.name),
    },
    {
      slug: "channels",
      title: "Chat Control Planes for Agents (Channels) | Claw EA",
      bullets: CHANNELS_V1.slice(0, 10).map((c) => c.name),
    },
    {
      slug: "workflows",
      title: "Enterprise Agent Workflows (Safe by Policy) | Claw EA",
      bullets: WORKFLOWS_V1.slice(0, 10).map((w) => w.name),
    },
    {
      slug: "policy",
      title: "Policy Artifacts (WPC, Scoped Tokens, Proof) | Claw EA",
      bullets: [
        "Work Policy Contracts (WPC)",
        "Scoped Tokens (CST)",
        "Receipts and Proof Bundles",
        "Validation and fail-closed rules",
      ],
    },
    {
      slug: "proof",
      title: "Proof and Attestation for Agents | Claw EA",
      bullets: [
        "Gateway receipts",
        "Proof bundles",
        "Event chains",
        "Verification",
        "Replay posture",
      ],
    },
    {
      slug: "mcp",
      title: "MCP (Model Context Protocol) for Enterprise Agents | Claw EA",
      bullets: MCP_TOPICS_V1.slice(0, 8).map((t) => t.title),
    },
    {
      slug: "supply-chain",
      title: "Agent Supply Chain Security (Skills and Plugins) | Claw EA",
      bullets: SUPPLY_CHAIN_TOPICS_V1.slice(0, 8).map((t) => t.title),
    },
    {
      slug: "events",
      title: "Event-native Agents (Triggers) | Claw EA",
      bullets: EVENT_SOURCES_V1.slice(0, 8).map((e) => e.name),
    },
    {
      slug: "compliance",
      title: "Compliance for Permissioned Agents | Claw EA",
      bullets: COMPLIANCE_FRAMEWORKS_V1.map((c) => c.name),
    },
    {
      slug: "guides",
      title: "Implementation Guides for Permissioned Agents | Claw EA",
      bullets: [
        "Lock down egress",
        "Add approvals",
        "Set budgets",
        "Verify proof bundles",
      ],
    },
    {
      slug: "glossary",
      title: "Glossary: Enterprise Agent Security and Policy Terms | Claw EA",
      bullets: GLOSSARY_TERMS_V2.slice(0, 10).map((g) => g.term),
    },
  ];

  for (const h of hubPages) {
    add({
      slug: h.slug,
      title: h.title,
      category: "hubs",
      priority: 0.9,
      indexable: true,
      prompt: makeHubPrompt(h.title.replace(/ \| Claw EA$/, ""), "Security, platform engineering, and compliance teams", h.bullets),
    });
  }

  // Controls
  for (const c of ALL_CONTROLS) {
    const isCore = CONTROLS_V1.some((x) => x.slug === c.slug);
    add({
      slug: `controls/${c.slug}`,
      title: `${c.name} for Agents | Policy-as-Code Control | Claw EA`,
      category: "controls",
      priority: isCore ? 0.85 : 0.55,
      indexable: isCore,
      prompt: makeControlPrompt(c),
    });

    add({
      slug: `controls/${c.slug}/examples`,
      title: `Examples: ${c.name} Policies | Claw EA`,
      category: "controls",
      priority: 0.45,
      indexable: false,
      prompt: makeControlExamplesPrompt(c),
    });
  }

  // Policy artifacts and proof pages
  const policyArtifacts: Array<{ slug: string; title: string; focus: string; indexable: boolean }> = [
    { slug: "work-policy-contract", title: "Work Policy Contracts (WPC)", focus: "portable policy-as-code for tool calls, egress, DLP, and approvals", indexable: true },
    { slug: "scoped-tokens", title: "Scoped Tokens (CST)", focus: "audience-scoped tokens for agent runs and tool calls", indexable: true },
    { slug: "token-scope-hash", title: "Token Scope Hash", focus: "deterministic hashing of scopes for binding and audit", indexable: true },
    { slug: "receipt-binding", title: "Receipt Binding", focus: "bind receipts to runs, agents, and policies to prevent replay", indexable: true },
    { slug: "proof-bundles", title: "Proof Bundles", focus: "bundle receipts, event chains, and artifacts into a verifiable package", indexable: true },
    { slug: "event-chain", title: "Event Chains", focus: "tamper-evident event logs with hashes and signatures", indexable: true },
    { slug: "urm", title: "Universal Run Manifest (URM)", focus: "summarize inputs, outputs, artifacts, and proofs for verification", indexable: true },
    { slug: "system-prompt-report", title: "System Prompt Report", focus: "prompt commitments and verification posture", indexable: true },
    { slug: "prompt-pack", title: "Prompt Pack", focus: "prompt commitments as hash-only artifacts", indexable: true },
    { slug: "trust-pulse", title: "Trust Pulse", focus: "self-reported trust evidence without tier uplift", indexable: false },
  ];

  for (const a of policyArtifacts) {
    add({
      slug: `policy/${a.slug}`,
      title: `${a.title} | Policy Artifact | Claw EA`,
      category: "policy",
      priority: a.indexable ? 0.85 : 0.45,
      indexable: a.indexable,
      prompt: makePolicyArtifactPrompt(a.slug, a.title, a.focus),
    });

    add({
      slug: `policy/${a.slug}/schema`,
      title: `${a.title} Schema and Fields | Claw EA`,
      category: "policy",
      priority: 0.5,
      indexable: false,
      prompt: makePolicyArtifactPrompt(`${a.slug}/schema`, `${a.title} Schema`, "schema-first explanation and field semantics"),
    });

    add({
      slug: `policy/${a.slug}/validation`,
      title: `${a.title} Validation (Fail-Closed) | Claw EA`,
      category: "policy",
      priority: 0.45,
      indexable: false,
      prompt: makePolicyArtifactPrompt(`${a.slug}/validation`, `${a.title} Validation`, "validation rules and fail-closed behavior"),
    });
  }

  // Dedicated proof / verify / audit pages (small set)
  const proofPages: Array<{ slug: string; title: string; focus: string; category: string; indexable: boolean }> = [
    { slug: "proof/gateway-receipts", title: "Gateway Receipts for Agents", focus: "what is signed and how to verify", category: "proof", indexable: true },
    { slug: "proof/proof-bundles", title: "Proof Bundles for Agent Runs", focus: "bundle shapes, retention, verification", category: "proof", indexable: true },
    { slug: "verify/proof-bundle", title: "How to Verify a Proof Bundle", focus: "fail-closed checks and common pitfalls", category: "verify", indexable: true },
    { slug: "verify/gateway-receipt", title: "How to Verify a Gateway Receipt", focus: "signature verification and binding", category: "verify", indexable: true },
    { slug: "audit/tamper-evident-logs", title: "Tamper-evident Audit Logs for Agents", focus: "what to log and how to retain", category: "audit", indexable: true },
    { slug: "audit/replay-and-rollback", title: "Replay and Rollback for Agent Actions", focus: "what can be replayed, what cannot", category: "audit", indexable: true },
  ];

  for (const p of proofPages) {
    add({
      slug: p.slug,
      title: `${p.title} | Claw EA`,
      category: p.category,
      priority: p.indexable ? 0.8 : 0.5,
      indexable: p.indexable,
      prompt: makeProofPrompt(p.slug, p.title, p.focus),
    });
  }

  // Channels
  for (const ch of CHANNELS_V1) {
    const subs: Array<"hub" | "access-control" | "deployment" | "threat-model"> = [
      "hub",
      "access-control",
      "deployment",
      "threat-model",
    ];

    for (const sub of subs) {
      add({
        slug: `channels/${ch.slug}${sub === "hub" ? "" : `/${sub}`}`,
        title:
          sub === "hub"
            ? `${ch.name} AI Agent Control Plane | Claw EA`
            : `${ch.name} AI Agents: ${sub.replace(/\b\w/g, (c) => c.toUpperCase())} | Claw EA`,
        category: "channels",
        priority: sub === "hub" ? 0.75 : 0.6,
        indexable: true,
        prompt: makeChannelPrompt(ch, sub),
      });
    }
  }

  // Tools (enterprise suite pages)
  for (const t of TOOLS_V1) {
    const toolIndexable = INDEXABLE_TOOL_SLUGS.has(t.slug);

    add({
      slug: `tools/${t.slug}`,
      title: `${t.name} for Permissioned Agents | Claw EA`,
      category: "tools",
      priority: toolIndexable ? 0.72 : 0.45,
      indexable: toolIndexable,
      prompt: makeToolPrompt(t, "hub"),
    });

    // Subpages: keep noindex by default to avoid over-indexing.
    const subs: Array<"security" | "api" | "mcp" | "workflows"> = ["security", "api", "mcp", "workflows"];
    for (const sub of subs) {
      add({
        slug: `tools/${t.slug}/${sub}`,
        title: `${t.name}: ${sub.toUpperCase()} | Claw EA`,
        category: "tools-deep",
        priority: 0.35,
        indexable: false,
        prompt: makeToolPrompt(t, sub),
      });
    }
  }

  // Workflows (Pattern C: workflow -> workflow+tool -> workflow+tool+channel)
  const workflowToolAll = TOOLS_V1; // 60-ish
  const workflowDeepTools = TOOLS_V1.slice(0, 50);
  const workflowDeepChannelSlugs = new Set([
    "microsoft-teams",
    "slack",
    "email",
    "google-chat",
    "discord",
    "telegram",
    "whatsapp",
    "signal",
  ]);
  const workflowDeepChannels = CHANNELS_V1.filter((c) => workflowDeepChannelSlugs.has(c.slug));

  for (const wf of WORKFLOWS_V1) {
    // workflow root
    add({
      slug: `workflows/${wf.slug}`,
      title: `${wf.name} | Secure Agent Workflow | Claw EA`,
      category: "workflows",
      priority: 0.8,
      indexable: true,
      prompt: makeWorkflowPrompt(wf),
    });

    // workflow + tool
    for (const tool of workflowToolAll) {
      const indexable = WORKFLOW_TOOL_INDEXABLE_SLUGS.has(tool.slug);
      add({
        slug: `workflows/${wf.slug}/${tool.slug}`,
        title: `${wf.name} with ${tool.name} | Claw EA`,
        category: "workflows",
        priority: indexable ? 0.65 : 0.4,
        indexable,
        prompt: makeWorkflowPrompt(wf, tool),
      });
    }

    // workflow + tool + channel (long-tail, noindex)
    for (const tool of workflowDeepTools) {
      for (const ch of workflowDeepChannels) {
        add({
          slug: `workflows/${wf.slug}/${tool.slug}/${ch.slug}`,
          title: `${wf.name} with ${tool.name} in ${ch.name} | Claw EA`,
          category: "workflows-deep",
          priority: 0.25,
          indexable: false,
          prompt: makeWorkflowPrompt(wf, tool, ch),
        });
      }
    }
  }

  // Events
  for (const es of EVENT_SOURCES_V1) {
    for (const sub of ["hub", "security", "policy"] as const) {
      add({
        slug: `events/${es.slug}${sub === "hub" ? "" : `/${sub}`}`,
        title:
          sub === "hub"
            ? `${es.name} for Event-native Agents | Claw EA`
            : `${es.name}: ${sub.toUpperCase()} | Claw EA`,
        category: "events",
        priority: sub === "hub" ? 0.6 : 0.35,
        indexable: sub === "hub",
        prompt: makeEventSourcePrompt(es, sub),
      });
    }
  }

  // MCP
  for (const t of MCP_TOPICS_V1) {
    add({
      slug: `mcp/${t.slug}`,
      title: `${t.title} | Claw EA`,
      category: "mcp",
      priority: 0.65,
      indexable: true,
      prompt: makeMcpTopicPrompt(t.slug, t.title),
    });
  }

  for (const s of MCP_SERVERS_V1) {
    add({
      slug: `mcp/servers/${s.slug}`,
      title: `${s.name} | Claw EA`,
      category: "mcp",
      priority: 0.6,
      indexable: true,
      prompt: makeMcpServerPrompt(s, "hub"),
    });
    add({
      slug: `mcp/servers/${s.slug}/security`,
      title: `${s.name} Security | Claw EA`,
      category: "mcp",
      priority: 0.5,
      indexable: true,
      prompt: makeMcpServerPrompt(s, "security"),
    });
  }

  // Supply chain
  for (const s of SUPPLY_CHAIN_TOPICS_V1) {
    add({
      slug: `supply-chain/${s.slug}`,
      title: `${s.title} | Agent Supply Chain | Claw EA`,
      category: "supply-chain",
      priority: 0.65,
      indexable: true,
      prompt: makeSupplyChainPrompt(s.slug, s.title),
    });
  }

  // If we have fewer than 35 supply-chain pages, pad with a few generated variants.
  if (SUPPLY_CHAIN_TOPICS_V1.length < 35) {
    const pad = [
      { slug: "extension-updates", title: "Safe Extension Updates and Rollbacks" },
      { slug: "publisher-verification", title: "Publisher Verification for Skills" },
      { slug: "dependency-review", title: "Dependency Review for MCP Servers" },
      { slug: "sandbox-test-matrix", title: "Sandbox Test Matrix for High-Risk Tools" },
      { slug: "kill-switch-playbooks", title: "Kill Switch Playbooks" },
      { slug: "incident-response-for-extensions", title: "Incident Response for Malicious Extensions" },
      { slug: "signature-rotation", title: "Signing Key Rotation" },
      { slug: "artifact-registry", title: "Content-addressed Artifact Registries" },
      { slug: "review-queues", title: "Review Queues for New Skills" },
      { slug: "risk-acceptance", title: "Risk Acceptance for Agent Extensions" },
      { slug: "scope-minimization", title: "Scope Minimization for Tool Surfaces" },
      { slug: "runtime-telemetry", title: "Runtime Telemetry for Extension Actions" },
      { slug: "drift-detection", title: "Drift Detection for Tool Outputs" },
      { slug: "provenance-policies", title: "Provenance Policies" },
      { slug: "quarantine-modes", title: "Quarantine Modes" },
    ];
    for (const p of pad) {
      add({
        slug: `supply-chain/${p.slug}`,
        title: `${p.title} | Agent Supply Chain | Claw EA`,
        category: "supply-chain",
        priority: 0.55,
        indexable: true,
        prompt: makeSupplyChainPrompt(p.slug, p.title),
      });
    }
  }

  // Compliance
  for (const cf of COMPLIANCE_FRAMEWORKS_V1) {
    add({
      slug: `compliance/${cf.slug}`,
      title: `${cf.name} for Permissioned Agents | Claw EA`,
      category: "compliance",
      priority: 0.7,
      indexable: true,
      prompt: makeCompliancePrompt(cf, "hub"),
    });

    add({
      slug: `compliance/${cf.slug}/controls`,
      title: `${cf.name} Controls Mapping for Agents | Claw EA`,
      category: "compliance",
      priority: 0.65,
      indexable: true,
      prompt: makeCompliancePrompt(cf, "controls"),
    });

    add({
      slug: `compliance/${cf.slug}/evidence`,
      title: `${cf.name} Evidence for Agents (Proof, Logs, Replay) | Claw EA`,
      category: "compliance",
      priority: 0.65,
      indexable: true,
      prompt: makeCompliancePrompt(cf, "evidence"),
    });

    // Framework + workflow pages (noindex)
    for (const wf of WORKFLOWS_V1.slice(0, 10)) {
      add({
        slug: `compliance/${cf.slug}/workflows/${wf.slug}`,
        title: `${cf.name} Evidence for ${wf.name} | Claw EA`,
        category: "compliance-deep",
        priority: 0.3,
        indexable: false,
        prompt: makeComplianceWorkflowPrompt(cf, wf),
      });
    }
  }

  // Guides
  const guideTopics: Array<{ slug: string; title: string; brief: string; indexable: boolean }> = [];

  // Controls guides
  for (const c of CONTROLS_V1) {
    guideTopics.push({
      slug: `control-${c.slug}`,
      title: `How to Implement ${c.name} for Agents`,
      brief: `Practical implementation steps for ${c.name}, including a policy-as-code snippet and verification.`,
      indexable: true,
    });
  }

  // Workflow guides
  for (const wf of WORKFLOWS_V1) {
    guideTopics.push({
      slug: `workflow-${wf.slug}`,
      title: `How to Run: ${wf.name}`,
      brief: `A practical runbook for ${wf.name}, including required controls and proof artifacts.`,
      indexable: false,
    });
  }

  // Tool guides (top 20 tools)
  for (const t of TOOLS_V1.slice(0, 20)) {
    guideTopics.push({
      slug: `tool-${t.slug}`,
      title: `How to Connect Agents to ${t.name} Safely`,
      brief: `Least privilege, approvals, and policy templates for ${t.name} agent workflows.`,
      indexable: true,
    });
  }

  // Channel hardening guides
  for (const ch of CHANNELS_V1.slice(0, 10)) {
    guideTopics.push({
      slug: `channel-${ch.slug}-hardening`,
      title: `${ch.name} Agent Hardening Checklist`,
      brief: `A hardened configuration checklist for running agents through ${ch.name}.`,
      indexable: true,
    });
  }

  // Extra guides to round toward ~80
  const extraGuides = [
    { slug: "first-30-days", title: "First 30 Days of Enterprise Agent Governance", brief: "A phased rollout plan: policy, pilots, evidence, and incident drills." },
    { slug: "approval-design", title: "Designing Approval UX for Agents", brief: "How to minimize friction while fail-closing high-risk actions." },
    { slug: "budgeting", title: "Budgeting and Cost Controls for Agents", brief: "How to set per-agent budgets, rate limits, and break-glass policies." },
    { slug: "incident-drills", title: "Agent Incident Drills", brief: "Run tabletop exercises for prompt injection, exfiltration, and malicious extensions." },
    { slug: "evidence-retention", title: "Evidence Retention for Agent Runs", brief: "Retention windows, replay posture, and audit export basics." },
    { slug: "mcp-rollout", title: "Rolling Out MCP Safely", brief: "Governance and change management for MCP servers in enterprise." },
    { slug: "supply-chain-basics", title: "Supply Chain Basics for Agent Extensions", brief: "Signing, scanning, provenance, and safe updates." },
    { slug: "policy-simulation", title: "Policy Simulation and Dry-Run Patterns", brief: "How to require simulate-first and compare planned vs actual actions." },
  ];

  for (const g of extraGuides) {
    guideTopics.push({ ...g, indexable: true });
  }

  // Emit guides index page (already hub), then individual guides.
  for (const g of guideTopics) {
    add({
      slug: `guides/${g.slug}`,
      title: `${g.title} | Claw EA`,
      category: "guides",
      priority: g.indexable ? 0.65 : 0.35,
      indexable: g.indexable,
      prompt: makeGuidePrompt(g.slug, g.title, g.brief),
    });
  }

  // Glossary term pages
  for (const g of GLOSSARY_TERMS_V2) {
    add({
      slug: `glossary/${g.slug}`,
      title: `What is ${g.term}? | Enterprise Agent Glossary | Claw EA`,
      category: "glossary",
      priority: 0.55,
      indexable: true,
      prompt: makeGlossaryPrompt(g.term),
    });
  }

  // Comparisons (conceptual)
  const compareTopics: Array<{ slug: string; title: string; angle: string }> = [
    {
      slug: "agent-guardrails-vs-policy-as-code",
      title: "Agent Guardrails vs Policy-as-Code",
      angle: "Compare enforceable controls vs best-effort guardrails and prompt-only rules.",
    },
    {
      slug: "mcp-vs-custom-tooling",
      title: "MCP vs Custom Tooling",
      angle: "Security and governance trade-offs between MCP servers and bespoke integrations.",
    },
    {
      slug: "cron-vs-event-native",
      title: "Cron vs Event-native Agents",
      angle: "Reliability, security, and auditability trade-offs.",
    },
    {
      slug: "prompt-injection-defense-patterns",
      title: "Prompt Injection Defense Patterns",
      angle: "Input validation, tool sandboxes, approvals, and proof.",
    },
    {
      slug: "signed-receipts-vs-logs",
      title: "Signed Receipts vs Traditional Logs",
      angle: "What cryptographic receipts add for audits and disputes.",
    },
  ];

  for (const ct of compareTopics) {
    add({
      slug: `compare/${ct.slug}`,
      title: `${ct.title} | Claw EA`,
      category: "compare",
      priority: 0.65,
      indexable: true,
      prompt: makeComparisonPrompt(ct.slug, ct.title, ct.angle),
    });
  }

  // Competitor pages (focus on enforcement, not features)
  for (const comp of COMPETITORS) {
    add({
      slug: `vs/${comp.slug}`,
      title: `Claw EA vs ${comp.name} | Secure Enterprise Agents`,
      category: "compare",
      priority: 0.6,
      indexable: true,
      prompt: makeCompetitorPrompt(comp),
    });
  }

  // Roles
  for (const r of ROLES) {
    add({
      slug: `for/${r.slug}`,
      title: `Claw EA for ${r.name} | Enterprise Agent Governance`,
      category: "roles",
      priority: 0.6,
      indexable: true,
      prompt: makeRolePrompt(r),
    });
  }

  // Sort: highest priority first.
  topics.sort((a, b) => b.priority - a.priority);

  return topics;
}

// ── Stats ─────────────────────────────────────────────────────────

export function taxonomyStats(): {
  total: number;
  indexable: number;
  breakdown: Record<string, number>;
  indexableBreakdown: Record<string, number>;
} {
  const topics = generateAllTopics();
  const breakdown: Record<string, number> = {};
  const indexableBreakdown: Record<string, number> = {};
  let indexable = 0;

  for (const t of topics) {
    breakdown[t.category] = (breakdown[t.category] ?? 0) + 1;
    if (t.indexable) {
      indexable++;
      indexableBreakdown[t.category] = (indexableBreakdown[t.category] ?? 0) + 1;
    }
  }

  return { total: topics.length, indexable, breakdown, indexableBreakdown };
}
