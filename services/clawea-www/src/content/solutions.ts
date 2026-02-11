/**
 * Solution pages content for programmatic SEO.
 * Each solution generates a page at /solutions/{slug}.
 */

export interface Solution {
  slug: string;
  name: string;
  title: string;
  description: string;
  heroHeadline: string;
  heroSub: string;
  icon: string;
  whatIs: string;
  howItWorks: { step: string; detail: string }[];
  benefits: { title: string; text: string }[];
  technicalDetails: string;
  faqs: { q: string; a: string }[];
  relatedSolutions: string[];
  relatedIndustries: string[];
}

export const SOLUTIONS: Solution[] = [
  {
    slug: "execution-attestation",
    name: "Execution Attestation",
    title: "Execution Attestation for AI Agents | Cryptographic Proof | Claw EA",
    description: "Cryptographic attestation of every AI agent action. Proof bundles, gateway receipts, and artifact hashes create tamper-evident records of agent execution.",
    heroHeadline: "Execution Attestation: Proof That Your AI Actually Did What It Claims",
    heroSub: "Every model call, tool invocation, and data access produces a cryptographic receipt. Chain them into proof bundles that hold up to third-party verification.",
    icon: "🔏",
    whatIs: "Execution attestation is the process of creating cryptographic proof that an AI agent performed specific actions in a specific order with specific inputs and outputs. Unlike traditional logging, attestation produces tamper-evident records signed by the agent's decentralized identity (DID). These records can be independently verified by auditors, regulators, or counterparties without trusting the platform operator.",
    howItWorks: [
      { step: "Agent starts a task", detail: "The agent receives a task assignment, and Claw EA creates a new run context with a unique run ID, timestamp, and mission metadata binding." },
      { step: "Gateway receipts are collected", detail: "Every model call routes through clawproxy, which signs a receipt containing the request hash, response hash, model identifier, provider, and latency. The receipt is returned alongside the model response." },
      { step: "Tool invocations are logged", detail: "Each tool call (file read, API call, search, etc.) generates a tool event with input/output hashes and the tool identifier. Events are chained to the run context." },
      { step: "Artifact hashes are computed", detail: "All outputs (files, messages, code, documents) are SHA-256 hashed. Hashes are stored in the proof bundle and optionally uploaded to clawsilo for long-term storage." },
      { step: "Proof bundle is sealed", detail: "At task completion, all receipts, tool events, and artifact hashes are compiled into a Universal Run Manifest (URM). The URM is signed by the agent's DID and sealed with a log root hash for integrity." },
    ],
    benefits: [
      { title: "Third-party verifiability", text: "Anyone with the proof bundle and the agent's public key can verify that the work happened as claimed. No trust in the platform required." },
      { title: "Regulatory compliance", text: "Proof bundles satisfy audit trail requirements across SOC 2, HIPAA, GDPR Article 22, and sector-specific frameworks." },
      { title: "Dispute resolution", text: "When disagreements arise about what an agent did, proof bundles provide cryptographic evidence that cannot be altered after the fact." },
      { title: "Insurance and liability", text: "Attested execution records provide the evidence basis for AI liability frameworks and insurance claims." },
    ],
    technicalDetails: `Each proof bundle contains:
- **Run Manifest**: JSON document with run_id, agent_did, mission_id, start/end timestamps
- **Gateway Receipts**: Signed records from clawproxy for each model call (request_hash, response_hash, model, provider, latency_ms)
- **Tool Events**: Hashed records of every tool invocation with input/output digests
- **Artifact Hashes**: SHA-256 hashes of all agent outputs
- **Log Root Hash**: Merkle root of all events for tamper detection
- **Agent Signature**: Ed25519 signature over the complete manifest using the agent's DID key`,
    faqs: [
      { q: "What is execution attestation for AI agents?", a: "Execution attestation is the process of creating cryptographic proof of every action an AI agent performs. Each model call, tool use, and output generates a signed receipt. These receipts are compiled into a tamper-evident proof bundle that any third party can verify independently." },
      { q: "How is execution attestation different from logging?", a: "Traditional logging records events in a mutable database controlled by the platform operator. Execution attestation creates cryptographically signed, tamper-evident records. Each receipt is signed by the agent's decentralized identity (DID), and the proof bundle includes a Merkle root hash. Any modification to any record invalidates the entire chain." },
      { q: "What is a Universal Run Manifest?", a: "A Universal Run Manifest (URM) is a structured document that contains the complete attested record of an agent's task execution. It includes gateway receipts for model calls, tool event hashes, artifact hashes, timestamps, and a Merkle log root. The manifest is signed by the agent's DID key." },
      { q: "Can execution attestation be faked?", a: "Proof bundles use Ed25519 signatures tied to the agent's DID and include gateway receipts signed by clawproxy. Faking attestation would require compromising both the agent's private key and clawproxy's signing key. The Merkle chain structure means any modification to any event invalidates the entire bundle." },
    ],
    relatedSolutions: ["proof-of-harness", "work-policy-contracts", "audit-compliance"],
    relatedIndustries: ["financial-services", "healthcare", "government"],
  },
  {
    slug: "proof-of-harness",
    name: "Proof of Harness",
    title: "Proof of Harness (PoH) | Verified AI Agent Execution | Claw EA",
    description: "Proof of Harness verifies that an AI agent ran inside a trusted execution environment with proper controls. Gateway receipts from clawproxy provide the cryptographic evidence.",
    heroHeadline: "Proof of Harness: Verify the Environment, Not Just the Output",
    heroSub: "It matters where and how AI runs. PoH receipts prove your agents executed inside a controlled, policy-enforced sandbox with auditable model routing.",
    icon: "🔐",
    whatIs: "Proof of Harness (PoH) is a verification framework that proves an AI agent ran inside a trusted, controlled execution environment. While execution attestation proves what an agent did, PoH proves where and how it ran. Gateway receipts from clawproxy demonstrate that model calls were routed through a controlled gateway, not directly to providers. This matters because it proves policy enforcement, egress mediation, and receipt collection were active during execution.",
    howItWorks: [
      { step: "Agent is deployed in sandbox", detail: "Claw EA provisions the agent inside a Cloudflare Sandbox container with the enterprise trust layer pre-installed." },
      { step: "Model calls route through clawproxy", detail: "The trust layer configures ANTHROPIC_BASE_URL and OPENAI_BASE_URL to point to clawproxy. All model calls pass through the gateway." },
      { step: "clawproxy signs each receipt", detail: "For every model call, clawproxy generates a signed receipt containing the request hash, response hash, model, provider, and its own signing timestamp." },
      { step: "Receipts prove harness execution", detail: "The presence of valid clawproxy receipts in a proof bundle proves the agent ran inside a harness with active gateway mediation. No receipts = no proof of controlled execution." },
    ],
    benefits: [
      { title: "Trust without inspection", text: "Verifiers can confirm controlled execution without accessing the sandbox or the agent's data. The receipts are the proof." },
      { title: "Gateway mediation evidence", text: "PoH receipts prove model calls went through clawproxy, which means egress controls, DLP redaction, and receipt collection were active." },
      { title: "Bounty verification", text: "On clawbounties.com, PoH receipts prove that submitted work was generated by an agent running inside a verified harness, not copy-pasted from an uncontrolled environment." },
      { title: "Insurance underwriting", text: "PoH provides the evidence layer for AI execution insurance. Insurers can verify that agents ran inside controlled environments before underwriting coverage." },
    ],
    technicalDetails: `A PoH receipt from clawproxy contains:
- **receipt_id**: Unique identifier
- **proxy_did**: clawproxy's signing identity
- **agent_did**: The requesting agent's DID
- **request_hash**: SHA-256 of the canonicalized request body
- **response_hash**: SHA-256 of the canonicalized response body
- **model**: Model identifier (e.g., claude-sonnet-4-20250514)
- **provider**: Provider identifier (e.g., anthropic)
- **timestamp**: ISO 8601 timestamp
- **latency_ms**: End-to-end latency
- **signature**: Ed25519 signature over all fields by clawproxy`,
    faqs: [
      { q: "What is Proof of Harness?", a: "Proof of Harness (PoH) is a verification system that proves an AI agent executed inside a trusted, controlled environment. Gateway receipts signed by clawproxy demonstrate that model calls were mediated, policy controls were active, and execution was monitored. PoH answers the question: did this agent run in a secure harness, or in an uncontrolled environment?" },
      { q: "How does Proof of Harness differ from execution attestation?", a: "Execution attestation proves what an agent did (actions, inputs, outputs). Proof of Harness proves where and how the agent ran (inside a controlled sandbox with gateway mediation). Together, they provide complete verification: both the actions and the execution environment." },
      { q: "Why does the execution environment matter?", a: "An AI agent can produce identical output in a controlled sandbox or an uncontrolled laptop. The difference is trust. A controlled environment guarantees that egress controls, DLP redaction, and audit logging were active. Without PoH, there is no way to verify these controls were in place." },
    ],
    relatedSolutions: ["execution-attestation", "work-policy-contracts", "secure-sandbox"],
    relatedIndustries: ["financial-services", "government", "legal"],
  },
  {
    slug: "work-policy-contracts",
    name: "Work Policy Contracts",
    title: "Work Policy Contracts (WPC) for AI Agent Governance | Claw EA",
    description: "Define and enforce guardrails for AI agents before execution begins. Work Policy Contracts specify egress rules, data handling, approval gates, and model restrictions.",
    heroHeadline: "Work Policy Contracts: Guardrails Before the Agent Runs",
    heroSub: "Define what your AI agents can and cannot do. WPCs enforce egress controls, DLP rules, approval gates, and model restrictions. Policy violations are logged, not just blocked.",
    icon: "📋",
    whatIs: "A Work Policy Contract (WPC) is a declarative policy document that defines the operational boundaries for an AI agent before it begins execution. WPCs are enforced by clawcontrols and embedded into the agent's sandbox environment. They specify which external endpoints the agent can reach, what data handling rules apply, which models can be used, and what actions require human approval. The WPC hash is included in every proof bundle, providing cryptographic linkage between the policy that was supposed to govern execution and the actual execution record.",
    howItWorks: [
      { step: "Security officer defines policy", detail: "Using the Claw EA admin interface or API, the security officer creates a WPC specifying egress allowlists, DLP rules, model restrictions, and approval gates." },
      { step: "WPC is hashed and registered", detail: "The WPC document is canonicalized and hashed. The hash is registered with clawcontrols and associated with the agent's deployment." },
      { step: "Agent sandbox enforces policy", detail: "When the agent starts, the sandbox loads the WPC and configures egress controls, model routing, and approval workflows accordingly." },
      { step: "Policy compliance is attested", detail: "The WPC hash is included in every proof bundle. Any verifier can check that the agent ran under a specific policy by comparing the attested WPC hash against the registered policy document." },
    ],
    benefits: [
      { title: "Pre-emptive governance", text: "Define boundaries before the agent runs, not after something goes wrong. WPCs shift AI governance from reactive to proactive." },
      { title: "Cryptographic policy binding", text: "The WPC hash in proof bundles creates an unbreakable link between the policy and the execution. Auditors can verify which rules governed any specific run." },
      { title: "Graduated enforcement", text: "WPCs support alert, throttle, and stop actions. Start with monitoring-only mode and tighten controls as you learn agent behavior patterns." },
      { title: "Template-based deployment", text: "Create WPC templates for common use cases. Deploy new agents with pre-approved policies in minutes, not weeks." },
    ],
    technicalDetails: `A Work Policy Contract specifies:
- **Egress allowlist**: List of permitted external endpoints (domains, IPs, API paths)
- **DLP redaction rules**: Patterns to redact from outbound data (PII, PHI, financial data)
- **Model restrictions**: Which models can be used, token limits, cost caps
- **Approval gates**: Actions that require human approval before execution
- **Data handling rules**: Retention, encryption, and residency requirements
- **Budget limits**: Maximum spend per run, per day, per month
- **Kill switch**: Conditions that trigger immediate agent termination`,
    faqs: [
      { q: "What is a Work Policy Contract?", a: "A Work Policy Contract (WPC) is a declarative policy document that defines the operational boundaries for an AI agent. It specifies which endpoints the agent can reach, what data rules apply, which models are allowed, and what requires human approval. WPCs are enforced by the Claw EA sandbox and their hash is embedded in every proof bundle for verification." },
      { q: "How are Work Policy Contracts enforced?", a: "WPCs are loaded into the agent's sandbox at startup. The sandbox configures network egress controls, DLP pipelines, and model routing based on the WPC rules. Policy violations trigger the configured action: alert (log only), throttle (rate limit), or stop (terminate the agent). All enforcement actions are recorded in the audit log." },
      { q: "Can Work Policy Contracts be changed during execution?", a: "WPC changes require a new deployment. This is intentional. It prevents policy weakening during execution and ensures every proof bundle references an immutable policy hash. To update a WPC, deploy a new agent version with the updated policy." },
    ],
    relatedSolutions: ["execution-attestation", "secure-sandbox", "audit-compliance"],
    relatedIndustries: ["government", "healthcare", "financial-services"],
  },
  {
    slug: "fleet-management",
    name: "AI Agent Fleet Management",
    title: "AI Agent Fleet Management | Deploy, Monitor, Control | Claw EA",
    description: "Deploy and manage fleets of AI agents across your organization. Centralized monitoring, budget controls, policy enforcement, and multi-tenant isolation.",
    heroHeadline: "Manage Hundreds of AI Agents From One Dashboard",
    heroSub: "Deploy agents across teams, set budget limits, enforce policies, and monitor health. Fleet management for organizations that run AI at scale.",
    icon: "📊",
    whatIs: "AI Agent Fleet Management is Claw EA's infrastructure for deploying, monitoring, and controlling multiple AI agents across an enterprise. Each agent runs in its own isolated sandbox, but fleet management provides centralized visibility and control. Organizations can deploy agents from templates, set per-agent and per-team budgets, enforce Work Policy Contracts across the fleet, and monitor agent health in real time. The fleet is managed through the Claw EA API or admin dashboard.",
    howItWorks: [
      { step: "Create agent templates", detail: "Define agent configurations including model routing, skills, WPC policies, and resource limits. Templates enable one-click deployment of pre-configured agents." },
      { step: "Deploy agents to teams", detail: "Provision agents for specific teams or use cases. Each agent gets its own sandbox, DID identity, and isolated storage." },
      { step: "Monitor fleet health", detail: "The fleet dashboard shows agent status, uptime, error rates, and resource usage across the entire organization." },
      { step: "Enforce policies at scale", detail: "Apply WPC updates, budget changes, and model restrictions across agent groups. Policy changes propagate through the fleet on next deployment cycle." },
    ],
    benefits: [
      { title: "Scale without chaos", text: "Deploy hundreds of agents with consistent policies, budgets, and monitoring. No shadow AI, no ungoverned agents." },
      { title: "Team-level autonomy", text: "Teams can deploy agents from approved templates without platform admin involvement. Guardrails are pre-configured." },
      { title: "Budget control", text: "Set per-agent, per-team, and org-wide budget limits. Get alerts, throttling, or automatic shutoff when limits approach." },
      { title: "Auto-recovery", text: "Claw EA automatically detects and restarts failed agents (up to configurable retry limits). Failures are logged in the audit trail." },
    ],
    technicalDetails: `Fleet management operates through:
- **Tenant API**: REST endpoints for agent CRUD, template management, and fleet operations
- **TenantDO**: Durable Object per organization tracking fleet state
- **AgentSandbox**: One Cloudflare Sandbox container per agent
- **Cron health checks**: Every 5 minutes, verify agent health and sync state to R2
- **Usage metering**: Per-agent compute, token, and API call tracking
- **Budget enforcement**: Configurable limits with alert/throttle/stop actions`,
    faqs: [
      { q: "How many AI agents can Claw EA manage?", a: "Claw EA supports up to 9,999 agents per enterprise tenant. Standard infrastructure runs up to 100 concurrent containers, with higher limits available for enterprise plans. Each agent runs in its own isolated Cloudflare Sandbox." },
      { q: "Can different teams have different agent configurations?", a: "Yes. Each team can deploy agents from different templates with team-specific model configs, WPC policies, and budget limits. The fleet dashboard provides org-wide visibility while maintaining team-level autonomy." },
      { q: "What happens when an agent fails?", a: "Claw EA runs health checks every 5 minutes. Failed agents are automatically restarted up to 3 times. If an agent fails repeatedly, it is marked as errored and an alert is sent to the fleet admin. All failures are logged in the audit trail." },
    ],
    relatedSolutions: ["work-policy-contracts", "model-routing", "audit-compliance"],
    relatedIndustries: ["technology", "financial-services", "insurance"],
  },
  {
    slug: "model-routing",
    name: "Model Routing and BYOK",
    title: "AI Model Routing and Bring Your Own Key (BYOK) | Claw EA",
    description: "Route AI model calls to the right provider based on task type, cost, and performance. Bring your own API keys or use Claw EA managed keys.",
    heroHeadline: "Smart Model Routing With Your Own API Keys",
    heroSub: "Route tasks to Claude, GPT-4, or open models based on rules you define. Use your own API keys for full cost control, or let Claw EA manage provider access.",
    icon: "🔀",
    whatIs: "Model Routing in Claw EA allows organizations to configure which AI models handle which tasks, with automatic failover and cost controls. Agents can use primary and fallback models, with routing rules that direct specific task types to specific providers. BYOK (Bring Your Own Key) lets tenants use their own provider API keys, maintaining their existing billing relationships and negotiated pricing.",
    howItWorks: [
      { step: "Configure model routing", detail: "Set primary and fallback models. Define routing rules that match task patterns to specific models (e.g., code tasks to Claude, analysis to GPT-4)." },
      { step: "Provide API keys (BYOK)", detail: "Enter your own Anthropic and OpenAI API keys. Keys are encrypted at rest and injected into agent sandboxes at startup." },
      { step: "All calls route through clawproxy", detail: "Whether using BYOK or managed keys, all model calls go through clawproxy for receipt generation. Your keys are never stored in logs or receipts." },
      { step: "Monitor usage per model", detail: "Track token usage, cost, and latency per model per agent. Optimize routing rules based on real performance data." },
    ],
    benefits: [
      { title: "Cost optimization", text: "Route simple tasks to cheaper models and complex tasks to capable ones. Reduce AI spend by 40-60% with smart routing." },
      { title: "Vendor flexibility", text: "No provider lock-in. Switch models or providers at any time by updating routing rules. No code changes required." },
      { title: "Existing billing", text: "BYOK means your existing pricing agreements and billing dashboards continue to work. Claw EA adds attestation without changing your provider relationship." },
      { title: "Automatic failover", text: "When the primary model is unavailable, agents automatically fail over to the configured fallback. Failovers are logged in the proof bundle." },
    ],
    technicalDetails: `Model routing configuration:
\`\`\`json
{
  "primary_model": "anthropic/claude-sonnet-4-5",
  "fallback_model": "openai/gpt-4o",
  "routing_rules": [
    { "task_pattern": "code_review|refactor", "model": "anthropic/claude-sonnet-4-5" },
    { "task_pattern": "summarize|translate", "model": "openai/gpt-4o-mini" },
    { "task_pattern": "data_analysis", "model": "anthropic/claude-sonnet-4-5" }
  ]
}
\`\`\``,
    faqs: [
      { q: "What is Bring Your Own Key (BYOK)?", a: "BYOK lets you use your own AI provider API keys (Anthropic, OpenAI, etc.) with Claw EA. Your keys are encrypted at rest and injected into agent sandboxes at startup. This means you keep your existing billing relationships and negotiated pricing. Claw EA adds the attestation and governance layer on top." },
      { q: "How does model routing work?", a: "You define routing rules that match task patterns to specific models. When an agent performs a task, the routing engine matches the task against your rules and directs the model call to the appropriate provider. All calls still go through clawproxy for receipt generation." },
      { q: "Are my API keys safe with Claw EA?", a: "API keys are encrypted at rest using Cloudflare secrets management. Keys are injected into isolated sandbox environments at startup and never appear in logs, receipts, or proof bundles. Each sandbox has its own encrypted key store." },
    ],
    relatedSolutions: ["proof-of-harness", "fleet-management", "execution-attestation"],
    relatedIndustries: ["technology", "financial-services", "insurance"],
  },
  {
    slug: "secure-sandbox",
    name: "Secure Sandbox Infrastructure",
    title: "Secure AI Agent Sandbox Infrastructure | Isolated Execution | Claw EA",
    description: "Every AI agent runs in its own isolated Cloudflare Sandbox container. No shared memory, strict egress controls, and cryptographic identity per agent.",
    heroHeadline: "Every Agent Gets Its Own Secure Sandbox",
    heroSub: "Cloudflare Sandbox containers provide hardware-level isolation. No shared memory. No cross-agent access. Strict network egress controls. Each agent is its own security boundary.",
    icon: "🏗️",
    whatIs: "Claw EA's Secure Sandbox Infrastructure provisions each AI agent in its own Cloudflare Sandbox container. This is not a shared VM or a Docker container on a shared host. Each sandbox is a hardware-isolated execution environment with its own filesystem, network stack, and memory space. Agents cannot access other agents' data, and network egress is mediated by Work Policy Contract rules. This architecture eliminates the most common vectors for data leakage in multi-tenant AI deployments.",
    howItWorks: [
      { step: "Agent is provisioned", detail: "Claw EA creates a new AgentSandbox Durable Object backed by a Cloudflare Sandbox container. The enterprise image with the trust layer is loaded." },
      { step: "Identity is assigned", detail: "The agent receives a unique DID (Decentralized Identifier) using Ed25519 key generation. This identity is used for all signing operations." },
      { step: "Storage is mounted", detail: "Per-agent R2 storage is mounted with a tenant/agent-scoped prefix. Agents can only see their own storage subtree." },
      { step: "Egress controls are configured", detail: "The Work Policy Contract defines which external endpoints the agent can reach. All other network access is blocked." },
      { step: "Agent sleeps when idle", detail: "After configurable idle time (default 30 minutes), the sandbox sleeps to reduce costs. It wakes on the next request." },
    ],
    benefits: [
      { title: "Hardware-level isolation", text: "Cloudflare Sandbox provides stronger isolation than containers. Each agent gets its own execution environment with no shared kernel state." },
      { title: "Zero cross-tenant leakage", text: "Agents from different tenants cannot access each other's data, network, or storage. Isolation is enforced at the infrastructure level." },
      { title: "Configurable sleep/wake", text: "Agents sleep after configurable idle periods and wake on demand. Pay only for active compute time." },
      { title: "Persistent state via R2", text: "Agent state persists across sleep/wake cycles through R2 storage. No data loss when agents idle." },
    ],
    technicalDetails: `Sandbox architecture per agent:
- **Container**: Cloudflare Sandbox (standard-1 instance type)
- **Image**: Enterprise MoltWorker with pre-wired trust layer
- **Identity**: Ed25519 DID key pair (generated at provisioning)
- **Storage**: R2 bucket mount at /data/clawea (agent-scoped prefix)
- **Network**: Egress mediated by WPC rules, all model calls through clawproxy
- **Lifecycle**: Provision → Deploy → Running → Sleep → Wake → Destroy
- **Health**: 5-minute cron checks with auto-restart (max 3 retries)`,
    faqs: [
      { q: "What is a Cloudflare Sandbox?", a: "Cloudflare Sandbox is a container runtime that provides hardware-level isolation for each instance. Unlike traditional containers that share a host kernel, Sandbox instances have their own isolated execution environment. This makes them suitable for multi-tenant workloads where data isolation is critical." },
      { q: "How does Claw EA prevent data leakage between agents?", a: "Three layers of isolation: (1) Each agent runs in its own Cloudflare Sandbox with no shared memory or filesystem, (2) R2 storage is mounted with agent-scoped prefixes so agents can only see their own data, (3) Network egress is controlled by Work Policy Contracts. Cross-agent communication is impossible at the infrastructure level." },
      { q: "What happens to agent state when it sleeps?", a: "Agent state is persisted to R2 storage through periodic sync operations. When the agent sleeps (after configurable idle time), its container is suspended. When it wakes, the container restarts and state is restored from R2. No data is lost during sleep/wake cycles." },
    ],
    relatedSolutions: ["work-policy-contracts", "execution-attestation", "fleet-management"],
    relatedIndustries: ["government", "healthcare", "financial-services"],
  },
  {
    slug: "audit-compliance",
    name: "Audit and Compliance",
    title: "AI Agent Audit and Compliance Infrastructure | Claw EA",
    description: "Built-in compliance infrastructure for AI agent operations. Tamper-evident audit logs, proof bundle exports, and automated compliance reporting.",
    heroHeadline: "Compliance Infrastructure That Auditors Actually Like",
    heroSub: "Stop scrambling before audits. Claw EA produces audit-ready records by default. Tamper-evident logs, exportable proof bundles, and compliance dashboards.",
    icon: "📑",
    whatIs: "Claw EA's audit and compliance infrastructure produces regulatory-grade records of every AI agent action by default. There is no separate compliance product to buy or integrate. Every agent deployment, model call, tool invocation, and configuration change is recorded in append-only audit logs with Merkle-rooted integrity. Proof bundles can be exported for external auditors. The system maps to SOC 2, HIPAA, GDPR, and sector-specific compliance frameworks.",
    howItWorks: [
      { step: "Actions are automatically logged", detail: "Every agent action generates an audit log entry with actor DID, action type, resource, details, and timestamp. No manual instrumentation required." },
      { step: "Logs are append-only", detail: "Audit logs are stored in D1 with an append-only schema. Entries cannot be modified or deleted. Merkle roots provide integrity verification." },
      { step: "Proof bundles are generated", detail: "At task completion, proof bundles compile all gateway receipts, tool events, and artifact hashes into a signed Universal Run Manifest." },
      { step: "Export for auditors", detail: "Export audit logs and proof bundles in standard formats. Send to your SIEM, GRC platform, or directly to external auditors." },
    ],
    benefits: [
      { title: "Audit-ready by default", text: "No special configuration needed. Every agent produces compliance-grade records from its first run." },
      { title: "Continuous compliance", text: "Compliance is not a point-in-time exercise. Claw EA produces evidence continuously, so you are always audit-ready." },
      { title: "Framework mapping", text: "Claw EA documentation maps audit trail capabilities to specific controls in SOC 2, HIPAA, GDPR, ISO 27001, and NIST frameworks." },
      { title: "Tamper evidence", text: "Merkle-rooted logs and signed proof bundles mean any modification to any record is detectable. This satisfies even the most stringent integrity requirements." },
    ],
    technicalDetails: `Audit infrastructure components:
- **Audit log table**: Append-only D1 table with actor_did, action, resource, details, timestamp
- **Proof bundles**: Universal Run Manifests signed by agent DIDs
- **Gateway receipts**: Signed by clawproxy for every model call
- **Integrity**: Merkle root hash chain across all events per run
- **Export formats**: JSON, CSV, SIEM-compatible (CEF, LEEF)
- **Retention**: Configurable per tenant (default: 7 years for regulated industries)`,
    faqs: [
      { q: "How does Claw EA support SOC 2 audits?", a: "Claw EA maps to SOC 2 Trust Services Criteria across all five categories. Agent audit logs satisfy CC6 (Logical and Physical Access Controls), CC7 (System Operations), and CC8 (Change Management). Proof bundles provide the evidence for CC9 (Risk Mitigation). Documentation is available for auditor review." },
      { q: "Can audit logs be exported to our SIEM?", a: "Yes. Audit logs can be exported in JSON, CSV, and SIEM-compatible formats (CEF, LEEF). Integration with Splunk, Datadog, and Elastic is supported. Real-time log streaming is available on enterprise plans." },
      { q: "How long are audit records retained?", a: "Retention is configurable per tenant. Default retention is 90 days for standard plans and 7 years for enterprise plans (suitable for financial services and healthcare regulatory requirements). Custom retention periods are available." },
    ],
    relatedSolutions: ["execution-attestation", "work-policy-contracts", "proof-of-harness"],
    relatedIndustries: ["financial-services", "healthcare", "government"],
  },
  {
    slug: "multi-agent-orchestration",
    name: "Multi-Agent Orchestration",
    title: "Multi-Agent Orchestration | Coordinated AI Agent Workflows | Claw EA",
    description: "Coordinate multiple AI agents working on complex workflows. Mission-level tracking, inter-agent handoff, and aggregated proof bundles.",
    heroHeadline: "Orchestrate Multi-Agent Workflows With Full Accountability",
    heroSub: "Complex tasks need multiple agents. Claw EA coordinates agent fleets with mission-level tracking, secure handoff, and unified proof bundles across all participants.",
    icon: "🔗",
    whatIs: "Multi-Agent Orchestration in Claw EA enables coordinated workflows where multiple AI agents collaborate on complex tasks. Each agent maintains its own sandbox and identity, but missions group their work under a shared mission_id. This enables aggregated proof bundles, cross-agent dependency tracking, and unified billing. Orchestration supports sequential handoff, parallel execution, and approval gates between agents.",
    howItWorks: [
      { step: "Define the mission", detail: "Create a mission with a mission_id that groups related agent work. Specify the agents, their roles, and the handoff logic." },
      { step: "Agents execute in parallel or sequence", detail: "Each agent works in its own sandbox. Agents can produce outputs that become inputs for downstream agents." },
      { step: "Handoff with artifact hashes", detail: "When one agent passes work to another, the artifact hash is recorded in both proof bundles. This creates a verifiable chain of custody across agents." },
      { step: "Mission proof bundle", detail: "At mission completion, individual proof bundles are aggregated into a mission-level manifest that shows the complete workflow across all participating agents." },
    ],
    benefits: [
      { title: "Complex workflow support", text: "Break complex tasks into specialized subtasks. Code review + security scan + documentation can run as separate agents with clear handoff." },
      { title: "Cross-agent accountability", text: "Mission-level tracking shows which agent did what. If something goes wrong, trace it to the specific agent, model call, and input." },
      { title: "Unified billing", text: "All compute, tokens, and API calls are aggregated at the mission level. One invoice, clear cost attribution." },
      { title: "Scalable execution", text: "Run multiple agents in parallel for faster completion. Each maintains its own sandbox isolation." },
    ],
    technicalDetails: `Multi-agent orchestration uses:
- **mission_id**: Shared identifier across all agents in a workflow
- **Agent roles**: Named roles (e.g., "code_reviewer", "security_scanner")
- **Handoff events**: Artifact hashes linking output of one agent to input of another
- **Mission manifest**: Aggregated proof bundle with cross-references between agent URMs
- **Billing aggregation**: Usage events tagged with mission_id for unified invoicing`,
    faqs: [
      { q: "Can multiple AI agents work together on one task?", a: "Yes. Claw EA supports multi-agent orchestration where multiple agents collaborate on complex workflows. Each agent maintains its own isolated sandbox, but missions group their work for unified tracking, billing, and proof generation." },
      { q: "How does Claw EA track accountability across multiple agents?", a: "Every agent in a mission produces its own proof bundle, and each bundle includes the shared mission_id. Handoff events create cryptographic links between agent outputs. The mission-level manifest aggregates all individual bundles for complete workflow accountability." },
    ],
    relatedSolutions: ["fleet-management", "execution-attestation", "secure-sandbox"],
    relatedIndustries: ["technology", "legal", "insurance"],
  },
];

export function getSolution(slug: string): Solution | undefined {
  return SOLUTIONS.find((s) => s.slug === slug);
}
