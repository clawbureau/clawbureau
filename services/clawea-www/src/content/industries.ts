/**
 * Industry vertical content for programmatic SEO pages.
 * Each industry generates a page at /enterprise/{slug}.
 */

export interface Industry {
  slug: string;
  name: string;
  title: string;
  description: string;
  heroHeadline: string;
  heroSub: string;
  icon: string;
  challenges: { title: string; text: string }[];
  solutions: { title: string; text: string }[];
  useCases: string[];
  complianceFrameworks: string[];
  stats: { num: string; label: string }[];
  faqs: { q: string; a: string }[];
  relatedIndustries: string[];
}

export const INDUSTRIES: Industry[] = [
  {
    slug: "financial-services",
    name: "Financial Services",
    title: "Enterprise AI Agents for Financial Services | Claw EA",
    description: "Deploy verified AI agents for banking, trading, and compliance workflows. Cryptographic proof of every action, audit-ready execution trails, and SOC 2 compatible infrastructure.",
    heroHeadline: "AI Agents for Financial Services That Auditors Trust",
    heroSub: "Every trade analysis, compliance check, and risk calculation your AI agent performs is cryptographically attested. Full audit trails. Zero blind spots.",
    icon: "🏦",
    challenges: [
      { title: "Regulatory scrutiny", text: "Financial regulators require complete audit trails for automated decision-making. Traditional AI tooling leaves gaps that slow audits and create risk." },
      { title: "Data residency", text: "Sensitive financial data cannot leave controlled environments. AI agents need sandboxed execution with strict egress controls." },
      { title: "Model risk management", text: "SR 11-7 and similar frameworks demand documented model governance. Every model call needs attribution, versioning, and decision rationale." },
    ],
    solutions: [
      { title: "Proof-of-Harness receipts", text: "Every LLM call is routed through clawproxy, producing signed gateway receipts. Auditors can verify which model was called, when, and what it returned." },
      { title: "Work Policy Contracts", text: "Define guardrails before execution begins. WPCs enforce egress allowlists, DLP redaction, and approval gates. Violations are logged, not just blocked." },
      { title: "Tamper-evident audit logs", text: "All agent actions are recorded in append-only audit logs with Merkle-rooted integrity. Export to your SIEM or GRC platform in minutes." },
    ],
    useCases: [
      "Automated KYC document processing",
      "Real-time transaction monitoring agents",
      "Regulatory filing preparation",
      "Portfolio risk analysis automation",
      "Client onboarding workflow agents",
      "Anti-money laundering screening",
    ],
    complianceFrameworks: ["SOC 2 Type II", "SOX Section 404", "GDPR Article 22", "SR 11-7 (Model Risk)", "DORA (EU)", "MAS TRM (Singapore)"],
    stats: [
      { num: "100%", label: "Action attestation" },
      { num: "<200ms", label: "Receipt overhead" },
      { num: "SOC 2", label: "Compatible infra" },
      { num: "24/7", label: "Agent uptime" },
    ],
    faqs: [
      { q: "How does Claw EA help with financial services compliance?", a: "Claw EA produces cryptographic proof of every AI agent action. Each model call generates a signed gateway receipt via clawproxy, creating a tamper-evident chain that maps directly to regulatory audit requirements under SOC 2, SOX, and DORA frameworks." },
      { q: "Can AI agents access sensitive financial data securely?", a: "Yes. Each agent runs in an isolated Cloudflare Sandbox container with configurable egress controls. Work Policy Contracts define exactly which endpoints, data sources, and APIs the agent can reach. Unauthorized access attempts are logged and blocked." },
      { q: "What audit trail does Claw EA produce for regulators?", a: "Every agent session generates a Universal Run Manifest containing all model calls, tool invocations, input/output hashes, and gateway receipts. These are stored in append-only audit logs with Merkle roots for integrity verification." },
      { q: "Is Claw EA suitable for algorithmic trading compliance?", a: "Claw EA provides the execution attestation layer needed for automated trading workflows. Every decision point is logged with model attribution, timing, and signed receipts. This satisfies MiFID II and SEC requirements for algorithmic trading record-keeping." },
    ],
    relatedIndustries: ["insurance", "legal", "government"],
  },
  {
    slug: "healthcare",
    name: "Healthcare",
    title: "Enterprise AI Agents for Healthcare | HIPAA-Ready | Claw EA",
    description: "HIPAA-compatible AI agent infrastructure for healthcare organizations. Sandboxed execution, DLP redaction pipelines, and verifiable proof bundles for clinical and administrative workflows.",
    heroHeadline: "AI Agents for Healthcare, Built for HIPAA",
    heroSub: "Deploy AI agents that process clinical data without exposing PHI. Automated redaction, isolated execution, and cryptographic proof that privacy controls held.",
    icon: "🏥",
    challenges: [
      { title: "HIPAA compliance", text: "Protected Health Information (PHI) requires strict access controls and audit trails. AI agents must demonstrate they never exposed PHI outside authorized boundaries." },
      { title: "Clinical accuracy", text: "Healthcare AI needs traceable reasoning chains. When an agent recommends a course of action, clinicians need to verify exactly what data and models informed that recommendation." },
      { title: "Interoperability", text: "Healthcare data lives in EHRs, FHIR APIs, and legacy systems. Agents need controlled access to multiple data sources without cross-contamination." },
    ],
    solutions: [
      { title: "PHI redaction pipeline", text: "Built-in DLP redaction strips PHI before data leaves the sandbox. Redaction actions are logged as part of the proof bundle, providing auditable evidence of privacy enforcement." },
      { title: "Isolated sandbox execution", text: "Each agent runs in its own Cloudflare Sandbox with no shared memory, no persistent network state, and strict egress policies. PHI stays inside the container." },
      { title: "Verifiable decision chains", text: "Every model call, tool invocation, and data access is hashed and chained. Clinicians and auditors can trace exactly how an agent reached its output." },
    ],
    useCases: [
      "Clinical documentation summarization",
      "Prior authorization automation",
      "Medical coding and billing agents",
      "Patient intake form processing",
      "Lab result analysis and flagging",
      "Clinical trial eligibility screening",
    ],
    complianceFrameworks: ["HIPAA", "HITECH Act", "21 CFR Part 11", "SOC 2 Type II", "HITRUST CSF", "GDPR (international patients)"],
    stats: [
      { num: "Zero", label: "PHI exposure risk" },
      { num: "100%", label: "Redaction audit trail" },
      { num: "HIPAA", label: "Compatible design" },
      { num: "Sub-sec", label: "Receipt latency" },
    ],
    faqs: [
      { q: "Is Claw EA HIPAA compliant for healthcare AI agents?", a: "Claw EA is designed for HIPAA-compatible deployments. Each agent runs in an isolated sandbox with PHI redaction pipelines, strict egress controls, and complete audit logging. Organizations sign a Business Associate Agreement (BAA) as part of enterprise onboarding." },
      { q: "How does Claw EA prevent PHI exposure in AI workflows?", a: "Three layers of protection: (1) Work Policy Contracts define which data the agent can access, (2) DLP redaction pipelines strip PHI before any data leaves the sandbox, (3) egress mediation through clawproxy ensures only authorized endpoints receive data. All protection actions are logged in the proof bundle." },
      { q: "Can healthcare AI agents integrate with EHR systems?", a: "Yes. Agents can connect to FHIR APIs and EHR systems through controlled egress endpoints defined in Work Policy Contracts. Each data access is logged with the source system, timestamp, and data hash for audit purposes." },
    ],
    relatedIndustries: ["insurance", "government", "pharmaceutical"],
  },
  {
    slug: "legal",
    name: "Legal",
    title: "Enterprise AI Agents for Law Firms and Legal Departments | Claw EA",
    description: "Deploy AI agents for contract analysis, legal research, and due diligence with privilege-safe execution and verifiable proof of work for every document processed.",
    heroHeadline: "AI Agents for Legal Work, With Proof of Every Action",
    heroSub: "Contract review, legal research, and due diligence agents that produce verifiable work product. Privilege-safe execution. Full chain of custody for every document.",
    icon: "⚖️",
    challenges: [
      { title: "Attorney-client privilege", text: "Legal AI agents handle privileged communications. Any data leak could waive privilege. Execution environments must guarantee no unauthorized data egress." },
      { title: "Chain of custody", text: "Legal work product requires provable chain of custody. When an AI agent processes a document, there must be verifiable evidence of what was accessed and when." },
      { title: "Billing accuracy", text: "Law firms bill by the hour. AI agent work needs precise attribution, tracking which matters used which compute, and producing defensible billing records." },
    ],
    solutions: [
      { title: "Privilege-safe sandboxes", text: "Each matter gets its own isolated agent with zero cross-matter data access. Egress controls prevent privileged data from leaving the sandbox boundary." },
      { title: "Document chain of custody", text: "Every document access, transformation, and output is hashed and timestamped in the proof bundle. Artifact hashes stored in clawsilo provide tamper-evident custody records." },
      { title: "Per-matter billing", text: "Usage events track compute, model calls, and API access per agent per matter. Export billing data with signed attestation of accuracy." },
    ],
    useCases: [
      "Contract review and clause extraction",
      "Legal research and case law analysis",
      "Due diligence document processing",
      "Regulatory compliance monitoring",
      "E-discovery document classification",
      "Patent landscape analysis",
    ],
    complianceFrameworks: ["ABA Model Rules (Ethics)", "GDPR", "SOC 2 Type II", "ISO 27001", "State Bar Ethics Opinions"],
    stats: [
      { num: "100%", label: "Document custody" },
      { num: "Zero", label: "Cross-matter leaks" },
      { num: "Signed", label: "Billing records" },
      { num: "50-80%", label: "Faster review" },
    ],
    faqs: [
      { q: "Can AI agents maintain attorney-client privilege?", a: "Claw EA runs each agent in a fully isolated Cloudflare Sandbox. Work Policy Contracts enforce zero egress outside authorized endpoints. No data from one matter can reach another matter's agent. This isolation model supports privilege preservation." },
      { q: "How does Claw EA prove chain of custody for legal documents?", a: "Every document the agent processes is hashed (SHA-256) on ingestion. All transformations, annotations, and outputs are chained with cryptographic receipts. The resulting proof bundle provides a tamper-evident chain of custody that holds up to scrutiny." },
      { q: "Can law firms use Claw EA for client-facing billing?", a: "Yes. Usage events are tracked per agent per matter, including compute time, model calls, and API requests. Billing exports include signed attestation, making them defensible for client billing disputes." },
    ],
    relatedIndustries: ["financial-services", "government", "insurance"],
  },
  {
    slug: "government",
    name: "Government",
    title: "Enterprise AI Agents for Government Agencies | Claw EA",
    description: "FedRAMP-ready AI agent infrastructure for government workflows. Air-gapped execution, sovereign data controls, and verifiable proof bundles for public sector accountability.",
    heroHeadline: "AI Agents for Government, Built for Accountability",
    heroSub: "Deploy AI agents that meet public sector security standards. Every action verifiable, every decision traceable, every output provable to oversight bodies.",
    icon: "🏛️",
    challenges: [
      { title: "Security clearance requirements", text: "Government data has classification levels. AI agents must operate within defined security boundaries with no possibility of data spillage across classifications." },
      { title: "Public accountability", text: "Government AI decisions may be subject to FOIA requests and congressional oversight. Agencies need complete, verifiable records of what AI did and why." },
      { title: "Procurement complexity", text: "Government procurement requires FedRAMP authorization, ATO processes, and documented security controls. AI infrastructure must fit existing compliance frameworks." },
    ],
    solutions: [
      { title: "Sovereign sandbox execution", text: "Each agent runs in an isolated container with configurable data residency. No data leaves the execution boundary unless explicitly authorized by policy." },
      { title: "FOIA-ready audit trails", text: "Proof bundles contain complete, timestamped records of every agent action. Export to agency records management systems with cryptographic integrity verification." },
      { title: "Work Policy Contract governance", text: "Agency security officers define WPCs that enforce classification boundaries, data handling rules, and approval workflows. Policy violations trigger immediate alerts." },
    ],
    useCases: [
      "Constituent correspondence processing",
      "Grant application review and scoring",
      "Regulatory comment analysis",
      "FOIA request processing",
      "Policy document drafting assistants",
      "Intelligence analysis support",
    ],
    complianceFrameworks: ["FedRAMP", "FISMA", "NIST 800-53", "NIST AI RMF", "Executive Order 14110", "CMMC"],
    stats: [
      { num: "NIST", label: "Aligned controls" },
      { num: "100%", label: "Action traceability" },
      { num: "Zero", label: "Data spillage" },
      { num: "Signed", label: "Proof bundles" },
    ],
    faqs: [
      { q: "Is Claw EA FedRAMP authorized?", a: "Claw EA runs on Cloudflare infrastructure, which holds FedRAMP Moderate authorization. The platform is architected to support agency ATO processes with documented security controls mapping to NIST 800-53." },
      { q: "How does Claw EA support FOIA compliance?", a: "Every agent action generates timestamped, signed proof bundles stored in tamper-evident audit logs. These records can be exported in standard formats for FOIA responses, providing complete transparency into AI-assisted government workflows." },
      { q: "Can Claw EA agents handle classified information?", a: "Claw EA supports configurable security boundaries through Work Policy Contracts. For classified workloads, agencies deploy agents with strict egress controls and data residency requirements. The sandbox model prevents cross-boundary data movement." },
    ],
    relatedIndustries: ["legal", "healthcare", "financial-services"],
  },
  {
    slug: "insurance",
    name: "Insurance",
    title: "Enterprise AI Agents for Insurance Companies | Claw EA",
    description: "Deploy AI agents for claims processing, underwriting, and policy management with full attestation trails and compliance-ready audit infrastructure.",
    heroHeadline: "AI Agents for Insurance, Verified End to End",
    heroSub: "Claims processing, underwriting, and fraud detection agents that produce verifiable proof of every decision. Regulator-ready from day one.",
    icon: "🛡️",
    challenges: [
      { title: "Claims accuracy", text: "Insurance regulators require documented rationale for claims decisions. AI-assisted decisions need traceable reasoning chains to avoid unfair denial disputes." },
      { title: "Fraud detection accountability", text: "When AI flags potential fraud, the evidence chain must be verifiable. False positives damage customer relationships; false negatives increase losses." },
      { title: "Rate filing documentation", text: "State regulators review rate filings in detail. Any AI-assisted actuarial analysis needs documented methodology and reproducible results." },
    ],
    solutions: [
      { title: "Decision attestation", text: "Every claims decision, underwriting assessment, and fraud flag includes a signed proof bundle documenting the exact model calls, data inputs, and reasoning chain." },
      { title: "Reproducible analysis", text: "Artifact hashes pin exact inputs and outputs. Re-run any analysis with the same model version and data to reproduce results for regulatory review." },
      { title: "Multi-agent orchestration", text: "Run specialized agents for claims intake, assessment, and approval in a coordinated fleet. Each agent's work is independently attested and auditable." },
    ],
    useCases: [
      "Claims intake and triage automation",
      "Underwriting risk assessment",
      "Fraud detection and investigation",
      "Policy document generation",
      "Reinsurance analysis",
      "Customer service agents with policy knowledge",
    ],
    complianceFrameworks: ["NAIC Model Laws", "State DOI Requirements", "SOC 2 Type II", "GDPR", "IFRS 17", "Solvency II"],
    stats: [
      { num: "3x", label: "Faster claims" },
      { num: "100%", label: "Decision trails" },
      { num: "Signed", label: "Proof bundles" },
      { num: "Multi", label: "Agent fleets" },
    ],
    faqs: [
      { q: "How does Claw EA help with insurance claims compliance?", a: "Every AI-assisted claims decision produces a signed proof bundle containing the full reasoning chain: model calls, data inputs, intermediate steps, and final output. This documentation satisfies state DOI requirements for automated decision-making rationale." },
      { q: "Can Claw EA agents handle underwriting workflows?", a: "Yes. Deploy specialized underwriting agents with access to risk models, actuarial data, and policy databases. Each assessment generates attested output with reproducible analysis trails for rate filing support." },
    ],
    relatedIndustries: ["financial-services", "healthcare", "legal"],
  },
  {
    slug: "manufacturing",
    name: "Manufacturing",
    title: "Enterprise AI Agents for Manufacturing | Claw EA",
    description: "Deploy verified AI agents for supply chain, quality control, and production optimization. Attested execution for ISO-certified environments.",
    heroHeadline: "AI Agents for Manufacturing, ISO-Certified Ready",
    heroSub: "Quality control, supply chain, and production optimization agents with verifiable execution trails. Built for regulated manufacturing environments.",
    icon: "🏭",
    challenges: [
      { title: "Quality documentation", text: "ISO 9001 and similar standards require documented processes. AI-assisted quality decisions need traceable records for certification audits." },
      { title: "Supply chain visibility", text: "Global supply chains generate massive data volumes. AI agents need controlled access to supplier systems with clear audit trails." },
      { title: "Safety-critical decisions", text: "Manufacturing AI must never make unchecked decisions that affect product safety. Human-in-the-loop controls are non-negotiable." },
    ],
    solutions: [
      { title: "ISO-compatible audit trails", text: "Agent proof bundles map directly to ISO 9001 documentation requirements. Every quality decision includes model attribution, data provenance, and timestamp verification." },
      { title: "Controlled supplier integration", text: "Work Policy Contracts define which supplier APIs and data sources each agent can access. Cross-supplier data isolation prevents competitive information leakage." },
      { title: "Approval gate enforcement", text: "Safety-critical outputs require human approval. WPCs enforce mandatory review gates with signed approver attestation before any safety-affecting action." },
    ],
    useCases: [
      "Predictive maintenance scheduling",
      "Quality inspection automation",
      "Supply chain disruption analysis",
      "Production planning optimization",
      "Supplier evaluation agents",
      "Safety incident analysis",
    ],
    complianceFrameworks: ["ISO 9001", "ISO 27001", "IATF 16949 (Automotive)", "AS9100 (Aerospace)", "IEC 62443 (Industrial)"],
    stats: [
      { num: "ISO", label: "Compatible trails" },
      { num: "100%", label: "Action provenance" },
      { num: "Gated", label: "Safety controls" },
      { num: "Multi", label: "Supplier isolation" },
    ],
    faqs: [
      { q: "Does Claw EA support ISO 9001 compliance?", a: "Claw EA produces audit trails that map to ISO 9001 documentation requirements. Every agent action generates timestamped, signed records that satisfy clause 7.5 (Documented Information) and clause 8.5 (Production and Service Provision) requirements." },
      { q: "Can AI agents safely make manufacturing decisions?", a: "Claw EA enforces mandatory approval gates for safety-critical actions via Work Policy Contracts. Agents can analyze and recommend, but safety-affecting outputs require human sign-off with signed attestation before execution." },
    ],
    relatedIndustries: ["technology", "government", "insurance"],
  },
  {
    slug: "technology",
    name: "Technology",
    title: "Enterprise AI Agents for Tech Companies | Claw EA",
    description: "Deploy fleets of AI coding agents, DevOps automation, and research assistants with verified execution. Ship faster with agents you can audit.",
    heroHeadline: "AI Agent Fleets for Engineering Teams",
    heroSub: "Code review, DevOps, security scanning, and research agents running in verified sandboxes. Scale your engineering capacity without sacrificing auditability.",
    icon: "💻",
    challenges: [
      { title: "IP protection", text: "Proprietary code and trade secrets flow through AI agents. Execution environments must guarantee no data leakage to model providers or third parties." },
      { title: "Supply chain security", text: "AI-generated code introduces supply chain risk. Organizations need proof of what model generated what code, and what training data influenced it." },
      { title: "Scale without chaos", text: "Engineering teams want dozens of AI agents. Without fleet management and policy controls, this becomes an ungovernable shadow IT problem." },
    ],
    solutions: [
      { title: "IP-safe sandboxes", text: "Each agent runs in an isolated container. Code and data never leave the sandbox boundary. Egress mediation ensures model calls go only through authorized gateways." },
      { title: "Code provenance", text: "Every AI-generated artifact gets a signed proof bundle. Track which model version produced which code change, with full input/output hashes for reproducibility." },
      { title: "Fleet management", text: "The Claw EA tenant dashboard provides fleet-wide visibility. Deploy, monitor, budget, and control agents across teams from a single pane of glass." },
    ],
    useCases: [
      "Automated code review agents",
      "CI/CD pipeline automation",
      "Security vulnerability scanning",
      "Documentation generation",
      "Incident response automation",
      "Research and prototyping agents",
    ],
    complianceFrameworks: ["SOC 2 Type II", "ISO 27001", "SLSA (Supply-chain)", "SSDF (NIST)", "CIS Controls"],
    stats: [
      { num: "25+", label: "Agents per team" },
      { num: "Signed", label: "Code provenance" },
      { num: "Fleet", label: "Management" },
      { num: "BYOK", label: "Model keys" },
    ],
    faqs: [
      { q: "How does Claw EA protect proprietary code?", a: "Each AI agent runs in a fully isolated Cloudflare Sandbox container. Code and data stay inside the sandbox boundary. Egress controls route model calls through clawproxy with no raw code exposure to third parties. All access patterns are logged." },
      { q: "Can we run multiple AI agents across engineering teams?", a: "Yes. Claw EA is designed for fleet management. Deploy up to thousands of agents across teams, each with independent sandboxes, model configs, and budget limits. The fleet dashboard provides centralized monitoring and policy enforcement." },
    ],
    relatedIndustries: ["financial-services", "manufacturing", "government"],
  },
  {
    slug: "pharmaceutical",
    name: "Pharmaceutical",
    title: "Enterprise AI Agents for Pharma and Life Sciences | Claw EA",
    description: "Deploy validated AI agents for drug discovery, clinical trials, and regulatory submissions. 21 CFR Part 11 compatible execution with full audit trails.",
    heroHeadline: "AI Agents for Pharma, Validated and Verifiable",
    heroSub: "Drug discovery, clinical trial analysis, and regulatory submission agents that meet GxP requirements. Every computation attested for FDA submission readiness.",
    icon: "💊",
    challenges: [
      { title: "GxP validation", text: "Pharmaceutical AI systems must be validated under 21 CFR Part 11 and Annex 11. This requires documented testing, change control, and audit trails for every system modification." },
      { title: "Data integrity (ALCOA+)", text: "Regulatory submissions demand data that is Attributable, Legible, Contemporaneous, Original, and Accurate. AI-generated analysis must meet these standards." },
      { title: "Reproducibility", text: "FDA reviewers may request reproduction of any AI-assisted analysis. Exact model versions, input data, and parameters must be preserved and re-executable." },
    ],
    solutions: [
      { title: "Validation-ready infrastructure", text: "Claw EA produces IQ/OQ/PQ-compatible documentation. Every agent deployment, configuration change, and model update is logged with change control metadata." },
      { title: "ALCOA+ compliant records", text: "Proof bundles satisfy ALCOA+ requirements. Every data point is attributable (signed by agent DID), contemporaneous (timestamped), original (hashed), and accurate (verified by gateway receipt)." },
      { title: "Pinned model reproducibility", text: "Agent configurations pin exact model versions. Artifact hashes and input data preservation enable exact reproduction of any analysis months or years later." },
    ],
    useCases: [
      "Drug-target interaction analysis",
      "Clinical trial data monitoring",
      "Regulatory submission document preparation",
      "Adverse event signal detection",
      "Medical literature review automation",
      "Manufacturing batch record analysis",
    ],
    complianceFrameworks: ["21 CFR Part 11", "EU Annex 11", "ICH E6(R2) GCP", "GAMP 5", "EU AI Act", "FDA AI/ML Framework"],
    stats: [
      { num: "GxP", label: "Validation ready" },
      { num: "ALCOA+", label: "Data integrity" },
      { num: "Pinned", label: "Model versions" },
      { num: "100%", label: "Reproducibility" },
    ],
    faqs: [
      { q: "Is Claw EA suitable for GxP-validated environments?", a: "Claw EA is designed to support GxP validation under 21 CFR Part 11 and EU Annex 11. The platform produces IQ/OQ/PQ-compatible documentation, maintains change control logs, and generates audit trails that satisfy GAMP 5 requirements for computerized systems." },
      { q: "Can pharmaceutical companies reproduce AI analysis for FDA review?", a: "Yes. Claw EA pins exact model versions in agent configurations and preserves input data hashes. Combined with proof bundles that record every computation step, organizations can reproduce any analysis with identical results for regulatory review." },
    ],
    relatedIndustries: ["healthcare", "manufacturing", "government"],
  },
];

export function getIndustry(slug: string): Industry | undefined {
  return INDUSTRIES.find((i) => i.slug === slug);
}
