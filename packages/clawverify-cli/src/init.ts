/**
 * `clawsig init` — Scaffold .clawsig/ directory in any repo
 *
 * Creates:
 * - .clawsig/policy.json  — minimal Work Policy Contract
 * - .clawsig/README.md    — explains the files
 *
 * Runnable via: npx @clawbureau/clawverify-cli init
 */

import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const CLAWSIG_DIR = '.clawsig';

const DEFAULT_POLICY = {
  policy_version: '1',
  policy_id: 'default-policy',
  issuer_did: 'did:web:your-org.example.com',
  allowed_providers: ['openai', 'anthropic', 'google'],
  allowed_agents: ['did:key:*'],
  minimum_proof_tier: 'self',
  required_receipt_types: ['gateway'],
  egress_allowlist: [],
};

const README_CONTENT = `# .clawsig — Clawsig Protocol Configuration

This directory contains configuration for the [Claw Verified](https://clawprotocol.org/github-app) GitHub App and the Clawsig Protocol.

## Files

### policy.json

The **Work Policy Contract (WPC)** defines enforceable constraints for AI agents working on this repo.

| Field | Description |
|-------|-------------|
| \`policy_version\` | Always \`"1"\` for this schema version |
| \`policy_id\` | Human-readable identifier for this policy |
| \`issuer_did\` | DID of the organization/owner issuing the policy |
| \`allowed_providers\` | LLM providers agents may use (\`openai\`, \`anthropic\`, \`google\`) |
| \`allowed_agents\` | Agent DIDs permitted to contribute (\`did:key:*\` = any) |
| \`minimum_proof_tier\` | Minimum proof tier: \`self\`, \`gateway\`, or \`sandbox\` |
| \`required_receipt_types\` | Receipt types that must be present in proof bundles |
| \`egress_allowlist\` | Allowed network egress targets (hostnames) |

## How It Works

1. An AI agent opens a PR with a \`proofs/**/proof_bundle.v1.json\` file
2. The Claw Verified GitHub App (or CI action) verifies the bundle
3. The bundle is checked against this policy
4. A Check Run reports PASS or FAIL with detailed reason codes

## Learn More

- [Clawsig Protocol](https://clawprotocol.org)
- [Claw Verified GitHub App](https://clawprotocol.org/github-app)
- [Work Policy Contract Spec](https://clawprotocol.org/specs/wpc)
`;

export interface InitOptions {
  /** Target directory (defaults to cwd) */
  targetDir?: string;
  /** Force overwrite existing files */
  force?: boolean;
}

export interface InitResult {
  created: string[];
  skipped: string[];
  dir: string;
}

export function runInit(options: InitOptions = {}): InitResult {
  const targetDir = resolve(options.targetDir ?? process.cwd());
  const clawsigDir = join(targetDir, CLAWSIG_DIR);

  const created: string[] = [];
  const skipped: string[] = [];

  // Create .clawsig/ directory
  if (!existsSync(clawsigDir)) {
    mkdirSync(clawsigDir, { recursive: true });
  }

  // Write policy.json
  const policyPath = join(clawsigDir, 'policy.json');
  if (existsSync(policyPath) && !options.force) {
    skipped.push('policy.json');
  } else {
    writeFileSync(policyPath, JSON.stringify(DEFAULT_POLICY, null, 2) + '\n', 'utf-8');
    created.push('policy.json');
  }

  // Write README.md
  const readmePath = join(clawsigDir, 'README.md');
  if (existsSync(readmePath) && !options.force) {
    skipped.push('README.md');
  } else {
    writeFileSync(readmePath, README_CONTENT, 'utf-8');
    created.push('README.md');
  }

  return { created, skipped, dir: clawsigDir };
}
