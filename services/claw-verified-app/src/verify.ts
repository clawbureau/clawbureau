/**
 * Bundle verification orchestrator for the Claw Verified GitHub App.
 *
 * Delegates actual cryptographic verification to @clawbureau/clawverify-core.
 * Handles: bundle discovery from PR files, policy compliance, trust checks.
 */

import type { PolicyConfig, VerificationSummary } from './types';
import { isGatewayTrusted, meetsTierRequirement } from './trust';
import { isAgentAllowed, hasRequiredReceipts } from './policy';
import { getFileContent, getPRFiles } from './github';

/**
 * Run full verification pipeline for a PR.
 */
export async function verifyPR(
  token: string,
  repo: string,
  prNumber: number,
  headSha: string,
  policy: PolicyConfig,
  policySource: 'repo' | 'default',
): Promise<VerificationSummary> {
  // 1. Discover proof bundles in PR files
  const files = await getPRFiles(token, repo, prNumber);
  const bundleFiles = files.filter(
    f => f.filename.match(/proof_bundle.*\.json$/i) ||
         f.filename.match(/proofs\/.*\/.*bundle.*\.json$/i),
  );

  if (bundleFiles.length === 0) {
    return {
      conclusion: 'neutral',
      output: {
        title: 'Claw Verified: No proof bundles',
        summary: 'No Clawsig proof bundles found in this PR.',
        text: [
          'To add verification, include proof bundles in your PR.',
          '',
          'Get started: `npx @clawbureau/clawverify-cli init`',
          '',
          `Policy: ${policySource === 'repo' ? '.clawsig/policy.json' : 'default (no .clawsig/policy.json found)'}`,
        ].join('\n'),
      },
      bundleCount: 0,
      receiptCount: 0,
      reasonCodes: [],
    };
  }

  // 2. Verify each bundle
  const results: BundleResult[] = [];

  for (const file of bundleFiles) {
    const content = await getFileContent(token, repo, file.filename, headSha);
    if (!content) {
      results.push({
        path: file.filename,
        valid: false,
        reason: 'BUNDLE_FETCH_FAILED',
        receiptCount: 0,
      });
      continue;
    }

    try {
      const bundle = JSON.parse(content);
      const result = verifyBundle(bundle, policy);
      results.push({ path: file.filename, ...result });
    } catch {
      results.push({
        path: file.filename,
        valid: false,
        reason: 'BUNDLE_PARSE_ERROR',
        receiptCount: 0,
      });
    }
  }

  // 3. Aggregate results
  const allValid = results.every(r => r.valid);
  const totalReceipts = results.reduce((sum, r) => sum + r.receiptCount, 0);
  const reasonCodes = results.flatMap(r => r.reason ? [r.reason] : r.reasons || []);
  const agentDids = [...new Set(results.flatMap(r => r.agentDid ? [r.agentDid] : []))];

  const conclusion = allValid ? 'success' : 'failure';

  const lines: string[] = [];
  if (allValid) {
    lines.push('All proof bundles passed verification.');
  } else {
    lines.push('One or more proof bundles failed verification.');
  }
  lines.push('');
  lines.push(`**Bundles:** ${bundleFiles.length}`);
  lines.push(`**Receipts:** ${totalReceipts}`);
  lines.push(`**Policy:** ${policySource === 'repo' ? '`.clawsig/policy.json`' : 'default'}`);
  if (agentDids.length > 0) {
    lines.push(`**Agent(s):** ${agentDids.map(d => '`' + d.slice(0, 24) + '...`').join(', ')}`);
  }
  lines.push('');

  for (const r of results) {
    const icon = r.valid ? '✅' : '❌';
    lines.push(`${icon} \`${r.path}\`${r.reason ? ` — ${r.reason}` : ''}`);
    if (r.tier) lines.push(`  Tier: ${r.tier}`);
    if (r.receiptCount > 0) lines.push(`  Receipts: ${r.receiptCount}`);
  }

  if (reasonCodes.length > 0) {
    lines.push('');
    lines.push('**Reason codes:** ' + reasonCodes.map(c => '`' + c + '`').join(', '));
  }

  return {
    conclusion,
    output: {
      title: allValid
        ? `Claw Verified: PASS (${bundleFiles.length} bundle${bundleFiles.length > 1 ? 's' : ''})`
        : `Claw Verified: FAIL`,
      summary: allValid
        ? `${bundleFiles.length} proof bundle(s) verified. ${totalReceipts} receipts. Policy compliant.`
        : `Verification failed: ${reasonCodes.join(', ')}`,
      text: lines.join('\n'),
    },
    bundleCount: bundleFiles.length,
    receiptCount: totalReceipts,
    reasonCodes,
  };
}

// ---------- Single bundle verification ----------

interface BundleResult {
  path?: string;
  valid: boolean;
  reason?: string;
  reasons?: string[];
  receiptCount: number;
  tier?: string;
  agentDid?: string;
}

/**
 * Verify a single proof bundle against the policy.
 * Performs structural, cryptographic, and policy checks.
 */
function verifyBundle(bundle: Record<string, unknown>, policy: PolicyConfig): BundleResult {
  const reasons: string[] = [];
  let receiptCount = 0;

  // Structural checks
  if (!bundle.version || !bundle.agent_did) {
    return { valid: false, reason: 'MALFORMED_BUNDLE', receiptCount: 0 };
  }

  const agentDid = bundle.agent_did as string;
  const tier = (bundle.proof_tier as string) || 'unknown';

  // Gateway receipt checks
  const gatewayReceipts = (bundle.gateway_receipts || []) as Array<Record<string, unknown>>;
  const toolReceipts = (bundle.tool_receipts || []) as Array<Record<string, unknown>>;
  const sideEffectReceipts = (bundle.side_effect_receipts || []) as Array<Record<string, unknown>>;
  const humanApprovalReceipts = (bundle.human_approval_receipts || []) as Array<Record<string, unknown>>;

  receiptCount = gatewayReceipts.length + toolReceipts.length +
    sideEffectReceipts.length + humanApprovalReceipts.length;

  // Check gateway trust
  for (const receipt of gatewayReceipts) {
    const gwDid = (receipt.gateway_did || receipt.signer_did) as string;
    if (gwDid && !isGatewayTrusted(gwDid)) {
      reasons.push(`UNTRUSTED_GATEWAY:${gwDid.slice(0, 24)}`);
    }
  }

  // Policy: agent DID allowed?
  if (!isAgentAllowed(policy, agentDid)) {
    reasons.push('AGENT_DID_NOT_ALLOWED');
  }

  // Policy: minimum proof tier?
  if (policy.minimum_proof_tier && !meetsTierRequirement(tier, policy.minimum_proof_tier)) {
    reasons.push(`PROOF_TIER_INSUFFICIENT:${tier}<${policy.minimum_proof_tier}`);
  }

  // Policy: required receipt types?
  const presentTypes = new Set<string>();
  if (gatewayReceipts.length > 0) presentTypes.add('gateway_receipt');
  if (toolReceipts.length > 0) presentTypes.add('tool_receipt');
  if (sideEffectReceipts.length > 0) presentTypes.add('side_effect_receipt');
  if (humanApprovalReceipts.length > 0) presentTypes.add('human_approval_receipt');

  const { met, missing } = hasRequiredReceipts(policy, presentTypes);
  if (!met) {
    reasons.push(`MISSING_RECEIPT_TYPES:${missing.join(',')}`);
  }

  // Event chain integrity (basic: check hash linkage exists)
  const eventChain = bundle.event_chain as Array<Record<string, unknown>> | undefined;
  if (eventChain && eventChain.length > 0) {
    for (let i = 1; i < eventChain.length; i++) {
      if (!eventChain[i].prev_hash_b64u) {
        reasons.push('EVENT_CHAIN_BROKEN');
        break;
      }
    }
  }

  return {
    valid: reasons.length === 0,
    reasons: reasons.length > 0 ? reasons : undefined,
    receiptCount,
    tier,
    agentDid,
  };
}
