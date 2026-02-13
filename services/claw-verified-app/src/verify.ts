/**
 * Bundle verification orchestrator for the Claw Verified GitHub App.
 *
 * Delegates actual cryptographic verification to @clawbureau/clawverify-core.
 * Handles: bundle discovery (VaaS + file tree), diff-to-receipt reconciliation,
 * policy compliance, trust checks, and Observe Mode.
 */

import type { PolicyConfig, VerificationSummary } from './types';
import { isGatewayTrusted, meetsTierRequirement } from './trust';
import { isAgentAllowed, hasRequiredReceipts } from './policy';
import { getFileContent, getPRFiles, getPRBody } from './github';
import { reconcileDiffWithBundle, formatReconciliationSummary } from './reconcile';
import type { ReconciliationResult } from './reconcile';

// ---------- VaaS URL patterns ----------

const VAAS_URL_PATTERNS = [
  /explorer\.clawsig\.com\/run\/([\w-]+)/,
  /api\.clawverify\.com\/v1\/badges\/([\w-]+)/,
];

const VAAS_BUNDLE_ENDPOINT = 'https://api.clawverify.com/v1/ledger/bundles';

// ---------- Internal types ----------

interface BundleEntry {
  source: string;
  bundle: Record<string, unknown> | null;
  fetchError?: string;
}

// ---------- Public API ----------

/**
 * Run full verification pipeline for a PR.
 *
 * Pipeline:
 *  1. Fetch PR files (fail-closed)
 *  2. Discover bundles: VaaS first, then file tree
 *  3. Diff-to-receipt reconciliation (before policy evaluation)
 *  4. Verify each bundle (crypto + policy)
 *  5. Observe Mode override (when no WPC exists)
 *  6. Aggregate and return
 */
export async function verifyPR(
  token: string,
  repo: string,
  prNumber: number,
  headSha: string,
  policy: PolicyConfig,
  policySource: 'repo' | 'default' | 'no_policy',
): Promise<VerificationSummary> {
  const isObserveMode = policySource === 'no_policy';

  // ---- Step 1: Fetch PR files (fail-closed) ----
  let prFiles: Array<{ filename: string; sha: string; status: string; previous_filename?: string }>;
  try {
    prFiles = await getPRFiles(token, repo, prNumber);
  } catch (err) {
    return failClosed(
      'Failed to fetch PR files from GitHub API.',
      err,
      'PR_FILES_FETCH_FAILED',
    );
  }

  // ---- Step 2: Bundle discovery ----

  // 2a. VaaS discovery (priority)
  const vaasResult = await discoverVaaSBundle(token, repo, prNumber);

  // 2b. File tree discovery (fallback)
  const treeBundleFiles = prFiles.filter(
    f => f.filename.match(/proof_bundle.*\.json$/i) ||
         f.filename.match(/proofs\/.*\/.*bundle.*\.json$/i),
  );

  // 2c. Resolve: VaaS takes priority, fall back to file tree
  const bundleEntries: BundleEntry[] = [];

  if (vaasResult) {
    bundleEntries.push({ source: `vaas:${vaasResult.runId}`, bundle: vaasResult.bundle });
  }

  if (bundleEntries.length === 0) {
    for (const file of treeBundleFiles) {
      const content = await getFileContent(token, repo, file.filename, headSha);
      if (!content) {
        bundleEntries.push({
          source: file.filename,
          bundle: null,
          fetchError: 'BUNDLE_FETCH_FAILED',
        });
        continue;
      }

      try {
        bundleEntries.push({ source: file.filename, bundle: JSON.parse(content) });
      } catch {
        bundleEntries.push({
          source: file.filename,
          bundle: null,
          fetchError: 'BUNDLE_PARSE_ERROR',
        });
      }
    }
  }

  // No bundles at all
  if (bundleEntries.length === 0) {
    return noBundlesResult(isObserveMode, policySource);
  }

  // ---- Step 3: Diff-to-receipt reconciliation ----
  const loadedBundles = bundleEntries
    .filter((e): e is BundleEntry & { bundle: Record<string, unknown> } => e.bundle !== null);

  let reconciliation: ReconciliationResult;
  try {
    reconciliation = await reconcileDiffWithBundle(prFiles, loadedBundles.map(e => e.bundle));
  } catch (err) {
    return failClosed(
      'Diff-to-receipt reconciliation failed.',
      err,
      'RECONCILIATION_ERROR',
    );
  }

  // ---- Step 4: Verify each bundle ----
  const results: BundleResult[] = [];

  for (const entry of bundleEntries) {
    if (!entry.bundle) {
      results.push({
        path: entry.source,
        valid: false,
        reason: entry.fetchError || 'BUNDLE_LOAD_FAILED',
        receiptCount: 0,
      });
      continue;
    }

    // RED TEAM FIX #5: Replay attack prevention (before crypto verification)
    const replayCheck = checkCommitShaBinding(entry.bundle, headSha);
    if (replayCheck) {
      results.push({
        path: entry.source,
        valid: false,
        reason: replayCheck,
        receiptCount: 0,
      });
      continue;
    }

    const result = verifyBundle(entry.bundle, policy);
    results.push({ path: entry.source, ...result });
  }

  // ---- Step 5: Aggregate ----
  const allBundlesValid = results.every(r => r.valid);
  const totalReceipts = results.reduce((sum, r) => sum + r.receiptCount, 0);
  const reasonCodes = results.flatMap(r => r.reason ? [r.reason] : r.reasons || []);
  const agentDids = [...new Set(results.flatMap(r => r.agentDid ? [r.agentDid] : []))];

  if (!reconciliation.reconciled) {
    reasonCodes.push('UNATTESTED_FILE_MUTATION');
  }

  const allValid = allBundlesValid && reconciliation.reconciled;

  // ---- Step 6: Observe Mode ----
  if (isObserveMode) {
    return buildObserveModeResult(
      results,
      reconciliation,
      allBundlesValid,
      totalReceipts,
      agentDids,
      bundleEntries.length,
      reasonCodes,
    );
  }

  // ---- Step 7: Normal conclusion ----
  return buildNormalResult(
    results,
    reconciliation,
    allValid,
    totalReceipts,
    agentDids,
    bundleEntries.length,
    reasonCodes,
    policySource,
  );
}

// ---------- VaaS bundle discovery ----------

/**
 * Discover a proof bundle via VaaS (Verification-as-a-Service).
 * Parses the PR body for VaaS badge URLs and fetches the bundle.
 * Returns null on failure (non-fatal — falls back to file tree).
 */
async function discoverVaaSBundle(
  token: string,
  repo: string,
  prNumber: number,
): Promise<{ bundle: Record<string, unknown>; runId: string } | null> {
  let body: string;
  try {
    body = await getPRBody(token, repo, prNumber);
  } catch {
    return null;
  }

  if (!body) return null;

  // Extract run_id from badge URL
  let runId: string | null = null;
  for (const pattern of VAAS_URL_PATTERNS) {
    const match = body.match(pattern);
    if (match) {
      runId = match[1];
      break;
    }
  }

  if (!runId) return null;

  // Fetch the bundle from VaaS
  try {
    const resp = await fetch(
      `${VAAS_BUNDLE_ENDPOINT}/${encodeURIComponent(runId)}`,
      {
        headers: {
          Accept: 'application/json',
          'User-Agent': 'claw-verified-app',
        },
      },
    );

    if (!resp.ok) return null;

    const bundle = await resp.json() as Record<string, unknown>;
    return { bundle, runId };
  } catch {
    return null;
  }
}

// ---------- Result builders ----------

function failClosed(
  summary: string,
  err: unknown,
  reasonCode: string,
): VerificationSummary {
  return {
    conclusion: 'failure',
    output: {
      title: 'Claw Verified: FAIL',
      summary,
      text: `Error: ${err instanceof Error ? err.message : String(err)}\n\nVerification cannot proceed (fail-closed).`,
    },
    bundleCount: 0,
    receiptCount: 0,
    reasonCodes: [reasonCode],
  };
}

function noBundlesResult(
  isObserveMode: boolean,
  policySource: string,
): VerificationSummary {
  if (isObserveMode) {
    return {
      conclusion: 'neutral',
      output: {
        title: 'Clawsig Verified (Observe Mode)',
        summary: 'No Clawsig proof bundles found in this PR. No Work Policy Contract (WPC) is enforced.',
        text: [
          'No proof bundles were found in this PR or via VaaS.',
          '',
          'To add verification, include proof bundles or link a VaaS run in the PR body.',
          '',
          'To enforce constraints, add `.clawsig/policy.json` to your default branch.',
          'See https://clawsig.com/docs/policy',
        ].join('\n'),
      },
      bundleCount: 0,
      receiptCount: 0,
      reasonCodes: [],
    };
  }

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

function buildObserveModeResult(
  results: BundleResult[],
  reconciliation: ReconciliationResult,
  allBundlesValid: boolean,
  totalReceipts: number,
  agentDids: string[],
  bundleCount: number,
  reasonCodes: string[],
): VerificationSummary {
  const lines: string[] = [];

  if (allBundlesValid) {
    lines.push('Agent execution is cryptographically valid.');
  } else {
    lines.push('One or more proof bundles failed cryptographic verification.');
  }

  lines.push('');
  lines.push('No Work Policy Contract (WPC) is enforced.');
  lines.push('To enforce constraints, add `.clawsig/policy.json` to your default branch.');
  lines.push('See https://clawsig.com/docs/policy');
  lines.push('');
  lines.push(`**Proof tier:** ${results[0]?.tier || 'unknown'}`);
  lines.push(`**Bundles:** ${bundleCount}`);
  lines.push(`**Receipts:** ${totalReceipts}`);

  if (agentDids.length > 0) {
    lines.push(`**Agent(s):** ${agentDids.map(d => '`' + d.slice(0, 24) + '...`').join(', ')}`);
  }

  if (!reconciliation.reconciled) {
    lines.push('');
    lines.push('**Warning — Unattested files detected:**');
    for (const f of reconciliation.unattested_files) {
      lines.push(`- \`${f}\``);
    }
  }

  lines.push('');
  for (const r of results) {
    const icon = r.valid ? '\u2705' : '\u274C';
    lines.push(`${icon} \`${r.path}\`${r.reason ? ` \u2014 ${r.reason}` : ''}`);
    if (r.tier) lines.push(`  Tier: ${r.tier}`);
    if (r.receiptCount > 0) lines.push(`  Receipts: ${r.receiptCount}`);
  }

  return {
    conclusion: 'neutral',
    output: {
      title: 'Clawsig Verified (Observe Mode)',
      summary: [
        'Agent execution is cryptographically valid.',
        'No Work Policy Contract (WPC) is enforced.',
        'To enforce constraints, add `.clawsig/policy.json` to your default branch.',
        'See https://clawsig.com/docs/policy',
      ].join(' '),
      text: lines.join('\n'),
    },
    bundleCount,
    receiptCount: totalReceipts,
    reasonCodes,
  };
}

function buildNormalResult(
  results: BundleResult[],
  reconciliation: ReconciliationResult,
  allValid: boolean,
  totalReceipts: number,
  agentDids: string[],
  bundleCount: number,
  reasonCodes: string[],
  policySource: string,
): VerificationSummary {
  const conclusion = allValid ? 'success' : 'failure';

  const lines: string[] = [];

  if (allValid) {
    // Differential Provenance: show breakdown of agent vs human authorship
    const { summary: provSummary } = reconciliation;
    if (provSummary.mixed_files > 0 || provSummary.human_files > 0) {
      lines.push(`**Provenance Verified** (Agent: ${provSummary.agent_files} files, ` +
        `Mixed: ${provSummary.mixed_files}, Human: ${provSummary.human_files})`);
    } else {
      lines.push('All proof bundles passed verification and diff reconciliation.');
    }
  } else if (!reconciliation.reconciled) {
    lines.push('**UNATTESTED FILE MUTATION DETECTED.**');
    lines.push('');
    lines.push(formatReconciliationSummary(reconciliation));
  } else {
    lines.push('One or more proof bundles failed verification.');
  }

  lines.push('');
  lines.push(`**Bundles:** ${bundleCount}`);
  lines.push(`**Receipts:** ${totalReceipts}`);
  lines.push(`**Policy:** ${policySource === 'repo' ? '`.clawsig/policy.json`' : 'default'}`);

  if (agentDids.length > 0) {
    lines.push(`**Agent(s):** ${agentDids.map(d => '`' + d.slice(0, 24) + '...`').join(', ')}`);
  }

  lines.push('');
  for (const r of results) {
    const icon = r.valid ? '\u2705' : '\u274C';
    lines.push(`${icon} \`${r.path}\`${r.reason ? ` \u2014 ${r.reason}` : ''}`);
    if (r.tier) lines.push(`  Tier: ${r.tier}`);
    if (r.receiptCount > 0) lines.push(`  Receipts: ${r.receiptCount}`);
  }

  if (reasonCodes.length > 0) {
    lines.push('');
    lines.push('**Reason codes:** ' + reasonCodes.map(c => '`' + c + '`').join(', '));
  }

  // Title and summary vary by failure type
  let title: string;
  let summary: string;

  if (allValid) {
    const { summary: provSummary } = reconciliation;
    const provDetail = provSummary.mixed_files > 0
      ? ` Agent: ${provSummary.agent_files}, Mixed: ${provSummary.mixed_files}, Human: ${provSummary.human_files}`
      : ` ${totalReceipts} receipts. All files attested.`;
    title = `Claw Verified: PASS (${bundleCount} bundle${bundleCount > 1 ? 's' : ''})`;
    summary = `${bundleCount} proof bundle(s) verified.${provDetail} Policy compliant.`;
  } else if (!reconciliation.reconciled) {
    title = 'Claw Verified: FAIL \u2014 UNATTESTED FILE MUTATION';
    summary = `${reconciliation.unattested_files.length} file(s) changed in this PR have no provenance link to agent activity.`;
  } else {
    title = 'Claw Verified: FAIL';
    summary = `Verification failed: ${reasonCodes.join(', ')}`;
  }

  return {
    conclusion,
    output: { title, summary, text: lines.join('\n') },
    bundleCount,
    receiptCount: totalReceipts,
    reasonCodes,
  };
}

// ---------- Replay attack prevention (Red Team Fix #5) ----------

/**
 * Check that the proof bundle's commit SHA matches the PR HEAD SHA.
 * Prevents replay attacks where a valid bundle from a benign PR is
 * attached to a malicious PR. Runs BEFORE cryptographic verification.
 */
function checkCommitShaBinding(
  bundle: Record<string, unknown>,
  prHeadSha: string,
): string | null {
  // 1. Top-level commit_proof_envelope
  const commitProofEnvelope = bundle.commit_proof_envelope as
    | { payload?: { commit_sha?: string } }
    | undefined;
  if (commitProofEnvelope?.payload?.commit_sha) {
    if (commitProofEnvelope.payload.commit_sha !== prHeadSha) {
      return `REPLAY_ATTACK: Bundle commit SHA ${commitProofEnvelope.payload.commit_sha} does not match PR HEAD ${prHeadSha}`;
    }
    return null;
  }

  // 2. Nested inside signed envelope payload
  const payload = bundle.payload as Record<string, unknown> | undefined;
  if (payload) {
    const nestedCommitProof = payload.commit_proof_envelope as
      | { payload?: { commit_sha?: string } }
      | undefined;
    if (nestedCommitProof?.payload?.commit_sha) {
      if (nestedCommitProof.payload.commit_sha !== prHeadSha) {
        return `REPLAY_ATTACK: Bundle commit SHA ${nestedCommitProof.payload.commit_sha} does not match PR HEAD ${prHeadSha}`;
      }
      return null;
    }
  }

  // 3. Metadata commit_sha (lightweight bundles)
  const metadata = (bundle.metadata ?? payload?.metadata) as
    | { commit_sha?: string }
    | undefined;
  if (metadata?.commit_sha) {
    if (metadata.commit_sha !== prHeadSha) {
      return `REPLAY_ATTACK: Bundle commit SHA ${metadata.commit_sha} does not match PR HEAD ${prHeadSha}`;
    }
    return null;
  }

  // No commit SHA found — allow through (policy may require it separately)
  return null;
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
  if (!bundle.version && !bundle.bundle_version && !(bundle.payload as Record<string, unknown>)?.bundle_version) {
    return { valid: false, reason: 'MALFORMED_BUNDLE', receiptCount: 0 };
  }

  const agentDid = (bundle.agent_did ?? (bundle.payload as Record<string, unknown>)?.agent_did) as string;
  if (!agentDid) {
    return { valid: false, reason: 'MALFORMED_BUNDLE', receiptCount: 0 };
  }

  const tier = (bundle.proof_tier as string) || 'unknown';

  // Gateway receipt checks
  const gatewayReceipts = (bundle.gateway_receipts || bundle.receipts ||
    (bundle.payload as Record<string, unknown>)?.receipts || []) as Array<Record<string, unknown>>;
  const toolReceipts = (bundle.tool_receipts ||
    (bundle.payload as Record<string, unknown>)?.tool_receipts || []) as Array<Record<string, unknown>>;
  const sideEffectReceipts = (bundle.side_effect_receipts ||
    (bundle.payload as Record<string, unknown>)?.side_effect_receipts || []) as Array<Record<string, unknown>>;
  const humanApprovalReceipts = (bundle.human_approval_receipts ||
    (bundle.payload as Record<string, unknown>)?.human_approval_receipts || []) as Array<Record<string, unknown>>;

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
  const eventChain = (bundle.event_chain ||
    (bundle.payload as Record<string, unknown>)?.event_chain) as Array<Record<string, unknown>> | undefined;
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
