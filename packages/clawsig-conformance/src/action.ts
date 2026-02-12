/**
 * GitHub Action entry point for the Clawsig Conformance Test.
 */

import * as core from '@actions/core';
import { runConformanceTest } from './runner.js';
import type { ProofTier } from './types.js';
import { PROOF_TIERS } from './types.js';

function isValidTier(tier: string): tier is ProofTier {
  return (PROOF_TIERS as readonly string[]).includes(tier);
}

async function run(): Promise<void> {
  try {
    const agentCommand = core.getInput('agent_command', { required: true });
    const expectedTierInput = core.getInput('expected_tier') || 'self';
    const timeoutInput = core.getInput('timeout') || '60';
    const outputPath = core.getInput('output_path') || '.clawsig/proof_bundle.json';

    if (!isValidTier(expectedTierInput)) {
      core.setFailed(`Invalid expected_tier "${expectedTierInput}". Must be one of: ${PROOF_TIERS.join(', ')}`);
      return;
    }
    const timeout = parseInt(timeoutInput, 10);
    if (isNaN(timeout) || timeout <= 0) { core.setFailed(`Invalid timeout "${timeoutInput}".`); return; }

    core.info(`Clawsig Conformance Test`);
    core.info(`  Command:       ${agentCommand}`);
    core.info(`  Expected tier: ${expectedTierInput}`);
    core.info(`  Timeout:       ${timeout}s`);
    core.info(`  Output path:   ${outputPath}`);
    core.info('');

    const result = await runConformanceTest({ agentCommand, expectedTier: expectedTierInput, timeout, outputPath });

    core.setOutput('passed', String(result.passed));
    core.setOutput('tier', result.tier ?? 'none');
    core.setOutput('bundle_found', String(result.bundle_found));
    core.setOutput('bundle_valid', String(result.bundle_valid));
    core.setOutput('event_chain_length', String(result.event_chain_length));
    core.setOutput('receipt_count', String(result.receipt_count));

    const icon = result.passed ? '\u2705' : '\u274c';
    const tierBadge = result.tier ? `\`${result.tier.toUpperCase()}\`` : '`NONE`';
    const lines = [
      `## ${icon} Clawsig Conformance Test`, '',
      '| Check | Result |', '|-------|--------|',
      `| Bundle found | ${result.bundle_found ? '\u2705' : '\u274c'} |`,
      `| Bundle valid | ${result.bundle_valid ? '\u2705' : '\u274c'} |`,
      `| Proof tier | ${tierBadge} |`,
      `| Meets expected (${expectedTierInput}) | ${result.tier_meets_expected ? '\u2705' : '\u274c'} |`,
      `| Event chain length | ${result.event_chain_length} |`,
      `| Receipt count | ${result.receipt_count} |`, '',
    ];
    if (result.passed) {
      lines.push(`> **Clawsig Inside** \u2014 This framework produces valid ${tierBadge} tier proof bundles.`, '',
        `[![Clawsig Inside](https://api.clawverify.com/v1/badges/conformance/${expectedTierInput}.svg)](https://clawsig.com/directory)`);
    }
    if (result.errors.length > 0) {
      lines.push('', '### Errors', '');
      for (const err of result.errors) lines.push(`- ${err}`);
    }
    await core.summary.addRaw(lines.join('\n')).write();

    if (result.errors.length > 0) { for (const err of result.errors) core.warning(err); }
    if (result.passed) core.info(`\nConformance test PASSED (tier: ${result.tier})`);
    else core.setFailed(`Conformance test FAILED. ${result.errors.length} error(s): ${result.errors.join('; ')}`);
  } catch (error) {
    core.setFailed(`Unexpected error: ${(error as Error).message}`);
  }
}

run();
