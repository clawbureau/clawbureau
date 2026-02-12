/**
 * WPC v1 -> v2 migration helper.
 *
 * Usage:
 *   clawsig migrate-policy <v1-policy.json>
 *
 * Converts a WPC v1 policy to WPC v2 IAM-style format.
 * Outputs valid WPC v2 JSON to stdout.
 */

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { WPCv1, WPCv2, PolicyStatement } from '@clawbureau/clawverify-core';

/**
 * Migrate a WPC v1 policy to WPC v2 format.
 *
 * Mapping rules:
 * - allowed_providers -> Allow model:invoke with StringEquals on Model:Provider
 * - allowed_models -> Allow model:invoke with StringLike on Model:Name
 * - egress_allowlist -> Allow side_effect:network_egress with StringLike on SideEffect:TargetDomain
 * - redaction_rules, receipt_privacy_mode -> preserved in metadata
 * - required_audit_packs -> preserved in metadata
 * - minimum_model_identity_tier -> preserved in metadata
 */
export function migrateV1toV2(v1: WPCv1): WPCv2 {
  if (v1.policy_version !== '1') {
    throw new Error(`Expected policy_version "1", got "${v1.policy_version}"`);
  }

  const statements: PolicyStatement[] = [];
  let sid = 0;

  // --- allowed_providers ---
  if (v1.allowed_providers && v1.allowed_providers.length > 0) {
    for (const provider of v1.allowed_providers) {
      statements.push({
        sid: `AllowProvider${capitalize(provider)}`,
        effect: 'Allow',
        actions: ['model:invoke'],
        resources: ['*'],
        conditions: {
          StringEquals: { 'Model:Provider': provider },
        },
      });
    }
  } else {
    statements.push({
      sid: `AllowAllProviders`,
      effect: 'Allow',
      actions: ['model:invoke'],
      resources: ['*'],
    });
  }

  // --- allowed_models ---
  if (v1.allowed_models && v1.allowed_models.length > 0) {
    // Remove blanket provider allows since we have specific model constraints
    const blanketIdx = statements.findIndex((s) => s.sid === 'AllowAllProviders');
    if (blanketIdx >= 0) {
      statements.splice(blanketIdx, 1);
    }

    for (const model of v1.allowed_models) {
      statements.push({
        sid: `AllowModel${sanitizeSid(model)}`,
        effect: 'Allow',
        actions: ['model:invoke'],
        resources: ['*'],
        conditions: {
          StringLike: { 'Model:Name': model },
        },
      });
    }
  }

  // --- egress_allowlist ---
  if (v1.egress_allowlist && v1.egress_allowlist.length > 0) {
    for (const domain of v1.egress_allowlist) {
      statements.push({
        sid: `AllowEgress${sanitizeSid(domain)}`,
        effect: 'Allow',
        actions: ['side_effect:network_egress'],
        resources: ['*'],
        conditions: {
          StringLike: { 'SideEffect:TargetDomain': domain },
        },
      });
    }
  } else {
    statements.push({
      sid: 'AllowAllEgress',
      effect: 'Allow',
      actions: ['side_effect:network_egress'],
      resources: ['*'],
    });
  }

  // --- Default: allow tools and filesystem (v1 had no restrictions) ---
  statements.push({
    sid: 'AllowAllToolsAndFilesystem',
    effect: 'Allow',
    actions: ['tool:*', 'side_effect:filesystem_read', 'side_effect:filesystem_write'],
    resources: ['*'],
  });

  // Build metadata preserving v1 fields that don't map to statements
  const metadata: Record<string, unknown> = {
    _migrated_from: 'v1',
    _migration_timestamp: new Date().toISOString(),
  };

  if (v1.minimum_model_identity_tier) {
    metadata._v1_minimum_model_identity_tier = v1.minimum_model_identity_tier;
  }
  if (v1.required_audit_packs && v1.required_audit_packs.length > 0) {
    metadata._v1_required_audit_packs = v1.required_audit_packs;
  }
  if (v1.redaction_rules && v1.redaction_rules.length > 0) {
    metadata._v1_redaction_rules = v1.redaction_rules;
  }
  if (v1.receipt_privacy_mode) {
    metadata._v1_receipt_privacy_mode = v1.receipt_privacy_mode;
  }
  if (v1.metadata) {
    Object.assign(metadata, v1.metadata);
  }

  return {
    policy_version: '2',
    policy_id: v1.policy_id,
    issuer_did: v1.issuer_did,
    statements,
    metadata,
  };
}

/** Capitalize first letter. */
function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

/** Sanitize a string for use as a statement ID suffix. */
function sanitizeSid(s: string): string {
  return s
    .replace(/[^a-zA-Z0-9]/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_|_$/g, '')
    .slice(0, 64);
}

/**
 * CLI entry point for `clawsig migrate-policy <path>`.
 */
export function runMigratePolicy(inputPath: string): void {
  const resolved = resolve(inputPath);
  let raw: string;
  try {
    raw = readFileSync(resolved, 'utf-8');
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(`Error reading file: ${msg}\n`);
    process.exitCode = 2;
    return;
  }

  let v1: WPCv1;
  try {
    v1 = JSON.parse(raw) as WPCv1;
  } catch {
    process.stderr.write('Error: input is not valid JSON\n');
    process.exitCode = 2;
    return;
  }

  if (v1.policy_version === '2' as string) {
    process.stderr.write('Policy is already v2, no migration needed.\n');
    process.stdout.write(JSON.stringify(v1, null, 2) + '\n');
    return;
  }

  if (v1.policy_version !== '1') {
    process.stderr.write(
      `Unsupported policy_version "${v1.policy_version}". Only v1 -> v2 migration is supported.\n`,
    );
    process.exitCode = 2;
    return;
  }

  try {
    const v2 = migrateV1toV2(v1);
    process.stdout.write(JSON.stringify(v2, null, 2) + '\n');
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(`Migration error: ${msg}\n`);
    process.exitCode = 1;
  }
}
