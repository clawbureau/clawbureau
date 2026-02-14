/**
 * Compiles WPC (Work Policy Contract) JSON into a flat line-based format
 * that sentinel-shell-policy.sh can read with pure bash glob matching.
 *
 * Output format (.clawsig/policy.compiled):
 *   # Comments start with #
 *   ALLOW_CMD:<glob pattern>
 *   DENY_CMD:<glob pattern>
 *   DENY_FILE:<glob pattern>
 *
 * Rules are evaluated in order: DENY_FILE first, then DENY_CMD with
 * ALLOW_CMD exceptions. This mirrors WPC's "explicit deny + allow list" model.
 */

import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';

interface WpcStatement {
  effect: 'Allow' | 'Deny';
  action?: string[];
  actions?: string[];
  resource?: string[];
  resources?: string[];
  condition?: Record<string, Record<string, string[]>>;
  conditions?: Record<string, Record<string, string[]>>;
}

interface WpcPolicy {
  statements: WpcStatement[];
}

export async function compilePolicyToBash(jsonPath: string, outPath: string): Promise<void> {
  try {
    const raw = await readFile(jsonPath, 'utf-8');
    const policy: WpcPolicy = JSON.parse(raw);
    const lines: string[] = [];

    lines.push('# Clawsig Compiled Policy');
    lines.push(`# Source: ${jsonPath}`);
    lines.push(`# Compiled: ${new Date().toISOString()}`);
    lines.push('');

    for (const stmt of policy.statements || []) {
      if (stmt.effect !== 'Deny') continue;

      const actions = stmt.action ?? stmt.actions ?? [];
      const resources = stmt.resource ?? stmt.resources ?? [];
      const conditions = stmt.condition ?? stmt.conditions ?? {};

      const isNetworkEgress =
        actions.includes('network:egress') ||
        actions.includes('side_effect:network_egress') ||
        actions.includes('*');

      const isFileRead =
        actions.includes('file:read') ||
        actions.includes('side_effect:filesystem_read') ||
        actions.includes('*');

      const isFileWrite =
        actions.includes('file:write') ||
        actions.includes('side_effect:filesystem_write');

      // Network egress deny with domain allow list
      if (isNetworkEgress) {
        const allowedDomains =
          conditions.StringNotLike?.['SideEffect:TargetDomain'] ??
          conditions.StringNotLike?.['destination'] ?? [];

        // Add ALLOW exceptions for whitelisted domains
        for (const domain of allowedDomains) {
          const clean = domain.replace(/^\*\.?/, '');
          lines.push(`ALLOW_CMD:*curl*${clean}*`);
          lines.push(`ALLOW_CMD:*wget*${clean}*`);
          lines.push(`ALLOW_CMD:*nc*${clean}*`);
        }

        // Deny outbound data patterns (curl POST/PUT with data)
        lines.push('DENY_CMD:*curl*-X*POST*-d*@*');
        lines.push('DENY_CMD:*curl*-X*PUT*-d*@*');
        lines.push('DENY_CMD:*curl*--data-binary*@*');
        lines.push('DENY_CMD:*curl*--upload-file*');
        lines.push('DENY_CMD:*curl*-T *');
        lines.push('DENY_CMD:*wget*--post-file*');

        // Deny pipe to network exfiltration
        lines.push('DENY_CMD:*|*curl*-d*@-*');
        lines.push('DENY_CMD:*|*nc *');
        lines.push('DENY_CMD:*|*netcat *');
      }

      // File access deny for specific paths
      if ((isFileRead || isFileWrite) && resources.length > 0) {
        for (const res of resources) {
          if (res === '*') continue; // Skip wildcard-all
          // Convert resource glob to bash pattern
          const glob = res
            .replace(/^~/, '*')  // ~ → * (bash glob won't expand ~)
            .replace(/\*\*/g, '*'); // ** → * (bash glob doesn't do recursive)
          lines.push(`DENY_FILE:*${glob}*`);
        }
      }
    }

    // Baseline exfiltration blocks (always present)
    lines.push('');
    lines.push('# Baseline exfiltration protections');
    lines.push('DENY_CMD:*curl*-X*POST*-d*@*/.ssh/*');
    lines.push('DENY_CMD:*curl*-X*POST*-d*@*/.aws/*');
    lines.push('DENY_CMD:*curl*-d*@*id_rsa*');
    lines.push('DENY_CMD:*curl*-d*@*id_ed25519*');
    lines.push('DENY_CMD:*curl*-d*@*.pem*');
    lines.push('DENY_CMD:*curl*-d*@*.key*');
    lines.push('DENY_CMD:*curl*-d*@*.env*');
    lines.push('DENY_CMD:*|*bash*');
    lines.push('DENY_CMD:*|*sh -c*');

    await mkdir(dirname(outPath), { recursive: true });
    await writeFile(outPath, lines.join('\n') + '\n', 'utf-8');
  } catch {
    // Fail soft — no compiled policy means no bash-level blocking
  }
}
