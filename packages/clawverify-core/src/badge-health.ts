/**
 * badge-health.ts — Heartbeat Badge status computation
 *
 * Red Team Fix #9: Dynamic badge that reflects real-time verification
 * activity. Prevents frameworks from passing conformance once and then
 * silently removing the integration while keeping the badge.
 *
 * The badge color is computed from trailing 7-day run statistics.
 */

/** Badge color enum for rendering. */
export type BadgeColor = 'green' | 'yellow' | 'gray' | 'red';

/** Input statistics for badge computation. */
export interface BadgeStats {
  /** Number of verification runs in the last 7 days. */
  runs_7d: number;
  /** Number of policy violations in the last 7 days. */
  violations_7d: number;
  /** ISO 8601 timestamp of the most recent run. */
  last_run_at: string;
}

/** Computed badge status. */
export interface BadgeStatus {
  /** Badge color for rendering. */
  color: BadgeColor;
  /** Human-readable label. */
  label: string;
  /** Whether the badge represents a healthy integration. */
  healthy: boolean;
}

/** Minimum number of runs in 7 days for the badge to be considered active. */
const MIN_ACTIVE_RUNS = 10;

/** Violation rate threshold (fraction) above which the badge turns red. */
const RED_VIOLATION_RATE = 0.1;

/**
 * Compute the badge status from trailing 7-day run statistics.
 *
 * Color logic:
 * - Green:  runs_7d >= 10 AND violations_7d == 0
 * - Yellow: runs_7d >= 10 AND violations_7d > 0 (but within 10%)
 * - Gray:   runs_7d < 10 (insufficient recent activity)
 * - Red:    violations_7d > runs_7d * 0.1 (>10% violation rate)
 */
export function computeBadgeStatus(stats: BadgeStats): BadgeStatus {
  const { runs_7d, violations_7d } = stats;

  // Insufficient activity — badge is stale
  if (runs_7d < MIN_ACTIVE_RUNS) {
    return {
      color: 'gray',
      label: 'Insufficient activity',
      healthy: false,
    };
  }

  // High violation rate — badge is red
  if (violations_7d > runs_7d * RED_VIOLATION_RATE) {
    return {
      color: 'red',
      label: `${violations_7d} violations (${((violations_7d / runs_7d) * 100).toFixed(1)}%)`,
      healthy: false,
    };
  }

  // Some violations but within tolerance — badge is yellow
  if (violations_7d > 0) {
    return {
      color: 'yellow',
      label: `${violations_7d} violation${violations_7d === 1 ? '' : 's'} in 7d`,
      healthy: true,
    };
  }

  // Clean — badge is green
  return {
    color: 'green',
    label: `${runs_7d} verified runs`,
    healthy: true,
  };
}
