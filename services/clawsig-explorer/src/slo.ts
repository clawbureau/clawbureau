export type SloSeverity = 'ok' | 'warn' | 'critical';

export interface SloWindowMetrics {
  window: '24h' | '7d';
  runs: number;
  fail_runs: number;
  fail_rate: number;
  error_budget_fraction: number;
  burn_rate: number;
}

export interface OpsSloHealth {
  generated_at: string;
  target_success_rate: number;
  error_budget_fraction: number;
  thresholds: {
    warn_burn_rate_24h: number;
    warn_burn_rate_7d: number;
    critical_burn_rate_24h: number;
    critical_burn_rate_7d: number;
  };
  windows: {
    window_24h: SloWindowMetrics;
    window_7d: SloWindowMetrics;
  };
  severity: SloSeverity;
  status: 'healthy' | 'watch' | 'degraded';
  reason_code: string;
  domain_degraded_hosts: string[];
  failing_workflows: string[];
  notes: string[];
}

interface InputStats {
  runs_24h: number;
  fail_runs_24h: number;
  fail_rate_24h: number;
  diagnostics_7d: {
    runs_7d: number;
    fail_runs_7d: number;
    fail_rate_7d: number;
  };
}

interface InputDomainHealth {
  host: string;
  ok: boolean;
}

interface InputWorkflowStatus {
  workflow: string;
  ok: boolean | null;
}

const TARGET_SUCCESS_RATE = 0.99;
const ERROR_BUDGET_FRACTION = 1 - TARGET_SUCCESS_RATE;

const WARN_BURN_RATE_24H = 1;
const WARN_BURN_RATE_7D = 1;
const CRITICAL_BURN_RATE_24H = 2;
const CRITICAL_BURN_RATE_7D = 1.5;

const severityRank: Record<SloSeverity, number> = {
  ok: 0,
  warn: 1,
  critical: 2,
};

function toFiniteNumber(value: unknown, fallback = 0): number {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string') {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return fallback;
}

function buildWindow(
  window: '24h' | '7d',
  runsRaw: unknown,
  failRunsRaw: unknown,
  failRateRaw: unknown,
): SloWindowMetrics {
  const runs = Math.max(0, toFiniteNumber(runsRaw, 0));
  const failRuns = Math.max(0, toFiniteNumber(failRunsRaw, 0));
  const fallbackRate = runs > 0 ? failRuns / runs : 0;
  const failRate = Math.max(0, toFiniteNumber(failRateRaw, fallbackRate));

  return {
    window,
    runs,
    fail_runs: failRuns,
    fail_rate: failRate,
    error_budget_fraction: ERROR_BUDGET_FRACTION,
    burn_rate: Number((failRate / ERROR_BUDGET_FRACTION).toFixed(6)),
  };
}

function maxSeverity(a: SloSeverity, b: SloSeverity): SloSeverity {
  return severityRank[a] >= severityRank[b] ? a : b;
}

export function deriveOpsSloHealth(input: {
  stats: InputStats;
  domainHealth: InputDomainHealth[];
  syntheticStatuses: InputWorkflowStatus[];
}): OpsSloHealth {
  const window24h = buildWindow(
    '24h',
    input.stats.runs_24h,
    input.stats.fail_runs_24h,
    input.stats.fail_rate_24h,
  );

  const window7d = buildWindow(
    '7d',
    input.stats.diagnostics_7d.runs_7d,
    input.stats.diagnostics_7d.fail_runs_7d,
    input.stats.diagnostics_7d.fail_rate_7d,
  );

  const degradedHosts = input.domainHealth
    .filter((row) => row.ok === false)
    .map((row) => row.host);

  const failingWorkflows = input.syntheticStatuses
    .filter((row) => row.ok === false)
    .map((row) => row.workflow);

  let severity: SloSeverity = 'ok';
  let reasonCode = 'SLO_HEALTHY';

  const critical24h = window24h.burn_rate >= CRITICAL_BURN_RATE_24H;
  const critical7d = window7d.burn_rate >= CRITICAL_BURN_RATE_7D;
  const warn24h = window24h.burn_rate >= WARN_BURN_RATE_24H;
  const warn7d = window7d.burn_rate >= WARN_BURN_RATE_7D;

  if (critical24h && critical7d) {
    severity = maxSeverity(severity, 'critical');
    reasonCode = 'SLO_CRITICAL_BURNRATE_MULTIWINDOW';
  } else if (critical24h) {
    severity = maxSeverity(severity, 'critical');
    reasonCode = 'SLO_CRITICAL_BURNRATE_24H';
  } else if (critical7d) {
    severity = maxSeverity(severity, 'critical');
    reasonCode = 'SLO_CRITICAL_BURNRATE_7D';
  } else if (warn24h && warn7d) {
    severity = maxSeverity(severity, 'warn');
    reasonCode = 'SLO_WARN_BURNRATE_MULTIWINDOW';
  } else if (warn24h) {
    severity = maxSeverity(severity, 'warn');
    reasonCode = 'SLO_WARN_BURNRATE_24H';
  } else if (warn7d) {
    severity = maxSeverity(severity, 'warn');
    reasonCode = 'SLO_WARN_BURNRATE_7D';
  }

  if (degradedHosts.length > 0) {
    severity = 'critical';
    reasonCode = 'SLO_CRITICAL_DOMAIN_HEALTH_DEGRADED';
  } else if (failingWorkflows.length > 0) {
    severity = 'critical';
    reasonCode = 'SLO_CRITICAL_SYNTHETIC_FAILURE';
  }

  const notes: string[] = [];
  if (degradedHosts.length > 0) {
    notes.push(`degraded_hosts=${degradedHosts.join(',')}`);
  }
  if (failingWorkflows.length > 0) {
    notes.push(`failing_workflows=${failingWorkflows.join(',')}`);
  }

  return {
    generated_at: new Date().toISOString(),
    target_success_rate: TARGET_SUCCESS_RATE,
    error_budget_fraction: ERROR_BUDGET_FRACTION,
    thresholds: {
      warn_burn_rate_24h: WARN_BURN_RATE_24H,
      warn_burn_rate_7d: WARN_BURN_RATE_7D,
      critical_burn_rate_24h: CRITICAL_BURN_RATE_24H,
      critical_burn_rate_7d: CRITICAL_BURN_RATE_7D,
    },
    windows: {
      window_24h: window24h,
      window_7d: window7d,
    },
    severity,
    status: severity === 'critical' ? 'degraded' : (severity === 'warn' ? 'watch' : 'healthy'),
    reason_code: reasonCode,
    domain_degraded_hosts: degradedHosts,
    failing_workflows: failingWorkflows,
    notes,
  };
}
