/**
 * ECON-OPS-001: Economy health dashboard aggregator.
 *
 * Fans out to each economy-lane service and aggregates a single-glance
 * health view. Admin-token-gated.
 *
 * Data sources:
 *   - clawsettle (local D1): risk holds, disputes, outbox depths, forwarding failures
 *   - ledger: risk holds, account count
 *   - escrow: active escrows, disputed escrows
 *   - clawbounties: open bounties, submissions, risk state
 *   - clawcuts: active policies
 *   - clawincome: health probe
 *   - clawinsure: health probe
 */

import type { Env } from './types';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type OverallStatus = 'healthy' | 'degraded' | 'unhealthy';

interface ServiceHealth {
  service: string;
  status: 'up' | 'down' | 'degraded';
  latency_ms: number;
  metrics: Record<string, unknown>;
  error?: string;
}

interface EconomyHealthReport {
  generated_at: string;
  overall_status: OverallStatus;
  services: ServiceHealth[];
  settlement: {
    loss_events: {
      total: number;
      by_status: Record<string, number>;
    };
    outbox: {
      apply: { pending: number; failed: number; forwarded: number };
      resolve: { pending: number; failed: number; forwarded: number };
    };
    disputes: {
      total_open: number;
      total_disputed_minor: string;
      aging_buckets: Array<{ label: string; count: number; total_minor: string }>;
      fees_pending: number;
    };
    recon: {
      mismatch_count: number;
      mismatch_types: string[];
    };
  };
  alerts: {
    outbox_stale_failures: boolean;
    disputes_aging_critical: boolean;
    recon_mismatches: boolean;
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function nowIso(): string {
  return new Date().toISOString();
}

interface ProbeResult {
  ok: boolean;
  status: number;
  latency_ms: number;
  data: Record<string, unknown> | null;
  error?: string;
}

async function probeService(
  baseUrl: string | undefined,
  path: string,
  token: string | undefined,
  timeoutMs = 5000
): Promise<ProbeResult> {
  if (!baseUrl || !token) {
    return { ok: false, status: 0, latency_ms: 0, data: null, error: 'not_configured' };
  }

  const url = `${baseUrl.replace(/\/$/, '')}${path}`;
  const start = Date.now();

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    const res = await fetch(url, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json',
      },
      signal: controller.signal,
    });

    clearTimeout(timer);
    const latency = Date.now() - start;

    if (!res.ok) {
      return { ok: false, status: res.status, latency_ms: latency, data: null, error: `http_${res.status}` };
    }

    const data = await res.json() as Record<string, unknown>;
    return { ok: true, status: res.status, latency_ms: latency, data };
  } catch (err) {
    const latency = Date.now() - start;
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, status: 0, latency_ms: latency, data: null, error: message };
  }
}

async function probeHealth(
  baseUrl: string | undefined,
  timeoutMs = 5000
): Promise<ProbeResult> {
  if (!baseUrl) {
    return { ok: false, status: 0, latency_ms: 0, data: null, error: 'not_configured' };
  }

  const url = `${baseUrl.replace(/\/$/, '')}/health`;
  const start = Date.now();

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const res = await fetch(url, { signal: controller.signal });
    clearTimeout(timer);
    const latency = Date.now() - start;
    return { ok: res.ok, status: res.status, latency_ms: latency, data: null };
  } catch (err) {
    const latency = Date.now() - start;
    return { ok: false, status: 0, latency_ms: latency, data: null, error: err instanceof Error ? err.message : String(err) };
  }
}

function toServiceHealth(name: string, probe: ProbeResult, metrics: Record<string, unknown> = {}): ServiceHealth {
  return {
    service: name,
    status: probe.ok ? 'up' : 'down',
    latency_ms: probe.latency_ms,
    metrics,
    ...(probe.error ? { error: probe.error } : {}),
  };
}

function asNumber(v: unknown): number {
  if (typeof v === 'number' && Number.isFinite(v)) return v;
  if (typeof v === 'string') { const n = Number(v); return Number.isFinite(n) ? n : 0; }
  return 0;
}

// ---------------------------------------------------------------------------
// Local D1 queries (clawsettle)
// ---------------------------------------------------------------------------

async function queryLocalSettlement(db: D1Database): Promise<EconomyHealthReport['settlement']> {
  // Loss events by status
  const eventStats = await db
    .prepare(
      `SELECT status, COUNT(1) AS cnt FROM loss_events GROUP BY status`
    )
    .all<{ status: string; cnt: number }>();

  const byStatus: Record<string, number> = {};
  let totalEvents = 0;
  for (const row of eventStats.results ?? []) {
    byStatus[row.status] = row.cnt;
    totalEvents += row.cnt;
  }

  // Outbox apply depths
  const applyStats = await db
    .prepare(
      `SELECT status, COUNT(1) AS cnt FROM loss_event_outbox GROUP BY status`
    )
    .all<{ status: string; cnt: number }>();

  const applyBuckets = { pending: 0, failed: 0, forwarded: 0 };
  for (const row of applyStats.results ?? []) {
    if (row.status === 'pending') applyBuckets.pending = row.cnt;
    else if (row.status === 'failed') applyBuckets.failed = row.cnt;
    else if (row.status === 'forwarded') applyBuckets.forwarded = row.cnt;
  }

  // Outbox resolve depths
  const resolveStats = await db
    .prepare(
      `SELECT status, COUNT(1) AS cnt FROM loss_event_resolution_outbox GROUP BY status`
    )
    .all<{ status: string; cnt: number }>();

  const resolveBuckets = { pending: 0, failed: 0, forwarded: 0 };
  for (const row of resolveStats.results ?? []) {
    if (row.status === 'pending') resolveBuckets.pending = row.cnt;
    else if (row.status === 'failed') resolveBuckets.failed = row.cnt;
    else if (row.status === 'forwarded') resolveBuckets.forwarded = row.cnt;
  }

  // Dispute aging
  const now = new Date();
  const openDisputes = await db
    .prepare(
      `SELECT created_at, disputed_amount_minor, amount_minor
       FROM dispute_loss_event_bridge
       WHERE dispute_status = 'open'`
    )
    .all<{ created_at: string; disputed_amount_minor: string | null; amount_minor: string }>();

  const bucketDefs = [
    { label: '0-7d', min: 0, max: 7 },
    { label: '7-30d', min: 7, max: 30 },
    { label: '30-60d', min: 30, max: 60 },
    { label: '60+d', min: 60, max: null as number | null },
  ];

  const agingBuckets = bucketDefs.map(d => ({ label: d.label, count: 0, total_minor: '0', _min: d.min, _max: d.max }));
  let totalOpen = 0;
  let totalDisputedBigInt = 0n;

  for (const row of openDisputes.results ?? []) {
    const ageDays = Math.floor((now.getTime() - new Date(row.created_at).getTime()) / 86400000);
    const minor = row.disputed_amount_minor ?? row.amount_minor;
    const minorBigInt = BigInt(minor);
    totalOpen++;
    totalDisputedBigInt += minorBigInt;

    for (const bucket of agingBuckets) {
      if (ageDays >= bucket._min && (bucket._max === null || ageDays < bucket._max)) {
        bucket.count++;
        bucket.total_minor = (BigInt(bucket.total_minor) + minorBigInt).toString();
        break;
      }
    }
  }

  // Pending fees
  const feesPending = await db
    .prepare(`SELECT COUNT(1) AS cnt FROM dispute_fees WHERE status = 'pending'`)
    .first<{ cnt: number }>();

  // Recon mismatches (lightweight: just count loss events with issues)
  const reconIssues: string[] = [];
  let reconCount = 0;

  // Check: open disputes with failed forwarding
  const failedForwarding = await db
    .prepare(
      `SELECT COUNT(1) AS cnt FROM dispute_loss_event_bridge b
       JOIN loss_events e ON e.id = b.loss_event_id
       WHERE b.dispute_status = 'open' AND e.status = 'failed'`
    )
    .first<{ cnt: number }>();
  if (failedForwarding && failedForwarding.cnt > 0) {
    reconCount += failedForwarding.cnt;
    reconIssues.push('open_dispute_forwarding_failed');
  }

  // Check: resolved disputes without fully forwarded resolution
  const unresolvedHolds = await db
    .prepare(
      `SELECT COUNT(1) AS cnt FROM dispute_loss_event_bridge b
       JOIN loss_event_resolutions r ON r.loss_event_id = b.loss_event_id
       WHERE b.dispute_status = 'resolved_won' AND r.status != 'forwarded'`
    )
    .first<{ cnt: number }>();
  if (unresolvedHolds && unresolvedHolds.cnt > 0) {
    reconCount += unresolvedHolds.cnt;
    reconIssues.push('resolved_hold_not_released');
  }

  // Check: stale outbox failures (older than 1 hour)
  const oneHourAgo = new Date(now.getTime() - 3600000).toISOString();
  const staleApply = await db
    .prepare(
      `SELECT COUNT(1) AS cnt FROM loss_event_outbox
       WHERE status = 'failed' AND updated_at < ?`
    )
    .bind(oneHourAgo)
    .first<{ cnt: number }>();
  if (staleApply && staleApply.cnt > 0) {
    reconIssues.push('stale_outbox_failures');
  }

  return {
    loss_events: {
      total: totalEvents,
      by_status: byStatus,
    },
    outbox: {
      apply: applyBuckets,
      resolve: resolveBuckets,
    },
    disputes: {
      total_open: totalOpen,
      total_disputed_minor: totalDisputedBigInt.toString(),
      aging_buckets: agingBuckets.map(b => ({ label: b.label, count: b.count, total_minor: b.total_minor })),
      fees_pending: feesPending?.cnt ?? 0,
    },
    recon: {
      mismatch_count: reconCount,
      mismatch_types: reconIssues,
    },
  };
}

// ---------------------------------------------------------------------------
// Ops alerts (Task 2)
// ---------------------------------------------------------------------------

export interface OpsAlert {
  id: string;
  alert_type: string;
  severity: 'info' | 'warning' | 'critical';
  details_json: string;
  created_at: string;
}

async function writeAlert(
  db: D1Database,
  alertType: string,
  severity: 'info' | 'warning' | 'critical',
  details: Record<string, unknown>
): Promise<void> {
  const id = `alert_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  const now = nowIso();
  await db
    .prepare(
      `INSERT INTO ops_alerts (id, alert_type, severity, details_json, created_at)
       VALUES (?, ?, ?, ?, ?)`
    )
    .bind(id, alertType, severity, JSON.stringify(details), now)
    .run();
}

/**
 * Run cron-triggered alert checks. Called from scheduled handler.
 */
export async function runOpsAlertChecks(db: D1Database): Promise<{ alerts_written: number }> {
  let written = 0;
  const now = new Date();

  // 1. Stale outbox failures (failed entries older than 1 hour)
  const oneHourAgo = new Date(now.getTime() - 3600000).toISOString();

  const staleApply = await db
    .prepare(
      `SELECT COUNT(1) AS cnt FROM loss_event_outbox
       WHERE status = 'failed' AND updated_at < ?`
    )
    .bind(oneHourAgo)
    .first<{ cnt: number }>();

  const staleResolve = await db
    .prepare(
      `SELECT COUNT(1) AS cnt FROM loss_event_resolution_outbox
       WHERE status = 'failed' AND updated_at < ?`
    )
    .bind(oneHourAgo)
    .first<{ cnt: number }>();

  if ((staleApply?.cnt ?? 0) > 0 || (staleResolve?.cnt ?? 0) > 0) {
    await writeAlert(db, 'outbox_stale_failures', 'warning', {
      apply_stale_count: staleApply?.cnt ?? 0,
      resolve_stale_count: staleResolve?.cnt ?? 0,
      threshold: '1h',
    });
    written++;
  }

  // 2. Disputes aging 60+ days
  const sixtyDaysAgo = new Date(now.getTime() - 60 * 86400000).toISOString();
  const aging60plus = await db
    .prepare(
      `SELECT COUNT(1) AS cnt FROM dispute_loss_event_bridge
       WHERE dispute_status = 'open' AND created_at < ?`
    )
    .bind(sixtyDaysAgo)
    .first<{ cnt: number }>();

  if ((aging60plus?.cnt ?? 0) > 0) {
    await writeAlert(db, 'disputes_aging_critical', 'critical', {
      count_60plus_days: aging60plus?.cnt ?? 0,
      note: 'Open disputes older than 60 days require immediate attention',
    });
    written++;
  }

  // 3. Recon mismatches
  const failedForwarding = await db
    .prepare(
      `SELECT COUNT(1) AS cnt FROM dispute_loss_event_bridge b
       JOIN loss_events e ON e.id = b.loss_event_id
       WHERE b.dispute_status = 'open' AND e.status = 'failed'`
    )
    .first<{ cnt: number }>();

  const unresolvedHolds = await db
    .prepare(
      `SELECT COUNT(1) AS cnt FROM dispute_loss_event_bridge b
       JOIN loss_event_resolutions r ON r.loss_event_id = b.loss_event_id
       WHERE b.dispute_status = 'resolved_won' AND r.status != 'forwarded'`
    )
    .first<{ cnt: number }>();

  const totalMismatches = (failedForwarding?.cnt ?? 0) + (unresolvedHolds?.cnt ?? 0);
  if (totalMismatches > 0) {
    await writeAlert(db, 'recon_mismatches', 'warning', {
      open_dispute_forwarding_failed: failedForwarding?.cnt ?? 0,
      resolved_hold_not_released: unresolvedHolds?.cnt ?? 0,
      total: totalMismatches,
    });
    written++;
  }

  return { alerts_written: written };
}

/**
 * Query ops alerts with filtering.
 */
export async function queryOpsAlerts(
  db: D1Database,
  params: { since?: string; severity?: string; limit?: number }
): Promise<OpsAlert[]> {
  const limit = Math.min(params.limit ?? 50, 200);
  const clauses: string[] = [];
  const binds: unknown[] = [];

  if (params.since) {
    clauses.push('created_at >= ?');
    binds.push(params.since);
  }

  if (params.severity && ['info', 'warning', 'critical'].includes(params.severity)) {
    clauses.push('severity = ?');
    binds.push(params.severity);
  }

  const where = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
  const query = `SELECT * FROM ops_alerts ${where} ORDER BY created_at DESC LIMIT ?`;
  binds.push(limit);

  const rows = await db.prepare(query).bind(...binds).all<OpsAlert>();
  return rows.results ?? [];
}

// ---------------------------------------------------------------------------
// Main aggregator
// ---------------------------------------------------------------------------

export async function getEconomyHealth(env: Env): Promise<EconomyHealthReport> {
  const start = Date.now();

  // Fan out: probe all services in parallel
  const [
    ledgerProbe,
    escrowProbe,
    bountiesProbe,
    cutsProbe,
    incomeProbe,
    insureProbe,
    ledgerHolds,
    escrowList,
    settlement,
  ] = await Promise.all([
    // Health probes
    probeHealth(env.LEDGER_BASE_URL),
    probeHealth(env.ESCROW_BASE_URL),
    probeHealth(env.CLAWBOUNTIES_BASE_URL),
    probeHealth(env.CLAWCUTS_BASE_URL),
    probeHealth(env.CLAWINCOME_BASE_URL),
    probeHealth(env.CLAWINSURE_BASE_URL),
    // Ledger: risk holds
    probeService(
      env.LEDGER_BASE_URL,
      '/v1/risk/holds?status=active&limit=1',
      (env.LEDGER_RISK_KEY ?? env.LEDGER_ADMIN_KEY)?.trim()
    ),
    // Escrow: list
    probeService(
      env.ESCROW_BASE_URL,
      '/v1/escrows?status=active&limit=1',
      env.ESCROW_RISK_KEY?.trim()
    ),
    // Local D1 settlement data
    queryLocalSettlement(env.DB),
  ]);

  // Build service health list
  const services: ServiceHealth[] = [
    toServiceHealth('clawsettle', { ok: true, status: 200, latency_ms: 0, data: null }, {
      loss_events_total: settlement.loss_events.total,
      outbox_apply_failed: settlement.outbox.apply.failed,
      outbox_resolve_failed: settlement.outbox.resolve.failed,
      disputes_open: settlement.disputes.total_open,
    }),
    toServiceHealth('ledger', ledgerProbe, {
      risk_holds_active: ledgerHolds.ok && ledgerHolds.data
        ? (Array.isArray((ledgerHolds.data as Record<string, unknown>).holds)
            ? 'available'
            : 'probe_ok')
        : 'probe_failed',
    }),
    toServiceHealth('escrow', escrowProbe, {
      active_escrows: escrowList.ok && escrowList.data
        ? (Array.isArray((escrowList.data as Record<string, unknown>).escrows)
            ? 'available'
            : 'probe_ok')
        : 'probe_failed',
    }),
    toServiceHealth('clawbounties', bountiesProbe),
    toServiceHealth('clawcuts', cutsProbe),
    toServiceHealth('clawincome', incomeProbe),
    toServiceHealth('clawinsure', insureProbe),
  ];

  // Derive alerts
  const alerts = {
    outbox_stale_failures: settlement.outbox.apply.failed > 0 || settlement.outbox.resolve.failed > 0,
    disputes_aging_critical: settlement.disputes.aging_buckets.some(
      b => b.label === '60+d' && b.count > 0
    ),
    recon_mismatches: settlement.recon.mismatch_count > 0,
  };

  // Derive overall status
  const downCount = services.filter(s => s.status === 'down').length;
  const hasActiveAlerts = alerts.outbox_stale_failures || alerts.disputes_aging_critical || alerts.recon_mismatches;

  let overallStatus: OverallStatus = 'healthy';
  if (downCount >= 3 || alerts.disputes_aging_critical) {
    overallStatus = 'unhealthy';
  } else if (downCount > 0 || hasActiveAlerts) {
    overallStatus = 'degraded';
  }

  return {
    generated_at: nowIso(),
    overall_status: overallStatus,
    services,
    settlement,
    alerts,
  };
}
