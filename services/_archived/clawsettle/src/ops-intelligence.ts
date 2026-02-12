/**
 * ECON-OPS-002: Operational intelligence — health snapshots, webhook SLA, threshold alerts.
 */

import type { Env } from './types';
import { getEconomyHealth } from './economy-health';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function nowIso(): string { return new Date().toISOString(); }
function clampInt(v: unknown, min: number, max: number, fallback: number): number {
  const n = typeof v === 'string' ? parseInt(v, 10) : typeof v === 'number' ? v : NaN;
  return Number.isFinite(n) ? Math.max(min, Math.min(max, Math.floor(n))) : fallback;
}

// ---------------------------------------------------------------------------
// Task 1: Health snapshots
// ---------------------------------------------------------------------------

export async function captureHealthSnapshot(env: Env): Promise<{ snapshot_id: string }> {
  const report = await getEconomyHealth(env);
  const id = `snap_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  const servicesUp = report.services.filter(s => s.status === 'up').length;
  const avgLatency = report.services.length > 0
    ? report.services.reduce((s, svc) => s + svc.latency_ms, 0) / report.services.length
    : 0;

  await env.DB.prepare(
    `INSERT INTO ops_health_snapshots
       (snapshot_id, timestamp, overall_status, services_json, services_up, services_total,
        disputes_open, recon_mismatches, outbox_depth_apply, outbox_depth_resolve, avg_latency_ms, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    id, report.generated_at, report.overall_status,
    JSON.stringify(report.services), servicesUp, report.services.length,
    report.settlement.disputes.total_open, report.settlement.recon.mismatch_count,
    report.settlement.outbox.apply.pending + report.settlement.outbox.apply.failed,
    report.settlement.outbox.resolve.pending + report.settlement.outbox.resolve.failed,
    Math.round(avgLatency * 100) / 100, nowIso()
  ).run();

  return { snapshot_id: id };
}

export async function queryHealthHistory(
  db: D1Database,
  hoursBack: number
): Promise<Array<Record<string, unknown>>> {
  const hours = clampInt(hoursBack, 1, 168, 24);
  const since = new Date(Date.now() - hours * 3600000).toISOString();
  const rows = await db.prepare(
    `SELECT snapshot_id, timestamp, overall_status, services_up, services_total,
            disputes_open, recon_mismatches, outbox_depth_apply, outbox_depth_resolve,
            avg_latency_ms
     FROM ops_health_snapshots WHERE timestamp >= ? ORDER BY timestamp DESC LIMIT 500`
  ).bind(since).all();
  return (rows.results ?? []) as Array<Record<string, unknown>>;
}

export async function queryHealthTrends(
  db: D1Database,
  daysBack: number
): Promise<Record<string, unknown>> {
  const days = clampInt(daysBack, 1, 30, 7);
  const since = new Date(Date.now() - days * 86400000).toISOString();

  // Per-service average latency from services_json
  const snapshots = await db.prepare(
    `SELECT services_json, overall_status, timestamp
     FROM ops_health_snapshots WHERE timestamp >= ? ORDER BY timestamp ASC`
  ).bind(since).all<{ services_json: string; overall_status: string; timestamp: string }>();

  const rows = snapshots.results ?? [];
  const serviceLatencies: Record<string, number[]> = {};
  const serviceUp: Record<string, number> = {};
  const serviceTotal: Record<string, number> = {};
  let degradedWindows = 0;
  let unhealthyWindows = 0;
  let prevStatus = '';

  for (const row of rows) {
    if (row.overall_status === 'degraded' && prevStatus !== 'degraded') degradedWindows++;
    if (row.overall_status === 'unhealthy' && prevStatus !== 'unhealthy') unhealthyWindows++;
    prevStatus = row.overall_status;

    try {
      const services = JSON.parse(row.services_json) as Array<{ service: string; latency_ms: number; status: string }>;
      for (const svc of services) {
        if (!serviceLatencies[svc.service]) {
          serviceLatencies[svc.service] = [];
          serviceUp[svc.service] = 0;
          serviceTotal[svc.service] = 0;
        }
        serviceLatencies[svc.service].push(svc.latency_ms);
        serviceTotal[svc.service]++;
        if (svc.status === 'up') serviceUp[svc.service]++;
      }
    } catch { /* skip malformed */ }
  }

  const perService: Record<string, { avg_latency_ms: number; p95_latency_ms: number; uptime_pct: number; samples: number }> = {};
  for (const [name, lats] of Object.entries(serviceLatencies)) {
    const sorted = [...lats].sort((a, b) => a - b);
    const avg = sorted.reduce((s, v) => s + v, 0) / sorted.length;
    const p95 = sorted[Math.floor(sorted.length * 0.95)] ?? 0;
    perService[name] = {
      avg_latency_ms: Math.round(avg * 100) / 100,
      p95_latency_ms: Math.round(p95 * 100) / 100,
      uptime_pct: serviceTotal[name] > 0
        ? Math.round((serviceUp[name] / serviceTotal[name]) * 10000) / 100
        : 0,
      samples: sorted.length,
    };
  }

  return {
    period: { days, since, until: nowIso() },
    total_snapshots: rows.length,
    degradation_windows: degradedWindows,
    unhealthy_windows: unhealthyWindows,
    per_service: perService,
  };
}

// ---------------------------------------------------------------------------
// Task 2: Webhook delivery SLA
// ---------------------------------------------------------------------------

export async function logWebhookDelivery(
  db: D1Database,
  params: {
    event_type: string;
    source: 'stripe' | 'internal' | 'loss_apply' | 'loss_resolve';
    received_at: string;
    processing_ms: number;
    status: 'success' | 'failed' | 'timeout';
    error_code?: string;
    idempotency_key?: string;
  }
): Promise<void> {
  const id = `dlv_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  await db.prepare(
    `INSERT INTO webhook_delivery_log
       (delivery_id, event_type, source, received_at, processed_at, processing_ms, status, error_code, idempotency_key, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    id, params.event_type, params.source, params.received_at,
    nowIso(), params.processing_ms, params.status,
    params.error_code ?? null, params.idempotency_key ?? null, nowIso()
  ).run();
}

export async function queryWebhookSla(
  db: D1Database,
  hoursBack: number
): Promise<Record<string, unknown>> {
  const hours = clampInt(hoursBack, 1, 168, 24);
  const since = new Date(Date.now() - hours * 3600000).toISOString();

  const rows = await db.prepare(
    `SELECT processing_ms, status, error_code, source FROM webhook_delivery_log WHERE received_at >= ? ORDER BY processing_ms ASC`
  ).bind(since).all<{ processing_ms: number; status: string; error_code: string | null; source: string }>();

  const all = rows.results ?? [];
  const successRows = all.filter(r => r.status === 'success');
  const failedRows = all.filter(r => r.status !== 'success');

  const times = successRows.map(r => r.processing_ms).sort((a, b) => a - b);
  const p50 = times[Math.floor(times.length * 0.50)] ?? 0;
  const p95 = times[Math.floor(times.length * 0.95)] ?? 0;
  const p99 = times[Math.floor(times.length * 0.99)] ?? 0;

  const failuresByCode: Record<string, number> = {};
  for (const r of failedRows) {
    const code = r.error_code ?? 'unknown';
    failuresByCode[code] = (failuresByCode[code] ?? 0) + 1;
  }

  const bySource: Record<string, { total: number; success: number; failed: number }> = {};
  for (const r of all) {
    if (!bySource[r.source]) bySource[r.source] = { total: 0, success: 0, failed: 0 };
    bySource[r.source].total++;
    if (r.status === 'success') bySource[r.source].success++;
    else bySource[r.source].failed++;
  }

  return {
    period: { hours, since, until: nowIso() },
    total_deliveries: all.length,
    success_count: successRows.length,
    failure_count: failedRows.length,
    success_rate_pct: all.length > 0 ? Math.round((successRows.length / all.length) * 10000) / 100 : 100,
    processing_ms: { p50, p95, p99 },
    failures_by_code: failuresByCode,
    by_source: bySource,
  };
}

export async function queryWebhookFailures(
  db: D1Database,
  since: string,
  limit = 50
): Promise<Array<Record<string, unknown>>> {
  const rows = await db.prepare(
    `SELECT * FROM webhook_delivery_log WHERE status != 'success' AND received_at >= ? ORDER BY received_at DESC LIMIT ?`
  ).bind(since, Math.min(limit, 200)).all();
  return (rows.results ?? []) as Array<Record<string, unknown>>;
}

// ---------------------------------------------------------------------------
// Task 3: Threshold-based alert rules
// ---------------------------------------------------------------------------

interface AlertRule {
  rule_id: string;
  name: string;
  severity: 'info' | 'warning' | 'critical';
  evaluate: (ctx: AlertEvalContext) => { firing: boolean; details: Record<string, unknown> };
}

interface AlertEvalContext {
  latestSnapshot: Record<string, unknown> | null;
  webhookSla: Record<string, unknown>;
  consecutiveDown: Record<string, number>;
}

const ALERT_RULES: AlertRule[] = [
  {
    rule_id: 'webhook_p99_high',
    name: 'Webhook P99 > 5000ms',
    severity: 'warning',
    evaluate: (ctx) => {
      const p99 = (ctx.webhookSla as any)?.processing_ms?.p99 ?? 0;
      return { firing: p99 > 5000, details: { p99, threshold: 5000 } };
    },
  },
  {
    rule_id: 'webhook_success_low',
    name: 'Webhook success rate < 99%',
    severity: 'critical',
    evaluate: (ctx) => {
      const rate = (ctx.webhookSla as any)?.success_rate_pct ?? 100;
      const total = (ctx.webhookSla as any)?.total_deliveries ?? 0;
      return { firing: total >= 10 && rate < 99, details: { success_rate_pct: rate, total, threshold: 99 } };
    },
  },
  {
    rule_id: 'recon_mismatches',
    name: 'Reconciliation mismatches > 0',
    severity: 'warning',
    evaluate: (ctx) => {
      const count = Number(ctx.latestSnapshot?.recon_mismatches ?? 0);
      return { firing: count > 0, details: { mismatch_count: count } };
    },
  },
  {
    rule_id: 'outbox_depth_high',
    name: 'Outbox depth > 10',
    severity: 'warning',
    evaluate: (ctx) => {
      const apply = Number(ctx.latestSnapshot?.outbox_depth_apply ?? 0);
      const resolve = Number(ctx.latestSnapshot?.outbox_depth_resolve ?? 0);
      const total = apply + resolve;
      return { firing: total > 10, details: { apply, resolve, total, threshold: 10 } };
    },
  },
  {
    rule_id: 'service_consecutive_down',
    name: 'Service down > 2 consecutive snapshots',
    severity: 'critical',
    evaluate: (ctx) => {
      const down = Object.entries(ctx.consecutiveDown).filter(([, c]) => c > 2);
      return {
        firing: down.length > 0,
        details: { services_down: Object.fromEntries(down), threshold: 2 },
      };
    },
  },
];

export async function evaluateAlertRules(env: Env): Promise<{ alerts_written: number; rules_evaluated: number; firing: string[] }> {
  const db = env.DB;

  // Get latest 3 snapshots for consecutive-down detection
  const recentSnaps = await db.prepare(
    `SELECT services_json FROM ops_health_snapshots ORDER BY timestamp DESC LIMIT 3`
  ).all<{ services_json: string }>();

  const latestSnap = await db.prepare(
    `SELECT * FROM ops_health_snapshots ORDER BY timestamp DESC LIMIT 1`
  ).first<Record<string, unknown>>();

  // Build consecutive-down map
  const consecutiveDown: Record<string, number> = {};
  for (const snap of (recentSnaps.results ?? []).reverse()) {
    try {
      const svcs = JSON.parse(snap.services_json) as Array<{ service: string; status: string }>;
      for (const s of svcs) {
        if (s.status === 'down') consecutiveDown[s.service] = (consecutiveDown[s.service] ?? 0) + 1;
        else consecutiveDown[s.service] = 0;
      }
    } catch { /* skip */ }
  }

  // Get webhook SLA for last hour
  const webhookSla = await queryWebhookSla(db, 1);

  const ctx: AlertEvalContext = { latestSnapshot: latestSnap ?? null, webhookSla, consecutiveDown };

  let written = 0;
  const firing: string[] = [];

  for (const rule of ALERT_RULES) {
    const result = rule.evaluate(ctx);
    if (result.firing) {
      firing.push(rule.rule_id);
      // Check if this rule already has an active alert (don't spam)
      const existing = await db.prepare(
        `SELECT id FROM ops_alerts WHERE rule_id = ? AND is_active = 1 LIMIT 1`
      ).bind(rule.rule_id).first<{ id: string }>();

      if (!existing) {
        const id = `alert_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
        await db.prepare(
          `INSERT INTO ops_alerts (id, alert_type, severity, details_json, created_at, rule_id, threshold_config_json, is_active)
           VALUES (?, ?, ?, ?, ?, ?, ?, 1)`
        ).bind(
          id, rule.name, rule.severity, JSON.stringify(result.details),
          nowIso(), rule.rule_id, JSON.stringify({ rule_id: rule.rule_id, name: rule.name })
        ).run();
        written++;
      }
    } else {
      // Auto-resolve if no longer firing
      await db.prepare(
        `UPDATE ops_alerts SET is_active = 0, resolved_at = ? WHERE rule_id = ? AND is_active = 1`
      ).bind(nowIso(), rule.rule_id).run();
    }
  }

  return { alerts_written: written, rules_evaluated: ALERT_RULES.length, firing };
}

export async function queryActiveAlerts(
  db: D1Database
): Promise<Array<Record<string, unknown>>> {
  const rows = await db.prepare(
    `SELECT id, alert_type, severity, rule_id, details_json, threshold_config_json, created_at
     FROM ops_alerts WHERE is_active = 1 ORDER BY created_at DESC LIMIT 100`
  ).all();
  return (rows.results ?? []) as Array<Record<string, unknown>>;
}
