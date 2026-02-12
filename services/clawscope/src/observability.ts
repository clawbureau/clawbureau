export interface ScopeObservabilityEvent {
  event_id: string;
  event_type:
    | 'token_issue'
    | 'token_revoke'
    | 'token_introspect'
    | 'token_matrix'
    | 'token_issue_denied'
    | 'token_introspect_denied';
  service: 'clawscope';
  route: string;
  method: string;
  status_code: number;
  duration_ms: number;
  token_hash?: string;
  mission_id?: string;
  scope_count?: number;
  scope_prefixes?: string[];
  trace_id: string;
  correlation_id?: string;
  details?: Record<string, unknown>;
  created_at: number;
}

interface ScopeAlertRule {
  rule_id: string;
  metric_name: 'error_rate_percent' | 'p95_latency_ms' | 'request_count';
  comparison: 'gt' | 'gte';
  threshold: number;
  window_minutes: number;
  service?: string;
  route?: string;
  mission_id?: string;
  active: number;
  created_at: number;
}

interface ScopeObservabilityEnv {
  SCOPE_VERSION: string;
  SCOPE_ADMIN_KEY?: string;
  SCOPE_ADMIN_KEYS_JSON?: string;
  SCOPE_OBSERVABILITY_DB?: D1Database;
  SCOPE_OBS_CACHE?: KVNamespace;
  SCOPE_OBS_EVENTS?: Queue<ScopeObservabilityEvent>;
  SCOPE_METRICS?: AnalyticsEngineDataset;
  SCOPE_REPORTS_BUCKET?: R2Bucket;
  SCOPE_OBS_COORDINATOR?: DurableObjectNamespace;
  SCOPE_ALERT_DEFAULT_ERROR_RATE_PERCENT?: string;
  SCOPE_ALERT_DEFAULT_P95_MS?: string;
  SCOPE_ALERT_DEFAULT_REQUEST_COUNT?: string;
}

function jsonResponse(body: unknown, status = 200, extraHeaders?: HeadersInit): Response {
  const headers = new Headers(extraHeaders);
  headers.set('content-type', 'application/json; charset=utf-8');
  return new Response(JSON.stringify(body, null, 2), { status, headers });
}

function textResponse(body: string, contentType: string, status = 200, extraHeaders?: HeadersInit): Response {
  const headers = new Headers(extraHeaders);
  headers.set('content-type', contentType);
  return new Response(body, { status, headers });
}

function errorResponse(code: string, message: string, status = 400): Response {
  return jsonResponse({ error: code, message }, status);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

function parseIntOrDefault(value: string | undefined, fallback: number): number {
  if (!value) return fallback;
  const n = Number.parseInt(value, 10);
  return Number.isFinite(n) ? n : fallback;
}

function parseNumberOrDefault(value: string | undefined, fallback: number): number {
  if (!value) return fallback;
  const n = Number.parseFloat(value);
  return Number.isFinite(n) ? n : fallback;
}

function getBearerToken(auth: string | null): string | null {
  if (!auth) return null;
  const trimmed = auth.trim();
  if (!trimmed) return null;
  if (trimmed.toLowerCase().startsWith('bearer ')) {
    return trimmed.slice(7).trim();
  }
  return trimmed;
}

function resolveAdminKeys(
  env: ScopeObservabilityEnv
): { ok: true; keys: string[] } | { ok: false; error: Response } {
  const keys = new Set<string>();

  if (isNonEmptyString(env.SCOPE_ADMIN_KEY)) {
    keys.add(env.SCOPE_ADMIN_KEY.trim());
  }

  const additionalRaw = env.SCOPE_ADMIN_KEYS_JSON?.trim();
  if (additionalRaw) {
    try {
      const parsed = JSON.parse(additionalRaw) as unknown;
      if (!Array.isArray(parsed)) {
        return {
          ok: false,
          error: errorResponse('ADMIN_KEY_CONFIG_INVALID', 'SCOPE_ADMIN_KEYS_JSON must be a JSON array', 503),
        };
      }

      for (const raw of parsed) {
        if (!isNonEmptyString(raw)) {
          return {
            ok: false,
            error: errorResponse(
              'ADMIN_KEY_CONFIG_INVALID',
              'SCOPE_ADMIN_KEYS_JSON entries must be non-empty strings',
              503
            ),
          };
        }
        keys.add(raw.trim());
      }
    } catch {
      return {
        ok: false,
        error: errorResponse('ADMIN_KEY_CONFIG_INVALID', 'SCOPE_ADMIN_KEYS_JSON must be valid JSON', 503),
      };
    }
  }

  if (keys.size === 0) {
    return {
      ok: false,
      error: errorResponse(
        'ADMIN_KEY_NOT_CONFIGURED',
        'SCOPE_ADMIN_KEY or SCOPE_ADMIN_KEYS_JSON is required',
        503
      ),
    };
  }

  return { ok: true, keys: Array.from(keys) };
}

function requireAdmin(request: Request, env: ScopeObservabilityEnv): Response | null {
  const resolved = resolveAdminKeys(env);
  if (!resolved.ok) return resolved.error;

  const provided = getBearerToken(request.headers.get('authorization'));
  if (!provided) {
    return errorResponse('UNAUTHORIZED', 'Missing Authorization header', 401);
  }

  if (!resolved.keys.includes(provided)) {
    return errorResponse('UNAUTHORIZED', 'Invalid admin token', 401);
  }

  return null;
}

let schemaInitialized = false;

async function ensureObservabilitySchema(db: D1Database): Promise<void> {
  if (schemaInitialized) return;

  await db.batch([
    db.prepare(`
      CREATE TABLE IF NOT EXISTS scope_observability_events (
        event_id TEXT PRIMARY KEY,
        event_type TEXT NOT NULL,
        service TEXT NOT NULL,
        route TEXT NOT NULL,
        method TEXT NOT NULL,
        status_code INTEGER NOT NULL,
        duration_ms REAL NOT NULL,
        token_hash TEXT,
        mission_id TEXT,
        scope_count INTEGER,
        trace_id TEXT NOT NULL,
        correlation_id TEXT,
        details_json TEXT,
        created_at INTEGER NOT NULL,
        created_at_iso TEXT NOT NULL
      )
    `),
    db.prepare(
      `CREATE INDEX IF NOT EXISTS idx_scope_obs_events_created ON scope_observability_events(created_at DESC)`
    ),
    db.prepare(
      `CREATE INDEX IF NOT EXISTS idx_scope_obs_events_route ON scope_observability_events(route, created_at DESC)`
    ),
    db.prepare(
      `CREATE INDEX IF NOT EXISTS idx_scope_obs_events_mission ON scope_observability_events(mission_id, created_at DESC)`
    ),
    db.prepare(
      `CREATE INDEX IF NOT EXISTS idx_scope_obs_events_trace ON scope_observability_events(trace_id, created_at DESC)`
    ),
    db.prepare(`
      CREATE TABLE IF NOT EXISTS scope_alert_rules (
        rule_id TEXT PRIMARY KEY,
        metric_name TEXT NOT NULL,
        comparison TEXT NOT NULL,
        threshold REAL NOT NULL,
        window_minutes INTEGER NOT NULL,
        service TEXT,
        route TEXT,
        mission_id TEXT,
        active INTEGER NOT NULL DEFAULT 1,
        created_at INTEGER NOT NULL
      )
    `),
    db.prepare(
      `CREATE INDEX IF NOT EXISTS idx_scope_alert_rules_active ON scope_alert_rules(active, created_at DESC)`
    ),
    db.prepare(`
      CREATE TABLE IF NOT EXISTS scope_alert_events (
        alert_event_id TEXT PRIMARY KEY,
        rule_id TEXT NOT NULL,
        metric_name TEXT NOT NULL,
        metric_value REAL NOT NULL,
        comparison TEXT NOT NULL,
        threshold REAL NOT NULL,
        window_start INTEGER NOT NULL,
        window_end INTEGER NOT NULL,
        trace_id TEXT,
        details_json TEXT,
        triggered_at INTEGER NOT NULL
      )
    `),
    db.prepare(
      `CREATE INDEX IF NOT EXISTS idx_scope_alert_events_triggered ON scope_alert_events(triggered_at DESC)`
    ),
    db.prepare(`
      CREATE TABLE IF NOT EXISTS scope_daily_usage_rollups (
        day TEXT NOT NULL,
        service TEXT NOT NULL,
        route TEXT NOT NULL,
        requests INTEGER NOT NULL,
        errors INTEGER NOT NULL,
        avg_latency_ms REAL NOT NULL,
        p95_latency_ms REAL NOT NULL,
        token_issues INTEGER NOT NULL,
        token_revocations INTEGER NOT NULL,
        generated_at INTEGER NOT NULL,
        PRIMARY KEY (day, service, route)
      )
    `),
    db.prepare(`
      CREATE TABLE IF NOT EXISTS scope_daily_cost_rollups (
        day TEXT NOT NULL,
        service TEXT NOT NULL,
        requests INTEGER NOT NULL,
        est_compute_cost_usd REAL NOT NULL,
        est_storage_cost_usd REAL NOT NULL,
        generated_at INTEGER NOT NULL,
        PRIMARY KEY (day, service)
      )
    `),
    db.prepare(`
      CREATE TABLE IF NOT EXISTS scope_daily_mission_rollups (
        day TEXT NOT NULL,
        mission_id TEXT NOT NULL,
        requests INTEGER NOT NULL,
        errors INTEGER NOT NULL,
        token_issues INTEGER NOT NULL,
        avg_latency_ms REAL NOT NULL,
        generated_at INTEGER NOT NULL,
        PRIMARY KEY (day, mission_id)
      )
    `),
    db.prepare(`
      CREATE TABLE IF NOT EXISTS scope_sla_reports (
        day TEXT PRIMARY KEY,
        availability_ratio REAL NOT NULL,
        error_rate REAL NOT NULL,
        p95_latency_ms REAL NOT NULL,
        generated_at INTEGER NOT NULL,
        report_key TEXT
      )
    `),
    db.prepare(`
      CREATE TABLE IF NOT EXISTS scope_trace_index (
        trace_id TEXT PRIMARY KEY,
        correlation_id TEXT,
        route TEXT,
        method TEXT,
        first_seen_at INTEGER NOT NULL,
        last_seen_at INTEGER NOT NULL,
        event_count INTEGER NOT NULL,
        latest_status_code INTEGER NOT NULL
      )
    `),
  ]);

  schemaInitialized = true;
}

function makeEventId(): string {
  return `obs_${crypto.randomUUID()}`;
}

function makeTraceId(request: Request): string {
  const existing = request.headers.get('x-trace-id');
  if (existing && existing.trim().length > 0) return existing.trim();
  return `trc_${crypto.randomUUID()}`;
}

function makeCorrelationId(request: Request): string | undefined {
  const existing = request.headers.get('x-correlation-id');
  if (existing && existing.trim().length > 0) return existing.trim();
  return undefined;
}

function quantile95(values: number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const idx = Math.max(0, Math.min(sorted.length - 1, Math.ceil(sorted.length * 0.95) - 1));
  return Number(sorted[idx] ?? 0);
}

function toCsv(rows: Array<Record<string, unknown>>, columns: string[]): string {
  const escape = (value: unknown): string => {
    if (value === null || value === undefined) return '';
    const s = String(value);
    if (s.includes(',') || s.includes('"') || s.includes('\n')) {
      return `"${s.replace(/"/g, '""')}"`;
    }
    return s;
  };

  const header = columns.join(',');
  const body = rows.map((row) => columns.map((c) => escape(row[c])).join(',')).join('\n');
  return `${header}\n${body}`;
}

function parseRouteScopePrefix(route: string): string {
  if (route.includes('/v1/tokens/issue/canonical')) return 'control:canonical';
  if (route.includes('/v1/tokens/issue')) return 'token:legacy';
  if (route.includes('/v1/tokens/revoke')) return 'token:revoke';
  if (route.includes('/v1/tokens/introspect')) return 'token:introspect';
  return 'other';
}

async function shouldEmitAlertOnce(
  env: ScopeObservabilityEnv,
  dedupeKey: string,
  ttlSeconds: number
): Promise<boolean> {
  if (env.SCOPE_OBS_COORDINATOR) {
    const id = env.SCOPE_OBS_COORDINATOR.idFromName('scope-alert-dedupe');
    const stub = env.SCOPE_OBS_COORDINATOR.get(id);

    const response = await stub.fetch('https://scope-observability.local/dedupe', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ key: dedupeKey, ttl_seconds: ttlSeconds }),
    });

    if (!response.ok) return false;

    const parsed = (await response.json()) as { emit?: boolean };
    return parsed.emit === true;
  }

  if (!env.SCOPE_OBS_CACHE) return true;

  const existing = await env.SCOPE_OBS_CACHE.get(`alert-dedupe:${dedupeKey}`);
  if (existing) return false;

  await env.SCOPE_OBS_CACHE.put(`alert-dedupe:${dedupeKey}`, '1', { expirationTtl: ttlSeconds });
  return true;
}

async function writeAnalyticsPoint(env: ScopeObservabilityEnv, event: ScopeObservabilityEvent): Promise<void> {
  if (!env.SCOPE_METRICS) return;

  env.SCOPE_METRICS.writeDataPoint({
    blobs: [
      event.route,
      event.method,
      String(event.status_code),
      event.event_type,
      parseRouteScopePrefix(event.route),
    ],
    doubles: [
      event.duration_ms,
      1,
      event.status_code >= 400 ? 1 : 0,
    ],
    indexes: [event.correlation_id ?? event.trace_id],
  });
}

async function computeMetricForRule(
  db: D1Database,
  rule: ScopeAlertRule,
  nowSec: number
): Promise<number> {
  const fromSec = nowSec - rule.window_minutes * 60;

  const filters: string[] = ['created_at >= ?'];
  const args: Array<string | number> = [fromSec];

  if (rule.service && rule.service.length > 0) {
    filters.push('service = ?');
    args.push(rule.service);
  }

  if (rule.route && rule.route.length > 0) {
    filters.push('route = ?');
    args.push(rule.route);
  }

  if (rule.mission_id && rule.mission_id.length > 0) {
    filters.push('mission_id = ?');
    args.push(rule.mission_id);
  }

  const where = filters.join(' AND ');

  if (rule.metric_name === 'request_count') {
    const row = await db
      .prepare(`SELECT COUNT(*) AS c FROM scope_observability_events WHERE ${where}`)
      .bind(...args)
      .first<{ c?: number }>();
    return Number(row?.c ?? 0);
  }

  if (rule.metric_name === 'error_rate_percent') {
    const row = await db
      .prepare(
        `
        SELECT
          COUNT(*) AS total,
          SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) AS errors
        FROM scope_observability_events
        WHERE ${where}
      `
      )
      .bind(...args)
      .first<{ total?: number; errors?: number }>();

    const total = Number(row?.total ?? 0);
    const errors = Number(row?.errors ?? 0);
    if (total <= 0) return 0;
    return Number(((errors / total) * 100).toFixed(3));
  }

  // p95_latency_ms
  const rows = await db
    .prepare(`SELECT duration_ms FROM scope_observability_events WHERE ${where} ORDER BY duration_ms ASC`)
    .bind(...args)
    .all<{ duration_ms?: number }>();

  const values = (rows.results ?? [])
    .map((r) => Number(r.duration_ms ?? 0))
    .filter((v) => Number.isFinite(v));

  return quantile95(values);
}

function compareMetric(metric: number, comparison: 'gt' | 'gte', threshold: number): boolean {
  if (comparison === 'gte') return metric >= threshold;
  return metric > threshold;
}

async function evaluateAlertRulesForEvent(
  env: ScopeObservabilityEnv,
  db: D1Database,
  event: ScopeObservabilityEvent
): Promise<void> {
  const activeRules = await db
    .prepare(
      `
      SELECT
        rule_id,
        metric_name,
        comparison,
        threshold,
        window_minutes,
        service,
        route,
        mission_id,
        active,
        created_at
      FROM scope_alert_rules
      WHERE active = 1
      ORDER BY created_at ASC
      `
    )
    .all<ScopeAlertRule>();

  const nowSec = Math.floor(Date.now() / 1000);

  for (const rule of activeRules.results ?? []) {
    const metric = await computeMetricForRule(db, rule, nowSec);
    const tripped = compareMetric(metric, rule.comparison, Number(rule.threshold));
    if (!tripped) continue;

    const windowSec = Math.max(60, rule.window_minutes * 60);
    const bucket = Math.floor(nowSec / windowSec);
    const dedupeKey = `${rule.rule_id}:${bucket}`;

    const emit = await shouldEmitAlertOnce(env, dedupeKey, windowSec);
    if (!emit) continue;

    await db.prepare(
      `
      INSERT INTO scope_alert_events (
        alert_event_id,
        rule_id,
        metric_name,
        metric_value,
        comparison,
        threshold,
        window_start,
        window_end,
        trace_id,
        details_json,
        triggered_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `
    )
      .bind(
        `alert_${crypto.randomUUID()}`,
        rule.rule_id,
        rule.metric_name,
        metric,
        rule.comparison,
        rule.threshold,
        nowSec - windowSec,
        nowSec,
        event.trace_id,
        JSON.stringify({ event_type: event.event_type, route: event.route, status_code: event.status_code }),
        nowSec
      )
      .run();
  }
}

async function persistEventToDb(env: ScopeObservabilityEnv, event: ScopeObservabilityEvent): Promise<void> {
  const db = env.SCOPE_OBSERVABILITY_DB;
  if (!db) return;

  await ensureObservabilitySchema(db);

  const detailsJson = event.details ? JSON.stringify(event.details) : null;

  await db.prepare(
    `
    INSERT OR REPLACE INTO scope_observability_events (
      event_id,
      event_type,
      service,
      route,
      method,
      status_code,
      duration_ms,
      token_hash,
      mission_id,
      scope_count,
      trace_id,
      correlation_id,
      details_json,
      created_at,
      created_at_iso
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `
  )
    .bind(
      event.event_id,
      event.event_type,
      event.service,
      event.route,
      event.method,
      event.status_code,
      event.duration_ms,
      event.token_hash ?? null,
      event.mission_id ?? null,
      event.scope_count ?? null,
      event.trace_id,
      event.correlation_id ?? null,
      detailsJson,
      event.created_at,
      new Date(event.created_at * 1000).toISOString()
    )
    .run();

  await db.prepare(
    `
    INSERT INTO scope_trace_index (
      trace_id,
      correlation_id,
      route,
      method,
      first_seen_at,
      last_seen_at,
      event_count,
      latest_status_code
    ) VALUES (?, ?, ?, ?, ?, ?, 1, ?)
    ON CONFLICT(trace_id) DO UPDATE SET
      correlation_id = excluded.correlation_id,
      route = excluded.route,
      method = excluded.method,
      last_seen_at = excluded.last_seen_at,
      event_count = scope_trace_index.event_count + 1,
      latest_status_code = excluded.latest_status_code
    `
  )
    .bind(
      event.trace_id,
      event.correlation_id ?? null,
      event.route,
      event.method,
      event.created_at,
      event.created_at,
      event.status_code
    )
    .run();

  await evaluateAlertRulesForEvent(env, db, event);
}

export async function emitScopeObservabilityEvent(
  env: ScopeObservabilityEnv,
  event: ScopeObservabilityEvent
): Promise<void> {
  await writeAnalyticsPoint(env, event);

  if (env.SCOPE_OBS_EVENTS) {
    await env.SCOPE_OBS_EVENTS.send(event, { contentType: 'json' });
  } else {
    await persistEventToDb(env, event);
  }

  if (env.SCOPE_OBS_CACHE) {
    await env.SCOPE_OBS_CACHE.put('metrics:last_event', JSON.stringify({
      event_type: event.event_type,
      route: event.route,
      status_code: event.status_code,
      created_at: event.created_at,
      trace_id: event.trace_id,
    }), { expirationTtl: 3600 });
  }
}

export async function processScopeObservabilityQueueBatch(
  batch: MessageBatch<ScopeObservabilityEvent>,
  env: ScopeObservabilityEnv
): Promise<void> {
  for (const message of batch.messages) {
    try {
      await persistEventToDb(env, message.body);
      message.ack();
    } catch {
      message.retry();
    }
  }
}

async function getEventsInWindow(
  db: D1Database,
  fromSec: number,
  service?: string,
  route?: string,
  missionId?: string
): Promise<Array<{ status_code: number; duration_ms: number; event_type: string }>> {
  const filters: string[] = ['created_at >= ?'];
  const args: Array<string | number> = [fromSec];

  if (service && service.length > 0) {
    filters.push('service = ?');
    args.push(service);
  }
  if (route && route.length > 0) {
    filters.push('route = ?');
    args.push(route);
  }
  if (missionId && missionId.length > 0) {
    filters.push('mission_id = ?');
    args.push(missionId);
  }

  const where = filters.join(' AND ');

  const rows = await db
    .prepare(`SELECT status_code, duration_ms, event_type FROM scope_observability_events WHERE ${where}`)
    .bind(...args)
    .all<{ status_code?: number; duration_ms?: number; event_type?: string }>();

  return (rows.results ?? []).map((r) => ({
    status_code: Number(r.status_code ?? 0),
    duration_ms: Number(r.duration_ms ?? 0),
    event_type: String(r.event_type ?? ''),
  }));
}

function computeDashboardFromEvents(events: Array<{ status_code: number; duration_ms: number }>): {
  requests: number;
  errors: number;
  error_rate_percent: number;
  avg_latency_ms: number;
  p95_latency_ms: number;
} {
  const requests = events.length;
  const errors = events.filter((e) => e.status_code >= 400).length;
  const durations = events.map((e) => e.duration_ms).filter((d) => Number.isFinite(d));
  const avg = durations.length > 0 ? durations.reduce((a, b) => a + b, 0) / durations.length : 0;
  const p95 = quantile95(durations);

  return {
    requests,
    errors,
    error_rate_percent: requests > 0 ? Number(((errors / requests) * 100).toFixed(3)) : 0,
    avg_latency_ms: Number(avg.toFixed(3)),
    p95_latency_ms: Number(p95.toFixed(3)),
  };
}

async function computePerRouteRows(db: D1Database, fromSec: number): Promise<Array<Record<string, unknown>>> {
  const rows = await db
    .prepare(
      `
      SELECT route, COUNT(*) AS requests,
             SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) AS errors,
             AVG(duration_ms) AS avg_latency_ms
      FROM scope_observability_events
      WHERE created_at >= ?
      GROUP BY route
      ORDER BY requests DESC
      LIMIT 50
      `
    )
    .bind(fromSec)
    .all<Record<string, unknown>>();

  return rows.results ?? [];
}

async function runRollupForDay(
  db: D1Database,
  day: string,
  generatedAt: number
): Promise<{
  usageRows: number;
  missionRows: number;
  costRows: number;
  sla: { availability_ratio: number; error_rate: number; p95_latency_ms: number };
}> {
  const startSec = Math.floor(Date.parse(`${day}T00:00:00Z`) / 1000);
  const endSec = startSec + 86400;

  const eventsRows = await db
    .prepare(
      `
      SELECT service, route, status_code, duration_ms, event_type, mission_id
      FROM scope_observability_events
      WHERE created_at >= ? AND created_at < ?
      `
    )
    .bind(startSec, endSec)
    .all<{
      service?: string;
      route?: string;
      status_code?: number;
      duration_ms?: number;
      event_type?: string;
      mission_id?: string | null;
    }>();

  const events = eventsRows.results ?? [];

  const usageMap = new Map<string, {
    service: string;
    route: string;
    requests: number;
    errors: number;
    latencies: number[];
    tokenIssues: number;
    tokenRevokes: number;
  }>();

  const missionMap = new Map<string, {
    mission_id: string;
    requests: number;
    errors: number;
    tokenIssues: number;
    latencies: number[];
  }>();

  for (const row of events) {
    const service = String(row.service ?? 'clawscope');
    const route = String(row.route ?? 'unknown');
    const statusCode = Number(row.status_code ?? 0);
    const duration = Number(row.duration_ms ?? 0);
    const eventType = String(row.event_type ?? '');

    const usageKey = `${service}::${route}`;
    const usage = usageMap.get(usageKey) ?? {
      service,
      route,
      requests: 0,
      errors: 0,
      latencies: [],
      tokenIssues: 0,
      tokenRevokes: 0,
    };

    usage.requests += 1;
    if (statusCode >= 400) usage.errors += 1;
    if (Number.isFinite(duration)) usage.latencies.push(duration);
    if (eventType === 'token_issue') usage.tokenIssues += 1;
    if (eventType === 'token_revoke') usage.tokenRevokes += 1;
    usageMap.set(usageKey, usage);

    if (isNonEmptyString(row.mission_id)) {
      const missionId = row.mission_id;
      const mission = missionMap.get(missionId) ?? {
        mission_id: missionId,
        requests: 0,
        errors: 0,
        tokenIssues: 0,
        latencies: [],
      };
      mission.requests += 1;
      if (statusCode >= 400) mission.errors += 1;
      if (eventType === 'token_issue') mission.tokenIssues += 1;
      if (Number.isFinite(duration)) mission.latencies.push(duration);
      missionMap.set(missionId, mission);
    }
  }

  for (const usage of usageMap.values()) {
    const avg = usage.latencies.length > 0 ? usage.latencies.reduce((a, b) => a + b, 0) / usage.latencies.length : 0;
    const p95 = quantile95(usage.latencies);

    await db.prepare(
      `
      INSERT INTO scope_daily_usage_rollups (
        day, service, route, requests, errors, avg_latency_ms, p95_latency_ms,
        token_issues, token_revocations, generated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(day, service, route) DO UPDATE SET
        requests = excluded.requests,
        errors = excluded.errors,
        avg_latency_ms = excluded.avg_latency_ms,
        p95_latency_ms = excluded.p95_latency_ms,
        token_issues = excluded.token_issues,
        token_revocations = excluded.token_revocations,
        generated_at = excluded.generated_at
      `
    )
      .bind(
        day,
        usage.service,
        usage.route,
        usage.requests,
        usage.errors,
        Number(avg.toFixed(3)),
        Number(p95.toFixed(3)),
        usage.tokenIssues,
        usage.tokenRevokes,
        generatedAt
      )
      .run();
  }

  for (const mission of missionMap.values()) {
    const avg = mission.latencies.length > 0 ? mission.latencies.reduce((a, b) => a + b, 0) / mission.latencies.length : 0;

    await db.prepare(
      `
      INSERT INTO scope_daily_mission_rollups (
        day, mission_id, requests, errors, token_issues, avg_latency_ms, generated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(day, mission_id) DO UPDATE SET
        requests = excluded.requests,
        errors = excluded.errors,
        token_issues = excluded.token_issues,
        avg_latency_ms = excluded.avg_latency_ms,
        generated_at = excluded.generated_at
      `
    )
      .bind(
        day,
        mission.mission_id,
        mission.requests,
        mission.errors,
        mission.tokenIssues,
        Number(avg.toFixed(3)),
        generatedAt
      )
      .run();
  }

  const perService = new Map<string, { requests: number }>();
  for (const usage of usageMap.values()) {
    const acc = perService.get(usage.service) ?? { requests: 0 };
    acc.requests += usage.requests;
    perService.set(usage.service, acc);
  }

  for (const [service, values] of perService.entries()) {
    const reqCount = values.requests;
    const estCompute = Number((reqCount * 0.0000012).toFixed(6));
    const estStorage = Number((reqCount * 0.0000002).toFixed(6));

    await db.prepare(
      `
      INSERT INTO scope_daily_cost_rollups (
        day, service, requests, est_compute_cost_usd, est_storage_cost_usd, generated_at
      ) VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(day, service) DO UPDATE SET
        requests = excluded.requests,
        est_compute_cost_usd = excluded.est_compute_cost_usd,
        est_storage_cost_usd = excluded.est_storage_cost_usd,
        generated_at = excluded.generated_at
      `
    )
      .bind(day, service, reqCount, estCompute, estStorage, generatedAt)
      .run();
  }

  const allStatuses = events.map((e) => Number(e.status_code ?? 0));
  const durations = events.map((e) => Number(e.duration_ms ?? 0)).filter((d) => Number.isFinite(d));
  const totalRequests = events.length;
  const totalErrors = allStatuses.filter((s) => s >= 400).length;
  const availability = totalRequests > 0 ? Number(((totalRequests - totalErrors) / totalRequests).toFixed(6)) : 1;
  const errorRate = totalRequests > 0 ? Number((totalErrors / totalRequests).toFixed(6)) : 0;
  const p95 = Number(quantile95(durations).toFixed(3));

  await db.prepare(
    `
    INSERT INTO scope_sla_reports (
      day, availability_ratio, error_rate, p95_latency_ms, generated_at, report_key
    ) VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(day) DO UPDATE SET
      availability_ratio = excluded.availability_ratio,
      error_rate = excluded.error_rate,
      p95_latency_ms = excluded.p95_latency_ms,
      generated_at = excluded.generated_at,
      report_key = excluded.report_key
    `
  )
    .bind(day, availability, errorRate, p95, generatedAt, null)
    .run();

  return {
    usageRows: usageMap.size,
    missionRows: missionMap.size,
    costRows: perService.size,
    sla: {
      availability_ratio: availability,
      error_rate: errorRate,
      p95_latency_ms: p95,
    },
  };
}

export async function runScopeObservabilityScheduled(
  env: ScopeObservabilityEnv,
  cron: string,
  scheduledTime: number
): Promise<void> {
  const db = env.SCOPE_OBSERVABILITY_DB;
  if (!db) return;

  await ensureObservabilitySchema(db);

  const ts = new Date(scheduledTime);
  const day = new Date(Date.UTC(ts.getUTCFullYear(), ts.getUTCMonth(), ts.getUTCDate() - 1))
    .toISOString()
    .slice(0, 10);

  const generatedAt = Math.floor(Date.now() / 1000);
  const rollup = await runRollupForDay(db, day, generatedAt);

  if (env.SCOPE_REPORTS_BUCKET) {
    const report = {
      generated_at: new Date(generatedAt * 1000).toISOString(),
      cron,
      day,
      rollup,
    };

    const key = `scheduled-rollups/${day}.json`;
    await env.SCOPE_REPORTS_BUCKET.put(key, JSON.stringify(report, null, 2), {
      httpMetadata: { contentType: 'application/json' },
    });

    await db.prepare(
      `UPDATE scope_sla_reports SET report_key = ? WHERE day = ?`
    )
      .bind(key, day)
      .run();
  }

  if (env.SCOPE_OBS_CACHE) {
    await env.SCOPE_OBS_CACHE.put(
      'rollup:last',
      JSON.stringify({ day, generated_at: generatedAt, rollup }),
      { expirationTtl: 86400 * 7 }
    );
  }
}

export async function handleScopeObservabilityRoutes(
  request: Request,
  env: ScopeObservabilityEnv
): Promise<Response | null> {
  const url = new URL(request.url);
  const method = request.method.toUpperCase();

  if (url.pathname.startsWith('/v1/metrics') ||
      url.pathname.startsWith('/v1/reports') ||
      url.pathname.startsWith('/v1/alerts') ||
      url.pathname.startsWith('/v1/analytics') ||
      url.pathname.startsWith('/v1/traces') ||
      url.pathname.startsWith('/v1/missions')) {
    const adminErr = requireAdmin(request, env);
    if (adminErr) return adminErr;

    if (!env.SCOPE_OBSERVABILITY_DB) {
      return errorResponse('OBSERVABILITY_NOT_CONFIGURED', 'SCOPE_OBSERVABILITY_DB is not configured', 503);
    }

    await ensureObservabilitySchema(env.SCOPE_OBSERVABILITY_DB);
  }

  // CSC-US-007 metrics dashboard
  if (method === 'GET' && url.pathname === '/v1/metrics/dashboard') {
    const windowMinutes = Math.min(Math.max(parseIntOrDefault(url.searchParams.get('window_minutes') ?? undefined, 60), 1), 24 * 60);
    const fromSec = Math.floor(Date.now() / 1000) - windowMinutes * 60;

    const events = await getEventsInWindow(env.SCOPE_OBSERVABILITY_DB!, fromSec);
    const overall = computeDashboardFromEvents(events);
    const perRoute = await computePerRouteRows(env.SCOPE_OBSERVABILITY_DB!, fromSec);

    const body = {
      status: 'ok',
      window_minutes: windowMinutes,
      overall,
      per_route: perRoute,
      generated_at: new Date().toISOString(),
    };

    if (env.SCOPE_OBS_CACHE) {
      await env.SCOPE_OBS_CACHE.put('dashboard:last', JSON.stringify(body), { expirationTtl: 90 });
    }

    return jsonResponse(body);
  }

  if (method === 'POST' && url.pathname === '/v1/reports/rollups/run') {
    const body = await request.json().catch(() => null);
    const b = body && typeof body === 'object' ? (body as Record<string, unknown>) : null;
    const requestedDay = b && typeof b.day === 'string' ? b.day.trim() : '';

    const now = new Date();
    const defaultDay = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()))
      .toISOString()
      .slice(0, 10);

    const day = requestedDay || defaultDay;
    if (!/^\d{4}-\d{2}-\d{2}$/.test(day)) {
      return errorResponse('INVALID_DAY', 'day must be YYYY-MM-DD', 400);
    }

    const generatedAt = Math.floor(Date.now() / 1000);
    const rollup = await runRollupForDay(env.SCOPE_OBSERVABILITY_DB!, day, generatedAt);

    if (env.SCOPE_REPORTS_BUCKET) {
      const key = `manual-rollups/${day}-${generatedAt}.json`;
      await env.SCOPE_REPORTS_BUCKET.put(
        key,
        JSON.stringify(
          {
            generated_at: new Date(generatedAt * 1000).toISOString(),
            day,
            rollup,
          },
          null,
          2
        ),
        { httpMetadata: { contentType: 'application/json' } }
      );
    }

    return jsonResponse({ status: 'ok', day, rollup, generated_at: generatedAt });
  }

  // CSC-US-008 usage reports (+ CSV export)
  if (method === 'GET' && url.pathname === '/v1/reports/usage') {
    const fromDay = (url.searchParams.get('from_day') ?? '').trim();
    const toDay = (url.searchParams.get('to_day') ?? '').trim();
    const format = (url.searchParams.get('format') ?? 'json').trim().toLowerCase();

    const where: string[] = [];
    const args: Array<string | number> = [];

    if (fromDay) {
      where.push('day >= ?');
      args.push(fromDay);
    }
    if (toDay) {
      where.push('day <= ?');
      args.push(toDay);
    }

    const rows = await env.SCOPE_OBSERVABILITY_DB!
      .prepare(
        `
        SELECT day, service, route, requests, errors, avg_latency_ms, p95_latency_ms,
               token_issues, token_revocations, generated_at
        FROM scope_daily_usage_rollups
        ${where.length > 0 ? `WHERE ${where.join(' AND ')}` : ''}
        ORDER BY day DESC, service ASC, route ASC
        LIMIT 5000
      `
      )
      .bind(...args)
      .all<Record<string, unknown>>();

    const data = rows.results ?? [];

    if (format === 'csv') {
      const csv = toCsv(data, [
        'day',
        'service',
        'route',
        'requests',
        'errors',
        'avg_latency_ms',
        'p95_latency_ms',
        'token_issues',
        'token_revocations',
        'generated_at',
      ]);

      let reportKey: string | null = null;
      if (env.SCOPE_REPORTS_BUCKET) {
        reportKey = `usage/usage-${new Date().toISOString().replace(/[:.]/g, '-')}.csv`;
        await env.SCOPE_REPORTS_BUCKET.put(reportKey, csv, {
          httpMetadata: { contentType: 'text/csv; charset=utf-8' },
        });
      }

      return textResponse(csv, 'text/csv; charset=utf-8', 200, reportKey ? { 'x-report-key': reportKey } : undefined);
    }

    return jsonResponse({ status: 'ok', rows: data, count: data.length });
  }

  // CSC-US-009 alerting rules + events
  if (method === 'POST' && url.pathname === '/v1/alerts/rules') {
    const body = await request.json().catch(() => null);
    if (!body || typeof body !== 'object') {
      return errorResponse('INVALID_JSON', 'Request body must be valid JSON', 400);
    }

    const b = body as Record<string, unknown>;

    const metricName =
      typeof b.metric_name === 'string' ? b.metric_name.trim() : '';
    const comparison = typeof b.comparison === 'string' ? b.comparison.trim() : '';
    const threshold = typeof b.threshold === 'number' && Number.isFinite(b.threshold) ? b.threshold : NaN;
    const windowMinutes =
      typeof b.window_minutes === 'number' && Number.isFinite(b.window_minutes)
        ? Math.floor(b.window_minutes)
        : 5;

    if (
      metricName !== 'error_rate_percent' &&
      metricName !== 'p95_latency_ms' &&
      metricName !== 'request_count'
    ) {
      return errorResponse(
        'INVALID_ALERT_METRIC',
        'metric_name must be one of error_rate_percent, p95_latency_ms, request_count',
        400
      );
    }

    if (comparison !== 'gt' && comparison !== 'gte') {
      return errorResponse('INVALID_ALERT_COMPARISON', 'comparison must be gt or gte', 400);
    }

    if (!Number.isFinite(threshold) || threshold < 0) {
      return errorResponse('INVALID_ALERT_THRESHOLD', 'threshold must be a non-negative number', 400);
    }

    if (windowMinutes < 1 || windowMinutes > 24 * 60) {
      return errorResponse('INVALID_ALERT_WINDOW', 'window_minutes must be between 1 and 1440', 400);
    }

    const service = typeof b.service === 'string' ? b.service.trim() : '';
    const route = typeof b.route === 'string' ? b.route.trim() : '';
    const missionId = typeof b.mission_id === 'string' ? b.mission_id.trim() : '';

    const nowSec = Math.floor(Date.now() / 1000);
    const ruleId = `rule_${crypto.randomUUID()}`;

    await env.SCOPE_OBSERVABILITY_DB!
      .prepare(
        `
        INSERT INTO scope_alert_rules (
          rule_id,
          metric_name,
          comparison,
          threshold,
          window_minutes,
          service,
          route,
          mission_id,
          active,
          created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
      `
      )
      .bind(
        ruleId,
        metricName,
        comparison,
        threshold,
        windowMinutes,
        service || null,
        route || null,
        missionId || null,
        nowSec
      )
      .run();

    return jsonResponse({
      status: 'created',
      rule: {
        rule_id: ruleId,
        metric_name: metricName,
        comparison,
        threshold,
        window_minutes: windowMinutes,
        service: service || null,
        route: route || null,
        mission_id: missionId || null,
      },
    }, 201);
  }

  if (method === 'GET' && url.pathname === '/v1/alerts/events') {
    const limit = Math.min(Math.max(parseIntOrDefault(url.searchParams.get('limit') ?? undefined, 100), 1), 1000);

    const rows = await env.SCOPE_OBSERVABILITY_DB!
      .prepare(
        `
        SELECT
          alert_event_id,
          rule_id,
          metric_name,
          metric_value,
          comparison,
          threshold,
          window_start,
          window_end,
          trace_id,
          details_json,
          triggered_at
        FROM scope_alert_events
        ORDER BY triggered_at DESC
        LIMIT ?
      `
      )
      .bind(limit)
      .all<Record<string, unknown>>();

    const events = (rows.results ?? []).map((row) => {
      let details: unknown = null;
      if (typeof row.details_json === 'string') {
        try {
          details = JSON.parse(row.details_json);
        } catch {
          details = row.details_json;
        }
      }

      return {
        ...row,
        details,
      };
    });

    return jsonResponse({ status: 'ok', events });
  }

  // CSC-US-010 cost analytics
  if (method === 'GET' && url.pathname === '/v1/analytics/cost') {
    const rows = await env.SCOPE_OBSERVABILITY_DB!
      .prepare(
        `
        SELECT day, service, requests, est_compute_cost_usd, est_storage_cost_usd, generated_at
        FROM scope_daily_cost_rollups
        ORDER BY day DESC, service ASC
        LIMIT 365
      `
      )
      .all<Record<string, unknown>>();

    const data = rows.results ?? [];
    const totals = data.reduce<{ requests: number; compute_usd: number; storage_usd: number }>(
      (acc, row) => {
        acc.requests += Number(row.requests ?? 0);
        acc.compute_usd += Number(row.est_compute_cost_usd ?? 0);
        acc.storage_usd += Number(row.est_storage_cost_usd ?? 0);
        return acc;
      },
      { requests: 0, compute_usd: 0, storage_usd: 0 }
    );

    return jsonResponse({
      status: 'ok',
      totals: {
        requests: totals.requests,
        compute_usd: Number(totals.compute_usd.toFixed(6)),
        storage_usd: Number(totals.storage_usd.toFixed(6)),
        total_usd: Number((totals.compute_usd + totals.storage_usd).toFixed(6)),
      },
      rows: data,
    });
  }

  // CSC-US-011 trace viewer
  const tracePath = /^\/v1\/traces\/([^/]+)$/.exec(url.pathname);
  if (method === 'GET' && tracePath) {
    const traceId = decodeURIComponent(tracePath[1] ?? '').trim();
    if (!traceId) return errorResponse('INVALID_TRACE_ID', 'trace_id is required', 400);

    const traceMeta = await env.SCOPE_OBSERVABILITY_DB!
      .prepare(
        `
        SELECT trace_id, correlation_id, route, method, first_seen_at, last_seen_at, event_count, latest_status_code
        FROM scope_trace_index
        WHERE trace_id = ?
      `
      )
      .bind(traceId)
      .first<Record<string, unknown>>();

    if (!traceMeta) {
      return errorResponse('TRACE_NOT_FOUND', 'trace_id not found', 404);
    }

    const events = await env.SCOPE_OBSERVABILITY_DB!
      .prepare(
        `
        SELECT event_id, event_type, route, method, status_code, duration_ms, token_hash, mission_id,
               details_json, created_at, created_at_iso
        FROM scope_observability_events
        WHERE trace_id = ?
        ORDER BY created_at ASC
        LIMIT 500
      `
      )
      .bind(traceId)
      .all<Record<string, unknown>>();

    return jsonResponse({
      status: 'ok',
      trace: traceMeta,
      events: events.results ?? [],
    });
  }

  if (method === 'GET' && url.pathname === '/v1/traces') {
    const correlationId = (url.searchParams.get('correlation_id') ?? '').trim();
    if (!correlationId) {
      return errorResponse('INVALID_REQUEST', 'correlation_id query parameter is required', 400);
    }

    const rows = await env.SCOPE_OBSERVABILITY_DB!
      .prepare(
        `
        SELECT trace_id, correlation_id, route, method, first_seen_at, last_seen_at, event_count, latest_status_code
        FROM scope_trace_index
        WHERE correlation_id = ?
        ORDER BY last_seen_at DESC
        LIMIT 200
      `
      )
      .bind(correlationId)
      .all();

    return jsonResponse({
      status: 'ok',
      correlation_id: correlationId,
      traces: rows.results ?? [],
    });
  }

  // CSC-US-012 SLA reports
  if (method === 'GET' && url.pathname === '/v1/reports/sla') {
    const day = (url.searchParams.get('day') ?? '').trim();

    if (day) {
      const row = await env.SCOPE_OBSERVABILITY_DB!
        .prepare(
          `
          SELECT day, availability_ratio, error_rate, p95_latency_ms, generated_at, report_key
          FROM scope_sla_reports
          WHERE day = ?
        `
        )
        .bind(day)
        .first<Record<string, unknown>>();

      if (!row) {
        return errorResponse('SLA_REPORT_NOT_FOUND', 'No SLA report found for day', 404);
      }

      return jsonResponse({ status: 'ok', report: row });
    }

    const rows = await env.SCOPE_OBSERVABILITY_DB!
      .prepare(
        `
        SELECT day, availability_ratio, error_rate, p95_latency_ms, generated_at, report_key
        FROM scope_sla_reports
        ORDER BY day DESC
        LIMIT 365
      `
      )
      .all();

    return jsonResponse({ status: 'ok', reports: rows.results ?? [] });
  }

  // CSC-US-013 mission aggregation
  if (method === 'GET' && url.pathname === '/v1/missions/aggregate') {
    const fromDay = (url.searchParams.get('from_day') ?? '').trim();
    const toDay = (url.searchParams.get('to_day') ?? '').trim();

    const where: string[] = [];
    const args: Array<string | number> = [];

    if (fromDay) {
      where.push('day >= ?');
      args.push(fromDay);
    }
    if (toDay) {
      where.push('day <= ?');
      args.push(toDay);
    }

    const rows = await env.SCOPE_OBSERVABILITY_DB!
      .prepare(
        `
        SELECT day, mission_id, requests, errors, token_issues, avg_latency_ms, generated_at
        FROM scope_daily_mission_rollups
        ${where.length > 0 ? `WHERE ${where.join(' AND ')}` : ''}
        ORDER BY day DESC, mission_id ASC
        LIMIT 5000
      `
      )
      .bind(...args)
      .all<Record<string, unknown>>();

    const grouped = new Map<string, {
      mission_id: string;
      requests: number;
      errors: number;
      token_issues: number;
      avg_latency_weighted_sum: number;
      weight: number;
    }>();

    for (const row of rows.results ?? []) {
      const missionId = String(row.mission_id ?? '');
      if (!missionId) continue;

      const requests = Number(row.requests ?? 0);
      const errors = Number(row.errors ?? 0);
      const tokenIssues = Number(row.token_issues ?? 0);
      const avgLatency = Number(row.avg_latency_ms ?? 0);

      const acc = grouped.get(missionId) ?? {
        mission_id: missionId,
        requests: 0,
        errors: 0,
        token_issues: 0,
        avg_latency_weighted_sum: 0,
        weight: 0,
      };

      acc.requests += requests;
      acc.errors += errors;
      acc.token_issues += tokenIssues;
      acc.avg_latency_weighted_sum += avgLatency * requests;
      acc.weight += requests;
      grouped.set(missionId, acc);
    }

    const missions = Array.from(grouped.values())
      .map((m) => ({
        mission_id: m.mission_id,
        requests: m.requests,
        errors: m.errors,
        token_issues: m.token_issues,
        error_rate_percent: m.requests > 0 ? Number(((m.errors / m.requests) * 100).toFixed(3)) : 0,
        avg_latency_ms: m.weight > 0 ? Number((m.avg_latency_weighted_sum / m.weight).toFixed(3)) : 0,
      }))
      .sort((a, b) => b.requests - a.requests);

    return jsonResponse({
      status: 'ok',
      missions,
      rows: rows.results ?? [],
    });
  }

  return null;
}

export function makeScopeEventFromResponse(input: {
  request: Request;
  route: string;
  started_at_ms: number;
  status_code: number;
  event_type: ScopeObservabilityEvent['event_type'];
  token_hash?: string;
  mission_id?: string;
  scope_count?: number;
  details?: Record<string, unknown>;
}): ScopeObservabilityEvent {
  const nowSec = Math.floor(Date.now() / 1000);
  return {
    event_id: makeEventId(),
    event_type: input.event_type,
    service: 'clawscope',
    route: input.route,
    method: input.request.method.toUpperCase(),
    status_code: input.status_code,
    duration_ms: Date.now() - input.started_at_ms,
    token_hash: input.token_hash,
    mission_id: input.mission_id,
    scope_count: input.scope_count,
    scope_prefixes: [parseRouteScopePrefix(input.route)],
    trace_id: makeTraceId(input.request),
    correlation_id: makeCorrelationId(input.request),
    details: input.details,
    created_at: nowSec,
  };
}

export class ScopeObservabilityCoordinator {
  private readonly state: DurableObjectState;

  constructor(state: DurableObjectState, _env: unknown) {
    this.state = state;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (request.method !== 'POST' || url.pathname !== '/dedupe') {
      return jsonResponse({ ok: false, error: 'not found' }, 404);
    }

    const body = await request.json().catch(() => null);
    if (!body || typeof body !== 'object') {
      return jsonResponse({ ok: false, error: 'invalid JSON' }, 400);
    }

    const key = typeof (body as Record<string, unknown>).key === 'string'
      ? ((body as Record<string, unknown>).key as string).trim()
      : '';
    const ttl = typeof (body as Record<string, unknown>).ttl_seconds === 'number'
      ? Math.floor((body as Record<string, unknown>).ttl_seconds as number)
      : 300;

    if (!key) {
      return jsonResponse({ ok: false, error: 'key is required' }, 400);
    }

    return this.state.blockConcurrencyWhile(async () => {
      const exists = await this.state.storage.get<boolean>(`dedupe:${key}`);
      if (exists) {
        return jsonResponse({ ok: true, emit: false });
      }

      await this.state.storage.put(`dedupe:${key}`, true, {
        expirationTtl: Math.max(60, Math.min(ttl, 86400)),
      } as any);

      return jsonResponse({ ok: true, emit: true });
    });
  }
}
