import { describe, it, expect } from 'vitest';
import {
  queryHealthHistory,
  queryHealthTrends,
  logWebhookDelivery,
  queryWebhookSla,
  queryWebhookFailures,
  queryActiveAlerts,
} from '../src/ops-intelligence';

// Minimal D1 mock
function createMockDb(rows: Array<Record<string, unknown>> = []) {
  const mockStmt = {
    bind: (..._args: unknown[]) => mockStmt,
    all: async () => ({ results: rows }),
    first: async () => rows[0] ?? null,
    run: async () => ({ success: true }),
  };
  return {
    prepare: (_sql: string) => mockStmt,
  } as unknown as D1Database;
}

describe('ops-intelligence', () => {
  describe('queryHealthHistory', () => {
    it('returns empty array for no data', async () => {
      const db = createMockDb([]);
      const result = await queryHealthHistory(db, 24);
      expect(result).toEqual([]);
    });

    it('clamps hours to valid range', async () => {
      const db = createMockDb([]);
      const result = await queryHealthHistory(db, 9999);
      expect(result).toEqual([]);
    });
  });

  describe('queryHealthTrends', () => {
    it('returns structure with empty data', async () => {
      const db = createMockDb([]);
      const result = await queryHealthTrends(db, 7);
      expect(result).toHaveProperty('period');
      expect(result).toHaveProperty('total_snapshots', 0);
      expect(result).toHaveProperty('per_service');
    });

    it('computes per-service stats from snapshots', async () => {
      const svcs = JSON.stringify([
        { service: 'ledger', latency_ms: 50, status: 'up' },
        { service: 'escrow', latency_ms: 100, status: 'down' },
      ]);
      const db = createMockDb([
        { services_json: svcs, overall_status: 'degraded', timestamp: new Date().toISOString() },
        { services_json: svcs, overall_status: 'degraded', timestamp: new Date().toISOString() },
      ]);
      const result = await queryHealthTrends(db, 7) as Record<string, unknown>;
      expect(result.total_snapshots).toBe(2);
      expect(result.degradation_windows).toBe(1);
      const ps = result.per_service as Record<string, Record<string, number>>;
      expect(ps.ledger.avg_latency_ms).toBe(50);
      expect(ps.ledger.uptime_pct).toBe(100);
      expect(ps.escrow.uptime_pct).toBe(0);
    });
  });

  describe('queryWebhookSla', () => {
    it('returns 100% success rate with no data', async () => {
      const db = createMockDb([]);
      const result = await queryWebhookSla(db, 24) as Record<string, unknown>;
      expect(result.total_deliveries).toBe(0);
      expect(result.success_rate_pct).toBe(100);
    });

    it('computes percentiles correctly', async () => {
      const rows = [
        { processing_ms: 10, status: 'success', error_code: null, source: 'stripe' },
        { processing_ms: 50, status: 'success', error_code: null, source: 'stripe' },
        { processing_ms: 100, status: 'success', error_code: null, source: 'loss_apply' },
        { processing_ms: 200, status: 'failed', error_code: 'TIMEOUT', source: 'loss_resolve' },
      ];
      const db = createMockDb(rows);
      const result = await queryWebhookSla(db, 24) as Record<string, unknown>;
      expect(result.total_deliveries).toBe(4);
      expect(result.success_count).toBe(3);
      expect(result.failure_count).toBe(1);
      const pms = result.processing_ms as Record<string, number>;
      expect(pms.p50).toBe(50);
      const fbc = result.failures_by_code as Record<string, number>;
      expect(fbc.TIMEOUT).toBe(1);
    });
  });

  describe('queryWebhookFailures', () => {
    it('returns empty for no failures', async () => {
      const db = createMockDb([]);
      const result = await queryWebhookFailures(db, new Date().toISOString());
      expect(result).toEqual([]);
    });
  });

  describe('queryActiveAlerts', () => {
    it('returns empty when no active alerts', async () => {
      const db = createMockDb([]);
      const result = await queryActiveAlerts(db);
      expect(result).toEqual([]);
    });
  });

  describe('logWebhookDelivery', () => {
    it('calls DB insert without throwing', async () => {
      let insertCalled = false;
      const mockStmt = {
        bind: (..._args: unknown[]) => mockStmt,
        run: async () => { insertCalled = true; return { success: true }; },
      };
      const db = { prepare: () => mockStmt } as unknown as D1Database;

      await logWebhookDelivery(db, {
        event_type: 'payment_intent.succeeded',
        source: 'stripe',
        received_at: new Date().toISOString(),
        processing_ms: 42,
        status: 'success',
      });
      expect(insertCalled).toBe(true);
    });
  });
});
