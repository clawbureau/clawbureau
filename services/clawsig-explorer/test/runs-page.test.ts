import { describe, expect, it } from 'vitest';
import { runsFeedPage } from '../src/pages/runs.js';

const baseRun = {
  run_id: 'run_aaaaaaaaaaaaaaaaaaaaaaaa',
  bundle_hash_b64u: 'hash123',
  agent_did: 'did:key:z6MkwP2s6d7v5n9r3m2q1h8j7k6l5p4o3i2u1y',
  proof_tier: 'gateway',
  status: 'FAIL',
  reason_code: 'HASH_MISMATCH',
  failure_class: 'none',
  verification_source: 'clawverify_api',
  auth_mode: 'pow',
  created_at: '2026-02-19T00:00:00.000Z',
};

describe('runsFeedPage', () => {
  it('renders active filters and preserves pagination links', () => {
    const html = runsFeedPage({
      runs: [baseRun],
      filters: {
        status: 'FAIL',
        reason_code: 'HASH_MISMATCH',
      },
      limit: 20,
      has_next: true,
      next_cursor: 'next-cursor-token',
      current_cursor: 'current-cursor-token',
      cursor_history: ['cursor-1'],
    });

    expect(html).toContain('Runs Feed (Triage Mode)');
    expect(html).toContain('Status: FAIL');
    expect(html).toContain('Reason: HASH_MISMATCH');
    expect(html).toContain('history=cursor-1%2Ccurrent-cursor-token');
    expect(html).toContain('Older &rarr;');
    expect(html).toContain('&larr; Newer');
    expect(html).toContain('sticky-filter-card');
    expect(html).toContain('Reset pagination');
    expect(html).toContain('Jump to newest');
    expect(html).toContain('aria-label="Filter by status"');
    expect(html).toContain('role="list"');
  });

  it('renders explicit error state when feed fetch fails', () => {
    const html = runsFeedPage({
      runs: [],
      filters: {},
      limit: 20,
      has_next: false,
      next_cursor: null,
      fetch_error: 'Runs feed is temporarily unavailable. Retry in a moment.',
    });

    expect(html).toContain('Runs Feed Error');
    expect(html).toContain('Runs feed is temporarily unavailable');
    expect(html).toContain('No public runs indexed yet');
    expect(html).toContain('Copy quickstart command');
    expect(html).toContain('loading-skeleton');
  });
});
