import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import { generateIdentity } from '../src/identity.js';
import { saveWorkConfig, DEFAULT_MARKETPLACE_URL } from '../src/work-config.js';
import type { WorkConfig } from '../src/work-config.js';
import { __setFetch } from '../src/work-api.js';
import type { Bounty } from '../src/work-api.js';
import {
  runWorkList,
  filterBounties,
  parseSkillsCsv,
  renderTable,
} from '../src/work-list.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let tmpDir: string;

async function quietAsync<T>(fn: () => Promise<T>): Promise<T> {
  const origOut = process.stdout.write;
  const origErr = process.stderr.write;
  process.stdout.write = (() => true) as typeof process.stdout.write;
  process.stderr.write = (() => true) as typeof process.stderr.write;
  try {
    return await fn();
  } finally {
    process.stdout.write = origOut;
    process.stderr.write = origErr;
  }
}

function captureStdout<T>(fn: () => Promise<T>): { result: Promise<T>; chunks: string[] } {
  const chunks: string[] = [];
  const origOut = process.stdout.write;
  const origErr = process.stderr.write;
  process.stdout.write = ((chunk: string) => {
    chunks.push(chunk);
    return true;
  }) as typeof process.stdout.write;
  process.stderr.write = (() => true) as typeof process.stderr.write;
  const result = fn().finally(() => {
    process.stdout.write = origOut;
    process.stderr.write = origErr;
  });
  return { result, chunks };
}

function makeBounty(overrides: Partial<Bounty> = {}): Bounty {
  return {
    id: 'b-001',
    title: 'Fix the widget',
    repo: 'clawbureau/clawsig-sdk',
    skills: ['typescript', 'rust'],
    budget: 200,
    currency: 'USD',
    status: 'open',
    created_at: '2025-06-01T00:00:00Z',
    ...overrides,
  };
}

function mockBountyResponse(bounties: Bounty[]): () => void {
  return __setFetch(async () =>
    new Response(
      JSON.stringify({ bounties }),
      { status: 200, headers: { 'Content-Type': 'application/json' } },
    ),
  );
}

beforeEach(async () => {
  tmpDir = await mkdtemp(join(tmpdir(), 'clawsig-wl-test-'));
  delete process.env['CLAWSIG_IDENTITY'];
});

afterEach(async () => {
  delete process.env['CLAWSIG_IDENTITY'];
  process.exitCode = undefined;
  await rm(tmpDir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// parseSkillsCsv
// ---------------------------------------------------------------------------

describe('parseSkillsCsv', () => {
  it('parses comma-separated values', () => {
    expect(parseSkillsCsv('typescript, rust, python')).toEqual([
      'typescript',
      'rust',
      'python',
    ]);
  });

  it('lowercases and trims', () => {
    expect(parseSkillsCsv(' TypeScript , RUST ')).toEqual(['typescript', 'rust']);
  });

  it('handles empty string', () => {
    expect(parseSkillsCsv('')).toEqual([]);
  });

  it('handles single skill', () => {
    expect(parseSkillsCsv('go')).toEqual(['go']);
  });
});

// ---------------------------------------------------------------------------
// filterBounties
// ---------------------------------------------------------------------------

describe('filterBounties', () => {
  const bounties: Bounty[] = [
    makeBounty({ id: 'b-1', skills: ['typescript'], budget: 100, repo: 'org/repo-a' }),
    makeBounty({ id: 'b-2', skills: ['rust', 'python'], budget: 500, repo: 'org/repo-b' }),
    makeBounty({ id: 'b-3', skills: ['typescript', 'go'], budget: 50, repo: 'org/repo-a' }),
    makeBounty({ id: 'b-4', budget: 300, repo: 'org/repo-c' }), // no skills array
    makeBounty({ id: 'b-5', skills: ['rust'], repo: 'org/repo-b' }), // no budget
  ];
  // Remove skills from b-4 to test missing field
  delete (bounties[3] as Record<string, unknown>).skills;
  delete (bounties[4] as Record<string, unknown>).budget;

  it('returns all bounties with no filters', () => {
    expect(filterBounties(bounties, {})).toHaveLength(5);
  });

  it('filters by skills', () => {
    const result = filterBounties(bounties, { skills: ['rust'] });
    expect(result.map((b) => b.id)).toEqual(['b-2', 'b-5']);
  });

  it('skills filter is case-insensitive', () => {
    const result = filterBounties(bounties, { skills: ['typescript'] });
    expect(result.map((b) => b.id)).toEqual(['b-1', 'b-3']);
  });

  it('excludes bounties with missing skills array', () => {
    const result = filterBounties(bounties, { skills: ['typescript'] });
    expect(result.find((b) => b.id === 'b-4')).toBeUndefined();
  });

  it('filters by budget-min', () => {
    const result = filterBounties(bounties, { budgetMin: 200 });
    expect(result.map((b) => b.id)).toEqual(['b-2', 'b-4']);
  });

  it('excludes bounties with missing budget', () => {
    const result = filterBounties(bounties, { budgetMin: 1 });
    expect(result.find((b) => b.id === 'b-5')).toBeUndefined();
  });

  it('filters by repo', () => {
    const result = filterBounties(bounties, { repo: 'org/repo-a' });
    expect(result.map((b) => b.id)).toEqual(['b-1', 'b-3']);
  });

  it('repo filter is case-insensitive', () => {
    const result = filterBounties(bounties, { repo: 'ORG/REPO-B' });
    expect(result.map((b) => b.id)).toEqual(['b-2', 'b-5']);
  });

  it('combines skills + budget-min + repo', () => {
    const result = filterBounties(bounties, {
      skills: ['typescript'],
      budgetMin: 100,
      repo: 'org/repo-a',
    });
    expect(result.map((b) => b.id)).toEqual(['b-1']);
  });

  it('returns empty when no matches', () => {
    const result = filterBounties(bounties, { skills: ['haskell'] });
    expect(result).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// renderTable
// ---------------------------------------------------------------------------

describe('renderTable', () => {
  it('renders "No bounties found." for empty list', () => {
    expect(renderTable([])).toBe('No bounties found.');
  });

  it('renders header + rows', () => {
    const output = renderTable([makeBounty()]);
    expect(output).toContain('ID');
    expect(output).toContain('BUDGET');
    expect(output).toContain('REPO');
    expect(output).toContain('TITLE');
    expect(output).toContain('b-001');
    expect(output).toContain('200 USD');
    expect(output).toContain('Fix the widget');
  });

  it('handles missing optional fields gracefully', () => {
    const b: Bounty = { id: 'b-x', title: '' };
    const output = renderTable([b]);
    expect(output).toContain('b-x');
    expect(output).toContain('-'); // missing budget/repo
    expect(output).toContain('(untitled)');
  });
});

// ---------------------------------------------------------------------------
// runWorkList: success path
// ---------------------------------------------------------------------------

describe('runWorkList: success', () => {
  it('returns bounties from marketplace', async () => {
    const bounties = [makeBounty({ id: 'b-1' }), makeBounty({ id: 'b-2' })];
    const restore = mockBountyResponse(bounties);
    try {
      const result = await quietAsync(() =>
        runWorkList({ projectDir: tmpDir }),
      );
      expect(result.status).toBe('ok');
      expect(result.total).toBe(2);
      expect(result.filtered).toBe(2);
      expect(result.bounties).toHaveLength(2);
    } finally {
      restore();
    }
  });

  it('uses marketplace from work config', async () => {
    const identityPath = join(tmpDir, '.clawsig', 'identity.jwk.json');
    const identity = await generateIdentity(identityPath);

    const config: WorkConfig = {
      configVersion: '1',
      workerDid: identity.did,
      marketplaceUrl: 'https://custom.example.com',
      createdAt: '2025-01-01T00:00:00Z',
    };
    await saveWorkConfig(config, tmpDir);

    let requestedUrl = '';
    const restore = __setFetch(async (input: RequestInfo | URL) => {
      requestedUrl = input.toString();
      return new Response(JSON.stringify({ bounties: [] }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    });

    try {
      await quietAsync(() => runWorkList({ projectDir: tmpDir }));
      expect(requestedUrl).toBe('https://custom.example.com/v1/bounties');
    } finally {
      restore();
    }
  });

  it('flag --marketplace overrides work config', async () => {
    const identityPath = join(tmpDir, '.clawsig', 'identity.jwk.json');
    const identity = await generateIdentity(identityPath);

    const config: WorkConfig = {
      configVersion: '1',
      workerDid: identity.did,
      marketplaceUrl: 'https://config.example.com',
      createdAt: '2025-01-01T00:00:00Z',
    };
    await saveWorkConfig(config, tmpDir);

    let requestedUrl = '';
    const restore = __setFetch(async (input: RequestInfo | URL) => {
      requestedUrl = input.toString();
      return new Response(JSON.stringify({ bounties: [] }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    });

    try {
      await quietAsync(() =>
        runWorkList({ marketplace: 'https://override.example.com', projectDir: tmpDir }),
      );
      expect(requestedUrl).toBe('https://override.example.com/v1/bounties');
    } finally {
      restore();
    }
  });

  it('sends worker DID header when available', async () => {
    const identityPath = join(tmpDir, '.clawsig', 'identity.jwk.json');
    const identity = await generateIdentity(identityPath);

    const config: WorkConfig = {
      configVersion: '1',
      workerDid: identity.did,
      marketplaceUrl: DEFAULT_MARKETPLACE_URL,
      createdAt: '2025-01-01T00:00:00Z',
    };
    await saveWorkConfig(config, tmpDir);

    let capturedHeaders: Record<string, string> = {};
    const restore = __setFetch(async (_input: RequestInfo | URL, init?: RequestInit) => {
      capturedHeaders = (init?.headers ?? {}) as Record<string, string>;
      return new Response(JSON.stringify({ bounties: [] }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    });

    try {
      await quietAsync(() => runWorkList({ projectDir: tmpDir }));
      expect(capturedHeaders['X-Worker-DID']).toBe(identity.did);
    } finally {
      restore();
    }
  });

  it('works without prior work init (best effort)', async () => {
    // No identity, no work config — should still hit default marketplace.
    let requestedUrl = '';
    const restore = __setFetch(async (input: RequestInfo | URL) => {
      requestedUrl = input.toString();
      return new Response(JSON.stringify({ bounties: [] }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    });

    try {
      const result = await quietAsync(() => runWorkList({ projectDir: tmpDir }));
      expect(result.status).toBe('ok');
      expect(result.workerDid).toBeNull();
      expect(requestedUrl).toContain('/v1/bounties');
    } finally {
      restore();
    }
  });
});

// ---------------------------------------------------------------------------
// runWorkList: filter integration
// ---------------------------------------------------------------------------

describe('runWorkList: filters', () => {
  const bounties = [
    makeBounty({ id: 'b-1', skills: ['typescript'], budget: 100, repo: 'org/alpha' }),
    makeBounty({ id: 'b-2', skills: ['rust'], budget: 500, repo: 'org/beta' }),
    makeBounty({ id: 'b-3', skills: ['typescript', 'go'], budget: 250, repo: 'org/alpha' }),
  ];

  it('filters by --skills', async () => {
    const restore = mockBountyResponse(bounties);
    try {
      const result = await quietAsync(() =>
        runWorkList({ skills: 'rust', projectDir: tmpDir }),
      );
      expect(result.filtered).toBe(1);
      expect(result.bounties[0]!.id).toBe('b-2');
    } finally {
      restore();
    }
  });

  it('filters by --budget-min', async () => {
    const restore = mockBountyResponse(bounties);
    try {
      const result = await quietAsync(() =>
        runWorkList({ budgetMin: 200, projectDir: tmpDir }),
      );
      expect(result.filtered).toBe(2);
      expect(result.bounties.map((b) => b.id)).toEqual(['b-2', 'b-3']);
    } finally {
      restore();
    }
  });

  it('filters by --repo', async () => {
    const restore = mockBountyResponse(bounties);
    try {
      const result = await quietAsync(() =>
        runWorkList({ repo: 'org/alpha', projectDir: tmpDir }),
      );
      expect(result.filtered).toBe(2);
      expect(result.bounties.map((b) => b.id)).toEqual(['b-1', 'b-3']);
    } finally {
      restore();
    }
  });

  it('combines all filters', async () => {
    const restore = mockBountyResponse(bounties);
    try {
      const result = await quietAsync(() =>
        runWorkList({
          skills: 'typescript',
          budgetMin: 200,
          repo: 'org/alpha',
          projectDir: tmpDir,
        }),
      );
      expect(result.filtered).toBe(1);
      expect(result.bounties[0]!.id).toBe('b-3');
    } finally {
      restore();
    }
  });
});

// ---------------------------------------------------------------------------
// runWorkList: empty results
// ---------------------------------------------------------------------------

describe('runWorkList: empty results', () => {
  it('handles zero bounties from API', async () => {
    const restore = mockBountyResponse([]);
    try {
      const result = await quietAsync(() =>
        runWorkList({ projectDir: tmpDir }),
      );
      expect(result.status).toBe('ok');
      expect(result.total).toBe(0);
      expect(result.filtered).toBe(0);
      expect(result.bounties).toEqual([]);
    } finally {
      restore();
    }
  });

  it('handles all bounties filtered out', async () => {
    const restore = mockBountyResponse([makeBounty({ id: 'b-1', skills: ['go'] })]);
    try {
      const result = await quietAsync(() =>
        runWorkList({ skills: 'haskell', projectDir: tmpDir }),
      );
      expect(result.status).toBe('ok');
      expect(result.total).toBe(1);
      expect(result.filtered).toBe(0);
    } finally {
      restore();
    }
  });
});

// ---------------------------------------------------------------------------
// runWorkList: network/API errors
// ---------------------------------------------------------------------------

describe('runWorkList: errors', () => {
  it('surfaces network error', async () => {
    const restore = __setFetch(async () => {
      throw new Error('DNS resolution failed');
    });
    try {
      const result = await quietAsync(() =>
        runWorkList({ projectDir: tmpDir }),
      );
      expect(result.status).toBe('error');
      expect(result.error?.code).toBe('NETWORK_ERROR');
      expect(result.error?.message).toContain('DNS resolution failed');
      expect(process.exitCode).toBe(1);
    } finally {
      restore();
    }
  });

  it('surfaces HTTP error', async () => {
    const restore = __setFetch(async () =>
      new Response('Service Unavailable', { status: 503 }),
    );
    try {
      const result = await quietAsync(() =>
        runWorkList({ projectDir: tmpDir }),
      );
      expect(result.status).toBe('error');
      expect(result.error?.code).toBe('LIST_FAILED');
      expect(result.error?.message).toContain('503');
      expect(process.exitCode).toBe(1);
    } finally {
      restore();
    }
  });

  it('surfaces parse error', async () => {
    const restore = __setFetch(async () =>
      new Response('not json', {
        status: 200,
        headers: { 'Content-Type': 'text/plain' },
      }),
    );
    try {
      const result = await quietAsync(() =>
        runWorkList({ projectDir: tmpDir }),
      );
      expect(result.status).toBe('error');
      expect(result.error?.code).toBe('LIST_PARSE_ERROR');
      expect(process.exitCode).toBe(1);
    } finally {
      restore();
    }
  });
});

// ---------------------------------------------------------------------------
// runWorkList: JSON output contract
// ---------------------------------------------------------------------------

describe('runWorkList: --json output', () => {
  it('produces parseable JSON with expected fields', async () => {
    const bounties = [makeBounty({ id: 'b-1' }), makeBounty({ id: 'b-2' })];
    const restore = mockBountyResponse(bounties);

    const { result, chunks } = captureStdout(() =>
      runWorkList({ json: true, projectDir: tmpDir }),
    );

    try {
      await result;
      const output = chunks.join('');
      const parsed = JSON.parse(output);

      expect(parsed.status).toBe('ok');
      expect(typeof parsed.marketplace).toBe('string');
      expect(parsed.total).toBe(2);
      expect(parsed.filtered).toBe(2);
      expect(Array.isArray(parsed.bounties)).toBe(true);
      expect(parsed.bounties[0].id).toBe('b-1');
      // worker_did can be null when no identity
      expect('worker_did' in parsed).toBe(true);
    } finally {
      restore();
    }
  });

  it('JSON output respects filters', async () => {
    const bounties = [
      makeBounty({ id: 'b-1', skills: ['go'], budget: 100 }),
      makeBounty({ id: 'b-2', skills: ['typescript'], budget: 500 }),
    ];
    const restore = mockBountyResponse(bounties);

    const { result, chunks } = captureStdout(() =>
      runWorkList({ json: true, skills: 'typescript', budgetMin: 200, projectDir: tmpDir }),
    );

    try {
      await result;
      const parsed = JSON.parse(chunks.join(''));
      expect(parsed.total).toBe(2);
      expect(parsed.filtered).toBe(1);
      expect(parsed.bounties).toHaveLength(1);
      expect(parsed.bounties[0].id).toBe('b-2');
    } finally {
      restore();
    }
  });

  it('JSON error output on API failure', async () => {
    const restore = __setFetch(async () => {
      throw new Error('offline');
    });

    const errChunks: string[] = [];
    const origOut = process.stdout.write;
    const origErr = process.stderr.write;
    process.stderr.write = ((chunk: string) => {
      errChunks.push(chunk);
      return true;
    }) as typeof process.stderr.write;
    process.stdout.write = (() => true) as typeof process.stdout.write;

    try {
      await runWorkList({ json: true, projectDir: tmpDir });
      const parsed = JSON.parse(errChunks.join(''));
      expect(parsed.error).toBe(true);
      expect(parsed.code).toBe('NETWORK_ERROR');
    } finally {
      restore();
      process.stdout.write = origOut;
      process.stderr.write = origErr;
    }
  });
});

// ---------------------------------------------------------------------------
// work-api: listBounties (unit)
// ---------------------------------------------------------------------------

describe('work-api: listBounties', () => {
  it('handles bare array response', async () => {
    const restore = __setFetch(async () =>
      new Response(
        JSON.stringify([{ id: 'b-1', title: 'Test' }]),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    );

    try {
      const { listBounties } = await import('../src/work-api.js');
      const result = await listBounties('https://example.com');
      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.bounties).toHaveLength(1);
        expect(result.bounties[0]!.id).toBe('b-1');
      }
    } finally {
      restore();
    }
  });

  it('handles malformed bounty items gracefully', async () => {
    const restore = __setFetch(async () =>
      new Response(
        JSON.stringify({ bounties: [null, 42, { id: 'b-ok', title: 'Good' }, 'bad'] }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    );

    try {
      const { listBounties } = await import('../src/work-api.js');
      const result = await listBounties('https://example.com');
      expect(result.ok).toBe(true);
      if (result.ok) {
        // All items are mapped, malformed ones get empty id/title
        expect(result.bounties).toHaveLength(4);
        expect(result.bounties[2]!.id).toBe('b-ok');
        expect(result.bounties[0]!.id).toBe('');
      }
    } finally {
      restore();
    }
  });
});
