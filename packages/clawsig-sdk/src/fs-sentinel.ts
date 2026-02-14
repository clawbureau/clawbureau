import { watch, type FSWatcher } from 'node:fs';
import { stat, readFile } from 'node:fs/promises';
import { join, resolve, isAbsolute, relative } from 'node:path';
import { createHash } from 'node:crypto';
import os from 'node:os';

export interface FsEvent {
  layer: 'fs';
  ts: string;
  operation: 'change' | 'rename';
  path: string;
  relativePath: string;
  isDirectory: boolean;
  contentHash?: string;
  activeToolCallId?: string;
}

export interface FsSentinelOptions {
  watchDirs?: string[];
  ignorePatterns?: RegExp[];
}

const DEFAULT_IGNORE: RegExp[] = [
  /[\\/]\.git[\\/]/,
  /[\\/]node_modules[\\/]/,
  /[\\/]\.clawsig[\\/]/,
  /[\\/]__pycache__[\\/]/,
  /[\\/]\.next[\\/]/,
  /[\\/]\.nuxt[\\/]/,
  /[\\/]dist[\\/]/,
  /[\\/]build[\\/]/,
  /[\\/]\.DS_Store$/,
  /[\\/]\.swp$/,
  /[\\/]\.swo$/,
  /clawsig-trace-/,
];

export class FsSentinel {
  private watchers = new Map<string, FSWatcher>();
  private events: FsEvent[] = [];
  private ignorePatterns: RegExp[];
  private dedupCache = new Map<string, NodeJS.Timeout>();
  private activeToolCallId: string | null = null;
  private running = false;
  private pendingCaptures = new Set<Promise<void>>();
  private watchDirs: string[];

  constructor(options: FsSentinelOptions = {}) {
    this.ignorePatterns = [
      ...DEFAULT_IGNORE,
      ...(options.ignorePatterns ?? []),
    ];

    const tmp = os.tmpdir();
    this.watchDirs = options.watchDirs ?? [process.cwd(), tmp, '/tmp'];
    // Deduplicate resolved paths
    this.watchDirs = Array.from(new Set(this.watchDirs.map(d => resolve(d))));
  }

  start(): void {
    if (this.running) return;
    this.running = true;

    for (const dir of this.watchDirs) {
      try {
        const watcher = watch(
          dir,
          { recursive: true, persistent: false },
          (eventType, filename) => {
            if (!filename) return;

            const fullPath = isAbsolute(filename.toString())
              ? filename.toString()
              : join(dir, filename.toString());

            if (this.shouldIgnore(fullPath)) return;

            const dedupKey = `${eventType}:${fullPath}`;
            if (this.dedupCache.has(dedupKey)) {
              clearTimeout(this.dedupCache.get(dedupKey));
            }

            const timer = setTimeout(() => {
              this.dedupCache.delete(dedupKey);
              const p = this.captureEvent(eventType as 'change' | 'rename', fullPath, dir);
              this.pendingCaptures.add(p);
              p.finally(() => this.pendingCaptures.delete(p));
            }, 50);

            this.dedupCache.set(dedupKey, timer);
          },
        );

        watcher.on('error', () => {});
        this.watchers.set(dir, watcher);
      } catch {
        // Skip inaccessible dirs
      }
    }
  }

  async flush(): Promise<void> {
    await new Promise(r => setTimeout(r, 100));
    await Promise.allSettled(Array.from(this.pendingCaptures));
  }

  async stop(): Promise<void> {
    this.running = false;
    for (const watcher of this.watchers.values()) {
      try { watcher.close(); } catch { /* ignore */ }
    }
    this.watchers.clear();
    for (const timer of this.dedupCache.values()) {
      clearTimeout(timer);
    }
    this.dedupCache.clear();
    await this.flush();
  }

  setActiveToolCallId(id: string | null): void {
    this.activeToolCallId = id;
  }

  getEvents(): FsEvent[] {
    return [...this.events];
  }

  getEventsSince(isoTimestamp: string): FsEvent[] {
    return this.events.filter(e => e.ts >= isoTimestamp);
  }

  get eventCount(): number {
    return this.events.length;
  }

  clear(): void {
    this.events = [];
  }

  private shouldIgnore(path: string): boolean {
    return this.ignorePatterns.some(p => p.test(path));
  }

  private async captureEvent(
    eventType: 'change' | 'rename',
    fullPath: string,
    watchRoot: string,
  ): Promise<void> {
    let isDirectory = false;
    let contentHash: string | undefined;

    try {
      const s = await stat(fullPath);
      isDirectory = s.isDirectory();

      if (!isDirectory && s.size < 1_048_576) {
        const content = await readFile(fullPath);
        contentHash = createHash('sha256').update(content).digest('base64url');
      }
    } catch {
      // File deleted or inaccessible
    }

    this.events.push({
      layer: 'fs',
      ts: new Date().toISOString(),
      operation: eventType,
      path: fullPath,
      relativePath: relative(watchRoot, fullPath),
      isDirectory,
      contentHash,
      activeToolCallId: this.activeToolCallId ?? undefined,
    });
  }
}
