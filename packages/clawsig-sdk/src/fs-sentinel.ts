/**
 * File System Sentinel — Hybrid fs.watch + trace file observer.
 *
 * Two complementary layers:
 * A) fs.watch (recursive) — captures file writes/renames in watched directories.
 * B) Trace file polling — reads events emitted by node-preload-sentinel.mjs,
 *    which patches the entire Node fs API to capture reads, writes, deletes, etc.
 *
 * The trace file path MUST be passed via constructor options (not env var),
 * because this sentinel runs in the parent wrap.ts process while the env var
 * is set on the child process only.
 */

import { watch, type FSWatcher } from 'node:fs';
import { stat, readFile } from 'node:fs/promises';
import { existsSync, createReadStream } from 'node:fs';
import { join, resolve, isAbsolute, relative } from 'node:path';
import { createHash } from 'node:crypto';
import { createInterface } from 'node:readline';
import os from 'node:os';

export interface FsEvent {
  layer: 'fs';
  ts: string;
  operation: 'change' | 'rename' | 'read' | 'write' | 'delete' | 'mkdir';
  path: string;
  relativePath: string;
  isDirectory: boolean;
  contentHash?: string;
  activeToolCallId?: string;
}

export interface FsSentinelOptions {
  watchDirs?: string[];
  ignorePatterns?: RegExp[];
  /** Explicit path to the CLAWSIG_TRACE_FILE. Required for trace polling. */
  traceFile?: string;
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

  // Trace file polling
  private traceFile: string | undefined;
  private traceCursor = 0;
  private tracePollTimer?: ReturnType<typeof setInterval>;

  constructor(options: FsSentinelOptions = {}) {
    this.ignorePatterns = [
      ...DEFAULT_IGNORE,
      ...(options.ignorePatterns ?? []),
    ];

    const tmp = os.tmpdir();
    this.watchDirs = options.watchDirs ?? [process.cwd(), tmp, '/tmp'];
    this.watchDirs = Array.from(new Set(this.watchDirs.map(d => resolve(d))));

    // Accept trace file path explicitly (NOT from env)
    this.traceFile = options.traceFile;
  }

  start(): void {
    if (this.running) return;
    this.running = true;

    // Layer A: fs.watch for write/rename notifications
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

            const dedupKey = `watch:${eventType}:${fullPath}`;
            if (this.dedupCache.has(dedupKey)) {
              clearTimeout(this.dedupCache.get(dedupKey)!);
            }

            const timer = setTimeout(() => {
              this.dedupCache.delete(dedupKey);
              const p = this.captureWatchEvent(eventType as 'change' | 'rename', fullPath, dir);
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

    // Layer B: Poll trace file for read/write events from node-preload-sentinel
    if (this.traceFile) {
      this.tracePollTimer = setInterval(() => {
        void this.pollTraceFile().catch(() => {});
      }, 500);
      this.tracePollTimer.unref();
    }
  }

  // -------------------------------------------------------------------------
  // Trace file polling
  // -------------------------------------------------------------------------

  private async pollTraceFile(): Promise<void> {
    if (!this.traceFile || !existsSync(this.traceFile)) return;

    try {
      const stats = await stat(this.traceFile);
      if (stats.size <= this.traceCursor) return;

      const stream = createReadStream(this.traceFile, {
        start: this.traceCursor,
        end: stats.size - 1,
        encoding: 'utf8',
      });
      const rl = createInterface({ input: stream, crlfDelay: Infinity });

      for await (const line of rl) {
        if (!line.trim()) continue;
        try {
          const event = JSON.parse(line);
          // Accept events from node-preload-sentinel (layer: 'interpose')
          if (event.layer !== 'interpose' || !event.syscall || !event.path) continue;

          const fullPath = isAbsolute(event.path) ? event.path : join(process.cwd(), event.path);
          if (this.shouldIgnore(fullPath)) continue;

          const syscall: string = event.syscall;
          let op: FsEvent['operation'] | null = null;

          if (syscall.includes('readFile') || syscall.includes('createReadStream') || syscall === 'read') {
            op = 'read';
          } else if (syscall.includes('writeFile') || syscall.includes('appendFile') ||
                     syscall.includes('createWriteStream') || syscall === 'write' ||
                     (syscall === 'copyFile')) {
            op = 'write';
          } else if (syscall.includes('unlink') || syscall.includes('rm')) {
            op = 'delete';
          } else if (syscall.includes('rename')) {
            op = 'rename';
          } else if (syscall.includes('mkdir')) {
            op = 'mkdir';
          }

          if (!op) continue;

          // Dedup within a 2s window
          const dedupKey = `trace:${op}:${fullPath}`;
          if (this.dedupCache.has(dedupKey)) continue;
          const timer = setTimeout(() => this.dedupCache.delete(dedupKey), 2000);
          this.dedupCache.set(dedupKey, timer);

          this.events.push({
            layer: 'fs',
            ts: event.ts || new Date().toISOString(),
            operation: op,
            path: fullPath,
            relativePath: relative(process.cwd(), fullPath),
            isDirectory: false,
            activeToolCallId: this.activeToolCallId ?? undefined,
          });
        } catch { /* skip unparseable lines */ }
      }

      this.traceCursor = stats.size;
    } catch { /* skip errors */ }
  }

  // -------------------------------------------------------------------------
  // Public API
  // -------------------------------------------------------------------------

  async flush(): Promise<void> {
    await this.pollTraceFile().catch(() => {});
    await new Promise(r => setTimeout(r, 100));
    await Promise.allSettled(Array.from(this.pendingCaptures));
  }

  async stop(): Promise<void> {
    this.running = false;

    for (const watcher of this.watchers.values()) {
      try { watcher.close(); } catch { /* ignore */ }
    }
    this.watchers.clear();

    if (this.tracePollTimer) {
      clearInterval(this.tracePollTimer);
      this.tracePollTimer = undefined;
    }

    for (const timer of this.dedupCache.values()) {
      clearTimeout(timer);
    }
    this.dedupCache.clear();

    await this.flush();

    // Deduplicate: same (operation, path) keeps first occurrence
    const seen = new Set<string>();
    this.events = this.events.filter(e => {
      const key = `${e.operation}:${e.path}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
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
    this.traceCursor = 0;
  }

  // -------------------------------------------------------------------------
  // Internals
  // -------------------------------------------------------------------------

  private shouldIgnore(path: string): boolean {
    return this.ignorePatterns.some(p => p.test(path));
  }

  private async captureWatchEvent(
    eventType: 'change' | 'rename',
    fullPath: string,
    watchRoot: string,
  ): Promise<void> {
    let isDirectory = false;
    let contentHash: string | undefined;

    if (eventType === 'change') {
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
