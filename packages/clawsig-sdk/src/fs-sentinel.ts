/**
 * Filesystem Sentinel — Real-time file mutation observation.
 *
 * Uses Node.js native fs.watch (recursive) on macOS (FSEvents) and Linux
 * (inotify via Node 20+ recursive support). Captures every file create,
 * modify, delete, rename event with millisecond timestamps.
 *
 * Key advantage over git diff:
 * - Catches temporary files (written then deleted within one tool call)
 * - Captures precise ordering of operations within a tool call
 * - Does NOT require the repo to be a git repository
 *
 * Coverage: ~90% of persistent file modifications in watched dirs.
 * Evasion: writes to /tmp, /dev/shm, memfd_create, out-of-bounds paths.
 */

import { watch, type FSWatcher } from 'node:fs';
import { stat, readFile } from 'node:fs/promises';
import { join, resolve, isAbsolute, relative } from 'node:path';
import { createHash } from 'node:crypto';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** A filesystem event captured by the sentinel. */
export interface FsEvent {
  layer: 'fs';
  /** ISO 8601 timestamp. */
  ts: string;
  /** Event type from fs.watch. */
  operation: 'change' | 'rename';
  /** Absolute path to the file. */
  path: string;
  /** Path relative to the watched root. */
  relativePath: string;
  /** Whether the target is a directory. */
  isDirectory: boolean;
  /** SHA-256 hash of file content after the event (if readable). */
  contentHash?: string;
  /** The active tool_call_id at the time of this event (set by CausalSieve). */
  activeToolCallId?: string;
}

/** Options for the FS Sentinel. */
export interface FsSentinelOptions {
  /** Directories to watch (absolute or relative, resolved from cwd). */
  watchDirs: string[];
  /** Regex patterns for paths to ignore. */
  ignorePatterns?: RegExp[];
}

// ---------------------------------------------------------------------------
// Default ignore patterns
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

export class FsSentinel {
  private watchers = new Map<string, FSWatcher>();
  private events: FsEvent[] = [];
  private ignorePatterns: RegExp[];
  private dedupCache = new Set<string>();
  private activeToolCallId: string | null = null;
  private running = false;

  constructor(private options: FsSentinelOptions) {
    this.ignorePatterns = [
      ...DEFAULT_IGNORE,
      ...(options.ignorePatterns ?? []),
    ];
  }

  /**
   * Start watching all configured directories.
   * Silently degrades if a directory can't be watched.
   */
  start(): void {
    if (this.running) return;
    this.running = true;

    for (const dir of this.options.watchDirs) {
      const absDir = resolve(dir);
      try {
        const watcher = watch(
          absDir,
          { recursive: true },
          (eventType, filename) => {
            if (!filename) return;

            const fullPath = isAbsolute(filename.toString())
              ? filename.toString()
              : join(absDir, filename.toString());

            // Check ignore patterns
            if (this.shouldIgnore(fullPath)) return;

            // Dedup rapid-fire events for the same file
            const dedupKey = `${eventType}:${fullPath}`;
            if (this.dedupCache.has(dedupKey)) return;
            this.dedupCache.add(dedupKey);
            setTimeout(() => this.dedupCache.delete(dedupKey), 50);

            // Capture event asynchronously
            void this.captureEvent(eventType, fullPath, absDir);
          },
        );

        watcher.on('error', () => {
          // Silently ignore watcher errors (directory deleted, etc.)
        });

        this.watchers.set(absDir, watcher);
      } catch {
        // Directory doesn't exist or permission denied — skip
      }
    }
  }

  /** Stop all watchers. */
  stop(): void {
    this.running = false;
    for (const watcher of this.watchers.values()) {
      try { watcher.close(); } catch { /* ignore */ }
    }
    this.watchers.clear();
  }

  /**
   * Set the currently active tool call ID.
   * All subsequent FS events will be tagged with this ID for attribution.
   */
  setActiveToolCallId(id: string | null): void {
    this.activeToolCallId = id;
  }

  /** Get all captured events. */
  getEvents(): FsEvent[] {
    return [...this.events];
  }

  /**
   * Get events captured since a given timestamp.
   * Useful for the CausalSieve to query events within a tool call window.
   */
  getEventsSince(isoTimestamp: string): FsEvent[] {
    return this.events.filter(e => e.ts >= isoTimestamp);
  }

  /** Get event count. */
  get eventCount(): number {
    return this.events.length;
  }

  /** Clear all captured events. */
  clear(): void {
    this.events = [];
  }

  // ---- Private ----

  private shouldIgnore(path: string): boolean {
    return this.ignorePatterns.some(p => p.test(path));
  }

  private async captureEvent(
    eventType: string,
    fullPath: string,
    watchRoot: string,
  ): Promise<void> {
    let isDirectory = false;
    let contentHash: string | undefined;

    try {
      const s = await stat(fullPath);
      isDirectory = s.isDirectory();

      // Hash file content for non-directories under 1MB
      if (!isDirectory && s.size < 1_048_576) {
        const content = await readFile(fullPath);
        contentHash = createHash('sha256').update(content).digest('base64url');
      }
    } catch {
      // File deleted or inaccessible — still record the event
    }

    const event: FsEvent = {
      layer: 'fs',
      ts: new Date().toISOString(),
      operation: eventType === 'rename' ? 'rename' : 'change',
      path: fullPath,
      relativePath: relative(watchRoot, fullPath),
      isDirectory,
      contentHash,
      activeToolCallId: this.activeToolCallId ?? undefined,
    };

    this.events.push(event);
  }
}
