/**
 * JSON output utilities for the --json CLI flag.
 *
 * Follows the GitHub `gh` CLI pattern: when --json is passed,
 * all output is strict machine-parseable JSON with no ANSI escape codes.
 *
 * - Data goes to stdout via printJson()
 * - Errors go to stderr via printJsonError()
 */

/**
 * Check if --json was passed in CLI args.
 * Only considers flags before the `--` separator (if present),
 * so `wrap -- cmd --json` does not trigger JSON mode.
 */
export function isJsonMode(args: string[]): boolean {
  const dashDashIdx = args.indexOf('--');
  const searchArgs = dashDashIdx === -1 ? args : args.slice(0, dashDashIdx);
  return searchArgs.includes('--json');
}

/**
 * Strip --json from CLI args without touching args after `--`.
 */
export function stripJsonFlag(args: string[]): string[] {
  const dashDashIdx = args.indexOf('--');
  if (dashDashIdx === -1) {
    return args.filter((arg) => arg !== '--json');
  }
  const before = args.slice(0, dashDashIdx).filter((arg) => arg !== '--json');
  const after = args.slice(dashDashIdx);
  return [...before, ...after];
}

/**
 * Print structured data as JSON to stdout.
 * No ANSI codes, no extra decoration — just valid JSON with a trailing newline.
 */
export function printJson(data: unknown): void {
  process.stdout.write(JSON.stringify(data, null, 2) + '\n');
}

/**
 * Print a structured error as JSON to stderr.
 * Includes `error: true` marker and the current `process.exitCode`.
 */
export function printJsonError(error: {
  code: string;
  message: string;
  details?: unknown;
}): void {
  const payload: Record<string, unknown> = {
    error: true,
    code: error.code,
    message: error.message,
    exit_code: process.exitCode ?? 2,
  };
  if (error.details !== undefined) {
    payload.details = error.details;
  }
  process.stderr.write(JSON.stringify(payload, null, 2) + '\n');
}
