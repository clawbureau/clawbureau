export class CliUsageError extends Error {
  readonly code = 'USAGE_ERROR';

  constructor(message: string) {
    super(message);
  }
}
