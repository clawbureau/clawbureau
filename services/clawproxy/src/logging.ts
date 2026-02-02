/**
 * Structured logging for clawproxy security events
 */

export type SecurityEventType =
  | 'BLOCKED_UNKNOWN_PROVIDER'
  | 'BLOCKED_INVALID_PATH'
  | 'BLOCKED_MISSING_AUTH'
  | 'RATE_LIMITED'
  | 'POLICY_VIOLATION'
  | 'POLICY_MISSING'
  | 'CONFIDENTIAL_REQUEST';

export interface SecurityEvent {
  type: SecurityEventType;
  timestamp: string;
  request: {
    method: string;
    path: string;
    clientIp?: string;
    userAgent?: string;
  };
  details: Record<string, unknown>;
}

/**
 * Log a security event (blocked attempt)
 * Uses structured logging for observability
 */
export function logSecurityEvent(
  request: Request,
  type: SecurityEventType,
  details: Record<string, unknown>
): void {
  const event: SecurityEvent = {
    type,
    timestamp: new Date().toISOString(),
    request: {
      method: request.method,
      path: new URL(request.url).pathname,
      clientIp: request.headers.get('CF-Connecting-IP') ?? undefined,
      userAgent: request.headers.get('User-Agent') ?? undefined,
    },
    details,
  };

  // Use console.warn for security events (blocked attempts)
  // These will be captured by Cloudflare Workers observability
  console.warn('[SECURITY]', JSON.stringify(event));
}

/**
 * Log a blocked provider attempt
 */
export function logBlockedProvider(
  request: Request,
  attemptedProvider: string
): void {
  logSecurityEvent(request, 'BLOCKED_UNKNOWN_PROVIDER', {
    attemptedProvider,
    message: `Blocked attempt to use unknown provider: ${attemptedProvider}`,
  });
}

/**
 * Log a rate limited request
 */
export function logRateLimited(
  request: Request,
  rateLimitKey: string
): void {
  logSecurityEvent(request, 'RATE_LIMITED', {
    rateLimitKey,
    message: `Request rate limited for key: ${rateLimitKey}`,
  });
}

/**
 * Log a policy violation (provider/model not allowed)
 */
export function logPolicyViolation(
  request: Request,
  policyHash: string,
  errorCode: string,
  details: string
): void {
  logSecurityEvent(request, 'POLICY_VIOLATION', {
    policyHash,
    errorCode,
    details,
    message: `Policy violation: ${details}`,
  });
}

/**
 * Log a missing policy in confidential mode
 */
export function logPolicyMissing(
  request: Request,
  reason: string
): void {
  logSecurityEvent(request, 'POLICY_MISSING', {
    reason,
    message: `Policy missing in confidential mode: ${reason}`,
  });
}

/**
 * Log a confidential request (metadata only, NEVER plaintext prompts/responses)
 * This ensures audit trail exists without exposing sensitive content
 */
export function logConfidentialRequest(
  request: Request,
  provider: string,
  model: string | undefined,
  policyHash: string | undefined
): void {
  // IMPORTANT: Only log metadata, NEVER log request/response body content
  logSecurityEvent(request, 'CONFIDENTIAL_REQUEST', {
    provider,
    model: model ?? 'unknown',
    policyHash: policyHash ?? 'unknown',
    // Explicitly note that content is not logged
    contentLogged: false,
    message: 'Confidential request processed (content not logged)',
  });
}
