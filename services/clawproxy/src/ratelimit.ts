/**
 * Rate limiting for clawproxy
 *
 * Limits requests by DID (preferred) or IP address as fallback
 */

import type { Env, RateLimitOutcome } from './types';

/** Rate limit configuration */
export const RATE_LIMIT_CONFIG = {
  /** Maximum requests per period */
  limit: 100,
  /** Period in seconds (must be 10 or 60 for Cloudflare) */
  period: 60,
} as const;

/**
 * Rate limit info returned to callers
 */
export interface RateLimitInfo {
  /** Whether the request is allowed */
  allowed: boolean;
  /** The key used for rate limiting */
  key: string;
  /** Maximum requests allowed per period */
  limit: number;
  /** Requests remaining in current window (estimated) */
  remaining: number;
  /** Unix timestamp when the rate limit resets */
  resetTime: number;
}

/**
 * Extract the rate limit key from the request
 * Prefers DID from X-Client-DID header, falls back to IP address
 */
export function extractRateLimitKey(request: Request): string {
  // Prefer DID if provided (for authenticated agents)
  const clientDid = request.headers.get('X-Client-DID');
  if (clientDid) {
    return `did:${clientDid}`;
  }

  // Fall back to IP address
  const clientIp = request.headers.get('CF-Connecting-IP');
  if (clientIp) {
    return `ip:${clientIp}`;
  }

  // Ultimate fallback (should never happen in production)
  return 'unknown';
}

/**
 * Check rate limit for a request
 * Returns info about whether the request is allowed and usage headers
 */
export async function checkRateLimit(
  request: Request,
  env: Env
): Promise<RateLimitInfo> {
  const key = extractRateLimitKey(request);
  const now = Math.floor(Date.now() / 1000);
  const resetTime = now + RATE_LIMIT_CONFIG.period;

  // Check if rate limiter binding is available
  if (!env.PROXY_RATE_LIMITER) {
    // No rate limiter configured, allow all requests
    return {
      allowed: true,
      key,
      limit: RATE_LIMIT_CONFIG.limit,
      remaining: RATE_LIMIT_CONFIG.limit,
      resetTime,
    };
  }

  let outcome: RateLimitOutcome;
  try {
    outcome = await env.PROXY_RATE_LIMITER.limit({ key });
  } catch {
    // If rate limiting fails, fail open (allow the request)
    // This prevents rate limiter issues from blocking all traffic
    return {
      allowed: true,
      key,
      limit: RATE_LIMIT_CONFIG.limit,
      remaining: RATE_LIMIT_CONFIG.limit,
      resetTime,
    };
  }

  return {
    allowed: outcome.success,
    key,
    limit: RATE_LIMIT_CONFIG.limit,
    // Remaining is estimated since Cloudflare doesn't expose exact count
    remaining: outcome.success ? Math.max(0, RATE_LIMIT_CONFIG.limit - 1) : 0,
    resetTime,
  };
}

/**
 * Build rate limit headers for response
 */
export function buildRateLimitHeaders(info: RateLimitInfo): Record<string, string> {
  return {
    'X-RateLimit-Limit': String(info.limit),
    'X-RateLimit-Remaining': String(info.remaining),
    'X-RateLimit-Reset': String(info.resetTime),
  };
}
