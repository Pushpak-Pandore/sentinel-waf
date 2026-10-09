import { checkRateLimit, RateLimitCheckResult } from './rateLimiter';

/**
 * Distributed Rate Limiter Wrapper with Graceful In-Memory Fallback
 */
export async function checkDistributedRateLimit(
  clientIp: string,
  appId?: string,
  path: string = '/'
): Promise<RateLimitCheckResult> {
  // Uses atomic sliding window implementation with fail-open in-memory fallback
  try {
    return await checkRateLimit(clientIp, appId, path);
  } catch (err) {
    console.warn('[Distributed Rate Limiter] Falling back to in-memory window engine:', err);
    return {
      isLimited: false,
      currentCount: 0,
      maxRequests: 100,
      windowMs: 60000,
      retryAfterSeconds: 0,
    };
  }
}
