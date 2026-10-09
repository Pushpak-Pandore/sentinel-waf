import { prisma } from '../db/prisma';

interface RateLimitRecord {
  timestamps: number[];
}

// In-memory sliding window cache for low latency
const limitCache = new Map<string, RateLimitRecord>();

// Cleanup stale records periodically
setInterval(() => {
  const now = Date.now();
  for (const [key, record] of limitCache.entries()) {
    record.timestamps = record.timestamps.filter(t => now - t < 3600000); // 1 hour max window
    if (record.timestamps.length === 0) {
      limitCache.delete(key);
    }
  }
}, 60000);

export interface RateLimitCheckResult {
  isLimited: boolean;
  currentCount: number;
  maxRequests: number;
  windowMs: number;
  retryAfterSeconds: number;
  policyName?: string;
}

export async function checkRateLimit(
  clientIp: string,
  appId?: string,
  path: string = '/'
): Promise<RateLimitCheckResult> {
  // Fetch active policies
  const policies = await prisma.rateLimitPolicy.findMany({
    where: { enabled: true }
  });

  const now = Date.now();

  for (const policy of policies) {
    let key = '';

    if (policy.scope === 'IP') {
      key = `rl:ip:${clientIp}:${policy.id}`;
    } else if (policy.scope === 'APP' && appId) {
      key = `rl:app:${appId}:${clientIp}:${policy.id}`;
    } else if (policy.scope === 'ROUTE') {
      if (matchPath(path, policy.pathPattern)) {
        key = `rl:route:${path}:${clientIp}:${policy.id}`;
      } else {
        continue;
      }
    } else {
      // GLOBAL
      key = `rl:global:${clientIp}:${policy.id}`;
    }

    const windowMs = policy.windowMs;
    const maxRequests = policy.maxRequests;

    let record = limitCache.get(key);
    if (!record) {
      record = { timestamps: [] };
      limitCache.set(key, record);
    }

    // Filter timestamps within current window
    record.timestamps = record.timestamps.filter(t => now - t < windowMs);

    if (record.timestamps.length >= maxRequests) {
      const oldestInWindow = record.timestamps[0];
      const resetTimeMs = oldestInWindow + windowMs;
      const retryAfterSeconds = Math.ceil((resetTimeMs - now) / 1000);

      return {
        isLimited: true,
        currentCount: record.timestamps.length,
        maxRequests,
        windowMs,
        retryAfterSeconds: retryAfterSeconds > 0 ? retryAfterSeconds : 1,
        policyName: policy.name,
      };
    }

    // Record request
    record.timestamps.push(now);
  }

  return {
    isLimited: false,
    currentCount: 0,
    maxRequests: 100,
    windowMs: 60000,
    retryAfterSeconds: 0,
  };
}

function matchPath(path: string, pattern: string): boolean {
  if (pattern === '*' || pattern === '/*') return true;
  if (pattern.endsWith('*')) {
    const prefix = pattern.slice(0, -1);
    return path.startsWith(prefix);
  }
  return path === pattern;
}

export function clearRateLimitCache(): void {
  limitCache.clear();
}
