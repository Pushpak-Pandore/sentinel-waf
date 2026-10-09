import { prisma } from '../db/prisma';

export async function getOverviewStats(timeRangeMs: number = 24 * 3600 * 1000) {
  const since = new Date(Date.now() - timeRangeMs);

  const [totalTraffic, decisionCounts, categoryCounts, severityCounts, topIpsRaw, topPathsRaw, recentEvents] = await Promise.all([
    prisma.trafficLog.count({ where: { timestamp: { gte: since } } }),
    prisma.trafficLog.groupBy({
      by: ['decision'],
      where: { timestamp: { gte: since } },
      _count: true,
    }),
    prisma.securityEvent.groupBy({
      by: ['category'],
      where: { timestamp: { gte: since } },
      _count: true,
    }),
    prisma.securityEvent.groupBy({
      by: ['severity'],
      where: { timestamp: { gte: since } },
      _count: true,
    }),
    prisma.securityEvent.groupBy({
      by: ['clientIp'],
      where: { timestamp: { gte: since } },
      _count: { clientIp: true },
      orderBy: { _count: { clientIp: 'desc' } },
      take: 5,
    }),
    prisma.securityEvent.groupBy({
      by: ['path'],
      where: { timestamp: { gte: since } },
      _count: { path: true },
      orderBy: { _count: { path: 'desc' } },
      take: 5,
    }),
    prisma.securityEvent.findMany({
      where: { timestamp: { gte: since } },
      orderBy: { timestamp: 'desc' },
      take: 10,
    }),
  ]);

  const decisions: Record<string, number> = { ALLOW: 0, BLOCK: 0, LOG: 0, RATE_LIMIT: 0 };
  for (const item of decisionCounts) {
    decisions[item.decision] = item._count;
  }

  const categories: Record<string, number> = {};
  for (const item of categoryCounts) {
    categories[item.category] = item._count;
  }

  const severities: Record<string, number> = {};
  for (const item of severityCounts) {
    severities[item.severity] = item._count;
  }

  const topIps = topIpsRaw.map(i => ({ ip: i.clientIp, count: i._count.clientIp }));
  const topPaths = topPathsRaw.map(p => ({ path: p.path, count: p._count.path }));

  // Calculate requests per second over timeframe
  const totalSeconds = Math.max(1, timeRangeMs / 1000);
  const requestsPerSecond = (totalTraffic / totalSeconds).toFixed(3);

  return {
    totalRequests: totalTraffic,
    allowedRequests: decisions.ALLOW || 0,
    blockedRequests: decisions.BLOCK || 0,
    monitoredRequests: decisions.LOG || 0,
    rateLimitedRequests: decisions.RATE_LIMIT || 0,
    requestsPerSecond: parseFloat(requestsPerSecond),
    categories,
    severities,
    topIps,
    topPaths,
    recentEvents,
  };
}

export async function getTimeSeriesAnalytics(timeRangeMs: number = 24 * 3600 * 1000) {
  const since = new Date(Date.now() - timeRangeMs);

  const logs = await prisma.trafficLog.findMany({
    where: { timestamp: { gte: since } },
    select: { timestamp: true, decision: true },
    orderBy: { timestamp: 'asc' },
  });

  // Group by hourly buckets
  const buckets = new Map<string, { time: string; allowed: number; blocked: number; log: number; rateLimit: number }>();

  for (const log of logs) {
    const d = new Date(log.timestamp);
    d.setMinutes(0, 0, 0);
    const key = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

    if (!buckets.has(key)) {
      buckets.set(key, { time: key, allowed: 0, blocked: 0, log: 0, rateLimit: 0 });
    }

    const b = buckets.get(key)!;
    if (log.decision === 'ALLOW') b.allowed++;
    else if (log.decision === 'BLOCK') b.blocked++;
    else if (log.decision === 'LOG') b.log++;
    else if (log.decision === 'RATE_LIMIT') b.rateLimit++;
  }

  return Array.from(buckets.values());
}
