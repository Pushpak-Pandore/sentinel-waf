import { Router, Request, Response } from 'express';
import { checkDbConnection, prisma } from '../db/prisma';
import { authenticateToken } from '../middleware/auth';
import http from 'http';

const router = Router();

// Public liveness check
router.get('/', async (req: Request, res: Response) => {
  const dbOk = await checkDbConnection();
  res.status(dbOk ? 200 : 503).json({
    status: dbOk ? 'HEALTHY' : 'DEGRADED',
    timestamp: new Date().toISOString(),
    wafEngine: 'ONLINE',
    database: dbOk ? 'CONNECTED' : 'DISCONNECTED',
  });
});

// Authenticated detailed health metrics
router.get('/detailed', authenticateToken, async (req: Request, res: Response) => {
  const startTime = Date.now();
  const dbOk = await checkDbConnection();
  const dbLatencyMs = Date.now() - startTime;

  // Check Upstream Application health
  const apps = await prisma.protectedApp.findMany();
  let upstreamHealth: 'HEALTHY' | 'DEGRADED' | 'UNREACHABLE' = 'HEALTHY';

  try {
    if (apps.length > 0) {
      const firstApp = apps[0];
      const targetUrl = new URL(firstApp.upstreamUrl);
      const isReachable = await new Promise<boolean>((resolve) => {
        const pingReq = http.request(
          {
            hostname: targetUrl.hostname,
            port: targetUrl.port || 80,
            path: '/',
            method: 'HEAD',
            timeout: 1000,
          },
          (res) => resolve(res.statusCode! < 500)
        );
        pingReq.on('error', () => resolve(false));
        pingReq.on('timeout', () => {
          pingReq.destroy();
          resolve(false);
        });
        pingReq.end();
      });
      if (!isReachable) upstreamHealth = 'UNREACHABLE';
    }
  } catch {
    upstreamHealth = 'UNREACHABLE';
  }

  const memoryUsage = process.memoryUsage();

  res.json({
    status: dbOk ? 'HEALTHY' : 'DEGRADED',
    wafEngineStatus: 'ONLINE',
    databaseStatus: dbOk ? 'CONNECTED' : 'DISCONNECTED',
    databaseLatencyMs: dbLatencyMs,
    upstreamHealth,
    uptimeSeconds: Math.floor(process.uptime()),
    nodeVersion: process.version,
    memoryUsageMB: {
      rss: (memoryUsage.rss / 1024 / 1024).toFixed(2),
      heapTotal: (memoryUsage.heapTotal / 1024 / 1024).toFixed(2),
      heapUsed: (memoryUsage.heapUsed / 1024 / 1024).toFixed(2),
    },
    protectedAppsCount: apps.length,
    timestamp: new Date().toISOString(),
  });
});

export default router;
