import { Router, Request, Response } from 'express';
import { z } from 'zod';
import http from 'http';
import { prisma } from '../db/prisma';
import { authenticateToken, requireRole } from '../middleware/auth';
import { logAudit } from '../services/auditLogger';
import { validateUpstreamUrl } from '../engine/proxy';

const router = Router();

const appSchema = z.object({
  appId: z.string().min(2),
  name: z.string().min(2),
  host: z.string().min(1),
  upstreamUrl: z.string().url(),
  enabled: z.boolean().default(true),
  wafMode: z.enum(['INHERIT', 'PREVENTION', 'DETECTION', 'DISABLED']).default('INHERIT'),
  requestLimit: z.number().default(100),
});

router.get('/', authenticateToken, async (req: Request, res: Response) => {
  try {
    const apps = await prisma.protectedApp.findMany({
      orderBy: { createdAt: 'desc' },
      include: {
        _count: {
          select: { events: true, trafficLogs: true }
        }
      }
    });
    res.json(apps);
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to fetch protected applications' });
  }
});

router.post('/', authenticateToken, requireRole('ADMIN'), async (req: Request, res: Response): Promise<void> => {
  try {
    const data = appSchema.parse(req.body);

    if (!validateUpstreamUrl(data.upstreamUrl)) {
      res.status(400).json({ error: 'SSRF Violation: Invalid or disallowed upstream URL destination.' });
      return;
    }

    const app = await prisma.protectedApp.create({ data });

    await logAudit('PROTECTED_APP_CREATE', 'ProtectedApp', app.id, { appId: app.appId, upstreamUrl: app.upstreamUrl }, req.user?.userId, req.user?.email, req.ip);

    res.status(201).json(app);
  } catch (err: any) {
    res.status(400).json({ error: 'Failed to register application', details: err.message });
  }
});

router.put('/:id', authenticateToken, requireRole('ADMIN'), async (req: Request, res: Response): Promise<void> => {
  try {
    const data = appSchema.partial().parse(req.body);

    if (data.upstreamUrl && !validateUpstreamUrl(data.upstreamUrl)) {
      res.status(400).json({ error: 'SSRF Violation: Disallowed upstream destination.' });
      return;
    }

    const updated = await prisma.protectedApp.update({
      where: { id: req.params.id },
      data,
    });

    await logAudit('PROTECTED_APP_UPDATE', 'ProtectedApp', updated.id, { appId: updated.appId }, req.user?.userId, req.user?.email, req.ip);

    res.json(updated);
  } catch (err: any) {
    res.status(400).json({ error: 'Failed to update application' });
  }
});

router.delete('/:id', authenticateToken, requireRole('ADMIN'), async (req: Request, res: Response): Promise<void> => {
  try {
    await prisma.protectedApp.delete({ where: { id: req.params.id } });
    await logAudit('PROTECTED_APP_DELETE', 'ProtectedApp', req.params.id, undefined, req.user?.userId, req.user?.email, req.ip);
    res.json({ success: true });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to delete application' });
  }
});

// Test upstream application health connectivity
router.post('/:id/check-health', authenticateToken, async (req: Request, res: Response): Promise<void> => {
  try {
    const app = await prisma.protectedApp.findUnique({ where: { id: req.params.id } });
    if (!app) {
      res.status(404).json({ error: 'App not found' });
      return;
    }

    const targetUrl = new URL(app.upstreamUrl);

    const startTime = Date.now();
    const reqOpts = {
      hostname: targetUrl.hostname,
      port: targetUrl.port || 80,
      path: '/',
      method: 'GET',
      timeout: 3000,
    };

    const clientReq = http.request(reqOpts, async (upstreamRes) => {
      const isOk = (upstreamRes.statusCode || 500) < 400;
      const statusStr = isOk ? 'HEALTHY' : 'DEGRADED';

      await prisma.protectedApp.update({
        where: { id: app.id },
        data: { healthStatus: statusStr }
      });

      res.json({
        appId: app.appId,
        upstreamUrl: app.upstreamUrl,
        healthStatus: statusStr,
        statusCode: upstreamRes.statusCode,
        latencyMs: Date.now() - startTime,
      });
    });

    clientReq.on('error', async (err) => {
      await prisma.protectedApp.update({
        where: { id: app.id },
        data: { healthStatus: 'UNREACHABLE' }
      });

      res.json({
        appId: app.appId,
        upstreamUrl: app.upstreamUrl,
        healthStatus: 'UNREACHABLE',
        error: err.message,
      });
    });

    clientReq.on('timeout', () => {
      clientReq.destroy();
    });

    clientReq.end();
  } catch (err: any) {
    res.status(500).json({ error: 'Health check failed' });
  }
});

export default router;
