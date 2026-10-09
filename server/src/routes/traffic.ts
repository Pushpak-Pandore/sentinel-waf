import { Router, Request, Response } from 'express';
import { authenticateToken } from '../middleware/auth';
import { prisma } from '../db/prisma';
import { addSseClient, removeSseClient } from '../services/eventLogger';

const router = Router();

// Traffic logs query with search, filter, pagination
router.get('/', authenticateToken, async (req: Request, res: Response) => {
  try {
    const page = parseInt((req.query.page as string) || '1', 10);
    const limit = parseInt((req.query.limit as string) || '20', 10);
    const search = (req.query.search as string) || '';
    const decision = (req.query.decision as string) || '';

    const where: any = {};
    if (decision) {
      where.decision = decision;
    }
    if (search) {
      where.OR = [
        { clientIp: { contains: search } },
        { path: { contains: search } },
        { correlationId: { contains: search } },
      ];
    }

    const [total, logs] = await Promise.all([
      prisma.trafficLog.count({ where }),
      prisma.trafficLog.findMany({
        where,
        orderBy: { timestamp: 'desc' },
        skip: (page - 1) * limit,
        take: limit,
        include: { protectedApp: true }
      }),
    ]);

    res.json({
      total,
      page,
      totalPages: Math.ceil(total / limit),
      logs,
    });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to fetch traffic logs', details: err.message });
  }
});

// CSV Export
router.get('/export', authenticateToken, async (req: Request, res: Response) => {
  try {
    const logs = await prisma.trafficLog.findMany({
      orderBy: { timestamp: 'desc' },
      take: 1000,
    });

    let csv = 'Timestamp,CorrelationID,ClientIP,Method,Path,StatusCode,DurationMs,Decision\n';
    for (const log of logs) {
      csv += `"${log.timestamp.toISOString()}","${log.correlationId}","${log.clientIp}","${log.method}","${log.path}",${log.statusCode},${log.durationMs},"${log.decision}"\n`;
    }

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=sentinel-traffic-logs.csv');
    res.status(200).send(csv);
  } catch (err: any) {
    res.status(500).json({ error: 'CSV export failed' });
  }
});

// Server-Sent Events (SSE) Stream
router.get('/stream', authenticateToken, (req: Request, res: Response) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  addSseClient(res);

  req.on('close', () => {
    removeSseClient(res);
  });
});

export default router;
