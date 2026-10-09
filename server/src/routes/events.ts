import { Router, Request, Response } from 'express';
import { authenticateToken } from '../middleware/auth';
import { prisma } from '../db/prisma';

const router = Router();

router.get('/', authenticateToken, async (req: Request, res: Response) => {
  try {
    const page = parseInt((req.query.page as string) || '1', 10);
    const limit = parseInt((req.query.limit as string) || '20', 10);
    const category = (req.query.category as string) || '';
    const severity = (req.query.severity as string) || '';
    const search = (req.query.search as string) || '';

    const where: any = {};
    if (category) where.category = category;
    if (severity) where.severity = severity;
    if (search) {
      where.OR = [
        { clientIp: { contains: search } },
        { path: { contains: search } },
        { correlationId: { contains: search } },
        { explanation: { contains: search } },
      ];
    }

    const [total, events] = await Promise.all([
      prisma.securityEvent.count({ where }),
      prisma.securityEvent.findMany({
        where,
        orderBy: { timestamp: 'desc' },
        skip: (page - 1) * limit,
        take: limit,
        include: { protectedApp: true },
      }),
    ]);

    res.json({
      total,
      page,
      totalPages: Math.ceil(total / limit),
      events,
    });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to fetch security events', details: err.message });
  }
});

router.get('/:id', authenticateToken, async (req: Request, res: Response): Promise<void> => {
  try {
    const event = await prisma.securityEvent.findUnique({
      where: { id: req.params.id },
      include: { protectedApp: true },
    });
    if (!event) {
      res.status(404).json({ error: 'Event not found' });
      return;
    }
    res.json(event);
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to fetch event details' });
  }
});

export default router;
