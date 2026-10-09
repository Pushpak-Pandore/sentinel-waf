import { Router, Request, Response } from 'express';
import { z } from 'zod';
import { prisma } from '../db/prisma';
import { authenticateToken, requireRole } from '../middleware/auth';
import { logAudit } from '../services/auditLogger';

const router = Router();

const exceptionSchema = z.object({
  appId: z.string().default('*'),
  pathPattern: z.string().default('*'),
  method: z.string().default('*'),
  ruleId: z.string().min(1),
  justification: z.string().min(3),
  expiresInDays: z.number().optional(),
});

router.get('/', authenticateToken, async (req: Request, res: Response) => {
  try {
    const exceptions = await prisma.wafException.findMany({
      orderBy: { createdAt: 'desc' },
    });
    res.json(exceptions);
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to fetch WAF exceptions' });
  }
});

router.post('/', authenticateToken, requireRole('ADMIN'), async (req: Request, res: Response): Promise<void> => {
  try {
    const { appId, pathPattern, method, ruleId, justification, expiresInDays } = exceptionSchema.parse(req.body);

    let expiresAt: Date | null = null;
    if (expiresInDays && expiresInDays > 0) {
      expiresAt = new Date(Date.now() + expiresInDays * 24 * 3600 * 1000);
    }

    const exception = await prisma.wafException.create({
      data: {
        appId,
        pathPattern,
        method: method.toUpperCase(),
        ruleId,
        justification,
        expiresAt,
        createdBy: req.user?.email || 'ADMIN',
      },
    });

    await logAudit('EXCEPTION_CREATE', 'WafException', exception.id, { ruleId, pathPattern, justification }, req.user?.userId, req.user?.email, req.ip);

    res.status(201).json(exception);
  } catch (err: any) {
    res.status(400).json({ error: 'Failed to create exception', details: err.message });
  }
});

router.delete('/:id', authenticateToken, requireRole('ADMIN'), async (req: Request, res: Response): Promise<void> => {
  try {
    await prisma.wafException.delete({ where: { id: req.params.id } });
    await logAudit('EXCEPTION_DELETE', 'WafException', req.params.id, undefined, req.user?.userId, req.user?.email, req.ip);
    res.json({ success: true });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to delete exception' });
  }
});

export default router;
