import { Router, Request, Response } from 'express';
import { z } from 'zod';
import { prisma } from '../db/prisma';
import { authenticateToken, requireRole } from '../middleware/auth';
import { logAudit } from '../services/auditLogger';
import { clearRateLimitCache } from '../engine/rateLimiter';

const router = Router();

const policySchema = z.object({
  name: z.string().min(2),
  scope: z.enum(['GLOBAL', 'IP', 'APP', 'ROUTE']),
  pathPattern: z.string().default('*'),
  windowMs: z.number().min(1000),
  maxRequests: z.number().min(1),
  burstLimit: z.number().default(20),
  action: z.enum(['RATE_LIMIT', 'BLOCK']).default('RATE_LIMIT'),
  enabled: z.boolean().default(true),
});

router.get('/', authenticateToken, async (req: Request, res: Response) => {
  try {
    const policies = await prisma.rateLimitPolicy.findMany({
      orderBy: { createdAt: 'desc' },
    });
    res.json(policies);
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to fetch rate limit policies' });
  }
});

router.post('/', authenticateToken, requireRole('ADMIN'), async (req: Request, res: Response): Promise<void> => {
  try {
    const data = policySchema.parse(req.body);
    const policy = await prisma.rateLimitPolicy.create({ data });

    clearRateLimitCache();
    await logAudit('RATE_POLICY_CREATE', 'RateLimitPolicy', policy.id, { name: policy.name }, req.user?.userId, req.user?.email, req.ip);

    res.status(201).json(policy);
  } catch (err: any) {
    res.status(400).json({ error: 'Failed to create rate limit policy', details: err.message });
  }
});

router.put('/:id', authenticateToken, requireRole('ADMIN'), async (req: Request, res: Response): Promise<void> => {
  try {
    const data = policySchema.partial().parse(req.body);
    const updated = await prisma.rateLimitPolicy.update({
      where: { id: req.params.id },
      data,
    });

    clearRateLimitCache();
    await logAudit('RATE_POLICY_UPDATE', 'RateLimitPolicy', updated.id, { name: updated.name }, req.user?.userId, req.user?.email, req.ip);

    res.json(updated);
  } catch (err: any) {
    res.status(400).json({ error: 'Failed to update policy' });
  }
});

router.delete('/:id', authenticateToken, requireRole('ADMIN'), async (req: Request, res: Response): Promise<void> => {
  try {
    await prisma.rateLimitPolicy.delete({ where: { id: req.params.id } });
    clearRateLimitCache();
    await logAudit('RATE_POLICY_DELETE', 'RateLimitPolicy', req.params.id, undefined, req.user?.userId, req.user?.email, req.ip);
    res.json({ success: true });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to delete policy' });
  }
});

export default router;
