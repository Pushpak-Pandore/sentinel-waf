import { Router, Request, Response } from 'express';
import { z } from 'zod';
import { prisma } from '../db/prisma';
import { authenticateToken, requireRole } from '../middleware/auth';
import { logAudit } from '../services/auditLogger';

const router = Router();

const patchSchema = z.object({
  patchId: z.string().min(3),
  name: z.string().min(3),
  appId: z.string().default('*'),
  pathPattern: z.string().min(1),
  method: z.string().default('*'),
  targetField: z.enum(['QUERY', 'BODY', 'PATH', 'HEADER', 'FULL_URL']).default('FULL_URL'),
  pattern: z.string().min(1),
  action: z.enum(['BLOCK', 'LOG']).default('BLOCK'),
  enabled: z.boolean().default(true),
  expiresInDays: z.number().optional(),
});

router.get('/', authenticateToken, async (req: Request, res: Response) => {
  try {
    const patches = await prisma.virtualPatch.findMany({
      orderBy: { createdAt: 'desc' },
    });
    res.json(patches);
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to fetch virtual patches' });
  }
});

router.post('/', authenticateToken, requireRole('ADMIN'), async (req: Request, res: Response): Promise<void> => {
  try {
    const { patchId, name, appId, pathPattern, method, targetField, pattern, action, enabled, expiresInDays } = patchSchema.parse(req.body);

    let expiresAt: Date | null = null;
    if (expiresInDays && expiresInDays > 0) {
      expiresAt = new Date(Date.now() + expiresInDays * 24 * 3600 * 1000);
    }

    const patch = await prisma.virtualPatch.create({
      data: {
        patchId,
        name,
        appId,
        pathPattern,
        method: method.toUpperCase(),
        targetField,
        pattern,
        action,
        enabled,
        expiresAt,
      },
    });

    await logAudit('VIRTUAL_PATCH_CREATE', 'VirtualPatch', patch.id, { patchId, name, pathPattern }, req.user?.userId, req.user?.email, req.ip);

    res.status(201).json(patch);
  } catch (err: any) {
    res.status(400).json({ error: 'Failed to create virtual patch', details: err.message });
  }
});

router.delete('/:id', authenticateToken, requireRole('ADMIN'), async (req: Request, res: Response): Promise<void> => {
  try {
    await prisma.virtualPatch.delete({ where: { id: req.params.id } });
    await logAudit('VIRTUAL_PATCH_DELETE', 'VirtualPatch', req.params.id, undefined, req.user?.userId, req.user?.email, req.ip);
    res.json({ success: true });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to delete virtual patch' });
  }
});

export default router;
