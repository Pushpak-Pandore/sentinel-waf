import { Router, Request, Response } from 'express';
import { z } from 'zod';
import { prisma } from '../db/prisma';
import { authenticateToken, requireRole } from '../middleware/auth';
import { logAudit } from '../services/auditLogger';
import { normalizeIp, matchIpOrCidr } from '../engine/ipEvaluator';

const router = Router();

const ipRuleSchema = z.object({
  ipOrCidr: z.string().min(1),
  type: z.enum(['ALLOW', 'BLOCK']),
  description: z.string().optional(),
  reason: z.string().optional(),
  expiresInDays: z.number().optional(),
});

router.get('/', authenticateToken, async (req: Request, res: Response) => {
  try {
    const rules = await prisma.ipAccessRule.findMany({
      orderBy: { createdAt: 'desc' },
    });
    res.json(rules);
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to fetch IP access rules' });
  }
});

router.post('/', authenticateToken, requireRole('ADMIN'), async (req: Request, res: Response): Promise<void> => {
  try {
    const { ipOrCidr, type, description, reason, expiresInDays } = ipRuleSchema.parse(req.body);

    const { version } = normalizeIp(ipOrCidr.split('/')[0]);

    let expiresAt: Date | null = null;
    if (expiresInDays && expiresInDays > 0) {
      expiresAt = new Date(Date.now() + expiresInDays * 24 * 3600 * 1000);
    }

    const rule = await prisma.ipAccessRule.create({
      data: {
        ipOrCidr: ipOrCidr.trim(),
        ipVersion: version,
        type,
        description: description || null,
        reason: reason || null,
        expiresAt,
      },
    });

    await logAudit(`IP_${type}_ADD`, 'IpAccessRule', rule.id, { ipOrCidr: rule.ipOrCidr }, req.user?.userId, req.user?.email, req.ip);

    res.status(201).json(rule);
  } catch (err: any) {
    res.status(400).json({ error: 'Failed to create IP rule', details: err.message });
  }
});

router.delete('/:id', authenticateToken, requireRole('ADMIN'), async (req: Request, res: Response): Promise<void> => {
  try {
    const rule = await prisma.ipAccessRule.delete({ where: { id: req.params.id } });
    await logAudit('IP_RULE_DELETE', 'IpAccessRule', req.params.id, { ipOrCidr: rule.ipOrCidr }, req.user?.userId, req.user?.email, req.ip);
    res.json({ success: true });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to delete IP access rule' });
  }
});

// Test CIDR matching endpoint
router.post('/check', authenticateToken, (req: Request, res: Response): void => {
  const { testIp, rulePattern } = req.body || {};
  if (!testIp || !rulePattern) {
    res.status(400).json({ error: 'testIp and rulePattern required' });
    return;
  }

  const isMatch = matchIpOrCidr(testIp, rulePattern);
  const normTarget = normalizeIp(testIp);

  res.json({
    testIp,
    normalizedIp: normTarget.ip,
    ipVersion: normTarget.version,
    rulePattern,
    isMatch,
    explanation: isMatch
      ? `IP '${testIp}' MATCHES CIDR block/entry '${rulePattern}'.`
      : `IP '${testIp}' DOES NOT MATCH CIDR block/entry '${rulePattern}'.`,
  });
});

export default router;
