import { Router, Request, Response } from 'express';
import { z } from 'zod';
import { prisma } from '../db/prisma';
import { authenticateToken, requireRole } from '../middleware/auth';
import { logAudit } from '../services/auditLogger';
import { safeRegexMatch } from '../engine/ruleMatcher';

const router = Router();

const ruleSchema = z.object({
  ruleId: z.string().min(3),
  name: z.string().min(3),
  description: z.string(),
  category: z.enum(['SQLI', 'XSS', 'CSRF', 'DOS', 'LFI', 'REMOTE_ACCESS', 'MALFORMED', 'BOT']),
  severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']),
  enabled: z.boolean().default(true),
  action: z.enum(['BLOCK', 'LOG', 'ALLOW']),
  matchType: z.enum(['REGEX', 'CONTAINS', 'EXACT', 'HEADER_PRESENT']),
  targetField: z.enum(['QUERY', 'BODY', 'PATH', 'HEADER', 'METHOD', 'FULL_URL']),
  pattern: z.string().min(1),
});

// List rules
router.get('/', authenticateToken, async (req: Request, res: Response) => {
  try {
    const category = req.query.category as string;
    const where: any = {};
    if (category) where.category = category;

    const rules = await prisma.wafRule.findMany({
      where,
      orderBy: { ruleId: 'asc' },
    });
    res.json(rules);
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to fetch rules' });
  }
});

// Create rule
router.post('/', authenticateToken, requireRole('ADMIN'), async (req: Request, res: Response): Promise<void> => {
  try {
    const data = ruleSchema.parse(req.body);

    // Validate regex pattern if matchType is REGEX
    if (data.matchType === 'REGEX') {
      try {
        let pat = data.pattern;
        if (pat.startsWith('(?i)')) pat = pat.substring(4);
        new RegExp(pat);
      } catch {
        res.status(400).json({ error: 'Invalid regular expression pattern' });
        return;
      }
    }

    const rule = await prisma.wafRule.create({ data });

    await logAudit('RULE_CREATE', 'WafRule', rule.id, { ruleId: rule.ruleId, name: rule.name }, req.user?.userId, req.user?.email, req.ip);

    res.status(201).json(rule);
  } catch (err: any) {
    res.status(400).json({ error: 'Bad request', details: err.message });
  }
});

// Update rule
router.put('/:id', authenticateToken, requireRole('ADMIN'), async (req: Request, res: Response): Promise<void> => {
  try {
    const data = ruleSchema.partial().parse(req.body);

    const existing = await prisma.wafRule.findUnique({ where: { id: req.params.id } });
    if (!existing) {
      res.status(404).json({ error: 'Rule not found' });
      return;
    }

    const updated = await prisma.wafRule.update({
      where: { id: req.params.id },
      data: {
        ...data,
        version: existing.version + 1,
      },
    });

    await logAudit('RULE_UPDATE', 'WafRule', updated.id, { ruleId: updated.ruleId, newVersion: updated.version }, req.user?.userId, req.user?.email, req.ip);

    res.json(updated);
  } catch (err: any) {
    res.status(400).json({ error: 'Update failed', details: err.message });
  }
});

// Toggle rule state
router.patch('/:id/toggle', authenticateToken, requireRole('ADMIN'), async (req: Request, res: Response): Promise<void> => {
  try {
    const existing = await prisma.wafRule.findUnique({ where: { id: req.params.id } });
    if (!existing) {
      res.status(404).json({ error: 'Rule not found' });
      return;
    }

    const updated = await prisma.wafRule.update({
      where: { id: req.params.id },
      data: { enabled: !existing.enabled },
    });

    await logAudit('RULE_TOGGLE', 'WafRule', updated.id, { enabled: updated.enabled }, req.user?.userId, req.user?.email, req.ip);

    res.json(updated);
  } catch (err: any) {
    res.status(500).json({ error: 'Toggle failed' });
  }
});

// Delete rule
router.delete('/:id', authenticateToken, requireRole('ADMIN'), async (req: Request, res: Response): Promise<void> => {
  try {
    const rule = await prisma.wafRule.delete({ where: { id: req.params.id } });
    await logAudit('RULE_DELETE', 'WafRule', req.params.id, { ruleId: rule.ruleId }, req.user?.userId, req.user?.email, req.ip);
    res.json({ success: true, message: 'Rule deleted successfully' });
  } catch (err: any) {
    res.status(500).json({ error: 'Delete failed' });
  }
});

// Test rule against input string
router.post('/test', authenticateToken, (req: Request, res: Response): void => {
  const { matchType, pattern, testInput } = req.body || {};

  if (!pattern || testInput === undefined) {
    res.status(400).json({ error: 'Pattern and testInput required' });
    return;
  }

  let isMatch = false;
  if (matchType === 'REGEX') {
    isMatch = safeRegexMatch(pattern, String(testInput));
  } else if (matchType === 'CONTAINS') {
    isMatch = String(testInput).toLowerCase().includes(pattern.toLowerCase());
  } else {
    isMatch = String(testInput) === pattern;
  }

  res.json({
    isMatch,
    pattern,
    matchType,
    testInput,
    explanation: isMatch ? 'Rule MATCHED the test input fixture.' : 'Rule DID NOT MATCH the test input fixture.',
  });
});

export default router;
