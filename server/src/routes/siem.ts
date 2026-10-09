import { Router, Request, Response } from 'express';
import { z } from 'zod';
import { prisma } from '../db/prisma';
import { authenticateToken, requireRole } from '../middleware/auth';
import { logAudit } from '../services/auditLogger';
import { forwardEventToSiem } from '../engine/siemForwarder';

const router = Router();

const siemSchema = z.object({
  name: z.string().min(2),
  url: z.string().url(),
  secret: z.string().optional(),
  enabled: z.boolean().default(true),
  minSeverity: z.enum(['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).default('MEDIUM'),
});

router.get('/', authenticateToken, async (req: Request, res: Response) => {
  try {
    const webhooks = await prisma.siemWebhook.findMany({
      orderBy: { createdAt: 'desc' },
    });
    res.json(webhooks);
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to fetch SIEM webhooks' });
  }
});

router.post('/', authenticateToken, requireRole('ADMIN'), async (req: Request, res: Response): Promise<void> => {
  try {
    const data = siemSchema.parse(req.body);
    const webhook = await prisma.siemWebhook.create({ data });

    await logAudit('SIEM_WEBHOOK_CREATE', 'SiemWebhook', webhook.id, { name: webhook.name, url: webhook.url }, req.user?.userId, req.user?.email, req.ip);

    res.status(201).json(webhook);
  } catch (err: any) {
    res.status(400).json({ error: 'Failed to create SIEM webhook', details: err.message });
  }
});

router.delete('/:id', authenticateToken, requireRole('ADMIN'), async (req: Request, res: Response): Promise<void> => {
  try {
    await prisma.siemWebhook.delete({ where: { id: req.params.id } });
    await logAudit('SIEM_WEBHOOK_DELETE', 'SiemWebhook', req.params.id, undefined, req.user?.userId, req.user?.email, req.ip);
    res.json({ success: true });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to delete SIEM webhook' });
  }
});

// Test delivery endpoint
router.post('/:id/test', authenticateToken, async (req: Request, res: Response): Promise<void> => {
  try {
    const webhook = await prisma.siemWebhook.findUnique({ where: { id: req.params.id } });
    if (!webhook) {
      res.status(404).json({ error: 'Webhook not found' });
      return;
    }

    const mockEvent = {
      id: 'test-event-uuid-001',
      correlationId: 'req-siem-test-100',
      clientIp: '198.51.100.50',
      ipVersion: 'IPv4',
      method: 'POST',
      path: '/api/v1/test',
      appId: null,
      status: 403,
      matchedRuleId: 'CRS-942-100',
      category: 'SQLI',
      severity: 'CRITICAL',
      decision: 'BLOCK',
      explanation: 'SIEM Delivery Verification Mock Event',
      anomalyScore: 5,
      inboundThreshold: 5,
      candidateDecision: 'PROJECTED_BLOCK',
      durationMs: 1.5,
      requestHeaders: null,
      queryParams: null,
      requestBody: null,
      userAgent: 'Sentinel-SIEM-Tester/1.0',
      countryCode: 'LOCAL',
      countryName: 'Local Network',
      mlAnomalyScore: 0.1,
      mlPrediction: 'NORMAL',
      mlFeatureMeta: null,
      timestamp: new Date(),
    };

    const deliveryResults = await forwardEventToSiem(mockEvent);

    res.json({
      webhookId: webhook.id,
      url: webhook.url,
      results: deliveryResults,
      message: 'Test event dispatched to SIEM webhook.',
    });
  } catch (err: any) {
    res.status(500).json({ error: 'SIEM test failed', details: err.message });
  }
});

export default router;
