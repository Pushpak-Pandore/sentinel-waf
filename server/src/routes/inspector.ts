import { Router, Request, Response } from 'express';
import { authenticateToken } from '../middleware/auth';
import { buildRequestContext, inspectRequest } from '../engine/pipeline';
import { logWafEvent } from '../services/eventLogger';
import { prisma } from '../db/prisma';

const router = Router();

router.post('/execute', authenticateToken, async (req: Request, res: Response): Promise<void> => {
  try {
    const { method = 'GET', path = '/', query = {}, headers = {}, body = {}, appId } = req.body || {};

    let targetAppUrl = 'http://localhost:5001'; // Default local test upstream
    if (appId) {
      const app = await prisma.protectedApp.findUnique({ where: { id: appId } });
      if (app) targetAppUrl = app.upstreamUrl;
    }

    // Synthesize mock Express request context
    const mockReq = {
      method: method.toUpperCase(),
      path,
      originalUrl: `${path}${Object.keys(query).length > 0 ? '?' + new URLSearchParams(query).toString() : ''}`,
      url: path,
      headers: {
        'user-agent': 'Sentinel-Request-Inspector/1.0',
        'content-type': 'application/json',
        ...headers,
      },
      query,
      body,
      socket: { remoteAddress: '127.0.0.1' },
      protocol: 'http',
    } as any;

    const context = buildRequestContext(mockReq, appId, targetAppUrl);
    const result = await inspectRequest(context);

    // Persist event in database so it appears in Live Traffic & Security Events
    await logWafEvent(context, result, result.statusCode, result.durationMs);

    res.json({
      requestContext: {
        correlationId: context.correlationId,
        clientIp: context.clientIp,
        ipVersion: context.ipVersion,
        method: context.method,
        path: context.path,
        headers: context.headers,
        query: context.query,
        body: context.body,
        targetAppUrl,
      },
      inspectionResult: {
        decision: result.decision,
        effectiveMode: result.effectiveMode,
        statusCode: result.statusCode,
        category: result.category,
        severity: result.severity,
        explanation: result.explanation,
        riskScore: result.riskScore,
        matchedRuleId: result.matchedRuleId,
        matchedRulesCount: result.matchedRules.length,
        matchedRules: result.matchedRules,
        durationMs: result.durationMs,
      },
    });
  } catch (err: any) {
    res.status(500).json({ error: 'Inspector execution failed', details: err.message });
  }
});

export default router;
