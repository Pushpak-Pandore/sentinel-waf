import { prisma } from '../db/prisma';
import { RequestContext, WafInspectionResult } from '../types/waf';
import { Response } from 'express';
import { forwardEventToSiem } from '../engine/siemForwarder';

// SSE Clients list for live traffic stream
const sseClients: Response[] = [];

export function addSseClient(res: Response): void {
  sseClients.push(res);
}

export function removeSseClient(res: Response): void {
  const idx = sseClients.indexOf(res);
  if (idx !== -1) {
    sseClients.splice(idx, 1);
  }
}

export function broadcastSse(eventData: any): void {
  const payload = `data: ${JSON.stringify(eventData)}\n\n`;
  for (const client of sseClients) {
    client.write(payload);
  }
}

/**
 * Persists security events and traffic logs into DB
 */
export async function logWafEvent(
  context: RequestContext,
  result: WafInspectionResult,
  finalStatus: number,
  durationMs: number
): Promise<void> {
  try {
    // Resolve protected app id if context.appId is provided
    let appDbId: string | null = null;
    if (context.appId) {
      const app = await prisma.protectedApp.findFirst({
        where: { OR: [{ id: context.appId }, { appId: context.appId }] }
      });
      if (app) appDbId = app.id;
    }

    // 1. Record TrafficLog entry for all traffic
    const trafficEntry = await prisma.trafficLog.create({
      data: {
        correlationId: context.correlationId,
        clientIp: context.clientIp,
        method: context.method,
        path: context.path,
        statusCode: finalStatus,
        durationMs,
        decision: result.decision,
        appId: appDbId,
        countryCode: result.countryCode || 'UNKNOWN',
        countryName: result.countryName || 'Unknown Country',
      },
    });

    // Broadcast live traffic event to connected SSE frontend dashboards
    broadcastSse({
      type: 'TRAFFIC_LOG',
      data: {
        id: trafficEntry.id,
        correlationId: context.correlationId,
        clientIp: context.clientIp,
        ipVersion: context.ipVersion,
        method: context.method,
        path: context.path,
        statusCode: finalStatus,
        durationMs,
        decision: result.decision,
        category: result.category,
        severity: result.severity,
        countryCode: result.countryCode || 'UNKNOWN',
        countryName: result.countryName || 'Unknown Country',
        timestamp: trafficEntry.timestamp,
      },
    });

    // 2. If request triggered a non-ALLOW decision or matched security rules, create SecurityEvent record
    if (result.decision !== 'ALLOW' || result.matchedRules.length > 0) {
      const secEvent = await prisma.securityEvent.create({
        data: {
          correlationId: context.correlationId,
          clientIp: context.clientIp,
          ipVersion: context.ipVersion,
          method: context.method,
          path: context.path,
          appId: appDbId,
          status: finalStatus,
          matchedRuleId: result.matchedRuleId || null,
          category: result.category,
          severity: result.severity,
          decision: result.decision,
          explanation: result.explanation,
          durationMs,
          requestHeaders: JSON.stringify(sanitizeHeaders(context.headers)),
          queryParams: JSON.stringify(context.query),
          requestBody: sanitizeBody(context.body),
          userAgent: context.userAgent || null,
          countryCode: result.countryCode || 'UNKNOWN',
          countryName: result.countryName || 'Unknown Country',
          mlAnomalyScore: result.mlAnomalyScore || 0,
          mlPrediction: result.mlPrediction || 'NORMAL',
          mlFeatureMeta: result.mlFeatureMeta || null,
        },
      });

      broadcastSse({
        type: 'SECURITY_EVENT',
        data: secEvent,
      });

      // Forward security event asynchronously to active SIEM webhooks
      forwardEventToSiem(secEvent).catch((err) => {
        console.error('[EventLogger] SIEM forwarding dispatch error:', err);
      });
    }
  } catch (err) {
    console.error('[EventLogger] Failed to persist WAF event:', err);
  }
}

function sanitizeHeaders(headers: Record<string, any>): Record<string, any> {
  const clean: Record<string, any> = {};
  for (const [key, val] of Object.entries(headers)) {
    const kLower = key.toLowerCase();
    if (kLower.includes('auth') || kLower.includes('cookie') || kLower.includes('secret') || kLower.includes('key')) {
      clean[key] = '***REDACTED***';
    } else {
      clean[key] = val;
    }
  }
  return clean;
}

function sanitizeBody(body: any): string {
  if (!body) return '';
  const str = typeof body === 'object' ? JSON.stringify(body) : String(body);
  return str
    .replace(/(password|passwd|token|secret|cvv|card)\s*":\s*"[^"]+"/gi, '$1":"***REDACTED***"')
    .substring(0, 1000);
}
