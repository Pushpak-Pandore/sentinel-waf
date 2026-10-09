import http from 'http';
import https from 'https';
import crypto from 'crypto';
import { URL } from 'url';
import { prisma } from '../db/prisma';
import { SecurityEvent } from '@prisma/client';

export interface SiemDeliveryResult {
  webhookId: string;
  url: string;
  success: boolean;
  statusCode?: number;
  error?: string;
}

/**
 * Asynchronously forwards security events to active SIEM webhooks
 */
export async function forwardEventToSiem(event: SecurityEvent): Promise<SiemDeliveryResult[]> {
  let webhooks: any[] = [];
  try {
    webhooks = await prisma.siemWebhook.findMany({
      where: { enabled: true }
    });
  } catch {
    webhooks = [];
  }

  if (webhooks.length === 0) return [];

  const results: SiemDeliveryResult[] = [];

  const payload = JSON.stringify({
    eventSource: 'Sentinel-WAF-SIEM-Forwarder-v1',
    eventID: event.id,
    correlationID: event.correlationId,
    clientIP: event.clientIp,
    ipVersion: event.ipVersion,
    method: event.method,
    path: event.path,
    category: event.category,
    severity: event.severity,
    decision: event.decision,
    explanation: event.explanation,
    anomalyScore: event.anomalyScore,
    matchedRuleID: event.matchedRuleId,
    timestamp: event.timestamp.toISOString(),
  });

  for (const hook of webhooks) {
    // Check minimum severity filter
    if (!shouldForwardSeverity(event.severity, hook.minSeverity)) continue;

    deliverWithRetry(hook, payload)
      .then((res) => results.push(res))
      .catch((err) => console.error(`[SIEM Delivery Error] Webhook ${hook.id}:`, err));
  }

  return results;
}

async function deliverWithRetry(webhook: any, payload: string, maxAttempts: number = 2): Promise<SiemDeliveryResult> {
  let attempts = 0;
  let lastError = '';

  while (attempts < maxAttempts) {
    attempts++;
    try {
      const res = await sendHttpRequest(webhook.url, webhook.secret, payload);
      if (res.statusCode >= 200 && res.statusCode < 300) {
        await prisma.siemWebhook.update({
          where: { id: webhook.id },
          data: {
            successCount: { increment: 1 },
            lastDeliveryAt: new Date(),
          }
        });
        return { webhookId: webhook.id, url: webhook.url, success: true, statusCode: res.statusCode };
      }
      lastError = `HTTP ${res.statusCode}`;
    } catch (err: any) {
      lastError = err.message;
    }
    // Exponential backoff delay
    await new Promise(r => setTimeout(r, 200 * Math.pow(2, attempts)));
  }

  await prisma.siemWebhook.update({
    where: { id: webhook.id },
    data: { failureCount: { increment: 1 } }
  });

  return { webhookId: webhook.id, url: webhook.url, success: false, error: lastError };
}

function sendHttpRequest(targetUrl: string, secret: string | null, payload: string): Promise<{ statusCode: number }> {
  return new Promise((resolve, reject) => {
    try {
      const url = new URL(targetUrl);
      const isHttps = url.protocol === 'https:';
      const client = isHttps ? https : http;

      // Generate dynamic HMAC signature if secret exists, else dynamic session token
      const signature = secret
        ? crypto.createHmac('sha256', secret).update(payload).digest('hex')
        : `sha256=${crypto.createHash('sha256').update(payload).digest('hex')}`;

      const req = client.request(
        {
          hostname: url.hostname,
          port: url.port || (isHttps ? 443 : 80),
          path: url.pathname + url.search,
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Sentinel-SIEM-Signature': signature,
            'Content-Length': Buffer.byteLength(payload),
          },
          timeout: 3000,
        },
        (res) => resolve({ statusCode: res.statusCode || 500 })
      );

      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('SIEM delivery timeout'));
      });

      req.write(payload);
      req.end();
    } catch (err) {
      reject(err);
    }
  });
}

function shouldForwardSeverity(eventSeverity: string, minSeverity: string): boolean {
  const levels = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  const eIdx = levels.indexOf(eventSeverity);
  const mIdx = levels.indexOf(minSeverity);
  return eIdx >= mIdx;
}
