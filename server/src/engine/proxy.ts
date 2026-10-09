import { Request, Response } from 'express';
import http from 'http';
import https from 'https';
import { URL } from 'url';
import { RequestContext } from '../types/waf';
import { normalizeIp } from './ipEvaluator';

// Hop-by-hop headers to strip
const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailers',
  'transfer-encoding',
  'upgrade',
]);

/**
 * Validates upstream URL for SSRF protection
 */
export function validateUpstreamUrl(targetUrl: string, allowedHosts: string[] = ['*']): boolean {
  try {
    const parsed = new URL(targetUrl);
    const host = parsed.hostname.toLowerCase();

    // Block cloud metadata services and dangerous internal SSRF vectors
    if (
      host === '169.254.169.254' ||
      host === 'metadata.google.internal' ||
      host.endsWith('.metadata.google.internal')
    ) {
      return false;
    }

    // Require valid http: or https: scheme
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return false;
    }

    // Check optional environment host restriction if explicitly configured
    const envAllowed = process.env.ALLOWED_UPSTREAM_HOSTS
      ? process.env.ALLOWED_UPSTREAM_HOSTS.split(',').map((h) => h.trim().toLowerCase())
      : null;

    if (envAllowed && envAllowed.length > 0 && !envAllowed.includes('*')) {
      return envAllowed.includes(host) || host === 'localhost' || host === '127.0.0.1';
    }

    return true;
  } catch {
    return false;
  }
}

/**
 * Forwards HTTP request to upstream origin and returns response to client
 */
export function forwardToUpstream(
  req: Request,
  res: Response,
  upstreamTargetUrl: string,
  context: RequestContext
): Promise<{ statusCode: number; durationMs: number }> {
  return new Promise((resolve) => {
    const startTime = Date.now();

    try {
      const target = new URL(upstreamTargetUrl);
      const isHttps = target.protocol === 'https:';

      const pathAndQuery = req.originalUrl || req.url;
      const fullPath = target.pathname === '/' ? pathAndQuery : `${target.pathname.replace(/\/$/, '')}${pathAndQuery}`;

      // Prepare headers
      const forwardedHeaders: Record<string, string | string[] | undefined> = {};
      for (const [key, value] of Object.entries(req.headers)) {
        if (!HOP_BY_HOP_HEADERS.has(key.toLowerCase())) {
          forwardedHeaders[key] = value;
        }
      }

      // Add standard proxy tracking headers
      forwardedHeaders['x-forwarded-for'] = context.clientIp;
      forwardedHeaders['x-forwarded-proto'] = req.protocol;
      forwardedHeaders['x-forwarded-host'] = req.headers.host || '';
      forwardedHeaders['x-sentinel-request-id'] = context.correlationId;
      forwardedHeaders['host'] = target.host;

      const clientModule = isHttps ? https : http;

      const proxyReq = clientModule.request(
        {
          hostname: target.hostname,
          port: target.port || (isHttps ? 443 : 80),
          method: req.method,
          path: fullPath,
          headers: forwardedHeaders as http.OutgoingHttpHeaders,
          timeout: 10000, // 10s upstream timeout
        },
        (upstreamRes) => {
          const statusCode = upstreamRes.statusCode || 200;

          // Set client response status & security headers
          res.status(statusCode);

          // Copy upstream headers to client response (excluding hop-by-hop)
          for (const [key, value] of Object.entries(upstreamRes.headers)) {
            if (!HOP_BY_HOP_HEADERS.has(key.toLowerCase()) && value !== undefined) {
              res.setHeader(key, value);
            }
          }

          // Inject Sentinel WAF headers
          res.setHeader('X-Sentinel-WAF', 'Active');
          res.setHeader('X-Sentinel-Request-ID', context.correlationId);

          upstreamRes.pipe(res);

          upstreamRes.on('end', () => {
            resolve({
              statusCode,
              durationMs: Date.now() - startTime,
            });
          });
        }
      );

      proxyReq.on('timeout', () => {
        proxyReq.destroy();
        if (!res.headersSent) {
          res.status(504).json({
            error: 'Gateway Timeout',
            message: 'Upstream application failed to respond in time.',
            correlationId: context.correlationId,
          });
        }
        resolve({ statusCode: 504, durationMs: Date.now() - startTime });
      });

      proxyReq.on('error', (err) => {
        console.error('[WAF Proxy Error]:', err.message);
        if (!res.headersSent) {
          res.status(502).json({
            error: 'Bad Gateway',
            message: 'Failed to connect to upstream protected application.',
            correlationId: context.correlationId,
          });
        }
        resolve({ statusCode: 502, durationMs: Date.now() - startTime });
      });

      // Write request body if POST/PUT/PATCH
      if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
        if (typeof req.body === 'string' || Buffer.isBuffer(req.body)) {
          proxyReq.write(req.body);
        } else if (typeof req.body === 'object' && Object.keys(req.body).length > 0) {
          proxyReq.write(JSON.stringify(req.body));
        }
      }

      proxyReq.end();
    } catch (err: any) {
      console.error('[WAF Proxy Setup Error]:', err.message);
      if (!res.headersSent) {
        res.status(500).json({
          error: 'Internal Server Error',
          message: 'Proxy processing failure',
          correlationId: context.correlationId,
        });
      }
      resolve({ statusCode: 500, durationMs: Date.now() - startTime });
    }
  });
}
