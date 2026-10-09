import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import dotenv from 'dotenv';
import path from 'path';
import fs from 'fs';

import { config } from './config/env';
import { checkDbConnection } from './db/prisma';

// API Routes
import authRoutes from './routes/auth';
import overviewRoutes from './routes/overview';
import trafficRoutes from './routes/traffic';
import eventsRoutes from './routes/events';
import analyticsRoutes from './routes/analytics';
import rulesRoutes from './routes/rules';
import ipAccessRoutes from './routes/ipAccess';
import rateLimitRoutes from './routes/rateLimit';
import appsRoutes from './routes/apps';
import inspectorRoutes from './routes/inspector';
import auditRoutes from './routes/audit';
import healthRoutes from './routes/health';
import settingsRoutes from './routes/settings';
import exceptionsRoutes from './routes/exceptions';
import virtualPatchesRoutes from './routes/virtualPatches';
import siemRoutes from './routes/siem';

// WAF Core Pipeline and Reverse Proxy Engine
import { buildRequestContext, inspectRequest } from './engine/pipeline';
import { forwardToUpstream } from './engine/proxy';
import { logWafEvent } from './services/eventLogger';
import { createMockUpstreamServer } from './mockUpstream/targetServer';

const app = express();

// Security Headers & Middleware
app.use(cors({ origin: true, credentials: true }));
app.use(helmet({ contentSecurityPolicy: false })); // Disable default CSP for local dashboard flexibility
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Health Check Endpoint (Public)
app.use('/health', healthRoutes);

// Mount API v1 Routes
const apiRouter = express.Router();
apiRouter.use('/auth', authRoutes);
apiRouter.use('/overview', overviewRoutes);
apiRouter.use('/traffic', trafficRoutes);
apiRouter.use('/events', eventsRoutes);
apiRouter.use('/analytics', analyticsRoutes);
apiRouter.use('/rules', rulesRoutes);
apiRouter.use('/ip-access', ipAccessRoutes);
apiRouter.use('/rate-limit', rateLimitRoutes);
apiRouter.use('/apps', appsRoutes);
apiRouter.use('/inspector', inspectorRoutes);
apiRouter.use('/audit', auditRoutes);
apiRouter.use('/settings', settingsRoutes);
apiRouter.use('/exceptions', exceptionsRoutes);
apiRouter.use('/virtual-patches', virtualPatchesRoutes);
apiRouter.use('/siem', siemRoutes);

app.use('/api/v1', apiRouter);

/**
 * REVERSE PROXY & WAF INSPECTION ROUTE
 * Any request to /proxy/* or registered hostname passes through WAF inspection pipeline
 */
app.all(['/proxy/*', '/proxy'], async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  const pathWithoutProxy = (req.originalUrl || req.url).replace(/^\/proxy/, '') || '/';
  
  // Construct a proxy request wrapper object avoiding getter mutation issues
  const reqWrapper: any = {
    method: req.method,
    path: pathWithoutProxy.split('?')[0],
    originalUrl: pathWithoutProxy,
    url: pathWithoutProxy,
    headers: req.headers,
    query: req.query,
    body: req.body,
    socket: req.socket,
    protocol: req.protocol,
  };

  const targetAppUrl = process.env.UPSTREAM_URL || `http://localhost:${config.upstreamPort}`;
  const context = buildRequestContext(reqWrapper, 'app-web-store', targetAppUrl);

  try {
    // 1. Run WAF Inspection Pipeline
    const result = await inspectRequest(context);

    // 2. If decision is BLOCK or RATE_LIMIT in Prevention mode, send custom WAF security response
    if (result.decision === 'BLOCK' || result.decision === 'RATE_LIMIT') {
      await logWafEvent(context, result, result.statusCode, result.durationMs);

      if (result.decision === 'RATE_LIMIT') {
        res.setHeader('Retry-After', '60');
      }

      res.status(result.statusCode).json({
        error: result.decision === 'RATE_LIMIT' ? 'Too Many Requests' : 'Forbidden',
        message: 'Request blocked by Sentinel Web Application Firewall policy.',
        correlationId: result.correlationId,
        category: result.category,
        severity: result.severity,
        explanation: result.explanation,
        matchedRuleId: result.matchedRuleId,
        timestamp: new Date().toISOString(),
      });
      return;
    }

    // 3. Otherwise (ALLOW or LOG mode), forward permitted request to upstream target
    const proxyRes = await forwardToUpstream(reqWrapper, res, targetAppUrl, context);

    // 4. Log event asynchronously
    await logWafEvent(context, result, proxyRes.statusCode, proxyRes.durationMs);
  } catch (err: any) {
    console.error('[WAF Proxy Route Error]:', err);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'WAF request handling exception',
      correlationId: context.correlationId,
    });
  }
});

// Serve static React client build if present
const clientDistPath = path.resolve(__dirname, '../../client/dist');
if (fs.existsSync(clientDistPath)) {
  app.use(express.static(clientDistPath));
  app.get('*', (req: Request, res: Response, next: NextFunction) => {
    if (req.path.startsWith('/api') || req.path.startsWith('/proxy') || req.path.startsWith('/health')) {
      return next();
    }
    res.sendFile(path.join(clientDistPath, 'index.html'));
  });
}

// Default 404 Handler for unknown routes
app.use((req: Request, res: Response) => {
  res.status(404).json({ error: 'Not Found', path: req.path });
});

// Centralized Error Handler
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  console.error('[Server Error Handler]:', err);
  res.status(500).json({
    error: 'Internal Server Error',
    message: process.env.NODE_ENV === 'development' ? err.message : 'An unhandled server error occurred.',
  });
});

import { setupHttpsServer } from './config/tls';

// Server Initialization
export async function startServer() {
  const dbOk = await checkDbConnection();
  if (!dbOk) {
    console.warn('[Warning] DB connection check failed during startup.');
  }

  // Start Mock Upstream Target Server
  createMockUpstreamServer(config.upstreamPort);

  const server = app.listen(config.port, () => {
    console.log(`=======================================================`);
    console.log(`   SENTINEL WAF SERVER RUNNING ON PORT : ${config.port}`);
    console.log(`   DEFAULT UPSTREAM TARGET PORT       : ${config.upstreamPort}`);
    console.log(`   PROXY REVERSE ENDPOINT             : http://localhost:${config.port}/proxy`);
    console.log(`   API BASE URL                       : http://localhost:${config.port}/api/v1`);
    console.log(`=======================================================`);
  });

  const httpsPort = parseInt(process.env.HTTPS_PORT || '5443', 10);
  const { server: httpsServer } = setupHttpsServer(app, httpsPort);

  return { app, server, httpsServer };
}

if (require.main === module) {
  startServer();
}

export default app;
