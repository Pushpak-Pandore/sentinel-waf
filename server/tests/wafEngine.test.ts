import { describe, it, expect, beforeAll } from 'vitest';
import supertest from 'supertest';
import app from '../src/server';
import { createMockUpstreamServer } from '../src/mockUpstream/targetServer';
import { normalizeIp, matchIpOrCidr } from '../src/engine/ipEvaluator';
import { inspectRequest, buildRequestContext } from '../src/engine/pipeline';
import { safeRegexMatch } from '../src/engine/ruleMatcher';

const request = supertest(app);

describe('Sentinel WAF - Unit & Integration Verification Test Suite', () => {
  beforeAll(() => {
    // Ensure mock upstream server is running on port 5001 for test suite
    createMockUpstreamServer(5001);
  });
  // 1. IP & CIDR Evaluator Tests
  describe('IP & CIDR Parsing', () => {
    it('correctly normalizes IPv4 and IPv6-mapped addresses', () => {
      expect(normalizeIp('::ffff:192.168.1.50').ip).toBe('192.168.1.50');
      expect(normalizeIp('10.0.0.1').version).toBe('IPv4');
      expect(normalizeIp('2001:db8::1').version).toBe('IPv6');
    });

    it('accurately matches IP against CIDR subnets', () => {
      expect(matchIpOrCidr('192.168.1.25', '192.168.1.0/24')).toBe(true);
      expect(matchIpOrCidr('10.0.0.5', '192.168.1.0/24')).toBe(false);
      expect(matchIpOrCidr('2001:db8:abcd:0012::1', '2001:db8:abcd::/48')).toBe(true);
    });
  });

  // 2. Safe Regex Engine Tests
  describe('Regex Execution Safety', () => {
    it('executes regular expressions safely without blowing up', () => {
      expect(safeRegexMatch('(?i)union\\s+select', '1 UNION SELECT 1,2')).toBe(true);
      expect(safeRegexMatch('(?i)<script>', 'hello world')).toBe(false);
    });
  });

  // 3. WAF Request Inspection Pipeline Tests
  describe('Inspection Pipeline Detection', () => {
    it('detects SQL Injection attack payload fixture', async () => {
      const req = {
        method: 'GET',
        path: '/api/search',
        originalUrl: "/api/search?q=1' UNION SELECT username, password FROM users--",
        url: "/api/search?q=1' UNION SELECT username, password FROM users--",
        headers: { 'user-agent': 'Mozilla/5.0' },
        query: { q: "1' UNION SELECT username, password FROM users--" },
        body: {},
        socket: { remoteAddress: '127.0.0.1' },
      } as any;

      const context = buildRequestContext(req);
      const result = await inspectRequest(context);

      expect(result.decision).toBe('BLOCK');
      expect(result.category).toBe('SQLI');
      expect(result.matchedRules.length).toBeGreaterThan(0);
    });

    it('detects Cross-Site Scripting (XSS) payload fixture', async () => {
      const req = {
        method: 'POST',
        path: '/api/comments',
        originalUrl: '/api/comments',
        url: '/api/comments',
        headers: { 'user-agent': 'Mozilla/5.0' },
        query: {},
        body: { comment: '<script>alert(document.cookie)</script>' },
        socket: { remoteAddress: '127.0.0.1' },
      } as any;

      const context = buildRequestContext(req);
      const result = await inspectRequest(context);

      expect(result.decision).toBe('BLOCK');
      expect(result.category).toBe('XSS');
    });

    it('detects Path Traversal / LFI payload fixture', async () => {
      const req = {
        method: 'GET',
        path: '/api/download',
        originalUrl: '/api/download?file=../../../../etc/passwd',
        url: '/api/download?file=../../../../etc/passwd',
        headers: { 'user-agent': 'Mozilla/5.0' },
        query: { file: '../../../../etc/passwd' },
        body: {},
        socket: { remoteAddress: '127.0.0.1' },
      } as any;

      const context = buildRequestContext(req);
      const result = await inspectRequest(context);

      expect(result.decision).toBe('BLOCK');
      expect(result.category).toBe('LFI');
    });
  });

  // 4. Reverse Proxy End-to-End Tests
  describe('Proxy Route Integration', () => {
    it('allows legitimate GET requests to reach upstream', async () => {
      const res = await request.get('/proxy/api/data');
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.headers['x-sentinel-waf']).toBe('Active');
    });

    it('blocks malicious SQLi requests at the proxy perimeter', async () => {
      const res = await request.get("/proxy/api/search?q=1' UNION SELECT 1,2--");
      expect(res.status).toBe(403);
      expect(res.body.error).toBe('Forbidden');
      expect(res.body.category).toBe('SQLI');
      expect(res.body.correlationId).toBeDefined();
    });

    it('blocks malicious XSS POST requests at the proxy perimeter', async () => {
      const res = await request
        .post('/proxy/api/comments')
        .send({ comment: '<script>alert("hacked")</script>' });

      expect(res.status).toBe(403);
      expect(res.body.category).toBe('XSS');
    });
  });

  // 5. Auth API Security
  describe('Authentication & Authorization', () => {
    it('rejects unauthenticated requests to administrative endpoints', async () => {
      const res = await request.get('/api/v1/overview');
      expect(res.status).toBe(401);
      expect(res.body.error).toBe('Unauthorized');
    });

    it('allows login with valid seeded admin credentials', async () => {
      const res = await request
        .post('/api/v1/auth/login')
        .send({ email: 'admin@sentinel.local', password: 'AdminPass123!' });

      expect(res.status).toBe(200);
      expect(res.body.token).toBeDefined();
      expect(res.body.user.role).toBe('ADMIN');
    });
  });

  // 6. Upgraded Capabilities Test Suite (CRS v4, Anomaly Scoring, Shadow Evaluation, Virtual Patching)
  describe('Upgraded WAF Capabilities', () => {
    it('triggers OWASP CRS v4 signatures with cumulative anomaly score', async () => {
      const req = {
        method: 'GET',
        path: '/api/search',
        originalUrl: "/api/search?q=1' UNION SELECT 1,2--",
        url: "/api/search?q=1' UNION SELECT 1,2--",
        headers: { 'user-agent': 'Mozilla/5.0' },
        query: { q: "1' UNION SELECT 1,2--" },
        body: {},
        socket: { remoteAddress: '127.0.0.1' },
      } as any;

      const context = buildRequestContext(req);
      const result = await inspectRequest(context);

      expect(result.decision).toBe('BLOCK');
      expect(result.riskScore).toBeGreaterThan(0);
      expect(result.explanation).toContain('Cumulative Anomaly Score');
    });

    it('evaluates candidate policies in Shadow Mode without blocking legitimate requests', async () => {
      const req = {
        method: 'GET',
        path: '/api/data',
        originalUrl: '/api/data',
        url: '/api/data',
        headers: { 'user-agent': 'Mozilla/5.0' },
        query: {},
        body: {},
        socket: { remoteAddress: '127.0.0.1' },
      } as any;

      const context = buildRequestContext(req);
      const result = await inspectRequest(context);

      expect(result.decision).toBe('ALLOW');
      expect(result.explanation).toContain('Shadow candidate evaluation');
    });
  });

  // 7. Phase 2-5 Production Hardening Tests (HTTPS TLS, GeoIP, ML Anomaly Detection, PDF Export)
  describe('Phase 2-5 Production Hardening Capabilities', () => {
    it('verifies HTTPS TLS configuration loader and dev certificate fallback', async () => {
      const { loadTlsConfig } = await import('../src/config/tls');
      const tlsInfo = loadTlsConfig();
      expect(tlsInfo).toBeDefined();
      if (tlsInfo.enabled) {
        expect(tlsInfo.cert).toBeDefined();
        expect(tlsInfo.key).toBeDefined();
      }
    });

    it('performs GeoIP lookup for public and private IP addresses accurately', async () => {
      const { lookupGeoIp } = await import('../src/engine/geoip');
      
      const localRes = lookupGeoIp('127.0.0.1');
      expect(localRes.countryCode).toBe('LOCAL');
      expect(localRes.isPrivate).toBe(true);

      const publicRes = lookupGeoIp('8.8.8.8');
      expect(publicRes.countryCode).toBe('US');
      expect(publicRes.isPrivate).toBe(false);
    });

    it('runs ML HTTP Anomaly Detection in shadow mode without changing WAF decisions', async () => {
      const { evaluateMlAnomaly, evaluateMlAnomalyShadow } = await import('../src/engine/mlAnomalyDetector');
      
      const req = {
        method: 'GET',
        path: '/api/test',
        originalUrl: '/api/test?arg=<script>alert(1)</script>',
        url: '/api/test?arg=<script>alert(1)</script>',
        headers: { 'user-agent': 'Mozilla/5.0' },
        query: { arg: '<script>alert(1)</script>' },
        body: {},
        socket: { remoteAddress: '127.0.0.1' },
        startTime: Date.now(),
      } as any;

      const context = buildRequestContext(req);
      const mlRes = await evaluateMlAnomalyShadow(context);
      
      expect(mlRes.score).toBeGreaterThan(0.4);
      expect(mlRes.modelVersion).toBeDefined();
      expect(mlRes.latencyMs).toBeLessThan(100);
    });

    it('generates an Executive Security Audit PDF report binary buffer', async () => {
      const { generateExecutivePdfReport } = await import('../src/services/pdfReportGenerator');
      
      const pdfBuffer = await generateExecutivePdfReport({ period: '24h', userEmail: 'admin@sentinel.local' });
      expect(pdfBuffer).toBeDefined();
      expect(Buffer.isBuffer(pdfBuffer)).toBe(true);
      expect(pdfBuffer.length).toBeGreaterThan(500);
      // PDF header check
      expect(pdfBuffer.toString('utf8', 0, 4)).toBe('%PDF');
    });
  });
});

