"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const vitest_1 = require("vitest");
const supertest_1 = __importDefault(require("supertest"));
const server_1 = __importDefault(require("../src/server"));
const targetServer_1 = require("../src/mockUpstream/targetServer");
const ipEvaluator_1 = require("../src/engine/ipEvaluator");
const pipeline_1 = require("../src/engine/pipeline");
const ruleMatcher_1 = require("../src/engine/ruleMatcher");
const request = (0, supertest_1.default)(server_1.default);
(0, vitest_1.describe)('Sentinel WAF - Unit & Integration Verification Test Suite', () => {
    (0, vitest_1.beforeAll)(() => {
        // Ensure mock upstream server is running on port 5001 for test suite
        (0, targetServer_1.createMockUpstreamServer)(5001);
    });
    // 1. IP & CIDR Evaluator Tests
    (0, vitest_1.describe)('IP & CIDR Parsing', () => {
        (0, vitest_1.it)('correctly normalizes IPv4 and IPv6-mapped addresses', () => {
            (0, vitest_1.expect)((0, ipEvaluator_1.normalizeIp)('::ffff:192.168.1.50').ip).toBe('192.168.1.50');
            (0, vitest_1.expect)((0, ipEvaluator_1.normalizeIp)('10.0.0.1').version).toBe('IPv4');
            (0, vitest_1.expect)((0, ipEvaluator_1.normalizeIp)('2001:db8::1').version).toBe('IPv6');
        });
        (0, vitest_1.it)('accurately matches IP against CIDR subnets', () => {
            (0, vitest_1.expect)((0, ipEvaluator_1.matchIpOrCidr)('192.168.1.25', '192.168.1.0/24')).toBe(true);
            (0, vitest_1.expect)((0, ipEvaluator_1.matchIpOrCidr)('10.0.0.5', '192.168.1.0/24')).toBe(false);
            (0, vitest_1.expect)((0, ipEvaluator_1.matchIpOrCidr)('2001:db8:abcd:0012::1', '2001:db8:abcd::/48')).toBe(true);
        });
    });
    // 2. Safe Regex Engine Tests
    (0, vitest_1.describe)('Regex Execution Safety', () => {
        (0, vitest_1.it)('executes regular expressions safely without blowing up', () => {
            (0, vitest_1.expect)((0, ruleMatcher_1.safeRegexMatch)('(?i)union\\s+select', '1 UNION SELECT 1,2')).toBe(true);
            (0, vitest_1.expect)((0, ruleMatcher_1.safeRegexMatch)('(?i)<script>', 'hello world')).toBe(false);
        });
    });
    // 3. WAF Request Inspection Pipeline Tests
    (0, vitest_1.describe)('Inspection Pipeline Detection', () => {
        (0, vitest_1.it)('detects SQL Injection attack payload fixture', async () => {
            const req = {
                method: 'GET',
                path: '/api/search',
                originalUrl: "/api/search?q=1' UNION SELECT username, password FROM users--",
                url: "/api/search?q=1' UNION SELECT username, password FROM users--",
                headers: { 'user-agent': 'Mozilla/5.0' },
                query: { q: "1' UNION SELECT username, password FROM users--" },
                body: {},
                socket: { remoteAddress: '127.0.0.1' },
            };
            const context = (0, pipeline_1.buildRequestContext)(req);
            const result = await (0, pipeline_1.inspectRequest)(context);
            (0, vitest_1.expect)(result.decision).toBe('BLOCK');
            (0, vitest_1.expect)(result.category).toBe('SQLI');
            (0, vitest_1.expect)(result.matchedRules.length).toBeGreaterThan(0);
        });
        (0, vitest_1.it)('detects Cross-Site Scripting (XSS) payload fixture', async () => {
            const req = {
                method: 'POST',
                path: '/api/comments',
                originalUrl: '/api/comments',
                url: '/api/comments',
                headers: { 'user-agent': 'Mozilla/5.0' },
                query: {},
                body: { comment: '<script>alert(document.cookie)</script>' },
                socket: { remoteAddress: '127.0.0.1' },
            };
            const context = (0, pipeline_1.buildRequestContext)(req);
            const result = await (0, pipeline_1.inspectRequest)(context);
            (0, vitest_1.expect)(result.decision).toBe('BLOCK');
            (0, vitest_1.expect)(result.category).toBe('XSS');
        });
        (0, vitest_1.it)('detects Path Traversal / LFI payload fixture', async () => {
            const req = {
                method: 'GET',
                path: '/api/download',
                originalUrl: '/api/download?file=../../../../etc/passwd',
                url: '/api/download?file=../../../../etc/passwd',
                headers: { 'user-agent': 'Mozilla/5.0' },
                query: { file: '../../../../etc/passwd' },
                body: {},
                socket: { remoteAddress: '127.0.0.1' },
            };
            const context = (0, pipeline_1.buildRequestContext)(req);
            const result = await (0, pipeline_1.inspectRequest)(context);
            (0, vitest_1.expect)(result.decision).toBe('BLOCK');
            (0, vitest_1.expect)(result.category).toBe('LFI');
        });
    });
    // 4. Reverse Proxy End-to-End Tests
    (0, vitest_1.describe)('Proxy Route Integration', () => {
        (0, vitest_1.it)('allows legitimate GET requests to reach upstream', async () => {
            const res = await request.get('/proxy/api/data');
            (0, vitest_1.expect)(res.status).toBe(200);
            (0, vitest_1.expect)(res.body.success).toBe(true);
            (0, vitest_1.expect)(res.headers['x-sentinel-waf']).toBe('Active');
        });
        (0, vitest_1.it)('blocks malicious SQLi requests at the proxy perimeter', async () => {
            const res = await request.get("/proxy/api/search?q=1' UNION SELECT 1,2--");
            (0, vitest_1.expect)(res.status).toBe(403);
            (0, vitest_1.expect)(res.body.error).toBe('Forbidden');
            (0, vitest_1.expect)(res.body.category).toBe('SQLI');
            (0, vitest_1.expect)(res.body.correlationId).toBeDefined();
        });
        (0, vitest_1.it)('blocks malicious XSS POST requests at the proxy perimeter', async () => {
            const res = await request
                .post('/proxy/api/comments')
                .send({ comment: '<script>alert("hacked")</script>' });
            (0, vitest_1.expect)(res.status).toBe(403);
            (0, vitest_1.expect)(res.body.category).toBe('XSS');
        });
    });
    // 5. Auth API Security
    (0, vitest_1.describe)('Authentication & Authorization', () => {
        (0, vitest_1.it)('rejects unauthenticated requests to administrative endpoints', async () => {
            const res = await request.get('/api/v1/overview');
            (0, vitest_1.expect)(res.status).toBe(401);
            (0, vitest_1.expect)(res.body.error).toBe('Unauthorized');
        });
        (0, vitest_1.it)('allows login with valid seeded admin credentials', async () => {
            const res = await request
                .post('/api/v1/auth/login')
                .send({ email: 'admin@sentinel.local', password: 'AdminPass123!' });
            (0, vitest_1.expect)(res.status).toBe(200);
            (0, vitest_1.expect)(res.body.token).toBeDefined();
            (0, vitest_1.expect)(res.body.user.role).toBe('ADMIN');
        });
    });
});
