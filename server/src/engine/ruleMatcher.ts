import { RequestContext, RuleMatchResult, AttackCategory, ThreatSeverity, WafDecisionType } from '../types/waf';
import { prisma } from '../db/prisma';

// Built-in WAF Signatures (Fallback and Default baseline protections)
export const DEFAULT_WAF_RULES = [
  // SQL Injection
  {
    ruleId: 'R-SQLI-001',
    name: 'SQL Injection - UNION Select Signature',
    category: 'SQLI' as AttackCategory,
    severity: 'CRITICAL' as ThreatSeverity,
    action: 'BLOCK' as WafDecisionType,
    matchType: 'REGEX',
    targetField: 'FULL_URL',
    pattern: "(?i)(union\\s+all\\s+select|union\\s+select)",
    explanation: 'Detected UNION SQL Injection payload in URL query or body.',
  },
  {
    ruleId: 'R-SQLI-002',
    name: 'SQL Injection - Boolean Based OR/AND 1=1',
    category: 'SQLI' as AttackCategory,
    severity: 'HIGH' as ThreatSeverity,
    action: 'BLOCK' as WafDecisionType,
    matchType: 'REGEX',
    targetField: 'FULL_URL',
    pattern: "(?i)('\\s*(or|and)\\s+['\"0-9a-z]+\\s*=\\s*['\"0-9a-z]+|'\\s*or\\s*1\\s*=\\s*1)",
    explanation: 'Detected boolean-based SQL Injection tautology payload.',
  },
  {
    ruleId: 'R-SQLI-003',
    name: 'SQL Injection - Exec / Stacked Queries / Meta Characters',
    category: 'SQLI' as AttackCategory,
    severity: 'CRITICAL' as ThreatSeverity,
    action: 'BLOCK' as WafDecisionType,
    matchType: 'REGEX',
    targetField: 'BODY',
    pattern: "(?i)(;\\s*drop\\s+table|;\\s*exec\\(|information_schema|sysdatabases|pg_sleep\\()",
    explanation: 'Detected stacked query or system table access SQL Injection.',
  },

  // Cross-Site Scripting (XSS)
  {
    ruleId: 'R-XSS-001',
    name: 'XSS - Script Element Tag Injection',
    category: 'XSS' as AttackCategory,
    severity: 'CRITICAL' as ThreatSeverity,
    action: 'BLOCK' as WafDecisionType,
    matchType: 'REGEX',
    targetField: 'FULL_URL',
    pattern: "(?i)(<script[^>]*>|%3Cscript%3E)",
    explanation: 'Detected <script> tag HTML/Script injection.',
  },
  {
    ruleId: 'R-XSS-002',
    name: 'XSS - Inline Event Handler Injection',
    category: 'XSS' as AttackCategory,
    severity: 'HIGH' as ThreatSeverity,
    action: 'BLOCK' as WafDecisionType,
    matchType: 'REGEX',
    targetField: 'FULL_URL',
    pattern: "(?i)(on(load|error|click|mouseover|submit)\\s*=)",
    explanation: 'Detected inline JavaScript event handler payload.',
  },
  {
    ruleId: 'R-XSS-003',
    name: 'XSS - JavaScript Protocol URI Injection',
    category: 'XSS' as AttackCategory,
    severity: 'HIGH' as ThreatSeverity,
    action: 'BLOCK' as WafDecisionType,
    matchType: 'REGEX',
    targetField: 'FULL_URL',
    pattern: "(?i)(javascript\\s*:|data\\s*:\\s*text/html)",
    explanation: 'Detected executable JavaScript pseudo-protocol payload.',
  },

  // LFI / Path Traversal
  {
    ruleId: 'R-LFI-001',
    name: 'Path Traversal - Directory Traversal Sequences',
    category: 'LFI' as AttackCategory,
    severity: 'HIGH' as ThreatSeverity,
    action: 'BLOCK' as WafDecisionType,
    matchType: 'REGEX',
    targetField: 'PATH',
    pattern: "(\\.\\./|\\.\\.\\\\|%2e%2e%2f|%2e%2e/)",
    explanation: 'Detected directory traversal sequence (../ or URL encoded equivalent).',
  },
  {
    ruleId: 'R-LFI-002',
    name: 'LFI - Sensitive System File Access Attempt',
    category: 'LFI' as AttackCategory,
    severity: 'CRITICAL' as ThreatSeverity,
    action: 'BLOCK' as WafDecisionType,
    matchType: 'REGEX',
    targetField: 'FULL_URL',
    pattern: "(?i)(/etc/passwd|/etc/shadow|c:\\\\windows\\\\system32|boot.ini|proc/self/environ)",
    explanation: 'Detected access attempt to OS sensitive system file path.',
  },

  // Remote Access / Admin Bypass
  {
    ruleId: 'R-REMOTE-001',
    name: 'Unauthorized Remote Access - Internal Management Route Probe',
    category: 'REMOTE_ACCESS' as AttackCategory,
    severity: 'MEDIUM' as ThreatSeverity,
    action: 'LOG' as WafDecisionType,
    matchType: 'REGEX',
    targetField: 'PATH',
    pattern: "(?i)^/(admin|server-status|actuator|wp-admin|\\.env|\\.git/config)",
    explanation: 'Detected access probe targeting administrative/sensitive route.',
  },

  // Malformed Requests & Command Injection
  {
    ruleId: 'R-MALFORMED-001',
    name: 'Command Injection - OS Shell Metacharacter Execution',
    category: 'MALFORMED' as AttackCategory,
    severity: 'CRITICAL' as ThreatSeverity,
    action: 'BLOCK' as WafDecisionType,
    matchType: 'REGEX',
    targetField: 'FULL_URL',
    pattern: "(\\|\\||&&|;\\s*cat\\s+|;\\s*ls\\s+|;\\s*ping\\s+)",
    explanation: 'Detected OS command injection shell chaining operators.',
  },
];

/**
 * Safe Regex Matcher with execution safety bound
 */
export function safeRegexMatch(patternStr: string, input: string): boolean {
  if (!input || !patternStr) return false;

  try {
    let flags = 'i';
    let cleanPattern = patternStr;

    // Remove inline flag prefix if present e.g. (?i)
    if (patternStr.startsWith('(?i)')) {
      flags = 'i';
      cleanPattern = patternStr.substring(4);
    }

    const regex = new RegExp(cleanPattern, flags);
    return regex.test(input);
  } catch (err) {
    console.warn(`[WAF Engine] Unsafe or invalid regex pattern: ${patternStr}`, err);
    return false;
  }
}

/**
 * Sanitizes input string for log storage (redacts passwords, tokens, API keys)
 */
export function sanitizeForLog(input: string): string {
  if (!input) return '';
  return input
    .replace(/(password|passwd|token|secret|authorization|bearer)\s*=\s*['"][^'"]+['"]/gi, '$1=***REDACTED***')
    .substring(0, 1000); // Bounded size
}

/**
 * Evaluates request context against all active WAF rules (DB + Baseline)
 */
export async function evaluateWafRules(context: RequestContext): Promise<RuleMatchResult[]> {
  const matches: RuleMatchResult[] = [];

  // Fetch DB active rules
  let dbRules: any[] = [];
  try {
    dbRules = await prisma.wafRule.findMany({
      where: { enabled: true }
    });
  } catch (err) {
    // If DB read fails during startup, fallback to built-in default rules
    dbRules = [];
  }

  const allRules = dbRules.length > 0 ? dbRules : DEFAULT_WAF_RULES;

  let urlFull = context.fullUrl || `${context.path}?${new URLSearchParams(context.query).toString()}`;
  try {
    urlFull = decodeURIComponent(urlFull);
  } catch {
    // If malformed URI encoding, keep original
  }

  const bodyStr = typeof context.body === 'object' ? JSON.stringify(context.body) : String(context.body || '');
  const headersStr = JSON.stringify(context.headers);

  for (const rule of allRules) {
    let targetValue = '';

    switch (rule.targetField) {
      case 'PATH':
        targetValue = context.path;
        break;
      case 'QUERY':
        targetValue = JSON.stringify(context.query);
        break;
      case 'BODY':
        targetValue = bodyStr;
        break;
      case 'HEADER':
        targetValue = headersStr;
        break;
      case 'METHOD':
        targetValue = context.method;
        break;
      case 'FULL_URL':
      default:
        targetValue = `${urlFull} ${bodyStr}`;
        break;
    }

    let isMatch = false;

    if (rule.matchType === 'REGEX') {
      isMatch = safeRegexMatch(rule.pattern, targetValue);
    } else if (rule.matchType === 'CONTAINS') {
      isMatch = targetValue.toLowerCase().includes(rule.pattern.toLowerCase());
    } else if (rule.matchType === 'EXACT') {
      isMatch = targetValue === rule.pattern;
    } else if (rule.matchType === 'HEADER_PRESENT') {
      isMatch = Boolean(context.headers[rule.pattern.toLowerCase()]);
    }

    if (isMatch) {
      matches.push({
        ruleId: rule.ruleId || rule.id,
        name: rule.name,
        category: rule.category as AttackCategory,
        severity: rule.severity as ThreatSeverity,
        action: rule.action as WafDecisionType,
        explanation: rule.explanation || `Matched rule ${rule.ruleId} (${rule.name})`,
        matchedField: rule.targetField,
        matchedPattern: rule.pattern,
        matchedValueSnippet: sanitizeForLog(targetValue),
      });
    }
  }

  return matches;
}
