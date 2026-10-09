import { AttackCategory, ThreatSeverity, WafDecisionType } from '../types/waf';

export interface CrsRuleDefinition {
  ruleId: string;
  name: string;
  description: string;
  category: AttackCategory;
  severity: ThreatSeverity;
  action: WafDecisionType;
  matchType: 'REGEX' | 'CONTAINS' | 'EXACT' | 'HEADER_PRESENT';
  targetField: 'QUERY' | 'BODY' | 'PATH' | 'HEADER' | 'METHOD' | 'FULL_URL';
  pattern: string;
  isCrsRule: boolean;
  scoreContribution: number; // Anomaly points: Critical=5, High=4, Medium=3, Low=2
}

/**
 * OWASP Core Rule Set (CRS) v4 Pinned Rule Definitions
 */
export const OWASP_CRS_V4_RULES: CrsRuleDefinition[] = [
  // CRS 920: Protocol Enforcement & Request Smuggling
  {
    ruleId: 'CRS-920-100',
    name: 'OWASP CRS v4 - HTTP Method Abuse / Protocol Violation',
    description: 'Detects illegal or dangerous HTTP protocol methods e.g. TRACE, CONNECT, TRACK.',
    category: 'MALFORMED',
    severity: 'MEDIUM',
    action: 'BLOCK',
    matchType: 'REGEX',
    targetField: 'METHOD',
    pattern: '^(TRACE|TRACK|CONNECT|PUT_DEBUG)$',
    isCrsRule: true,
    scoreContribution: 3,
  },
  {
    ruleId: 'CRS-920-170',
    name: 'OWASP CRS v4 - Request Smuggling (Header Host Abuse)',
    description: 'Detects HTTP Request Smuggling header anomalies e.g. multiple Host headers or Transfer-Encoding + Content-Length conflict.',
    category: 'MALFORMED',
    severity: 'HIGH',
    action: 'BLOCK',
    matchType: 'REGEX',
    targetField: 'HEADER',
    pattern: '(?i)(transfer-encoding\\s*:.*chunked.*content-length\\s*:|content-length\\s*:.*transfer-encoding\\s*:)',
    isCrsRule: true,
    scoreContribution: 4,
  },

  // CRS 930: Local File Inclusion (LFI) & Directory Traversal
  {
    ruleId: 'CRS-930-100',
    name: 'OWASP CRS v4 - LFI Path Traversal Sequence',
    description: 'Detects directory traversal sequences across URI paths, query params, and body inputs.',
    category: 'LFI',
    severity: 'CRITICAL',
    action: 'BLOCK',
    matchType: 'REGEX',
    targetField: 'FULL_URL',
    pattern: '(?i)(\\.\\./|\\.\\.\\\\|%2e%2e%2f|%2e%2e/|%252e%252e%252f)',
    isCrsRule: true,
    scoreContribution: 5,
  },
  {
    ruleId: 'CRS-930-110',
    name: 'OWASP CRS v4 - OS System File & Environment Path Probe',
    description: 'Detects probes targeting Linux / Windows sensitive system files (/etc/passwd, win.ini, proc/self/environ).',
    category: 'LFI',
    severity: 'CRITICAL',
    action: 'BLOCK',
    matchType: 'REGEX',
    targetField: 'FULL_URL',
    pattern: '(?i)(/etc/passwd|/etc/shadow|/proc/self/|c:\\\\windows\\\\system32|boot.ini|\\\\system32\\\\cmd.exe)',
    isCrsRule: true,
    scoreContribution: 5,
  },

  // CRS 932: Remote Code Execution (RCE) & Command Injection
  {
    ruleId: 'CRS-932-100',
    name: 'OWASP CRS v4 - Unix / Windows OS Command Injection Execution',
    description: 'Detects OS shell command injection chaining syntax e.g. ; cat /etc/passwd or || ls -la.',
    category: 'MALFORMED',
    severity: 'CRITICAL',
    action: 'BLOCK',
    matchType: 'REGEX',
    targetField: 'FULL_URL',
    pattern: '(?i)(;\\s*(cat|ls|id|whoami|uname|ping|netstat|curl|wget|powershell|cmd)\\b|\\|\\||&&)',
    isCrsRule: true,
    scoreContribution: 5,
  },

  // CRS 941: Cross-Site Scripting (XSS)
  {
    ruleId: 'CRS-941-100',
    name: 'OWASP CRS v4 - Script Element HTML Tag Injection',
    description: 'Detects script element tag injection attempting DOM script execution.',
    category: 'XSS',
    severity: 'CRITICAL',
    action: 'BLOCK',
    matchType: 'REGEX',
    targetField: 'FULL_URL',
    pattern: '(?i)(<script[^>]*>|%3Cscript%3E|document\\.cookie|document\\.location|window\\.location)',
    isCrsRule: true,
    scoreContribution: 5,
  },
  {
    ruleId: 'CRS-941-110',
    name: 'OWASP CRS v4 - Inline Event Handler Attribute Injection',
    description: 'Detects DOM event handler attributes e.g. onerror=, onload=, onclick=.',
    category: 'XSS',
    severity: 'HIGH',
    action: 'BLOCK',
    matchType: 'REGEX',
    targetField: 'FULL_URL',
    pattern: '(?i)(on(error|load|click|mouseover|submit|focus)\\s*=)',
    isCrsRule: true,
    scoreContribution: 4,
  },

  // CRS 942: SQL Injection (SQLi)
  {
    ruleId: 'CRS-942-100',
    name: 'OWASP CRS v4 - SQLi UNION Select Signature',
    description: 'Detects UNION-based SQL Injection statements.',
    category: 'SQLI',
    severity: 'CRITICAL',
    action: 'BLOCK',
    matchType: 'REGEX',
    targetField: 'FULL_URL',
    pattern: '(?i)(union\\s+all\\s+select|union\\s+select)',
    isCrsRule: true,
    scoreContribution: 5,
  },
  {
    ruleId: 'CRS-942-110',
    name: 'OWASP CRS v4 - SQLi Tautology & Logical Expression',
    description: 'Detects boolean tautologies e.g. OR 1=1 or AND 1=1.',
    category: 'SQLI',
    severity: 'HIGH',
    action: 'BLOCK',
    matchType: 'REGEX',
    targetField: 'FULL_URL',
    pattern: "(?i)('\\s*(or|and)\\s+['\"0-9a-z]+\\s*=\\s*['\"0-9a-z]+|'\\s*or\\s*1\\s*=\\s*1)",
    isCrsRule: true,
    scoreContribution: 4,
  },
  {
    ruleId: 'CRS-942-120',
    name: 'OWASP CRS v4 - SQLi Stacked Queries & DBMS Functions',
    description: 'Detects stacked query commands e.g. ; DROP TABLE or DBMS sleep functions.',
    category: 'SQLI',
    severity: 'CRITICAL',
    action: 'BLOCK',
    matchType: 'REGEX',
    targetField: 'BODY',
    pattern: '(?i)(;\\s*drop\\s+table|;\\s*exec\\(|information_schema|sysdatabases|pg_sleep\\(|sleep\\(\\d+\\))',
    isCrsRule: true,
    scoreContribution: 5,
  },

  // CRS 944: Java / PHP Deserialization & Code Injection
  {
    ruleId: 'CRS-944-100',
    name: 'OWASP CRS v4 - Java Object Deserialization RCE Payload',
    description: 'Detects Java serialized object magic bytes and CommonsCollections payload signatures.',
    category: 'REMOTE_ACCESS',
    severity: 'CRITICAL',
    action: 'BLOCK',
    matchType: 'REGEX',
    targetField: 'BODY',
    pattern: '(?i)(rO0ABX|ysoserial|org\\.apache\\.commons\\.collections)',
    isCrsRule: true,
    scoreContribution: 5,
  },
];
