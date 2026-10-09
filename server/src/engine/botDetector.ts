import { RequestContext } from '../types/waf';

export interface BotCheckResult {
  isSuspicious: boolean;
  riskScore: number; // 0 - 100
  indicators: string[];
}

const KNOWN_SCANNER_USER_AGENTS = [
  'sqlmap',
  'nikto',
  'nmap',
  'gobuster',
  'dirbuster',
  'hydra',
  'masscan',
  'zgrab',
  'w3af',
  'acunetix',
  'netsparker',
  'burpsuite',
  'python-requests',
  'go-http-client',
];

export function detectBotActivity(context: RequestContext): BotCheckResult {
  const indicators: string[] = [];
  let riskScore = 0;

  const ua = (context.userAgent || '').toLowerCase();

  // 1. Check User-Agent presence
  if (!context.userAgent || context.userAgent.trim() === '') {
    indicators.push('Missing User-Agent header');
    riskScore += 30;
  }

  // 2. Check Known Vulnerability Scanners & Automation tools
  for (const tool of KNOWN_SCANNER_USER_AGENTS) {
    if (ua.includes(tool)) {
      indicators.push(`Known automated security scanner detected in User-Agent: '${tool}'`);
      riskScore += 70;
      break;
    }
  }

  // 3. Check for missing standard browser headers
  const hasAccept = Boolean(context.headers['accept']);
  const hasAcceptEncoding = Boolean(context.headers['accept-encoding']);

  if (!hasAccept && !hasAcceptEncoding) {
    indicators.push('Absence of standard browser headers (Accept / Accept-Encoding)');
    riskScore += 20;
  }

  // 4. High-risk path probing (e.g. phpmyadmin, env files, config probes)
  const pathLower = context.path.toLowerCase();
  if (pathLower.includes('.env') || pathLower.includes('phpmyadmin') || pathLower.includes('actuator/env')) {
    indicators.push(`Suspicious target path probe: '${context.path}'`);
    riskScore += 40;
  }

  // Cap score at 100
  riskScore = Math.min(100, riskScore);

  return {
    isSuspicious: riskScore >= 50,
    riskScore,
    indicators,
  };
}
