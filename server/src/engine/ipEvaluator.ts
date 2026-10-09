import ipaddr from 'ipaddr.js';
import { prisma } from '../db/prisma';
import { Request } from 'express';

export interface IpEvalResult {
  ip: string;
  ipVersion: 'IPv4' | 'IPv6';
  isAllowed: boolean;
  isBlocked: boolean;
  matchingRuleId?: string;
  reason?: string;
}

/**
 * Extracts and normalizes client IP address from express request
 */
export function extractClientIp(req: Request, trustedProxies: string[] = ['127.0.0.1', '::1']): { ip: string; version: 'IPv4' | 'IPv6' } {
  let rawIp = req.socket.remoteAddress || '127.0.0.1';

  // If request comes from trusted proxy, check X-Forwarded-For
  const xForwardedFor = req.headers['x-forwarded-for'];
  if (xForwardedFor && isTrustedProxy(rawIp, trustedProxies)) {
    const ips = (Array.isArray(xForwardedFor) ? xForwardedFor[0] : xForwardedFor)
      .split(',')
      .map(s => s.trim());
    if (ips.length > 0 && ips[0]) {
      rawIp = ips[0];
    }
  } else if (req.headers['x-real-ip'] && isTrustedProxy(rawIp, trustedProxies)) {
    const xRealIp = req.headers['x-real-ip'];
    rawIp = Array.isArray(xRealIp) ? xRealIp[0] : xRealIp;
  }

  return normalizeIp(rawIp);
}

/**
 * Normalizes IPv4 and IPv6 strings
 */
export function normalizeIp(rawIp: string): { ip: string; version: 'IPv4' | 'IPv6' } {
  let cleanIp = rawIp.trim();

  // Handle IPv4-mapped IPv6 (e.g., ::ffff:192.168.1.1)
  if (cleanIp.startsWith('::ffff:')) {
    cleanIp = cleanIp.substring(7);
  }

  try {
    const parsed = ipaddr.parse(cleanIp);
    if (parsed.kind() === 'ipv4') {
      return { ip: parsed.toString(), version: 'IPv4' };
    } else {
      // If IPv6 is mapped IPv4
      if (parsed.kind() === 'ipv6') {
        const ipv6 = parsed as ipaddr.IPv6;
        if (ipv6.isIPv4MappedAddress()) {
          return { ip: ipv6.toIPv4Address().toString(), version: 'IPv4' };
        }
      }
      return { ip: parsed.toString(), version: 'IPv6' };
    }
  } catch {
    return { ip: cleanIp, version: cleanIp.includes(':') ? 'IPv6' : 'IPv4' };
  }
}

function isTrustedProxy(ip: string, trustedProxies: string[]): boolean {
  const norm = normalizeIp(ip).ip;
  return trustedProxies.includes(norm) || norm === '127.0.0.1' || norm === '::1';
}

/**
 * Evaluates target IP against database IpAccessRules (Supports single IP & CIDR notation)
 */
export async function evaluateIpAccess(clientIp: string): Promise<IpEvalResult> {
  const { ip, version } = normalizeIp(clientIp);

  // Fetch active access rules
  const rules = await prisma.ipAccessRule.findMany({
    where: {
      OR: [
        { expiresAt: null },
        { expiresAt: { gt: new Date() } }
      ]
    }
  });

  let matchedAllowRule: any = null;
  let matchedBlockRule: any = null;

  for (const rule of rules) {
    if (matchIpOrCidr(ip, rule.ipOrCidr)) {
      if (rule.type === 'ALLOW') {
        matchedAllowRule = rule;
      } else if (rule.type === 'BLOCK') {
        matchedBlockRule = rule;
      }
    }
  }

  // Precedence Rule: ALLOW explicit entries override BLOCK entries if both exist,
  // otherwise BLOCK triggers.
  if (matchedAllowRule) {
    return {
      ip,
      ipVersion: version,
      isAllowed: true,
      isBlocked: false,
      matchingRuleId: matchedAllowRule.id,
      reason: matchedAllowRule.reason || 'IP explicitly Whitelisted',
    };
  }

  if (matchedBlockRule) {
    return {
      ip,
      ipVersion: version,
      isAllowed: false,
      isBlocked: true,
      matchingRuleId: matchedBlockRule.id,
      reason: matchedBlockRule.reason || 'IP explicitly Blacklisted',
    };
  }

  return {
    ip,
    ipVersion: version,
    isAllowed: false,
    isBlocked: false,
  };
}

/**
 * Checks if target IP matches exact IP or CIDR block
 */
export function matchIpOrCidr(targetIp: string, rulePattern: string): boolean {
  try {
    const normTarget = normalizeIp(targetIp).ip;
    const cleanPattern = rulePattern.trim();

    // Exact string match
    if (normTarget === normalizeIp(cleanPattern).ip) {
      return true;
    }

    // CIDR notation check
    if (cleanPattern.includes('/')) {
      const parsedIp = ipaddr.parse(normTarget);
      const parsedCidr = ipaddr.parseCIDR(cleanPattern);

      if (parsedIp.kind() === parsedCidr[0].kind()) {
        return parsedIp.match(parsedCidr);
      }
    }
  } catch {
    return false;
  }
  return false;
}
