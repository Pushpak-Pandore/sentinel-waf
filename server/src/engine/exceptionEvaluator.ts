import { prisma } from '../db/prisma';
import { RequestContext, RuleMatchResult } from '../types/waf';

export async function filterRuleExceptions(
  context: RequestContext,
  matchedRules: RuleMatchResult[]
): Promise<{ activeRules: RuleMatchResult[]; bypassedRules: RuleMatchResult[] }> {
  if (matchedRules.length === 0) {
    return { activeRules: [], bypassedRules: [] };
  }

  let exceptions: any[] = [];
  try {
    exceptions = await prisma.wafException.findMany({
      where: {
        OR: [
          { expiresAt: null },
          { expiresAt: { gt: new Date() } }
        ]
      }
    });
  } catch {
    exceptions = [];
  }

  if (exceptions.length === 0) {
    return { activeRules: matchedRules, bypassedRules: [] };
  }

  const activeRules: RuleMatchResult[] = [];
  const bypassedRules: RuleMatchResult[] = [];

  for (const rule of matchedRules) {
    const isExempt = exceptions.some(exc => {
      // 1. Check Rule ID match
      if (exc.ruleId !== '*' && exc.ruleId !== rule.ruleId) return false;

      // 2. Check App ID scope
      if (exc.appId !== '*' && context.appId && exc.appId !== context.appId) return false;

      // 3. Check Method scope
      if (exc.method !== '*' && exc.method.toUpperCase() !== context.method.toUpperCase()) return false;

      // 4. Check Path pattern scope
      if (!matchPathPattern(context.path, exc.pathPattern)) return false;

      return true;
    });

    if (isExempt) {
      bypassedRules.push(rule);
    } else {
      activeRules.push(rule);
    }
  }

  return { activeRules, bypassedRules };
}

function matchPathPattern(path: string, pattern: string): boolean {
  if (pattern === '*' || pattern === '/*') return true;
  if (pattern.endsWith('*')) {
    const prefix = pattern.slice(0, -1);
    return path.startsWith(prefix);
  }
  return path === pattern;
}
