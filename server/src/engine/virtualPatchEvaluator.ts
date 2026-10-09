import { prisma } from '../db/prisma';
import { RequestContext, RuleMatchResult, WafDecisionType } from '../types/waf';
import { safeRegexMatch } from './ruleMatcher';

export async function evaluateVirtualPatches(context: RequestContext): Promise<RuleMatchResult[]> {
  let patches: any[] = [];
  try {
    patches = await prisma.virtualPatch.findMany({
      where: {
        enabled: true,
        OR: [
          { expiresAt: null },
          { expiresAt: { gt: new Date() } }
        ]
      }
    });
  } catch {
    patches = [];
  }

  if (patches.length === 0) return [];

  const patchMatches: RuleMatchResult[] = [];
  const urlFull = context.fullUrl || `${context.path}?${new URLSearchParams(context.query).toString()}`;
  const bodyStr = typeof context.body === 'object' ? JSON.stringify(context.body) : String(context.body || '');

  for (const patch of patches) {
    // Check App ID scope
    if (patch.appId !== '*' && context.appId && patch.appId !== context.appId) continue;

    // Check Method scope
    if (patch.method !== '*' && patch.method.toUpperCase() !== context.method.toUpperCase()) continue;

    // Check Path pattern scope
    if (!matchPathPattern(context.path, patch.pathPattern)) continue;

    let targetValue = urlFull;
    if (patch.targetField === 'PATH') targetValue = context.path;
    else if (patch.targetField === 'QUERY') targetValue = JSON.stringify(context.query);
    else if (patch.targetField === 'BODY') targetValue = bodyStr;
    else if (patch.targetField === 'HEADER') targetValue = JSON.stringify(context.headers);

    if (safeRegexMatch(patch.pattern, targetValue)) {
      patchMatches.push({
        ruleId: patch.patchId,
        name: `Virtual Patch: ${patch.name}`,
        category: 'VIRTUAL_PATCH',
        severity: 'CRITICAL',
        action: patch.action as WafDecisionType,
        explanation: `Triggered active Virtual Patch '${patch.patchId}' (${patch.name}) on route '${patch.pathPattern}'`,
        matchedField: patch.targetField,
        matchedPattern: patch.pattern,
        matchedValueSnippet: targetValue.substring(0, 200),
      });
    }
  }

  return patchMatches;
}

function matchPathPattern(path: string, pattern: string): boolean {
  if (pattern === '*' || pattern === '/*') return true;
  if (pattern.endsWith('*')) {
    const prefix = pattern.slice(0, -1);
    return path.startsWith(prefix);
  }
  return path === pattern;
}
