import { RequestContext, RuleMatchResult, WafDecisionType } from '../types/waf';
import { OWASP_CRS_V4_RULES } from './crsRules';
import { safeRegexMatch } from './ruleMatcher';

export interface ShadowEvaluationResult {
  candidateDecision: 'PROJECTED_BLOCK' | 'PROJECTED_LOG' | 'PROJECTED_ALLOW';
  shadowMatchedRules: RuleMatchResult[];
  explanation: string;
}

export function evaluateShadowCandidatePolicy(
  context: RequestContext,
  activeDecision: WafDecisionType
): ShadowEvaluationResult {
  const shadowMatches: RuleMatchResult[] = [];
  const urlFull = context.fullUrl || `${context.path}?${new URLSearchParams(context.query).toString()}`;
  const bodyStr = typeof context.body === 'object' ? JSON.stringify(context.body) : String(context.body || '');

  // Evaluate candidate CRS rules in Shadow Mode
  for (const rule of OWASP_CRS_V4_RULES) {
    let targetValue = urlFull;
    if (rule.targetField === 'PATH') targetValue = context.path;
    else if (rule.targetField === 'QUERY') targetValue = JSON.stringify(context.query);
    else if (rule.targetField === 'BODY') targetValue = bodyStr;
    else if (rule.targetField === 'HEADER') targetValue = JSON.stringify(context.headers);
    else if (rule.targetField === 'METHOD') targetValue = context.method;

    if (safeRegexMatch(rule.pattern, targetValue)) {
      shadowMatches.push({
        ruleId: `SHADOW-${rule.ruleId}`,
        name: `Candidate Policy Shadow Rule: ${rule.name}`,
        category: rule.category,
        severity: rule.severity,
        action: rule.action,
        explanation: `[SHADOW CANDIDATE EVALUATION] Would trigger candidate rule ${rule.ruleId} (${rule.name})`,
        matchedField: rule.targetField,
        matchedPattern: rule.pattern,
        matchedValueSnippet: targetValue.substring(0, 150),
      });
    }
  }

  let projected: 'PROJECTED_BLOCK' | 'PROJECTED_LOG' | 'PROJECTED_ALLOW' = 'PROJECTED_ALLOW';
  if (shadowMatches.some(m => m.action === 'BLOCK')) {
    projected = 'PROJECTED_BLOCK';
  } else if (shadowMatches.length > 0) {
    projected = 'PROJECTED_LOG';
  }

  return {
    candidateDecision: projected,
    shadowMatchedRules: shadowMatches,
    explanation: `Shadow candidate evaluation projected decision: '${projected}' (${shadowMatches.length} candidate rules matched). Active enforcement response remains: '${activeDecision}'.`,
  };
}
