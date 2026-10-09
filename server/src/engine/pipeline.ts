import { Request } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { RequestContext, WafInspectionResult, WafMode, WafDecisionType, AttackCategory, ThreatSeverity, RuleMatchResult } from '../types/waf';
import { extractClientIp, evaluateIpAccess } from './ipEvaluator';
import { checkDistributedRateLimit } from './redisRateLimiter';
import { evaluateWafRules, safeRegexMatch } from './ruleMatcher';
import { evaluateCsrfPolicy } from './csrfEvaluator';
import { detectBotActivity } from './botDetector';
import { OWASP_CRS_V4_RULES } from './crsRules';
import { evaluateAnomalyScore } from './anomalyEngine';
import { filterRuleExceptions } from './exceptionEvaluator';
import { evaluateVirtualPatches } from './virtualPatchEvaluator';
import { evaluateShadowCandidatePolicy } from './shadowEvaluator';
import { lookupGeoIp } from './geoip';
import { evaluateMlAnomalyShadow } from './mlAnomalyDetector';
import { prisma } from '../db/prisma';
import { config } from '../config/env';

export function buildRequestContext(req: Request, appId?: string, upstreamUrl?: string): RequestContext {
  const correlationId = (req.headers['x-sentinel-request-id'] as string) || (req.headers['x-request-id'] as string) || uuidv4();
  const { ip, version } = extractClientIp(req, config.trustedProxies);

  const rawBody = typeof req.body === 'string' ? req.body : undefined;
  const contentLength = parseInt((req.headers['content-length'] as string) || '0', 10);

  return {
    correlationId,
    clientIp: ip,
    ipVersion: version,
    method: req.method.toUpperCase(),
    path: req.path,
    fullUrl: req.originalUrl || req.url,
    headers: req.headers as Record<string, string | string[] | undefined>,
    query: req.query || {},
    body: req.body || {},
    rawBody,
    contentLength,
    contentType: req.headers['content-type'],
    userAgent: req.headers['user-agent'],
    appId,
    upstreamUrl,
    startTime: Date.now(),
  };
}

export async function getEffectiveWafMode(appId?: string): Promise<WafMode> {
  let globalMode: WafMode = config.wafMode;
  try {
    const setting = await prisma.systemSetting.findUnique({ where: { key: 'WAF_MODE' } });
    if (setting && ['PREVENTION', 'DETECTION', 'DISABLED'].includes(setting.value)) {
      globalMode = setting.value as WafMode;
    }
  } catch {
    globalMode = config.wafMode;
  }

  if (globalMode === 'DISABLED') return 'DISABLED';

  if (appId) {
    try {
      const app = await prisma.protectedApp.findFirst({
        where: { OR: [{ id: appId }, { appId: appId }] }
      });
      if (app && app.wafMode !== 'INHERIT') {
        return app.wafMode as WafMode;
      }
    } catch {
      // Ignore
    }
  }

  return globalMode;
}

export async function getInboundAnomalyThreshold(): Promise<number> {
  try {
    const setting = await prisma.systemSetting.findUnique({ where: { key: 'ANOMALY_THRESHOLD' } });
    if (setting && !isNaN(parseInt(setting.value, 10))) {
      return parseInt(setting.value, 10);
    }
  } catch {
    // Default fallback threshold
  }
  return 5;
}

/**
 * Central Upgraded WAF Pipeline Inspector
 */
export async function inspectRequest(context: RequestContext): Promise<WafInspectionResult> {
  const geo = lookupGeoIp(context.clientIp);
  const mlShadow = await evaluateMlAnomalyShadow(context);
  const mode = await getEffectiveWafMode(context.appId);

  if (mode === 'DISABLED') {
    return {
      correlationId: context.correlationId,
      clientIp: context.clientIp,
      ipVersion: context.ipVersion,
      decision: 'ALLOW',
      effectiveMode: 'DISABLED',
      statusCode: 200,
      category: 'INFO' as AttackCategory,
      severity: 'INFO' as ThreatSeverity,
      explanation: 'WAF Inspection is currently DISABLED by administrator policy.',
      matchedRules: [],
      riskScore: 0,
      durationMs: Date.now() - context.startTime,
      countryCode: geo.countryCode,
      countryName: geo.countryName,
      mlAnomalyScore: mlShadow.score,
      mlPrediction: mlShadow.prediction,
      mlFeatureMeta: JSON.stringify(mlShadow.featureVector),
    };
  }

  const rawMatchedRules: RuleMatchResult[] = [];

  // Stage 1: IP Access Control Check (Allowlist / Blacklist)
  const ipEval = await evaluateIpAccess(context.clientIp);

  if (ipEval.isBlocked) {
    return {
      correlationId: context.correlationId,
      clientIp: context.clientIp,
      ipVersion: context.ipVersion,
      decision: mode === 'PREVENTION' ? 'BLOCK' : 'LOG',
      effectiveMode: mode,
      statusCode: mode === 'PREVENTION' ? 403 : 200,
      matchedRuleId: ipEval.matchingRuleId,
      category: 'IP_BLOCK',
      severity: 'HIGH',
      explanation: ipEval.reason || `Client IP ${context.clientIp} is explicitly Blacklisted.`,
      matchedRules: [{
        ruleId: ipEval.matchingRuleId || 'IP-BLACK-001',
        name: 'IP Access Control Blocklist',
        category: 'IP_BLOCK',
        severity: 'HIGH',
        action: 'BLOCK',
        explanation: ipEval.reason || `IP ${context.clientIp} matched Blocklist`,
        matchedField: 'CLIENT_IP',
        matchedPattern: context.clientIp,
        matchedValueSnippet: context.clientIp,
      }],
      riskScore: 90,
      durationMs: Date.now() - context.startTime,
    };
  }

  // Stage 2: Distributed Rate Limit Policy Evaluation
  const rateLimitResult = await checkDistributedRateLimit(context.clientIp, context.appId, context.path);
  if (rateLimitResult.isLimited) {
    return {
      correlationId: context.correlationId,
      clientIp: context.clientIp,
      ipVersion: context.ipVersion,
      decision: mode === 'PREVENTION' ? 'RATE_LIMIT' : 'LOG',
      effectiveMode: mode,
      statusCode: mode === 'PREVENTION' ? 429 : 200,
      category: 'RATE_LIMIT',
      severity: 'MEDIUM',
      explanation: `Exceeded request rate limit (${rateLimitResult.currentCount}/${rateLimitResult.maxRequests} in ${rateLimitResult.windowMs / 1000}s). Policy: '${rateLimitResult.policyName || 'Global'}'. Retry after ${rateLimitResult.retryAfterSeconds}s.`,
      matchedRules: [{
        ruleId: 'RATE-LIMIT-POLICY',
        name: `Rate Limit Policy (${rateLimitResult.policyName || 'Global'})`,
        category: 'RATE_LIMIT',
        severity: 'MEDIUM',
        action: 'RATE_LIMIT',
        explanation: `Threshold exceeded: ${rateLimitResult.currentCount}/${rateLimitResult.maxRequests}`,
        matchedField: 'CLIENT_IP',
        matchedPattern: rateLimitResult.policyName || 'RateLimit',
        matchedValueSnippet: `${rateLimitResult.currentCount} requests`,
      }],
      riskScore: 60,
      durationMs: Date.now() - context.startTime,
    };
  }

  // Stage 3: Baseline Protocol Controls
  const ALLOWED_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'];
  if (!ALLOWED_METHODS.includes(context.method)) {
    return {
      correlationId: context.correlationId,
      clientIp: context.clientIp,
      ipVersion: context.ipVersion,
      decision: mode === 'PREVENTION' ? 'BLOCK' : 'LOG',
      effectiveMode: mode,
      statusCode: mode === 'PREVENTION' ? 405 : 200,
      category: 'MALFORMED',
      severity: 'MEDIUM',
      explanation: `Unsupported or invalid HTTP method '${context.method}'.`,
      matchedRules: [],
      riskScore: 50,
      durationMs: Date.now() - context.startTime,
    };
  }

  // Stage 4: Virtual Patching Evaluation (Immediate High-Priority Patch Matches)
  const virtualPatchMatches = await evaluateVirtualPatches(context);
  if (virtualPatchMatches.length > 0 && mode === 'PREVENTION') {
    const patch = virtualPatchMatches[0];
    return {
      correlationId: context.correlationId,
      clientIp: context.clientIp,
      ipVersion: context.ipVersion,
      decision: 'BLOCK',
      effectiveMode: mode,
      statusCode: 403,
      matchedRuleId: patch.ruleId,
      category: 'VIRTUAL_PATCH',
      severity: 'CRITICAL',
      explanation: patch.explanation,
      matchedRules: virtualPatchMatches,
      riskScore: 100,
      durationMs: Date.now() - context.startTime,
    };
  }
  rawMatchedRules.push(...virtualPatchMatches);

  // Stage 5: OWASP CRS v4 Signatures + DB Rules Evaluation
  const dbRulesMatches = await evaluateWafRules(context);
  rawMatchedRules.push(...dbRulesMatches);

  let urlFull = context.fullUrl || `${context.path}?${new URLSearchParams(context.query).toString()}`;
  try {
    urlFull = decodeURIComponent(urlFull);
  } catch {
    // Keep original if malformed
  }
  const bodyStr = typeof context.body === 'object' ? JSON.stringify(context.body) : String(context.body || '');

  // Evaluate OWASP CRS v4 Rules
  for (const crsRule of OWASP_CRS_V4_RULES) {
    let targetValue = urlFull;
    if (crsRule.targetField === 'PATH') targetValue = context.path;
    else if (crsRule.targetField === 'QUERY') targetValue = JSON.stringify(context.query);
    else if (crsRule.targetField === 'BODY') targetValue = bodyStr;
    else if (crsRule.targetField === 'HEADER') targetValue = JSON.stringify(context.headers);
    else if (crsRule.targetField === 'METHOD') targetValue = context.method;

    if (safeRegexMatch(crsRule.pattern, targetValue)) {
      rawMatchedRules.push({
        ruleId: crsRule.ruleId,
        name: crsRule.name,
        category: crsRule.category,
        severity: crsRule.severity,
        action: crsRule.action,
        explanation: crsRule.description,
        matchedField: crsRule.targetField,
        matchedPattern: crsRule.pattern,
        matchedValueSnippet: targetValue.substring(0, 150),
      });
    }
  }

  // Stage 6: CSRF Checks
  const csrfEval = evaluateCsrfPolicy(context);
  if (!csrfEval.isValid) {
    rawMatchedRules.push({
      ruleId: 'R-CSRF-001',
      name: 'CSRF Origin Validation Policy',
      category: 'CSRF',
      severity: 'HIGH',
      action: 'BLOCK',
      explanation: csrfEval.reason || 'CSRF Origin validation failure',
      matchedField: 'HEADER',
      matchedPattern: 'Origin/Referer',
      matchedValueSnippet: String(context.headers['origin'] || context.headers['referer'] || 'None'),
    });
  }

  // Stage 7: Bot Activity Heuristics
  const botResult = detectBotActivity(context);
  if (botResult.isSuspicious) {
    rawMatchedRules.push({
      ruleId: 'R-BOT-001',
      name: 'Bot Activity Heuristics',
      category: 'BOT',
      severity: 'MEDIUM',
      action: 'LOG',
      explanation: botResult.indicators.join('; '),
      matchedField: 'USER_AGENT',
      matchedPattern: 'BotHeuristics',
      matchedValueSnippet: context.userAgent || 'None',
    });
  }

  // Stage 8: False-Positive Exception Filtering
  const { activeRules, bypassedRules } = await filterRuleExceptions(context, rawMatchedRules);

  // Stage 9: Cumulative Threat Anomaly Scoring Calculation
  const inboundThreshold = await getInboundAnomalyThreshold();
  const anomalyResult = evaluateAnomalyScore(activeRules, inboundThreshold);

  // Stage 11: Candidate Policy Shadow Evaluation
  const shadowEval = evaluateShadowCandidatePolicy(context, 'ALLOW');

  if (activeRules.length === 0) {
    return {
      correlationId: context.correlationId,
      clientIp: context.clientIp,
      ipVersion: context.ipVersion,
      decision: 'ALLOW',
      effectiveMode: mode,
      statusCode: 200,
      category: 'INFO' as AttackCategory,
      severity: 'INFO' as ThreatSeverity,
      explanation: bypassedRules.length > 0
        ? `Request allowed (${bypassedRules.length} rule(s) bypassed by active False-Positive Exception policy). ${shadowEval.explanation}`
        : `Request passed all security checks. ${shadowEval.explanation}`,
      matchedRules: [],
      riskScore: 0,
      durationMs: Date.now() - context.startTime,
      countryCode: geo.countryCode,
      countryName: geo.countryName,
      mlAnomalyScore: mlShadow.score,
      mlPrediction: mlShadow.prediction,
      mlFeatureMeta: JSON.stringify(mlShadow.featureVector),
    };
  }

  // Stage 10: Decision Resolution based on Anomaly Threshold & Mode
  const primaryRule = activeRules[0];
  let finalDecision: WafDecisionType = 'ALLOW';

  if (anomalyResult.isThresholdExceeded || activeRules.some(r => r.action === 'BLOCK')) {
    finalDecision = 'BLOCK';
  } else {
    finalDecision = 'LOG';
  }

  let statusCode = 200;
  let actualDecision: WafDecisionType = finalDecision;

  if (finalDecision === 'BLOCK') {
    if (mode === 'PREVENTION') {
      actualDecision = 'BLOCK';
      statusCode = 403;
    } else {
      actualDecision = 'LOG';
      statusCode = 200;
    }
  }

  const explanationStr = `[${mode} MODE] Cumulative Anomaly Score: ${anomalyResult.totalAnomalyScore} (Inbound Threshold: ${inboundThreshold}). ${primaryRule.explanation} (${activeRules.length} active rule(s) matched${bypassedRules.length > 0 ? `, ${bypassedRules.length} rule(s) bypassed by exception` : ''}). ${shadowEval.explanation}`;

  return {
    correlationId: context.correlationId,
    clientIp: context.clientIp,
    ipVersion: context.ipVersion,
    decision: actualDecision,
    effectiveMode: mode,
    statusCode,
    matchedRuleId: primaryRule.ruleId,
    category: primaryRule.category,
    severity: primaryRule.severity,
    explanation: explanationStr,
    matchedRules: activeRules,
    riskScore: Math.min(100, anomalyResult.totalAnomalyScore * 15),
    durationMs: Date.now() - context.startTime,
    countryCode: geo.countryCode,
    countryName: geo.countryName,
    mlAnomalyScore: mlShadow.score,
    mlPrediction: mlShadow.prediction,
    mlFeatureMeta: JSON.stringify(mlShadow.featureVector),
  };
}
