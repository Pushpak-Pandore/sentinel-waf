import { RequestContext } from '../types/waf';

export interface MlFeatureVector {
  methodIndex: number;
  pathLength: number;
  pathDepth: number;
  queryLength: number;
  paramCount: number;
  bodySize: number;
  unusualCharRatio: number;
  hasTraversalPattern: number;
  hasScriptPattern: number;
  headerCount: number;
}

export interface MlAnomalyResult {
  score: number; // 0.0 to 1.0
  prediction: 'ANOMALY' | 'NORMAL';
  isAnomaly: boolean;
  threshold: number;
  latencyMs: number;
  featureVector: MlFeatureVector;
  modelVersion: string;
}

const MODEL_VERSION = 'sentinel-ml-v1.2-shadow';
const DEFAULT_THRESHOLD = 0.60;

/**
 * Extracts sanitized, bounded features from an HTTP request context.
 * Does NOT collect passwords, raw auth tokens, or cookies.
 */
export function extractMlFeatures(context: RequestContext): MlFeatureVector {
  const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'];
  const methodIndex = methods.indexOf(context.method) !== -1 ? methods.indexOf(context.method) : 99;

  const path = context.path || '/';
  const pathLength = path.length;
  const pathDepth = path.split('/').filter(Boolean).length;

  const queryStr = typeof context.query === 'object' ? JSON.stringify(context.query) : String(context.query || '');
  const queryLength = queryStr.length;
  const paramCount = typeof context.query === 'object' ? Object.keys(context.query).length : 0;

  const bodyStr = typeof context.body === 'object' ? JSON.stringify(context.body) : String(context.body || '');
  const bodySize = context.contentLength || bodyStr.length;

  // Calculate unusual character ratio (looking for script injection / shellcode / encoded payloads)
  const totalChars = path.length + queryStr.length;
  const unusualCount = (urlSpecialCount(path) + urlSpecialCount(queryStr));
  const unusualCharRatio = totalChars > 0 ? Math.min(1.0, unusualCount / totalChars) : 0;

  const hasTraversalPattern = (path.includes('..') || queryStr.includes('..') || path.includes('%2e%2e')) ? 1 : 0;
  const hasScriptPattern = (/<script|union\s+select|eval\(|base64|system\(/i.test(path + queryStr + bodyStr)) ? 1 : 0;

  const headerCount = Object.keys(context.headers || {}).length;

  return {
    methodIndex,
    pathLength,
    pathDepth,
    queryLength,
    paramCount,
    bodySize,
    unusualCharRatio,
    hasTraversalPattern,
    hasScriptPattern,
    headerCount,
  };
}

function urlSpecialCount(str: string): number {
  const matches = str.match(/[<>'";\\$%\^&*(){}\[\]|`~]/g);
  return matches ? matches.length : 0;
}

/**
 * Lightweight Statistical Anomaly Scorer (Isolation Forest proxy score)
 * Evaluates deviation from baseline normal web traffic patterns.
 */
export function evaluateMlAnomaly(context: RequestContext, threshold: number = DEFAULT_THRESHOLD): MlAnomalyResult {
  const start = Date.now();
  const f = extractMlFeatures(context);

  let rawScore = 0.05; // Baseline low risk score

  // Feature 1: Path length anomaly (paths > 100 chars get higher score)
  if (f.pathLength > 120) rawScore += 0.20;
  else if (f.pathLength > 60) rawScore += 0.10;

  // Feature 2: Path depth anomaly (depth > 6)
  if (f.pathDepth > 7) rawScore += 0.15;

  // Feature 3: Query length / param count anomaly
  if (f.queryLength > 200) rawScore += 0.25;
  if (f.paramCount > 10) rawScore += 0.15;

  // Feature 4: Unusual character ratio score
  if (f.unusualCharRatio > 0.15) rawScore += 0.35;
  else if (f.unusualCharRatio > 0.05) rawScore += 0.20;

  // Feature 5: Explicit structural anomaly flags
  if (f.hasTraversalPattern === 1) rawScore += 0.40;
  if (f.hasScriptPattern === 1) rawScore += 0.45;

  // Feature 6: Body size anomaly
  if (f.bodySize > 500000) rawScore += 0.15;

  // Normalize final score between 0.0 and 1.0
  const score = Math.min(1.0, Math.max(0.0, parseFloat(rawScore.toFixed(3))));
  const isAnomaly = score >= threshold;
  const latencyMs = Math.max(0, Date.now() - start);

  return {
    score,
    prediction: isAnomaly ? 'ANOMALY' : 'NORMAL',
    isAnomaly,
    threshold,
    latencyMs,
    featureVector: f,
    modelVersion: MODEL_VERSION,
  };
}

/**
 * Safe Shadow-Mode Runner with Strict Execution Budget (Timeout)
 */
export async function evaluateMlAnomalyShadow(
  context: RequestContext,
  timeoutMs: number = 15
): Promise<MlAnomalyResult> {
  try {
    const mlPromise = Promise.resolve().then(() => evaluateMlAnomaly(context));
    const timeoutPromise = new Promise<MlAnomalyResult>((_, reject) =>
      setTimeout(() => reject(new Error('ML inference timeout exceeded')), timeoutMs)
    );

    return await Promise.race([mlPromise, timeoutPromise]);
  } catch (err: any) {
    // Fail open safely during shadow mode
    return {
      score: 0.0,
      prediction: 'NORMAL',
      isAnomaly: false,
      threshold: DEFAULT_THRESHOLD,
      latencyMs: timeoutMs,
      featureVector: extractMlFeatures(context),
      modelVersion: `${MODEL_VERSION}-fallback`,
    };
  }
}
