import { RuleMatchResult, ThreatSeverity } from '../types/waf';

export interface AnomalyEvaluationResult {
  totalAnomalyScore: number;
  inboundThreshold: number;
  isThresholdExceeded: boolean;
  scoreContributions: Array<{ ruleId: string; severity: ThreatSeverity; points: number }>;
}

export function calculateSeverityScore(severity: ThreatSeverity): number {
  switch (severity) {
    case 'CRITICAL':
      return 5;
    case 'HIGH':
      return 4;
    case 'MEDIUM':
      return 3;
    case 'LOW':
      return 2;
    default:
      return 1;
  }
}

export function evaluateAnomalyScore(
  matchedRules: RuleMatchResult[],
  inboundThreshold: number = 5
): AnomalyEvaluationResult {
  const seenRules = new Set<string>();
  const scoreContributions: Array<{ ruleId: string; severity: ThreatSeverity; points: number }> = [];
  let totalAnomalyScore = 0;

  for (const match of matchedRules) {
    // Prevent duplicate score inflation from same rule ID
    if (seenRules.has(match.ruleId)) continue;
    seenRules.add(match.ruleId);

    const points = calculateSeverityScore(match.severity);
    totalAnomalyScore += points;
    scoreContributions.push({
      ruleId: match.ruleId,
      severity: match.severity,
      points,
    });
  }

  return {
    totalAnomalyScore,
    inboundThreshold,
    isThresholdExceeded: totalAnomalyScore >= inboundThreshold,
    scoreContributions,
  };
}
