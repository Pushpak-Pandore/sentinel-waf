export type WafDecisionType = 'ALLOW' | 'LOG' | 'BLOCK' | 'RATE_LIMIT';

export type WafMode = 'PREVENTION' | 'DETECTION' | 'DISABLED';

export type ThreatSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type AttackCategory =
  | 'SQLI'
  | 'XSS'
  | 'CSRF'
  | 'DOS'
  | 'LFI'
  | 'REMOTE_ACCESS'
  | 'MALFORMED'
  | 'BOT'
  | 'IP_BLOCK'
  | 'RATE_LIMIT'
  | 'VIRTUAL_PATCH';

export interface RequestContext {
  correlationId: string;
  clientIp: string;
  ipVersion: 'IPv4' | 'IPv6';
  method: string;
  path: string;
  fullUrl: string;
  headers: Record<string, string | string[] | undefined>;
  query: Record<string, any>;
  body: any;
  rawBody?: string;
  contentLength: number;
  contentType?: string;
  userAgent?: string;
  appId?: string;
  upstreamUrl?: string;
  startTime: number;
}

export interface RuleMatchResult {
  ruleId: string;
  name: string;
  category: AttackCategory;
  severity: ThreatSeverity;
  action: WafDecisionType;
  explanation: string;
  matchedField: string;
  matchedPattern: string;
  matchedValueSnippet: string;
}

export interface WafInspectionResult {
  correlationId: string;
  clientIp: string;
  ipVersion: 'IPv4' | 'IPv6';
  decision: WafDecisionType;
  effectiveMode: WafMode;
  statusCode: number;
  matchedRuleId?: string;
  category: AttackCategory;
  severity: ThreatSeverity;
  explanation: string;
  matchedRules: RuleMatchResult[];
  riskScore: number; // 0 - 100
  durationMs: number;
  countryCode?: string;
  countryName?: string;
  mlAnomalyScore?: number;
  mlPrediction?: string;
  mlFeatureMeta?: string;
}
