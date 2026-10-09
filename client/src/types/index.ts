export type WafMode = 'PREVENTION' | 'DETECTION' | 'DISABLED';
export type WafDecision = 'ALLOW' | 'LOG' | 'BLOCK' | 'RATE_LIMIT';
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
  | 'INFO';

export interface User {
  id: string;
  email: string;
  name: string;
  role: 'ADMIN' | 'ANALYST';
}

export interface OverviewStats {
  totalRequests: number;
  allowedRequests: number;
  blockedRequests: number;
  monitoredRequests: number;
  rateLimitedRequests: number;
  requestsPerSecond: number;
  categories: Record<string, number>;
  severities: Record<string, number>;
  topIps: Array<{ ip: string; count: number }>;
  topPaths: Array<{ path: string; count: number }>;
  recentEvents: SecurityEvent[];
}

export interface TrafficLog {
  id: string;
  correlationId: string;
  clientIp: string;
  ipVersion?: string;
  method: string;
  path: string;
  statusCode: number;
  durationMs: number;
  decision: WafDecision;
  appId?: string;
  timestamp: string;
}

export interface SecurityEvent {
  id: string;
  correlationId: string;
  clientIp: string;
  ipVersion: string;
  method: string;
  path: string;
  appId?: string;
  status: number;
  matchedRuleId?: string;
  category: AttackCategory;
  severity: ThreatSeverity;
  decision: WafDecision;
  explanation: string;
  durationMs: number;
  requestHeaders?: string;
  queryParams?: string;
  requestBody?: string;
  userAgent?: string;
  timestamp: string;
}

export interface WafRule {
  id: string;
  ruleId: string;
  name: string;
  description: string;
  category: AttackCategory;
  severity: ThreatSeverity;
  enabled: boolean;
  action: WafDecision;
  matchType: 'REGEX' | 'CONTAINS' | 'EXACT' | 'HEADER_PRESENT';
  targetField: 'QUERY' | 'BODY' | 'PATH' | 'HEADER' | 'METHOD' | 'FULL_URL';
  pattern: string;
  version: number;
  createdAt: string;
  updatedAt: string;
}

export interface IpAccessRule {
  id: string;
  ipOrCidr: string;
  ipVersion: 'IPv4' | 'IPv6';
  type: 'ALLOW' | 'BLOCK';
  description?: string;
  reason?: string;
  expiresAt?: string;
  createdAt: string;
}

export interface RateLimitPolicy {
  id: string;
  name: string;
  scope: 'GLOBAL' | 'IP' | 'APP' | 'ROUTE';
  pathPattern: string;
  windowMs: number;
  maxRequests: number;
  burstLimit: number;
  action: 'RATE_LIMIT' | 'BLOCK';
  enabled: boolean;
  createdAt: string;
}

export interface ProtectedApp {
  id: string;
  appId: string;
  name: string;
  host: string;
  upstreamUrl: string;
  enabled: boolean;
  wafMode: 'INHERIT' | 'PREVENTION' | 'DETECTION' | 'DISABLED';
  requestLimit: number;
  healthStatus: 'HEALTHY' | 'DEGRADED' | 'UNREACHABLE';
  createdAt: string;
}

export interface AuditLog {
  id: string;
  userId?: string;
  userEmail?: string;
  action: string;
  entity: string;
  entityId?: string;
  details?: string;
  ipAddress?: string;
  timestamp: string;
  user?: User;
}

export interface SystemHealth {
  status: string;
  wafEngineStatus: string;
  databaseStatus: string;
  databaseLatencyMs: number;
  upstreamHealth: string;
  uptimeSeconds: number;
  nodeVersion: string;
  memoryUsageMB: {
    rss: string;
    heapTotal: string;
    heapUsed: string;
  };
  protectedAppsCount: number;
  timestamp: string;
}
