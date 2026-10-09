import { RequestContext } from '../types/waf';

export interface CsrfCheckResult {
  isValid: boolean;
  reason?: string;
}

export function evaluateCsrfPolicy(context: RequestContext, allowedOrigins: string[] = ['localhost', '127.0.0.1']): CsrfCheckResult {
  const method = context.method.toUpperCase();

  // Non-state changing methods (GET, HEAD, OPTIONS) do not require CSRF origin validation
  if (['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    return { isValid: true };
  }

  const origin = context.headers['origin'];
  const referer = context.headers['referer'];

  // If no Origin or Referer is present on state-changing requests, log/warn
  if (!origin && !referer) {
    return {
      isValid: false,
      reason: 'State-changing request missing both Origin and Referer headers.',
    };
  }

  const headerVal = (Array.isArray(origin) ? origin[0] : origin) || (Array.isArray(referer) ? referer[0] : referer) || '';

  try {
    const url = new URL(headerVal);
    const hostName = url.hostname;

    const matches = allowedOrigins.some(allowed => hostName === allowed || hostName.endsWith(`.${allowed}`));
    if (!matches && !allowedOrigins.includes('*')) {
      return {
        isValid: false,
        reason: `Untrusted Origin/Referer domain '${hostName}'. Allowed origins: ${allowedOrigins.join(', ')}`,
      };
    }
  } catch {
    return {
      isValid: false,
      reason: `Malformed Origin/Referer header value: '${headerVal}'`,
    };
  }

  return { isValid: true };
}
