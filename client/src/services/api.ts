const API_BASE = '/api/v1';

export async function apiFetch<T = any>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const token = localStorage.getItem('sentinel_token');

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string> || {}),
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers,
  });

  if (response.status === 401) {
    localStorage.removeItem('sentinel_token');
    if (window.location.pathname !== '/login' && !endpoint.includes('/auth/login')) {
      window.location.href = '/login';
    }
    throw new Error('Unauthorized');
  }

  const data = await response.json();

  if (!response.ok) {
    throw new Error(data.message || data.error || 'API Request failed');
  }

  return data;
}

export const api = {
  // Auth
  login: (credentials: any) => apiFetch('/auth/login', { method: 'POST', body: JSON.stringify(credentials) }),
  getMe: () => apiFetch('/auth/me'),
  logout: () => apiFetch('/auth/logout', { method: 'POST' }),

  // Stats & Overview
  getOverview: (timeframe = 86400000) => apiFetch(`/overview?timeframe=${timeframe}`),
  getAnalytics: (timeframe = 86400000) => apiFetch(`/analytics?timeframe=${timeframe}`),

  // Traffic & Events
  getTraffic: (params = '') => apiFetch(`/traffic?${params}`),
  getEvents: (params = '') => apiFetch(`/events?${params}`),
  getEventDetails: (id: string) => apiFetch(`/events/${id}`),

  // WAF Rules
  getRules: (category = '') => apiFetch(`/rules?category=${category}`),
  createRule: (rule: any) => apiFetch('/rules', { method: 'POST', body: JSON.stringify(rule) }),
  updateRule: (id: string, rule: any) => apiFetch(`/rules/${id}`, { method: 'PUT', body: JSON.stringify(rule) }),
  toggleRule: (id: string) => apiFetch(`/rules/${id}/toggle`, { method: 'PATCH' }),
  deleteRule: (id: string) => apiFetch(`/rules/${id}`, { method: 'DELETE' }),
  testRule: (data: any) => apiFetch('/rules/test', { method: 'POST', body: JSON.stringify(data) }),

  // IP Access Control
  getIpRules: () => apiFetch('/ip-access'),
  createIpRule: (rule: any) => apiFetch('/ip-access', { method: 'POST', body: JSON.stringify(rule) }),
  deleteIpRule: (id: string) => apiFetch(`/ip-access/${id}`, { method: 'DELETE' }),
  checkCidr: (data: any) => apiFetch('/ip-access/check', { method: 'POST', body: JSON.stringify(data) }),

  // Rate Limit Policies
  getRateLimitPolicies: () => apiFetch('/rate-limit'),
  createRateLimitPolicy: (policy: any) => apiFetch('/rate-limit', { method: 'POST', body: JSON.stringify(policy) }),
  deleteRateLimitPolicy: (id: string) => apiFetch(`/rate-limit/${id}`, { method: 'DELETE' }),

  // Protected Applications
  getApps: () => apiFetch('/apps'),
  createApp: (app: any) => apiFetch('/apps', { method: 'POST', body: JSON.stringify(app) }),
  deleteApp: (id: string) => apiFetch(`/apps/${id}`, { method: 'DELETE' }),
  checkAppHealth: (id: string) => apiFetch(`/apps/${id}/check-health`, { method: 'POST' }),

  // Request Inspector
  executeInspector: (data: any) => apiFetch('/inspector/execute', { method: 'POST', body: JSON.stringify(data) }),

  // Audit Logs
  getAuditLogs: (page = 1) => apiFetch(`/audit?page=${page}`),

  // Health & Settings
  getHealth: () => apiFetch('/health/detailed'),
  getSettings: () => apiFetch('/settings'),
  updateSetting: (key: string, value: string) => apiFetch('/settings', { method: 'POST', body: JSON.stringify({ key, value }) }),

  // Upgraded Capabilities API Endpoints
  getExceptions: () => apiFetch('/exceptions'),
  createException: (data: any) => apiFetch('/exceptions', { method: 'POST', body: JSON.stringify(data) }),
  deleteException: (id: string) => apiFetch(`/exceptions/${id}`, { method: 'DELETE' }),

  getVirtualPatches: () => apiFetch('/virtual-patches'),
  createVirtualPatch: (data: any) => apiFetch('/virtual-patches', { method: 'POST', body: JSON.stringify(data) }),
  deleteVirtualPatch: (id: string) => apiFetch(`/virtual-patches/${id}`, { method: 'DELETE' }),

  getSiemWebhooks: () => apiFetch('/siem'),
  createSiemWebhook: (data: any) => apiFetch('/siem', { method: 'POST', body: JSON.stringify(data) }),
  deleteSiemWebhook: (id: string) => apiFetch(`/siem/${id}`, { method: 'DELETE' }),
  testSiemWebhook: (id: string) => apiFetch(`/siem/${id}/test`, { method: 'POST' }),

  // Phase 3, 4, 5 Upgrade Endpoints
  getGeoThreats: (period = '24h') => apiFetch(`/analytics/geo-threats?period=${period}`),
  getMlShadowAnalytics: (period = '24h') => apiFetch(`/analytics/ml-shadow?period=${period}`),
  downloadPdfReport: async (period = '24h') => {
    const token = localStorage.getItem('sentinel_token');
    const res = await fetch(`${API_BASE}/analytics/report/pdf?period=${period}`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });
    if (!res.ok) throw new Error('Failed to generate PDF report');
    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Sentinel_WAF_Executive_Security_Report_${period}_${Date.now()}.pdf`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
  },
};
