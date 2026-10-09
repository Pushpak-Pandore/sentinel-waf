import React, { useEffect, useState } from 'react';
import { DataCard } from '../components/DataCard';
import { ThreatBadge } from '../components/ThreatBadge';
import { OverviewStats } from '../types';
import { api } from '../services/api';
import { ShieldAlert, ShieldCheck, Activity, Gauge, AlertTriangle, RefreshCw } from 'lucide-react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, BarChart, Bar, XAxis, YAxis } from 'recharts';

export const Overview: React.FC = () => {
  const [stats, setStats] = useState<OverviewStats | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchStats = () => {
    setLoading(true);
    api.getOverview()
      .then(setStats)
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchStats();
    const interval = setInterval(fetchStats, 10000); // 10s auto refresh
    return () => clearInterval(interval);
  }, []);

  if (loading && !stats) {
    return (
      <div className="p-8 flex items-center justify-center min-h-[400px]">
        <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
      </div>
    );
  }

  const categoryData = stats
    ? Object.entries(stats.categories).map(([name, value]) => ({ name, value }))
    : [];

  const COLORS = ['#EF4444', '#F97316', '#F59E0B', '#3B82F6', '#8B5CF6', '#10B981'];

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-100 uppercase tracking-tight">Security Operations Dashboard</h1>
          <p className="text-xs text-slate-400">Real-time Web Application Firewall Telemetry & Threat Metrics</p>
        </div>
        <button
          onClick={fetchStats}
          className="px-3 py-1.5 rounded-lg bg-dark-800 border border-dark-700 text-xs text-slate-300 hover:text-white flex items-center gap-2"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        <DataCard
          title="Total Requests"
          value={stats?.totalRequests || 0}
          subtitle={`${stats?.requestsPerSecond || 0} req/sec`}
          icon={Activity}
          variant="info"
        />
        <DataCard
          title="Permitted Traffic"
          value={stats?.allowedRequests || 0}
          subtitle="Passed security policy"
          icon={ShieldCheck}
          variant="success"
        />
        <DataCard
          title="Blocked Threats"
          value={stats?.blockedRequests || 0}
          subtitle="Prevented attacks"
          icon={ShieldAlert}
          variant="danger"
        />
        <DataCard
          title="Monitored Events"
          value={stats?.monitoredRequests || 0}
          subtitle="Detection mode logs"
          icon={AlertTriangle}
          variant="warning"
        />
        <DataCard
          title="Rate Limited"
          value={stats?.rateLimitedRequests || 0}
          subtitle="HTTP 429 Throttle"
          icon={Gauge}
        />
      </div>

      {/* Analytics Breakdown Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Threat Categories Donut Chart */}
        <div className="bg-dark-800 border border-dark-700 rounded-lg p-5">
          <h3 className="text-xs uppercase font-mono font-bold text-slate-300 mb-4">Attack Categories Distribution</h3>
          {categoryData.length > 0 ? (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={categoryData}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={80}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {categoryData.map((_, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ backgroundColor: '#111827', borderColor: '#374151', borderRadius: '0.5rem', fontSize: '12px' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="h-64 flex items-center justify-center text-xs text-slate-500 font-mono">No security threats detected yet</div>
          )}
        </div>

        {/* Top Attacking IPs */}
        <div className="bg-dark-800 border border-dark-700 rounded-lg p-5">
          <h3 className="text-xs uppercase font-mono font-bold text-slate-300 mb-4">Top Threat Source IPs</h3>
          <div className="space-y-3">
            {stats?.topIps && stats.topIps.length > 0 ? (
              stats.topIps.map((ip) => (
                <div key={ip.ip} className="flex items-center justify-between text-xs p-2 rounded bg-dark-900 border border-dark-700">
                  <span className="font-mono text-cyan-400">{ip.ip}</span>
                  <span className="px-2 py-0.5 rounded bg-red-950 text-red-400 border border-red-900 font-bold">{ip.count} events</span>
                </div>
              ))
            ) : (
              <p className="text-xs text-slate-500 font-mono py-8 text-center">No threat sources recorded</p>
            )}
          </div>
        </div>

        {/* Top Targeted Paths */}
        <div className="bg-dark-800 border border-dark-700 rounded-lg p-5">
          <h3 className="text-xs uppercase font-mono font-bold text-slate-300 mb-4">Most Targeted URIs</h3>
          <div className="space-y-3">
            {stats?.topPaths && stats.topPaths.length > 0 ? (
              stats.topPaths.map((p) => (
                <div key={p.path} className="flex items-center justify-between text-xs p-2 rounded bg-dark-900 border border-dark-700">
                  <span className="font-mono text-slate-300 truncate max-w-[200px]">{p.path}</span>
                  <span className="px-2 py-0.5 rounded bg-amber-950 text-amber-400 border border-amber-900 font-bold">{p.count} attempts</span>
                </div>
              ))
            ) : (
              <p className="text-xs text-slate-500 font-mono py-8 text-center">No target paths recorded</p>
            )}
          </div>
        </div>
      </div>

      {/* Recent Security Events Feed */}
      <div className="bg-dark-800 border border-dark-700 rounded-lg p-5">
        <h3 className="text-xs uppercase font-mono font-bold text-slate-300 mb-4">Recent Threat Interceptions</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-dark-900 text-slate-400 uppercase font-mono border-b border-dark-700">
              <tr>
                <th className="p-3">Timestamp</th>
                <th className="p-3">Client IP</th>
                <th className="p-3">Method</th>
                <th className="p-3">Path</th>
                <th className="p-3">Category</th>
                <th className="p-3">Severity</th>
                <th className="p-3">Decision</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-dark-700/50">
              {stats?.recentEvents && stats.recentEvents.length > 0 ? (
                stats.recentEvents.map((event) => (
                  <tr key={event.id} className="hover:bg-dark-700/30 font-mono">
                    <td className="p-3 text-slate-400">{new Date(event.timestamp).toLocaleTimeString()}</td>
                    <td className="p-3 text-cyan-400 font-semibold">{event.clientIp}</td>
                    <td className="p-3 font-bold">{event.method}</td>
                    <td className="p-3 text-slate-300 truncate max-w-[250px]">{event.path}</td>
                    <td className="p-3"><ThreatBadge type="category" value={event.category} /></td>
                    <td className="p-3"><ThreatBadge type="severity" value={event.severity} /></td>
                    <td className="p-3"><ThreatBadge type="decision" value={event.decision} /></td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="p-6 text-center text-slate-500 font-mono">No security events recorded in the selected timeframe.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
