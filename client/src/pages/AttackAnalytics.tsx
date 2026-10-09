import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { BarChart3, RefreshCw, FileText, Download } from 'lucide-react';
import { WorldThreatMap, CountryThreatData } from '../components/WorldThreatMap';
import { MlShadowCard, MlShadowData } from '../components/MlShadowCard';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
} from 'recharts';

export const AttackAnalytics: React.FC = () => {
  const [timeframe, setTimeframe] = useState<number>(86400000); // 24h default
  const [periodStr, setPeriodStr] = useState<string>('24h');
  const [data, setData] = useState<any>(null);
  const [geoData, setGeoData] = useState<CountryThreatData[]>([]);
  const [mlData, setMlData] = useState<MlShadowData | null>(null);

  const [loading, setLoading] = useState(true);
  const [exportingPdf, setExportingPdf] = useState(false);

  const fetchAnalytics = () => {
    setLoading(true);

    const periodParam = timeframe === 3600000 ? '24h' : timeframe === 86400000 ? '24h' : timeframe === 604800000 ? '7d' : '30d';
    setPeriodStr(periodParam);

    Promise.all([
      api.getAnalytics(timeframe),
      api.getGeoThreats(periodParam),
      api.getMlShadowAnalytics(periodParam),
    ])
      .then(([analyticsRes, geoRes, mlRes]) => {
        setData(analyticsRes);
        setGeoData(geoRes.countries || []);
        setMlData(mlRes);
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchAnalytics();
  }, [timeframe]);

  const handleExportPdf = async () => {
    try {
      setExportingPdf(true);
      await api.downloadPdfReport(periodStr);
    } catch (err) {
      console.error('PDF Report Export Failed:', err);
      alert('Failed to generate Executive PDF report.');
    } finally {
      setExportingPdf(false);
    }
  };

  const COLORS = ['#EF4444', '#F97316', '#F59E0B', '#3B82F6', '#8B5CF6', '#10B981'];

  const categoryPieData = data?.summary?.categories
    ? Object.entries(data.summary.categories).map(([name, value]) => ({ name, value }))
    : [];

  const topIpBarData = data?.summary?.topIps || [];

  return (
    <div className="p-6 space-y-6">
      {/* Title & Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 uppercase tracking-tight flex items-center gap-2">
            <BarChart3 className="w-5 h-5 text-cyan-400" />
            Attack Analytics & Threat Intelligence
          </h1>
          <p className="text-xs text-slate-400">Historical Attack Trends, GeoIP Attribution, ML Anomaly Telemetry, and PDF Audit Reports</p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <button
            onClick={handleExportPdf}
            disabled={exportingPdf}
            className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-mono text-xs font-bold flex items-center gap-2 transition-all shadow-lg shadow-cyan-900/30 disabled:opacity-50"
          >
            {exportingPdf ? (
              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <FileText className="w-3.5 h-3.5" />
            )}
            Export PDF Executive Report
          </button>

          <select
            value={timeframe}
            onChange={(e) => setTimeframe(Number(e.target.value))}
            className="bg-dark-800 border border-dark-700 text-xs text-slate-200 rounded-lg px-3 py-1.5 focus:outline-none font-mono"
          >
            <option value={3600000}>Last 1 Hour</option>
            <option value={86400000}>Last 24 Hours</option>
            <option value={604800000}>Last 7 Days</option>
            <option value={2592000000}>Last 30 Days</option>
          </select>

          <button
            onClick={fetchAnalytics}
            className="px-3 py-1.5 rounded-lg bg-dark-800 border border-dark-700 text-xs text-slate-300 hover:text-white flex items-center gap-2"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* PHASE 3: Interactive GeoIP World Threat Map */}
      <WorldThreatMap countries={geoData} loading={loading} />

      {/* Main Time-Series Traffic Chart */}
      <div className="bg-dark-800 border border-dark-700 rounded-lg p-5">
        <h3 className="text-xs uppercase font-mono font-bold text-slate-300 mb-4">Traffic & Security Interception Trends Over Time</h3>
        <div className="h-72">
          {data?.timeSeries && data.timeSeries.length > 0 ? (
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={data.timeSeries}>
                <defs>
                  <linearGradient id="colorAllowed" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#10B981" stopOpacity={0.8}/>
                    <stop offset="95%" stopColor="#10B981" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="colorBlocked" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#EF4444" stopOpacity={0.8}/>
                    <stop offset="95%" stopColor="#EF4444" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" stroke="#6B7280" fontSize={11} tickLine={false} />
                <YAxis stroke="#6B7280" fontSize={11} tickLine={false} />
                <Tooltip contentStyle={{ backgroundColor: '#111827', borderColor: '#374151', borderRadius: '0.5rem', fontSize: '12px' }} />
                <Area type="monotone" dataKey="allowed" name="Allowed Traffic" stroke="#10B981" fillOpacity={1} fill="url(#colorAllowed)" />
                <Area type="monotone" dataKey="blocked" name="Blocked Threats" stroke="#EF4444" fillOpacity={1} fill="url(#colorBlocked)" />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-full flex items-center justify-center text-xs text-slate-500 font-mono">
              Insufficient time-series data for selected timeframe. Submit test requests via the Request Inspector.
            </div>
          )}
        </div>
      </div>

      {/* PHASE 4: Machine Learning Anomaly Detection Telemetry */}
      <MlShadowCard data={mlData} loading={loading} />

      {/* Grid of Visual Distribution Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Category Pie */}
        <div className="bg-dark-800 border border-dark-700 rounded-lg p-5">
          <h3 className="text-xs uppercase font-mono font-bold text-slate-300 mb-4">Attack Vector Breakdown</h3>
          <div className="h-64">
            {categoryPieData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={categoryPieData}
                    cx="50%"
                    cy="50%"
                    outerRadius={80}
                    dataKey="value"
                    label={({ name, value }) => `${name}: ${value}`}
                  >
                    {categoryPieData.map((_, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ backgroundColor: '#111827', borderColor: '#374151', borderRadius: '0.5rem', fontSize: '12px' }} />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs text-slate-500 font-mono">No category data recorded</div>
            )}
          </div>
        </div>

        {/* Top Attacking IPs Bar Chart */}
        <div className="bg-dark-800 border border-dark-700 rounded-lg p-5">
          <h3 className="text-xs uppercase font-mono font-bold text-slate-300 mb-4">Top Attacking IP Addresses</h3>
          <div className="h-64">
            {topIpBarData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={topIpBarData} layout="vertical">
                  <XAxis type="number" stroke="#6B7280" fontSize={11} />
                  <YAxis type="category" dataKey="ip" stroke="#6B7280" fontSize={11} width={100} />
                  <Tooltip contentStyle={{ backgroundColor: '#111827', borderColor: '#374151', borderRadius: '0.5rem', fontSize: '12px' }} />
                  <Bar dataKey="count" fill="#06B6D4" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs text-slate-500 font-mono">No threat IP data recorded</div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
